//! Verifies Tezos context (Irmin) Merkle proofs and links a state root to a block header.
//!
//! Formats were checked against a live Octez 25.3 node, see PLAN.md.

use blake2::{digest::consts::U32, Blake2b, Digest};
use sha2::Digest as _;

pub type Hash = [u8; 32];

const SOME: [u8; 8] = [0xff, 0, 0, 0, 0, 0, 0, 0];
const NONE: [u8; 8] = [0; 8];
/// Irmin hashes nodes above this many entries as inode trees (irmin-pack `stable_hash`).
const MAX_FLAT_ENTRIES: usize = 256;
/// Inode branching factor (irmin-pack `entries`).
const INODE_ENTRIES: usize = 32;

/// Proof tree as served by `context/merkle_tree_v2` (holey=false).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Tree {
    Value(Vec<u8>),
    BlindedValue(Hash),
    Node(Vec<(Vec<u8>, Tree)>),
    BlindedNode(Hash),
    /// Directory with more than 256 entries, stored as an irmin-pack inode tree.
    /// Extenders are expanded into single child inodes when parsing.
    Inode(Inode),
}

/// Internal inode of a big directory. `length` counts all entries below it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Inode {
    pub length: u64,
    /// (child index < 32, child), only the non-empty slots.
    pub proofs: Vec<(u8, InodeTree)>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum InodeTree {
    Blinded(Hash),
    /// Leaf inode holding at most 32 entries of the directory.
    Values(Vec<(Vec<u8>, Tree)>),
    Tree(Inode),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    RootMismatch,
    DuplicateStep,
    StepTooLong,
    TooManyEntries,
    PathNotFound,
    NotAValue,
    BadJson(&'static str),
    BadLeaf,
    BadInode,
    ValueMismatch,
}

fn blake2b(parts: &[&[u8]]) -> Hash {
    let mut h = Blake2b::<U32>::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn contents_hash(v: &[u8]) -> Hash {
    blake2b(&[&u64be(v.len() as u64), v])
}

fn u64be(n: u64) -> [u8; 8] {
    n.to_be_bytes()
}

/// Irmin.Type (repr) varint: LEB128, used for ints, list and string lengths, variant tags.
fn varint(h: &mut Blake2b<U32>, mut n: u64) {
    while n >= 128 {
        h.update([(n as u8 & 127) | 128]);
        n >>= 7;
    }
    h.update([n as u8]);
}

/// (step, is_contents, child hash)
type Entry<'a> = (&'a [u8], bool, Hash);

/// Sorts (step, child) entries, rejecting duplicates and steps the RPC can't encode.
fn sorted_entries(entries: &[(Vec<u8>, Tree)]) -> Result<Vec<Entry<'_>>, Error> {
    let mut sorted = Vec::with_capacity(entries.len());
    for (step, child) in entries {
        if step.len() > 255 {
            return Err(Error::StepTooLong);
        }
        let (is_contents, h) = child.hash()?;
        sorted.push((step.as_slice(), is_contents, h));
    }
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    if sorted.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(Error::DuplicateStep);
    }
    Ok(sorted)
}

impl Inode {
    /// Hash of `Bin.v` (irmin-pack inode.ml) for `Tree { depth; length; entries }`:
    /// tag 1, depth, length, then the sparse `{ index; hash }` list, ascending by index.
    fn hash(&self, depth: u64) -> Result<Hash, Error> {
        if self.proofs.is_empty() {
            return Err(Error::BadInode);
        }
        let mut ptrs = Vec::with_capacity(self.proofs.len());
        for (i, child) in &self.proofs {
            if *i as usize >= INODE_ENTRIES {
                return Err(Error::BadInode);
            }
            ptrs.push((*i, child.hash(depth + 1)?));
        }
        ptrs.sort_by_key(|p| p.0);
        if ptrs.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(Error::BadInode);
        }
        let mut h = Blake2b::<U32>::new();
        varint(&mut h, 1);
        varint(&mut h, depth);
        varint(&mut h, self.length);
        varint(&mut h, ptrs.len() as u64);
        for (i, ptr) in ptrs {
            varint(&mut h, i as u64);
            h.update(ptr);
        }
        Ok(h.finalize().into())
    }

    /// Finds `step` in any unblinded leaf. We don't recompute the seeded child index:
    /// the hash binds every leaf and Irmin keeps each step in exactly one leaf.
    fn find(&self, step: &[u8]) -> Option<&Tree> {
        self.proofs.iter().find_map(|(_, c)| match c {
            InodeTree::Blinded(_) => None,
            InodeTree::Values(es) => es.iter().find(|(s, _)| s.as_slice() == step).map(|(_, t)| t),
            InodeTree::Tree(i) => i.find(step),
        })
    }
}

impl InodeTree {
    fn hash(&self, depth: u64) -> Result<Hash, Error> {
        match self {
            InodeTree::Blinded(h) => Ok(*h),
            InodeTree::Tree(i) => i.hash(depth),
            // Non-root `Values` inode: tag 0 then (step, value) pairs, with value
            // tagged 0 for `Node and 1 for `Contents (default metadata).
            InodeTree::Values(entries) => {
                if entries.is_empty() || entries.len() > INODE_ENTRIES {
                    return Err(Error::BadInode);
                }
                let sorted = sorted_entries(entries)?;
                let mut h = Blake2b::<U32>::new();
                varint(&mut h, 0);
                varint(&mut h, sorted.len() as u64);
                for (step, is_contents, child) in sorted {
                    varint(&mut h, step.len() as u64);
                    h.update(step);
                    varint(&mut h, is_contents as u64);
                    h.update(child);
                }
                Ok(h.finalize().into())
            }
        }
    }
}

impl Tree {
    /// Returns (is_contents, hash).
    pub fn hash(&self) -> Result<(bool, Hash), Error> {
        match self {
            Tree::Value(v) => Ok((true, contents_hash(v))),
            Tree::BlindedValue(h) => Ok((true, *h)),
            Tree::BlindedNode(h) => Ok((false, *h)),
            Tree::Node(entries) => {
                if entries.len() > MAX_FLAT_ENTRIES {
                    return Err(Error::TooManyEntries);
                }
                let sorted = sorted_entries(entries)?;
                let mut h = Blake2b::<U32>::new();
                h.update(u64be(sorted.len() as u64));
                for (step, is_contents, child) in sorted {
                    h.update(if is_contents { SOME } else { NONE });
                    varint(&mut h, step.len() as u64);
                    h.update(step);
                    h.update(u64be(32));
                    h.update(child);
                }
                Ok((false, h.finalize().into()))
            }
            // Irmin hashes small directories flat even if stored as inodes, so a
            // root inode only makes sense above 256 entries.
            Tree::Inode(i) => {
                if i.length <= MAX_FLAT_ENTRIES as u64 {
                    return Err(Error::BadInode);
                }
                Ok((false, i.hash(0)?))
            }
        }
    }

    fn child(&self, step: &[u8]) -> Option<&Tree> {
        match self {
            Tree::Node(entries) => entries.iter().find(|(s, _)| s.as_slice() == step).map(|(_, t)| t),
            Tree::Inode(i) => i.find(step),
            _ => None,
        }
    }

    /// Parses the `state` field of a `merkle_tree_v2` RPC response.
    pub fn from_rpc_json(v: &serde_json::Value) -> Result<Tree, Error> {
        let obj = v.as_object().ok_or(Error::BadJson("not an object"))?;
        let (k, inner) = obj.iter().next().ok_or(Error::BadJson("empty object"))?;
        let hash = |s: &serde_json::Value| -> Result<Hash, Error> {
            let s = s.as_str().ok_or(Error::BadJson("hash not a string"))?;
            decode_context_hash(s).ok_or(Error::BadJson("bad b58 hash"))
        };
        match k.as_str() {
            "other_trees" => Tree::from_rpc_json(inner),
            "value" => {
                let s = inner.as_str().ok_or(Error::BadJson("value not a string"))?;
                Ok(Tree::Value(hex::decode(s).map_err(|_| Error::BadJson("value not hex"))?))
            }
            "blinded_value" => Ok(Tree::BlindedValue(hash(inner)?)),
            "blinded_node" => Ok(Tree::BlindedNode(hash(inner)?)),
            "node" => Ok(Tree::Node(entries_from_json(inner)?)),
            "inode" => Ok(Tree::Inode(inode_from_json(inner)?)),
            "extender" => Ok(Tree::Inode(extender_from_json(inner)?)),
            _ => Err(Error::BadJson("unsupported tree kind")),
        }
    }
}

fn entries_from_json(v: &serde_json::Value) -> Result<Vec<(Vec<u8>, Tree)>, Error> {
    let arr = v.as_array().ok_or(Error::BadJson("node not an array"))?;
    let mut entries = Vec::with_capacity(arr.len());
    for e in arr {
        let pair = e.as_array().filter(|p| p.len() == 2).ok_or(Error::BadJson("bad entry"))?;
        let step = hex::decode(pair[0].as_str().ok_or(Error::BadJson("step"))?)
            .map_err(|_| Error::BadJson("step not hex"))?;
        entries.push((step, Tree::from_rpc_json(&pair[1])?));
    }
    Ok(entries)
}

fn field<'a>(v: &'a serde_json::Value, k: &str) -> Result<&'a serde_json::Value, Error> {
    v.get(k).ok_or(Error::BadJson("missing field"))
}

/// int64 fields come as decimal strings in data-encoding JSON.
fn length_from_json(v: &serde_json::Value) -> Result<u64, Error> {
    let l = field(v, "length")?;
    match l.as_str() {
        Some(s) => s.parse().map_err(|_| Error::BadJson("bad length")),
        None => l.as_u64().ok_or(Error::BadJson("bad length")),
    }
}

/// `{length, proofs: {sparse_proof: [[i, t]..]} | {dense_proof: [t; 32]}}`
fn inode_from_json(v: &serde_json::Value) -> Result<Inode, Error> {
    let length = length_from_json(v)?;
    let proofs = field(v, "proofs")?;
    let mut out = vec![];
    if let Some(sparse) = proofs.get("sparse_proof") {
        for e in sparse.as_array().ok_or(Error::BadJson("sparse_proof"))? {
            let pair = e.as_array().filter(|p| p.len() == 2).ok_or(Error::BadJson("sparse entry"))?;
            let i = pair[0].as_u64().filter(|&i| i < INODE_ENTRIES as u64).ok_or(Error::BadJson("index"))?;
            let t = inode_tree_from_json(&pair[1])?.ok_or(Error::BadJson("none in sparse_proof"))?;
            out.push((i as u8, t));
        }
    } else if let Some(dense) = proofs.get("dense_proof") {
        let arr = dense.as_array().filter(|a| a.len() == INODE_ENTRIES).ok_or(Error::BadJson("dense_proof"))?;
        for (i, e) in arr.iter().enumerate() {
            if let Some(t) = inode_tree_from_json(e)? {
                out.push((i as u8, t));
            }
        }
    } else {
        return Err(Error::BadJson("unknown proofs kind"));
    }
    Ok(Inode { length, proofs: out })
}

/// An extender is a chain of single child inodes sharing `length`, one per segment index.
fn extender_from_json(v: &serde_json::Value) -> Result<Inode, Error> {
    let length = length_from_json(v)?;
    let seg = hex::decode(field(v, "segment")?.as_str().ok_or(Error::BadJson("segment"))?)
        .map_err(|_| Error::BadJson("segment not hex"))?;
    let segments = decode_segment(&seg).ok_or(Error::BadJson("bad segment"))?;
    let mut t = inode_tree_from_json(field(v, "proof")?)?.ok_or(Error::BadJson("none in extender"))?;
    for &i in segments.iter().skip(1).rev() {
        t = InodeTree::Tree(Inode { length, proofs: vec![(i, t)] });
    }
    let first = *segments.first().ok_or(Error::BadJson("empty segment"))?;
    Ok(Inode { length, proofs: vec![(first, t)] })
}

/// Parses an `inode_tree`. `None` is the empty dense_proof slot.
fn inode_tree_from_json(v: &serde_json::Value) -> Result<Option<InodeTree>, Error> {
    let obj = v.as_object().filter(|o| o.len() == 1).ok_or(Error::BadJson("inode_tree not a 1 key object"))?;
    let (k, inner) = obj.iter().next().ok_or(Error::BadJson("empty object"))?;
    match k.as_str() {
        "other_inode_trees" => inode_tree_from_json(inner),
        "inode_tree" => Ok(Some(InodeTree::Tree(inode_from_json(inner)?))),
        "inode_values" => Ok(Some(InodeTree::Values(entries_from_json(inner)?))),
        "blinded_inode" => {
            let s = inner.as_str().ok_or(Error::BadJson("hash not a string"))?;
            Ok(Some(InodeTree::Blinded(decode_context_hash(s).ok_or(Error::BadJson("bad b58 hash"))?)))
        }
        // No real proof has shown one yet, so its hashing is unverified. Fail closed.
        "inode_extender" => Err(Error::BadJson("inode_extender unsupported")),
        "none" => Ok(None),
        _ => Err(Error::BadJson("unsupported inode_tree kind")),
    }
}

/// Decodes the 5 bit index list of an extender (merkle_proof_encoding.ml `segment_encoding_32`):
/// indexes packed MSB first, then a 1 bit and zero padding.
fn decode_segment(b: &[u8]) -> Option<Vec<u8>> {
    let last = *b.last()?;
    if last == 0 || b.len() > 255 {
        return None;
    }
    let bits = b.len() * 8 - (last.trailing_zeros() as usize + 1);
    if bits % 5 != 0 {
        return None;
    }
    let bit = |n: usize| (b[n / 8] >> (7 - n % 8)) & 1;
    Some((0..bits / 5).map(|j| (0..5).fold(0u8, |acc, k| acc << 1 | bit(j * 5 + k))).collect())
}

/// Checks `tree` hashes to `root` and walks `path`. `None` means a fully listed node lacks
/// the next step, which proves absence since a node's hash commits to all its entries.
fn lookup<'a>(root: &Hash, tree: &'a Tree, path: &[&[u8]]) -> Result<Option<&'a Tree>, Error> {
    let (is_contents, h) = tree.hash()?;
    if is_contents || &h != root {
        return Err(Error::RootMismatch);
    }
    let mut cur = tree;
    for step in path {
        cur = match cur {
            Tree::Node(entries) => match entries.iter().find(|(s, _)| s.as_slice() == *step) {
                Some((_, t)) => t,
                None => return Ok(None),
            },
            // Absence in an inode would need the seeded index, so a miss there stays an error.
            _ => cur.child(step).ok_or(Error::PathNotFound)?,
        };
    }
    Ok(Some(cur))
}

/// Checks `tree` hashes to `root` and returns the value at `path`.
pub fn verify_membership(root: &Hash, tree: &Tree, path: &[&[u8]]) -> Result<Vec<u8>, Error> {
    verify_optional(root, tree, path)?.ok_or(Error::PathNotFound)
}

/// Like `verify_membership`, but `Ok(None)` when the proof shows `path` is absent.
pub fn verify_optional(root: &Hash, tree: &Tree, path: &[&[u8]]) -> Result<Option<Vec<u8>>, Error> {
    match lookup(root, tree, path)? {
        None => Ok(None),
        Some(Tree::Value(v)) => Ok(Some(v.clone())),
        Some(_) => Err(Error::NotAValue),
    }
}

/// Checks the contents at `path` are `value`. A blinded leaf is enough, its hash binds the value.
pub fn verify_value(root: &Hash, tree: &Tree, path: &[&[u8]], value: &[u8]) -> Result<(), Error> {
    let got = match lookup(root, tree, path)?.ok_or(Error::PathNotFound)? {
        Tree::Value(v) => contents_hash(v),
        Tree::BlindedValue(h) => *h,
        _ => return Err(Error::NotAValue),
    };
    if got != contents_hash(value) {
        return Err(Error::ValueMismatch);
    }
    Ok(())
}

/// Context path of a big_map value. `key_hash` is blake2b-256 of the PACKed key.
pub fn big_map_value_path(big_map_id: u64, key_hash: &Hash) -> Vec<Vec<u8>> {
    vec![
        b"data".to_vec(),
        b"big_maps".to_vec(),
        b"index".to_vec(),
        big_map_id.to_string().into_bytes(),
        b"contents".to_vec(),
        hex::encode(key_hash).into_bytes(),
        b"data".to_vec(),
    ]
}

/// blake2b(PACK(bytes)) for a big_map<bytes, _> key.
pub fn bytes_key_hash(key: &[u8]) -> Hash {
    blake2b(&[&[0x05, 0x0a], &(key.len() as u32).to_be_bytes(), key])
}

/// Stored big_map values are Micheline binary without the 0x05 PACK prefix. Expects `bytes` of length 32.
pub fn decode_bytes32_leaf(leaf: &[u8]) -> Result<Hash, Error> {
    if leaf.len() != 37 || leaf[0] != 0x0a || leaf[1..5] != [0, 0, 0, 32] {
        return Err(Error::BadLeaf);
    }
    Ok(leaf[5..].try_into().unwrap())
}

/// What Octez commits alongside the tree when it finishes applying block B.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CommitInfo {
    /// header(B).context, the parent commit
    pub parent: Hash,
    /// header(B).timestamp, unix seconds
    pub timestamp: i64,
    /// protocol commit message, e.g. "lvl 833, fit:(833, unlocked, 0, 0), round 0, 9 ops". Untrusted preimage data.
    pub message: Vec<u8>,
}

/// Commit hash of B's resulting context, which is what header(B+1).context holds.
pub fn commit_hash(root: &Hash, info: &CommitInfo) -> Hash {
    blake2b(&[
        &u64be(32),
        root,
        &u64be(1),
        &u64be(32),
        &info.parent,
        &info.timestamp.to_be_bytes(),
        &u64be(5),
        b"Tezos",
        &u64be(info.message.len() as u64),
        &info.message,
    ])
}

/// Decodes a b58check "Co..." context hash (2 byte prefix).
pub fn decode_context_hash(s: &str) -> Option<Hash> {
    let raw = b58check_decode(s)?;
    if raw.len() != 34 || raw[..2] != [79, 199] {
        return None;
    }
    raw[2..].try_into().ok()
}

fn b58check_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHA: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut out: Vec<u8> = vec![];
    for c in s.bytes() {
        let mut carry = ALPHA.iter().position(|&a| a == c)? as u32;
        for b in out.iter_mut().rev() {
            carry += (*b as u32) * 58;
            *b = carry as u8;
            carry >>= 8;
        }
        while carry > 0 {
            out.insert(0, carry as u8);
            carry >>= 8;
        }
    }
    let zeros = s.bytes().take_while(|&c| c == b'1').count();
    let mut raw = vec![0u8; zeros];
    raw.extend(out);
    if raw.len() < 4 {
        return None;
    }
    let (data, check) = raw.split_at(raw.len() - 4);
    let d = sha2_256(&sha2_256(data));
    (d[..4] == *check).then(|| data.to_vec())
}

fn sha2_256(data: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(b: &[u8]) -> Tree {
        Tree::Value(b.to_vec())
    }

    fn node(es: Vec<(&[u8], Tree)>) -> Tree {
        Tree::Node(es.into_iter().map(|(s, t)| (s.to_vec(), t)).collect())
    }

    fn root_of(t: &Tree) -> Hash {
        t.hash().unwrap().1
    }

    /// root { data { a: 1, b: <blinded 2> }, protocol: P }
    fn tree() -> Tree {
        let b = leaf(b"2").hash().unwrap().1;
        node(vec![
            (b"data", node(vec![(b"a", leaf(b"1")), (b"b", Tree::BlindedValue(b))])),
            (b"protocol", leaf(&[9; 32])),
        ])
    }

    #[test]
    fn optional_in_flat_node() {
        let t = tree();
        let r = root_of(&t);
        // Blinded siblings still list their step, so the node proves `z` isn't there.
        assert_eq!(verify_optional(&r, &t, &[b"data", b"z"]), Ok(None));
        assert_eq!(verify_optional(&r, &t, &[b"data", b"a"]), Ok(Some(b"1".to_vec())));
        // Present but blinded can't be read.
        assert_eq!(verify_optional(&r, &t, &[b"data", b"b"]), Err(Error::NotAValue));
    }

    #[test]
    fn optional_dropped_entry_breaks_root() {
        let r = root_of(&tree());
        let mut t = tree();
        let Tree::Node(es) = &mut t else { panic!() };
        let Tree::Node(data) = &mut es[0].1 else { panic!() };
        data.remove(0);
        assert_eq!(verify_optional(&r, &t, &[b"data", b"a"]), Err(Error::RootMismatch));
    }

    #[test]
    fn optional_blinded_parent_fails() {
        let t = tree();
        let r = root_of(&t);
        let Tree::Node(mut es) = t else { panic!() };
        es[0].1 = Tree::BlindedNode(root_of(&es[0].1));
        let t = Tree::Node(es);
        assert_eq!(verify_optional(&r, &t, &[b"data", b"z"]), Err(Error::PathNotFound));
    }

    #[test]
    fn optional_inode_parent() {
        // 300 entries so it's hashed as an inode. One leaf holds `k`, the rest are blinded.
        let inode = Inode {
            length: 300,
            proofs: vec![
                (0, InodeTree::Values(vec![(b"k".to_vec(), leaf(b"v"))])),
                (1, InodeTree::Blinded([1; 32])),
            ],
        };
        let t = node(vec![(b"dir", Tree::Inode(inode))]);
        let r = root_of(&t);
        assert_eq!(verify_optional(&r, &t, &[b"dir", b"k"]), Ok(Some(b"v".to_vec())));
        // Absence would need the seeded index, which we don't compute, so fail closed.
        assert_eq!(verify_optional(&r, &t, &[b"dir", b"z"]), Err(Error::PathNotFound));
    }

    #[test]
    fn value_blinded_or_not() {
        let t = tree();
        let r = root_of(&t);
        assert_eq!(verify_value(&r, &t, &[b"protocol"], &[9; 32]), Ok(()));
        assert_eq!(verify_value(&r, &t, &[b"data", b"b"], b"2"), Ok(()));
        assert_eq!(verify_value(&r, &t, &[b"protocol"], &[8; 32]), Err(Error::ValueMismatch));
        assert_eq!(verify_value(&r, &t, &[b"data", b"z"], b"2"), Err(Error::PathNotFound));
        assert_eq!(verify_value(&r, &t, &[b"data"], b"2"), Err(Error::NotAValue));
    }

    #[test]
    fn inode_extender_fails_closed() {
        let blinded = serde_json::json!({"blinded_inode": "CoVeZeUA74qyE5iPBiNvCHpCReoZdyfJ9q7EWBjnkj1Artp81nxg"});
        let j = serde_json::json!({"inode": {"length": "300", "proofs": {"sparse_proof": [
            [3, {"inode_extender": {"length": "300", "segment": "08a0", "proof": blinded}}]
        ]}}});
        assert_eq!(Tree::from_rpc_json(&j), Err(Error::BadJson("inode_extender unsupported")));
    }
}
