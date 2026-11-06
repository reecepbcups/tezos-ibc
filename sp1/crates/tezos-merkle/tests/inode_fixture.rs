// Mainnet proofs through inode directories (big_maps/index and a big_map's contents),
// dumped by fixtures/dump_mainnet.py from rpc.tzbeta.net.
use tezos_merkle::*;

fn fixture(name: &str) -> serde_json::Value {
    let p = format!("{}/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

// Same commit message reconstruction as live_fixture.rs.
fn commit_info(f: &serde_json::Value) -> (Hash, CommitInfo) {
    let blk = &f["block"];
    let fit: Vec<&str> = blk["fitness"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
    let lvl = blk["level"].as_i64().unwrap();
    let locked = if fit[2].is_empty() { "unlocked".to_string() } else { format!("locked: {}", i64::from_str_radix(fit[2], 16).unwrap()) };
    let pred_round = -1 - i32::from_be_bytes(hex::decode(fit[3]).unwrap().try_into().unwrap()) as i64;
    let round = i64::from_str_radix(fit[4], 16).unwrap();
    let minus = if pred_round != 0 { "-" } else { "" };
    let msg = format!("lvl {lvl}, fit:({lvl}, {locked}, {minus}{pred_round}, {round}), round {round}, {} ops", f["op_count"]);
    let ts = unix_secs(blk["timestamp"].as_str().unwrap());
    let next = decode_context_hash(f["next_header"]["context"].as_str().unwrap()).unwrap();
    (next, CommitInfo { parent: decode_context_hash(blk["context"].as_str().unwrap()).unwrap(), timestamp: ts, message: msg.into_bytes() })
}

fn unix_secs(s: &str) -> i64 {
    let n = |a: usize, b: usize| s[a..b].parse::<i64>().unwrap();
    let (y, m, d) = (n(0, 4), n(5, 7), n(8, 10));
    let (y2, m2) = if m <= 2 { (y - 1, m + 12) } else { (y, m) };
    let days = 365 * y2 + y2 / 4 - y2 / 100 + y2 / 400 + (153 * (m2 - 3) + 2) / 5 + d - 719469;
    days * 86400 + n(11, 13) * 3600 + n(14, 16) * 60 + n(17, 19)
}

fn path(f: &serde_json::Value) -> Vec<Vec<u8>> {
    let kh: Hash = hex::decode(f["key_hash"].as_str().unwrap()).unwrap().try_into().unwrap();
    big_map_value_path(f["big_map_id"].as_u64().unwrap(), &kh)
}

fn refs(p: &[Vec<u8>]) -> Vec<&[u8]> {
    p.iter().map(|s| s.as_slice()).collect()
}

fn count_inodes(t: &Tree) -> usize {
    match t {
        Tree::Node(es) => es.iter().map(|(_, c)| count_inodes(c)).sum(),
        Tree::Inode(i) => 1 + count_inner(i),
        _ => 0,
    }
}

fn count_inner(i: &Inode) -> usize {
    i.proofs
        .iter()
        .map(|(_, c)| match c {
            InodeTree::Tree(i) => 1 + count_inner(i),
            InodeTree::Values(es) => es.iter().map(|(_, c)| count_inodes(c)).sum(),
            InodeTree::Blinded(_) => 0,
        })
        .sum()
}

#[test]
fn mainnet_roots_through_inodes() {
    for (name, min_inodes) in [("mainnet_bm199.json", 4), ("mainnet_bm511.json", 4)] {
        let f = fixture(name);
        let tree = Tree::from_rpc_json(&f["proof"]["state"]).unwrap();
        assert!(count_inodes(&tree) >= min_inodes, "{name}: expected the path to cross inodes");
        let (_, root) = tree.hash().unwrap();
        assert_eq!(Some(root), decode_context_hash(f["proof"]["before"]["node"].as_str().unwrap()), "{name}");
        let (next_ctx, info) = commit_info(&f);
        assert_eq!(commit_hash(&root, &info), next_ctx, "{name}: root doesn't link to header(B+1).context");
        let leaf = verify_membership(&root, &tree, &refs(&path(&f))).unwrap();
        assert!(!leaf.is_empty());
    }
}

#[test]
fn bm199_value_and_empty_slots() {
    let f = fixture("mainnet_bm199.json");
    // The contents dir has 1059 entries, so the key sits in a depth 2 leaf with empty sibling slots.
    assert!(f["proof"].to_string().contains("\"none\""));
    let tree = Tree::from_rpc_json(&f["proof"]["state"]).unwrap();
    let (_, root) = tree.hash().unwrap();
    let leaf = verify_membership(&root, &tree, &refs(&path(&f))).unwrap();
    assert_eq!(hex::encode(leaf), "0707002d0200000000");
}

#[test]
fn tampered_inode_length_fails() {
    let f = fixture("mainnet_bm511.json");
    let tree = Tree::from_rpc_json(&f["proof"]["state"]).unwrap();
    let (_, root) = tree.hash().unwrap();
    let s = f["proof"]["state"].to_string().replacen("\"length\":\"", "\"length\":\"1", 1);
    let bad = Tree::from_rpc_json(&serde_json::from_str(&s).unwrap()).unwrap();
    assert_eq!(verify_membership(&root, &bad, &refs(&path(&f))), Err(Error::RootMismatch));
}

#[test]
fn tampered_leaf_value_fails() {
    let f = fixture("mainnet_bm199.json");
    let tree = Tree::from_rpc_json(&f["proof"]["state"]).unwrap();
    let (_, root) = tree.hash().unwrap();
    let leaf = hex::encode(verify_membership(&root, &tree, &refs(&path(&f))).unwrap());
    let mut flipped = leaf.clone().into_bytes();
    let last = flipped.len() - 1;
    flipped[last] = if flipped[last] == b'0' { b'1' } else { b'0' };
    let s = f["proof"]["state"].to_string().replace(&format!("\"value\":\"{leaf}\""), &format!("\"value\":\"{}\"", String::from_utf8(flipped).unwrap()));
    let bad = Tree::from_rpc_json(&serde_json::from_str(&s).unwrap()).unwrap();
    assert_eq!(verify_membership(&root, &bad, &refs(&path(&f))), Err(Error::RootMismatch));
}

#[test]
fn missing_key_fails() {
    let f = fixture("mainnet_bm511.json");
    let tree = Tree::from_rpc_json(&f["proof"]["state"]).unwrap();
    let (_, root) = tree.hash().unwrap();
    let p = big_map_value_path(511, &[7; 32]);
    assert_eq!(verify_membership(&root, &tree, &refs(&p)), Err(Error::PathNotFound));
}

// Rewrites every dense_proof as the equivalent sparse_proof; the root must not change.
fn to_sparse(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(o) => {
            if let Some(serde_json::Value::Array(arr)) = o.remove("dense_proof") {
                let sparse: Vec<serde_json::Value> = arr
                    .into_iter()
                    .enumerate()
                    .filter(|(_, e)| *e != serde_json::json!({"other_inode_trees": {"other_inode_trees": {"none": {}}}}))
                    .map(|(i, mut e)| {
                        to_sparse(&mut e);
                        serde_json::json!([i, e])
                    })
                    .collect();
                o.insert("sparse_proof".into(), sparse.into());
            } else {
                o.values_mut().for_each(to_sparse);
            }
        }
        serde_json::Value::Array(a) => a.iter_mut().for_each(to_sparse),
        _ => {}
    }
}

#[test]
fn sparse_and_dense_hash_the_same() {
    let f = fixture("mainnet_bm199.json");
    let (_, root) = Tree::from_rpc_json(&f["proof"]["state"]).unwrap().hash().unwrap();
    let mut s = f["proof"]["state"].clone();
    to_sparse(&mut s);
    assert!(s.to_string().contains("sparse_proof") && !s.to_string().contains("dense_proof"));
    let tree = Tree::from_rpc_json(&s).unwrap();
    assert_eq!(tree.hash().unwrap().1, root);
    verify_membership(&root, &tree, &refs(&path(&f))).unwrap();
}

#[test]
fn extender_expands_to_single_child_chain() {
    let h = "CoVtrgbkAEqeZpK5DTEHio6n9eK3qHD6GpNbQo6T6TLobmtYmNxW";
    let blinded = serde_json::json!({"other_inode_trees": {"other_inode_trees": {"blinded_inode": h}}});
    // segment [1, 2] packs as 00001 00010 then the 1 bit terminator: 0x08 0xa0.
    let j = serde_json::json!({"other_trees": {"other_trees": {"extender": {"length": "300", "segment": "08a0", "proof": blinded}}}});
    let want = Tree::Inode(Inode {
        length: 300,
        proofs: vec![(1, InodeTree::Tree(Inode { length: 300, proofs: vec![(2, InodeTree::Blinded(decode_context_hash(h).unwrap()))] }))],
    });
    assert_eq!(Tree::from_rpc_json(&j).unwrap(), want);
}

#[test]
fn rejects_malformed_inodes() {
    let h = "CoVtrgbkAEqeZpK5DTEHio6n9eK3qHD6GpNbQo6T6TLobmtYmNxW";
    let blinded = serde_json::json!({"other_inode_trees": {"other_inode_trees": {"blinded_inode": h}}});
    let none = serde_json::json!({"other_inode_trees": {"other_inode_trees": {"none": {}}}});
    let inode = |length: &str, proofs: serde_json::Value| serde_json::json!({"inode": {"length": length, "proofs": proofs}});
    // root inodes at or below 256 entries are hashed flat by Irmin
    let t = Tree::from_rpc_json(&inode("256", serde_json::json!({"sparse_proof": [[0, blinded]]}))).unwrap();
    assert_eq!(t.hash(), Err(Error::BadInode));
    // index out of range, none in sparse, short dense, duplicate index, bad segment
    for bad in [
        inode("300", serde_json::json!({"sparse_proof": [[32, blinded]]})),
        inode("300", serde_json::json!({"sparse_proof": [[0, none]]})),
        inode("300", serde_json::json!({"dense_proof": [blinded]})),
        serde_json::json!({"extender": {"length": "300", "segment": "00", "proof": blinded}}),
        serde_json::json!({"extender": {"length": "300", "segment": "80", "proof": blinded}}),
        serde_json::json!({"none": {}}),
    ] {
        assert!(Tree::from_rpc_json(&bad).is_err(), "{bad}");
    }
    let dup = Tree::from_rpc_json(&inode("300", serde_json::json!({"sparse_proof": [[0, blinded], [0, blinded]]}))).unwrap();
    assert_eq!(dup.hash(), Err(Error::BadInode));
    let empty = Tree::from_rpc_json(&inode("300", serde_json::json!({"sparse_proof": []}))).unwrap();
    assert_eq!(empty.hash(), Err(Error::BadInode));
}

// Real Octez v25.3 sandbox proof whose big_map contents (300 entries) were crafted so every key
// shares its inode index at depth 0 (5) and 1 (17), and depth 2 is one of {0, 1, 2}. Irmin then
// emits an extender with segment [5, 17] over a 3 child sparse_proof. Keys come from a port of
// OCaml's Hashtbl.seeded_hash, checked against the mainnet fixtures' inode paths.
#[test]
fn sandbox_extender_and_sparse_proof() {
    let f = fixture("sandbox_extender.json");
    let s = f["proof"]["state"].to_string();
    assert!(s.contains("\"extender\":") && s.contains("\"segment\":\"2c60\""));
    assert!(s.contains("sparse_proof"));
    let tree = Tree::from_rpc_json(&f["proof"]["state"]).unwrap();
    let (_, root) = tree.hash().unwrap();
    assert_eq!(Some(root), decode_context_hash(f["proof"]["before"]["node"].as_str().unwrap()));
    let (next_ctx, info) = commit_info(&f);
    assert_eq!(commit_hash(&root, &info), next_ctx, "root doesn't link to header(B+1).context");
    // big_map bytes unit: the stored value is Unit
    assert_eq!(hex::encode(verify_membership(&root, &tree, &refs(&path(&f))).unwrap()), "030b");
}
