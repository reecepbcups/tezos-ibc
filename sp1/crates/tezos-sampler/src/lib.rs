//! Tezos attestation slot sampling (protocol 025 PsUshuai, all-bakers-attest off).
//!
//! Ports `Delegate_sampler.Random.owner` and `Sampler.sample` (alias method) from
//! `src/proto_025_PsUshuai/lib_protocol`. Inputs are `cycle/<c>/delegate_sampler_state`
//! and `cycle/<c>/random_seed`, both read from the context so they can be Merkle proven.

use blake2::{digest::consts::U20, digest::consts::U32, Blake2b, Digest};
use tezos_merkle::{verify_membership, Hash, Tree};

pub type Seed = [u8; 32];

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Truncated,
    TrailingBytes,
    BadTag(u8),
    BadOption(u8),
    /// support, p and alias arrays disagree in length, or are empty
    BadShape,
    BadTotal,
    BadAlias,
    BadSeed,
    Proof(tezos_merkle::Error),
}

/// `Signature.Public_key.t`, tag byte then raw key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    Ed25519([u8; 32]),
    Secp256k1([u8; 33]),
    P256([u8; 33]),
    Bls([u8; 48]),
}

/// `Signature.Public_key_hash.t`: tag (0 tz1, 1 tz2, 2 tz3, 3 tz4) and blake2b-160.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pkh {
    pub tag: u8,
    pub hash: [u8; 20],
}

impl PublicKey {
    pub fn tag(&self) -> u8 {
        match self {
            PublicKey::Ed25519(_) => 0,
            PublicKey::Secp256k1(_) => 1,
            PublicKey::P256(_) => 2,
            PublicKey::Bls(_) => 3,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        match self {
            PublicKey::Ed25519(k) => k,
            PublicKey::Secp256k1(k) | PublicKey::P256(k) => k,
            PublicKey::Bls(k) => k,
        }
    }

    pub fn hash(&self) -> Pkh {
        Pkh {
            tag: self.tag(),
            hash: Blake2b::<U20>::digest(self.bytes()).into(),
        }
    }
}

/// `Raw_context.consensus_pk` as stored in the sampler support.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsensusPk {
    pub consensus_pk: PublicKey,
    /// Only stored when it differs from hash(consensus_pk).
    pub delegate: Option<Pkh>,
    pub companion_pk: Option<[u8; 48]>,
}

impl ConsensusPk {
    /// The delegate the slot's power counts for, like `consensus_pk.delegate` in OCaml.
    pub fn delegate(&self) -> Pkh {
        self.delegate.unwrap_or_else(|| self.consensus_pk.hash())
    }
}

/// `Sampler.t` for `int64` masses: Vose alias table built by the protocol at cycle end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SamplerState {
    pub total: i64,
    pub support: Vec<ConsensusPk>,
    pub p: Vec<i64>,
    pub alias: Vec<i32>,
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < n {
            return Err(Error::Truncated);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn i32(&mut self) -> Result<i32, Error> {
        Ok(i32::from_be_bytes(self.arr()?))
    }
    fn i64(&mut self) -> Result<i64, Error> {
        Ok(i64::from_be_bytes(self.arr()?))
    }
    fn present(&mut self) -> Result<bool, Error> {
        match self.u8()? {
            0x00 => Ok(false),
            0xff => Ok(true),
            b => Err(Error::BadOption(b)),
        }
    }
    fn public_key(&mut self) -> Result<PublicKey, Error> {
        Ok(match self.u8()? {
            0 => PublicKey::Ed25519(self.arr()?),
            1 => PublicKey::Secp256k1(self.arr()?),
            2 => PublicKey::P256(self.arr()?),
            3 => PublicKey::Bls(self.arr()?),
            t => return Err(Error::BadTag(t)),
        })
    }
    fn pkh(&mut self) -> Result<Pkh, Error> {
        let tag = self.u8()?;
        if tag > 3 {
            return Err(Error::BadTag(tag));
        }
        Ok(Pkh {
            tag,
            hash: self.arr()?,
        })
    }
    fn consensus_pk(&mut self) -> Result<ConsensusPk, Error> {
        let consensus_pk = self.public_key()?;
        let delegate = if self.present()? {
            Some(self.pkh()?)
        } else {
            None
        };
        let companion_pk = if self.present()? {
            Some(self.arr()?)
        } else {
            None
        };
        Ok(ConsensusPk {
            consensus_pk,
            delegate,
            companion_pk,
        })
    }

    /// `Sampler.array_encoding`: obj3 length int31, fallback, elements (u32 byte-size prefixed list).
    /// The fallback is only read past, we require `elements.len() == length` so it's never used.
    fn fallback_array<T>(
        &mut self,
        mut elt: impl FnMut(&mut Self) -> Result<T, Error>,
    ) -> Result<Vec<T>, Error> {
        let len = self.i32()?;
        let _fallback = elt(self)?;
        let size = u32::from_be_bytes(self.arr()?) as usize;
        let mut inner = Reader(self.take(size)?);
        let mut out = Vec::with_capacity(len.max(0) as usize);
        while !inner.0.is_empty() {
            out.push(elt(&mut inner)?);
        }
        if len < 0 || out.len() != len as usize {
            return Err(Error::BadShape);
        }
        Ok(out)
    }
}

impl SamplerState {
    /// Decodes the raw bytes of `cycle/<c>/delegate_sampler_state` (`Sampler.encoding Raw_context.consensus_pk_encoding`).
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader(bytes);
        let total = r.i64()?;
        let support = r.fallback_array(|r| r.consensus_pk())?;
        let p = r.fallback_array(|r| r.i64())?;
        let alias = r.fallback_array(|r| r.i32())?;
        if !r.0.is_empty() {
            return Err(Error::TrailingBytes);
        }
        if support.is_empty() || p.len() != support.len() || alias.len() != support.len() {
            return Err(Error::BadShape);
        }
        if total <= 0 {
            return Err(Error::BadTotal);
        }
        Ok(SamplerState {
            total,
            support,
            p,
            alias,
        })
    }
}

/// `Delegate_sampler.Random` draw state: 32 hash bytes and a read offset.
struct Draw {
    bytes: [u8; 32],
    off: usize,
    hashes: u32,
}

fn blake2b32(data: &[u8]) -> [u8; 32] {
    Blake2b::<U32>::digest(data).into()
}

impl Draw {
    /// `init_random_state`: blake2b(seed ‖ int32 cycle_position ‖ int32 slot).
    fn new(seed: &Seed, cycle_position: i32, slot: i32) -> Self {
        let mut buf = [0u8; 40];
        buf[..32].copy_from_slice(seed);
        buf[32..36].copy_from_slice(&cycle_position.to_be_bytes());
        buf[36..].copy_from_slice(&slot.to_be_bytes());
        Draw {
            bytes: blake2b32(&buf),
            off: 0,
            hashes: 1,
        }
    }

    /// `take_int64`: uniform in [0, bound) by rejection over |int64|, rehashing when 32 bytes are used up.
    fn take(&mut self, bound: i64) -> i64 {
        let drop_if_over = i64::MAX - i64::MAX % bound;
        loop {
            if self.off > 32 - 8 {
                self.bytes = blake2b32(&self.bytes);
                self.off = 0;
                self.hashes += 1;
            }
            let r = i64::from_be_bytes(self.bytes[self.off..self.off + 8].try_into().unwrap());
            self.off += 8;
            // OCaml maps min_int to 0 because abs(min_int) = min_int.
            let r = if r == i64::MIN { 0 } else { r.abs() };
            if r < drop_if_over {
                return r % bound;
            }
        }
    }
}

/// Support index of the owner of attestation `slot` at a level with `cycle_position`.
/// Returns the index and the number of blake2b calls used.
pub fn slot_owner(
    state: &SamplerState,
    seed: &Seed,
    cycle_position: i32,
    slot: i32,
) -> Result<(usize, u32), Error> {
    let mut d = Draw::new(seed, cycle_position, slot);
    let i = d.take(state.support.len() as i64) as usize;
    let elt = d.take(state.total);
    if elt < state.p[i] {
        return Ok((i, d.hashes));
    }
    let j = state.alias[i];
    if j < 0 || j as usize >= state.support.len() {
        return Err(Error::BadAlias);
    }
    Ok((j as usize, d.hashes))
}

/// Attestation committee of one level.
#[derive(Debug, PartialEq, Eq)]
pub struct Committee {
    /// support index owning each slot 0..committee_size
    pub owners: Vec<u32>,
    /// slots held per support index. Support entries are one per delegate, so this is per delegate power.
    pub power: Vec<u32>,
    pub blake2b_calls: u32,
}

/// Samples every slot of a level, like `Delegate_sampler.attesting_power` with all-bakers-attest off.
pub fn committee(
    state: &SamplerState,
    seed: &Seed,
    cycle_position: i32,
    committee_size: u32,
) -> Result<Committee, Error> {
    let mut owners = Vec::with_capacity(committee_size as usize);
    let mut power = vec![0u32; state.support.len()];
    let mut calls = 0;
    for slot in 0..committee_size {
        let (i, h) = slot_owner(state, seed, cycle_position, slot as i32)?;
        owners.push(i as u32);
        power[i] += 1;
        calls += h;
    }
    Ok(Committee {
        owners,
        power,
        blake2b_calls: calls,
    })
}

/// One `cycle_era` from the context's `cycle_eras` list.
#[derive(Clone, Copy, Debug)]
pub struct CycleEra {
    pub first_level: i32,
    pub first_cycle: u32,
    pub blocks_per_cycle: i32,
}

impl CycleEra {
    /// (cycle, cycle_position) of a level inside this era, as in `Level_repr.level_from_raw_with_era`.
    pub fn level_info(&self, level: i32) -> Option<(u32, i32)> {
        let pos = level.checked_sub(self.first_level).filter(|p| *p >= 0)?;
        Some((
            self.first_cycle + (pos / self.blocks_per_cycle) as u32,
            pos % self.blocks_per_cycle,
        ))
    }
}

/// Context path (from the root, so with the "data" prefix) of a cycle entry, e.g. `random_seed`.
pub fn cycle_path(cycle: u32, name: &str) -> [Vec<u8>; 4] {
    [
        b"data".to_vec(),
        b"cycle".to_vec(),
        cycle.to_string().into_bytes(),
        name.as_bytes().to_vec(),
    ]
}

/// Proves and decodes a cycle's sampler state and seed against a context root.
pub fn verify_cycle(
    root: &Hash,
    state_proof: &Tree,
    seed_proof: &Tree,
    cycle: u32,
) -> Result<(SamplerState, Seed), Error> {
    let get = |tree: &Tree, name: &str| {
        let p = cycle_path(cycle, name);
        let refs = [
            p[0].as_slice(),
            p[1].as_slice(),
            p[2].as_slice(),
            p[3].as_slice(),
        ];
        verify_membership(root, tree, &refs).map_err(Error::Proof)
    };
    let state = SamplerState::decode(&get(state_proof, "delegate_sampler_state")?)?;
    let seed: Seed = get(seed_proof, "random_seed")?
        .try_into()
        .map_err(|_| Error::BadSeed)?;
    Ok((state, seed))
}
