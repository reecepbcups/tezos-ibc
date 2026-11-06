//! Tezos light client update, the whole check the SP1 program runs. Kept as a plain
//! library so it is tested natively.
//!
//! Trust chain, from a trusted commit C_T (state after block T) to a new one:
//! 1. root_T opens C_T, and proves cycle(n+1)'s sampler state and seed.
//! 2. The sampled committee of level n+1 reaches quorum on H(n+1)'s payload.
//! 3. That payload commits to hash(H(n)), so H(n) is final and H(n).context is
//!    the commit of the state after n-1.
//! 4. Packet commitments are proven against that commit.
//!
//! The rules above are PsUshuai's, so `Config::protocol` is checked in every state they
//! depend on, and all bakers attest must not be active yet (it changes voting power).

use alloy_sol_types::SolValue;
use serde::{Deserialize, Serialize};
use tezos_consensus::{
    attested_predecessor, verify_quorum, Attestation, BlockHeader, Committee, Validator,
};
use tezos_merkle::{
    big_map_value_path, bytes_key_hash, commit_hash, decode_bytes32_leaf, verify_membership,
    verify_optional, verify_value, CommitInfo, Hash, Tree,
};
use tezos_sampler::{verify_cycle, CycleEra, SamplerState, Seed};

alloy_sol_types::sol! {
    /// Mirrors `TezosLightClient.Commitment`.
    #[derive(Debug, PartialEq, Eq)]
    struct Commitment {
        bytes path;
        bytes32 value;
    }

    /// Mirrors `TezosLightClient.PublicValues`, committed abi encoded.
    #[derive(Debug, PartialEq, Eq)]
    struct PublicValues {
        bytes32 chainId;
        uint64 bigMapId;
        uint64 trustedLevel;
        bytes32 trustedCommit;
        uint64 newLevel;
        bytes32 newCommit;
        uint64 newTimestamp;
        Commitment[] commitments;
    }
}

/// Chain constants. They are compiled into the program, so the vkey binds them.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub era: CycleEra,
    pub committee_size: u32,
    /// `consensus_threshold_size`, in slots
    pub threshold: u64,
    /// Protocol whose rules this client implements, as stored at the context's `protocol` key
    pub protocol: Hash,
    /// Shell header `proto` of blocks applied by `protocol`
    pub proto_level: u8,
}

/// PsUshuai9QapM5TGj1JpuVGkdxz5GykdnEvS6Rh8SUVrARvZLCY
pub const PS_USHUAI: Hash = [
    0x64, 0x50, 0x71, 0xcc, 0x22, 0x9b, 0xc3, 0x62, 0xac, 0x95, 0x96, 0x00, 0x30, 0xc4, 0xcf, 0xed,
    0xad, 0x42, 0x54, 0x8e, 0x32, 0xad, 0x7a, 0xda, 0xef, 0xd7, 0x00, 0x99, 0x81, 0x77, 0x9b, 0x51,
];

/// tezos/sandbox (gen-params.py): one era from level 1.
pub const SANDBOX: Config = Config {
    era: CycleEra {
        first_level: 1,
        first_cycle: 0,
        blocks_per_cycle: 16,
    },
    committee_size: 7000,
    threshold: 4667,
    protocol: PS_USHUAI,
    proto_level: 1,
};

/// Tezos mainnet, era from the Tallinn activation (blocks_per_cycle 10800 to 14400).
pub const MAINNET: Config = Config {
    era: CycleEra {
        first_level: 11640289,
        first_cycle: 1124,
        blocks_per_cycle: 14400,
    },
    committee_size: 7000,
    threshold: 4667,
    protocol: PS_USHUAI,
    proto_level: 25,
};

/// A packet commitment proof: ICS24 path and a context proof of its big_map entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentProof {
    pub path: Vec<u8>,
    pub proof: Tree,
}

/// Everything the program reads. Nothing here is trusted until `verify` links it to `trusted_commit`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Input {
    /// Chain id attestations are signed with
    pub chain_id: [u8; 4],
    pub big_map_id: u64,
    pub trusted_level: i32,
    /// Commit of the state after `trusted_level`, as stored by the Solidity client
    pub trusted_commit: Hash,
    pub trusted_root: Hash,
    pub trusted_info: CommitInfo,
    /// `cycle/<c>/delegate_sampler_state` and `random_seed` for the cycle of H(n+1), against `trusted_root`
    pub sampler_state_proof: Tree,
    pub seed_proof: Tree,
    /// `data/all_bakers_attest_first_level` against `trusted_root`, present or proven absent
    pub all_bakers_attest_proof: Tree,
    /// H(n+1)
    pub attested: BlockHeader,
    /// H(n+1)'s non-consensus operation hashes (passes 1..3, in order)
    pub attested_ops: Vec<Hash>,
    /// Attestations of H(n+1), from block n+2's consensus pass
    pub attestations: Vec<Attestation>,
    /// H(n)
    pub header: BlockHeader,
    /// H(n-1), only for its `proto`
    pub parent: BlockHeader,
    /// Root and commit info of the state after n-1, which H(n).context commits to
    pub new_root: Hash,
    pub new_info: CommitInfo,
    /// Any proof against `new_root`, for its `protocol` key
    pub new_state_proof: Tree,
    pub commitments: Vec<CommitmentProof>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    TrustedCommitMismatch,
    NegativeLevel,
    LevelOutsideEra(i32),
    CommitteeTooLarge,
    Sampler(tezos_sampler::Error),
    Consensus(tezos_consensus::Error),
    Merkle(tezos_merkle::Error),
    PredecessorMismatch,
    LevelGap,
    NotNewer,
    NewCommitMismatch,
    ParentMismatch,
    NegativeTimestamp,
    /// Named state's `protocol` isn't `Config::protocol`
    WrongProtocol(&'static str),
    /// Named header's `proto` isn't `Config::proto_level`, so a protocol switch is in play
    WrongProtoLevel(&'static str),
    /// All bakers attest is active from this level, which our quorum rules don't implement
    AllBakersAttest(i32),
    BadActivationLevel,
}

impl From<tezos_sampler::Error> for Error {
    fn from(e: tezos_sampler::Error) -> Self {
        Error::Sampler(e)
    }
}

impl From<tezos_consensus::Error> for Error {
    fn from(e: tezos_consensus::Error) -> Self {
        Error::Consensus(e)
    }
}

impl From<tezos_merkle::Error> for Error {
    fn from(e: tezos_merkle::Error) -> Self {
        Error::Merkle(e)
    }
}

/// Runs the full check and returns the values the program commits.
pub fn verify(cfg: &Config, input: &Input) -> Result<PublicValues, Error> {
    if commit_hash(&input.trusted_root, &input.trusted_info) != input.trusted_commit {
        return Err(Error::TrustedCommitMismatch);
    }
    // The trusted state feeds the sampler, so its protocol defines what the cycle data means.
    check_protocol(cfg, &input.trusted_root, &input.sampler_state_proof, "trusted")?;

    let level = input.attested.level;
    // The activation level is written with the sampler state of its cycle and never removed,
    // so if the trusted state lacks it, it is past every cycle we can sample from here.
    let activation = verify_optional(
        &input.trusted_root,
        &input.all_bakers_attest_proof,
        &[b"data", b"all_bakers_attest_first_level"],
    )?;
    if let Some(v) = activation {
        let first = activation_level(&v)?;
        if level >= first {
            return Err(Error::AllBakersAttest(first));
        }
    }

    // Committee of n+1 from the cycle data in the trusted state.
    let (cycle, pos) = cfg
        .era
        .level_info(level)
        .ok_or(Error::LevelOutsideEra(level))?;
    let (state, seed) = verify_cycle(
        &input.trusted_root,
        &input.sampler_state_proof,
        &input.seed_proof,
        cycle,
    )?;
    let committee = committee_at(&state, &seed, pos, cfg.committee_size)?;

    // Quorum on H(n+1)'s payload makes its predecessor, H(n), final.
    verify_quorum(
        &input.chain_id,
        &input.attested,
        &input.attestations,
        &committee,
        cfg.threshold,
    )?;
    let pred = attested_predecessor(&input.attested, &input.attested_ops)?;
    if input.header.hash() != pred {
        return Err(Error::PredecessorMismatch);
    }
    if input.header.level.checked_add(1) != Some(level) {
        return Err(Error::LevelGap);
    }
    // n+1 was applied by the state after n's protocol. The QC doesn't cover H(n+1).context
    // or proto, so get there from H(n): the shell bumps proto exactly when a block's result
    // has a new protocol, so equal proto means states n-1 and n share it (checked below).
    if input.parent.hash() != input.header.predecessor {
        return Err(Error::ParentMismatch);
    }
    for (h, name) in [(&input.header, "n"), (&input.parent, "n-1")] {
        if h.proto != cfg.proto_level {
            return Err(Error::WrongProtoLevel(name));
        }
    }
    // Best effort only: the QC doesn't cover H(n+1).proto, so a prover can set it.
    if input.attested.proto != cfg.proto_level {
        return Err(Error::WrongProtoLevel("n+1"));
    }

    // H(n).context is the commit of the state after n-1.
    let new_level = input.header.level - 1;
    if new_level < input.trusted_level {
        return Err(Error::NotNewer);
    }
    let new_commit = input.header.context;
    if commit_hash(&input.new_root, &input.new_info) != new_commit {
        return Err(Error::NewCommitMismatch);
    }
    // Commitments are read with this state's storage layout.
    check_protocol(cfg, &input.new_root, &input.new_state_proof, "new")?;

    let mut commitments = Vec::with_capacity(input.commitments.len());
    for c in &input.commitments {
        let path = big_map_value_path(input.big_map_id, &bytes_key_hash(&c.path));
        let refs: Vec<&[u8]> = path.iter().map(Vec::as_slice).collect();
        let leaf = verify_membership(&input.new_root, &c.proof, &refs)?;
        commitments.push(Commitment {
            path: c.path.clone().into(),
            value: decode_bytes32_leaf(&leaf)?.into(),
        });
    }

    let mut chain_id = [0u8; 32];
    chain_id[..4].copy_from_slice(&input.chain_id);
    Ok(PublicValues {
        chainId: chain_id.into(),
        bigMapId: input.big_map_id,
        trustedLevel: level_u64(input.trusted_level)?,
        trustedCommit: input.trusted_commit.into(),
        newLevel: level_u64(new_level)?,
        newCommit: new_commit.into(),
        // H(n) carries new_commit, so its time dates the new state for the trusting period.
        newTimestamp: u64::try_from(input.header.timestamp).map_err(|_| Error::NegativeTimestamp)?,
        commitments,
    })
}

/// `verify` then abi encode, which is what the program commits.
pub fn verify_encoded(cfg: &Config, input: &Input) -> Result<Vec<u8>, Error> {
    verify(cfg, input).map(|pv| pv.abi_encode())
}

/// Requires the root `protocol` key (raw 32 byte hash, lib_context `current_protocol_key`)
/// of the state `root` to be the pinned protocol.
fn check_protocol(cfg: &Config, root: &Hash, proof: &Tree, state: &'static str) -> Result<(), Error> {
    match verify_value(root, proof, &[b"protocol"], &cfg.protocol) {
        Err(tezos_merkle::Error::ValueMismatch) => Err(Error::WrongProtocol(state)),
        r => Ok(r?),
    }
}

/// Level_repr binary: level, level_position, cycle, cycle_position (int32 each), then a bool.
fn activation_level(v: &[u8]) -> Result<i32, Error> {
    if v.len() != 17 {
        return Err(Error::BadActivationLevel);
    }
    Ok(i32::from_be_bytes(v[..4].try_into().unwrap()))
}

fn level_u64(l: i32) -> Result<u64, Error> {
    u64::try_from(l).map_err(|_| Error::NegativeLevel)
}

/// Samples a level's slots and keys each delegate by its first slot, which is the slot
/// its attestations name.
pub fn committee_at(
    state: &SamplerState,
    seed: &Seed,
    cycle_position: i32,
    committee_size: u32,
) -> Result<Committee, Error> {
    if committee_size > u32::from(u16::MAX) + 1 {
        return Err(Error::CommitteeTooLarge);
    }
    let sampled = tezos_sampler::committee(state, seed, cycle_position, committee_size)?;
    let mut seen = vec![false; state.support.len()];
    let mut out = Committee::new();
    for (slot, &i) in sampled.owners.iter().enumerate() {
        let i = i as usize;
        if std::mem::replace(&mut seen[i], true) {
            continue;
        }
        let s = &state.support[i];
        out.insert(
            slot as u16,
            Validator {
                consensus_pk: public_key(&s.consensus_pk),
                companion_pk: s.companion_pk.map(|k| k.to_vec()),
                power: u64::from(sampled.power[i]),
            },
        );
    }
    Ok(out)
}

fn public_key(k: &tezos_sampler::PublicKey) -> tezos_consensus::PublicKey {
    use tezos_consensus::PublicKey as C;
    use tezos_sampler::PublicKey as S;
    match k {
        S::Ed25519(b) => C::Ed25519(*b),
        S::Secp256k1(b) => C::Secp256k1(b.to_vec()),
        S::P256(b) => C::P256(b.to_vec()),
        S::Bls(b) => C::Bls(b.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::MAINNET;

    // Checked against mainnet RPC helpers/current_level.
    #[test]
    fn mainnet_cycle_math() {
        let era = MAINNET.era;
        for (level, want) in [
            (11640289, Some((1124, 0))),
            (11640288, None),
            (15701088, Some((1405, 14399))),
            (15701089, Some((1406, 0))),
            (15702111, Some((1406, 1022))),
        ] {
            assert_eq!(era.level_info(level), want, "level {level}");
        }
    }
}
