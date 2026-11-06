//! Tezos (PsUshuai, protocol 025) consensus checks for a light client:
//! block header hashing, block payload hashes, attestation signatures and quorum.

pub mod attestation;
pub mod b58;
pub mod header;
pub mod payload;
pub mod quorum;
pub mod rpc;

pub use attestation::{Attestation, PublicKey};
pub use header::BlockHeader;
pub use payload::block_payload_hash;
pub use quorum::{attested_predecessor, verify_quorum, Committee, Validator};

pub type Hash = [u8; 32];

/// Wraps `$e` in an SP1 cycle tracker named `$name`, totals show up in the execution report.
/// Only prints in a zkVM build with the `profiling` feature, so tests and normal runs stay quiet.
#[macro_export]
macro_rules! track {
    ($name:literal, $e:expr) => {{
        if $crate::PROFILING {
            println!(concat!("cycle-tracker-report-start: ", $name));
        }
        let r = $e;
        if $crate::PROFILING {
            println!(concat!("cycle-tracker-report-end: ", $name));
        }
        r
    }};
}

/// Evaluated here, not at the macro's call site, so callers don't need their own feature check.
#[doc(hidden)]
pub const PROFILING: bool = cfg!(all(target_os = "zkvm", feature = "profiling"));

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Base58(String),
    Hex(String),
    Json(String),
    BadFitness,
    BadKey,
    BadSignature,
    /// tz4 attestations must come in an `attestations_aggregate` (validate.ml).
    BlsNotAggregated,
    NonBlsInAggregate(u16),
    EmptyAggregate,
    MissingCompanion(u16),
    UnknownSlot(u16),
    DuplicateDelegate(u16),
    WrongLevel(i32),
    WrongRound(i32),
    WrongPayloadHash,
    BelowThreshold {
        power: u64,
        threshold: u64,
    },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

/// blake2b-256 over the concatenation of `parts`.
pub fn blake2b256(parts: &[&[u8]]) -> Hash {
    use blake2::{digest::consts::U32, Blake2b, Digest};
    let mut h = Blake2b::<U32>::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Chain id bytes from its base58 form (e.g. `NetXdQprcVkpaWU` for mainnet).
pub fn chain_id_from_b58(s: &str) -> Result<[u8; 4], Error> {
    b58::decode_fixed(s, b58::CHAIN_ID)
}
