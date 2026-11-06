//! Base58check prefixes from octez src/lib_crypto/base58.ml.

use crate::Error;

pub const BLOCK_HASH: &[u8] = &[1, 52];
pub const OPERATION_HASH: &[u8] = &[5, 116];
pub const OPERATION_LIST_LIST_HASH: &[u8] = &[29, 159, 109];
pub const CONTEXT_HASH: &[u8] = &[79, 199];
pub const PAYLOAD_HASH: &[u8] = &[1, 106, 242];
pub const NONCE_HASH: &[u8] = &[69, 220, 169];
pub const CHAIN_ID: &[u8] = &[87, 82, 0];
pub const ED25519_PK: &[u8] = &[13, 15, 37, 217];
pub const SECP256K1_PK: &[u8] = &[3, 254, 226, 86];
pub const P256_PK: &[u8] = &[3, 178, 139, 127];
pub const BLS_PK: &[u8] = &[6, 149, 135, 204];
pub const GENERIC_SIG: &[u8] = &[4, 130, 43];
pub const ED25519_SIG: &[u8] = &[9, 245, 205, 134, 18];
pub const SECP256K1_SIG: &[u8] = &[13, 115, 101, 19, 63];
pub const P256_SIG: &[u8] = &[54, 240, 44, 52];
pub const BLS_SIG: &[u8] = &[40, 171, 64, 207];

/// Decodes a base58check string, returning the payload if it has `prefix`.
pub fn decode_prefixed(s: &str, prefix: &[u8]) -> Result<Vec<u8>, Error> {
    let raw = bs58::decode(s)
        .with_check(None)
        .into_vec()
        .map_err(|_| Error::Base58(s.into()))?;
    match raw.strip_prefix(prefix) {
        Some(p) => Ok(p.to_vec()),
        None => Err(Error::Base58(s.into())),
    }
}

/// Like [`decode_prefixed`] but for fixed size payloads (hashes).
pub fn decode_fixed<const N: usize>(s: &str, prefix: &[u8]) -> Result<[u8; N], Error> {
    decode_prefixed(s, prefix)?
        .try_into()
        .map_err(|_| Error::Base58(s.into()))
}

pub fn encode(prefix: &[u8], payload: &[u8]) -> String {
    let mut v = prefix.to_vec();
    v.extend_from_slice(payload);
    bs58::encode(v).with_check().into_string()
}

/// Decodes any signature form (sig, edsig, spsig1, p2sig, BLsig) to raw bytes.
pub fn decode_signature(s: &str) -> Result<Vec<u8>, Error> {
    for (prefix, len) in [
        (GENERIC_SIG, 64),
        (ED25519_SIG, 64),
        (SECP256K1_SIG, 64),
        (P256_SIG, 64),
        (BLS_SIG, 96),
    ] {
        if let Ok(p) = decode_prefixed(s, prefix) {
            if p.len() == len {
                return Ok(p);
            }
        }
    }
    Err(Error::Base58(s.into()))
}
