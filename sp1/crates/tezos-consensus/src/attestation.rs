//! Attestation encodings and signature checks for PsUshuai.
//!
//! Sources (proto_025_PsUshuai/lib_protocol): operation_repr.ml (encodings,
//! `check_signature`, `Bls_mode`), validate.ml (`check_attestation_signature`,
//! `check_attestations_aggregate_signature`), dal_attestations_repr.ml
//! (`Dal_dependent_signing`). Curves: lib_crypto/{ed25519,secp256k1,p256,bls}.ml.

use serde::{Deserialize, Serialize};

use crate::{b58, blake2b256, Error, Hash};

/// Attestation watermark tag (operation_repr.ml `to_watermark`).
const ATTESTATION_WATERMARK: u8 = 0x13;
const TAG_ATTESTATION: u8 = 21;
const TAG_ATTESTATION_WITH_DAL: u8 = 23;
const TAG_ATTESTATIONS_AGGREGATE: u8 = 31;
/// `Bls_mode.attestation_case`: tz4 keys sign the content without slot or DAL bits.
const TAG_BLS_MODE_ATTESTATION: u8 = 41;
/// Bls12_381_signature.MinPk.Pop, used by lib_crypto/bls.ml `check`.
pub const BLS_POP_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusContent {
    pub level: i32,
    pub round: i32,
    pub block_payload_hash: Hash,
}

impl ConsensusContent {
    fn encode(&self, b: &mut Vec<u8>) {
        b.extend_from_slice(&self.level.to_be_bytes());
        b.extend_from_slice(&self.round.to_be_bytes());
        b.extend_from_slice(&self.block_payload_hash);
    }
}

/// A DAL attestation bitset as a little endian magnitude without trailing zeros.
pub type DalBits = Vec<u8>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeMember {
    pub slot: u16,
    pub dal: Option<DalBits>,
}

/// A consensus operation attesting a block, as found in pass 0 of the next block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Attestation {
    /// `attestation` / `attestation_with_dal`, signed by a tz1/tz2/tz3 consensus key.
    Single {
        branch: Hash,
        slot: u16,
        content: ConsensusContent,
        dal: Option<DalBits>,
        /// 64 bytes r ‖ s (or ed25519 R ‖ S).
        signature: Vec<u8>,
    },
    /// `attestations_aggregate`, one BLS signature over tz4 members.
    Aggregate {
        branch: Hash,
        content: ConsensusContent,
        committee: Vec<CommitteeMember>,
        signature: Vec<u8>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PublicKey {
    Ed25519([u8; 32]),
    Secp256k1(Vec<u8>),
    P256(Vec<u8>),
    /// Compressed G1 point (MinPk).
    Bls(Vec<u8>),
}

impl PublicKey {
    pub fn from_b58(s: &str) -> Result<Self, Error> {
        if let Ok(k) = b58::decode_fixed(s, b58::ED25519_PK) {
            return Ok(PublicKey::Ed25519(k));
        }
        for (prefix, len, mk) in [
            (
                b58::SECP256K1_PK,
                33,
                PublicKey::Secp256k1 as fn(Vec<u8>) -> PublicKey,
            ),
            (b58::P256_PK, 33, PublicKey::P256),
            (b58::BLS_PK, 48, PublicKey::Bls),
        ] {
            if let Ok(k) = b58::decode_prefixed(s, prefix) {
                if k.len() == len {
                    return Ok(mk(k));
                }
            }
        }
        Err(Error::Base58(s.into()))
    }
}

/// Data_encoding `Z.t` (zarith): 6 data bits + sign in the first byte, then 7 bits per byte.
fn encode_zarith_nat(mag: &[u8], b: &mut Vec<u8>) {
    let bits = mag.len() * 8;
    let bit = |i: usize| i < bits && (mag[i / 8] >> (i % 8)) & 1 == 1;
    let take =
        |from: usize, n: usize| (0..n).fold(0u8, |acc, k| acc | ((bit(from + k) as u8) << k));
    let rest_nonzero = |from: usize| (from..bits).any(bit);
    let mut pos = 6;
    let mut byte = take(0, 6);
    loop {
        if !rest_nonzero(pos) {
            b.push(byte);
            return;
        }
        b.push(byte | 0x80);
        byte = take(pos, 7);
        pos += 7;
    }
}

/// Zarith `Z.to_bits`: little endian limbs, so the length is a multiple of 8 (empty for 0).
fn z_to_bits(mag: &[u8]) -> Vec<u8> {
    let mut v = mag.to_vec();
    v.resize(mag.len().div_ceil(8) * 8, 0);
    v
}

/// Parses a decimal natural number to a little endian magnitude without trailing zeros.
pub fn dal_bits_from_decimal(s: &str) -> Result<DalBits, Error> {
    let mut mag: Vec<u8> = Vec::new();
    for c in s.bytes() {
        if !c.is_ascii_digit() {
            return Err(Error::Json(format!("bad dal_attestation {s}")));
        }
        let mut carry = (c - b'0') as u16;
        for byte in mag.iter_mut() {
            let v = *byte as u16 * 10 + carry;
            *byte = v as u8;
            carry = v >> 8;
        }
        if carry > 0 {
            mag.push(carry as u8);
        }
    }
    Ok(mag)
}

impl Attestation {
    pub fn content(&self) -> &ConsensusContent {
        match self {
            Attestation::Single { content, .. } | Attestation::Aggregate { content, .. } => content,
        }
    }

    pub fn branch(&self) -> &Hash {
        match self {
            Attestation::Single { branch, .. } | Attestation::Aggregate { branch, .. } => branch,
        }
    }

    /// Unsigned contents as in `operation.unsigned` (no shell, no signature).
    fn encode_contents(&self, b: &mut Vec<u8>) {
        match self {
            Attestation::Single {
                slot, content, dal, ..
            } => {
                b.push(if dal.is_some() {
                    TAG_ATTESTATION_WITH_DAL
                } else {
                    TAG_ATTESTATION
                });
                b.extend_from_slice(&slot.to_be_bytes());
                content.encode(b);
                if let Some(d) = dal {
                    encode_zarith_nat(d, b);
                }
            }
            Attestation::Aggregate {
                content, committee, ..
            } => {
                b.push(TAG_ATTESTATIONS_AGGREGATE);
                content.encode(b);
                let mut c = Vec::new();
                for m in committee {
                    c.extend_from_slice(&m.slot.to_be_bytes());
                    match &m.dal {
                        Some(d) => {
                            c.push(0xff);
                            encode_zarith_nat(d, &mut c);
                        }
                        None => c.push(0),
                    }
                }
                b.extend_from_slice(&(c.len() as u32).to_be_bytes());
                b.extend_from_slice(&c);
            }
        }
    }

    /// Operation hash: blake2b(branch ‖ contents ‖ signature).
    pub fn hash(&self) -> Hash {
        let mut b = self.branch().to_vec();
        self.encode_contents(&mut b);
        match self {
            Attestation::Single { signature, .. } => b.extend_from_slice(signature),
            Attestation::Aggregate { signature, .. } => {
                // 96 byte BLS sigs: a pseudo content `0xff ‖ 0x03 (Bls_prefix) ‖ sig[..32]`, then the 64 byte suffix.
                b.extend_from_slice(&[0xff, 0x03]);
                b.extend_from_slice(signature);
            }
        }
        blake2b256(&[&b])
    }

    /// Bytes signed by a non-BLS key: watermark ‖ branch ‖ contents.
    pub fn signed_bytes(&self, chain_id: &[u8; 4]) -> Vec<u8> {
        let mut b = vec![ATTESTATION_WATERMARK];
        b.extend_from_slice(chain_id);
        b.extend_from_slice(self.branch());
        self.encode_contents(&mut b);
        b
    }
}

/// `serialize_unsigned_operation bls_mode_unsigned_encoding`: branch ‖ 41 ‖ level ‖ round ‖ payload hash.
/// Every tz4 member signs this same message, which is what allows a plain aggregate.
pub fn bls_mode_bytes(branch: &Hash, content: &ConsensusContent) -> Vec<u8> {
    let mut b = branch.to_vec();
    b.push(TAG_BLS_MODE_ATTESTATION);
    content.encode(&mut b);
    b
}

/// Verifies a tz1/tz2/tz3 signature. Tezos signs blake2b-256(watermark ‖ bytes) on all three curves.
pub fn verify_single(pk: &PublicKey, signed_bytes: &[u8], sig: &[u8]) -> Result<(), Error> {
    let digest = blake2b256(&[signed_bytes]);
    let ok = match pk {
        PublicKey::Ed25519(k) => {
            use ed25519_dalek::Verifier;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(k).map_err(|_| Error::BadKey)?;
            let s = ed25519_dalek::Signature::from_slice(sig).map_err(|_| Error::BadSignature)?;
            vk.verify(&digest, &s).is_ok()
        }
        PublicKey::Secp256k1(k) => {
            use k256::ecdsa::signature::hazmat::PrehashVerifier;
            let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(k).map_err(|_| Error::BadKey)?;
            // k256 rejects high-s like libsecp256k1 does.
            let s = k256::ecdsa::Signature::from_slice(sig).map_err(|_| Error::BadSignature)?;
            vk.verify_prehash(&digest, &s).is_ok()
        }
        PublicKey::P256(k) => {
            use p256::ecdsa::signature::hazmat::PrehashVerifier;
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(k).map_err(|_| Error::BadKey)?;
            let s = p256::ecdsa::Signature::from_slice(sig).map_err(|_| Error::BadSignature)?;
            vk.verify_prehash(&digest, &s).is_ok()
        }
        PublicKey::Bls(_) => return Err(Error::BlsNotAggregated),
    };
    if ok {
        Ok(())
    } else {
        Err(Error::BadSignature)
    }
}

pub(crate) mod bls {
    use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
    use bls12_381::{
        multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, Scalar,
    };

    use super::*;

    pub fn g1(bytes: &[u8]) -> Result<G1Projective, Error> {
        let arr: [u8; 48] = bytes.try_into().map_err(|_| Error::BadKey)?;
        Option::<G1Affine>::from(G1Affine::from_compressed(&arr))
            .map(G1Projective::from)
            .ok_or(Error::BadKey)
    }

    /// Bls.Public_key.hash: blake2b-160 of the compressed key.
    fn pkh(pk: &[u8]) -> [u8; 20] {
        use blake2::{digest::consts::U20, Blake2b, Digest};
        Blake2b::<U20>::digest(pk).into()
    }

    /// `Dal_dependent_signing.weight`: blake2b(pkh(consensus) ‖ pkh(companion) ‖ op ‖ Z.to_bits(dal))
    /// read as a little endian integer, reduced mod r.
    pub fn dal_weight(consensus_pk: &[u8], companion_pk: &[u8], op: &[u8], dal: &[u8]) -> Scalar {
        let h = blake2b256(&[&pkh(consensus_pk), &pkh(companion_pk), op, &z_to_bits(dal)]);
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&h);
        Scalar::from_bytes_wide(&wide)
    }

    /// MinPk Pop verify: e(pk, H(msg)) == e(g1, sig).
    pub fn verify(pk: &G1Projective, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        let sig: [u8; 96] = sig.try_into().map_err(|_| Error::BadSignature)?;
        let sig: G2Affine =
            Option::<G2Affine>::from(G2Affine::from_compressed(&sig)).ok_or(Error::BadSignature)?;
        let pk = G1Affine::from(pk);
        if bool::from(pk.is_identity()) {
            return Err(Error::BadKey);
        }
        #[cfg(not(target_os = "zkvm"))]
        let h = <G2Projective as HashToCurve<ExpandMsgXmd<sha2_09::Sha256>>>::hash_to_curve(
            msg,
            BLS_POP_DST,
        );
        // The SP1 patch takes digest 0.10 hashers and iterator messages.
        #[cfg(target_os = "zkvm")]
        let h = <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
            [msg],
            BLS_POP_DST,
        );
        let gt = multi_miller_loop(&[
            (&pk, &G2Prepared::from(G2Affine::from(h))),
            (&-G1Affine::generator(), &G2Prepared::from(sig)),
        ])
        .final_exponentiation();
        if gt == Gt::identity() {
            Ok(())
        } else {
            Err(Error::BadSignature)
        }
    }
}
