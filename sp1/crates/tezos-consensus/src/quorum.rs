//! Quorum check over the attestations of a block.
//!
//! Finality assumption (Tenderbake): attestations sign a *payload* hash, and the
//! payload hash of H(n+1) commits to `predecessor = hash(H(n))`. Once a quorum
//! (power >= threshold) attests H(n+1)'s payload, H(n) is final, so H(n).context
//! (the state root of n-1) can be trusted. H(n+1) itself is not final from this
//! alone: only its payload (and so its predecessor) is.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::attestation::{bls, bls_mode_bytes, verify_single, Attestation, PublicKey};
use crate::{block_payload_hash, BlockHeader, Error, Hash};

/// A delegate's rights at the attested level, keyed by its first (canonical) slot
/// in the committee map. Attestations name that slot, so slot -> key is what binds
/// a signature to a delegate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validator {
    pub consensus_pk: PublicKey,
    /// tz4 companion key (compressed G1), needed when a member attests DAL content.
    pub companion_pk: Option<Vec<u8>>,
    /// Attesting power (slots on mainnet today).
    pub power: u64,
}

/// first slot -> validator
pub type Committee = BTreeMap<u16, Validator>;

/// Checks that `attestations` form a quorum on `attested` (H(n+1)) and returns the summed power.
///
/// Every attestation must match H(n+1)'s level, round and payload hash and carry a valid
/// signature from the slot owner's consensus key. A slot or key counted twice is an error.
/// `threshold` is `consensus_threshold_size` (4667 on mainnet) while slots are the power unit.
pub fn verify_quorum(
    chain_id: &[u8; 4],
    attested: &BlockHeader,
    attestations: &[Attestation],
    committee: &Committee,
    threshold: u64,
) -> Result<u64, Error> {
    let round = attested.round()?;
    let mut seen_slots = BTreeSet::new();
    let mut seen_keys = BTreeSet::new();
    let mut power = 0u64;
    let mut count = |slot: u16| -> Result<&Validator, Error> {
        let v = committee.get(&slot).ok_or(Error::UnknownSlot(slot))?;
        if !seen_slots.insert(slot) || !seen_keys.insert(v.consensus_pk.clone()) {
            return Err(Error::DuplicateDelegate(slot));
        }
        power += v.power;
        Ok(v)
    };

    for att in attestations {
        let c = att.content();
        if c.level != attested.level {
            return Err(Error::WrongLevel(c.level));
        }
        if c.round != round {
            return Err(Error::WrongRound(c.round));
        }
        if c.block_payload_hash != attested.payload_hash {
            return Err(Error::WrongPayloadHash);
        }
        match att {
            Attestation::Single {
                slot, signature, ..
            } => {
                let v = count(*slot)?;
                verify_single(&v.consensus_pk, &att.signed_bytes(chain_id), signature)?;
            }
            Attestation::Aggregate {
                branch,
                content,
                committee: members,
                signature,
            } => crate::track!("bls_aggregate", {
                if members.is_empty() {
                    return Err(Error::EmptyAggregate);
                }
                let op = bls_mode_bytes(branch, content);
                let mut agg = bls12_381::G1Projective::identity();
                // Weighted companions are summed in one msm after the loop, it's much cheaper.
                let mut comps = Vec::new();
                let mut weights = Vec::new();
                for m in members {
                    let v = count(m.slot)?;
                    let PublicKey::Bls(pk) = &v.consensus_pk else {
                        return Err(Error::NonBlsInAggregate(m.slot));
                    };
                    agg += bls::g1(pk)?;
                    // DAL content makes the member sign with consensus + weight * companion.
                    if let Some(dal) = &m.dal {
                        let comp = v
                            .companion_pk
                            .as_ref()
                            .ok_or(Error::MissingCompanion(m.slot))?;
                        comps.push(bls::g1_affine(comp)?);
                        weights.push(bls::dal_weight(pk, comp, &op, dal));
                    }
                }
                agg += crate::track!("bls_dal_msm", bls::msm(&comps, &weights));
                let mut msg = vec![0x13];
                msg.extend_from_slice(chain_id);
                msg.extend_from_slice(&op);
                crate::track!("bls_pairing", bls::verify(&agg, &msg, signature))?;
            }),
        }
    }
    if power < threshold {
        return Err(Error::BelowThreshold { power, threshold });
    }
    Ok(power)
}

/// Given a trusted (quorum attested) H(n+1) and its non-consensus operation hashes
/// (passes 1..3 in order), returns H(n+1).predecessor after checking that the payload
/// hash commits to it. The caller then checks `hash(H(n)) == ` the result.
pub fn attested_predecessor(
    attested: &BlockHeader,
    non_consensus_ops: &[Hash],
) -> Result<Hash, Error> {
    let want = block_payload_hash(
        &attested.predecessor,
        attested.payload_round,
        non_consensus_ops,
    );
    if want != attested.payload_hash {
        return Err(Error::WrongPayloadHash);
    }
    Ok(attested.predecessor)
}
