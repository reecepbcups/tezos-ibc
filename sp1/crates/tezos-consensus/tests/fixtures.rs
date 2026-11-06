//! Hermetic tests against JSON dumped by fixtures/dump.py (sandbox + mainnet).

use serde_json::Value;
use tezos_consensus::attestation::PublicKey;
use tezos_consensus::rpc::attestation_from_rpc;
use tezos_consensus::{
    attested_predecessor, b58, chain_id_from_b58, verify_quorum, Attestation, BlockHeader,
    Committee, Error, Hash, Validator,
};

const FIXTURES: &[&str] = &[
    "quorum_993",
    "quorum_1009",
    "mainnet_quorum",
    "mainnet_quorum_dal",
];

struct Fx {
    raw: Value,
    chain_id: [u8; 4],
    header_n: BlockHeader,
    header_n1: BlockHeader,
    ops_n1: Vec<Hash>,
    attestations: Vec<Attestation>,
    committee: Committee,
    threshold: u64,
}

fn load(name: &str) -> Fx {
    let path = format!("{}/fixtures/{name}.json", env!("CARGO_MANIFEST_DIR"));
    let raw: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let header = |k: &str| BlockHeader::from_rpc_json(&raw[k].to_string()).unwrap();
    // Payload ops are the non-consensus passes 1..3.
    let ops_n1 = raw["operation_hashes_n1"].as_array().unwrap()[1..]
        .iter()
        .flat_map(|p| p.as_array().unwrap())
        .map(|h| b58::decode_fixed(h.as_str().unwrap(), b58::OPERATION_HASH).unwrap())
        .collect();
    let attestations = raw["attestations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| attestation_from_rpc(o).unwrap())
        .collect();
    let committee = raw["rights"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            let companion =
                r["companion_pk"]
                    .as_str()
                    .map(|s| match PublicKey::from_b58(s).unwrap() {
                        PublicKey::Bls(k) => k,
                        _ => panic!("companion not BLS"),
                    });
            let v = Validator {
                consensus_pk: PublicKey::from_b58(r["consensus_pk"].as_str().unwrap()).unwrap(),
                companion_pk: companion,
                power: r["attesting_power"].as_u64().unwrap(),
            };
            (r["first_slot"].as_u64().unwrap() as u16, v)
        })
        .collect();
    Fx {
        chain_id: chain_id_from_b58(raw["chain_id"].as_str().unwrap()).unwrap(),
        header_n: header("header_n"),
        header_n1: header("header_n1"),
        ops_n1,
        attestations,
        committee,
        threshold: raw["consensus_threshold_size"].as_u64().unwrap(),
        raw,
    }
}

fn b58_hash(v: &Value, prefix: &[u8]) -> Hash {
    b58::decode_fixed(v.as_str().unwrap(), prefix).unwrap()
}

#[test]
fn header_hashes_match_rpc() {
    for name in FIXTURES {
        let fx = load(name);
        for k in ["header_n", "header_n1"] {
            let h = BlockHeader::from_rpc_json(&fx.raw[k].to_string()).unwrap();
            assert_eq!(
                h.hash(),
                b58_hash(&fx.raw[k]["hash"], b58::BLOCK_HASH),
                "{name} {k}"
            );
        }
    }
}

#[test]
fn payload_hash_and_predecessor_link() {
    for name in FIXTURES {
        let fx = load(name);
        let pred = attested_predecessor(&fx.header_n1, &fx.ops_n1).unwrap();
        assert_eq!(pred, fx.header_n.hash(), "{name}");
    }
}

#[test]
fn attestation_encoding_matches_op_hash() {
    for name in FIXTURES {
        let fx = load(name);
        for (a, o) in fx
            .attestations
            .iter()
            .zip(fx.raw["attestations"].as_array().unwrap())
        {
            assert_eq!(
                a.hash(),
                b58_hash(&o["hash"], b58::OPERATION_HASH),
                "{name} {}",
                o["hash"]
            );
        }
    }
}

#[test]
fn quorum_accepts_real_attestations() {
    for name in FIXTURES {
        let fx = load(name);
        let power = verify_quorum(
            &fx.chain_id,
            &fx.header_n1,
            &fx.attestations,
            &fx.committee,
            fx.threshold,
        )
        .unwrap_or_else(|e| panic!("{name}: {e}"));
        let want: u64 = fx.committee.values().map(|v| v.power).sum();
        assert_eq!(power, want, "{name}");
        assert!(power >= fx.threshold);
    }
}

fn single_idx(atts: &[Attestation]) -> usize {
    atts.iter()
        .position(|a| matches!(a, Attestation::Single { .. }))
        .unwrap()
}

fn agg_idx(atts: &[Attestation]) -> usize {
    atts.iter()
        .position(|a| matches!(a, Attestation::Aggregate { .. }))
        .unwrap()
}

fn flip_sig(a: &mut Attestation) {
    match a {
        Attestation::Single { signature, .. } | Attestation::Aggregate { signature, .. } => {
            // Swap the signature for a different valid encoding: flip a bit in r/S for
            // single sigs; for BLS, a garbage point fails to decode or to verify.
            signature[5] ^= 1;
        }
    }
}

type Mutate = fn(&mut Fx);
type Expect = fn(&Error) -> bool;

#[test]
fn quorum_rejects_bad_input() {
    let cases: &[(&str, Mutate, Expect)] = &[
        (
            "tampered single sig",
            |fx| {
                let i = single_idx(&fx.attestations);
                flip_sig(&mut fx.attestations[i])
            },
            |e| *e == Error::BadSignature,
        ),
        (
            "tampered aggregate sig",
            |fx| {
                let i = agg_idx(&fx.attestations);
                flip_sig(&mut fx.attestations[i])
            },
            |e| *e == Error::BadSignature,
        ),
        (
            "wrong payload hash",
            |fx| fx.header_n1.payload_hash[0] ^= 1,
            |e| *e == Error::WrongPayloadHash,
        ),
        (
            "wrong level",
            |fx| fx.header_n1.level += 1,
            |e| matches!(e, Error::WrongLevel(_)),
        ),
        (
            "wrong round",
            |fx| *fx.header_n1.fitness[4].last_mut().unwrap() ^= 1,
            |e| matches!(e, Error::WrongRound(_)),
        ),
        (
            "duplicate delegate",
            |fx| {
                let a = fx.attestations[single_idx(&fx.attestations)].clone();
                fx.attestations.push(a);
            },
            |e| matches!(e, Error::DuplicateDelegate(_)),
        ),
        (
            "same key under two slots",
            |fx| {
                let (&slot, v) = fx
                    .committee
                    .iter()
                    .find(|(_, v)| !matches!(v.consensus_pk, PublicKey::Bls(_)))
                    .unwrap();
                let v = v.clone();
                // Point another single attestation's slot at the same key.
                let other = fx
                    .attestations
                    .iter()
                    .find_map(|a| match a {
                        Attestation::Single { slot: s, .. } if *s != slot => Some(*s),
                        _ => None,
                    })
                    .unwrap();
                fx.committee.insert(other, v);
            },
            |e| matches!(e, Error::DuplicateDelegate(_) | Error::BadSignature),
        ),
        (
            "below threshold",
            |fx| fx.threshold = fx.committee.values().map(|v| v.power).sum::<u64>() + 1,
            |e| matches!(e, Error::BelowThreshold { .. }),
        ),
        (
            "dropped attestations",
            |fx| {
                let i = agg_idx(&fx.attestations);
                fx.attestations = vec![fx.attestations[i].clone()];
            },
            |e| matches!(e, Error::BelowThreshold { .. }),
        ),
        (
            "unknown slot",
            |fx| {
                let Attestation::Single { slot, .. } =
                    &fx.attestations[single_idx(&fx.attestations)]
                else {
                    unreachable!()
                };
                let s = *slot;
                fx.committee.remove(&s);
            },
            |e| matches!(e, Error::UnknownSlot(_)),
        ),
        (
            "wrong key for slot",
            |fx| {
                let Attestation::Single { slot, .. } =
                    &fx.attestations[single_idx(&fx.attestations)]
                else {
                    unreachable!()
                };
                let s = *slot;
                let other = fx
                    .committee
                    .iter()
                    .find(|(k, v)| **k != s && matches!(v.consensus_pk, PublicKey::Ed25519(_)))
                    .unwrap()
                    .1
                    .clone();
                let v = fx.committee.get_mut(&s).unwrap();
                v.consensus_pk = other.consensus_pk;
            },
            |e| matches!(e, Error::BadSignature | Error::DuplicateDelegate(_)),
        ),
        (
            "wrong chain id",
            |fx| fx.chain_id[0] ^= 1,
            |e| *e == Error::BadSignature,
        ),
        (
            "non-BLS key in aggregate",
            |fx| {
                let Attestation::Aggregate { committee, .. } =
                    &fx.attestations[agg_idx(&fx.attestations)]
                else {
                    unreachable!()
                };
                let s = committee[0].slot;
                fx.committee.get_mut(&s).unwrap().consensus_pk = PublicKey::Ed25519([1; 32]);
            },
            |e| matches!(e, Error::NonBlsInAggregate(_)),
        ),
    ];
    for name in FIXTURES {
        for (case, mutate, ok) in cases {
            let mut fx = load(name);
            mutate(&mut fx);
            let err = verify_quorum(
                &fx.chain_id,
                &fx.header_n1,
                &fx.attestations,
                &fx.committee,
                fx.threshold,
            )
            .expect_err(&format!("{name}: {case} accepted"));
            assert!(ok(&err), "{name}: {case}: unexpected {err:?}");
        }
    }
}

#[test]
fn mainnet_dal_companion_is_required() {
    let mut fx = load("mainnet_quorum");
    let Attestation::Aggregate { committee, .. } = &fx.attestations[agg_idx(&fx.attestations)]
    else {
        unreachable!()
    };
    let s = committee.iter().find(|m| m.dal.is_some()).unwrap().slot;
    fx.committee.get_mut(&s).unwrap().companion_pk = None;
    let err = verify_quorum(
        &fx.chain_id,
        &fx.header_n1,
        &fx.attestations,
        &fx.committee,
        fx.threshold,
    )
    .unwrap_err();
    assert_eq!(err, Error::MissingCompanion(s));
}

#[test]
fn predecessor_link_rejects_tampering() {
    let cases: &[(&str, Mutate)] = &[
        ("forged predecessor", |fx| fx.header_n1.predecessor[0] ^= 1),
        ("forged payload round", |fx| fx.header_n1.payload_round += 1),
        ("extra op", |fx| fx.ops_n1.push([7; 32])),
        ("reordered ops", |fx| {
            if fx.ops_n1.len() >= 2 {
                fx.ops_n1.swap(0, 1)
            } else {
                fx.ops_n1.insert(0, [7; 32])
            }
        }),
    ];
    for name in FIXTURES {
        for (case, mutate) in cases {
            let mut fx = load(name);
            mutate(&mut fx);
            assert_eq!(
                attested_predecessor(&fx.header_n1, &fx.ops_n1),
                Err(Error::WrongPayloadHash),
                "{name}: {case}"
            );
        }
    }
}
