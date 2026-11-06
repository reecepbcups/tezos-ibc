// Full update checks against a real input dumped by the relayer (DUMP_INPUT) from the sandbox.
// The fixture has 6 single attestations plus a tz4 aggregate, and one packet commitment (seq 2).
use alloy_sol_types::SolValue;
use tezos_consensus::{Attestation, Error as ConsensusError};
use tezos_lc::*;
use tezos_merkle::{commit_hash, Error as MerkleError, Tree};

fn input() -> Input {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/update.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn rejects(f: impl FnOnce(&mut Input)) -> Error {
    let mut i = input();
    f(&mut i);
    verify(&SANDBOX, &i).unwrap_err()
}

/// Flips the first leaf value in a proof tree.
fn tamper_leaf(t: &mut Tree) -> bool {
    match t {
        Tree::Value(v) => {
            *v.last_mut().unwrap() ^= 1;
            true
        }
        Tree::Node(entries) => entries.iter_mut().any(|(_, c)| tamper_leaf(c)),
        _ => false,
    }
}

#[test]
fn accepts_live_update() {
    let i = input();
    let pv = verify(&SANDBOX, &i).unwrap();
    assert_eq!(&pv.chainId[..4], &i.chain_id);
    assert!(pv.chainId[4..].iter().all(|b| *b == 0));
    assert_eq!(pv.bigMapId, i.big_map_id);
    assert_eq!(pv.trustedLevel, i.trusted_level as u64);
    assert_eq!(pv.newLevel, (i.attested.level - 2) as u64);
    assert_eq!(pv.newCommit.0, i.header.context);
    assert_eq!(pv.newTimestamp, i.header.timestamp as u64);
    assert_eq!(pv.commitments.len(), 1);
    let mut path = b"eth-0\x01".to_vec();
    path.extend(2u64.to_be_bytes());
    assert_eq!(pv.commitments[0].path.to_vec(), path);
    assert!(!pv.commitments[0].value.is_zero());
    // Same bytes the program commits, and they decode as the Solidity struct.
    let enc = verify_encoded(&SANDBOX, &i).unwrap();
    assert_eq!(PublicValues::abi_decode(&enc).unwrap(), pv);
}

#[test]
fn wrong_trusted_commit() {
    let e = rejects(|i| i.trusted_commit[0] ^= 1);
    assert_eq!(e, Error::TrustedCommitMismatch);
}

#[test]
fn trusted_root_from_another_state() {
    // A root that doesn't open trusted_commit can't feed the sampler.
    let e = rejects(|i| i.trusted_root[31] ^= 1);
    assert_eq!(e, Error::TrustedCommitMismatch);
}

#[test]
fn header_not_attested_predecessor() {
    let e = rejects(|i| i.header.timestamp += 1);
    assert_eq!(e, Error::PredecessorMismatch);
}

#[test]
fn below_quorum() {
    let e = rejects(|i| {
        i.attestations.truncate(2);
        i.slots = quorum_slots(&SANDBOX, i).unwrap();
    });
    assert!(
        matches!(e, Error::Consensus(ConsensusError::BelowThreshold { .. })),
        "{e:?}"
    );
}

fn below_by_one(e: &Error) -> bool {
    *e == Error::Consensus(ConsensusError::BelowThreshold {
        power: SANDBOX.threshold - 1,
        threshold: SANDBOX.threshold,
    })
}

/// Index of a single attestation, whose slots are listed in `Input::slots`.
fn single_with_listed_slots(i: &Input) -> usize {
    i.attestations
        .iter()
        .position(|a| matches!(a, Attestation::Single { .. }))
        .unwrap()
}

#[test]
fn counted_slots() {
    type Mutate = fn(&mut Input);
    type Expect = fn(&Error) -> bool;
    let rejected: &[(&str, Mutate, Expect)] = &[
        (
            "duplicate slot",
            |i| i.slots[1] = i.slots[0],
            |e| *e == Error::SlotsNotIncreasing,
        ),
        (
            "unsorted",
            |i| i.slots.swap(0, 1),
            |e| *e == Error::SlotsNotIncreasing,
        ),
        (
            "slot past committee",
            |i| i.slots.push(SANDBOX.committee_size as u16),
            |e| *e == Error::SlotOutOfRange(SANDBOX.committee_size as u16),
        ),
        (
            "named slot past committee",
            |i| match &mut i.attestations[0] {
                Attestation::Single { slot, .. } => *slot = 7000,
                Attestation::Aggregate { committee, .. } => committee[0].slot = 7000,
            },
            |e| *e == Error::SlotOutOfRange(7000),
        ),
        // Its owner's slots stay listed, so they're now owned by a non-signer.
        (
            "signer dropped",
            |i| {
                i.attestations.remove(single_with_listed_slots(i));
            },
            |e| matches!(e, Error::SlotNotSigned(_)),
        ),
        (
            "signer's signature invalid",
            |i| {
                let k = single_with_listed_slots(i);
                match &mut i.attestations[k] {
                    Attestation::Single { signature, .. } => signature[3] ^= 1,
                    _ => unreachable!(),
                }
            },
            |e| *e == Error::Consensus(ConsensusError::BadSignature),
        ),
        ("threshold minus one", |i| drop(i.slots.pop()), below_by_one),
        (
            "no slots",
            |i| i.slots.clear(),
            |e| {
                matches!(
                    e,
                    Error::Consensus(ConsensusError::BelowThreshold { power: 0, .. })
                )
            },
        ),
    ];
    for (name, mutate, ok) in rejected {
        let e = rejects(mutate);
        assert!(ok(&e), "{name}: {e:?}");
    }

    let base = input();
    assert_eq!(
        base.slots.len() as u64,
        SANDBOX.threshold,
        "fixture lists exactly threshold"
    );
    // Every signer slot, more than needed, is fine too.
    let mut all = base.clone();
    all.slots = (0..SANDBOX.committee_size as u16).collect();
    verify(&SANDBOX, &all).unwrap();
}

#[test]
fn forged_signature() {
    let e = rejects(|i| match &mut i.attestations[0] {
        Attestation::Single { signature, .. } | Attestation::Aggregate { signature, .. } => {
            signature[10] ^= 1
        }
    });
    assert_eq!(e, Error::Consensus(ConsensusError::BadSignature));
}

#[test]
fn wrong_chain_id() {
    let e = rejects(|i| i.chain_id[0] ^= 1);
    assert_eq!(e, Error::Consensus(ConsensusError::BadSignature));
}

#[test]
fn tampered_attested_ops() {
    // Ops of n+1 must hash into the attested payload.
    let e = rejects(|i| i.attested_ops.push([7; 32]));
    assert_eq!(e, Error::Consensus(ConsensusError::WrongPayloadHash));
}

#[test]
fn sampler_from_wrong_cycle() {
    // Claiming n+1 in another cycle needs that cycle's proof, which this one isn't.
    let e = rejects(|i| i.attested.level += SANDBOX.era.blocks_per_cycle);
    assert!(matches!(e, Error::Sampler(_)), "{e:?}");
}

#[test]
fn wrong_big_map_id() {
    let e = rejects(|i| i.big_map_id += 1);
    assert_eq!(e, Error::Merkle(MerkleError::PathNotFound));
}

#[test]
fn tampered_commitment() {
    let e = rejects(|i| assert!(tamper_leaf(&mut i.commitments[0].proof)));
    assert_eq!(e, Error::Merkle(MerkleError::RootMismatch));
}

#[test]
fn commitment_path_swapped() {
    let e = rejects(|i| *i.commitments[0].path.last_mut().unwrap() = 3);
    assert_eq!(e, Error::Merkle(MerkleError::PathNotFound));
}

#[test]
fn new_root_not_committed() {
    let e = rejects(|i| i.new_info.timestamp += 1);
    assert_eq!(e, Error::NewCommitMismatch);
}

#[test]
fn not_newer_than_trusted() {
    let e = rejects(|i| i.trusted_level = i.header.level);
    assert_eq!(e, Error::NotNewer);
}

#[test]
fn wrong_protocol_pin() {
    let cfg = Config { protocol: [7; 32], ..SANDBOX };
    assert_eq!(verify(&cfg, &input()).unwrap_err(), Error::WrongProtocol("trusted"));
}

/// Points the root `protocol` entry at another protocol's contents hash.
fn claim_protocol(t: &mut Tree, protocol: [u8; 32]) {
    let Tree::Node(es) = t else { panic!("root not a node") };
    let (_, p) = es.iter_mut().find(|(s, _)| s == b"protocol").unwrap();
    *p = Tree::Value(protocol.to_vec());
}

#[test]
fn tampered_protocol_proof() {
    // A proof claiming the pinned protocol for a state that runs another one can't open its root.
    let other = Config { protocol: [7; 32], ..SANDBOX };
    let mut i = input();
    claim_protocol(&mut i.sampler_state_proof, other.protocol);
    assert_eq!(verify(&other, &i).unwrap_err(), Error::Merkle(MerkleError::RootMismatch));
    let mut i = input();
    claim_protocol(&mut i.new_state_proof, [7; 32]);
    assert_eq!(verify(&SANDBOX, &i).unwrap_err(), Error::Merkle(MerkleError::RootMismatch));
}

#[test]
fn new_state_proof_from_another_state() {
    let e = rejects(|i| i.new_state_proof = i.sampler_state_proof.clone());
    assert_eq!(e, Error::Merkle(MerkleError::RootMismatch));
}

#[test]
fn parent_not_linked() {
    // H(n-1).proto is what shows n+1 ran on the pinned protocol, so it must be the real parent.
    let e = rejects(|i| i.parent.proto += 1);
    assert_eq!(e, Error::ParentMismatch);
}

/// Rebuilds the trusted state with `data/all_bakers_attest_first_level` set to `level`,
/// keeping every trusted proof consistent with the new root.
fn activate_all_bakers_attest(i: &mut Input, level: i32) {
    // Level_repr: level, level_position, cycle, cycle_position, expected_commitment
    let mut v = level.to_be_bytes().to_vec();
    v.extend([0; 12]);
    v.push(0);
    for t in [
        &mut i.sampler_state_proof,
        &mut i.seed_proof,
        &mut i.all_bakers_attest_proof,
    ] {
        let Tree::Node(root) = t else { panic!("root not a node") };
        let (_, data) = root.iter_mut().find(|(s, _)| s == b"data").unwrap();
        let Tree::Node(es) = data else { panic!("data not a node") };
        es.push((b"all_bakers_attest_first_level".to_vec(), Tree::Value(v.clone())));
    }
    i.trusted_root = i.sampler_state_proof.hash().unwrap().1;
    i.trusted_commit = commit_hash(&i.trusted_root, &i.trusted_info);
}

#[test]
fn all_bakers_attest_activation() {
    let attested = input().attested.level;
    for (first, want) in [
        (attested - 100, Err(Error::AllBakersAttest(attested - 100))),
        (attested, Err(Error::AllBakersAttest(attested))),
        (attested + 1, Ok(())),
    ] {
        let mut i = input();
        activate_all_bakers_attest(&mut i, first);
        assert_eq!(verify(&SANDBOX, &i).map(|_| ()), want, "first level {first}");
    }
}

#[test]
fn all_bakers_attest_hidden() {
    // The old proof lists data/ without the key, which no longer hashes to the trusted root.
    let mut i = input();
    let absent = i.all_bakers_attest_proof.clone();
    let level = i.attested.level;
    activate_all_bakers_attest(&mut i, level);
    i.all_bakers_attest_proof = absent;
    assert_eq!(verify(&SANDBOX, &i).unwrap_err(), Error::Merkle(MerkleError::RootMismatch));
}

#[test]
fn all_bakers_attest_blinded() {
    // Present but blinded can't be read, so it can't pass as absent.
    let mut i = input();
    let level = i.attested.level;
    activate_all_bakers_attest(&mut i, level);
    let Tree::Node(root) = &mut i.all_bakers_attest_proof else { panic!() };
    let (_, data) = root.iter_mut().find(|(s, _)| s == b"data").unwrap();
    let Tree::Node(es) = data else { panic!() };
    let (_, v) = es.iter_mut().find(|(s, _)| s == b"all_bakers_attest_first_level").unwrap();
    *v = Tree::BlindedValue(v.hash().unwrap().1);
    assert_eq!(verify(&SANDBOX, &i).unwrap_err(), Error::Merkle(MerkleError::NotAValue));
}

#[test]
fn wrong_proto_level() {
    // H(n+1).proto isn't covered by the QC, so tampering it reaches the pin check.
    let e = rejects(|i| i.attested.proto += 1);
    assert_eq!(e, Error::WrongProtoLevel("n+1"));
    let e = rejects(|i| i.header.proto += 1);
    assert_eq!(e, Error::PredecessorMismatch);
}

#[test]
fn final_header_on_other_proto_level() {
    // H(n+1).proto matches the pin, but the final H(n) (and H(n-1)) sit on another level.
    // H(n) is hash linked, so a pin the real chain doesn't meet stands in for a wrong H(n).
    let cfg = Config { proto_level: 2, ..SANDBOX };
    let mut i = input();
    i.attested.proto = 2;
    assert_eq!(verify(&cfg, &i).unwrap_err(), Error::WrongProtoLevel("n"));
}

#[test]
fn proto_levels_ok_but_state_protocol_wrong() {
    // Every header proto matches, the context protocol proof alone rejects.
    let i = input();
    assert!([&i.parent, &i.header, &i.attested].iter().all(|h| h.proto == SANDBOX.proto_level));
    let cfg = Config { protocol: [7; 32], ..SANDBOX };
    assert_eq!(verify(&cfg, &i).unwrap_err(), Error::WrongProtocol("trusted"));
    let mut i = input();
    claim_protocol(&mut i.new_state_proof, [7; 32]);
    assert_eq!(verify(&SANDBOX, &i).unwrap_err(), Error::Merkle(MerkleError::RootMismatch));
}

#[test]
fn all_bakers_attest_parent_blinded() {
    // A blinded data/ hides its entries, so it can't prove absence.
    let mut i = input();
    let Tree::Node(root) = &mut i.all_bakers_attest_proof else { panic!() };
    let (_, data) = root.iter_mut().find(|(s, _)| s == b"data").unwrap();
    *data = Tree::BlindedNode(data.hash().unwrap().1);
    assert_eq!(verify(&SANDBOX, &i).unwrap_err(), Error::Merkle(MerkleError::PathNotFound));
}

// Mainnet update dumped by `relayer profile` (attested 15703487, no commitments): 75 singles
// plus a 63 member aggregate, every member with DAL content.
#[test]
fn accepts_mainnet_update() {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/mainnet_update.json");
    let i: Input = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    let pv = verify(&MAINNET, &i).unwrap();
    assert_eq!(pv.newLevel, (i.attested.level - 2) as u64);
    assert_eq!(pv.newCommit.0, i.header.context);
    assert!(pv.commitments.is_empty());
}
