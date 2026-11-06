// Checks slot sampling against `helpers/validators` and the sampler/seed Merkle proofs,
// all dumped from the sandbox by fixtures/dump.py.
use sha2::Digest as _;
use std::collections::BTreeMap;
use std::sync::OnceLock;
use tezos_merkle::{
    commit_hash, decode_context_hash, CommitInfo, Error as MerkleError, Hash, Tree,
};
use tezos_sampler::*;

const COMMITTEE: u32 = 7000;
// sandbox has a single era from level 1 with 16 blocks per cycle
const ERA: CycleEra = CycleEra {
    first_level: 1,
    first_cycle: 0,
    blocks_per_cycle: 16,
};

fn fixture() -> &'static serde_json::Value {
    static F: OnceLock<serde_json::Value> = OnceLock::new();
    F.get_or_init(|| {
        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/sandbox.json");
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    })
}

fn cycles() -> Vec<u32> {
    fixture()["cycles"]
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.parse().unwrap())
        .collect()
}

fn cyc(c: u32) -> &'static serde_json::Value {
    &fixture()["cycles"][c.to_string()]
}

fn raw_state(c: u32) -> Vec<u8> {
    hex::decode(cyc(c)["sampler_state"].as_str().unwrap()).unwrap()
}

fn seed(c: u32) -> Seed {
    hex::decode(cyc(c)["random_seed"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn b58_pkh(pkh: &Pkh) -> String {
    let prefix: [u8; 3] = [6, 161, [159, 161, 164, 166][pkh.tag as usize]];
    let mut data = prefix.to_vec();
    data.extend(pkh.hash);
    let check = sha2::Sha256::digest(sha2::Sha256::digest(&data));
    data.extend(&check[..4]);
    bs58::encode(data).into_string()
}

/// Ground truth for a level: consensus key pkh -> slots.
fn expected(c: u32, level: &str) -> BTreeMap<String, Vec<u32>> {
    let v = cyc(c)["validators"][level].as_object().unwrap();
    v.iter()
        .map(|(k, s)| {
            (
                k.clone(),
                s.as_array()
                    .unwrap()
                    .iter()
                    .map(|x| x.as_u64().unwrap() as u32)
                    .collect(),
            )
        })
        .collect()
}

fn computed(
    state: &SamplerState,
    seed: &Seed,
    pos: i32,
) -> (BTreeMap<String, Vec<u32>>, Committee) {
    let com = committee(state, seed, pos, COMMITTEE).unwrap();
    let mut m: BTreeMap<String, Vec<u32>> = BTreeMap::new();
    for (slot, &i) in com.owners.iter().enumerate() {
        m.entry(b58_pkh(&state.support[i as usize].consensus_pk.hash()))
            .or_default()
            .push(slot as u32);
    }
    (m, com)
}

#[test]
fn every_level_matches_validators_rpc() {
    let mut levels = 0;
    for c in cycles() {
        let state = SamplerState::decode(&raw_state(c)).unwrap();
        for level in cyc(c)["validators"].as_object().unwrap().keys() {
            let (lc, pos) = ERA.level_info(level.parse().unwrap()).unwrap();
            assert_eq!(lc, c, "level {level} sits in cycle {c}");
            let (got, com) = computed(&state, &seed(c), pos);
            assert_eq!(got, expected(c, level), "level {level}");
            assert_eq!(com.power.iter().sum::<u32>(), COMMITTEE);
            // one draw state per slot, rehash only after a rare rejection
            assert!(
                com.blake2b_calls >= COMMITTEE && com.blake2b_calls < COMMITTEE + 10,
                "{}",
                com.blake2b_calls
            );
            levels += 1;
        }
    }
    assert!(
        levels >= 32 && cycles().len() >= 2,
        "need many levels over 2+ cycles, got {levels}"
    );
}

#[test]
fn decodes_delegate_and_companion() {
    let state = SamplerState::decode(&raw_state(cycles()[0])).unwrap();
    assert_eq!(state.support.len(), 7);
    let bls: Vec<_> = state
        .support
        .iter()
        .filter(|s| matches!(s.consensus_pk, PublicKey::Bls(_)))
        .collect();
    assert_eq!(bls.len(), 1);
    assert_eq!(
        b58_pkh(&bls[0].consensus_pk.hash()),
        "tz4C7vSeujRn4GDXgpCEvUpnxjc61qMB4BrD"
    );
    assert_eq!(
        b58_pkh(&bls[0].delegate()),
        "tz1ddb9NMYHZi5UzPdzTZMYQQZoMub195zgv"
    );
    for s in &state.support {
        if s.delegate.is_none() {
            assert_eq!(s.delegate(), s.consensus_pk.hash());
        }
    }
}

// "2026-11-06T19:30:01Z" -> unix seconds, enough for test fixtures.
fn unix_secs(s: &str) -> i64 {
    let n = |a: usize, b: usize| s[a..b].parse::<i64>().unwrap();
    let (y, m, d) = (n(0, 4), n(5, 7), n(8, 10));
    let (y2, m2) = if m <= 2 { (y - 1, m + 12) } else { (y, m) };
    let days = 365 * y2 + y2 / 4 - y2 / 100 + y2 / 400 + (153 * (m2 - 3) + 2) / 5 + d - 719469;
    days * 86400 + n(11, 13) * 3600 + n(14, 16) * 60 + n(17, 19)
}

/// Root of block B's resulting context, checked against header(B+1).context.
fn trusted_root() -> Hash {
    let f = fixture();
    let blk = &f["block"];
    let fit: Vec<&str> = blk["fitness"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap())
        .collect();
    assert!(
        fit[2].is_empty() && fit[3] == "ffffffff",
        "fixture assumes unlocked, pred round 0"
    );
    let lvl = blk["level"].as_i64().unwrap();
    let round = i64::from_str_radix(fit[4], 16).unwrap();
    let msg = format!(
        "lvl {lvl}, fit:({lvl}, unlocked, 0, {round}), round {round}, {} ops",
        f["op_count"]
    );
    let info = CommitInfo {
        parent: decode_context_hash(blk["context"].as_str().unwrap()).unwrap(),
        timestamp: unix_secs(blk["timestamp"].as_str().unwrap()),
        message: msg.into_bytes(),
    };
    let (_, root) = proof(cycles()[0], "state_proof").hash().unwrap();
    let next = decode_context_hash(f["next_header"]["context"].as_str().unwrap()).unwrap();
    assert_eq!(
        commit_hash(&root, &info),
        next,
        "root doesn't link to header(B+1).context"
    );
    root
}

fn proof(c: u32, which: &str) -> Tree {
    Tree::from_rpc_json(&cyc(c)[which]["state"]).unwrap()
}

#[test]
fn proofs_verify_for_every_cycle() {
    let root = trusted_root();
    for c in cycles() {
        let (state, s) =
            verify_cycle(&root, &proof(c, "state_proof"), &proof(c, "seed_proof"), c).unwrap();
        assert_eq!(state, SamplerState::decode(&raw_state(c)).unwrap());
        assert_eq!(s, seed(c));
    }
}

fn tamper_json(c: u32, which: &str, from: &str, to: &str) -> Tree {
    let s = serde_json::to_string(&cyc(c)[which]["state"]).unwrap();
    assert!(s.contains(from));
    Tree::from_rpc_json(&serde_json::from_str(&s.replacen(from, to, 1)).unwrap()).unwrap()
}

#[test]
fn bad_proofs_fail() {
    let root = trusted_root();
    let c = cycles()[0];
    let seed_hex = cyc(c)["random_seed"].as_str().unwrap();
    let mut bad_seed = seed_hex.to_string();
    bad_seed.replace_range(0..2, if &seed_hex[..2] == "00" { "01" } else { "00" });
    let state_hex = &cyc(c)["sampler_state"].as_str().unwrap()[..16];
    let mut bad_state = state_hex.to_string();
    bad_state.replace_range(15..16, if &state_hex[15..] == "0" { "1" } else { "0" });
    let other = cycles()[1];
    let cases: Vec<(&str, Tree, Tree, u32, Error)> = vec![
        (
            "tampered seed",
            proof(c, "state_proof"),
            tamper_json(c, "seed_proof", seed_hex, &bad_seed),
            c,
            Error::Proof(MerkleError::RootMismatch),
        ),
        (
            "tampered state",
            tamper_json(c, "state_proof", state_hex, &bad_state),
            proof(c, "seed_proof"),
            c,
            Error::Proof(MerkleError::RootMismatch),
        ),
        // a proof for cycle c blinds every other cycle, so it can't be used to claim another cycle's data
        (
            "wrong cycle",
            proof(c, "state_proof"),
            proof(c, "seed_proof"),
            other,
            Error::Proof(MerkleError::PathNotFound),
        ),
        (
            "absent cycle",
            proof(c, "state_proof"),
            proof(c, "seed_proof"),
            1,
            Error::Proof(MerkleError::PathNotFound),
        ),
    ];
    for (name, st, sd, cycle, want) in cases {
        assert_eq!(
            verify_cycle(&root, &st, &sd, cycle).unwrap_err(),
            want,
            "{name}"
        );
    }
}

#[test]
fn tampered_inputs_change_committee() {
    let c = cycles()[0];
    let level = cyc(c)["validators"]
        .as_object()
        .unwrap()
        .keys()
        .next()
        .unwrap()
        .clone();
    let (_, pos) = ERA.level_info(level.parse().unwrap()).unwrap();
    let want = expected(c, &level);
    let state = SamplerState::decode(&raw_state(c)).unwrap();
    let mut s2 = seed(c);
    s2[31] ^= 1;
    let mut skewed = state.clone();
    skewed.p[0] /= 2;
    let mut swapped = state.clone();
    swapped.support.swap(0, 1);
    let cases: Vec<(&str, SamplerState, Seed, i32)> = vec![
        ("flipped seed bit", state.clone(), s2, pos),
        ("other cycle seed", state.clone(), seed(cycles()[1]), pos),
        (
            "wrong cycle position",
            state.clone(),
            seed(c),
            (pos + 1) % 16,
        ),
        ("halved p[0]", skewed, seed(c), pos),
        ("swapped support", swapped, seed(c), pos),
    ];
    for (name, st, sd, p) in cases {
        assert_ne!(computed(&st, &sd, p).0, want, "{name}");
    }
}

#[test]
fn bad_encodings_fail() {
    let raw = raw_state(cycles()[0]);
    let mut trailing = raw.clone();
    trailing.push(0);
    let mut bad_tag = raw.clone();
    bad_tag[12] = 9; // fallback consensus_pk tag, after total (8) and length (4)
    let mut neg_total = raw.clone();
    neg_total[..8].copy_from_slice(&0i64.to_be_bytes());
    let mut bad_len = raw.clone();
    bad_len[11] += 1; // support length no longer matches its elements
    let cases: Vec<(&str, &[u8], Error)> = vec![
        ("empty", &[], Error::Truncated),
        ("truncated", &raw[..raw.len() - 1], Error::Truncated),
        ("trailing", &trailing, Error::TrailingBytes),
        ("bad pk tag", &bad_tag, Error::BadTag(9)),
        ("zero total", &neg_total, Error::BadTotal),
        ("support length", &bad_len, Error::BadShape),
    ];
    for (name, bytes, want) in cases {
        assert_eq!(SamplerState::decode(bytes).unwrap_err(), want, "{name}");
    }
}

#[test]
fn bad_alias_is_an_error_not_a_panic() {
    let mut state = SamplerState::decode(&raw_state(cycles()[0])).unwrap();
    for p in state.p.iter_mut() {
        *p = 0; // force the alias branch
    }
    state.alias.iter_mut().for_each(|a| *a = -1);
    assert_eq!(
        slot_owner(&state, &seed(cycles()[0]), 0, 0).unwrap_err(),
        Error::BadAlias
    );
}

#[test]
fn era_level_info() {
    let cases = [
        (1, Some((0, 0))),
        (16, Some((0, 15))),
        (17, Some((1, 0))),
        (948, Some((59, 3))),
        (0, None),
    ];
    for (level, want) in cases {
        assert_eq!(ERA.level_info(level), want, "level {level}");
    }
}
