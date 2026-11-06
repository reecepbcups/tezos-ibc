// Checks a packet commitment proof dumped from the sandbox by fixtures/dump.py.
use tezos_merkle::*;

fn fixture() -> serde_json::Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/membership.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn commit_info(f: &serde_json::Value) -> (Hash, CommitInfo) {
    let blk = &f["block"];
    let fit: Vec<&str> = blk["fitness"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
    let lvl = blk["level"].as_i64().unwrap();
    let locked = if fit[2].is_empty() { "unlocked".to_string() } else { format!("locked: {}", i64::from_str_radix(fit[2], 16).unwrap()) };
    let pred_round = -1 - i32::from_be_bytes(hex::decode(fit[3]).unwrap().try_into().unwrap()) as i64;
    let round = i64::from_str_radix(fit[4], 16).unwrap();
    let minus = if pred_round != 0 { "-" } else { "" };
    let msg = format!("lvl {lvl}, fit:({lvl}, {locked}, {minus}{pred_round}, {round}), round {round}, {} ops", f["op_count"]);
    let ts = chrono_secs(blk["timestamp"].as_str().unwrap());
    let next = decode_context_hash(f["next_header"]["context"].as_str().unwrap()).unwrap();
    (next, CommitInfo { parent: decode_context_hash(blk["context"].as_str().unwrap()).unwrap(), timestamp: ts, message: msg.into_bytes() })
}

// "2026-11-06T19:30:01Z" -> unix seconds, enough for test fixtures.
fn chrono_secs(s: &str) -> i64 {
    let n = |a: usize, b: usize| s[a..b].parse::<i64>().unwrap();
    let (y, m, d) = (n(0, 4), n(5, 7), n(8, 10));
    let (y2, m2) = if m <= 2 { (y - 1, m + 12) } else { (y, m) };
    let days = 365 * y2 + y2 / 4 - y2 / 100 + y2 / 400 + (153 * (m2 - 3) + 2) / 5 + d - 719469;
    days * 86400 + n(11, 13) * 3600 + n(14, 16) * 60 + n(17, 19)
}

#[test]
fn packet_commitment_proves_to_next_header() {
    let f = fixture();
    let tree = Tree::from_rpc_json(&f["proof"]["state"]).unwrap();
    let (_, root) = tree.hash().unwrap();
    let (next_ctx, info) = commit_info(&f);
    assert_eq!(commit_hash(&root, &info), next_ctx, "root doesn't link to header(B+1).context");

    let path = hex::decode(f["path"].as_str().unwrap()).unwrap();
    let kh = bytes_key_hash(&path);
    assert_eq!(hex::encode(kh), f["key_hash"].as_str().unwrap());
    let p = big_map_value_path(5, &kh);
    let refs: Vec<&[u8]> = p.iter().map(|s| s.as_slice()).collect();
    let leaf = verify_membership(&root, &tree, &refs).unwrap();
    let c = decode_bytes32_leaf(&leaf).unwrap();
    assert_eq!(hex::encode(c), "de05b2fb09e969a905fa88affa90ed1a68562955511f88c36557103a5a61c32f");
}

#[test]
fn tampered_value_fails() {
    let f = fixture();
    let mut s = serde_json::to_string(&f["proof"]["state"]).unwrap();
    s = s.replace("de05b2fb", "de05b2fc");
    let tree = Tree::from_rpc_json(&serde_json::from_str(&s).unwrap()).unwrap();
    let (_, root) = Tree::from_rpc_json(&f["proof"]["state"]).unwrap().hash().unwrap();
    let path = big_map_value_path(5, &bytes_key_hash(&hex::decode(f["path"].as_str().unwrap()).unwrap()));
    let refs: Vec<&[u8]> = path.iter().map(|s| s.as_slice()).collect();
    assert_eq!(verify_membership(&root, &tree, &refs), Err(Error::RootMismatch));
}

#[test]
fn missing_key_fails() {
    let f = fixture();
    let tree = Tree::from_rpc_json(&f["proof"]["state"]).unwrap();
    let (_, root) = tree.hash().unwrap();
    let path = big_map_value_path(5, &bytes_key_hash(b"eth-0\x01\0\0\0\0\0\0\0\x02"));
    let refs: Vec<&[u8]> = path.iter().map(|s| s.as_slice()).collect();
    assert!(verify_membership(&root, &tree, &refs).is_err());
}
