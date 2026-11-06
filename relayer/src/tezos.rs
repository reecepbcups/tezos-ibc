//! Tezos RPC reads: program inputs and sent packets.

use alloy::primitives::{Address, U256};
use anyhow::{anyhow, bail, ensure, Context, Result};
use serde_json::Value;
use tezos_consensus::rpc::attestation_from_rpc;
use tezos_consensus::{b58, BlockHeader};
use tezos_lc::{CommitmentProof, Input};
use tezos_merkle::{bytes_key_hash, commit_hash, CommitInfo, Hash, Tree};

/// Per request. Merkle proofs on a busy node are the slowest reads.
const RPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Backoff doubles from 0.5s, so 5 attempts span about 8s plus timeouts.
const RPC_ATTEMPTS: u32 = 5;

pub struct Rpc {
    http: reqwest::Client,
    base: String,
}

/// A packet as sent by ibc_core, with the fields TezosNFT.recvPacket needs.
#[derive(Debug, Clone)]
pub struct Packet {
    pub seq: u64,
    /// level of the block that sent it
    pub level: i32,
    pub timeout: u64,
    pub source_port: String,
    pub dest_port: String,
    pub version: String,
    pub encoding: String,
    /// abi.encode(uint256 tokenId, address recipient)
    pub value: Vec<u8>,
    pub commitment: Hash,
}

/// What TezosNFT accepts, see its PORT, VERSION and ENCODING constants.
pub const NFT_PORT: &str = "fa2-nft";
pub const NFT_VERSION: &str = "fa2-nft-1";
pub const NFT_ENCODING: &str = "application/x-solidity-abi";

/// A packet's payload as TezosNFT.recvPacket takes it.
#[derive(Debug, PartialEq)]
pub struct NftTransfer {
    pub token_id: U256,
    pub recipient: Address,
}

/// Checks `p` is a TezosNFT packet and decodes its value. Anyone can send on our client,
/// so anything else is junk to skip, not an error.
pub fn decode_nft(p: &Packet) -> Result<NftTransfer> {
    ensure!(p.source_port == NFT_PORT, "source port {:?}", p.source_port);
    ensure!(p.dest_port == NFT_PORT, "dest port {:?}", p.dest_port);
    ensure!(p.version == NFT_VERSION, "version {:?}", p.version);
    ensure!(p.encoding == NFT_ENCODING, "encoding {:?}", p.encoding);
    ensure!(p.value.len() == 64, "value is {} bytes, want 64", p.value.len());
    // TezosNFT hashes abi.encode(tokenId, recipient), so dirty address padding could never be proven.
    ensure!(p.value[32..44].iter().all(|b| *b == 0), "address padding not zero");
    let recipient = Address::from_slice(&p.value[44..]);
    // _mint reverts on the zero address
    ensure!(!recipient.is_zero(), "zero recipient");
    Ok(NftTransfer {
        token_id: U256::from_be_slice(&p.value[..32]),
        recipient,
    })
}

/// ICS24 commitment path: clientId || 0x01 || u64be(seq)
pub fn commitment_path(client: &str, seq: u64) -> Vec<u8> {
    let mut p = client.as_bytes().to_vec();
    p.push(1);
    p.extend_from_slice(&seq.to_be_bytes());
    p
}

impl Rpc {
    pub fn new(base: &str) -> Self {
        Rpc {
            // A paused or wedged node otherwise hangs the relayer forever.
            http: reqwest::Client::builder()
                .timeout(RPC_TIMEOUT)
                .build()
                .expect("reqwest client"),
            base: base.trim_end_matches('/').to_string(),
        }
    }

    pub async fn get(&self, path: &str) -> Result<Value> {
        let url = format!("{}{path}", self.base);
        self.get_opt(path)
            .await?
            .ok_or_else(|| anyhow!("GET {url}: 404 Not Found"))
    }

    /// Like `get`, but None on 404. Dropped connections, timeouts and gateway errors are
    /// retried with backoff, the sandbox node closes connections now and then.
    pub async fn get_opt(&self, path: &str) -> Result<Option<Value>> {
        let url = format!("{}{path}", self.base);
        let mut delay = std::time::Duration::from_millis(500);
        let mut attempt = 1;
        loop {
            let err = match self.http.get(&url).send().await {
                Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND => return Ok(None),
                Ok(r) if r.status().is_success() => match r.bytes().await {
                    Ok(b) => {
                        let v = serde_json::from_slice(&b).with_context(|| format!("GET {url}"))?;
                        return Ok(Some(v));
                    }
                    Err(e) => anyhow!(e),
                },
                Ok(r) if matches!(r.status().as_u16(), 502..=504) => anyhow!("{}", r.status()),
                Ok(r) => bail!("GET {url}: {}", r.status()),
                Err(e) if e.is_connect() || e.is_timeout() || e.is_request() || e.is_body() => {
                    anyhow!(e)
                }
                Err(e) => return Err(anyhow!(e).context(format!("GET {url}"))),
            };
            if attempt == RPC_ATTEMPTS {
                return Err(err.context(format!("GET {url}, {attempt} attempts")));
            }
            eprintln!(
                "warn: GET {url}: {err:#}, retry {attempt}/{} in {delay:?}",
                RPC_ATTEMPTS - 1
            );
            tokio::time::sleep(delay).await;
            delay *= 2;
            attempt += 1;
        }
    }

    fn block(level: i32) -> String {
        format!("/chains/main/blocks/{level}")
    }

    pub async fn head_level(&self) -> Result<i32> {
        let h = self.get("/chains/main/blocks/head/header").await?;
        Ok(h["level"].as_i64().ok_or(anyhow!("no level"))? as i32)
    }

    pub async fn chain_id(&self) -> Result<[u8; 4]> {
        let s = self.get("/chains/main/chain_id").await?;
        Ok(tezos_consensus::chain_id_from_b58(s.as_str().unwrap_or_default())?)
    }

    pub async fn constant(&self, name: &str) -> Result<i64> {
        let c = self.get("/chains/main/blocks/head/context/constants").await?;
        c[name].as_i64().ok_or(anyhow!("no constant {name}"))
    }

    async fn header_json(&self, level: i32) -> Result<Value> {
        self.get(&format!("{}/header", Self::block(level))).await
    }

    pub async fn header(&self, level: i32) -> Result<BlockHeader> {
        let j = self.header_json(level).await?;
        Ok(BlockHeader::from_rpc_json(&j.to_string())?)
    }

    async fn op_hashes(&self, level: i32) -> Result<Vec<Vec<Hash>>> {
        let passes = self
            .get(&format!("{}/operation_hashes", Self::block(level)))
            .await?;
        passes
            .as_array()
            .ok_or(anyhow!("operation_hashes"))?
            .iter()
            .map(|p| {
                p.as_array()
                    .ok_or(anyhow!("pass"))?
                    .iter()
                    .map(|h| {
                        Ok(b58::decode_fixed(
                            h.as_str().unwrap_or_default(),
                            b58::OPERATION_HASH,
                        )?)
                    })
                    .collect()
            })
            .collect()
    }

    /// `merkle_tree_v2` proof (holey=false) of `path` in the state after block `level`.
    pub async fn proof(&self, level: i32, path: &str) -> Result<Tree> {
        let j = self
            .get(&format!(
                "{}/context/merkle_tree_v2/{path}?holey=false",
                Self::block(level)
            ))
            .await?;
        Tree::from_rpc_json(&j["state"]).map_err(|e| anyhow!("proof {path}: {e:?}"))
    }

    /// What Octez committed after applying block `level`, so commit_hash(root, info) == header(level+1).context.
    pub async fn commit_info(&self, level: i32) -> Result<CommitInfo> {
        let h = self.header_json(level).await?;
        let fit: Vec<&str> = h["fitness"]
            .as_array()
            .ok_or(anyhow!("fitness"))?
            .iter()
            .map(|x| x.as_str().unwrap_or_default())
            .collect();
        if fit.len() != 5 {
            bail!("unexpected fitness {fit:?}");
        }
        let locked = if fit[2].is_empty() {
            "unlocked".to_string()
        } else {
            format!("locked: {}", i64::from_str_radix(fit[2], 16)?)
        };
        let pred_round =
            -1 - i64::from(i32::from_be_bytes(hex::decode(fit[3])?.try_into().map_err(
                |_| anyhow!("bad predecessor round"),
            )?));
        let round = i64::from_str_radix(fit[4], 16)?;
        let minus = if pred_round != 0 { "-" } else { "" };
        let ops: usize = self.op_hashes(level).await?.iter().map(Vec::len).sum();
        let message = format!(
            "lvl {level}, fit:({level}, {locked}, {minus}{pred_round}, {round}), round {round}, {ops} ops"
        );
        let header = BlockHeader::from_rpc_json(&h.to_string())?;
        Ok(CommitInfo {
            parent: header.context,
            timestamp: header.timestamp,
            message: message.into_bytes(),
        })
    }

    /// Storage fields of ibc_core: (next_sequence big_map id, commitments big_map id).
    pub async fn core_big_maps(&self, core: &str) -> Result<(u64, u64)> {
        let s = self
            .get(&format!(
                "/chains/main/blocks/head/context/contracts/{core}/storage"
            ))
            .await?;
        let id = |i: usize| -> Result<u64> {
            Ok(s["args"][i]["int"]
                .as_str()
                .ok_or(anyhow!("ibc_core storage layout"))?
                .parse()?)
        };
        Ok((id(1)?, id(2)?))
    }

    /// ibc_core next_sequence[client] after block `level`, 1 if unset.
    pub async fn next_sequence(&self, big_map: u64, client: &str, level: i32) -> Result<u64> {
        // script expr hash: "expr" prefix over blake2b(PACK(string))
        let mut packed = vec![0x05, 0x01];
        packed.extend_from_slice(&(client.len() as u32).to_be_bytes());
        packed.extend_from_slice(client.as_bytes());
        let h = tezos_consensus::blake2b256(&[&packed]);
        let expr = b58::encode(&[13, 44, 64, 27], &h);
        let path = format!("{}/context/big_maps/{big_map}/{expr}", Self::block(level));
        let Some(v) = self.get_opt(&path).await? else {
            return Ok(1);
        };
        Ok(v["int"].as_str().ok_or(anyhow!("next_sequence"))?.parse()?)
    }

    /// Finds the send_packet calls for `seqs` by walking blocks back from `from` to `to`.
    /// Seqs sent before `to` are missing from the result.
    /// Needs receipts, so an archive (or not yet pruned) node.
    pub async fn find_packets(
        &self,
        core: &str,
        client: &str,
        seqs: &[u64],
        from: i32,
        to: i32,
    ) -> Result<Vec<Packet>> {
        let mut found: Vec<Packet> = vec![];
        let mut level = from;
        while level >= to.max(1) && found.len() < seqs.len() {
            let ops = self
                .get(&format!("{}/operations/3", Self::block(level)))
                .await?;
            for op in ops.as_array().into_iter().flatten() {
                for c in op["contents"].as_array().into_iter().flatten() {
                    for p in packets_in(&c["metadata"], core, client, level) {
                        if seqs.contains(&p.seq) && !found.iter().any(|f| f.seq == p.seq) {
                            found.push(p);
                        }
                    }
                }
            }
            level -= 1;
        }
        found.sort_by_key(|p| p.seq);
        Ok(found)
    }
}

/// Flattens a right comb pair, which the RPC shows either as `Pair` or as a sequence.
fn comb(v: &Value) -> Vec<&Value> {
    if let Some(a) = v.as_array() {
        return a.iter().flat_map(comb_tail).collect();
    }
    if v["prim"] == "Pair" {
        return v["args"].as_array().into_iter().flatten().flat_map(comb_tail).collect();
    }
    vec![v]
}

fn comb_tail(v: &Value) -> Vec<&Value> {
    if v["prim"] == "Pair" {
        comb(v)
    } else {
        vec![v]
    }
}

/// send_packet transactions to `core` and their events, matched in order.
fn packets_in(meta: &Value, core: &str, client: &str, level: i32) -> Vec<Packet> {
    let mut sends = vec![];
    let mut events = vec![];
    for r in meta["internal_operation_results"].as_array().into_iter().flatten() {
        if r["result"]["status"] != "applied" {
            continue;
        }
        if r["kind"] == "transaction"
            && r["destination"] == core
            && r["parameters"]["entrypoint"] == "send_packet"
        {
            sends.push(comb(&r["parameters"]["value"]));
        } else if r["kind"] == "event" && r["source"] == core && r["tag"] == "send_packet" {
            events.push(comb(&r["payload"]));
        }
    }
    let int = |v: &Value| v["int"].as_str().and_then(|s| s.parse::<u64>().ok());
    let bytes = |v: &Value| v["bytes"].as_str().and_then(|s| hex::decode(s).ok());
    let string = |v: &Value| v["string"].as_str().map(str::to_string);
    sends
        .iter()
        .zip(&events)
        .filter_map(|(s, e)| {
            if s.len() != 7 || e.len() != 3 || s[0]["string"] != client || e[0]["string"] != client {
                return None;
            }
            Some(Packet {
                seq: int(e[1])?,
                level,
                timeout: int(s[1])?,
                source_port: string(s[2])?,
                dest_port: string(s[3])?,
                version: string(s[4])?,
                encoding: string(s[5])?,
                value: bytes(s[6])?,
                commitment: bytes(e[2])?.try_into().ok()?,
            })
        })
        .collect()
}

/// Where to start: the trusted state, as stored by the Solidity client.
pub struct Trusted {
    pub level: i32,
    pub commit: Hash,
}

/// Gathers the program input proving H(n) final via a quorum on H(n+1) = `attested_level`,
/// and `paths` against the state after n-1.
pub async fn build_input(
    rpc: &Rpc,
    trusted: &Trusted,
    big_map_id: u64,
    attested_level: i32,
    era: &tezos_lc::Config,
    paths: &[Vec<u8>],
) -> Result<Input> {
    let n = attested_level - 1;
    let (cycle, _) = era
        .era
        .level_info(attested_level)
        .ok_or(anyhow!("level outside era"))?;

    let sampler_state_proof = rpc
        .proof(trusted.level, &format!("cycle/{cycle}/delegate_sampler_state"))
        .await?;
    let seed_proof = rpc
        .proof(trusted.level, &format!("cycle/{cycle}/random_seed"))
        .await?;
    // RPC paths are under data/. When the key is absent the node still lists all of data/.
    let all_bakers_attest_proof = rpc
        .proof(trusted.level, "all_bakers_attest_first_level")
        .await?;
    let trusted_root = sampler_state_proof.hash().map_err(|e| anyhow!("{e:?}"))?.1;
    let trusted_info = rpc.commit_info(trusted.level).await?;
    if commit_hash(&trusted_root, &trusted_info) != trusted.commit {
        bail!("trusted commit at {} doesn't match the node", trusted.level);
    }

    let attested = rpc.header(attested_level).await?;
    let attested_ops = rpc.op_hashes(attested_level).await?[1..].concat();
    let consensus = rpc
        .get(&format!("{}/operations/0", Rpc::block(attested_level + 1)))
        .await?;
    let mut attestations = vec![];
    for op in consensus.as_array().into_iter().flatten() {
        // Pass 0 also carries preattestations, skip anything that isn't an attestation of n+1.
        if let Ok(a) = attestation_from_rpc(op) {
            if a.content().level == attested_level {
                attestations.push(a);
            }
        }
    }

    let new_level = n - 1;
    let mut commitments = vec![];
    let mut new_root = None;
    for path in paths {
        let key = hex::encode(bytes_key_hash(path));
        let proof = rpc
            .proof(new_level, &format!("big_maps/index/{big_map_id}/contents/{key}/data"))
            .await?;
        new_root = Some(proof.hash().map_err(|e| anyhow!("{e:?}"))?.1);
        commitments.push(CommitmentProof {
            path: path.clone(),
            proof,
        });
    }
    // Small proof whose root node carries the state's `protocol` key.
    let new_state_proof = rpc.proof(new_level, "version").await?;
    let new_root = match new_root {
        Some(r) => r,
        None => new_state_proof.hash().map_err(|e| anyhow!("{e:?}"))?.1,
    };

    Ok(Input {
        chain_id: rpc.chain_id().await?,
        big_map_id,
        trusted_level: trusted.level,
        trusted_commit: trusted.commit,
        trusted_root,
        trusted_info,
        sampler_state_proof,
        seed_proof,
        all_bakers_attest_proof,
        attested,
        attested_ops,
        attestations,
        header: rpc.header(n).await?,
        parent: rpc.header(n - 1).await?,
        new_root,
        new_info: rpc.commit_info(new_level).await?,
        new_state_proof,
        commitments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn value(token: u8, pad: u8, addr: u8) -> Vec<u8> {
        let mut v = vec![0u8; 64];
        v[31] = token;
        v[32..44].fill(pad);
        v[44..].fill(addr);
        v
    }

    fn packet(edit: impl FnOnce(&mut Packet)) -> Packet {
        let mut p = Packet {
            seq: 1,
            level: 10,
            timeout: 0,
            source_port: NFT_PORT.into(),
            dest_port: NFT_PORT.into(),
            version: NFT_VERSION.into(),
            encoding: NFT_ENCODING.into(),
            value: value(7, 0, 0xaa),
            commitment: [0; 32],
        };
        edit(&mut p);
        p
    }

    #[test]
    fn decode_nft_rejects_junk() {
        let ok = Some(NftTransfer {
            token_id: U256::from(7),
            recipient: Address::repeat_byte(0xaa),
        });
        let cases: Vec<(&str, Packet, Option<NftTransfer>)> = vec![
            ("valid", packet(|_| {}), ok),
            ("other source port", packet(|p| p.source_port = "transfer".into()), None),
            ("other dest port", packet(|p| p.dest_port = "x".into()), None),
            ("other version", packet(|p| p.version = "fa2-nft-2".into()), None),
            ("other encoding", packet(|p| p.encoding = "application/json".into()), None),
            ("empty value", packet(|p| p.value = vec![]), None),
            ("short value", packet(|p| p.value.truncate(63)), None),
            ("long value", packet(|p| p.value.push(0)), None),
            ("dirty padding", packet(|p| p.value = value(7, 1, 0xaa)), None),
            ("zero recipient", packet(|p| p.value = value(7, 0, 0)), None),
        ];
        for (name, p, want) in cases {
            assert_eq!(decode_nft(&p).ok(), want, "{name}");
        }
    }

    fn send(client: &str, value: Value) -> Value {
        json!({
            "kind": "transaction", "destination": "KT1core",
            "result": {"status": "applied"},
            "parameters": {"entrypoint": "send_packet", "value": [
                {"string": client}, {"int": "5"}, {"string": "p"}, {"string": "p"},
                {"string": "v"}, {"string": "e"}, value
            ]}
        })
    }

    fn event(client: &str, seq: &str) -> Value {
        json!({
            "kind": "event", "source": "KT1core", "tag": "send_packet",
            "result": {"status": "applied"},
            "payload": [{"string": client}, {"int": seq}, {"bytes": "00".repeat(32)}]
        })
    }

    #[test]
    fn packets_in_skips_junk() {
        let cases = vec![
            ("valid", send("eth-0", json!({"bytes": "ab"})), event("eth-0", "3"), Some(3)),
            ("other client", send("other", json!({"bytes": "ab"})), event("other", "3"), None),
            ("value not bytes", send("eth-0", json!({"int": "1"})), event("eth-0", "3"), None),
            ("bad hex", send("eth-0", json!({"bytes": "zz"})), event("eth-0", "3"), None),
            ("bad seq", send("eth-0", json!({"bytes": "ab"})), event("eth-0", "x"), None),
        ];
        for (name, s, e, want) in cases {
            let meta = json!({"internal_operation_results": [s, e]});
            let got = packets_in(&meta, "KT1core", "eth-0", 1);
            assert_eq!(got.first().map(|p| p.seq), want, "{name}");
        }
    }
}
