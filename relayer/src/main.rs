//! One shot relayer: moves the Ethereum Tezos light client to a recent final block, proving
//! unrelayed packet commitments on the way, then delivers those packets to TezosNFT.
//!
//! `relayer vkey` prints the program vkey, `relayer anchor` the client deploy args.
//! `relayer` (or `relayer run`) relays.
//! `relayer keep` relays forever and keeps the client fresh, see `keep`.
//! `relayer prove <trusted> <new> [seq..]` prints a proof without submitting, see `prove`.
//! `relayer profile ..` executes one update and prints cycles per phase, see profile.rs.
//! SP1_PROVER=mock|cpu|network picks the prover (default mock). Mock proofs are empty bytes and
//! only pass the local MockVerifier; cpu and network make real Groth16 proofs.

mod profile;
mod quorum;
mod tezos;

use std::collections::HashSet;
use std::time::Duration;

use alloy::primitives::{Address, Bytes, FixedBytes};
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::SolValue;
use anyhow::{anyhow, bail, Context, Result};
use sp1_sdk::env::{EnvProver, EnvProvingKey};
use sp1_sdk::{include_elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin};
use tezos::{build_input, commitment_path, decode_nft, NftTransfer, Packet, Rpc, Trusted};

const ELF: sp1_sdk::Elf = include_elf!("tezos-lc-program");
/// TEZOS_NETWORK=sandbox|mainnet (default sandbox). Must match the ELF's `mainnet` feature.
static CFG: std::sync::LazyLock<tezos_lc::Config> = std::sync::LazyLock::new(|| {
    match std::env::var("TEZOS_NETWORK").as_deref() {
        Err(_) | Ok("sandbox") => tezos_lc::SANDBOX,
        Ok("mainnet") => tezos_lc::MAINNET,
        Ok(other) => panic!("unknown TEZOS_NETWORK {other:?}, want sandbox or mainnet"),
    }
});
/// anvil account 0
const ANVIL_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

sol! {
    #[sol(rpc)]
    contract TezosLightClient {
        function latestLevel() external view returns (uint64);
        function stateCommit(uint64 level) external view returns (bytes32);
        function BIG_MAP_ID() external view returns (uint64);
        function stateTimestamp(uint64 level) external view returns (uint64);
        function TRUSTING_PERIOD() external view returns (uint64);
        function commitmentOf(bytes calldata path) external view returns (bytes32);
        function update(bytes calldata publicValues, bytes calldata proof) external;
        function frozen() external view returns (bool);
        event Updated(uint64 indexed level, bytes32 commit);
    }

    #[sol(rpc)]
    contract TezosNFT {
        function received(uint64 sequence) external view returns (bool);
        function recvPacket(uint64 sequence, uint64 timeoutTimestamp, uint256 tokenId, address recipient) external;
    }
}

fn env(k: &str, default: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| default.to_string())
}

fn env_req(k: &str) -> Result<String> {
    std::env::var(k).with_context(|| format!("set {k}"))
}

#[tokio::main]
async fn main() -> Result<()> {
    // sp1-sdk logs the network explorer link per proof request at info. RUST_LOG overrides.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sp1_sdk=info".into()),
        )
        .with_writer(std::io::stderr)
        .with_timer(tracing_subscriber::fmt::time::ChronoUtc::new(
            "%Y-%m-%dT%H:%M:%S".into(),
        ))
        .init();
    let network = env("TEZOS_NETWORK", "sandbox");
    if network != env!("TEZOS_NETWORK_BUILT") {
        bail!(
            "TEZOS_NETWORK={network} but the program was built for {}, rebuild with it set",
            env!("TEZOS_NETWORK_BUILT")
        );
    }
    let cmd = std::env::args().nth(1).unwrap_or_else(|| "run".into());
    if cmd == "anchor" {
        return anchor().await;
    }
    let prover = prover().await?;
    let pk = prover.setup(ELF).await?;
    let vkey = pk.verifying_key().bytes32();
    match cmd.as_str() {
        "vkey" => {
            println!("{vkey}");
            Ok(())
        }
        "run" => {
            // So whoever deployed the client can check it pins this program.
            println!("program vkey {vkey}");
            run(&prover, &pk).await
        }
        "keep" => {
            println!("program vkey {vkey}");
            keep(&prover, &pk).await
        }
        "prove" => prove(&prover, &pk).await,
        "profile" => profile::profile(&prover).await,
        c => bail!("unknown command {c}, want run, keep, prove, profile, vkey or anchor"),
    }
}

/// Builds the prover named by SP1_PROVER. Unlike ProverClient::from_env, defaults to mock and
/// errors on unknown values instead of panicking.
async fn prover() -> Result<EnvProver> {
    let b = ProverClient::builder();
    Ok(match env("SP1_PROVER", "mock").as_str() {
        "mock" => EnvProver::Mock(b.mock().build().await),
        "cpu" => EnvProver::Cpu(b.cpu().build().await),
        "network" => {
            let key = env_req("NETWORK_PRIVATE_KEY")?;
            EnvProver::Network(b.network().private_key(&key).build().await)
        }
        p => bail!("unknown SP1_PROVER {p}, want mock, cpu or network"),
    })
}

/// Prints deploy args for the Solidity client, anchored at the state after head~1.
/// Trusting the node here is the usual light client genesis assumption.
async fn anchor() -> Result<()> {
    let rpc = Rpc::new(&env("TEZOS_RPC", "http://localhost:8732"));
    let (_, big_map_id) = rpc.core_big_maps(&env_req("CORE")?).await?;
    let head = rpc.head_level().await?;
    let mut chain_id = [0u8; 32];
    chain_id[..4].copy_from_slice(&rpc.chain_id().await?);
    println!("CHAIN_ID=0x{}", hex::encode(chain_id));
    println!("BIG_MAP_ID={big_map_id}");
    println!("ANCHOR_LEVEL={}", head - 1);
    // H(head) carries the anchor commit, and its timestamp, same as the program's newTimestamp.
    let h = rpc.header(head).await?;
    println!("ANCHOR_COMMIT=0x{}", hex::encode(h.context));
    println!("ANCHOR_TIMESTAMP={}", h.timestamp);
    Ok(())
}

/// Proves `trusted -> new` on whatever chain TEZOS_RPC serves and prints PV=0x.. PROOF=0x..
/// without sending. The e2e uses it to prove two forks against the same stored anchor.
async fn prove(prover: &EnvProver, pk: &EnvProvingKey) -> Result<()> {
    let args: Vec<String> = std::env::args().skip(2).collect();
    if args.len() < 2 {
        bail!("usage: relayer prove <trusted_level> <new_level> [seq..]");
    }
    let rpc = Rpc::new(&env("TEZOS_RPC", "http://localhost:8732"));
    let provider = ProviderBuilder::new().connect_http(env("ETH_RPC", "http://localhost:18545").parse()?);
    let client = TezosLightClient::new(env_req("CLIENT")?.parse::<Address>()?, &provider);
    let level: u64 = args[0].parse().context("trusted_level")?;
    let trusted = Trusted {
        level: i32::try_from(level)?,
        commit: client.stateCommit(level).call().await?.0,
    };
    let new_level: i32 = args[1].parse().context("new_level")?;
    let source_client = env("SOURCE_CLIENT", "eth-0");
    let mut paths = vec![];
    for s in &args[2..] {
        paths.push(commitment_path(&source_client, s.parse().context("seq")?));
    }
    let big_map_id = client.BIG_MAP_ID().call().await?;
    // new_level is pinned by a QC on new_level+1, carried by new_level+2.
    let input = build_input(&rpc, &trusted, big_map_id, new_level + 2, &CFG, &paths).await?;
    tezos_lc::verify(&CFG, &input).map_err(|e| anyhow!("input rejected: {e:?}"))?;
    let mut stdin = SP1Stdin::new();
    stdin.write(&input);
    let proof = prover.prove(pk, stdin).groth16().await?;
    println!("PV=0x{}", hex::encode(proof.public_values.to_vec()));
    println!("PROOF=0x{}", hex::encode(proof.bytes()));
    Ok(())
}

async fn run(prover: &EnvProver, pk: &EnvProvingKey) -> Result<()> {
    let rpc = Rpc::new(&env("TEZOS_RPC", "http://localhost:8732"));
    let core = env_req("CORE")?;
    let source_client = env("SOURCE_CLIENT", "eth-0");
    let signer: PrivateKeySigner = env("PRIVATE_KEY", ANVIL_KEY).parse()?;
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect_http(env("ETH_RPC", "http://localhost:18545").parse()?);
    let client = TezosLightClient::new(env_req("CLIENT")?.parse::<Address>()?, &provider);
    let nft = TezosNFT::new(env_req("NFT")?.parse::<Address>()?, &provider);
    if client.frozen().call().await? {
        eprintln!("warn: client frozen: deliveries paused until admin re-anchor");
        return Ok(());
    }

    let big_map_id = client.BIG_MAP_ID().call().await?;
    let (next_seq_map, commitments_map) = rpc.core_big_maps(&core).await?;
    if commitments_map != big_map_id {
        bail!("client tracks big_map {big_map_id}, ibc_core uses {commitments_map}");
    }
    let rights_delay = rpc.constant("consensus_rights_delay").await? as u32;

    // Newest level the loop can prove. Reading packets there, not at head, means a reorg can't
    // shift seqs or commitments under us. Later packets wait for the next run.
    let final_level = rpc.head_level().await? - 3;
    // Packets sent before this are never looked for. Set it to the ibc_core deploy level.
    let start_level: i32 = env("TEZOS_START_LEVEL", "1")
        .parse()
        .context("TEZOS_START_LEVEL")?;

    // Rerun safe: anything not yet received is pending, proven or not.
    let next = rpc
        .next_sequence(next_seq_map, &source_client, final_level)
        .await?;
    let mut pending = vec![];
    for seq in 1..next {
        if !nft.received(seq).call().await? {
            pending.push(seq);
        }
    }
    let found = rpc
        .find_packets(&core, &source_client, &pending, final_level, start_level)
        .await?;
    for seq in pending.iter().filter(|s| !found.iter().any(|p| p.seq == **s)) {
        eprintln!("warn: packet {seq} not found in levels {start_level}..={final_level}, skipping");
    }
    // Anyone can send on our client, so junk is skipped rather than blocking later packets.
    let mut packets: Vec<(Packet, NftTransfer)> = vec![];
    for p in found {
        match decode_nft(&p) {
            Ok(t) => packets.push((p, t)),
            Err(e) => eprintln!("warn: packet {} isn't for TezosNFT, skipping: {e}", p.seq),
        }
    }
    println!(
        "pending packets: {:?}",
        packets.iter().map(|(p, _)| p.seq).collect::<Vec<_>>()
    );
    // Delivered or given up on, so the loop below always ends.
    let mut done: HashSet<u64> = HashSet::new();

    loop {
        let trusted_level = client.latestLevel().call().await?;
        let trusted = Trusted {
            level: i32::try_from(trusted_level)?,
            commit: client.stateCommit(trusted_level).call().await?.0,
        };
        // The trusted context holds sampler states up to rights_delay cycles ahead.
        let (tc, _) = CFG
            .era
            .level_info(trusted.level)
            .ok_or(anyhow!("trusted level outside era"))?;
        let last_provable = CFG.era.first_level
            + (tc + rights_delay + 1 - CFG.era.first_cycle) as i32 * CFG.era.blocks_per_cycle
            - 1;
        let head = rpc.head_level().await?;
        // attested level n+1; its attestations are in n+2 <= head
        let attested = (head - 1).min(last_provable);
        if attested < trusted.level + 2 {
            println!("waiting for blocks past {}", trusted.level);
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        }
        let new_level = attested - 2;

        let mut to_prove = vec![];
        for (p, _) in packets.iter().filter(|(p, _)| p.level <= new_level) {
            let path = commitment_path(&source_client, p.seq);
            if client.commitmentOf(path.clone().into()).call().await?.is_zero() {
                to_prove.push(path);
            }
        }

        let input = build_input(&rpc, &trusted, big_map_id, attested, &CFG, &to_prove).await?;
        if let Ok(p) = std::env::var("DUMP_INPUT") {
            std::fs::write(&p, serde_json::to_vec(&input)?)?;
            println!("wrote {p}");
        }
        // Native run first: same code as the program, fails fast with a readable error.
        let pv = tezos_lc::verify(&CFG, &input).map_err(|e| anyhow!("input rejected: {e:?}"))?;

        let mut stdin = SP1Stdin::new();
        stdin.write(&input);
        let (out, report) = prover.execute(ELF, stdin.clone()).await?;
        println!(
            "update {} -> {} ({} commitments): {} cycles",
            trusted.level,
            new_level,
            to_prove.len(),
            report.total_instruction_count()
        );
        if out.as_slice() != pv.abi_encode().as_slice() {
            bail!("program output differs from native run");
        }
        let proof = prover.prove(pk, stdin).groth16().await?;
        let receipt = client
            .update(Bytes::from(proof.public_values.to_vec()), Bytes::from(proof.bytes()))
            .send()
            .await?
            .get_receipt()
            .await?;
        if !receipt.status() {
            bail!("update reverted: {:?}", receipt.transaction_hash);
        }

        for (p, t) in &packets {
            if p.level > new_level || done.contains(&p.seq) {
                continue;
            }
            if nft.received(p.seq).call().await? {
                done.insert(p.seq);
                continue;
            }
            let proven = client
                .commitmentOf(commitment_path(&source_client, p.seq).into())
                .call()
                .await?;
            // Read at a final level, so a mismatch won't fix itself by waiting.
            if proven != FixedBytes(p.commitment) {
                eprintln!("warn: packet {} proven commitment {proven} differs, skipping", p.seq);
                done.insert(p.seq);
                continue;
            }
            let recv = nft.recvPacket(p.seq, p.timeout, t.token_id, t.recipient);
            // Simulate first: a revert skips this packet, a transport error still aborts.
            if let Err(e) = recv.call().await {
                match e.as_revert_data() {
                    Some(data) => {
                        eprintln!("warn: recvPacket {} would revert ({data}), skipping", p.seq);
                        done.insert(p.seq);
                        continue;
                    }
                    None => return Err(e.into()),
                }
            }
            let receipt = recv.send().await?.get_receipt().await?;
            done.insert(p.seq);
            if !receipt.status() {
                eprintln!("warn: recvPacket {} reverted: {:?}", p.seq, receipt.transaction_hash);
                continue;
            }
            println!(
                "delivered packet {}: token {} to {}",
                p.seq, t.token_id, t.recipient
            );
        }

        if packets.iter().all(|(p, _)| done.contains(&p.seq)) {
            break;
        }
        // Caught up but a packet isn't final yet: wait for more blocks instead of exiting.
        if attested == head - 1 {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
    Ok(())
}

/// Settings for `relayer keep`, read once at startup.
struct KeepConfig {
    /// KEEP_INTERVAL: time between checks
    interval: Duration,
    /// KEEP_MAX_AGE: update once the trusted state is this old. Default 6h leaves most of the
    /// 2 day TRUSTING_PERIOD as margin for RPC outages.
    max_age: Duration,
    /// KEEP_MAX_LAG: update once head is this many blocks past the client. Proofs only reach
    /// consensus_rights_delay+1 cycles ahead, so the default is one cycle.
    max_lag: i32,
}

/// `relayer keep`: loops until ctrl-c. Each tick relays pending packets and, with none, still
/// updates the client when its trusted state gets old, so it never hits TrustExpired or falls
/// out of proof range. Errors, transient or not, are logged and retried with backoff.
async fn keep(prover: &EnvProver, pk: &EnvProvingKey) -> Result<()> {
    let cfg = KeepConfig {
        interval: parse_duration(&env("KEEP_INTERVAL", "30s")).context("KEEP_INTERVAL")?,
        max_age: parse_duration(&env("KEEP_MAX_AGE", "6h")).context("KEEP_MAX_AGE")?,
        max_lag: env("KEEP_MAX_LAG", &CFG.era.blocks_per_cycle.to_string())
            .parse()
            .context("KEEP_MAX_LAG")?,
    };
    let provider =
        ProviderBuilder::new().connect_http(env("ETH_RPC", "http://localhost:18545").parse()?);
    let client = TezosLightClient::new(env_req("CLIENT")?.parse::<Address>()?, &provider);
    let period = client
        .TRUSTING_PERIOD()
        .call()
        .await
        .context("read TRUSTING_PERIOD")?;
    if cfg.max_age.as_secs() >= period {
        bail!(
            "KEEP_MAX_AGE {:?} must be under the client's TRUSTING_PERIOD {period}s",
            cfg.max_age
        );
    }
    println!(
        "keep: interval {:?}, max age {:?}, max lag {} blocks, trusting period {period}s",
        cfg.interval, cfg.max_age, cfg.max_lag
    );

    use alloy::providers::Provider;
    let blocks: u64 = env("KEEP_WATCH_BLOCKS", "14400")
        .parse()
        .context("KEEP_WATCH_BLOCKS")?;
    let mut watch = Watch {
        // About 2 days of Eth blocks: older states are past TRUSTING_PERIOD, so useless as evidence.
        from_block: provider.get_block_number().await?.saturating_sub(blocks),
        honest: vec![],
    };

    let mut stop = std::pin::pin!(tokio::signal::ctrl_c());
    // Seqs received, or given up on by run. Not looked at again.
    let mut settled = HashSet::new();
    let mut failures = 0u32;
    loop {
        let wait = tokio::select! {
            r = keep_tick(prover, pk, &cfg, &mut settled, &mut watch) => match r {
                Ok(()) => {
                    failures = 0;
                    cfg.interval
                }
                Err(e) => {
                    failures += 1;
                    let backoff = Duration::from_secs(2 << failures.min(7)).min(Duration::from_secs(300));
                    eprintln!("keep: error (failure {failures}), retrying in {backoff:?}: {e:#}");
                    backoff
                }
            },
            _ = &mut stop => break,
        };
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = &mut stop => break,
        }
    }
    println!("keep: ctrl-c, stopping");
    Ok(())
}

/// One keeper check, then `run` if there are packets to relay or the client needs refreshing.
async fn keep_tick(
    prover: &EnvProver,
    pk: &EnvProvingKey,
    cfg: &KeepConfig,
    settled: &mut HashSet<u64>,
    watch: &mut Watch,
) -> Result<()> {
    use alloy::providers::Provider;
    let rpc = Rpc::new(&env("TEZOS_RPC", "http://localhost:8732"));
    let core = env_req("CORE")?;
    let source_client = env("SOURCE_CLIENT", "eth-0");
    let provider =
        ProviderBuilder::new().connect_http(env("ETH_RPC", "http://localhost:18545").parse()?);
    let client = TezosLightClient::new(env_req("CLIENT")?.parse::<Address>()?, &provider);
    let nft = TezosNFT::new(env_req("NFT")?.parse::<Address>()?, &provider);

    // Same check run does, but here it also stops watcher duty: update reverts once frozen.
    if client.frozen().call().await? {
        eprintln!("warn: client frozen: deliveries paused until admin re-anchor");
        return Ok(());
    }
    if watch_states(prover, pk, watch).await? {
        return Ok(());
    }

    let (next_seq_map, _) = rpc.core_big_maps(&core).await?;
    let head = rpc.head_level().await?;
    // Same final level run reads at, so run finds every packet seen here.
    let next = rpc
        .next_sequence(next_seq_map, &source_client, head - 3)
        .await?;
    let mut pending = vec![];
    for seq in 1..next {
        if settled.contains(&seq) {
            continue;
        }
        if nft.received(seq).call().await? {
            settled.insert(seq);
        } else {
            pending.push(seq);
        }
    }

    let level = client.latestLevel().call().await?;
    let trusted_ts = client.stateTimestamp(level).call().await?;
    // TrustExpired compares to block.timestamp, which can run ahead of the wall clock on anvil.
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let block_ts = provider
        .get_block(alloy::eips::BlockId::latest())
        .await?
        .map_or(0, |b| b.header.timestamp);
    let age = wall.max(block_ts).saturating_sub(trusted_ts);
    let lag = head - i32::try_from(level)?;
    println!("keep: client level {level} age {age}s, head {head} lag {lag}, pending {pending:?}");

    let tick = Tick {
        pending: !pending.is_empty(),
        age,
        lag,
        // run's target when caught up: H(head-1) attested, so head-3 is proven.
        newest_provable: head - 3,
        client: i32::try_from(level)?,
    };
    let reason = match decide(&tick, cfg) {
        Decision::Relay(r) => r,
        Decision::Skip(r) => {
            println!("keep: skip: {r}");
            return Ok(());
        }
        Decision::Idle => return Ok(()),
    };
    println!("keep: relaying, {reason}");
    run(prover, pk).await?;

    // run returns once each packet is delivered or skipped. Skipped ones would only make every
    // later tick update again, so settle them too.
    for seq in pending {
        if !nft.received(seq).call().await? {
            eprintln!("warn: keep: packet {seq} not delivered, run skipped it, not retrying");
        }
        settled.insert(seq);
    }
    let new_level = client.latestLevel().call().await?;
    println!("keep: client level {level} -> {new_level}");
    Ok(())
}

/// Keeper memory for watcher duty.
struct Watch {
    /// next Eth block to scan for Updated events
    from_block: u64,
    /// client levels whose stored commit matched our node, ascending
    honest: Vec<u64>,
}

/// Watcher duty: checks each client state stored since the last scan against our own node.
/// A mismatch means a fork's proof got in, so we prove our state at the same level from an
/// honest trusted one, which freezes the client. Only works while that trusted state is inside
/// TRUSTING_PERIOD, hence every tick. Returns true if it froze the client.
async fn watch_states(prover: &EnvProver, pk: &EnvProvingKey, w: &mut Watch) -> Result<bool> {
    use alloy::providers::Provider;
    let rpc = Rpc::new(&env("TEZOS_RPC", "http://localhost:8732"));
    let signer: PrivateKeySigner = env("PRIVATE_KEY", ANVIL_KEY).parse()?;
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect_http(env("ETH_RPC", "http://localhost:18545").parse()?);
    let client = TezosLightClient::new(env_req("CLIENT")?.parse::<Address>()?, &provider);

    let to = provider.get_block_number().await?;
    if to < w.from_block {
        return Ok(false);
    }
    let events = client
        .Updated_filter()
        .from_block(w.from_block)
        .to_block(to)
        .query()
        .await?;
    let head = rpc.head_level().await?;
    for (ev, log) in events {
        let level = ev.level;
        let stored = client.stateCommit(level).call().await?;
        // zero: from before a re-anchor
        if stored.is_zero() || w.honest.contains(&level) {
            continue;
        }
        // Proving it back needs a QC on level+1, carried by level+2.
        if i32::try_from(level)? + 2 > head {
            w.from_block = log.block_number.unwrap_or(w.from_block);
            return Ok(false);
        }
        let ours = rpc.header(i32::try_from(level)? + 1).await?.context;
        if stored.0 == ours {
            w.honest.push(level);
            w.honest.sort_unstable();
            continue;
        }
        eprintln!(
            "!!! keep: MISBEHAVIOUR: client state {level} is {stored}, our node has 0x{}. Freezing the client.",
            hex::encode(ours)
        );
        let trusted_level = *w
            .honest
            .iter()
            .rev()
            .find(|l| **l < level)
            .ok_or_else(|| anyhow!("no honest client state below {level} to prove from"))?;
        let trusted = Trusted {
            level: i32::try_from(trusted_level)?,
            commit: client.stateCommit(trusted_level).call().await?.0,
        };
        let big_map_id = client.BIG_MAP_ID().call().await?;
        let input = build_input(
            &rpc,
            &trusted,
            big_map_id,
            i32::try_from(level)? + 2,
            &CFG,
            &[],
        )
        .await?;
        tezos_lc::verify(&CFG, &input).map_err(|e| anyhow!("input rejected: {e:?}"))?;
        let mut stdin = SP1Stdin::new();
        stdin.write(&input);
        let proof = prover.prove(pk, stdin).groth16().await?;
        let receipt = client
            .update(
                Bytes::from(proof.public_values.to_vec()),
                Bytes::from(proof.bytes()),
            )
            .send()
            .await?
            .get_receipt()
            .await?;
        let frozen = client.frozen().call().await?;
        if !receipt.status() || !frozen {
            bail!(
                "honest proof of {level} didn't freeze the client: {:?}",
                receipt.transaction_hash
            );
        }
        eprintln!("!!! keep: proved our state {level} from {trusted_level}, client frozen");
        return Ok(true);
    }
    w.from_block = to + 1;
    Ok(false)
}

/// What a keeper tick read from both chains.
struct Tick {
    pending: bool,
    /// seconds since the client's latest trusted state
    age: u64,
    /// head minus the client's latest level
    lag: i32,
    newest_provable: i32,
    client: i32,
}

#[derive(Debug, PartialEq)]
enum Decision {
    Relay(&'static str),
    Skip(&'static str),
    Idle,
}

/// Whether a tick should run an update. Packets always do. Age and lag only do once the
/// update can land past the client: a same level update keeps the old timestamp, so a stalled
/// head would otherwise burn a proof every tick.
fn decide(t: &Tick, cfg: &KeepConfig) -> Decision {
    if t.pending {
        return Decision::Relay("pending packets");
    }
    let reason = if t.age > cfg.max_age.as_secs() {
        "trusted state too old"
    } else if t.lag >= cfg.max_lag {
        "client too far behind head"
    } else {
        return Decision::Idle;
    };
    if t.newest_provable <= t.client {
        return Decision::Skip("head not past client");
    }
    Decision::Relay(reason)
}

/// Parses "90", "90s", "15m", "12h" or "2d".
fn parse_duration(s: &str) -> Result<Duration> {
    let i = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (n, unit) = s.split_at(i);
    let n: u64 = n.parse().with_context(|| format!("bad duration {s:?}"))?;
    let unit = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        u => bail!("bad duration unit {u:?} in {s:?}, want s, m, h or d"),
    };
    Ok(Duration::from_secs(n * unit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decide_cases() {
        let cfg = KeepConfig {
            interval: Duration::from_secs(1),
            max_age: Duration::from_secs(30),
            max_lag: 16,
        };
        let t = |pending, age, lag, newest_provable| Tick {
            pending,
            age,
            lag,
            newest_provable,
            client: 100,
        };
        let cases = [
            (t(false, 10, 5, 102), Decision::Idle),
            (t(true, 10, 5, 102), Decision::Relay("pending packets")),
            // packets still go even if head is stalled, run waits for blocks
            (t(true, 10, 2, 99), Decision::Relay("pending packets")),
            (
                t(false, 31, 5, 102),
                Decision::Relay("trusted state too old"),
            ),
            (
                t(false, 10, 16, 113),
                Decision::Relay("client too far behind head"),
            ),
            (t(false, 31, 3, 100), Decision::Skip("head not past client")),
            (t(false, 31, 2, 99), Decision::Skip("head not past client")),
            (
                t(false, 31, 4, 101),
                Decision::Relay("trusted state too old"),
            ),
        ];
        for (i, (tick, want)) in cases.iter().enumerate() {
            assert_eq!(decide(tick, &cfg), *want, "case {i}");
        }
    }

    #[test]
    fn parse_duration_units() {
        let cases = [
            ("90", Some(90)),
            ("30s", Some(30)),
            ("15m", Some(900)),
            ("12h", Some(43200)),
            ("2d", Some(172800)),
            ("", None),
            ("h", None),
            ("5w", None),
            ("-1s", None),
        ];
        for (s, want) in cases {
            assert_eq!(parse_duration(s).ok().map(|d| d.as_secs()), want, "{s:?}");
        }
    }
}
