//! `relayer profile <attested_level> [trusted_level]` or `relayer profile <input.json>`:
//! executes one update (no proving, no Ethereum) and prints where the cycles go.
//! Build with `--features profiling`, or the per phase trackers come back empty.

use anyhow::{anyhow, bail, Context, Result};
use sp1_sdk::env::EnvProver;
use sp1_sdk::{Prover, SP1Stdin};
use tezos_consensus::{Attestation, PublicKey};
use tezos_lc::Input;

use crate::tezos::{build_input, Rpc, Trusted};
use crate::{env, CFG, ELF};

pub async fn profile(prover: &EnvProver) -> Result<()> {
    let args: Vec<String> = std::env::args().skip(2).collect();
    let input = match args.first() {
        Some(f) if f.ends_with(".json") => serde_json::from_slice(&std::fs::read(f)?)?,
        Some(a) => {
            let attested: i32 = a.parse().context("attested_level")?;
            // Default trusts n-1, the newest state the update can prove, so new == trusted.
            let level = match args.get(1) {
                Some(t) => t.parse().context("trusted_level")?,
                None => attested - 2,
            };
            let rpc = Rpc::new(&env("TEZOS_RPC", "http://localhost:8732"));
            // Commit of the state after `level` is in the next header, as anchor() reads it.
            let trusted = Trusted {
                level,
                commit: rpc.header(level + 1).await?.context,
            };
            // No commitments, so the big_map id is never read.
            build_input(&rpc, &trusted, 0, attested, &CFG, &[]).await?
        }
        None => bail!("usage: relayer profile <attested_level> [trusted_level] | <input.json>"),
    };
    if let Ok(p) = std::env::var("DUMP_INPUT") {
        std::fs::write(&p, serde_json::to_vec(&input)?)?;
    }
    tezos_lc::verify(&CFG, &input).map_err(|e| anyhow!("input rejected: {e:?}"))?;
    print_signers(&input)?;

    let mut stdin = SP1Stdin::new();
    stdin.write(&input);
    let (_, report) = prover.execute(ELF, stdin).await?;
    let total = report.total_instruction_count();
    println!("total instructions: {total}");
    let mut phases: Vec<_> = report.cycle_tracker.iter().collect();
    phases.sort_by(|a, b| b.1.cmp(a.1));
    println!("phase|cycles|%|calls");
    for (name, c) in phases {
        let calls = report.invocation_tracker.get(name).copied().unwrap_or(0);
        println!("{name}|{c}|{:.1}|{calls}", *c as f64 * 100.0 / total as f64);
    }
    println!("syscall|count");
    for (code, n) in report.syscall_counts.iter().filter(|(_, n)| **n > 0) {
        println!("{code:?}|{n}");
    }
    Ok(())
}

/// Signer counts and slots by key kind, and where cumulative slots first reach the threshold
/// in input order, to size an early quorum exit.
fn print_signers(input: &Input) -> Result<()> {
    let (cycle, pos) = CFG
        .era
        .level_info(input.attested.level)
        .ok_or(anyhow!("level outside era"))?;
    let (state, seed) = tezos_sampler::verify_cycle(
        &input.trusted_root,
        &input.sampler_state_proof,
        &input.seed_proof,
        cycle,
    )
    .map_err(|e| anyhow!("{e:?}"))?;
    let committee = tezos_lc::committee_at(&state, &seed, pos, CFG.committee_size)
        .map_err(|e| anyhow!("{e:?}"))?;
    let kind = |pk: &PublicKey| match pk {
        PublicKey::Ed25519(_) => "ed25519",
        PublicKey::Secp256k1(_) => "secp256k1",
        PublicKey::P256(_) => "p256",
        PublicKey::Bls(_) => "bls",
    };
    let mut by_kind: std::collections::BTreeMap<&str, (u64, u64)> = Default::default();
    let mut power = 0;
    let mut reached = None;
    // Ops past the threshold, by key kind, i.e. what an early exit would skip.
    let mut after: std::collections::BTreeMap<&str, u64> = Default::default();
    for (i, att) in input.attestations.iter().enumerate() {
        let slots: Vec<u16> = match att {
            Attestation::Single { slot, .. } => vec![*slot],
            Attestation::Aggregate { committee, .. } => committee.iter().map(|m| m.slot).collect(),
        };
        if reached.is_some() {
            let k = match att {
                Attestation::Single { slot, .. } => {
                    committee.get(slot).map_or("?", |v| kind(&v.consensus_pk))
                }
                Attestation::Aggregate { .. } => "bls_aggregate",
            };
            *after.entry(k).or_default() += 1;
        }
        for s in slots {
            let v = committee.get(&s).ok_or(anyhow!("unknown slot {s}"))?;
            let e = by_kind.entry(kind(&v.consensus_pk)).or_default();
            e.0 += 1;
            e.1 += v.power;
            power += v.power;
        }
        if reached.is_none() && power >= CFG.threshold {
            reached = Some(i + 1);
        }
    }
    let calls = tezos_sampler::committee(&state, &seed, pos, CFG.committee_size)
        .map_err(|e| anyhow!("{e:?}"))?
        .blake2b_calls;
    println!(
        "committee members: {}, sampler blake2b calls: {calls}",
        committee.len()
    );
    println!("kind|signers|slots");
    for (k, (n, p)) in &by_kind {
        println!("{k}|{n}|{p}");
    }
    println!(
        "attestation ops: {}, slots: {power}, threshold: {}, reached after op {:?}",
        input.attestations.len(),
        CFG.threshold,
        reached
    );
    println!("ops after threshold: {after:?}");
    Ok(())
}
