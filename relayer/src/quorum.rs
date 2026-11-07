//! Sends the program only enough attestations to reach the threshold, since every
//! signature checked costs cycles. Purely an optimization: any failure falls back to all ops.

use anyhow::{anyhow, bail, Result};
use tezos_consensus::Attestation;
use tezos_lc::{Config, Input};

/// Indices of the ops to keep, given each op's (is aggregate, power). Aggregates go first
/// because one can't be split, then singles by power descending, until `threshold`.
pub fn select(ops: &[(bool, u64)], threshold: u64) -> Result<Vec<usize>> {
    let mut order: Vec<usize> = (0..ops.len()).collect();
    // Stable sort keeps input order among equals, so the pick is deterministic.
    order.sort_by_key(|&i| (!ops[i].0, std::cmp::Reverse(ops[i].1)));
    let mut power = 0;
    let mut out = vec![];
    for i in order {
        if power >= threshold {
            break;
        }
        power += ops[i].1;
        out.push(i);
    }
    if power < threshold {
        bail!("attestations hold {power} slots, below threshold {threshold}");
    }
    out.sort_unstable();
    Ok(out)
}

/// `full` cut down to a quorum subset, with `slots` picked for it. Returns `full` unchanged
/// (slots included) if anything goes wrong, so liveness never depends on this.
pub fn trim(cfg: &Config, full: Input) -> Input {
    match subset(cfg, &full) {
        Ok(s) => s,
        Err(e) => {
            elogln!("quorum subset failed, sending all attestations: {e:#}");
            full
        }
    }
}

fn subset(cfg: &Config, full: &Input) -> Result<Input> {
    let (cycle, pos) = cfg
        .era
        .level_info(full.attested.level)
        .ok_or(anyhow!("level outside era"))?;
    let (state, seed) = tezos_sampler::verify_cycle(
        &full.trusted_root,
        &full.sampler_state_proof,
        &full.seed_proof,
        cycle,
    )
    .map_err(|e| anyhow!("{e:?}"))?;
    let committee = tezos_lc::committee_at(&state, &seed, pos, cfg.committee_size)
        .map_err(|e| anyhow!("{e:?}"))?;
    let power = |s: &u16| committee.get(s).map_or(0, |v| v.power);
    let ops: Vec<(bool, u64)> = full
        .attestations
        .iter()
        .map(|a| match a {
            Attestation::Single { slot, .. } => (false, power(slot)),
            Attestation::Aggregate { committee, .. } => {
                (true, committee.iter().map(|m| power(&m.slot)).sum())
            }
        })
        .collect();
    let keep = select(&ops, cfg.threshold)?;
    let mut s = full.clone();
    s.attestations = keep.iter().map(|&i| full.attestations[i].clone()).collect();
    s.slots = tezos_lc::quorum_slots(cfg, &s).map_err(|e| anyhow!("{e:?}"))?;
    tezos_lc::verify(cfg, &s).map_err(|e| anyhow!("subset rejected: {e:?}"))?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_cases() {
        let agg = |p| (true, p);
        let single = |p| (false, p);
        let cases: Vec<(&str, Vec<(bool, u64)>, u64, Option<Vec<usize>>)> = vec![
            (
                "aggregate alone enough",
                vec![single(500), agg(5000), single(100)],
                4667,
                Some(vec![1]),
            ),
            // mainnet 15703487 shape: aggregate 2523, then the biggest singles
            (
                "aggregate plus singles",
                vec![
                    single(549),
                    single(91),
                    single(1200),
                    agg(2523),
                    single(700),
                    single(48),
                ],
                4667,
                Some(vec![0, 2, 3, 4]),
            ),
            (
                "singles only, sandbox",
                vec![
                    single(1004),
                    single(991),
                    single(1010),
                    single(1006),
                    single(1013),
                    single(976),
                ],
                4667,
                Some(vec![0, 1, 2, 3, 4]),
            ),
            (
                "exactly threshold",
                vec![single(4000), single(667), single(10)],
                4667,
                Some(vec![0, 1]),
            ),
            (
                "not enough",
                vec![agg(2000), single(2000), single(666)],
                4667,
                None,
            ),
            ("empty", vec![], 4667, None),
        ];
        for (name, ops, threshold, want) in cases {
            assert_eq!(select(&ops, threshold).ok(), want, "{name}");
        }
    }

    fn fixture(name: &str) -> Input {
        let p = format!(
            "{}/../sp1/crates/tezos-lc/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
    }

    #[test]
    fn trims_real_inputs() {
        for (name, cfg, want_ops) in [
            ("update.json", tezos_lc::SANDBOX, 5),
            ("mainnet_update.json", tezos_lc::MAINNET, 4),
        ] {
            let full = fixture(name);
            let s = trim(&cfg, full.clone());
            assert_eq!(s.attestations.len(), want_ops, "{name}");
            assert_eq!(s.slots.len() as u64, cfg.threshold, "{name}");
            tezos_lc::verify(&cfg, &s).unwrap();
        }
    }

    #[test]
    fn falls_back_to_full_input() {
        // Below threshold even with every op: the subset fails, so the full input comes back.
        let mut full = fixture("update.json");
        full.attestations.truncate(2);
        let n = full.attestations.len();
        assert_eq!(trim(&tezos_lc::SANDBOX, full).attestations.len(), n);
    }
}
