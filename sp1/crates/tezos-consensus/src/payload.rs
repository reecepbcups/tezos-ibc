//! Block payload hash, the value attestations sign.
//!
//! From proto_025_PsUshuai/lib_protocol/block_payload_repr.ml:
//! `blake2b(predecessor ‖ i32be(payload_round) ‖ Operation_list_hash.compute(ops))`
//! where ops are the hashes of the block's non-consensus operations
//! (validation passes 1..3, in block order; apply.ml `record_operation`).

use crate::{blake2b256, Hash};

pub fn block_payload_hash(predecessor: &Hash, payload_round: i32, op_hashes: &[Hash]) -> Hash {
    blake2b256(&[
        predecessor,
        &payload_round.to_be_bytes(),
        &operation_list_hash(op_hashes),
    ])
}

/// `Operation_list_hash.compute`, a port of `Generic_Merkle_tree` in lib_crypto/blake2B.ml.
/// Leaves are `blake2b(op_hash)`; odd levels are padded with the last element,
/// so the tree is effectively padded to a power of two with copies of the last leaf.
pub fn operation_list_hash(op_hashes: &[Hash]) -> Hash {
    let node = |a: &Hash, b: &Hash| blake2b256(&[a, b]);
    let n = op_hashes.len();
    match n {
        0 => blake2b256(&[]),
        1 => blake2b256(&[&op_hashes[0]]),
        _ => {
            let last = blake2b256(&[&op_hashes[n - 1]]);
            let mut a = vec![last; n + 1];
            for (i, h) in op_hashes.iter().enumerate() {
                a[i] = blake2b256(&[h]);
            }
            // Straight port of the OCaml `step` loop, array size grows by one at most.
            let mut n = n;
            loop {
                let m = n.div_ceil(2);
                for i in 0..m {
                    a[i] = node(&a[2 * i], &a[2 * i + 1]);
                }
                if a.len() < m + 2 {
                    a.resize(m + 2, [0; 32]);
                }
                a[m] = node(&a[n], &a[n]);
                if m == 1 {
                    return a[0];
                } else if m.is_multiple_of(2) {
                    n = m;
                } else {
                    a[m + 1] = a[m];
                    n = m + 1;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference: pad leaves to a power of two with the last one, then a plain binary tree.
    fn padded(ops: &[Hash]) -> Hash {
        let mut lvl: Vec<Hash> = ops.iter().map(|h| blake2b256(&[h])).collect();
        lvl.resize(ops.len().next_power_of_two(), *lvl.last().unwrap());
        while lvl.len() > 1 {
            lvl = lvl.chunks(2).map(|c| blake2b256(&[&c[0], &c[1]])).collect();
        }
        lvl[0]
    }

    #[test]
    fn merkle_matches_padded_tree() {
        for n in 1..40u8 {
            let ops: Vec<Hash> = (0..n).map(|i| [i; 32]).collect();
            assert_eq!(operation_list_hash(&ops), padded(&ops), "n={n}");
        }
    }
}
