//! SP1 program: one Tezos light client update. All logic lives in `tezos_lc::verify`.
#![no_main]
sp1_zkvm::entrypoint!(main);

// Picked at compile time so the vkey binds the network.
#[cfg(not(any(feature = "mainnet", feature = "wrong-protocol-pin")))]
const CFG: tezos_lc::Config = tezos_lc::SANDBOX;
#[cfg(feature = "mainnet")]
const CFG: tezos_lc::Config = tezos_lc::MAINNET;
// e2e/protocol.sh only: pins PtTALLiN so a PsUshuai chain must be rejected.
#[cfg(feature = "wrong-protocol-pin")]
const CFG: tezos_lc::Config = tezos_lc::Config {
    protocol: [
        0xe4, 0x1e, 0xbc, 0x12, 0xf0, 0x0b, 0xf0, 0x4d, 0x89, 0xed, 0x0b, 0x1b, 0x5e, 0x97, 0xe6,
        0x36, 0x80, 0xd4, 0x31, 0x75, 0x37, 0x05, 0x72, 0x6d, 0xf9, 0xdb, 0xf7, 0xe9, 0xe5, 0x12,
        0xe1, 0x9b,
    ],
    ..tezos_lc::SANDBOX
};

pub fn main() {
    // Deserializing the proofs isn't free, so it gets its own tracker.
    let input: tezos_lc::Input =
        tezos_consensus::track!("read_input", sp1_zkvm::io::read());
    let out = tezos_consensus::track!("verify", tezos_lc::verify_encoded(&CFG, &input))
        .expect("tezos update rejected");
    sp1_zkvm::io::commit_slice(&out);
}
