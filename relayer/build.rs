use sp1_build::{build_program_with_args, BuildArgs};

fn main() {
    println!("cargo:rerun-if-env-changed=SP1_DOCKER");
    println!("cargo:rerun-if-env-changed=TEZOS_NETWORK");
    let network = std::env::var("TEZOS_NETWORK").unwrap_or_else(|_| "sandbox".into());
    // main.rs refuses to run with a different TEZOS_NETWORK than the ELF was built for.
    println!("cargo:rustc-env=TEZOS_NETWORK_BUILT={network}");
    let mut features = if network == "mainnet" { vec!["mainnet".into()] } else { vec![] };
    // e2e/protocol.sh: a program that must reject this chain's protocol.
    println!("cargo:rerun-if-env-changed=WRONG_PROTOCOL_PIN");
    if std::env::var("WRONG_PROTOCOL_PIN").is_ok_and(|v| v == "1") {
        features.push("wrong-protocol-pin".into());
    }

    // SP1_DOCKER=1 builds in Succinct's pinned image so the vkey doesn't depend on this machine.
    // Off by default since local mock runs don't care and docker is slow.
    let docker = std::env::var("SP1_DOCKER").is_ok_and(|v| v == "1");
    let args = if docker {
        BuildArgs {
            docker: true,
            locked: true,
            features,
            // Program pulls in ../crates, so the whole sp1/ dir has to be mounted.
            workspace_directory: Some("../sp1".into()),
            ..Default::default()
        }
    } else {
        BuildArgs { features, ..Default::default() }
    };
    build_program_with_args("../sp1/program", args);
}
