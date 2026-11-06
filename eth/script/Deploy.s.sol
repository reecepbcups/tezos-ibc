// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {TezosLightClient, ISP1Verifier} from "../src/TezosLightClient.sol";
import {TezosNFT} from "../src/TezosNFT.sol";

/// @dev SP1MockVerifier semantics: any public values pass with an empty proof. Local only.
contract MockVerifier is ISP1Verifier {
    function verifyProof(bytes32, bytes calldata, bytes calldata proof) external pure {
        require(proof.length == 0, "mock: proof must be empty");
    }
}

/// @dev Anchor (level, commit, timestamp) is read off chain from the Tezos RPC, see `relayer anchor`.
abstract contract DeployBase is Script {
    function deploy(ISP1Verifier verifier, address admin) internal {
        vm.startBroadcast();
        TezosLightClient client = new TezosLightClient(
            verifier,
            vm.envBytes32("VKEY"),
            vm.envBytes32("CHAIN_ID"),
            uint64(vm.envUint("BIG_MAP_ID")),
            // Must stay below Tezos unbonding, see TezosLightClient.TRUSTING_PERIOD.
            uint64(vm.envOr("TRUSTING_PERIOD", uint256(2 days))),
            // Re-anchor is shorter so a frozen client recovers faster, see REANCHOR_DELAY.
            uint64(vm.envOr("REANCHOR_DELAY", uint256(2 days))),
            uint64(vm.envOr("UPGRADE_DELAY", uint256(7 days))),
            admin,
            uint64(vm.envUint("ANCHOR_LEVEL")),
            vm.envBytes32("ANCHOR_COMMIT"),
            uint64(vm.envUint("ANCHOR_TIMESTAMP"))
        );
        TezosNFT nft = new TezosNFT(client);
        vm.stopBroadcast();
        console.log("CLIENT=%s", address(client));
        console.log("NFT=%s", address(nft));
        console.log("ADMIN=%s", admin);
    }
}

/// @notice Local deploy with a mock verifier. Pair with SP1_PROVER=mock.
contract Deploy is DeployBase {
    function run() external {
        vm.startBroadcast();
        ISP1Verifier verifier = new MockVerifier();
        vm.stopBroadcast();
        // Defaults to the deployer, fine for a local chain.
        deploy(verifier, vm.envOr("ADMIN", msg.sender));
    }
}

/// @notice Real deploy against Succinct's SP1 verifier. Pair with SP1_PROVER=cpu|network and an
/// ELF built with SP1_DOCKER=1, so VKEY matches what anyone else rebuilds.
/// SP1_VERIFIER: Succinct's Groth16 gateway, 0x397A5f7f3dBd538f23DE225B51f532c34448dA9B on
/// mainnet and Sepolia (sp1-contracts deployments/*.json, CREATE2 so other chains likely match).
contract DeployMainnet is DeployBase {
    function run() external {
        address verifier = vm.envAddress("SP1_VERIFIER");
        require(verifier.code.length > 0, "SP1_VERIFIER has no code");
        require(vm.envBytes32("VKEY") != bytes32(0), "VKEY unset");
        require(vm.envBytes32("CHAIN_ID") != bytes32(0), "CHAIN_ID unset");
        require(vm.envUint("BIG_MAP_ID") != 0, "BIG_MAP_ID unset");
        require(vm.envUint("ANCHOR_LEVEL") != 0, "ANCHOR_LEVEL unset");
        require(vm.envBytes32("ANCHOR_COMMIT") != bytes32(0), "ANCHOR_COMMIT unset");
        require(vm.envUint("ANCHOR_TIMESTAMP") != 0, "ANCHOR_TIMESTAMP unset");
        // Should be a Safe multisig, it can re-anchor the client and swap the vkey after the delays.
        address admin = vm.envAddress("ADMIN");
        require(admin != address(0), "ADMIN unset");
        deploy(ISP1Verifier(verifier), admin);
    }
}
