// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {TezosLightClient, ISP1Verifier} from "../src/TezosLightClient.sol";
import {TezosNFT} from "../src/TezosNFT.sol";

/// @dev Like Succinct's SP1MockVerifier: any public values pass with an empty proof.
contract MockVerifier is ISP1Verifier {
    function verifyProof(bytes32, bytes calldata, bytes calldata proof) external pure {
        require(proof.length == 0, "mock: proof must be empty");
    }
}

/// @dev Only accepts one program vkey.
contract KeyedVerifier is ISP1Verifier {
    bytes32 immutable WANT;

    constructor(bytes32 want) {
        WANT = want;
    }

    function verifyProof(bytes32 vkey, bytes calldata, bytes calldata) external view {
        require(vkey == WANT, "wrong vkey");
    }
}

contract TezosNFTTest is Test {
    bytes32 constant CHAIN = bytes32(bytes4(0x8eceda2f)); // placeholder sandbox chain id bytes
    uint64 constant BIG_MAP = 5;
    bytes32 constant GENESIS_COMMIT = keccak256("anchor");
    // Real packet from the sandbox (tezos/deployed.env): token 7 to anvil account 1.
    bytes32 constant TEZOS_COMMITMENT = 0xde05b2fb09e969a905fa88affa90ed1a68562955511f88c36557103a5a61c32f;
    uint64 constant TIMEOUT = 1794079838;
    address constant RECIPIENT = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
    uint64 constant ANCHOR_TS = 1_700_000_000;
    uint64 constant PERIOD = 2 days;
    uint64 constant LOCK = 2 days; // re-anchor
    uint64 constant SLOW = 7 days; // vkey, admin
    address constant ADMIN = address(0xA11CE);

    TezosLightClient client;
    TezosNFT nft;

    function setUp() public {
        vm.warp(ANCHOR_TS);
        client = new TezosLightClient(
            new MockVerifier(), bytes32(0), CHAIN, BIG_MAP, PERIOD, LOCK, SLOW, ADMIN, 100, GENESIS_COMMIT, ANCHOR_TS
        );
        nft = new TezosNFT(client);
    }

    function _pv(uint64 trustedLevel, bytes32 trusted, uint64 newLevel, bytes32 newCommit, bytes32 value)
        internal
        view
        returns (bytes memory)
    {
        TezosLightClient.Commitment[] memory cs = new TezosLightClient.Commitment[](1);
        cs[0] = TezosLightClient.Commitment(nft.commitmentPath(1), value);
        // One second per level keeps timestamps deterministic.
        uint64 ts = ANCHOR_TS + newLevel - 100;
        return
            abi.encode(
                TezosLightClient.PublicValues(CHAIN, BIG_MAP, trustedLevel, trusted, newLevel, newCommit, ts, cs)
            );
    }

    function test_commitmentMatchesTezos() public view {
        assertEq(nft.packetCommitment(TIMEOUT, 7, RECIPIENT), TEZOS_COMMITMENT);
        assertEq(nft.commitmentPath(1), hex"6574682d30010000000000000001");
    }

    function test_happyPath() public {
        client.update(_pv(100, GENESIS_COMMIT, 120, keccak256("s120"), TEZOS_COMMITMENT), "");
        assertEq(client.latestLevel(), 120);
        nft.recvPacket(1, TIMEOUT, 7, RECIPIENT);
        assertEq(nft.ownerOf(7), RECIPIENT);
        vm.expectRevert(TezosNFT.AlreadyReceived.selector);
        nft.recvPacket(1, TIMEOUT, 7, RECIPIENT);
    }

    function test_recvRejects() public {
        vm.expectRevert(TezosNFT.NotProven.selector);
        nft.recvPacket(1, TIMEOUT, 7, RECIPIENT);

        client.update(_pv(100, GENESIS_COMMIT, 120, keccak256("s120"), TEZOS_COMMITMENT), "");
        // Same sequence, different fields: commitment won't match.
        vm.expectRevert(TezosNFT.NotProven.selector);
        nft.recvPacket(1, TIMEOUT, 8, RECIPIENT);
        vm.expectRevert(TezosNFT.NotProven.selector);
        nft.recvPacket(1, TIMEOUT, 7, address(0xBEEF));
        vm.expectRevert(TezosNFT.NotProven.selector);
        nft.recvPacket(1, TIMEOUT + 1, 7, RECIPIENT);
    }

    function test_updateRejects() public {
        bytes32 c = TEZOS_COMMITMENT;
        bytes memory pv1 = _pv(100, keccak256("wrong"), 120, keccak256("s120"), c);
        vm.expectRevert(TezosLightClient.UntrustedState.selector);
        client.update(pv1, "");
        bytes memory pv2 = _pv(99, GENESIS_COMMIT, 120, keccak256("s120"), c);
        vm.expectRevert(TezosLightClient.UntrustedState.selector);
        client.update(pv2, "");
        bytes memory pv3 = _pv(100, GENESIS_COMMIT, 90, keccak256("s90"), c);
        vm.expectRevert(TezosLightClient.NotNewer.selector);
        client.update(pv3, "");
        bytes memory pv4 = _pv(100, GENESIS_COMMIT, 120, keccak256("s120"), c);
        vm.expectRevert("mock: proof must be empty");
        client.update(pv4, hex"01");

        TezosLightClient.Commitment[] memory none = new TezosLightClient.Commitment[](0);
        vm.expectRevert(TezosLightClient.WrongChain.selector);
        client.update(
            abi.encode(TezosLightClient.PublicValues(bytes32(0), BIG_MAP, 100, GENESIS_COMMIT, 120, 0, 0, none)), ""
        );
        vm.expectRevert(TezosLightClient.WrongBigMap.selector);
        client.update(abi.encode(TezosLightClient.PublicValues(CHAIN, 6, 100, GENESIS_COMMIT, 120, 0, 0, none)), "");
    }

    function test_conflictingStateFreezes() public {
        client.update(_pv(100, GENESIS_COMMIT, 120, keccak256("s120"), TEZOS_COMMITMENT), "");
        // Same level, other commit: no revert, so the evidence sticks.
        vm.expectEmit(address(client));
        emit TezosLightClient.Frozen(120, keccak256("s120"), keccak256("other"));
        client.update(_pv(100, GENESIS_COMMIT, 120, keccak256("other"), TEZOS_COMMITMENT), "");
        assertTrue(client.frozen());
        assertEq(client.stateCommit(120), keccak256("s120"));

        bytes memory next = _pv(120, keccak256("s120"), 130, keccak256("s130"), TEZOS_COMMITMENT);
        vm.expectRevert(TezosLightClient.ClientFrozen.selector);
        client.update(next, "");
        // Proven before the freeze, still refused.
        vm.expectRevert(TezosNFT.ClientFrozen.selector);
        nft.recvPacket(1, TIMEOUT, 7, RECIPIENT);
    }

    function test_conflictingCommitmentFreezes() public {
        client.update(_pv(100, GENESIS_COMMIT, 120, keccak256("s120"), TEZOS_COMMITMENT), "");
        client.update(_pv(120, keccak256("s120"), 130, keccak256("s130"), keccak256("different")), "");
        assertTrue(client.frozen());
        assertEq(client.commitmentOf(nft.commitmentPath(1)), TEZOS_COMMITMENT);
    }

    function test_sameCommitIsNotConflict() public {
        bytes memory pv = _pv(100, GENESIS_COMMIT, 120, keccak256("s120"), TEZOS_COMMITMENT);
        client.update(pv, "");
        client.update(pv, "");
        client.update(_pv(120, keccak256("s120"), 130, keccak256("s130"), TEZOS_COMMITMENT), "");
        assertFalse(client.frozen());
        assertEq(client.latestLevel(), 130);
    }

    function test_sameCommitNeverFreezes() public {
        // Same level and commit, different proofs (another round's QC, more commitments): honest.
        bytes memory a = _pv(100, GENESIS_COMMIT, 120, keccak256("s120"), TEZOS_COMMITMENT);
        TezosLightClient.Commitment[] memory none = new TezosLightClient.Commitment[](0);
        bytes memory b = abi.encode(
            TezosLightClient.PublicValues(
                CHAIN, BIG_MAP, 100, GENESIS_COMMIT, 120, keccak256("s120"), ANCHOR_TS + 20, none
            )
        );
        vm.expectRevert(TezosLightClient.NotMisbehaviour.selector);
        client.submitMisbehaviour(a, "", b, "");
        // Replaying one proof as both halves.
        vm.expectRevert(TezosLightClient.NotMisbehaviour.selector);
        client.submitMisbehaviour(a, "", a, "");

        client.update(a, "");
        client.update(a, "");
        client.update(b, "");
        assertFalse(client.frozen());
        assertEq(client.stateCommit(120), keccak256("s120"));
    }

    function test_misbehaviour() public {
        bytes memory a = _pv(100, GENESIS_COMMIT, 120, keccak256("A"), TEZOS_COMMITMENT);
        bytes memory b = _pv(100, GENESIS_COMMIT, 120, keccak256("B"), TEZOS_COMMITMENT);
        // Nothing stored at 120, both just have to be valid.
        vm.prank(address(0xBAD));
        client.submitMisbehaviour(a, "", b, "");
        assertTrue(client.frozen());
        vm.expectRevert(TezosLightClient.ClientFrozen.selector);
        client.update(a, "");
    }

    function test_misbehaviourRejects() public {
        bytes memory a = _pv(100, GENESIS_COMMIT, 120, keccak256("A"), TEZOS_COMMITMENT);
        vm.expectRevert(TezosLightClient.NotMisbehaviour.selector);
        client.submitMisbehaviour(a, "", a, "");
        bytes memory other = _pv(100, GENESIS_COMMIT, 121, keccak256("B"), TEZOS_COMMITMENT);
        vm.expectRevert(TezosLightClient.NotMisbehaviour.selector);
        client.submitMisbehaviour(a, "", other, "");

        bytes memory untrusted = _pv(100, keccak256("fork"), 120, keccak256("B"), TEZOS_COMMITMENT);
        vm.expectRevert(TezosLightClient.UntrustedState.selector);
        client.submitMisbehaviour(a, "", untrusted, "");
        bytes memory b = _pv(100, GENESIS_COMMIT, 120, keccak256("B"), TEZOS_COMMITMENT);
        vm.expectRevert("mock: proof must be empty");
        client.submitMisbehaviour(a, "", b, hex"01");

        TezosLightClient.Commitment[] memory none = new TezosLightClient.Commitment[](0);
        bytes memory otherChain = abi.encode(
            TezosLightClient.PublicValues(bytes32(0), BIG_MAP, 100, GENESIS_COMMIT, 120, keccak256("B"), 0, none)
        );
        vm.expectRevert(TezosLightClient.WrongChain.selector);
        client.submitMisbehaviour(a, "", otherChain, "");

        vm.warp(ANCHOR_TS + PERIOD + 1);
        vm.expectRevert(TezosLightClient.TrustExpired.selector);
        client.submitMisbehaviour(a, "", b, "");
        assertFalse(client.frozen());
    }

    function _reanchorCall(uint64 level, bytes32 commit, uint64 ts) internal pure returns (bytes memory) {
        return abi.encodeCall(TezosLightClient.reanchor, (level, commit, ts));
    }

    function test_reanchorUnfreezes() public {
        // Fork state proven, then the conflict freezes.
        client.update(_pv(100, GENESIS_COMMIT, 120, keccak256("s120"), TEZOS_COMMITMENT), "");
        client.update(_pv(100, GENESIS_COMMIT, 120, keccak256("other"), TEZOS_COMMITMENT), "");
        assertTrue(client.frozen());

        uint64 ts = ANCHOR_TS + 1 hours;
        bytes memory call = _reanchorCall(200, keccak256("s200"), ts);
        vm.prank(ADMIN);
        vm.expectEmit(address(client));
        emit TezosLightClient.Queued(keccak256(call), call, block.timestamp + LOCK);
        client.queue(call);

        vm.warp(block.timestamp + LOCK - 1);
        vm.prank(ADMIN);
        vm.expectRevert(TezosLightClient.TimelockActive.selector);
        client.execute(call);

        vm.warp(block.timestamp + 1);
        vm.expectRevert(TezosLightClient.NotAdmin.selector);
        client.execute(call);
        vm.prank(ADMIN);
        client.execute(call);

        assertFalse(client.frozen());
        assertEq(client.epoch(), 1);
        assertEq(client.latestLevel(), 200);
        assertEq(client.stateCommit(200), keccak256("s200"));
        // Old epoch is gone: fork state, anchor and its commitments.
        assertEq(client.stateCommit(120), bytes32(0));
        assertEq(client.commitmentOf(nft.commitmentPath(1)), bytes32(0));
        bytes memory fromOld = _pv(120, keccak256("s120"), 210, keccak256("s210"), TEZOS_COMMITMENT);
        vm.expectRevert(TezosLightClient.UntrustedState.selector);
        client.update(fromOld, "");

        // Fresh root works for relaying again.
        client.update(_pv(200, keccak256("s200"), 210, keccak256("s210"), TEZOS_COMMITMENT), "");
        nft.recvPacket(1, TIMEOUT, 7, RECIPIENT);
        assertEq(nft.ownerOf(7), RECIPIENT);

        // One shot: the queue entry is consumed.
        vm.prank(ADMIN);
        vm.expectRevert(TezosLightClient.NotQueued.selector);
        client.execute(call);
    }

    function test_reanchorAfterExpiry() public {
        bytes memory pv = _pv(100, GENESIS_COMMIT, 120, keccak256("s120"), TEZOS_COMMITMENT);
        vm.warp(ANCHOR_TS + PERIOD + 1);
        vm.expectRevert(TezosLightClient.TrustExpired.selector);
        client.update(pv, "");

        bytes memory call = _reanchorCall(300, keccak256("s300"), uint64(block.timestamp));
        vm.startPrank(ADMIN);
        client.queue(call);
        vm.warp(block.timestamp + LOCK);
        client.execute(call);
        vm.stopPrank();
        // Trust clock runs from the new anchor's own timestamp.
        assertEq(client.stateTimestamp(300), ANCHOR_TS + PERIOD + 1);
        client.update(_pv(300, keccak256("s300"), 310, keccak256("s310"), TEZOS_COMMITMENT), "");
        assertEq(client.latestLevel(), 310);
    }

    function test_adminGuards() public {
        bytes memory call = abi.encodeCall(TezosLightClient.setVkey, (bytes32(uint256(1))));
        vm.expectRevert(TezosLightClient.NotAdmin.selector);
        client.queue(call);
        vm.expectRevert(TezosLightClient.NotAdmin.selector);
        client.cancel(call);
        // Targets only run through execute.
        vm.prank(ADMIN);
        vm.expectRevert(TezosLightClient.NotSelf.selector);
        client.reanchor(200, keccak256("s200"), ANCHOR_TS);
        vm.expectRevert(TezosLightClient.NotSelf.selector);
        client.setVkey(bytes32(uint256(1)));
        vm.expectRevert(TezosLightClient.NotSelf.selector);
        client.setAdmin(address(this));

        vm.startPrank(ADMIN);
        vm.expectRevert(TezosLightClient.NotQueued.selector);
        client.execute(call);
        client.queue(call);
        vm.expectRevert(TezosLightClient.AlreadyQueued.selector);
        client.queue(call);
        client.cancel(call);
        vm.warp(block.timestamp + SLOW);
        vm.expectRevert(TezosLightClient.NotQueued.selector);
        client.execute(call);
        vm.expectRevert(TezosLightClient.NotQueued.selector);
        client.cancel(call);
        vm.stopPrank();
    }

    function test_reanchorGatedOnState() public {
        bytes memory call = _reanchorCall(300, keccak256("s300"), ANCHOR_TS + PERIOD);
        // Healthy client: the admin can't touch its trust root at all.
        vm.prank(ADMIN);
        vm.expectRevert(TezosLightClient.ClientHealthy.selector);
        client.queue(call);
        // Fresh state keeps it healthy right up to the boundary.
        client.update(_pv(100, GENESIS_COMMIT, 120, keccak256("s120"), TEZOS_COMMITMENT), "");
        vm.warp(ANCHOR_TS + 20 + PERIOD);
        vm.prank(ADMIN);
        vm.expectRevert(TezosLightClient.ClientHealthy.selector);
        client.queue(call);

        // Expired: queue works.
        vm.warp(ANCHOR_TS + 20 + PERIOD + 1);
        vm.prank(ADMIN);
        client.queue(call);
    }

    function test_reanchorRecheckedAtExecute() public {
        // Two re-anchors queued while expired. Once one runs the client is healthy again.
        vm.warp(ANCHOR_TS + PERIOD + 1);
        uint64 ts = uint64(block.timestamp);
        bytes memory first = _reanchorCall(300, keccak256("s300"), ts);
        bytes memory second = _reanchorCall(301, keccak256("evil"), ts);
        vm.startPrank(ADMIN);
        client.queue(first);
        client.queue(second);
        vm.warp(block.timestamp + LOCK);
        client.execute(first);
        vm.expectRevert(TezosLightClient.ClientHealthy.selector);
        client.execute(second);
        vm.stopPrank();
        assertEq(client.latestLevel(), 300);
    }

    function test_reanchorQueuedWhileFrozen() public {
        client.submitMisbehaviour(
            _pv(100, GENESIS_COMMIT, 120, keccak256("A"), TEZOS_COMMITMENT),
            "",
            _pv(100, GENESIS_COMMIT, 120, keccak256("B"), TEZOS_COMMITMENT),
            ""
        );
        // Anchor is still in its trusting period, frozen alone is enough.
        bytes memory call = _reanchorCall(300, keccak256("s300"), ANCHOR_TS + 1);
        vm.startPrank(ADMIN);
        client.queue(call);
        vm.warp(block.timestamp + LOCK);
        client.execute(call);
        vm.stopPrank();
        assertFalse(client.frozen());
    }

    function test_setVkey() public {
        bytes32 v2 = bytes32(uint256(2));
        TezosLightClient c = new TezosLightClient(
            new KeyedVerifier(v2), bytes32(0), CHAIN, BIG_MAP, PERIOD, LOCK, SLOW, ADMIN, 100, GENESIS_COMMIT, ANCHOR_TS
        );
        bytes memory pv = _pv(100, GENESIS_COMMIT, 120, keccak256("s120"), TEZOS_COMMITMENT);
        vm.expectRevert("wrong vkey");
        c.update(pv, "");

        bytes memory call = abi.encodeCall(TezosLightClient.setVkey, (v2));
        vm.startPrank(ADMIN);
        c.queue(call);
        vm.expectRevert(TezosLightClient.TimelockActive.selector);
        c.execute(call);
        vm.warp(block.timestamp + LOCK);
        // Re-anchor delay isn't enough for this one.
        vm.expectRevert(TezosLightClient.TimelockActive.selector);
        c.execute(call);
        vm.warp(block.timestamp + SLOW - LOCK);
        c.execute(call);
        vm.stopPrank();
        assertEq(c.vkey(), v2);
        // Anchor is still trusted, the upgrade doesn't touch states.
        vm.warp(ANCHOR_TS + 1);
        c.update(pv, "");
        assertEq(c.latestLevel(), 120);
    }

    function test_onlyAdminActionsQueue() public {
        vm.startPrank(ADMIN);
        vm.expectRevert(TezosLightClient.UnknownAction.selector);
        client.queue(abi.encodeCall(TezosLightClient.update, ("", "")));
        vm.expectRevert(TezosLightClient.UnknownAction.selector);
        client.queue(hex"01");
        vm.stopPrank();
    }

    function test_setAdmin() public {
        address next = address(0xB0B);
        bytes memory call = abi.encodeCall(TezosLightClient.setAdmin, (next));
        vm.startPrank(ADMIN);
        client.queue(call);
        vm.expectRevert(TezosLightClient.TimelockActive.selector);
        client.execute(call);
        vm.warp(block.timestamp + LOCK);
        // Re-anchor delay isn't enough for this one.
        vm.expectRevert(TezosLightClient.TimelockActive.selector);
        client.execute(call);
        vm.warp(block.timestamp + SLOW - LOCK);
        client.execute(call);
        vm.expectRevert(TezosLightClient.NotAdmin.selector);
        client.queue(call);
        vm.stopPrank();
        assertEq(client.admin(), next);
    }

    function test_trustExpired() public {
        bytes memory pv = _pv(100, GENESIS_COMMIT, 120, keccak256("s120"), TEZOS_COMMITMENT);
        // Exactly at the boundary the anchor is still trusted.
        vm.warp(ANCHOR_TS + PERIOD);
        uint256 snap = vm.snapshotState();
        client.update(pv, "");
        vm.revertToState(snap);

        vm.warp(ANCHOR_TS + PERIOD + 1);
        vm.expectRevert(TezosLightClient.TrustExpired.selector);
        client.update(pv, "");

        // A fresh state stored before expiry is a new root with its own clock.
        vm.warp(ANCHOR_TS + 1 days);
        client.update(pv, "");
        assertEq(client.stateTimestamp(120), ANCHOR_TS + 20);
        vm.warp(ANCHOR_TS + 20 + PERIOD);
        client.update(_pv(120, keccak256("s120"), 130, keccak256("s130"), TEZOS_COMMITMENT), "");
        assertEq(client.latestLevel(), 130);
    }
}
