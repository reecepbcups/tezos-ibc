// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Same interface as Succinct's SP1 verifier gateway
interface ISP1Verifier {
    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external view;
}

/// @notice Tezos light client checked by one SP1 program. Each proof moves the client from a trusted
/// Tezos state to a newer final one and can carry IBC packet commitments proven against it.
/// @dev The SP1 program does the heavy lifting: attestation quorum (sampled slots under the mainnet rules),
/// signatures, block hashes and Irmin Merkle proofs. This contract only chains trusted states.
/// Two valid proofs of different states at one level mean >1/3 of stake equivocated, so the client
/// freezes (permissionless, instant) until the timelocked admin re-anchors it.
contract TezosLightClient {
    struct Commitment {
        bytes path; // ICS24 path: clientId || 0x01 || u64be(sequence)
        bytes32 value; // ICS24 packet commitment
    }

    /// @dev Must match the SP1 program's output, abi encoded.
    struct PublicValues {
        bytes32 chainId; // Tezos chain id, 4 bytes left aligned
        uint64 bigMapId; // ibc_core commitments big_map the leaves were read from
        uint64 trustedLevel;
        bytes32 trustedCommit; // context commit hash stored for trustedLevel
        uint64 newLevel;
        bytes32 newCommit; // context commit hash of newLevel's resulting state
        uint64 newTimestamp; // unix seconds of the Tezos header carrying newCommit
        Commitment[] commitments; // proven against newCommit
    }

    ISP1Verifier public immutable VERIFIER;
    bytes32 public immutable CHAIN_ID;
    /// @notice ibc_core's commitments big_map. Ids are global on Tezos, so nobody else can write to it.
    uint64 public immutable BIG_MAP_ID;
    /// @notice Seconds a stored state stays usable as a trust root. Must stay below Tezos unbonding,
    /// or bakers with withdrawn stake could sign an alternate history without being slashed.
    uint64 public immutable TRUSTING_PERIOD;
    /// @notice Delay before a queued re-anchor runs. A fake root is as strong as a fake vkey, so this
    /// is shorter than UPGRADE_DELAY only to trade some safety for faster recovery. Only usable
    /// once the client is frozen or expired.
    uint64 public immutable REANCHOR_DELAY;
    /// @notice Delay before a queued vkey change or admin transfer runs, so users can react.
    uint64 public immutable UPGRADE_DELAY;

    /// @notice SP1 program vkey. Storage so a Tezos protocol upgrade can swap the program.
    bytes32 public vkey;
    /// @notice Ideally a multisig. Can only act through the timelock.
    address public admin;
    /// @notice Set on proven equivocation. Blocks updates and packet receipt until a re-anchor.
    bool public frozen;
    /// @notice Bumped on re-anchor so states and commitments from before it stop counting.
    uint64 public epoch;
    uint64 public latestLevel;
    /// @notice admin call -> unix time it can run, 0 if not queued
    mapping(bytes32 => uint256) public queuedAt;

    struct State {
        bytes32 commit; // context commit hash of that level's resulting state
        uint64 timestamp; // Tezos timestamp of that state
    }

    mapping(uint64 => mapping(uint64 => State)) internal states; // epoch -> level
    mapping(uint64 => mapping(bytes32 => bytes32)) internal proven; // epoch -> keccak256(path)

    event Updated(uint64 indexed level, bytes32 commit);
    event CommitmentProven(bytes path, bytes32 value);
    event Frozen(uint64 indexed level, bytes32 existing, bytes32 conflicting);
    event Queued(bytes32 indexed id, bytes data, uint256 eta);
    event Cancelled(bytes32 indexed id, bytes data);
    event Executed(bytes32 indexed id, bytes data);
    event Reanchored(uint64 indexed epoch, uint64 level, bytes32 commit);

    error WrongChain();
    error WrongBigMap();
    error UntrustedState();
    error TrustExpired();
    error NotNewer();
    error ClientFrozen();
    error NotMisbehaviour();
    error NotAdmin();
    error NotSelf();
    error AlreadyQueued();
    error NotQueued();
    error TimelockActive();
    error UnknownAction();
    error ClientHealthy();

    constructor(
        ISP1Verifier verifier,
        bytes32 programVkey,
        bytes32 chainId,
        uint64 bigMapId,
        uint64 trustingPeriod,
        uint64 reanchorDelay,
        uint64 upgradeDelay,
        address admin_,
        uint64 level,
        bytes32 commit,
        uint64 timestamp
    ) {
        VERIFIER = verifier;
        vkey = programVkey;
        CHAIN_ID = chainId;
        BIG_MAP_ID = bigMapId;
        TRUSTING_PERIOD = trustingPeriod;
        REANCHOR_DELAY = reanchorDelay;
        UPGRADE_DELAY = upgradeDelay;
        admin = admin_;
        // Trusted anchor, checked off chain at deploy. Same trust as the genesis of any light client.
        _store(level, State(commit, timestamp));
    }

    /// @notice Anyone can submit. A bad proof just reverts. A valid proof that conflicts with what's
    /// stored freezes the client instead, since reverting would throw the evidence away.
    function update(bytes calldata publicValues, bytes calldata proof) external {
        if (frozen) revert ClientFrozen();
        PublicValues memory pv = _verify(publicValues, proof);
        // Proving at the same level again is allowed so more commitments can be added later.
        if (pv.newLevel < pv.trustedLevel) revert NotNewer();

        uint64 e = epoch;
        bytes32 existing = states[e][pv.newLevel].commit;
        if (existing != bytes32(0) && existing != pv.newCommit) return _freeze(pv.newLevel, existing, pv.newCommit);
        if (existing == bytes32(0)) _store(pv.newLevel, State(pv.newCommit, pv.newTimestamp));

        for (uint256 i = 0; i < pv.commitments.length; ++i) {
            Commitment memory c = pv.commitments[i];
            bytes32 key = keccak256(c.path);
            bytes32 prev = proven[e][key];
            // Tezos never rewrites a packet commitment, so two values means two histories.
            if (prev != bytes32(0) && prev != c.value) return _freeze(pv.newLevel, prev, c.value);
            proven[e][key] = c.value;
            emit CommitmentProven(c.path, c.value);
        }
    }

    /// @notice Anyone can submit two valid proofs of different states at the same level. Each one is a
    /// Tezos quorum certificate, so together they show >1/3 of stake signed two histories.
    /// @dev newCommit is the state after newLevel, fixed by the chain up to there. QCs from other
    /// rounds of an honest chain give the same commit, so they never count.
    function submitMisbehaviour(bytes calldata pvA, bytes calldata proofA, bytes calldata pvB, bytes calldata proofB)
        external
    {
        PublicValues memory a = _verify(pvA, proofA);
        PublicValues memory b = _verify(pvB, proofB);
        if (a.newLevel != b.newLevel || a.newCommit == b.newCommit) revert NotMisbehaviour();
        _freeze(a.newLevel, a.newCommit, b.newCommit);
    }

    function stateCommit(uint64 level) external view returns (bytes32) {
        return states[epoch][level].commit;
    }

    function stateTimestamp(uint64 level) external view returns (uint64) {
        return states[epoch][level].timestamp;
    }

    function commitmentOf(bytes calldata path) external view returns (bytes32) {
        return proven[epoch][keccak256(path)];
    }

    // Admin timelock. `data` is calldata for one of the onlySelf functions below, so the Queued
    // event shows exactly what will run.

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    modifier onlySelf() {
        if (msg.sender != address(this)) revert NotSelf();
        _;
    }

    function queue(bytes calldata data) external onlyAdmin returns (bytes32 id) {
        id = keccak256(data);
        if (queuedAt[id] != 0) revert AlreadyQueued();
        uint256 eta = block.timestamp + _delay(data);
        if (bytes4(data[:4]) == this.reanchor.selector) _requireStuck();
        queuedAt[id] = eta;
        emit Queued(id, data, eta);
    }

    function cancel(bytes calldata data) external onlyAdmin {
        bytes32 id = keccak256(data);
        if (queuedAt[id] == 0) revert NotQueued();
        delete queuedAt[id];
        emit Cancelled(id, data);
    }

    function execute(bytes calldata data) external onlyAdmin {
        bytes32 id = keccak256(data);
        uint256 eta = queuedAt[id];
        if (eta == 0) revert NotQueued();
        if (block.timestamp < eta) revert TimelockActive();
        delete queuedAt[id];
        emit Executed(id, data);
        (bool ok, bytes memory ret) = address(this).call(data);
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
    }

    /// @notice Recovery after a freeze or an expired trust root. Starts a new epoch so nothing proven
    /// before, possibly from a bad fork, is trusted anymore.
    /// @dev Checked at queue and again here, so a client that recovered meanwhile can't be re-anchored.
    function reanchor(uint64 level, bytes32 commit, uint64 timestamp) external onlySelf {
        _requireStuck();
        uint64 e = ++epoch;
        frozen = false;
        latestLevel = 0;
        _store(level, State(commit, timestamp));
        emit Reanchored(e, level, commit);
    }

    /// @notice Protocol upgrade path: a new Tezos protocol needs a new program.
    function setVkey(bytes32 newVkey) external onlySelf {
        vkey = newVkey;
    }

    function setAdmin(address newAdmin) external onlySelf {
        admin = newAdmin;
    }

    /// @dev Only the three admin actions can be queued, each with its own delay.
    function _delay(bytes calldata data) internal view returns (uint256) {
        if (data.length < 4) revert UnknownAction();
        bytes4 sel = bytes4(data[:4]);
        if (sel == this.reanchor.selector) return REANCHOR_DELAY;
        if (sel == this.setVkey.selector || sel == this.setAdmin.selector) return UPGRADE_DELAY;
        revert UnknownAction();
    }

    /// @dev Re-anchor is only for a client that already failed, never a healthy one.
    function _requireStuck() internal view {
        if (frozen) return;
        if (uint256(states[epoch][latestLevel].timestamp) + TRUSTING_PERIOD < block.timestamp) return;
        revert ClientHealthy();
    }

    /// @dev Checks the proof, chain and that it starts from a live trusted state.
    function _verify(bytes calldata publicValues, bytes calldata proof) internal view returns (PublicValues memory pv) {
        VERIFIER.verifyProof(vkey, publicValues, proof);
        pv = abi.decode(publicValues, (PublicValues));
        if (pv.chainId != CHAIN_ID) revert WrongChain();
        if (pv.bigMapId != BIG_MAP_ID) revert WrongBigMap();
        State memory t = states[epoch][pv.trustedLevel];
        if (t.commit == bytes32(0) || t.commit != pv.trustedCommit) revert UntrustedState();
        if (uint256(t.timestamp) + TRUSTING_PERIOD < block.timestamp) revert TrustExpired();
    }

    function _store(uint64 level, State memory s) internal {
        states[epoch][level] = s;
        if (level > latestLevel) latestLevel = level;
        emit Updated(level, s.commit);
    }

    function _freeze(uint64 level, bytes32 existing, bytes32 conflicting) internal {
        frozen = true;
        emit Frozen(level, existing, conflicting);
    }
}
