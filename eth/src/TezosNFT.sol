// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {TezosLightClient} from "./TezosLightClient.sol";

/// @notice ERC721 side of the one way FA2 bridge. Mints when a Tezos packet commitment has been proven.
/// @dev Rebuilds the IBC v2 commitment (ICS24Host.packetCommitmentBytes32) from the packet fields,
/// so a proven commitment pins the token id and recipient.
contract TezosNFT is ERC721 {
    TezosLightClient public immutable CLIENT;
    /// @notice ibc_core client id on Tezos for this bridge, the source of packets
    bytes public constant SOURCE_CLIENT = "eth-0";
    /// @notice our client id as Tezos sees it, the packet's dest client
    bytes public constant DEST_CLIENT = "tezos-0";
    bytes public constant PORT = "fa2-nft";
    bytes public constant VERSION = "fa2-nft-1";
    bytes public constant ENCODING = "application/x-solidity-abi";

    /// @notice sequence -> received
    mapping(uint64 => bool) public received;

    error AlreadyReceived();
    error NotProven();
    error ClientFrozen();

    constructor(TezosLightClient client) ERC721("Tezos NFT", "TZNFT") {
        CLIENT = client;
    }

    /// @notice Anyone can call. Mints `tokenId` to `recipient` once the matching packet is proven.
    /// @dev No timeout check on purpose. Tezos can't learn about a timeout (send only), so refusing late
    /// packets would strand the escrowed FA2 forever.
    function recvPacket(uint64 sequence, uint64 timeoutTimestamp, uint256 tokenId, address recipient) external {
        // A frozen client may hold commitments from a bad fork.
        if (CLIENT.frozen()) revert ClientFrozen();
        if (received[sequence]) revert AlreadyReceived();
        bytes32 proven = CLIENT.commitmentOf(commitmentPath(sequence));
        if (proven == bytes32(0) || proven != packetCommitment(timeoutTimestamp, tokenId, recipient)) {
            revert NotProven();
        }
        received[sequence] = true;
        // _mint, not _safeMint: a contract recipient without onERC721Received would strand the token.
        _mint(recipient, tokenId);
    }

    function commitmentPath(uint64 sequence) public pure returns (bytes memory) {
        return abi.encodePacked(SOURCE_CLIENT, uint8(1), sequence);
    }

    function packetCommitment(uint64 timeoutTimestamp, uint256 tokenId, address recipient)
        public
        pure
        returns (bytes32)
    {
        bytes32 payloadHash = sha256(
            abi.encodePacked(
                sha256(PORT), sha256(PORT), sha256(VERSION), sha256(ENCODING), sha256(abi.encode(tokenId, recipient))
            )
        );
        return sha256(
            abi.encodePacked(
                uint8(2), sha256(DEST_CLIENT), sha256(abi.encodePacked(timeoutTimestamp)), sha256(abi.encodePacked(payloadHash))
            )
        );
    }
}
