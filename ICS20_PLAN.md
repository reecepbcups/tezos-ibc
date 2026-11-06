# ICS20 plan (Tezos -> Ethereum fungible tokens)

Two parts. Part A is what we build now: one way, same shape as the NFT bridge. Part B is what it'd take to make it real ICS20, bidirectional with acks and timeouts. Part A is built so B doesn't have to change the packet format.

## Part A: one way ICS20

### How it works

```text
user --approve/operator--> ft_escrow (Tezos, port "transfer")
ft_escrow: pull tokens, keep them, call ibc_core.send_packet
ibc_core: store commitment at  "eth-0" || 0x01 || u64be(seq)   (unchanged)
relayer: SP1 proof of the commitment -> TezosLightClient.update
anyone: TezosTransfer.recvPacket(seq, timeout, data) -> rebuild commitment, check, mint voucher
```

Same trust model as the NFT bridge, nothing new in the light client or the SP1 program. `ibc_core.jsligo` doesn't change. Ports are bound once by the deployer, so we just `bind_port("transfer", ft_escrow)`.

Payload is the exact ibc-solidity ICS20 format so B can reuse it:

|Field|Value|
|-|-|
|source/dest port|`transfer`|
|version|`ics20-1`|
|encoding|`application/x-solidity-abi`|
|value|`abi.encode(FungibleTokenPacketData{denom, sender, receiver, amount, memo})`|

The struct's in `ibc-contracts/ibc-solidity/contracts/msgs/IICS20TransferMsgs.sol`. It's all strings plus a `uint256`, so the ABI encoding is dynamic (offsets + padded strings). That's the main new bit of LIGO work, the NFT payload was two fixed words.

### Tezos: `tezos/contracts/ft_escrow.jsligo`

One escrow instance per token. Simplest thing, and it dodges the problem below.

```jsligo
type token = ["Fa2", [address, nat]] | ["Fa12", address] | ["Tez"];

type storage = {
  core: address,
  token: token,
  denom: string,        // set at origination, e.g. "KT1...:0" or "tez"
  source_client: string // "eth-0"
};

// entry transfer({ amount: nat, receiver: string, memo: string, timeout_timestamp: nat })
```

Michelson gotchas:

- There's no address -> string op. So we can't build `denom` or `sender` from addresses on chain. `denom` is a storage string the deployer sets (checked off chain at deploy). For `sender` we can hex encode `Bytes.pack(sender)` with a nibble lookup, or just send `""`. Ethereum never reads it in part A.
- `receiver` has to be a `0x` + 40 hex string, since `ICS20Lib.mustHexStringToAddress` parses it on the other side. There's no refund path in part A, so a bad receiver = stuck funds. Either take the receiver as 20 bytes and hex encode it in LIGO (40 `String.concat`s off a 16 entry map, fine on gas), or take a string and validate every char. Hex encoding in LIGO is safer, so let's do that.
- Pull first, then send, like `nft_escrow`. If the pull fails, no packet.
- `Tez`: check `Tezos.get_amount() == amount * 1mutez`. Other variants: reject any tez.
- `amount > 0`.

Tests: LIGO unit tests for the ABI encoder against vectors from `cast abi-encode`. That's the bit that's easy to get subtly wrong.

### Ethereum: `eth/src/TezosTransfer.sol`

Like `TezosNFT`, talks to the client directly, no router.

- `recvPacket(uint64 seq, uint64 timeout, FungibleTokenPacketData data)`
  - not frozen, not already received
  - rebuild commitment with `sha256(abi.encode(data))` as the value hash, compare to `CLIENT.commitmentOf(path)`
  - mint `amount` of the voucher for `data.denom` to `mustHexStringToAddress(data.receiver)`
- One voucher ERC20 per denom. Admin registers `denom -> voucher` (with name, symbol, decimals, since FA2 metadata doesn't come over the wire). Unregistered denom reverts, the relayer retries later.
- No timeout check, same reason as `TezosNFT`. Tezos can't refund, so refusing late packets would strand the escrow.

Voucher supply on Ethereum always equals what's locked in the escrow on Tezos. In part A nothing ever comes back, so it's a one way peg.

### Shared client, shared sequences

NFT and ICS20 packets share `eth-0` and its sequence counter. So `TezosNFT` and `TezosTransfer` each see gaps. That's fine, `recvPacket` on the wrong contract just reverts `NotProven`. The relayer has to route by port though.

### Relayer

- `relayer/src/tezos.rs`: add `decode_ics20(&Packet)` next to `decode_nft`, with the same table test style (bad port, bad version, bad encoding, malformed ABI, bad receiver hex, zero amount).
- `relayer/src/main.rs`: `run`/`keep` currently hardwire `TezosNFT`. Switch to a `match p.source_port` that picks the target contract. `received(seq)` gets checked on the contract that matches the port.
- New env var `TRANSFER` for the contract address.

### E2E

- `tezos/deploy.sh`: deploy a test FA2 fungible + `ft_escrow`, bind `transfer`.
- `eth/script/Deploy.s.sol`: deploy `TezosTransfer`, register the test denom.
- New `e2e/ics20.sh` + `just e2e-ics20`: send FT and an NFT in the same Tezos block, prove once, both land. Check voucher balance and escrow balance match.

### Rough order and time

|Step|Time|
|-|-|
|`ft_escrow.jsligo` + ABI encoder + tests|1.5 days|
|`TezosTransfer.sol` + vouchers + forge tests|1 day|
|relayer routing + `decode_ics20`|0.5 day|
|deploy scripts + e2e|1 day|

About 4 days total if the LIGO ABI encoding goes smoothly. Add a day if it doesn't.

## Part B: bidirectional ICS20 (later)

The goal is to drop `TezosTransfer` and use stock ibc-solidity (`ICS26Router` + `ICS20Transfer`) on Ethereum, with a full IBC v2 core on Tezos. Here's what's missing, hardest first.

### 1. Ethereum light client on Tezos (the big one)

Tezos has to verify Ethereum state to accept packets, acks and timeouts from it.

The obvious move would be "verify an SP1 proof on Tezos", but SP1's Groth16/Plonk wrappers are over BN254. As far as I know Michelson only has BLS12-381 ops (`PAIRING_CHECK`, `bls12_381_g1/g2/fr`), no BN254. **I haven't verified this against the latest protocol, check before planning around it.**

Options:

|Option|Notes|
|-|-|
|Sync committee client in Michelson|Eth sync committee sigs are BLS12-381 too, so `PAIRING_CHECK` works. Needs hash_to_curve, SSZ, 512 pubkey aggregation, MPT/SSZ storage proofs. Gas limits are the real risk. Also sync committees aren't finality-strong security, which is a known weakness.|
|Groth16 over BLS12-381|Wrap our own circuit (gnark can do BLS12-381 Groth16) and verify with `PAIRING_CHECK`. Lets us keep "prove Ethereum in a zkVM". Needs a custom wrapper, SP1 doesn't ship one.|
|Attestor / multisig client|Easy, a few days. Big trust downgrade, fine for a testnet.|

Probably: attestor first to unblock everything else, then the BLS12-381 Groth16 route.

### 2. Full IBC v2 core on Tezos

`ibc_core.jsligo` is send only. It needs:

- `recv_packet`: verify membership of the Eth commitment via the client, write a receipt, call the app, write the ack commitment
- `acknowledge_packet`: verify the ack on Eth, delete our commitment, call the app (refund on error ack)
- `timeout_packet`: verify non-membership of the receipt on Eth past the timeout, delete the commitment, refund
- storage for receipts and acks under the ICS24 paths, same layout as `ICS24Host.sol`
- client registry instead of the fixed `counterparty` map

About 1 to 2 weeks in LIGO, plus tests.

### 3. Tezos app gets a real ICS20 module

`ft_escrow` becomes a full transfer app:

- `on_recv`: if the denom has our prefix (coming home) -> unescrow. Else mint a Tezos voucher (an FA2 we deploy per denom).
- `on_ack` error / `on_timeout`: refund the sender.
- denom trace handling like `ICS20Lib.getDenomPrefix`.

### 4. Proof work on our side of the light client

- **Non-membership proofs in `tezos-merkle`**. Ethereum's `ICS20Transfer` timeouts need proof that a receipt isn't in Tezos state. Irmin absence proofs mean showing the step isn't in the node (or inode subtree). Not done today. About 1 week.
- **Acks and receipts paths**. Prove entries of more big_maps than just `commitments`. `PublicValues.bigMapId` is a single id, so it either becomes a list, or receipts/acks go in the same big_map with distinct path prefixes (simpler, and that's how ICS24 does it anyway).
- **`ILightClient` interface**. `TezosLightClient.sol` needs `updateClient`, `verifyMembership`, `verifyNonMembership`, `misbehaviour`, `getClientState` so `ICS26Router` can use it. Membership checks against a stored state instead of the current "commitments carried in the update" design. Either store the state root and verify proofs on chain (Irmin proofs in Solidity, blake2b is pricey on the EVM), or keep doing it in SP1 and have `verifyMembership` take an SP1 proof. The second matches how the eureka SP1 tendermint client does it. About 1 week.
- The existing `PLAN.md` TODOs, BLS in SP1 and cycle handover proofs, are needed for mainnet either way.

### 5. Relayer

It needs to go both ways: watch Ethereum for `SendPacket`, prove into the Tezos client, relay acks back, and run timeouts. Probably worth looking at the eureka relayer in `ibc-contracts` instead of growing ours. 1 to 2 weeks.

### Migrating from A to B

Vouchers minted by `TezosTransfer` aren't `ICS20Transfer`'s `IBCERC20`s. To avoid a token swap later, make part A's vouchers implement the same mint/burn interface (`IMintableAndBurnable`) and check if `ICS20Transfer` can be pointed at existing tokens. I'm not sure it can today, needs a look. Worst case it's a one time burn and remint migration.

The Tezos escrow keeps its balances if `ft_escrow` is upgradable or the new app can pull from it. Simplest: give `ft_escrow` a deployer-only "hand escrow to new app" entry, used once.

### Rough size

|Piece|Time|
|-|-|
|Eth client on Tezos (attestor)|3 days|
|Eth client on Tezos (BLS12-381 zk)|1 to 2 months|
|Full IBC core in LIGO|1 to 2 weeks|
|Tezos ICS20 app + vouchers|1 week|
|Non-membership proofs|1 week|
|`ILightClient` adapter|1 week|
|Bidirectional relayer|1 to 2 weeks|

So roughly 6 to 8 weeks with an attestor client, and 2 to 3 months with a trustless one.

## Unresolved questions

1. Which tokens: FA2 fungible, FA1.2, XTZ, or all?
2. One escrow per token ok, or one escrow for many tokens?
3. `sender`: hex of packed address, or empty?
4. Voucher registration: admin only, or permissionless deploy per denom?
5. Is `TezosTransfer` admin the same Safe as the client admin?
6. Part B: is an attestor client acceptable as a first step?
