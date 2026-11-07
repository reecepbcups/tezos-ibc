# Tezos -> Ethereum IBC (FA2 -> ERC721)

One way. Tezos stores IBC v2 packet commitments, a light relayer carries proofs, and an SP1 Tezos light client on Ethereum checks them. The ERC721 contract talks to the client directly (BadBridge style, no router).

`ibc-contracts/` is the cosmos repo, used as reference only. `ref/` has irmin + a sparse octez checkout for reading source.

## Layout (planned)

|Dir|What|
|-|-|
|`tezos/sandbox/`|docker sandbox, Tallinn, 5 bakers, quorum 171/256|
|`tezos/contracts/`|LIGO: IBC core (send only) + FA2 escrow app + test FA2|
|`sp1/`|Rust: tezos light client lib, SP1 programs (update, membership), host prover|
|`eth/`|Solidity: `TezosLightClient.sol` + ERC721 receiver, mock SP1 verifier for local|
|`relayer/`|small Rust bin: watch Tezos, build proofs, submit to anvil|

## What the spike proved (all checked against the live sandbox)

Context commit, `scratch/commit_check.py`:

```text
header(B+1).context = blake2b( u64(32) ‖ root(B)
                             ‖ u64(1) ‖ u64(32) ‖ header(B).context
                             ‖ i64be(ts_B) ‖ u64(5) "Tezos"
                             ‖ u64(len) "lvl L, fit:(L, unlocked, 0, R), round R, N ops" )
```

So a block's state root is pinned by the *next* header. The message is just preimage data, we don't have to trust it.

Tree node, `scratch/tree_check.py`:

```text
node     = blake2b( u64(n) ‖ for each entry sorted by step: kind(8B) ‖ u8(len) step ‖ u64(32) hash )
           kind = ff00..00 for contents, 00..00 for node
contents = blake2b( u64(len) ‖ bytes )
```

`merkle_tree_v2/<path>` with `holey=false` gives the full path. With `holey=true` you only get a blinded root, which is useless for us.

Big_map value path: `big_maps/index/<id>/contents/<blake2b(packed key) hex>/data`.

## Finality

Attestations attest the *payload hash*, not the block hash. So to trust header H(n) we need a QC on block n+1, whose payload hash commits to `predecessor = hash(H(n))`. Then H(n).context gives the state root of n-1. I'm pretty sure this matches Tenderbake finality (a block is final once its successor has a QC), but it's worth a second look.

## Open: validator set

Right now the sandbox runs tz1 (ed25519) bakers. Slots get sampled per level from the cycle seed + stake, so the client would have to re-run Tezos' alias sampler. That's ugly.

If >= half the bakers use tz4 (BLS) consensus keys, Tallinn turns on "all bakers attest". Power is then stake weight, fixed per cycle, with no per-level sampling. The client tracks `{bls pk, stake}` per cycle and proves the next cycle's set from context with the same Merkle code. That looks like the clean path.

## Trust assumptions

Besides >2/3 of Tezos stake being honest, you're trusting the client's admin. It should be a Safe multisig.

After a timelock the admin can:

- rotate the program vkey (7 days by default, `UPGRADE_DELAY`). That's the protocol upgrade path.
- re-anchor the client (2 days, `REANCHOR_DELAY`). That's how it recovers after a freeze or when the trust root expired. It's only allowed once the client already failed like that (checked at queue and again at execute), so a healthy client can't be re-anchored at all.
- hand admin to someone else (7 days).

So on a healthy client the vkey (and who holds admin) is the only lever, and it's 7 days. Either of the first two can mint any NFT, including ones still sitting on Tezos. A fake root is as good as a fake vkey since it brings its own fake committee. Re-anchor gets the shorter delay on purpose, so a frozen bridge comes back faster. Both delays are constructor params if you want them equal.

The bridge is one way, so users can't really exit during the timelock. Somebody has to watch `Queued` events (they carry the full call) and yell, or cancel through the Safe.

Freezing doesn't need the admin. Anyone can post two valid proofs with different states at one level (`submitMisbehaviour`), or an `update` that conflicts with a stored state does it. Same commit at one level never freezes, Tezos can legitimately have QCs from different rounds.

Freezing limits damage, it doesn't undo it. If a fake update lands and someone calls `recvPacket` before anyone posts the evidence (even in the same block), that mint stands. Normal IBC clients have the same limit.

```text
queue(data) -> wait delay -> execute(data)     admin only, cancel(data) any time before
update / submitMisbehaviour -> frozen          anyone, instant
```

## Running the keeper

`relayer start` relays packets and refreshes the client before it goes stale. A packet relay moves the client forward too, so the 24h refresh only costs a proof on days with no traffic. It also serves a tiny HTTP server so something can page you when it stops working.

```sh
CLIENT=0x.. NFT=0x.. CORE=KT1.. ETH_RPC=https://.. TEZOS_RPC=https://.. \
KEEP_LOGS_TOKEN=$(openssl rand -hex 32) relayer start
```

The knobs:

- `KEEP_INTERVAL` (30s), `KEEP_MAX_AGE` (24h), `KEEP_MAX_LAG` (one cycle): when it checks and when it updates
- `KEEP_HTTP_ADDR` (`127.0.0.1:8080`), set it empty to turn the server off
- `KEEP_HEALTH_MAX_AGE` (30h): unhealthy once the trusted state is older than this
- `KEEP_HEALTH_STALE` (30m): unhealthy if no tick succeeded for this long, which also catches a hung loop
- `KEEP_LOGS_TOKEN`: unset means `/logs` is just a 404

Endpoints, GET only:

- `/healthz`, no auth. 200 when fine, 503 with JSON `reasons` when it's not (starting, frozen client, old trust, no recent good tick)
- `/logs?n=200`, last N lines (max 2000), needs `Authorization: Bearer $KEEP_LOGS_TOKEN`

Point an uptime monitor at `/healthz` every 5 to 15 min. You've got a day of slack before the 2 day trusting period runs out, so that's plenty.

Only `/healthz` should be reachable by the monitor. Keep `/logs` private, or at least behind the token, and there's no TLS so put a proxy in front if it leaves the box.

```sh
curl -s localhost:8080/healthz
curl -s -H "Authorization: Bearer $KEEP_LOGS_TOKEN" 'localhost:8080/logs?n=50'
```

### UptimeRobot

[UptimeRobot](https://uptimerobot.com/) works fine for this. It needs to reach `/healthz` from the internet though, so put a proxy in front that only lets that one path out, with TLS. Caddy makes that short:

```text
keeper.example.com {
    handle /healthz {
        reverse_proxy 127.0.0.1:8080
    }
    respond 404
}
```

Then in UptimeRobot:

1. New monitor, type HTTP(s), URL `https://keeper.example.com/healthz`
2. Interval 5 min (the free plan's minimum)
3. Add an alert contact you'll actually see, like Slack, Telegram or SMS. Email is easy to miss and you've only got a day
4. Optional: a keyword monitor on `"ok":true` instead, so a proxy that answers 200 by itself can't hide a dead keeper

Any non 200 from `/healthz` means the keeper is down, stuck, or the client is frozen. Check `/logs` from the box (or over SSH) to see why.

If you'd rather not expose a port, UptimeRobot also has heartbeat monitors where the service pings them instead. The keeper doesn't do that yet, it'd be a small addition.

## TODO, known gaps

- BLS (`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`) in SP1
- cycle handover proofs
