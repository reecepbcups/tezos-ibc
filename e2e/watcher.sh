#!/bin/sh
# Keeper watcher duty: a fork's proof gets into the client, the keeper (on the honest chain)
# spots the bad state, proves the honest one at the same level and so freezes the client.
# Fork setup is e2e/freeze.sh's: commit the stopped sandbox, run the copy as a second chain.
#   TEZOS_CONTAINER=tezos-c TEZOS_PORT=38732 FORK_CONTAINER=tezos-c2 FORK_PORT=38733 ANVIL_PORT=38549 e2e/watcher.sh
TEZOS_CONTAINER=${TEZOS_CONTAINER:-tezos-c}
TEZOS_PORT=${TEZOS_PORT:-38732}
ANVIL_PORT=${ANVIL_PORT:-38549}
. "$(dirname "$0")/lib.sh"
FORK=${FORK_CONTAINER:-tezos-c2}
FORK_PORT=${FORK_PORT:-38733}
FORK_RPC=http://localhost:$FORK_PORT
IMAGE=$FORK-image
KLOG=$WORK/keep.log
# Waits up to $1 seconds for the rest of the args to succeed.
within() { n=$1; shift; while [ "$n" -gt 0 ]; do "$@" && return 0; sleep 1; n=$((n - 1)); done; return 1; }
KEEPER=
cleanup() {
  [ -n "$KEEPER" ] && kill "$KEEPER" 2>/dev/null || true
  docker rm -f "$FORK" >/dev/null 2>&1 || true
  docker rmi "$IMAGE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

start_infra
# Own copy: the cargo target dir may be shared, and other e2e scripts rebuild with other flags.
TARGET=$(cd "$ROOT/relayer" && cargo metadata -q --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
BIN=$WORK/relayer
cp "$TARGET/release/relayer" "$BIN"
deploy_tezos
anchor
deploy_eth
echo "client $CLIENT nft $NFT, anchor $ANCHOR_LEVEL"
wait_level $((ANCHOR_LEVEL + 4))

echo "== fork $TEZOS_CONTAINER into $FORK"
docker exec "$TEZOS_CONTAINER" pkill -TERM octez-node || true
sleep 3
docker stop "$TEZOS_CONTAINER" >/dev/null
docker rm -f "$FORK" >/dev/null 2>&1 || true
docker commit "$TEZOS_CONTAINER" "$IMAGE" >/dev/null
docker start "$TEZOS_CONTAINER" >/dev/null
SB=$ROOT/tezos/sandbox
docker run -d --name "$FORK" -p "$FORK_PORT:8732" -v "$SB/start.sh:/start.sh:ro" \
  -v "$SB/params.json:/params.json:ro" --entrypoint sh "$IMAGE" /start.sh >/dev/null
until curl -sf "$FORK_RPC/chains/main/blocks/head/header" >/dev/null; do sleep 1; done
until curl -sf "$TEZOS_RPC/chains/main/blocks/head/header" >/dev/null; do sleep 1; done
# Same bakers and clock could bake identical blocks, a transfer only on the fork splits them.
docker exec "$FORK" octez-client -d /home/tezos/data/client -E http://127.0.0.1:8732 \
  transfer 1 from bootstrap2 to bootstrap3 --burn-cap 1 >/dev/null 2>&1

hash() { curl -sf "$1/chains/main/blocks/$2/hash" | tr -d '"'; }
ctx() { curl -sf "$1/chains/main/blocks/$2/header" | sed -n 's/.*"context":"\([^"]*\)".*/\1/p'; }
F=$ANCHOR_LEVEL
while [ "$(hash "$TEZOS_RPC" "$F")" = "$(hash "$FORK_RPC" "$F")" ]; do
  F=$((F + 1))
  wait_level "$F"; wait_level "$F" "$FORK_RPC"
done
L=$((F + 1))
wait_level $((L + 3)); wait_level $((L + 3)) "$FORK_RPC"
echo "  diverged at $F, state $L: honest $(ctx "$TEZOS_RPC" $((L + 1))), fork $(ctx "$FORK_RPC" $((L + 1)))"

echo "== fork's proof of $L lands"
out=$(TEZOS_RPC=$FORK_RPC "$BIN" prove "$ANCHOR_LEVEL" "$L" 2>>"$LOG") || { tail -5 "$LOG"; exit 1; }
PV=$(echo "$out" | sed -n 's/^PV=//p'); PROOF=$(echo "$out" | sed -n 's/^PROOF=//p')
check "fork update of $L accepted" send "$CLIENT" "update(bytes,bytes)" "$PV" "$PROOF"
frozen() { [ "$(call "$CLIENT" "frozen()(bool)")" = true ]; }
not_frozen() { ! frozen; }
check "client not frozen yet" not_frozen

echo "== keeper on the honest chain"
KEEP_INTERVAL=2s KEEP_MAX_AGE=30s "$BIN" start >"$KLOG" 2>&1 &
KEEPER=$!
check "keeper freezes the client" within 120 frozen
grep "MISBEHAVIOUR\|client frozen" "$KLOG" | head -2 | cut -c1-200 | sed 's/^/    /'
check "keeper logged the misbehaviour" grep -q "MISBEHAVIOUR: client state $L" "$KLOG"
warned() { grep -q "WARN client frozen: deliveries paused until admin re-anchor" "$KLOG"; }
check "keeper warns frozen and skips" within 30 warned
check "keeper still alive" kill -0 "$KEEPER"
check "token $TOKEN_ID not delivered while frozen" sh -c "! cast call $NFT 'ownerOf(uint256)(address)' $TOKEN_ID --rpc-url $ETH_RPC >/dev/null 2>&1"

finish
