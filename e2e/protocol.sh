#!/bin/sh
# Negative e2e: a program pinned to PtTALLiN must refuse an update from the PsUshuai sandbox.
# The relayer's own native check keeps the real pin, so the rejection comes from the program run.
# Prints PASS when the update fails with WrongProtocol and the client doesn't move.
set -eu
cd "$(dirname "$0")/.."
ROOT=$PWD
TEZOS_CONTAINER=${TEZOS_CONTAINER:-tezos-sandbox}
TEZOS_PORT=${TEZOS_PORT:-8732}
TEZOS_RPC=${TEZOS_RPC:-http://localhost:$TEZOS_PORT}
ANVIL_PORT=${ANVIL_PORT:-18545}
ETH_RPC=${ETH_RPC:-http://localhost:$ANVIL_PORT}
ANVIL_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
SP1_PROVER=mock
export TEZOS_RPC ETH_RPC SP1_PROVER TEZOS_CONTAINER TEZOS_PORT

# Own target dir so the wrong pin ELF never replaces the real one.
export CARGO_TARGET_DIR="$ROOT/relayer/target/wrong-pin"
. "$ROOT/e2e/relayer-bin.sh"
RELAYER_BIN=$(mktemp)
WRONG_PROTOCOL_PIN=1 relayer_bin "$RELAYER_BIN"
relayer() { (cd "$ROOT/relayer" && "$RELAYER_BIN" "$@"); }

if ! cast block-number --rpc-url "$ETH_RPC" >/dev/null 2>&1; then
  echo "starting anvil"
  anvil --port "$ANVIL_PORT" --silent >/dev/null 2>&1 &
  ANVIL_PID=$!
  trap 'kill $ANVIL_PID 2>/dev/null' EXIT
  until cast block-number --rpc-url "$ETH_RPC" >/dev/null 2>&1; do sleep 0.5; done
fi
if ! curl -sf "$TEZOS_RPC/chains/main/blocks/head/header" >/dev/null; then
  echo "starting tezos sandbox"
  tezos/sandbox/run.sh
fi
until [ "$(curl -sf "$TEZOS_RPC/chains/main/blocks/head/header" | sed -n 's/.*"level":\([0-9]*\).*/\1/p')" -gt 5 ] 2>/dev/null; do sleep 2; done
curl -sf "$TEZOS_RPC/chains/main/blocks/head/protocols"; echo

echo "== tezos deploy + bridge NFT"
DEPLOYED_ENV=$(mktemp)
export DEPLOYED_ENV
tezos/deploy.sh
. "$DEPLOYED_ENV"
export CORE TEZOS_START_LEVEL

echo "== building relayer + wrong pin program"
(cd relayer && WRONG_PROTOCOL_PIN=1 cargo build -q --release)
VKEY=$(relayer vkey)
eval "$(relayer anchor)"
export VKEY CHAIN_ID BIG_MAP_ID ANCHOR_LEVEL ANCHOR_COMMIT ANCHOR_TIMESTAMP

echo "== eth deploy"
OUT=$(cd eth && forge script script/Deploy.s.sol:Deploy --rpc-url "$ETH_RPC" --private-key "$ANVIL_KEY" --broadcast 2>&1) || { echo "$OUT"; exit 1; }
CLIENT=$(echo "$OUT" | sed -n 's/.*CLIENT=\(0x[0-9a-fA-F]*\).*/\1/p' | head -1)
NFT=$(echo "$OUT" | sed -n 's/.*NFT=\(0x[0-9a-fA-F]*\).*/\1/p' | head -1)
export CLIENT NFT

echo "== relay, expecting the program to reject"
BEFORE=$(cast call "$CLIENT" "latestLevel()(uint64)" --rpc-url "$ETH_RPC")
if OUT=$(relayer run 2>&1); then STATUS=0; else STATUS=$?; fi
echo "$OUT" | grep -v -E '^(warning|  |   *\||$)' | tail -8
AFTER=$(cast call "$CLIENT" "latestLevel()(uint64)" --rpc-url "$ETH_RPC")
echo "relayer exit $STATUS, client level $BEFORE -> $AFTER"

fail=0
[ "$STATUS" != 0 ] || { echo "FAIL: relayer succeeded"; fail=1; }
echo "$OUT" | grep -q 'WrongProtocol("trusted")' || { echo "FAIL: not rejected for the protocol pin"; fail=1; }
[ "$AFTER" = "$BEFORE" ] || { echo "FAIL: client moved"; fail=1; }
[ $fail = 0 ] && echo "PASS"
exit $fail
