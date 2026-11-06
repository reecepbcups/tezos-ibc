#!/bin/sh
# End to end: Tezos sandbox -> FA2 NFT escrowed -> SP1 light client update on anvil -> ERC721 minted.
# SP1_PROVER=mock (default) deploys a mock verifier. cpu|network make real proofs, so they need
# SP1_VERIFIER set to a real gateway, e.g. anvil forked from Sepolia.
# Reuses a running sandbox and anvil, starts them otherwise.
set -eu
cd "$(dirname "$0")"
ROOT=$PWD
TEZOS_CONTAINER=${TEZOS_CONTAINER:-tezos-sandbox}
TEZOS_PORT=${TEZOS_PORT:-8732}
TEZOS_RPC=${TEZOS_RPC:-http://localhost:$TEZOS_PORT}
# Not 8545: something else may already run there.
ANVIL_PORT=${ANVIL_PORT:-18545}
ETH_RPC=${ETH_RPC:-http://localhost:$ANVIL_PORT}
ANVIL_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
SP1_PROVER=${SP1_PROVER:-mock}
export TEZOS_RPC ETH_RPC SP1_PROVER TEZOS_CONTAINER TEZOS_PORT

. "$ROOT/e2e/relayer-bin.sh"
RELAYER_BIN=$(mktemp)
relayer_bin "$RELAYER_BIN"
relayer() { (cd "$ROOT/relayer" && "$RELAYER_BIN" "$@"); }
tz() { docker exec "$TEZOS_CONTAINER" octez-client -d /home/tezos/data/client -E http://127.0.0.1:8732 "$@" 2>/dev/null; }

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
# deploy.sh needs a baking chain, wait for a few levels.
until [ "$(curl -sf "$TEZOS_RPC/chains/main/blocks/head/header" | sed -n 's/.*"level":\([0-9]*\).*/\1/p')" -gt 5 ] 2>/dev/null; do sleep 2; done

echo "== tezos deploy + bridge NFT"
# Absolute, deploy.sh runs from tezos/. Per run so parallel sandboxes don't share it.
DEPLOYED_ENV=${DEPLOYED_ENV:-$ROOT/tezos/deployed.env}
export DEPLOYED_ENV
tezos/deploy.sh
. "$DEPLOYED_ENV"
export CORE TEZOS_START_LEVEL

VKEY=$(relayer vkey)
# Anchor after the bridge, so the packet commitment is already in every later state.
eval "$(relayer anchor)"
export VKEY CHAIN_ID BIG_MAP_ID ANCHOR_LEVEL ANCHOR_COMMIT ANCHOR_TIMESTAMP
echo "anchor level $ANCHOR_LEVEL, big_map $BIG_MAP_ID, vkey $VKEY"
# deploy.sh saw our packet in COMMITMENTS_BIG_MAP, so the client must pin that one.
[ "$BIG_MAP_ID" = "$COMMITMENTS_BIG_MAP" ] || { echo "FAIL: anchor big_map $BIG_MAP_ID, ibc_core commitments $COMMITMENTS_BIG_MAP"; exit 1; }

echo "== eth deploy"
eth/install-libs.sh
if [ "$SP1_PROVER" = mock ]; then SCRIPT=Deploy; else SCRIPT=DeployMainnet; fi
OUT=$(cd eth && forge script "script/Deploy.s.sol:$SCRIPT" --rpc-url "$ETH_RPC" --private-key "$ANVIL_KEY" --broadcast 2>&1) || { echo "$OUT"; exit 1; }
CLIENT=$(echo "$OUT" | sed -n 's/.*CLIENT=\(0x[0-9a-fA-F]*\).*/\1/p' | head -1)
NFT=$(echo "$OUT" | sed -n 's/.*NFT=\(0x[0-9a-fA-F]*\).*/\1/p' | head -1)
export CLIENT NFT
echo "client $CLIENT nft $NFT"
# The deployed client must pin ibc_core's commitments big_map, as read from core storage.
PINNED=$(cast call "$CLIENT" "BIG_MAP_ID()(uint64)" --rpc-url "$ETH_RPC")
[ "$PINNED" = "$COMMITMENTS_BIG_MAP" ] || { echo "FAIL: client pins big_map $PINNED, ibc_core uses $COMMITMENTS_BIG_MAP"; exit 1; }

echo "== relay"
relayer run

# Second packet sent after the anchor, so the client has to advance to a newer level to prove it.
echo "== bridge #8 after anchor, relay again"
ALICE=tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx
tz transfer 0 from bootstrap1 to "$FA2" --entrypoint mint --arg "(Pair 8 \"$ALICE\")" --burn-cap 1 >/dev/null
tz transfer 0 from bootstrap1 to "$FA2" --entrypoint update_operators \
  --arg "{ Left (Pair \"$ALICE\" (Pair \"$ESCROW\" 8)) }" --burn-cap 1 >/dev/null
tz transfer 0 from bootstrap1 to "$ESCROW" \
  --arg "(Pair 8 (Pair $RECIPIENT $TIMEOUT))" --burn-cap 1 >/dev/null
# Relayer only reads final levels (head - 3), so let the send settle first.
lvl() { curl -sf "$TEZOS_RPC/chains/main/blocks/head/header" | sed -n 's/.*"level":\([0-9]*\).*/\1/p'; }
SENT=$(lvl)
until [ "$(lvl)" -ge $((SENT + 4)) ]; do sleep 1; done
BEFORE=$(cast call "$CLIENT" "latestLevel()(uint64)" --rpc-url "$ETH_RPC")
relayer run
AFTER=$(cast call "$CLIENT" "latestLevel()(uint64)" --rpc-url "$ETH_RPC")
OWNER8=$(cast call "$NFT" "ownerOf(uint256)(address)" 8 --rpc-url "$ETH_RPC")
echo "client level $BEFORE -> $AFTER, eth ownerOf(8) = $OWNER8"

echo "== checks"
OWNER=$(cast call "$NFT" "ownerOf(uint256)(address)" "$TOKEN_ID" --rpc-url "$ETH_RPC")
LEDGER=$(curl -sf "$TEZOS_RPC/chains/main/blocks/head/context/contracts/$FA2/storage" | python3 -c "import json,sys; print(json.load(sys.stdin)['args'][1]['int'])")
EXPR=$(tz hash data "$TOKEN_ID" of type nat | sed -n 's/^Script-expression-ID-Hash: //p')
FA2_OWNER=$(curl -sf "$TEZOS_RPC/chains/main/blocks/head/context/big_maps/$LEDGER/$EXPR" | python3 -c "import json,sys; print(json.load(sys.stdin)['string'])")
echo "eth ownerOf($TOKEN_ID) = $OWNER, fa2 owner = $FA2_OWNER"
fail=0
[ "$(echo "$OWNER" | tr A-F a-f)" = "$(echo "$RECIPIENT" | tr A-F a-f)" ] || { echo "FAIL: erc721 owner"; fail=1; }
[ "$FA2_OWNER" = "$ESCROW" ] || { echo "FAIL: escrow doesn't hold the FA2"; fail=1; }
[ "$AFTER" -gt "$BEFORE" ] || { echo "FAIL: client didn't advance"; fail=1; }
[ "$(echo "$OWNER8" | tr A-F a-f)" = "$(echo "$RECIPIENT" | tr A-F a-f)" ] || { echo "FAIL: erc721 #8 owner"; fail=1; }
[ $fail = 0 ] && echo "PASS"
exit $fail
