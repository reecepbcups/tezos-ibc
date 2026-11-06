# Shared by e2e/freeze.sh and e2e/recovery.sh. Sourced, not run.
# Defaults keep off the ports e2e.sh and other sandboxes use.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TEZOS_CONTAINER=${TEZOS_CONTAINER:-tezos-a}
TEZOS_PORT=${TEZOS_PORT:-18732}
TEZOS_RPC=http://localhost:$TEZOS_PORT
ANVIL_PORT=${ANVIL_PORT:-18546}
ETH_RPC=http://localhost:$ANVIL_PORT
SP1_PROVER=${SP1_PROVER:-mock}
# Short so the e2e can warp past them. Deploy scripts default to 2 and 7 days.
REANCHOR_DELAY=${REANCHOR_DELAY:-30}
UPGRADE_DELAY=${UPGRADE_DELAY:-60}
ANVIL_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80   # admin, account 0
OTHER_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d   # account 1
ADMIN=$(cast wallet address --private-key $ANVIL_KEY)
ALICE=tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx
export TEZOS_RPC ETH_RPC SP1_PROVER TEZOS_CONTAINER TEZOS_PORT REANCHOR_DELAY UPGRADE_DELAY ADMIN

# Logs and deploy outputs, kept out of the repo.
WORK=${WORK:-$(mktemp -d)}
LOG=$WORK/relayer.log
FAILS=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILS=$((FAILS + 1)); }
check() { desc=$1; shift; if "$@"; then pass "$desc"; else fail "$desc"; fi; }
finish() { [ "$FAILS" = 0 ] && echo "ALL PASS" || echo "$FAILS FAILED"; exit "$FAILS"; }
lower() { echo "$1" | tr A-F a-f; }

. "$ROOT/e2e/relayer-bin.sh"
RELAYER_BIN=$WORK/relayer-bin
relayer_bin "$RELAYER_BIN"
relayer() { (cd "$ROOT/relayer" && "$RELAYER_BIN" "$@" 2>>"$LOG"); }
tz() { docker exec "$TEZOS_CONTAINER" octez-client -d /home/tezos/data/client -E http://127.0.0.1:8732 "$@" 2>/dev/null; }
head_level() { curl -sf "${1:-$TEZOS_RPC}/chains/main/blocks/head/header" | sed -n 's/.*"level":\([0-9]*\).*/\1/p'; }
wait_level() { until [ "$(head_level "${2:-}")" -ge "$1" ] 2>/dev/null; do sleep 1; done; }
call() { cast call "$@" --rpc-url "$ETH_RPC"; }
send() { cast send "$@" --rpc-url "$ETH_RPC" --private-key "$ANVIL_KEY" >/dev/null 2>&1; }
# Mines first, the last block may be minutes old.
eth_now() { cast rpc evm_mine --rpc-url "$ETH_RPC" >/dev/null && cast block latest -f timestamp --rpc-url "$ETH_RPC"; }
warp() { cast rpc evm_increaseTime "$1" --rpc-url "$ETH_RPC" >/dev/null && cast rpc evm_mine --rpc-url "$ETH_RPC" >/dev/null; }

# Succeeds when `cast <args>` reverts with custom error $1, e.g. ClientFrozen().
reverts_with() {
  err=$1; shift
  if out=$(cast "$@" --rpc-url "$ETH_RPC" 2>&1); then return 1; fi
  echo "$out" | grep -qi "$(cast sig "$err")"
}

start_infra() {
  # Fresh anvil every run: an earlier warp leaves its clock days ahead of Tezos.
  pkill -f "anvil --port $ANVIL_PORT" 2>/dev/null && sleep 1
  anvil --port "$ANVIL_PORT" --silent >/dev/null 2>&1 &
  until cast block-number --rpc-url "$ETH_RPC" >/dev/null 2>&1; do sleep 0.5; done
  if ! curl -sf "$TEZOS_RPC/chains/main/blocks/head/header" >/dev/null; then
    "$ROOT/tezos/sandbox/run.sh" >/dev/null
  fi
  wait_level 6
  echo "logs in $WORK"
  (cd "$ROOT/relayer" && cargo build -q --release 2>/dev/null)
  "$ROOT/eth/install-libs.sh" >/dev/null
}

# Tezos contracts + first bridged NFT. Own env file, other runs may rewrite tezos/deployed.env.
deploy_tezos() {
  DEPLOYED_ENV=$WORK/deployed.env "$ROOT/tezos/deploy.sh" >"$WORK/deploy.log" 2>&1 || { cat "$WORK/deploy.log"; exit 1; }
  . "$WORK/deployed.env"
  export CORE FA2 ESCROW TOKEN_ID RECIPIENT TIMEOUT TEZOS_START_LEVEL
}

# Sets VKEY CHAIN_ID BIG_MAP_ID ANCHOR_* from TEZOS_RPC's head.
anchor() {
  VKEY=$(relayer vkey)
  a=$(relayer anchor) || { tail -5 "$LOG"; exit 1; }
  eval "$a"
  export VKEY CHAIN_ID BIG_MAP_ID ANCHOR_LEVEL ANCHOR_COMMIT ANCHOR_TIMESTAMP
}

deploy_eth() {
  out=$(cd "$ROOT/eth" && forge script script/Deploy.s.sol:Deploy --rpc-url "$ETH_RPC" \
    --private-key "$ANVIL_KEY" --broadcast 2>&1) || { echo "$out"; exit 1; }
  CLIENT=$(echo "$out" | sed -n 's/.*CLIENT=\(0x[0-9a-fA-F]*\).*/\1/p' | head -1)
  NFT=$(echo "$out" | sed -n 's/.*NFT=\(0x[0-9a-fA-F]*\).*/\1/p' | head -1)
  export CLIENT NFT
}

# Escrows FA2 token $1 to RECIPIENT on Tezos.
bridge() {
  tz transfer 0 from bootstrap1 to "$FA2" --entrypoint mint --arg "(Pair $1 \"$ALICE\")" --burn-cap 1 >/dev/null
  tz transfer 0 from bootstrap1 to "$FA2" --entrypoint update_operators \
    --arg "{ Left (Pair \"$ALICE\" (Pair \"$ESCROW\" $1)) }" --burn-cap 1 >/dev/null
  tz transfer 0 from bootstrap1 to "$ESCROW" --arg "(Pair $1 (Pair $RECIPIENT $TIMEOUT))" --burn-cap 1 >/dev/null
  # relayer only reads final levels
  wait_level $(($(head_level) + 4))
}

owner_is_recipient() {
  [ "$(lower "$(call "$NFT" "ownerOf(uint256)(address)" "$1" 2>/dev/null)")" = "$(lower "$RECIPIENT")" ]
}

# Re-anchor is only allowed on a frozen or expired client.
reanchor_refused() {
  rd=$(cast calldata "reanchor(uint64,bytes32,uint64)" "$ANCHOR_LEVEL" "$ANCHOR_COMMIT" "$ANCHOR_TIMESTAMP")
  reverts_with "ClientHealthy()" send "$CLIENT" "queue(bytes)" "$rd" --private-key "$ANVIL_KEY"
}

# Queues reanchor at TEZOS_RPC's head, checks the timelock and admin guards, executes.
reanchor_flow() {
  anchor
  data=$(cast calldata "reanchor(uint64,bytes32,uint64)" "$ANCHOR_LEVEL" "$ANCHOR_COMMIT" "$ANCHOR_TIMESTAMP")
  check "non-admin can't queue" reverts_with "NotAdmin()" send "$CLIENT" "queue(bytes)" "$data" --private-key "$OTHER_KEY"
  check "admin queues re-anchor at $ANCHOR_LEVEL" send "$CLIENT" "queue(bytes)" "$data"
  check "execute before timelock reverts" reverts_with "TimelockActive()" send "$CLIENT" "execute(bytes)" "$data" --private-key "$ANVIL_KEY"
  warp "$REANCHOR_DELAY"
  check "non-admin can't execute" reverts_with "NotAdmin()" send "$CLIENT" "execute(bytes)" "$data" --private-key "$OTHER_KEY"
  check "admin executes after timelock" send "$CLIENT" "execute(bytes)" "$data"
  check "client unfrozen, latestLevel = $ANCHOR_LEVEL" \
    [ "$(call "$CLIENT" "frozen()(bool)")" = false -a "$(call "$CLIENT" "latestLevel()(uint64)")" = "$ANCHOR_LEVEL" ]
}
