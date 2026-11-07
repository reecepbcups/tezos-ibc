#!/bin/sh
# e2e.sh with real Groth16 proofs from the Succinct network, checked by the real SP1 gateway on an
# anvil fork of Sepolia. Tezos is still the local sandbox. Spends PROVE (one proof per update).
set -eu
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "need .env with NETWORK_PRIVATE_KEY" >&2; exit 1; }
set -a; . ./.env; set +a
: "${NETWORK_PRIVATE_KEY:?missing in .env}"

# Own sandbox with 3s blocks. A network proof takes about 70s, and at 1s blocks Tezos outruns the
# 3 cycle (48 block) window one proof can cover, which costs an extra catch up proof.
TEZOS_CONTAINER=${TEZOS_CONTAINER:-tezos-real}
TEZOS_PORT=${TEZOS_PORT:-58732}
SANDBOX_BLOCK_DELAY=${SANDBOX_BLOCK_DELAY:-3}
export TEZOS_CONTAINER TEZOS_PORT SANDBOX_BLOCK_DELAY
tezos/sandbox/run.sh >/dev/null

ANVIL_PORT=${ANVIL_PORT:-18555}
FORK_URL=${FORK_URL:-https://ethereum-sepolia-rpc.publicnode.com}
ETH_RPC=http://localhost:$ANVIL_PORT
# Always a fresh fork, a plain anvil on this port would have no gateway.
pkill -f "anvil --port $ANVIL_PORT" 2>/dev/null && sleep 1
anvil --port "$ANVIL_PORT" --fork-url "$FORK_URL" --silent >/dev/null 2>&1 &
ANVIL_PID=$!
trap 'kill $ANVIL_PID 2>/dev/null' EXIT
until cast block-number --rpc-url "$ETH_RPC" >/dev/null 2>&1; do sleep 0.5; done

SP1_VERIFIER=${SP1_VERIFIER:-0x397A5f7f3dBd538f23DE225B51f532c34448dA9B}
[ "$(cast code "$SP1_VERIFIER" --rpc-url "$ETH_RPC")" != 0x ] || { echo "no gateway at $SP1_VERIFIER on the fork" >&2; exit 1; }
# Anvil account 0, the same key e2e.sh deploys with.
ADMIN=${ADMIN:-0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266}
SP1_PROVER=network
export ANVIL_PORT ETH_RPC SP1_VERIFIER ADMIN SP1_PROVER NETWORK_PRIVATE_KEY
./e2e.sh
