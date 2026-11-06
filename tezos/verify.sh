#!/bin/sh
# Checks a deployed ibc_core on chain: ports["fa2-nft"] must be the escrow, then prints the
# commitments big_map id so the Eth client is deployed against the real one.
# usage: verify.sh CORE ESCROW
set -eu
CORE=$1
ESCROW=$2
NAME=${TEZOS_CONTAINER:-tezos-sandbox}
oc() { docker exec "$NAME" octez-client -d /home/tezos/data/client -E http://127.0.0.1:8732 "$@" 2>/dev/null; }
expr_of() { oc hash data "$1" of type "$2" | sed -n 's/^Script-expression-ID-Hash: //p'; }

# Comb in declaration order: counterparty, next_sequence, commitments, ports, deployer.
IDS=$(oc rpc get "/chains/main/blocks/head/context/contracts/$CORE/storage" \
  | python3 -c 'import json,sys; a=json.load(sys.stdin)["args"]; print(a[2]["int"], a[3]["int"])') \
  || { echo "FAIL: can't read ibc_core $CORE storage" >&2; exit 1; }
COMMITMENTS=${IDS% *}
PORTS=${IDS#* }

OWNER=$(oc rpc get "/chains/main/blocks/head/context/big_maps/$PORTS/$(expr_of '"fa2-nft"' string)" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["string"])') || OWNER=unbound
if [ "$OWNER" != "$ESCROW" ]; then
  echo "FAIL: ibc_core ports[fa2-nft] = $OWNER, want escrow $ESCROW" >&2
  exit 1
fi
echo "ports[fa2-nft] = $ESCROW ok" >&2
echo "$COMMITMENTS"
