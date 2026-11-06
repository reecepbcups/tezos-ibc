#!/bin/sh
# Deploys ibc_core, a test FA2 and the escrow to the running sandbox, then bridges one NFT.
# Writes addresses to tezos/deployed.env, or $DEPLOYED_ENV so parallel sandboxes don't clobber it.
set -eu
cd "$(dirname "$0")"

RECIPIENT=${RECIPIENT:-0x70997970c51812dc3a010c7d01b50e0d17dc79c8} # anvil account 1
TOKEN_ID=${TOKEN_ID:-7}
ALICE=tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx # bootstrap1

NAME=${TEZOS_CONTAINER:-tezos-sandbox}
docker exec "$NAME" mkdir -p /home/tezos/build
for f in contracts/build/*.tz; do docker cp "$f" "$NAME:/home/tezos/build/" >/dev/null; done

# Capture first so a failed octez-client call fails c, not just the filtering grep.
c() {
  out=$(docker exec "$NAME" octez-client -d /home/tezos/data/client -E http://127.0.0.1:8732 "$@" 2>&1) \
    || { printf '%s\n' "$out" >&2; return 1; }
  printf '%s\n' "$out" | grep -v -i "warning\|mainnet\|fundraiser\|^ *$" || true
}
addr() { a=$(c show known contract "$1") && printf '%s\n' "$a" | tail -1; }

# Relayer scans for packets back to here, not to genesis.
START_LEVEL=$(docker exec "$NAME" octez-client -d /home/tezos/data/client -E http://127.0.0.1:8732 rpc get /chains/main/blocks/head/header \
  | sed -n 's/.*"level": *\([0-9]*\).*/\1/p' | head -1)
[ -n "$START_LEVEL" ] || { echo "can't read head level" >&2; exit 1; }
c originate contract ibc_core transferring 0 from bootstrap1 running /home/tezos/build/ibc_core.tz \
  --init "(Pair { Elt \"eth-0\" \"tezos-0\" } {} {} {} \"$ALICE\")" --burn-cap 10 --force >/dev/null
c originate contract fa2_nft transferring 0 from bootstrap1 running /home/tezos/build/fa2_nft.tz \
  --init "(Pair \"$ALICE\" {} {} {} {})" --burn-cap 10 --force >/dev/null
CORE=$(addr ibc_core); FA2=$(addr fa2_nft)
c originate contract nft_escrow transferring 0 from bootstrap1 running /home/tezos/build/nft_escrow.tz \
  --init "(Pair \"$CORE\" (Pair \"$FA2\" \"eth-0\"))" --burn-cap 10 --force >/dev/null
ESCROW=$(addr nft_escrow)
# Only the deployer (bootstrap1) can bind, so the port can't be squatted before this.
c transfer 0 from bootstrap1 to ibc_core --entrypoint bind_port --arg "(Pair \"fa2-nft\" \"$ESCROW\")" --burn-cap 1 >/dev/null
# Fails unless the port really went to our escrow.
COMMITMENTS_BIG_MAP=$(./verify.sh "$CORE" "$ESCROW")

c transfer 0 from bootstrap1 to fa2_nft --entrypoint mint --arg "(Pair $TOKEN_ID \"$ALICE\")" --burn-cap 1 >/dev/null
c transfer 0 from bootstrap1 to fa2_nft --entrypoint update_operators \
  --arg "{ Left (Pair \"$ALICE\" (Pair \"$ESCROW\" $TOKEN_ID)) }" --burn-cap 1 >/dev/null
TIMEOUT=$(( $(date +%s) + 86400 ))
# Escrow has a single entrypoint now, so it's the default one.
out=$(c transfer 0 from bootstrap1 to nft_escrow \
  --arg "(Pair $TOKEN_ID (Pair $RECIPIENT $TIMEOUT))" --burn-cap 1)
printf '%s\n' "$out" | grep -i "send_packet\|Payload" -A2 | head -20 || true
# The Eth client pins this big_map id, so check our packet (eth-0, seq 1) really landed in it.
KEY=$(c hash data 0x6574682d30010000000000000001 of type bytes | sed -n 's/^Script-expression-ID-Hash: //p')
docker exec "$NAME" octez-client -d /home/tezos/data/client -E http://127.0.0.1:8732 \
  rpc get "/chains/main/blocks/head/context/big_maps/$COMMITMENTS_BIG_MAP/$KEY" 2>/dev/null | grep -q bytes \
  || { echo "FAIL: packet commitment not in big_map $COMMITMENTS_BIG_MAP" >&2; exit 1; }
echo "commitments big_map $COMMITMENTS_BIG_MAP holds packet 1"

OUT=${DEPLOYED_ENV:-deployed.env}
cat > "$OUT" <<EOF
CORE=$CORE
FA2=$FA2
ESCROW=$ESCROW
TOKEN_ID=$TOKEN_ID
RECIPIENT=$RECIPIENT
TIMEOUT=$TIMEOUT
TEZOS_START_LEVEL=$START_LEVEL
COMMITMENTS_BIG_MAP=$COMMITMENTS_BIG_MAP
EOF
cat "$OUT"
