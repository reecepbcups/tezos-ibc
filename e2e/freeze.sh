#!/bin/sh
# Real equivocation: sandbox A is anchored, then its stopped container is committed to an image and
# started a second time as A2. Both nodes run with --no-bootstrap-peers, so the same 8 bakers keep
# signing two diverging chains from the shared anchored state. Proofs from both freeze the client.
. "$(dirname "$0")/lib.sh"
FORK=${FORK_CONTAINER:-tezos-a2}
FORK_PORT=${FORK_PORT:-18733}
FORK_RPC=http://localhost:$FORK_PORT
IMAGE=$FORK-image

start_infra
echo "== deploy + anchor on A"
deploy_tezos
anchor
deploy_eth
CLIENT1=$CLIENT NFT1=$NFT
echo "client $CLIENT nft $NFT, anchor $ANCHOR_LEVEL"
wait_level $((ANCHOR_LEVEL + 4))

echo "== fork $TEZOS_CONTAINER into $FORK"
# Stop the node gracefully first so the copied store is clean.
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
# Same bakers, same clock: the chains could bake identical blocks. A transfer only on A2 forces a split.
docker exec "$FORK" octez-client -d /home/tezos/data/client -E http://127.0.0.1:8732 \
  transfer 1 from bootstrap2 to bootstrap3 --burn-cap 1 >/dev/null 2>&1

hash() { curl -sf "$1/chains/main/blocks/$2/hash" | tr -d '"'; }
F=$ANCHOR_LEVEL
while [ "$(hash "$TEZOS_RPC" "$F")" = "$(hash "$FORK_RPC" "$F")" ]; do
  F=$((F + 1))
  wait_level "$F"; wait_level "$F" "$FORK_RPC"
done
L=$((F + 1)) # first state that differs
P=$((F - 2)) # shared state whose QC (on F-1) is carried by the diverged block F
check "chains diverge at level $F, both baking" [ "$P" -ge "$ANCHOR_LEVEL" ]
echo "  A block $F $(hash "$TEZOS_RPC" "$F")"
echo "  B block $F $(hash "$FORK_RPC" "$F")"
wait_level $((L + 3)); wait_level $((L + 3)) "$FORK_RPC"
ctx() { curl -sf "$1/chains/main/blocks/$2/header" | sed -n 's/.*"context":"\([^"]*\)".*/\1/p'; }
echo "  state $L: A $(ctx "$TEZOS_RPC" $((L + 1))), B $(ctx "$FORK_RPC" $((L + 1)))"

echo "== proving from anchor $ANCHOR_LEVEL"
# prove_on <rpc> <var> <level> [seq..]: sets <var>_PV and <var>_PROOF
prove_on() {
  rpc=$1 v=$2; shift 2
  out=$(TEZOS_RPC=$rpc relayer prove "$ANCHOR_LEVEL" "$@") || { tail -5 "$LOG"; exit 1; }
  eval "${v}_PV=$(echo "$out" | sed -n 's/^PV=//p') ${v}_PROOF=$(echo "$out" | sed -n 's/^PROOF=//p')"
}
prove_on "$TEZOS_RPC" AP "$P" 1
prove_on "$FORK_RPC" BP "$P"
prove_on "$TEZOS_RPC" AL "$L" 1
prove_on "$FORK_RPC" BL "$L"
frozen() { [ "$(call "$1" "frozen()(bool)")" = true ]; }
not_frozen() { ! frozen "$1"; }

echo "== same level, same commit: never freezes"
check "level $P proofs from A and B differ" [ "$AP_PV" != "$BP_PV" ]
check "misbehaviour with equal commits rejected" \
  reverts_with "NotMisbehaviour()" send "$CLIENT" "submitMisbehaviour(bytes,bytes,bytes,bytes)" "$AP_PV" "$AP_PROOF" "$BP_PV" "$BP_PROOF" --private-key "$OTHER_KEY"
check "update with A's proof of $P" send "$CLIENT" "update(bytes,bytes)" "$AP_PV" "$AP_PROOF"
check "update with B's proof of $P" send "$CLIENT" "update(bytes,bytes)" "$BP_PV" "$BP_PROOF"
check "replay A's proof of $P" send "$CLIENT" "update(bytes,bytes)" "$AP_PV" "$AP_PROOF"
check "not frozen" not_frozen "$CLIENT"
check "admin can't re-anchor a healthy client" reanchor_refused
check "recvPacket(1) would succeed" sh -c "cast call $NFT 'recvPacket(uint64,uint64,uint256,address)' 1 $TIMEOUT $TOKEN_ID $RECIPIENT --rpc-url $ETH_RPC >/dev/null 2>&1"

echo "== conflicting update freezes instead of reverting"
check "update with A's proof of $L" send "$CLIENT" "update(bytes,bytes)" "$AL_PV" "$AL_PROOF"
STORED=$(call "$CLIENT" "stateCommit(uint64)(bytes32)" "$L")
check "update with B's proof of $L succeeds (no revert)" send "$CLIENT" "update(bytes,bytes)" "$BL_PV" "$BL_PROOF"
check "client frozen" frozen "$CLIENT"
check "stored commit for $L unchanged" [ "$(call "$CLIENT" "stateCommit(uint64)(bytes32)" "$L")" = "$STORED" ]
check "update now reverts ClientFrozen" reverts_with "ClientFrozen()" call "$CLIENT" "update(bytes,bytes)" "$AL_PV" "$AL_PROOF"
check "recvPacket now reverts ClientFrozen" reverts_with "ClientFrozen()" \
  call "$NFT" "recvPacket(uint64,uint64,uint256,address)" 1 "$TIMEOUT" "$TOKEN_ID" "$RECIPIENT"

echo "== submitMisbehaviour on a fresh client"
deploy_eth
echo "client $CLIENT"
check "same proof twice rejected" reverts_with "NotMisbehaviour()" \
  send "$CLIENT" "submitMisbehaviour(bytes,bytes,bytes,bytes)" "$AL_PV" "$AL_PROOF" "$AL_PV" "$AL_PROOF" --private-key "$OTHER_KEY"
check "non-admin submits A vs B at $L" sh -c "cast send $CLIENT 'submitMisbehaviour(bytes,bytes,bytes,bytes)' $AL_PV 0x${AL_PROOF#0x} $BL_PV 0x${BL_PROOF#0x} --rpc-url $ETH_RPC --private-key $OTHER_KEY >/dev/null 2>&1"
check "fresh client frozen" frozen "$CLIENT"

echo "== admin re-anchor unfreezes the first client"
CLIENT=$CLIENT1 NFT=$NFT1
reanchor_flow
bridge 8
relayer run >/dev/null || tail -3 "$LOG"
check "relay after re-anchor delivers token $TOKEN_ID" owner_is_recipient "$TOKEN_ID"
check "relay after re-anchor delivers token 8" owner_is_recipient 8

docker rm -f "$FORK" >/dev/null
docker rmi "$IMAGE" >/dev/null 2>&1 || true
finish
