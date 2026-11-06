#!/bin/sh
# Recovery after the trust root expires: relay works, anvil warps past the trusting period so
# updates fail with TrustExpired, the admin re-anchors through the timelock, relaying works again.
. "$(dirname "$0")/lib.sh"

start_infra
echo "== deploy"
deploy_tezos
anchor
deploy_eth
echo "client $CLIENT nft $NFT admin $ADMIN, anchor $ANCHOR_LEVEL"
check "admin is $ADMIN" [ "$(lower "$(call "$CLIENT" "admin()(address)")")" = "$(lower "$ADMIN")" ]

echo "== normal relay"
relayer run >/dev/null
check "relay delivers token $TOKEN_ID" owner_is_recipient "$TOKEN_ID"
check "admin can't re-anchor a healthy client" reanchor_refused

# Tezos time can't be warped, so after both warps anvil runs ahead of it. The fresh re-anchor
# only stays inside the trusting period if the old root is already older than that lead.
LATEST=$(call "$CLIENT" "latestLevel()(uint64)")
TS=$(call "$CLIENT" "stateTimestamp(uint64)(uint64)" "$LATEST" | cut -d' ' -f1)
PERIOD=$(call "$CLIENT" "TRUSTING_PERIOD()(uint64)" | cut -d' ' -f1)
# 120s covers re-anchor, the warps and one relayer run.
LEAD=$((REANCHOR_DELAY + 120))
echo "== waiting until state $LATEST is ${LEAD}s old"
while [ $(($(date +%s) - TS)) -lt $LEAD ]; do sleep 2; done

echo "== warp past trusting period ($PERIOD s from state $LATEST)"
warp $((TS + PERIOD + 1 - $(eth_now)))
bridge 9
if relayer run >/dev/null; then st=0; else st=1; fi
grep -i "error" "$LOG" | tail -1 | cut -c1-200 | sed 's/^/  relayer: /'
# alloy prints the revert data, the selector is enough
expired() { [ $st = 1 ] && tail -20 "$LOG" | grep -qi "$(cast sig 'TrustExpired()')"; }
check "relayer update fails with TrustExpired" expired
check "token 9 not delivered" sh -c "! cast call $NFT 'ownerOf(uint256)(address)' 9 --rpc-url $ETH_RPC >/dev/null 2>&1"

echo "== admin re-anchor"
reanchor_flow

echo "== relay after re-anchor"
relayer run >/dev/null
check "relay delivers token 9" owner_is_recipient 9
finish
