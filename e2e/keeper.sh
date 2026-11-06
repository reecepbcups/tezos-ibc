#!/bin/sh
# `relayer keep` end to end: refreshes the client with no packets, relays a new NFT, rides out a
# Tezos RPC outage, and without it the client expires. Plus deploy.sh's port check failing.
# Short thresholds so it runs in a few minutes:
#   TEZOS_CONTAINER=tezos-c TEZOS_PORT=38732 ANVIL_PORT=38546 e2e/keeper.sh
TEZOS_CONTAINER=${TEZOS_CONTAINER:-tezos-c}
TEZOS_PORT=${TEZOS_PORT:-38732}
ANVIL_PORT=${ANVIL_PORT:-38546}
. "$(dirname "$0")/lib.sh"
# Short enough to warp past, long enough the keeper never gets close with KEEP_MAX_AGE=30s.
TRUSTING_PERIOD=${TRUSTING_PERIOD:-300}
export TRUSTING_PERIOD
KLOG=$WORK/keep.log
level() { call "$CLIENT" "latestLevel()(uint64)"; }
# Waits up to $1 seconds for the rest of the args to succeed.
within() { n=$1; shift; while [ "$n" -gt 0 ]; do "$@" && return 0; sleep 1; n=$((n - 1)); done; return 1; }
level_above() { [ "$(level)" -gt "$1" ]; }

start_infra
# Own copy: the cargo target dir may be shared, and other e2e scripts rebuild with other flags.
TARGET=$(cd "$ROOT/relayer" && cargo metadata -q --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
BIN=$WORK/relayer
cp "$TARGET/release/relayer" "$BIN"
deploy_tezos
anchor
check "anchor big_map $BIG_MAP_ID = ibc_core commitments $COMMITMENTS_BIG_MAP" [ "$BIG_MAP_ID" = "$COMMITMENTS_BIG_MAP" ]
deploy_eth
check "client pins big_map $COMMITMENTS_BIG_MAP" [ "$(call "$CLIENT" "BIG_MAP_ID()(uint64)")" = "$COMMITMENTS_BIG_MAP" ]
echo "client $CLIENT nft $NFT, trusting period $(call "$CLIENT" "TRUSTING_PERIOD()(uint64)")s"

# Lag check off, so only the age threshold can trigger an update without packets.
KEEP_INTERVAL=2s KEEP_MAX_AGE=30s KEEP_MAX_LAG=1000000 "$BIN" keep >"$KLOG" 2>&1 &
KEEPER=$!
trap 'kill $KEEPER 2>/dev/null || true; docker unpause "$TEZOS_CONTAINER" >/dev/null 2>&1 || true' EXIT
echo "keeper pid $KEEPER, log $KLOG"

# deploy.sh bridged token 7 before the anchor, the keeper picks it up right away.
check "keeper relays token $TOKEN_ID" within 120 owner_is_recipient "$TOKEN_ID"

# (a) no packets: next update must wait for the age threshold.
L0=$(level); T0=$(date +%s)
check "(a) keeper advances client with no packets" within 90 level_above "$L0"
T1=$(date +%s)
echo "    client $L0 -> $(level) after $((T1 - T0))s"
aged() { [ $((T1 - T0)) -ge 10 ] && grep -q "relaying, trusted state too old" "$KLOG"; }
check "(a) triggered by age, not early" aged
grep "keep: client level .* age" "$KLOG" | tail -1 | sed 's/^/    /'

# (b) new NFT bridged while the keeper runs.
bridge 9
check "(b) keeper relays newly bridged token 9" within 120 owner_is_recipient 9

# (c) Tezos RPC outage: the container hangs, requests time out, the keeper must keep going.
docker pause "$TEZOS_CONTAINER" >/dev/null
echo "    tezos paused"
sleep 45
check "(c) keeper alive during outage" kill -0 "$KEEPER"
check "(c) keeper logged RPC errors" grep -q "warn: GET\|keep: error" "$KLOG"
grep "warn: GET\|keep: error" "$KLOG" | tail -2 | cut -c1-200 | sed 's/^/    /'
docker unpause "$TEZOS_CONTAINER" >/dev/null
echo "    tezos unpaused"
wait_level $(($(head_level) + 2))
bridge 10
check "(c) keeper resumes and relays token 10" within 150 owner_is_recipient 10

TS=$(call "$CLIENT" "stateTimestamp(uint64)(uint64)" "$(level)" | cut -d" " -f1)
AGE=$(($(eth_now) - TS))
check "client fresh with keeper: age ${AGE}s < period ${TRUSTING_PERIOD}s" [ "$AGE" -lt "$TRUSTING_PERIOD" ]

# Graceful stop on ctrl-c.
kill -INT "$KEEPER"
within 20 sh -c "! kill -0 $KEEPER 2>/dev/null"
RC=0; wait "$KEEPER" || RC=$?
stopped() { [ "$RC" = 0 ] && grep -q "ctrl-c, stopping" "$KLOG"; }
check "keeper exits 0 on SIGINT" stopped

# (d) no keeper: once anvil time passes the trusting period, no update can land.
warp $((TRUSTING_PERIOD + 60))
OUT=$WORK/expired.log
if "$BIN" run >"$OUT" 2>&1; then RUN_OK=1; else RUN_OK=0; fi
expired() { [ "$RUN_OK" = 0 ] && grep -qi "$(cast sig 'TrustExpired()')" "$OUT"; }
check "(d) without keeper, update reverts TrustExpired after warp" expired
tail -1 "$OUT" | cut -c1-200 | sed 's/^/    /'

# deploy.sh's port check: a core whose fa2-nft port is bound elsewhere must fail verify.sh.
tz originate contract ibc_core_bad transferring 0 from bootstrap1 running /home/tezos/build/ibc_core.tz \
  --init "(Pair {} {} {} {} \"$ALICE\")" --burn-cap 10 --force >/dev/null
BAD=$(tz show known contract ibc_core_bad | grep KT1)
tz transfer 0 from bootstrap1 to "$BAD" --entrypoint bind_port --arg "(Pair \"fa2-nft\" \"$FA2\")" --burn-cap 1 >/dev/null
check "verify.sh rejects port bound to the wrong contract" sh -c "! '$ROOT/tezos/verify.sh' '$BAD' '$ESCROW' 2>'$WORK/verify.err'"
sed 's/^/    /' "$WORK/verify.err"
verified() { "$ROOT/tezos/verify.sh" "$CORE" "$ESCROW" >/dev/null 2>&1; }
check "verify.sh accepts the real deploy" verified

finish
