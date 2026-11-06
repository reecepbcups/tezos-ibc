#!/bin/sh
# Runs inside tezos/tezos. One node, PsUshuai (same as mainnet), 8 bootstrap bakers covering tz1/tz2/tz3/tz4.
# Archive mode so the relayer can still read old contexts and receipts (full mode prunes in ~3 cycles here).
set -eu

DATA=$HOME/data/node
CLIENT_DIR=$HOME/data/client
PROTO=PsUshuai9QapM5TGj1JpuVGkdxz5GykdnEvS6Rh8SUVrARvZLCY
C="octez-client -d $CLIENT_DIR -E http://127.0.0.1:8732"

mkdir -p $DATA $CLIENT_DIR
cat > $HOME/data/sandbox.json <<EOF
{ "genesis_pubkey": "edpkuSLWfVU1Vq7Jg9FucPyKmma6otcMHac9zG4oU1KMHSTBpJuGQ2" }
EOF

[ -f $DATA/identity.json ] || octez-node identity generate 0 --data-dir $DATA
octez-node config init --data-dir $DATA --network sandbox --expected-pow 0 \
  --rpc-addr 0.0.0.0:8732 --allow-all-rpc 0.0.0.0:8732 --no-bootstrap-peers \
  --synchronisation-threshold 0 --connections 0 --history-mode archive 2>/dev/null || true
octez-node run --data-dir $DATA --sandbox $HOME/data/sandbox.json &

until $C rpc get /chains/main/blocks/head/hash >/dev/null 2>&1; do sleep 1; done

$C import secret key activator unencrypted:edsk31vznjHSSpGExDMHYASz45VZqXN4DPxvsa4hAyY8dHM28cZzp6 --force
$C import secret key bootstrap1 unencrypted:edsk3gUfUPyBSfrS9CCgmCiQsTCHGkviBDusMxDJstFtojtc1zcpsh --force
$C import secret key bootstrap2 unencrypted:edsk39qAm1fiMjgmPkw1EgQYkMzkJezLNewd7PLNHTkr6w9XA2zdfo --force
$C import secret key bootstrap3 unencrypted:edsk4ArLQgBTLWG5FJmnGnT689VKoqhXwmDPBuGx3z4cvwU9MmrPZZ --force
$C import secret key bootstrap4 unencrypted:edsk2uqQB9AY4FvioK2YMdfmyMrer5R8mGFyuaLLFfSRo8EoyNdht3 --force
$C import secret key bootstrap5 unencrypted:edsk4QLrcijEffxV31gGdN2HU7UpyJjA8drFoNcmnB28n89YjPNRFm --force
# Throwaway sandbox keys, see gen-params.py
$C import secret key baker_secp unencrypted:spsk2U5sfwVotenHbrbxtfCXqUsZ9fkgjvqo8GfDJAid2Z8CDriRkc --force
$C import secret key baker_p256 unencrypted:p2sk3i26ZYgMHkwUaKK65R6rW8FKwhAjmuenxPL3B8xCeMPzR7cQF3 --force

LEVEL=$($C rpc get /chains/main/blocks/head/header | sed -n 's/.*"level": *\([0-9]*\).*/\1/p')
if [ "${LEVEL:-0}" = "0" ]; then
  $C -block genesis activate protocol $PROTO with fitness 1 and key activator and parameters /params.json
fi

# After activation: the genesis client chokes on BLS keys in the wallet.
$C import secret key baker_bls unencrypted:BLsk2Mn8fUsniKUnqrbonHp3zE46apoVXs2rAqStq81uz35DeNbD79 --force

exec octez-baker-PsUshuai -d $CLIENT_DIR -E http://127.0.0.1:8732 run with local node $DATA \
  bootstrap1 bootstrap2 bootstrap3 bootstrap4 bootstrap5 baker_secp baker_p256 baker_bls \
  --liquidity-baking-toggle-vote pass --without-dal
