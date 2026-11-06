#!/bin/sh
# Fresh sandbox on :${TEZOS_PORT:-8732}. Wipes chain state each run.
# TEZOS_CONTAINER and TEZOS_PORT let several sandboxes run side by side.
cd "$(dirname "$0")"
NAME=${TEZOS_CONTAINER:-tezos-sandbox}
python3 gen-params.py
docker rm -f "$NAME" >/dev/null 2>&1
docker run -d --name "$NAME" -p "${TEZOS_PORT:-8732}:8732" \
  -v "$PWD/start.sh:/start.sh:ro" -v "$PWD/params.json:/params.json:ro" \
  --entrypoint sh tezos/tezos:octez-v25.3 /start.sh
