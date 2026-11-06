#!/bin/sh
# Native arm64 LIGO in a container. The amd64 docker image hangs under emulation on Apple Silicon.
# Get the binary: curl -sL -o tools/ligo https://gitlab.com/ligolang/ligo/-/jobs/13679772867/artifacts/raw/ligo_arm64_unix && chmod +x tools/ligo
cd "$(dirname "$0")/.."
exec docker run --rm -e LIGO_SKIP_ANALYTICS=true -v "$PWD:/w" -w /w/tezos/contracts debian:bookworm-slim /w/tools/ligo "$@"
