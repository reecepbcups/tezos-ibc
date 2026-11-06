#!/bin/sh
# eth/lib is gitignored. Pulls the pinned libs as plain files (same versions bad-bridge uses).
set -eu
cd "$(dirname "$0")"
mkdir -p lib
[ -d lib/forge-std ] || git -c advice.detachedHead=false clone -q --depth 1 --branch v1.16.2 https://github.com/foundry-rs/forge-std lib/forge-std
[ -d lib/openzeppelin-contracts ] || git -c advice.detachedHead=false clone -q --depth 1 --branch v5.4.0 https://github.com/OpenZeppelin/openzeppelin-contracts lib/openzeppelin-contracts
rm -rf lib/forge-std/.git lib/openzeppelin-contracts/.git
