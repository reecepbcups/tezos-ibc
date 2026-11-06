# Sourced. Builds the relayer once and copies the binary to $1, so each call skips cargo and
# a later build with other flags (protocol.sh's wrong pin) can't swap it mid-run.
relayer_bin() {
  (cd "$ROOT/relayer" && cargo build -q --release) || return 1
  t=$(cd "$ROOT/relayer" && cargo metadata -q --format-version 1 --no-deps \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
  cp "$t/release/relayer" "$1" && chmod +x "$1"
}
