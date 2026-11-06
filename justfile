# Unit tests for every crate and contract.
test:
    cd sp1 && cargo test -q
    cd relayer && cargo test -q
    cd eth && forge test

# Each e2e script uses its own sandbox and anvil ports.
e2e:
    ./e2e.sh

e2e-recovery:
    e2e/recovery.sh

e2e-freeze:
    e2e/freeze.sh

e2e-keeper:
    e2e/keeper.sh

e2e-watcher:
    e2e/watcher.sh

# Last, it builds a wrong-pin relayer in its own target dir.
e2e-protocol:
    e2e/protocol.sh

# Everything, one after the other. Stops at the first failure.
e2e-all: test e2e e2e-recovery e2e-freeze e2e-keeper e2e-watcher e2e-protocol

# Real Groth16 proofs via the Succinct network (needs .env), real gateway on a Sepolia fork.
e2e-real:
    e2e/real.sh
