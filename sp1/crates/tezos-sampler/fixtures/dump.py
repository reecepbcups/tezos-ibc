# Dumps sampler fixtures from the sandbox at block head~1: sampler state + seed proofs per cycle, and validators per level.
import json, urllib.request, os, sys
RPC = os.environ.get('TEZOS_RPC', 'http://localhost:8732')
rpc = lambda p: json.load(urllib.request.urlopen(RPC + p))
blk = rpc('/chains/main/blocks/head~1/header')
h = blk['hash']
nxt = rpc(f'/chains/main/blocks/head/header')
assert nxt['predecessor'] == h
ops = sum(len(x) for x in rpc(f'/chains/main/blocks/{h}/operations'))
cycles = rpc(f'/chains/main/blocks/{h}/context/raw/json/cycle?depth=1')
bpc = rpc(f'/chains/main/blocks/{h}/context/constants')['blocks_per_cycle']
out = dict(block=blk, next_header=nxt, op_count=ops, blocks_per_cycle=bpc, cycles={})
for c in sorted(int(x[0]) if isinstance(x, list) else int(x) for x in cycles):
    try:
        state = rpc(f'/chains/main/blocks/{h}/context/raw/bytes/cycle/{c}/delegate_sampler_state')
    except Exception:
        continue
    d = dict(
        sampler_state=state,
        random_seed=rpc(f'/chains/main/blocks/{h}/context/raw/bytes/cycle/{c}/random_seed'),
        state_proof=rpc(f'/chains/main/blocks/{h}/context/merkle_tree_v2/cycle/{c}/delegate_sampler_state'),
        seed_proof=rpc(f'/chains/main/blocks/{h}/context/merkle_tree_v2/cycle/{c}/random_seed'),
        validators={},
    )
    # sandbox has one cycle era starting at level 1, so cycle c is levels c*bpc+1 ..= (c+1)*bpc
    for lvl in range(c * bpc + 1, (c + 1) * bpc + 1):
        try:
            v = rpc(f'/chains/main/blocks/{h}/helpers/validators?level={lvl}')[0]
            d['validators'][lvl] = {e['consensus_key']: e['rounds'] for e in v['delegates']}
        except Exception as e:
            print('skip', lvl, e, file=sys.stderr)
    out['cycles'][c] = d
name = sys.argv[1] if len(sys.argv) > 1 else 'sandbox.json'
json.dump(out, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), name), 'w'))
print('ok', blk['level'], list(out['cycles']), {c: len(v['validators']) for c, v in out['cycles'].items()})
