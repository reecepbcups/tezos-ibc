# Dumps a mainnet big_map membership proof plus headers B and B+1.
# usage: [RPC=http://127.0.0.1:8732] python3 dump_mainnet.py <big_map_id> <expru... or key hash hex> <out.json>
import json, hashlib, os, urllib.request, sys
RPC = os.environ.get('RPC', 'https://rpc.tzbeta.net')
A = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def b58dec(s, plen):
    n = 0
    for c in s.encode(): n = n * 58 + A.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    data, chk = raw[:-4], raw[-4:]
    assert hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4] == chk
    return data[plen:]
def rpc(p):
    req = urllib.request.Request(RPC + p, headers={'User-Agent': 'curl/8'})
    return json.load(urllib.request.urlopen(req, timeout=120))
bm, expr, out = int(sys.argv[1]), sys.argv[2], sys.argv[3]
kh = b58dec(expr, 4).hex() if expr.startswith("expr") else expr
assert len(kh) == 64
blk = rpc('/chains/main/blocks/head~3/header')
nxt = rpc(f'/chains/main/blocks/{blk["level"] + 1}/header')
assert nxt['predecessor'] == blk['hash']
ops = sum(len(x) for x in rpc(f'/chains/main/blocks/{blk["hash"]}/operations'))
proof = rpc(f'/chains/main/blocks/{blk["hash"]}/context/merkle_tree_v2/big_maps/index/{bm}/contents/{kh}/data?holey=false')
json.dump(dict(big_map_id=bm, key_hash=kh, block=blk, next_header=nxt, op_count=ops, proof=proof), open(out, 'w'))
print('ok', blk['level'], len(json.dumps(proof)))
