# Dumps a membership fixture for the packet in tezos/deployed.env: proof, block B, header B+1.
import json, struct, hashlib, urllib.request, sys, os
RPC = os.environ.get('TEZOS_RPC', 'http://localhost:8732')
rpc = lambda p: json.load(urllib.request.urlopen(RPC + p))
env = dict(l.strip().split('=', 1) for l in open(os.path.join(os.path.dirname(__file__), '../../tezos/deployed.env')))
seq = int(sys.argv[1]) if len(sys.argv) > 1 else 1
path = b'eth-0' + b'\x01' + struct.pack('>Q', seq)
key_hash = hashlib.blake2b(b'\x05\x0a' + struct.pack('>I', len(path)) + path, digest_size=32).hexdigest()
blk = rpc('/chains/main/blocks/head~3/header')
nxt = rpc('/chains/main/blocks/head~2/header')
ops = sum(len(x) for x in rpc(f'/chains/main/blocks/{blk["hash"]}/operations'))
proof = rpc(f'/chains/main/blocks/{blk["hash"]}/context/merkle_tree_v2/big_maps/index/5/contents/{key_hash}/data')
json.dump(dict(path=path.hex(), key_hash=key_hash, big_map_id=5, block=blk, next_header=nxt, op_count=ops, proof=proof),
          open(os.path.join(os.path.dirname(__file__), 'membership.json'), 'w'), indent=1)
print('ok', blk['level'])
