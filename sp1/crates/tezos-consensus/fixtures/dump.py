# Dumps a quorum fixture: headers n, n+1, op hashes of n+1, attestations for n+1 (pass 0 of n+2),
# and rights + consensus/companion pks for the slots that attested.
# usage: python3 dump.py <n> [rpc] [name]   (n+2 must exist)
import json, sys, os, urllib.request
n = int(sys.argv[1])
RPC = sys.argv[2] if len(sys.argv) > 2 else 'http://localhost:8732'
name = sys.argv[3] if len(sys.argv) > 3 else f'quorum_{n}'
rpc = lambda p: json.load(urllib.request.urlopen(urllib.request.Request(RPC + p, headers={'User-Agent': 'curl/8'})))
b = lambda l: f'/chains/main/blocks/{l}'
atts = rpc(f'{b(n + 2)}/operations/0')
# Rights come from receipts (slot -> delegate, power) since public nodes block helpers/attestation_rights.
rights = []
for o in atts:
    c = o['contents'][0]
    if c['kind'] == 'attestations_aggregate':
        for m, r in zip(c['committee'], c['metadata']['committee']):
            rights.append(dict(first_slot=m['slot'], delegate=r['delegate'], attesting_power=r['consensus_power']['slots']))
    elif c['level'] == n + 1:
        md = c['metadata']
        rights.append(dict(first_slot=c['slot'], delegate=md['delegate'], attesting_power=md['consensus_power']['slots']))
for d in rights:
    d['consensus_pk'] = rpc(f'{b(n + 2)}/context/delegates/{d["delegate"]}/consensus_key')['active']['pk']
    if d['consensus_pk'].startswith('BLpk'):
        comp = rpc(f'{b(n + 2)}/context/delegates/{d["delegate"]}/companion_key')['active']
        d['companion_pk'] = comp['pk'] if comp else None
c = rpc(f'{b(n + 1)}/context/constants')
out = dict(
    chain_id=rpc('/chains/main/chain_id'),
    header_n=rpc(f'{b(n)}/header'),
    header_n1=rpc(f'{b(n + 1)}/header'),
    operation_hashes_n1=rpc(f'{b(n + 1)}/operation_hashes'),
    attestations=atts,
    rights=rights,
    consensus_threshold_size=c['consensus_threshold_size'],
    consensus_committee_size=c['consensus_committee_size'],
)
path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f'{name}.json')
json.dump(out, open(path, 'w'), indent=1)
print('wrote', path, len(rights), 'delegates')
