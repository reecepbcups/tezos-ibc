# Builds params.json from the PsUshuai sandbox defaults, tuned to look like mainnet consensus.
import json
d = json.load(open('ushuai-sandbox-params.json'))
d.update(consensus_committee_size=7000, consensus_threshold_size=4667,
         blocks_per_cycle=16, minimal_block_delay="1")
# Extra bakers so every mainnet signature scheme shows up in attestations.
d['bootstrap_accounts'] += [
    ["sppk7cT6TiY7VkhDV2pSbY2C9t49WrZLv36PDTU3T5wja1HjiCtnJPs", "4000000000000"],
    ["p2pk67hkrPcxhDTqryEJ7rms9xdm26BNQiuP8jTSJxwjRajpUBbN8o9", "4000000000000"],
    # tz4 as consensus key of bootstrap5, like most mainnet tz4 bakers (tz1 delegate, tz4 consensus key)
]
d['bootstrap_accounts'][4].append("BLpk1ucMtTA3h1mT2nsfDB9GdN9sM6Fn4UoCqFmVGnxorEPiJnjrWkHrckGw4xUYmqiYj1yeZ1ZH")
json.dump(d, open('params.json', 'w'), indent=1)
