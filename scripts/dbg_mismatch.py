#!/usr/bin/env python3
"""Find and print first N mismatches with full config context."""
import os, random, subprocess, sys
from fuzz_diff import gen_config, gen_txn_addr, emit_stim, run_seed, ROOT

def main():
    seed = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    txns = 3000
    rng = random.Random(seed * 7919)
    batches, cur, cur_txns = [], None, []
    for i in range(txns):
        if cur is None or i % 500 == 0:
            if cur is not None:
                batches.append((cur, cur_txns))
            cur, cur_txns = gen_config(rng), []
        prot = rng.getrandbits(3)
        wr = int(rng.random() < 0.5)
        addr = gen_txn_addr(rng, cur)
        cur_txns.append((wr, prot, addr))
    batches.append((cur, cur_txns))

    res = run_seed("vvp", os.path.join(ROOT, "out"), 99, batches)
    lines = [l.split() for l in open(res).read().splitlines() if l.strip()]

    from golden_model import decide
    shown = 0
    exp_i = 0
    for b_idx, (regions, tlist) in enumerate(batches):
        print(f"--- batch {b_idx}: " + ", ".join(
            f"R{i}:b={hex(r.base)},m={hex(r.mask)},p={r.perm:06b}" +
            (f",EN" if regions[i] else "") for i, r in enumerate(regions) if r))
        for wr, prot, addr in tlist:
            g, reg = decide(regions, addr, prot, wr)
            wr_s, pr_s, ad_s, resp_s = lines[exp_i]
            dut_g = int(resp_s) == 0
            if g != dut_g and shown < 6:
                kind = "FP(golden=DENY dut=GRANT)" if False else \
                       ("FP golden-ALLOW dut-BLOCK" if g else "FN golden-DENY dut-GRANT")
                print(f"  {kind}: wr={wr} prot={prot:03b} addr={addr:08x} "
                      f"golden g={g} reg={reg} | dut resp={resp_s}")
                # show which region RTL should have picked
                hits = [(i, r) for i, r in enumerate(regions)
                        if r and (addr & r.mask) == r.base]
                print(f"     hits={[(i, hex(r.base), hex(r.mask), bin(r.perm)) for i,r in hits]}")
                shown += 1
            exp_i += 1
        if shown >= 6:
            break

if __name__ == "__main__":
    main()
