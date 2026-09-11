#!/usr/bin/env python3
"""Differential fuzz harness: random stimulus -> iverilog sim -> golden compare.
Usage: python fuzz_diff.py --seeds 4 --txns 2000 [--work out]
Exit code: 0 clean, 1 mismatches (FN counts as security failure)."""
import argparse, os, random, subprocess, sys
from golden_model import Region, decide, op_code

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))

def gen_config(rng):
    regions = [None] * 16
    n_active = rng.randint(1, 5)
    used_bases = []
    for i in rng.sample(range(16), n_active):
        mask_bits = rng.choice([4, 8, 12, 16, 20])
        mask = ((1 << 32) - 1) ^ ((1 << (32 - mask_bits)) - 1)
        base = rng.randrange(1 << mask_bits) << (32 - mask_bits)
        if rng.random() < 0.25 and used_bases:      # force overlaps
            b0, _ = rng.choice(used_bases)
            base = b0                               # shared base, new mask
        used_bases.append((base, mask))
        perm = rng.getrandbits(6)                    # {sx,sw,sr,nx,nw,nr}
        if rng.random() < 0.2:
            perm = 0                                 # all-deny region
        regions[i] = Region(base, mask, perm)
    return regions

def gen_txn_addr(rng, regions):
    live = [(r.base, r.mask) for r in regions if r is not None]
    roll = rng.random()
    if live and roll < 0.55:                          # inside a region
        b, m = rng.choice(live)
        inv = (~m) & 0xFFFFFFFF
        return (b | rng.randrange(inv + 1)) & 0xFFFFFFFF
    elif live and roll < 0.70:                        # exact base / boundary
        b, m = rng.choice(live)
        return rng.choice([b, b ^ (m & -m & m), (b | m) & 0xFFFFFFFF])
    else:                                             # fully random
        return rng.getrandbits(32)

def emit_stim(path, batches):
    with open(path, "w") as f:
        for regions, txns in batches:
            # grouped order matching tb_fuzz.do_cfg: en | b0..b15 | m0..m15 | p0..p15
            f.write("0 %08x " % en_word(regions))
            for r in regions:
                f.write("%08x " % (r.base if r else 0))
            for r in regions:
                f.write("%08x " % (r.mask if r else 0))
            for r in regions:
                f.write("%02x " % (r.perm if r else 0))
            f.write("\n")
            for wr, prot, addr in txns:
                f.write("1 %d %d %08x\n" % (wr, prot, addr))
        f.write("-1\n")

def en_word(regions):
    v = 0
    for i, r in enumerate(regions):
        if r is not None:
            v |= 1 << i
    return v

def run_seed(vvp, seed_dir, seed, regions_batches):
    stim = os.path.join(seed_dir, "stim_%d.txt" % seed)
    res = os.path.join(seed_dir, "res_%d.txt" % seed)
    emit_stim(stim, regions_batches)
    cp = subprocess.run([vvp, "-n", "tb_fuzz.vvp", "+STIM=%s" % stim, "+RES=%s" % res],
                        cwd=os.path.join(ROOT, "tb"), capture_output=True, text=True,
                        timeout=600)
    if "FUZZ DONE" not in cp.stdout:
        print("SIM FAIL seed", seed, cp.stdout[-400:], cp.stderr[-400:])
        sys.exit(2)
    return res

def compare(res_file, regions_batches):
    fn = fp = ok = 0
    expected = []
    for regions, txns in regions_batches:
        for wr, prot, addr in txns:
            g, _ = decide(regions, addr, prot, wr)
            expected.append(g)
    with open(res_file) as f:
        lines = [l.split() for l in f.read().splitlines() if l.strip()]
    assert len(lines) == len(expected), "txn count mismatch"
    for (wr_s, pr_s, ad_s, resp_s), g in zip(lines, expected):
        dut_grant = (int(resp_s) == 0)
        if dut_grant and not g:
            fn += 1                                   # SECURITY HOLE
        elif g and not dut_grant:
            fp += 1                                   # availability bug
        else:
            ok += 1
    return ok, fp, fn

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=4)
    ap.add_argument("--txns", type=int, default=2000)
    ap.add_argument("--cfg-every", type=int, default=500)
    ap.add_argument("--start-seed", type=int, default=1)
    ap.add_argument("--vvp", default="vvp")
    a = ap.parse_args()

    work = os.path.join(ROOT, "out")
    os.makedirs(work, exist_ok=True)

    tot_ok = tot_fn = tot_fp = 0
    for seed in range(a.start_seed, a.start_seed + a.seeds):
        rng = random.Random(seed * 7919)
        batches, cur_regions, cur_txns = [], None, []
        for i in range(a.txns):
            if cur_regions is None or i % a.cfg_every == 0:
                if cur_regions is not None:
                    batches.append((cur_regions, cur_txns))
                cur_regions, cur_txns = gen_config(rng), []
            prot = rng.getrandbits(3)
            wr = rng.random() < 0.5
            addr = gen_txn_addr(rng, cur_regions)
            cur_txns.append((int(wr), prot, addr))
        batches.append((cur_regions, cur_txns))

        res = run_seed(a.vvp, work, seed, batches)
        ok, fp, fn = compare(res, batches)
        tot_ok += ok; tot_fp += fp; tot_fn += fn
        print("seed %-4d txns=%-7d match=%-7d FP=%-4d FN=%-4d" %
              (seed, a.txns, ok, fp, fn))

    print("TOTAL: match=%d FP=%d FN=%d" % (tot_ok, tot_fp, tot_fn))
    if tot_fn or tot_fp:
        sys.exit(1)
    print("DIFFERENTIAL CLEAN")

if __name__ == "__main__":
    main()
