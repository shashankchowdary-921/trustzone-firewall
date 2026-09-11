#!/usr/bin/env python3
"""P10 — QoR sweep: N_REGIONS x TAINT_EN, yosys synth + abc gate mapping.
Median of 3 runs per config (abc mapping is nondeterministic run-to-run).
Emits out/qor_sweep.csv. GE-proxy = mapped simple-gate instance count.
policy_cone_levels = decision-cone depth (zero-cycle-relevant path).
Taint overhead measured from standalone tzf_taint synthesis."""
import os, re, subprocess, csv, statistics

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
GATES = "AND,NAND,OR,NOR,XOR,XNOR,ANDNOT,ORNOT,AOI3,OAI3,AOI4,OAI4,MUX"

def run(cmd):
    cp = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
    return cp.stdout + cp.stderr

def gate_count(stat_path):
    g = 0
    for line in open(os.path.join(ROOT, stat_path)).read().splitlines():
        m = re.match(r"^\s+(\d+)\s+(\$_\S+|\$mux|\$pmux)\s*$", line)
        if m:
            g += int(m.group(1))
    return g

def synth_fw(nreg, taint):
    log = run(["yosys", "-q", "-p",
        "read_verilog -sv rtl/tzf_policy.sv rtl/tzf_faultlog.sv rtl/tzf_taint.sv "
        "rtl/tz_firewall.sv; "
        "chparam -set N_REGIONS %d -set TAINT_EN %d tz_firewall; "
        "synth -top tz_firewall -flatten; "
        "abc -g %s; opt_clean; "
        "tee -o out/stat.txt stat; tee -o out/ltp.txt ltp" % (nreg, taint, GATES)])
    if "ERROR" in log.upper():
        print("SYNTH FAIL", nreg, taint)
        return None
    ltp = open(os.path.join(ROOT, "out", "ltp.txt")).read()
    depth = re.search(r"length=(\d+)", ltp)
    # policy-cone-only depth
    run(["yosys", "-q", "-p",
         "read_verilog -sv rtl/tzf_policy.sv; "
         "chparam -set N_REGIONS %d tzf_policy; "
         "synth -top tzf_policy -flatten; abc -g %s; opt_clean; "
         "tee -o out/ltp_pol.txt ltp" % (nreg, GATES)])
    pol = open(os.path.join(ROOT, "out", "ltp_pol.txt")).read()
    pdepth = re.search(r"length=(\d+)", pol)
    return (gate_count("out/stat.txt"),
            int(depth.group(1)) if depth else -1,
            int(pdepth.group(1)) if pdepth else -1)

def synth_taint():
    run(["yosys", "-q", "-p",
         "read_verilog -sv rtl/tzf_taint.sv; "
         "chparam -set REGION_W 4 tzf_taint; "
         "synth -top tzf_taint -flatten; abc -g %s; opt_clean; "
         "tee -o out/stat_t.txt stat" % GATES])
    return gate_count("out/stat_t.txt")

def main():
    rows = []
    for nreg in (4, 8, 12, 16):
        for taint in (0, 1):
            gs, deps, pdeps = [], [], []
            for _ in range(3):
                r = synth_fw(nreg, taint)
                if r:
                    gs.append(r[0]); deps.append(r[1]); pdeps.append(r[2])
            if gs:
                g = int(statistics.median(gs))
                dep = int(statistics.median(deps))
                pdep = int(statistics.median(pdeps))
                rows.append([nreg, taint, g, dep, pdep])
                print("N=%-3d taint=%d  gates(med3)=%-6d depth=%-3d policy_depth=%d"
                      % (nreg, taint, g, dep, pdep))
    tg = synth_taint()
    print("tzf_taint standalone gates:", tg)
    base = {r[0]: r[2] for r in rows if r[1] == 0}
    overheads = []
    for nreg in sorted(base):
        pct = 100.0 * tg / base[nreg]
        overheads.append([nreg, round(pct, 2)])
        print("taint overhead @N=%d: %.2f%%" % (nreg, pct))
    with open(os.path.join(ROOT, "out", "qor_sweep.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["n_regions", "taint_en", "gate_cells_ge_proxy",
                    "logic_depth_levels", "policy_cone_levels"])
        w.writerows(rows)
        w.writerow([])
        w.writerow(["tzf_taint_standalone_gates", tg])
        w.writerow(["taint_overhead_pct_by_N"] + [o[1] for o in overheads])

if __name__ == "__main__":
    main()
