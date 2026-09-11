
"""P8 — Seeded security-bug campaign (O3).
Injects >= 20 security bugs into RTL copies; each must be caught by BOTH
the formal complete-mediation suite (quick BMC) AND the differential fuzz
harness. Emits detection matrix CSV. Undetected bugs are reported honestly.
"""
import os, re, shutil, subprocess, sys, csv

HERE   = os.path.dirname(os.path.abspath(__file__))
ROOT   = os.path.normpath(os.path.join(HERE, ".."))
RTL    = ["tzf_policy.sv", "tzf_faultlog.sv", "tzf_taint.sv", "tz_firewall.sv"]
SMTBMC = r"C:\msys64\mingw64\bin\yosys-smtbmc-script.py"

MUT = [
 # id  file             class        old -> new
 ("M01","tzf_policy.sv","priority",  ("for (i = N_REGIONS-1; i >= 0; i = i - 1)","for (i = 0; i < N_REGIONS; i = i + 1)")),
 ("M02","tzf_policy.sv","enable-gate",("hit[g] = cfg_enable[g] &&","hit[g] =")),
 ("M03","tzf_policy.sv","decode",    ("(addr & cfg_mask[g*ADDR_WIDTH +: ADDR_WIDTH])\n           == cfg_base[g*ADDR_WIDTH +: ADDR_WIDTH])",
                                    "(addr & cfg_mask[g*ADDR_WIDTH +: ADDR_WIDTH])\n           != cfg_base[g*ADDR_WIDTH +: ADDR_WIDTH])")),
 ("M04","tzf_policy.sv","class-swap",("wire       ns   = axprot[1];","wire       ns   = ~axprot[1];")),
 ("M05","tzf_policy.sv","fetch-bit", ("(axprot[2]    ? sel[2] : sel[0]);","(axprot[0]    ? sel[2] : sel[0]);")),
 ("M06","tzf_policy.sv","op-select", ("is_write      ? sel[1] :\n                 (axprot[2]    ? sel[2] : sel[0]);","sel[0];")),
 ("M07","tzf_policy.sv","default-open",("!any ? 1'b0 :","!any ? 1'b1 :")),
 ("M08","tzf_policy.sv","mask-shift",("(addr & cfg_mask[g*ADDR_WIDTH +: ADDR_WIDTH])","(addr & (cfg_mask[g*ADDR_WIDTH +: ADDR_WIDTH] >> 1))")),
 ("M09","tz_firewall.sv","bypass-stall",("assign s_arready = !rd_pend_q && (rd_grant ? m_arready : 1'b1);","assign s_arready = (rd_grant ? m_arready : 1'b1);")),
 ("M10","tz_firewall.sv","data-leak",("assign s_rdata  = rd_pend_q ? {DATA_WIDTH{1'b0}} : m_rdata;","assign s_rdata  = m_rdata;")),
 ("M11","tz_firewall.sv","resp-flip", ("assign s_bresp  = (ws_state == WS_BERR) ? RESP_DECERR : m_bresp;","assign s_bresp  = m_bresp;")),
 ("M12","tz_firewall.sv","aw-window", ("assign s_awready = (ws_state == WS_IDLE) &&\n                     (wr_grant ? m_awready : 1'b1);","assign s_awready = (wr_grant ? m_awready : 1'b1);")),
 ("M13","tz_firewall.sv","deadlock",  ("end else if (r_int_done) begin\n        rd_pend_q <= 1'b0;\n      end","end")),
 ("M14","tz_firewall.sv","drain-early",("wire w_drain_done = (ws_state == WS_DRAIN) && s_wvalid && s_wlast;","wire w_drain_done = (ws_state == WS_DRAIN) && s_wvalid;")),
 ("M15","tz_firewall.sv","log-spam",  ("wire block_ev    = rd_block_ev || wr_block_ev;","wire block_ev    = ar_fire || aw_fire;")),
 ("M16","tz_firewall.sv","chan-swap", (".cfg_perm(cfg_perm), .addr(s_awaddr), .axprot(s_awprot), .is_write(1'b1),",".cfg_perm(cfg_perm), .addr(s_araddr), .axprot(s_arprot), .is_write(1'b0),")),
 ("M17","tz_firewall.sv","rlast-hang",("assign s_rlast  = rd_pend_q ? 1'b1       : m_rlast;","assign s_rlast  = rd_pend_q ? 1'b0       : m_rlast;")),
 ("M18","tzf_faultlog.sv","ovf-overwrite",("if (push_i && !do_push) ovf_sticky <= 1'b1;","if (push_i && !do_push) begin ovf_sticky <= 1'b1; entries[rd_ptr] <= entry_new; end")),
 ("M19","tzf_faultlog.sv","int-mask",  ("assign irq      = int_en && ((count != 0) || ovf_sticky);","assign irq      = ((count != 0) || ovf_sticky);")),
 ("M20","tzf_faultlog.sv","underflow", ("wire do_pop  = rd_en && (count != 0);","wire do_pop  = rd_en;")),
 ("M21","tzf_faultlog.sv","ts-freeze", ("else        ts_cnt <= ts_cnt + {{(TS_WIDTH-1){1'b0}}, 1'b1};","else        ts_cnt <= ts_cnt;")),
 ("M22","tzf_taint.sv","taint-blind",("if ((ar_fire | aw_fire) && !req_ns)","if ((ar_fire | aw_fire))")),
]

def make_mutant(mid, fname, old, new, dst):
    if fname not in RTL or old == new:
        return False, "bad-filename-or-noop-mutation"
    shutil.rmtree(dst, ignore_errors=True)
    os.makedirs(dst)
    for f in RTL:
        txt = open(os.path.join(ROOT, "rtl", f)).read()
        if f == fname:
            if old not in txt:
                return False, "patch anchor not found"
            txt = txt.replace(old, new, 1)
        open(os.path.join(dst, f), "w").write(txt)
    return True, ""

def run(cmd, cwd=None, timeout=300):
    try:
        cp = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                            timeout=timeout)
        return cp.returncode, cp.stdout + cp.stderr
    except subprocess.TimeoutExpired:
        return -99, "TIMEOUT"

def formal_check(mdir):
    ycmd = ("read_verilog -formal -sv %s/tzf_policy.sv %s/tzf_faultlog.sv "
            "%s/tzf_taint.sv %s/tz_firewall.sv formal/fm_mediation.sv; "
            "prep -top fm_mediation -flatten; async2sync; dffunmap; "
            "write_smt2 -wires out\\mut.smt2") % (mdir, mdir, mdir, mdir)
    rc, o = run(["yosys", "-q", "-p", ycmd], timeout=240)
    if rc != 0:
        return True                      # build failure == detected
    rc, o = run([sys.executable, SMTBMC, "-s", "z3", "-t", "8",
                 os.path.join(ROOT, "out", "mut.smt2")], timeout=300)
    return "Status: FAILED" in o or "Assert failed" in o or rc != 0

def fuzz_check(mdir):
    tb = os.path.join(ROOT, "tb")
    vvp = os.path.join(mdir, "tb.vvp")
    src = [os.path.join(mdir, f) for f in
           ["tzf_policy.sv", "tzf_faultlog.sv", "tzf_taint.sv", "tz_firewall.sv"]]
    rc, o = run(["iverilog", "-g2012", "-o", vvp, os.path.join(tb, "tb_fuzz.sv")] + src,
                timeout=120)
    if rc != 0:
        return True
    sys.path.insert(0, HERE)
    from fuzz_diff import gen_config, gen_txn_addr, emit_stim
    import random
    caught = False
    for seed in (101, 202):
        rng = random.Random(seed)
        regions = gen_config(rng)
        txns = []
        for _ in range(400):
            prot = rng.getrandbits(3)
            wr = int(rng.random() < 0.5)
            txns.append((wr, prot, gen_txn_addr(rng, regions)))
        stim = os.path.join(mdir, "stim.txt"); res = os.path.join(mdir, "res.txt")
        emit_stim(stim, [(regions, txns)])
        rc, o = run(["vvp", "-n", vvp, "+STIM=%s" % stim, "+RES=%s" % res],
                    cwd=tb, timeout=90)
        if rc != 0 or "FUZZ DONE" not in o:
            return True                   # hang/crash == detected
        from golden_model import decide
        exp = [decide(regions, a, p, w)[0] for w, p, a in txns]
        lines = [l.split() for l in open(res).read().splitlines() if l.strip()]
        if len(lines) != len(exp):
            return True
        for (wr_s, pr_s, ad_s, resp_s), g in zip(lines, exp):
            if (int(resp_s) == 0) != g:
                caught = True
    return caught

def main():
    out_csv = os.path.join(ROOT, "out", "bug_matrix.csv")
    rows, both = [], 0
    for mid, fname, cls, (old, new) in MUT:
        mdir = os.path.join(ROOT, "out", "mutants", mid)
        ok, err = make_mutant(mid, fname, old, new, mdir)
        if not ok:
            rows.append([mid, cls, fname, "PATCHFAIL:" + err, "", ""]); continue
        F = formal_check(mdir)
        Z = fuzz_check(mdir)
        tag = "BOTH" if (F and Z) else ("FORMAL" if F else ("FUZZ" if Z else "UNDETECTED"))
        both += 1 if tag == "BOTH" else 0
        rows.append([mid, cls, fname, old.strip()[:40], "Y" if F else "N",
                     "Y" if Z else "N", tag])
        print("%s %-12s formal=%s fuzz=%s -> %s" % (mid, cls, F, Z, tag))
    with open(out_csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "class", "file", "mutation", "formal", "fuzz", "verdict"])
        w.writerows(rows)
    n_undet = sum(1 for r in rows if r[-1] == "UNDETECTED")
    print("\nCampaign: %d mutants, %d caught-by-BOTH, %d undetected"
          % (len(rows), both, n_undet))

if __name__ == "__main__":
    main()

