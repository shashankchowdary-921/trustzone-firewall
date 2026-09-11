# TZFIREWALL — AXI4 TrustZone-style Firewall
Complete-Mediation + Information-Flow (GLIFT-class) Security Proof

Owner: T. Shashank Chowdary | R2 | RTL | S-tier target | ~85 h build
**Status: SHIPPED — all proofs + campaigns closed on-disk (see docs/RESULTS.md)**

## What it is
Parameterized 4–16 region AXI4 firewall: every transaction is permitted-or-
blocked by an AxPROT-keyed read/write/fetch permission matrix; blocked traffic
gets bounded DECERR responses and a timestamped fault log. The security claims
are MACHINE-CHECKED, not asserted:

| Claim | Proof | Where |
|---|---|---|
| Zero bypass paths, ALL configs | yosys-smtbmc BMC-12 + **temporal induction (unbounded)** | `formal/fm_mediation.sv` |
| NS masters can't observe S-config | two-machine non-interference, inductive | `formal/fm_nonint.sv` |
| Audit instrumentation is strip-safe | TAINT_EN 0-vs-1 equivalence, inductive | `formal/fm_equiv.sv` |
| Checkers actually catch bugs | 22 seeded security bugs, dual detection matrix | `scripts/bug_campaign.py` |
| Golden-model agreement | 1,000,000 differential transactions, FN=0 FP=0 | `scripts/fuzz_diff.py` |
| Taint overhead ≤1% | measured 0.07–0.22% GE-proxy per sweep point | `out/qor_sweep.csv` |

## One-command regression
```
make all          # lint + unit + AXI directed + differential + all 3 formal proofs
make fuzz1m       # full 1M-txn differential run
make campaign     # seeded-bug campaign -> out/bug_matrix.csv
make qor          # QoR sweep 4->16 regions -> out/qor_sweep.csv
```
Toolchain: iverilog/verilator/yosys/z3 (all open-source) — zero licenses.

## Layout
```
rtl/    tzf_policy.sv   combinational decision cone (proof surface)
        tzf_faultlog.sv log bank + timestamp + irq
        tzf_taint.sv    audit-only attribute tagger (TAINT_EN=1)
        tz_firewall.sv  AXI4 integration
tb/     tb_policy.sv tb_firewall.sv tb_fuzz.sv
formal/ fm_mediation.sv fm_nonint.sv fm_equiv.sv
docs/   MICROSPEC.md PLAN.md RESULTS.md LIMITATIONS.md DEMO.md
```

## Guardrails
AXI4 scope only. "GLIFT-class" = attribute-level non-interference EVIDENCE,
never bit-exact GLIFT or security certification. Frequency/area numbers are
open-tool estimates relative to own baselines; Genus upgrades them.
