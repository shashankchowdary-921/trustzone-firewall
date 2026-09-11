# R2 TrustZone Firewall — 12-Phase Execution Plan (~85 h)
ALL PHASES CLOSED 2026-08-22. Evidence map below.

| Phase | Scope | Gate | Status | Evidence |
|---|---|---|---|---|
| P0 | Toolchain probe + scaffold | tools green | DONE | yosys 0.66/z3/iverilog/verilator probed |
| P1 | Microspec freeze | spec v1.1 signed | DONE | docs/MICROSPEC.md (op-decode fix pre-RTL) |
| P2 | Policy core RTL | unit sim green | DONE | tb_policy 10/10 PASS |
| P3 | AXI4 paths + default-deny | txn sim green | DONE | tb_firewall ALL PASS |
| P4 | Fault log + ts + irq | log checks pass | DONE | tb_firewall T1/T3/T8 blocks |
| P5 | TBs + golden + diff loop | zero mismatch | DONE | fuzz_diff 15k clean; harness found+fixed emitter bug |
| P6 | Complete-mediation proof (O1) | unbounded proof | DONE | smtbmc BMC-12 PASSED + temporal induction PASSED, all configs |
| P7 | Non-interference + equivalence (O2) | inductive proofs | DONE | fm_nonint PASSED (induction); fm_equiv PASSED (induction) |
| P8 | Seeded bug campaign (O3) | dual detection | DONE | 22 bugs: formal 16 / fuzz 10 / BOTH 10 / gaps 2 (documented); campaign also hardened the suite (independent ref, shadow FSMs, dead-assert fix, filename-typo guard) |
| P9 | Differential fuzz 1M txns | FN=0 FP=0 | DONE | 1,000,000/1,000,000 match |
| P10 | QoR sweep + latency doc (O4) | CSV + <=1% taint | DONE | out/qor_sweep.csv; overhead 0.07-0.22% measured; cone depth 14->23 levels; ~12 kGE est @N=16 (<14kGE target) |
| P11 | One-command regression (O5) | clean clone->green | DONE | Makefile `make all`; README.md |
| P12 | Limitations/demo/results + audit | acceptance closed | DONE | docs/RESULTS.md LIMITATIONS.md DEMO.md |

## Toolchain
iverilog + verilator (msys64 sim) · yosys-smtbmc + z3 (formal, no sby/WSL)
· yosys+abc (QoR proxy) · Python 3.13 (golden/fuzz/campaign). Zero licenses.
