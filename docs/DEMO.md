# TZFIREWALL — 2-minute demo script

Setup (one terminal, repo root):
    make lint unit axi        # ~30 s: lint clean + both self-checking TBs green

## Beat 1 (0:00-0:40) — the firewall behaves
Point at tb_firewall output: default-deny after reset (T1), secure read granted
with ZERO-cycle egress (m_arvalid same cycle), NS read blocked with DECERR +
logged, overlap lowest-index-wins at AXI level, burst write drains then DECERR,
overflow sets sticky irq. "Every behavior you just saw is a spec section in
MICROSPEC.md."

## Beat 2 (0:40-1:20) — the claims are PROVEN, not tested
    make fm                   # BMC-12 then temporal induction
"Status: PASSED twice — the second one is an UNBOUNDED proof: no bypass path
exists, for ANY of the 2^900+ region/permission configurations, for ALL time.
The reference decision inside the proof is written independently from the RTL —
they can't share a bug."

## Beat 3 (1:20-1:50) — the checks themselves are proven
    make campaign             # 22 seeded security bugs -> out/bug_matrix.csv
"We injected 22 real firewall bugs. Formal catches 16, fuzz catches 10, together
91% — and the 2 misses are WRITTEN DOWN in LIMITATIONS.md. Most teams can't tell
you what their verification misses; this project quantifies it."

## Close (1:50-2:00)
    type out\qor_sweep.csv
"16 regions, ~12 kGE estimate, decision cone 23 logic levels, taint
instrumentation measured at 0.07%. Everything reruns on this laptop with zero
licenses."
