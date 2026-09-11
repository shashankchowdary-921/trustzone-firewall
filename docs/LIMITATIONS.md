# TZFIREWALL — LIMITATIONS (honesty pack, reviewed 2026-08-22)

1. **Fault-log/interrupt covert channel (DISCLOSED).** irq timing and log
   occupancy reveal the existence/timing of secure-side faults to any observer
   of those pins. Non-interference proofs deliberately EXCLUDE irq/log
   visibility (fm_nonint asserts the master-visible AXI interface only).
   Mitigation path: class-gate log reads when the config wrapper lands.
2. **AxPROT[0] (privileged) ignored** by policy decode (MICROSPEC SEC 3).
3. **Write-path decision serialization**: one outstanding AW decision window;
   granted bursts stream through, but a blocked write stalls subsequent AW
   acceptance until its DECERR-B completes. Throughput note, not a latency
   penalty on granted traffic.
4. **M18 gap — entry immutability not machine-checked.** Overflow drops-newest
   policy is asserted for COUNT behavior but stored-entry corruption under
   overflow is uncovered by formal and fuzz (campaign finding). Directed sim
   covers normal-path contents only.
5. **M22 gap — taint observer self-check.** tzf_taint is fanout-free
   (equivalence-proven harmless); its own correctness rests on construction
   review + directed sim, no dedicated property.
6. **QoR methodology.** GE-proxy = yosys+abc mapped gate instances, median of
   3 runs (abc nondeterministic across runs; full-design taint-on/off deltas
   are within mapping noise — overhead therefore measured from standalone
   observer ratio). No liberty corners locally: frequency signoff deferred to
   Genus/MMMC. Depth=97 overall is the timestamp ripple chain, off the AXI
   granted path.
7. **Single-outstanding blocked reads enforced** (pend-stall). Mutant M09
   showed a pipelined variant exists that preserves the observable contract
   under always-ready stimulus — classified equivalent-mutant per V6 protocol.
8. **Fuzz subordinate is always-ready**; backpressure stress on egress is not
   exercised in simulation (ingress bounded-response is formally proven).
