# TZFIREWALL MICROSPEC v1.1 — FROZEN 2026-08-22
Parameterized AXI4 TrustZone-style firewall. Every formal property in P6/P7
references a section number here. Changes after P2 start = version bump.

## 1. PARAMETERS
- N_REGIONS: 4..16 (power-of-2 not required; sweep points: 4, 8, 12, 16)
- ADDR_WIDTH = 32, DATA_WIDTH = 32, ID_WIDTH = 4
- Region config: BASE[i], MASK[i] (mask = contiguous high bits, LSB-aligned
  zeros enforced at programming time), PERM[i] = {sec_r, sec_w, sec_x,
  ns_r, ns_w, ns_x} — 6 bits per region

## 2. ADDRESS MATCHING (SEC 2)
- hit[i] = (addr & MASK[i]) == BASE[i]
- OVERLAP RESOLUTION (SEC 2.1): LOWEST region index wins. Deterministic by
  construction; proven for all configuration pairs in P6.
- NO-MATCH (SEC 2.2): default-DENY. Reset state = all regions disabled
  -> every transaction blocked. Proven reachable-from-reset property.

## 3. DECISION FUNCTION (SEC 3) — v1.1 CORRECTED
- Channel determines base op: AR -> R, AW -> W
- AxPROT[2]=1 on AR -> instruction fetch -> check X instead of R
- security class: AxPROT[1]=1 -> non-secure (NS), else secure (S)
  (IHI0022: AxPROT[1]=NS flag, AxPROT[2]=instruction/data; AxPROT[0]
  privileged bit is IGNORED by this firewall — documented limitation)
- grant = hit_any && PERM[hit_region][class][op]; else BLOCK.
- BLOCK RESPONSE POLICY (SEC 3.1):
  - AR blocked -> RRESP=DECERR, RLAST-driven single-beat R, RID preserved
  - AW blocked -> W-channel drains to WLAST (tracked), BRESP=DECERR, BID kept
  - Blocked transactions NEVER stall > bounded cycles (proven bound in P6)

## 4. FAULT LOG + TIMESTAMP (SEC 4)
- Free-running 32-bit timestamp counter, increments every ACLK, wraps mod 2^32
- On each BLOCK: one log entry pushed {timestamp, addr, AxPROT[2:1], op,
  hit_region or 4'hF if no-match}
- Back-to-back blocks: up to LOG_DEPTH entries buffered; overflow drops NEWEST
  and sets sticky OVF bit (SEC 4.1 — documented policy, proven no-corruption
  of stored entries)
- Interrupt: pulse on first fault, level until log read; maskable via INT_EN

## 5. CONFIG INTERFACE (SEC 5)
- Config registers programmed via simple APB-like slave (PSEL/PENABLE cycle);
  config writes take effect only at region-enable bit toggle — mid-transfer
  reprogramming of an ACTIVE decision is disallowed by handshake gate (SEC 5.1)
- Formal treats all config as anyconst free constants -> proofs cover ALL
  configurations without state explosion (SEC 5.2 — core trick of O1/O2)

## 6. TAINT LAYER (AUDIT BUILDS ONLY, SEC 6)
- Attribute-level taint: tracks {class(S/NS), op(R/W/X), region-ID} through
  decision cone + response path + log path
- Non-interference target (O2): no observable S->NS flow via granted data,
  DECERR responses, log contents, or interrupt timing beyond disclosed
  covert channel (see limitations doc, P12)

## 7. OPEN QUESTIONS (resolve before P2 RTL)
Q1. DATA_WIDTH 32 vs 64 — default 32 for kGE budget? [assumed 32]
Q2. LOG_DEPTH = 8 entries OK?                    [assumed 8]
Q3. APB config port vs plain write-strobe interface? [assumed minimal strobe;
    full APB wrapper deferred — keeps formal cone small]
