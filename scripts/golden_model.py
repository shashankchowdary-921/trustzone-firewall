#!/usr/bin/env python3
"""Golden permission model — MICROSPEC v1.1 SEC 2/3 reference."""
from dataclasses import dataclass

@dataclass
class Region:
    base: int; mask: int; perm: int  # perm bits {sx,sw,sr,nx,nw,nr}

def decide(regions, addr, prot, is_write):
    """returns (grant, region_or_-1). regions: list[Region|None], lowest idx wins."""
    hit = -1
    for i, r in enumerate(regions):
        if r is None:
            continue
        if (addr & r.mask) == r.base:
            hit = i
            break                      # SEC 2.1 lowest index wins
    if hit < 0:
        return False, -1               # SEC 2.2 default-deny
    p = regions[hit].perm
    ns = bool(prot & 0x2)              # AxPROT[1]
    # canonical layout per MICROSPEC: bit0=nr/nr-class LSB ... {sx,sw,sr,nx,nw,nr}
    sel = p & 0b000111 if ns else (p >> 3) & 0b111   # {nx,nw,nr} / {sx,sw,sr}
    nr, nw, nx = sel & 1, (sel >> 1) & 1, (sel >> 2) & 1
    if is_write:
        return bool(nw), hit
    fetch = bool(prot & 0x4)           # AxPROT[2]
    return bool(nx if fetch else nr), hit

def op_code(prot, is_write):
    if is_write:
        return 1                       # W
    return 2 if (prot & 0x4) else 0    # X / R
