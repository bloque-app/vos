#!/usr/bin/env python3
"""Regenerate with `python3 vos-protocol/tools/gen_blake2b_rv64em.py > vos-protocol/src/blake2b_rv64em.S`
and check with `python3 vos-protocol/tools/check_blake2b_rv64em.py vos-protocol/src/blake2b_rv64em.S`.

Emit a BLAKE2b compression for riscv64em tuned to the PVM gas model.

The gas model charges a load or store 25 cycles on one of four ALU slots, so the
schedule minimises memory operations: the sixteen working words live in ten
registers under an offline-optimal (Belady) replacement over the fixed G order,
the rest in a stack frame, and the whole compression is one basic block.
"""
import sys

SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
]
COLS = [(0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15)]
DIAG = [(0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)]

TWO = False
CACHE = ["ra", "t0", "t1", "t2", "s0", "s1", "a0", "a2", "a3"] + ([] if TWO else ["a4"])
TMP2 = "a4"
TMP = "a5"
MPTR = "a1"
# Frame: v[16] spills, then saved ra, s0, s1, h_ptr, t, last mask.
V_OFF = lambda i: 8 * i
SAVE = {"ra": 128, "s0": 136, "s1": 144, "h": 152, "t": 160, "f": 168}
FRAME = 176


def gs():
    out = []
    for r in range(12):
        s = SIGMA[r]
        for i, g in enumerate(COLS):
            out.append((g, s[2 * i], s[2 * i + 1]))
        for i, g in enumerate(DIAG):
            out.append((g, s[8 + 2 * i], s[8 + 2 * i + 1]))
    return out


def main():
    G = gs()
    asm = []
    e = asm.append
    name = "vos_protocol_blake2b_compress"
    e(f".section .text.{name},\"ax\",@progbits")
    e(f".global {name}")
    e(f".type {name}, @function")
    e(f"{name}:")
    # a0 = h (8 x u64, in/out), a1 = m (128 bytes, any alignment), a2 = t, a3 = last (0/1)
    e(f"addi sp, sp, -{FRAME}")
    for reg in ("ra", "s0", "s1"):
        e(f"sd {reg}, {SAVE[reg]}(sp)")
    e(f"sd a0, {SAVE['h']}(sp)")
    e(f"sd a2, {SAVE['t']}(sp)")
    e(f"neg a3, a3")
    e(f"sd a3, {SAVE['f']}(sp)")
    # Initial values: v[0..8] from h, v[8..16] from the IV table, with t and f folded in.
    # They are materialised into the stack frame first (one pass), then the cache starts empty.
    e(f"lla {TMP}, vos_protocol_blake2b_iv")
    for i in range(8):
        e(f"ld {CACHE[i % 4]}, {8 * i}(a0)")
        e(f"sd {CACHE[i % 4]}, {V_OFF(i)}(sp)")
    for i in range(8):
        reg = CACHE[i % 4]
        e(f"ld {reg}, {8 * i}({TMP})")
        if i == 4:
            e(f"xor {reg}, {reg}, a2")
        if i == 6:
            e(f"xor {reg}, {reg}, a3")
        e(f"sd {reg}, {V_OFF(8 + i)}(sp)")
    # Belady replacement over the fixed access order.
    cache = {}  # word -> reg
    free = list(CACHE)

    def next_use(w, k):
        for j in range(k + 1, len(G)):
            if w in G[j][0]:
                return j
        return 10 ** 9

    def reg_of(w, k, pinned):
        if w in cache:
            return cache[w]
        if not free:
            victim = max((x for x in cache if x not in pinned), key=lambda x: next_use(x, k))
            r = cache.pop(victim)
            e(f"sd {r}, {V_OFF(victim)}(sp)")
            free.append(r)
        r = free.pop(0)
        e(f"ld {r}, {V_OFF(w)}(sp)")
        cache[w] = r
        return r

    def rotr(x, n):
        e(f"srli {TMP}, {x}, {n}")
        e(f"slli {x}, {x}, {64 - n}")
        e(f"or {x}, {x}, {TMP}")

    for k, ((a, b, c, d), x, y) in enumerate(G):
        pinned = {a, b, c, d}
        ra_, rb, rc, rd = (reg_of(w, k, pinned) for w in (a, b, c, d))
        e(f"ld {TMP}, {8 * x}({MPTR})")
        if TWO:
            e(f"ld {TMP2}, {8 * y}({MPTR})")
        e(f"add {ra_}, {ra_}, {rb}")
        e(f"add {ra_}, {ra_}, {TMP}")
        e(f"xor {rd}, {rd}, {ra_}")
        rotr(rd, 32)
        e(f"add {rc}, {rc}, {rd}")
        e(f"xor {rb}, {rb}, {rc}")
        rotr(rb, 24)
        if not TWO:
            e(f"ld {TMP}, {8 * y}({MPTR})")
        e(f"add {ra_}, {ra_}, {rb}")
        e(f"add {ra_}, {ra_}, {TMP2 if TWO else TMP}")
        e(f"xor {rd}, {rd}, {ra_}")
        rotr(rd, 16)
        e(f"add {rc}, {rc}, {rd}")
        e(f"xor {rb}, {rb}, {rc}")
        rotr(rb, 63)
    # Finalise: h[i] ^= v[i] ^ v[i+8]. Spill everything still cached, then combine from the frame.
    for w, r in sorted(cache.items()):
        e(f"sd {r}, {V_OFF(w)}(sp)")
    e(f"ld a0, {SAVE['h']}(sp)")
    for i in range(8):
        e(f"ld t0, {8 * i}(a0)")
        e(f"ld t1, {V_OFF(i)}(sp)")
        e(f"ld t2, {V_OFF(i + 8)}(sp)")
        e("xor t0, t0, t1")
        e("xor t0, t0, t2")
        e(f"sd t0, {8 * i}(a0)")
    for reg in ("ra", "s0", "s1"):
        e(f"ld {reg}, {SAVE[reg]}(sp)")
    e(f"addi sp, sp, {FRAME}")
    e("ret")
    e(f".size {name}, .-{name}")
    e(".section .rodata.vos_protocol_blake2b_iv,\"a\",@progbits")
    e(".p2align 3")
    e("vos_protocol_blake2b_iv:")
    for v in [0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
              0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179]:
        e(f".dword {hex(v)}")
    print("\n".join(asm))


main()
