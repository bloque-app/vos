addi sp, sp, -176
sd ra, 128(sp)
sd s0, 136(sp)
sd s1, 144(sp)
sd a0, 152(sp)
sd a2, 160(sp)
neg a3, a3
sd a3, 168(sp)
lla a5, 1f
ld ra, 0(a0)
sd ra, 0(sp)
ld t0, 8(a0)
sd t0, 8(sp)
ld t1, 16(a0)
sd t1, 16(sp)
ld t2, 24(a0)
sd t2, 24(sp)
ld ra, 32(a0)
sd ra, 32(sp)
ld t0, 40(a0)
sd t0, 40(sp)
ld t1, 48(a0)
sd t1, 48(sp)
ld t2, 56(a0)
sd t2, 56(sp)
ld ra, 0(a5)
sd ra, 64(sp)
ld t0, 8(a5)
sd t0, 72(sp)
ld t1, 16(a5)
sd t1, 80(sp)
ld t2, 24(a5)
sd t2, 88(sp)
ld ra, 32(a5)
xor ra, ra, a2
sd ra, 96(sp)
ld t0, 40(a5)
sd t0, 104(sp)
ld t1, 48(a5)
xor t1, t1, a3
sd t1, 112(sp)
ld t2, 56(a5)
sd t2, 120(sp)
ld ra, 0(sp)
ld t0, 32(sp)
ld t1, 64(sp)
ld t2, 96(sp)
ld a5, 0(a1)
add ra, ra, t0
add ra, ra, a5
xor t2, t2, ra
srli a5, t2, 32
slli t2, t2, 32
or t2, t2, a5
add t1, t1, t2
xor t0, t0, t1
srli a5, t0, 24
slli t0, t0, 40
or t0, t0, a5
ld a5, 8(a1)
add ra, ra, t0
add ra, ra, a5
xor t2, t2, ra
srli a5, t2, 16
slli t2, t2, 48
or t2, t2, a5
add t1, t1, t2
xor t0, t0, t1
srli a5, t0, 63
slli t0, t0, 1
or t0, t0, a5
ld s0, 8(sp)
ld s1, 40(sp)
ld a0, 72(sp)
ld a2, 104(sp)
ld a5, 16(a1)
add s0, s0, s1
add s0, s0, a5
xor a2, a2, s0
srli a5, a2, 32
slli a2, a2, 32
or a2, a2, a5
add a0, a0, a2
xor s1, s1, a0
srli a5, s1, 24
slli s1, s1, 40
or s1, s1, a5
ld a5, 24(a1)
add s0, s0, s1
add s0, s0, a5
xor a2, a2, s0
srli a5, a2, 16
slli a2, a2, 48
or a2, a2, a5
add a0, a0, a2
xor s1, s1, a0
srli a5, s1, 63
slli s1, s1, 1
or s1, s1, a5
ld a3, 16(sp)
ld a4, 48(sp)
sd t0, 32(sp)
ld t0, 80(sp)
sd a0, 72(sp)
ld a0, 112(sp)
ld a5, 32(a1)
add a3, a3, a4
add a3, a3, a5
xor a0, a0, a3
srli a5, a0, 32
slli a0, a0, 32
or a0, a0, a5
add t0, t0, a0
xor a4, a4, t0
srli a5, a4, 24
slli a4, a4, 40
or a4, a4, a5
ld a5, 40(a1)
add a3, a3, a4
add a3, a3, a5
xor a0, a0, a3
srli a5, a0, 16
slli a0, a0, 48
or a0, a0, a5
add t0, t0, a0
xor a4, a4, t0
srli a5, a4, 63
slli a4, a4, 1
or a4, a4, a5
sd a0, 112(sp)
ld a0, 24(sp)
sd t1, 64(sp)
ld t1, 56(sp)
sd a2, 104(sp)
ld a2, 88(sp)
sd a3, 16(sp)
ld a3, 120(sp)
ld a5, 48(a1)
add a0, a0, t1
add a0, a0, a5
xor a3, a3, a0
srli a5, a3, 32
slli a3, a3, 32
or a3, a3, a5
add a2, a2, a3
xor t1, t1, a2
srli a5, t1, 24
slli t1, t1, 40
or t1, t1, a5
ld a5, 56(a1)
add a0, a0, t1
add a0, a0, a5
xor a3, a3, a0
srli a5, a3, 16
slli a3, a3, 48
or a3, a3, a5
add a2, a2, a3
xor t1, t1, a2
srli a5, t1, 63
slli t1, t1, 1
or t1, t1, a5
ld a5, 64(a1)
add ra, ra, s1
add ra, ra, a5
xor a3, a3, ra
srli a5, a3, 32
slli a3, a3, 32
or a3, a3, a5
add t0, t0, a3
xor s1, s1, t0
srli a5, s1, 24
slli s1, s1, 40
or s1, s1, a5
ld a5, 72(a1)
add ra, ra, s1
add ra, ra, a5
xor a3, a3, ra
srli a5, a3, 16
slli a3, a3, 48
or a3, a3, a5
add t0, t0, a3
xor s1, s1, t0
srli a5, s1, 63
slli s1, s1, 1
or s1, s1, a5
ld a5, 80(a1)
add s0, s0, a4
add s0, s0, a5
xor t2, t2, s0
srli a5, t2, 32
slli t2, t2, 32
or t2, t2, a5
add a2, a2, t2
xor a4, a4, a2
srli a5, a4, 24
slli a4, a4, 40
or a4, a4, a5
ld a5, 88(a1)
add s0, s0, a4
add s0, s0, a5
xor t2, t2, s0
srli a5, t2, 16
slli t2, t2, 48
or t2, t2, a5
add a2, a2, t2
xor a4, a4, a2
srli a5, a4, 63
slli a4, a4, 1
or a4, a4, a5
sd a2, 88(sp)
ld a2, 16(sp)
sd a3, 120(sp)
ld a3, 64(sp)
sd a4, 48(sp)
ld a4, 104(sp)
ld a5, 96(a1)
add a2, a2, t1
add a2, a2, a5
xor a4, a4, a2
srli a5, a4, 32
slli a4, a4, 32
or a4, a4, a5
add a3, a3, a4
xor t1, t1, a3
srli a5, t1, 24
slli t1, t1, 40
or t1, t1, a5
ld a5, 104(a1)
add a2, a2, t1
add a2, a2, a5
xor a4, a4, a2
srli a5, a4, 16
slli a4, a4, 48
or a4, a4, a5
add a3, a3, a4
xor t1, t1, a3
srli a5, t1, 63
slli t1, t1, 1
or t1, t1, a5
sd t1, 56(sp)
ld t1, 32(sp)
sd t0, 80(sp)
ld t0, 72(sp)
sd a2, 16(sp)
ld a2, 112(sp)
ld a5, 112(a1)
add a0, a0, t1
add a0, a0, a5
xor a2, a2, a0
srli a5, a2, 32
slli a2, a2, 32
or a2, a2, a5
add t0, t0, a2
xor t1, t1, t0
srli a5, t1, 24
slli t1, t1, 40
or t1, t1, a5
ld a5, 120(a1)
add a0, a0, t1
add a0, a0, a5
xor a2, a2, a0
srli a5, a2, 16
slli a2, a2, 48
or a2, a2, a5
add t0, t0, a2
xor t1, t1, t0
srli a5, t1, 63
slli t1, t1, 1
or t1, t1, a5
ld a5, 112(a1)
add ra, ra, t1
add ra, ra, a5
xor t2, t2, ra
srli a5, t2, 32
slli t2, t2, 32
or t2, t2, a5
add a3, a3, t2
xor t1, t1, a3
srli a5, t1, 24
slli t1, t1, 40
or t1, t1, a5
ld a5, 80(a1)
add ra, ra, t1
add ra, ra, a5
xor t2, t2, ra
srli a5, t2, 16
slli t2, t2, 48
or t2, t2, a5
add a3, a3, t2
xor t1, t1, a3
srli a5, t1, 63
slli t1, t1, 1
or t1, t1, a5
ld a5, 32(a1)
add s0, s0, s1
add s0, s0, a5
xor a4, a4, s0
srli a5, a4, 32
slli a4, a4, 32
or a4, a4, a5
add t0, t0, a4
xor s1, s1, t0
srli a5, s1, 24
slli s1, s1, 40
or s1, s1, a5
ld a5, 64(a1)
add s0, s0, s1
add s0, s0, a5
xor a4, a4, s0
srli a5, a4, 16
slli a4, a4, 48
or a4, a4, a5
add t0, t0, a4
xor s1, s1, t0
srli a5, s1, 63
slli s1, s1, 1
or s1, s1, a5
sd t1, 32(sp)
ld t1, 16(sp)
sd t0, 72(sp)
ld t0, 48(sp)
sd a3, 64(sp)
ld a3, 80(sp)
ld a5, 72(a1)
add t1, t1, t0
add t1, t1, a5
xor a2, a2, t1
srli a5, a2, 32
slli a2, a2, 32
or a2, a2, a5
add a3, a3, a2
xor t0, t0, a3
srli a5, t0, 24
slli t0, t0, 40
or t0, t0, a5
ld a5, 120(a1)
add t1, t1, t0
add t1, t1, a5
xor a2, a2, t1
srli a5, a2, 16
slli a2, a2, 48
or a2, a2, a5
add a3, a3, a2
xor t0, t0, a3
srli a5, t0, 63
slli t0, t0, 1
or t0, t0, a5
sd a2, 112(sp)
ld a2, 56(sp)
sd a4, 104(sp)
ld a4, 88(sp)
sd t1, 16(sp)
ld t1, 120(sp)
ld a5, 104(a1)
add a0, a0, a2
add a0, a0, a5
xor t1, t1, a0
srli a5, t1, 32
slli t1, t1, 32
or t1, t1, a5
add a4, a4, t1
xor a2, a2, a4
srli a5, a2, 24
slli a2, a2, 40
or a2, a2, a5
ld a5, 48(a1)
add a0, a0, a2
add a0, a0, a5
xor t1, t1, a0
srli a5, t1, 16
slli t1, t1, 48
or t1, t1, a5
add a4, a4, t1
xor a2, a2, a4
srli a5, a2, 63
slli a2, a2, 1
or a2, a2, a5
ld a5, 8(a1)
add ra, ra, s1
add ra, ra, a5
xor t1, t1, ra
srli a5, t1, 32
slli t1, t1, 32
or t1, t1, a5
add a3, a3, t1
xor s1, s1, a3
srli a5, s1, 24
slli s1, s1, 40
or s1, s1, a5
ld a5, 96(a1)
add ra, ra, s1
add ra, ra, a5
xor t1, t1, ra
srli a5, t1, 16
slli t1, t1, 48
or t1, t1, a5
add a3, a3, t1
xor s1, s1, a3
srli a5, s1, 63
slli s1, s1, 1
or s1, s1, a5
ld a5, 0(a1)
add s0, s0, t0
add s0, s0, a5
xor t2, t2, s0
srli a5, t2, 32
slli t2, t2, 32
or t2, t2, a5
add a4, a4, t2
xor t0, t0, a4
srli a5, t0, 24
slli t0, t0, 40
or t0, t0, a5
ld a5, 16(a1)
add s0, s0, t0
add s0, s0, a5
xor t2, t2, s0
srli a5, t2, 16
slli t2, t2, 48
or t2, t2, a5
add a4, a4, t2
xor t0, t0, a4
srli a5, t0, 63
slli t0, t0, 1
or t0, t0, a5
sd a4, 88(sp)
ld a4, 16(sp)
sd t1, 120(sp)
ld t1, 64(sp)
sd t0, 48(sp)
ld t0, 104(sp)
ld a5, 88(a1)
add a4, a4, a2
add a4, a4, a5
xor t0, t0, a4
srli a5, t0, 32
slli t0, t0, 32
or t0, t0, a5
add t1, t1, t0
xor a2, a2, t1
srli a5, a2, 24
slli a2, a2, 40
or a2, a2, a5
ld a5, 56(a1)
add a4, a4, a2
add a4, a4, a5
xor t0, t0, a4
srli a5, t0, 16
slli t0, t0, 48
or t0, t0, a5
add t1, t1, t0
xor a2, a2, t1
srli a5, a2, 63
slli a2, a2, 1
or a2, a2, a5
sd a2, 56(sp)
ld a2, 32(sp)
sd a3, 80(sp)
ld a3, 72(sp)
sd a4, 16(sp)
ld a4, 112(sp)
ld a5, 40(a1)
add a0, a0, a2
add a0, a0, a5
xor a4, a4, a0
srli a5, a4, 32
slli a4, a4, 32
or a4, a4, a5
add a3, a3, a4
xor a2, a2, a3
srli a5, a2, 24
slli a2, a2, 40
or a2, a2, a5
ld a5, 24(a1)
add a0, a0, a2
add a0, a0, a5
xor a4, a4, a0
srli a5, a4, 16
slli a4, a4, 48
or a4, a4, a5
add a3, a3, a4
xor a2, a2, a3
srli a5, a2, 63
slli a2, a2, 1
or a2, a2, a5
ld a5, 88(a1)
add ra, ra, a2
add ra, ra, a5
xor t2, t2, ra
srli a5, t2, 32
slli t2, t2, 32
or t2, t2, a5
add t1, t1, t2
xor a2, a2, t1
srli a5, a2, 24
slli a2, a2, 40
or a2, a2, a5
ld a5, 64(a1)
add ra, ra, a2
add ra, ra, a5
xor t2, t2, ra
srli a5, t2, 16
slli t2, t2, 48
or t2, t2, a5
add t1, t1, t2
xor a2, a2, t1
srli a5, a2, 63
slli a2, a2, 1
or a2, a2, a5
ld a5, 96(a1)
add s0, s0, s1
add s0, s0, a5
xor t0, t0, s0
srli a5, t0, 32
slli t0, t0, 32
or t0, t0, a5
add a3, a3, t0
xor s1, s1, a3
srli a5, s1, 24
slli s1, s1, 40
or s1, s1, a5
ld a5, 0(a1)
add s0, s0, s1
add s0, s0, a5
xor t0, t0, s0
srli a5, t0, 16
slli t0, t0, 48
or t0, t0, a5
add a3, a3, t0
xor s1, s1, a3
srli a5, s1, 63
slli s1, s1, 1
or s1, s1, a5
sd a2, 32(sp)
ld a2, 16(sp)
sd a3, 72(sp)
ld a3, 48(sp)
sd t1, 64(sp)
ld t1, 80(sp)
ld a5, 40(a1)
add a2, a2, a3
add a2, a2, a5
xor a4, a4, a2
srli a5, a4, 32
slli a4, a4, 32
or a4, a4, a5
add t1, t1, a4
xor a3, a3, t1
srli a5, a3, 24
slli a3, a3, 40
or a3, a3, a5
ld a5, 16(a1)
add a2, a2, a3
add a2, a2, a5
xor a4, a4, a2
srli a5, a4, 16
slli a4, a4, 48
or a4, a4, a5
add t1, t1, a4
xor a3, a3, t1
srli a5, a3, 63
slli a3, a3, 1
or a3, a3, a5
sd a4, 112(sp)
ld a4, 56(sp)
sd t0, 104(sp)
ld t0, 88(sp)
sd a2, 16(sp)
ld a2, 120(sp)
ld a5, 120(a1)
add a0, a0, a4
add a0, a0, a5
xor a2, a2, a0
srli a5, a2, 32
slli a2, a2, 32
or a2, a2, a5
add t0, t0, a2
xor a4, a4, t0
srli a5, a4, 24
slli a4, a4, 40
or a4, a4, a5
ld a5, 104(a1)
add a0, a0, a4
add a0, a0, a5
xor a2, a2, a0
srli a5, a2, 16
slli a2, a2, 48
or a2, a2, a5
add t0, t0, a2
xor a4, a4, t0
srli a5, a4, 63
slli a4, a4, 1
or a4, a4, a5
ld a5, 80(a1)
add ra, ra, s1
add ra, ra, a5
xor a2, a2, ra
srli a5, a2, 32
slli a2, a2, 32
or a2, a2, a5
add t1, t1, a2
xor s1, s1, t1
srli a5, s1, 24
slli s1, s1, 40
or s1, s1, a5
ld a5, 112(a1)
add ra, ra, s1
add ra, ra, a5
xor a2, a2, ra
srli a5, a2, 16
slli a2, a2, 48
or a2, a2, a5
add t1, t1, a2
xor s1, s1, t1
srli a5, s1, 63
slli s1, s1, 1
or s1, s1, a5
ld a5, 24(a1)
add s0, s0, a3
add s0, s0, a5
xor t2, t2, s0
srli a5, t2, 32
slli t2, t2, 32
or t2, t2, a5
add t0, t0, t2
xor a3, a3, t0
srli a5, a3, 24
slli a3, a3, 40
or a3, a3, a5
ld a5, 48(a1)
add s0, s0, a3
add s0, s0, a5
xor t2, t2, s0
srli a5, t2, 16
slli t2, t2, 48
or t2, t2, a5
add t0, t0, t2
xor a3, a3, t0
srli a5, a3, 63
slli a3, a3, 1
or a3, a3, a5
sd t0, 88(sp)
ld t0, 16(sp)
sd a2, 120(sp)
ld a2, 64(sp)
sd a3, 48(sp)
ld a3, 104(sp)
ld a5, 56(a1)
add t0, t0, a4
add t0, t0, a5
xor a3, a3, t0
srli a5, a3, 32
slli a3, a3, 32
or a3, a3, a5
add a2, a2, a3
xor a4, a4, a2
srli a5, a4, 24
slli a4, a4, 40
or a4, a4, a5
ld a5, 8(a1)
add t0, t0, a4
add t0, t0, a5
xor a3, a3, t0
srli a5, a3, 16
slli a3, a3, 48
or a3, a3, a5
add a2, a2, a3
xor a4, a4, a2
srli a5, a4, 63
slli a4, a4, 1
or a4, a4, a5
sd a4, 56(sp)
ld a4, 32(sp)
sd t1, 80(sp)
ld t1, 72(sp)
sd t0, 16(sp)
ld t0, 112(sp)
ld a5, 72(a1)
add a0, a0, a4
add a0, a0, a5
xor t0, t0, a0
srli a5, t0, 32
slli t0, t0, 32
or t0, t0, a5
add t1, t1, t0
xor a4, a4, t1
srli a5, a4, 24
slli a4, a4, 40
or a4, a4, a5
ld a5, 32(a1)
add a0, a0, a4
add a0, a0, a5
xor t0, t0, a0
srli a5, t0, 16
slli t0, t0, 48
or t0, t0, a5
add t1, t1, t0
xor a4, a4, t1
srli a5, a4, 63
slli a4, a4, 1
or a4, a4, a5
ld a5, 56(a1)
add ra, ra, a4
add ra, ra, a5
xor t2, t2, ra
srli a5, t2, 32
slli t2, t2, 32
or t2, t2, a5
add a2, a2, t2
xor a4, a4, a2
srli a5, a4, 24
slli a4, a4, 40
or a4, a4, a5
ld a5, 72(a1)
add ra, ra, a4
add ra, ra, a5
xor t2, t2, ra
srli a5, t2, 16
slli t2, t2, 48
or t2, t2, a5
add a2, a2, t2
xor a4, a4, a2
srli a5, a4, 63
slli a4, a4, 1
or a4, a4, a5
ld a5, 24(a1)
add s0, s0, s1
add s0, s0, a5
xor a3, a3, s0
srli a5, a3, 32
slli a3, a3, 32
or a3, a3, a5
add t1, t1, a3
xor s1, s1, t1
srli a5, s1, 24
slli s1, s1, 40
or s1, s1, a5
ld a5, 8(a1)
add s0, s0, s1
add s0, s0, a5
xor a3, a3, s0
srli a5, a3, 16
slli a3, a3, 48
or a3, a3, a5
add t1, t1, a3
xor s1, s1, t1
srli a5, s1, 63
slli s1, s1, 1
or s1, s1, a5
sd a4, 32(sp)
ld a4, 16(sp)
sd t1, 72(sp)
ld t1, 48(sp)
sd a2, 64(sp)
ld a2, 80(sp)
ld a5, 104(a1)
add a4, a4, t1
add a4, a4, a5
xor t0, t0, a4
srli a5, t0, 32
slli t0, t0, 32
or t0, t0, a5
add a2, a2, t0
xor t1, t1, a2
srli a5, t1, 24
slli t1, t1, 40
or t1, t1, a5
ld a5, 96(a1)
add a4, a4, t1
add a4, a4, a5
xor t0, t0, a4
srli a5, t0, 16
slli t0, t0, 48
or t0, t0, a5
add a2, a2, t0
xor t1, t1, a2
srli a5, t1, 63
slli t1, t1, 1
or t1, t1, a5
sd t0, 112(sp)
ld t0, 56(sp)
sd a3, 104(sp)
ld a3, 88(sp)
sd a4, 16(sp)
ld a4, 120(sp)
ld a5, 88(a1)
add a0, a0, t0
add a0, a0, a5
xor a4, a4, a0
srli a5, a4, 32
slli a4, a4, 32
or a4, a4, a5
add a3, a3, a4
xor t0, t0, a3
srli a5, t0, 24
slli t0, t0, 40
or t0, t0, a5
ld a5, 112(a1)
add a0, a0, t0
add a0, a0, a5
xor a4, a4, a0
srli a5, a4, 16
slli a4, a4, 48
or a4, a4, a5
add a3, a3, a4
xor t0, t0, a3
srli a5, t0, 63
slli t0, t0, 1
or t0, t0, a5
ld a5, 16(a1)
add ra, ra, s1
add ra, ra, a5
xor a4, a4, ra
srli a5, a4, 32
slli a4, a4, 32
or a4, a4, a5
add a2, a2, a4
xor s1, s1, a2
srli a5, s1, 24
slli s1, s1, 40
or s1, s1, a5
ld a5, 48(a1)
add ra, ra, s1
add ra, ra, a5
xor a4, a4, ra
srli a5, a4, 16
slli a4, a4, 48
or a4, a4, a5
add a2, a2, a4
xor s1, s1, a2
srli a5, s1, 63
slli s1, s1, 1
or s1, s1, a5
ld a5, 40(a1)
add s0, s0, t1
add s0, s0, a5
xor t2, t2, s0
srli a5, t2, 32
slli t2, t2, 32
or t2, t2, a5
add a3, a3, t2
xor t1, t1, a3
srli a5, t1, 24
slli t1, t1, 40
or t1, t1, a5
ld a5, 80(a1)
add s0, s0, t1
add s0, s0, a5
xor t2, t2, s0
srli a5, t2, 16
slli t2, t2, 48
or t2, t2, a5
add a3, a3, t2
xor t1, t1, a3
srli a5, t1, 63
slli t1, t1, 1
or t1, t1, a5
sd a3, 88(sp)
ld a3, 16(sp)
sd a4, 120(sp)
ld a4, 64(sp)
sd t1, 48(sp)
ld t1, 104(sp)
ld a5, 32(a1)
add a3, a3, t0
add a3, a3, a5
xor t1, t1, a3
srli a5, t1, 32
slli t1, t1, 32
or t1, t1, a5
add a4, a4, t1
xor t0, t0, a4
srli a5, t0, 24
slli t0, t0, 40
or t0, t0, a5
ld a5, 0(a1)
add a3, a3, t0
add a3, a3, a5
xor t1, t1, a3
srli a5, t1, 16
slli t1, t1, 48
or t1, t1, a5
add a4, a4, t1
xor t0, t0, a4
srli a5, t0, 63
slli t0, t0, 1
or t0, t0, a5
sd t0, 56(sp)
ld t0, 32(sp)
sd a2, 80(sp)
ld a2, 72(sp)
sd a3, 16(sp)
ld a3, 112(sp)
ld a5, 120(a1)
add a0, a0, t0
add a0, a0, a5
xor a3, a3, a0
srli a5, a3, 32
slli a3, a3, 32
or a3, a3, a5
add a2, a2, a3
xor t0, t0, a2
srli a5, t0, 24
slli t0, t0, 40
or t0, t0, a5
ld a5, 64(a1)
add a0, a0, t0
add a0, a0, a5
xor a3, a3, a0
srli a5, a3, 16
slli a3, a3, 48
or a3, a3, a5
add a2, a2, a3
xor t0, t0, a2
srli a5, t0, 63
slli t0, t0, 1
or t0, t0, a5
ld a5, 72(a1)
add ra, ra, t0
add ra, ra, a5
xor t2, t2, ra
srli a5, t2, 32
slli t2, t2, 32
or t2, t2, a5
add a4, a4, t2
xor t0, t0, a4
srli a5, t0, 24
slli t0, t0, 40
or t0, t0, a5
ld a5, 0(a1)
add ra, ra, t0
add ra, ra, a5
xor t2, t2, ra
srli a5, t2, 16
slli t2, t2, 48
or t2, t2, a5
add a4, a4, t2
xor t0, t0, a4
srli a5, t0, 63
slli t0, t0, 1
or t0, t0, a5
ld a5, 40(a1)
add s0, s0, s1
add s0, s0, a5
xor t1, t1, s0
srli a5, t1, 32
slli t1, t1, 32
or t1, t1, a5
add a2, a2, t1
xor s1, s1, a2
srli a5, s1, 24
slli s1, s1, 40
or s1, s1, a5
ld a5, 56(a1)
add s0, s0, s1
add s0, s0, a5
xor t1, t1, s0
srli a5, t1, 16
slli t1, t1, 48
or t1, t1, a5
add a2, a2, t1
xor s1, s1, a2
srli a5, s1, 63
slli s1, s1, 1
or s1, s1, a5
sd t0, 32(sp)
ld t0, 16(sp)
sd a2, 72(sp)
ld a2, 48(sp)
sd a4, 64(sp)
ld a4, 80(sp)
ld a5, 16(a1)
add t0, t0, a2
add t0, t0, a5
xor a3, a3, t0
srli a5, a3, 32
slli a3, a3, 32
or a3, a3, a5
add a4, a4, a3
xor a2, a2, a4
srli a5, a2, 24
slli a2, a2, 40
or a2, a2, a5
ld a5, 32(a1)
add t0, t0, a2
add t0, t0, a5
xor a3, a3, t0
srli a5, a3, 16
slli a3, a3, 48
or a3, a3, a5
add a4, a4, a3
xor a2, a2, a4
srli a5, a2, 63
slli a2, a2, 1
or a2, a2, a5
sd a3, 112(sp)
ld a3, 56(sp)
sd t1, 104(sp)
ld t1, 88(sp)
sd t0, 16(sp)
ld t0, 120(sp)
ld a5, 80(a1)
add a0, a0, a3
add a0, a0, a5
xor t0, t0, a0
srli a5, t0, 32
slli t0, t0, 32
or t0, t0, a5
add t1, t1, t0
xor a3, a3, t1
srli a5, a3, 24
slli a3, a3, 40
or a3, a3, a5
ld a5, 120(a1)
add a0, a0, a3
add a0, a0, a5
xor t0, t0, a0
srli a5, t0, 16
slli t0, t0, 48
or t0, t0, a5
add t1, t1, t0
xor a3, a3, t1
srli a5, a3, 63
slli a3, a3, 1
or a3, a3, a5
ld a5, 112(a1)
add ra, ra, s1
add ra, ra, a5
xor t0, t0, ra
srli a5, t0, 32
slli t0, t0, 32
or t0, t0, a5
add a4, a4, t0
xor s1, s1, a4
srli a5, s1, 24
slli s1, s1, 40
or s1, s1, a5
ld a5, 8(a1)
add ra, ra, s1
add ra, ra, a5
xor t0, t0, ra
srli a5, t0, 16
slli t0, t0, 48
or t0, t0, a5
add a4, a4, t0
xor s1, s1, a4
srli a5, s1, 63
slli s1, s1, 1
or s1, s1, a5
ld a5, 88(a1)
add s0, s0, a2
add s0, s0, a5
xor t2, t2, s0
srli a5, t2, 32
slli t2, t2, 32
or t2, t2, a5
add t1, t1, t2
xor a2, a2, t1
srli a5, a2, 24
slli a2, a2, 40
or a2, a2, a5
ld a5, 96(a1)
add s0, s0, a2
add s0, s0, a5
xor t2, t2, s0
srli a5, t2, 16
slli t2, t2, 48
or t2, t2, a5
add t1, t1, t2
xor a2, a2, t1
srli a5, a2, 63
slli a2, a2, 1
or a2, a2, a5
sd t1, 88(sp)
ld t1, 16(sp)
sd t0, 120(sp)
ld t0, 64(sp)
sd a2, 48(sp)
ld a2, 104(sp)
ld a5, 48(a1)
add t1, t1, a3
add t1, t1, a5
xor a2, a2, t1
srli a5, a2, 32
slli a2, a2, 32
or a2, a2, a5
add t0, t0, a2
xor a3, a3, t0
srli a5, a3, 24
slli a3, a3, 40
or a3, a3, a5
ld a5, 64(a1)
add t1, t1, a3
add t1, t1, a5
xor a2, a2, t1
srli a5, a2, 16
slli a2, a2, 48
or a2, a2, a5
add t0, t0, a2
xor a3, a3, t0
srli a5, a3, 63
slli a3, a3, 1
or a3, a3, a5
sd a3, 56(sp)
ld a3, 32(sp)
sd a4, 80(sp)
ld a4, 72(sp)
sd t1, 16(sp)
ld t1, 112(sp)
ld a5, 24(a1)
add a0, a0, a3
add a0, a0, a5
xor t1, t1, a0
srli a5, t1, 32
slli t1, t1, 32
or t1, t1, a5
add a4, a4, t1
xor a3, a3, a4
srli a5, a3, 24
slli a3, a3, 40
or a3, a3, a5
ld a5, 104(a1)
add a0, a0, a3
add a0, a0, a5
xor t1, t1, a0
srli a5, t1, 16
slli t1, t1, 48
or t1, t1, a5
add a4, a4, t1
xor a3, a3, a4
srli a5, a3, 63
slli a3, a3, 1
or a3, a3, a5
ld a5, 16(a1)
add ra, ra, a3
add ra, ra, a5
xor t2, t2, ra
srli a5, t2, 32
slli t2, t2, 32
or t2, t2, a5
add t0, t0, t2
xor a3, a3, t0
srli a5, a3, 24
slli a3, a3, 40
or a3, a3, a5
ld a5, 96(a1)
add ra, ra, a3
add ra, ra, a5
xor t2, t2, ra
srli a5, t2, 16
slli t2, t2, 48
or t2, t2, a5
add t0, t0, t2
xor a3, a3, t0
srli a5, a3, 63
slli a3, a3, 1
or a3, a3, a5
ld a5, 48(a1)
add s0, s0, s1
add s0, s0, a5
xor a2, a2, s0
srli a5, a2, 32
slli a2, a2, 32
or a2, a2, a5
add a4, a4, a2
xor s1, s1, a4
srli a5, s1, 24
slli s1, s1, 40
or s1, s1, a5
ld a5, 80(a1)
add s0, s0, s1
add s0, s0, a5
xor a2, a2, s0
srli a5, a2, 16
slli a2, a2, 48
or a2, a2, a5
add a4, a4, a2
xor s1, s1, a4
srli a5, s1, 63
slli s1, s1, 1
or s1, s1, a5
sd a3, 32(sp)
ld a3, 16(sp)
sd a4, 72(sp)
ld a4, 48(sp)
sd t0, 64(sp)
ld t0, 80(sp)
ld a5, 0(a1)
add a3, a3, a4
add a3, a3, a5
xor t1, t1, a3
srli a5, t1, 32
slli t1, t1, 32
or t1, t1, a5
add t0, t0, t1
xor a4, a4, t0
srli a5, a4, 24
slli a4, a4, 40
or a4, a4, a5
ld a5, 88(a1)
add a3, a3, a4
add a3, a3, a5
xor t1, t1, a3
srli a5, t1, 16
slli t1, t1, 48
or t1, t1, a5
add t0, t0, t1
xor a4, a4, t0
srli a5, a4, 63
slli a4, a4, 1
or a4, a4, a5
sd t1, 112(sp)
ld t1, 56(sp)
sd a2, 104(sp)
ld a2, 88(sp)
sd a3, 16(sp)
ld a3, 120(sp)
ld a5, 64(a1)
add a0, a0, t1
add a0, a0, a5
xor a3, a3, a0
srli a5, a3, 32
slli a3, a3, 32
or a3, a3, a5
add a2, a2, a3
xor t1, t1, a2
srli a5, t1, 24
slli t1, t1, 40
or t1, t1, a5
ld a5, 24(a1)
add a0, a0, t1
add a0, a0, a5
xor a3, a3, a0
srli a5, a3, 16
slli a3, a3, 48
or a3, a3, a5
add a2, a2, a3
xor t1, t1, a2
srli a5, t1, 63
slli t1, t1, 1
or t1, t1, a5
ld a5, 32(a1)
add ra, ra, s1
add ra, ra, a5
xor a3, a3, ra
srli a5, a3, 32
slli a3, a3, 32
or a3, a3, a5
add t0, t0, a3
xor s1, s1, t0
srli a5, s1, 24
slli s1, s1, 40
or s1, s1, a5
ld a5, 104(a1)
add ra, ra, s1
add ra, ra, a5
xor a3, a3, ra
srli a5, a3, 16
slli a3, a3, 48
or a3, a3, a5
add t0, t0, a3
xor s1, s1, t0
srli a5, s1, 63
slli s1, s1, 1
or s1, s1, a5
ld a5, 56(a1)
add s0, s0, a4
add s0, s0, a5
xor t2, t2, s0
srli a5, t2, 32
slli t2, t2, 32
or t2, t2, a5
add a2, a2, t2
xor a4, a4, a2
srli a5, a4, 24
slli a4, a4, 40
or a4, a4, a5
ld a5, 40(a1)
add s0, s0, a4
add s0, s0, a5
xor t2, t2, s0
srli a5, t2, 16
slli t2, t2, 48
or t2, t2, a5
add a2, a2, t2
xor a4, a4, a2
srli a5, a4, 63
slli a4, a4, 1
or a4, a4, a5
sd a2, 88(sp)
ld a2, 16(sp)
sd a3, 120(sp)
ld a3, 64(sp)
sd a4, 48(sp)
ld a4, 104(sp)
ld a5, 120(a1)
add a2, a2, t1
add a2, a2, a5
xor a4, a4, a2
srli a5, a4, 32
slli a4, a4, 32
or a4, a4, a5
add a3, a3, a4
xor t1, t1, a3
srli a5, t1, 24
slli t1, t1, 40
or t1, t1, a5
ld a5, 112(a1)
add a2, a2, t1
add a2, a2, a5
xor a4, a4, a2
srli a5, a4, 16
slli a4, a4, 48
or a4, a4, a5
add a3, a3, a4
xor t1, t1, a3
srli a5, t1, 63
slli t1, t1, 1
or t1, t1, a5
sd t1, 56(sp)
ld t1, 32(sp)
sd t0, 80(sp)
ld t0, 72(sp)
sd a2, 16(sp)
ld a2, 112(sp)
ld a5, 8(a1)
add a0, a0, t1
add a0, a0, a5
xor a2, a2, a0
srli a5, a2, 32
slli a2, a2, 32
or a2, a2, a5
add t0, t0, a2
xor t1, t1, t0
srli a5, t1, 24
slli t1, t1, 40
or t1, t1, a5
ld a5, 72(a1)
add a0, a0, t1
add a0, a0, a5
xor a2, a2, a0
srli a5, a2, 16
slli a2, a2, 48
or a2, a2, a5
add t0, t0, a2
xor t1, t1, t0
srli a5, t1, 63
slli t1, t1, 1
or t1, t1, a5
ld a5, 96(a1)
add ra, ra, t1
add ra, ra, a5
xor t2, t2, ra
srli a5, t2, 32
slli t2, t2, 32
or t2, t2, a5
add a3, a3, t2
xor t1, t1, a3
srli a5, t1, 24
slli t1, t1, 40
or t1, t1, a5
ld a5, 40(a1)
add ra, ra, t1
add ra, ra, a5
xor t2, t2, ra
srli a5, t2, 16
slli t2, t2, 48
or t2, t2, a5
add a3, a3, t2
xor t1, t1, a3
srli a5, t1, 63
slli t1, t1, 1
or t1, t1, a5
ld a5, 8(a1)
add s0, s0, s1
add s0, s0, a5
xor a4, a4, s0
srli a5, a4, 32
slli a4, a4, 32
or a4, a4, a5
add t0, t0, a4
xor s1, s1, t0
srli a5, s1, 24
slli s1, s1, 40
or s1, s1, a5
ld a5, 120(a1)
add s0, s0, s1
add s0, s0, a5
xor a4, a4, s0
srli a5, a4, 16
slli a4, a4, 48
or a4, a4, a5
add t0, t0, a4
xor s1, s1, t0
srli a5, s1, 63
slli s1, s1, 1
or s1, s1, a5
sd t1, 32(sp)
ld t1, 16(sp)
sd t0, 72(sp)
ld t0, 48(sp)
sd a3, 64(sp)
ld a3, 80(sp)
ld a5, 112(a1)
add t1, t1, t0
add t1, t1, a5
xor a2, a2, t1
srli a5, a2, 32
slli a2, a2, 32
or a2, a2, a5
add a3, a3, a2
xor t0, t0, a3
srli a5, t0, 24
slli t0, t0, 40
or t0, t0, a5
ld a5, 104(a1)
add t1, t1, t0
add t1, t1, a5
xor a2, a2, t1
srli a5, a2, 16
slli a2, a2, 48
or a2, a2, a5
add a3, a3, a2
xor t0, t0, a3
srli a5, t0, 63
slli t0, t0, 1
or t0, t0, a5
sd a2, 112(sp)
ld a2, 56(sp)
sd a4, 104(sp)
ld a4, 88(sp)
sd t1, 16(sp)
ld t1, 120(sp)
ld a5, 32(a1)
add a0, a0, a2
add a0, a0, a5
xor t1, t1, a0
srli a5, t1, 32
slli t1, t1, 32
or t1, t1, a5
add a4, a4, t1
xor a2, a2, a4
srli a5, a2, 24
slli a2, a2, 40
or a2, a2, a5
ld a5, 80(a1)
add a0, a0, a2
add a0, a0, a5
xor t1, t1, a0
srli a5, t1, 16
slli t1, t1, 48
or t1, t1, a5
add a4, a4, t1
xor a2, a2, a4
srli a5, a2, 63
slli a2, a2, 1
or a2, a2, a5
ld a5, 0(a1)
add ra, ra, s1
add ra, ra, a5
xor t1, t1, ra
srli a5, t1, 32
slli t1, t1, 32
or t1, t1, a5
add a3, a3, t1
xor s1, s1, a3
srli a5, s1, 24
slli s1, s1, 40
or s1, s1, a5
ld a5, 56(a1)
add ra, ra, s1
add ra, ra, a5
xor t1, t1, ra
srli a5, t1, 16
slli t1, t1, 48
or t1, t1, a5
add a3, a3, t1
xor s1, s1, a3
srli a5, s1, 63
slli s1, s1, 1
or s1, s1, a5
ld a5, 48(a1)
add s0, s0, t0
add s0, s0, a5
xor t2, t2, s0
srli a5, t2, 32
slli t2, t2, 32
or t2, t2, a5
add a4, a4, t2
xor t0, t0, a4
srli a5, t0, 24
slli t0, t0, 40
or t0, t0, a5
ld a5, 24(a1)
add s0, s0, t0
add s0, s0, a5
xor t2, t2, s0
srli a5, t2, 16
slli t2, t2, 48
or t2, t2, a5
add a4, a4, t2
xor t0, t0, a4
srli a5, t0, 63
slli t0, t0, 1
or t0, t0, a5
sd a4, 88(sp)
ld a4, 16(sp)
sd t1, 120(sp)
ld t1, 64(sp)
sd t0, 48(sp)
ld t0, 104(sp)
ld a5, 72(a1)
add a4, a4, a2
add a4, a4, a5
xor t0, t0, a4
srli a5, t0, 32
slli t0, t0, 32
or t0, t0, a5
add t1, t1, t0
xor a2, a2, t1
srli a5, a2, 24
slli a2, a2, 40
or a2, a2, a5
ld a5, 16(a1)
add a4, a4, a2
add a4, a4, a5
xor t0, t0, a4
srli a5, t0, 16
slli t0, t0, 48
or t0, t0, a5
add t1, t1, t0
xor a2, a2, t1
srli a5, a2, 63
slli a2, a2, 1
or a2, a2, a5
sd a2, 56(sp)
ld a2, 32(sp)
sd a3, 80(sp)
ld a3, 72(sp)
sd a4, 16(sp)
ld a4, 112(sp)
ld a5, 64(a1)
add a0, a0, a2
add a0, a0, a5
xor a4, a4, a0
srli a5, a4, 32
slli a4, a4, 32
or a4, a4, a5
add a3, a3, a4
xor a2, a2, a3
srli a5, a2, 24
slli a2, a2, 40
or a2, a2, a5
ld a5, 88(a1)
add a0, a0, a2
add a0, a0, a5
xor a4, a4, a0
srli a5, a4, 16
slli a4, a4, 48
or a4, a4, a5
add a3, a3, a4
xor a2, a2, a3
srli a5, a2, 63
slli a2, a2, 1
or a2, a2, a5
ld a5, 104(a1)
add ra, ra, a2
add ra, ra, a5
xor t2, t2, ra
srli a5, t2, 32
slli t2, t2, 32
or t2, t2, a5
add t1, t1, t2
xor a2, a2, t1
srli a5, a2, 24
slli a2, a2, 40
or a2, a2, a5
ld a5, 88(a1)
add ra, ra, a2
add ra, ra, a5
xor t2, t2, ra
srli a5, t2, 16
slli t2, t2, 48
or t2, t2, a5
add t1, t1, t2
xor a2, a2, t1
srli a5, a2, 63
slli a2, a2, 1
or a2, a2, a5
ld a5, 56(a1)
add s0, s0, s1
add s0, s0, a5
xor t0, t0, s0
srli a5, t0, 32
slli t0, t0, 32
or t0, t0, a5
add a3, a3, t0
xor s1, s1, a3
srli a5, s1, 24
slli s1, s1, 40
or s1, s1, a5
ld a5, 112(a1)
add s0, s0, s1
add s0, s0, a5
xor t0, t0, s0
srli a5, t0, 16
slli t0, t0, 48
or t0, t0, a5
add a3, a3, t0
xor s1, s1, a3
srli a5, s1, 63
slli s1, s1, 1
or s1, s1, a5
sd a2, 32(sp)
ld a2, 16(sp)
sd a3, 72(sp)
ld a3, 48(sp)
sd t1, 64(sp)
ld t1, 80(sp)
ld a5, 96(a1)
add a2, a2, a3
add a2, a2, a5
xor a4, a4, a2
srli a5, a4, 32
slli a4, a4, 32
or a4, a4, a5
add t1, t1, a4
xor a3, a3, t1
srli a5, a3, 24
slli a3, a3, 40
or a3, a3, a5
ld a5, 8(a1)
add a2, a2, a3
add a2, a2, a5
xor a4, a4, a2
srli a5, a4, 16
slli a4, a4, 48
or a4, a4, a5
add t1, t1, a4
xor a3, a3, t1
srli a5, a3, 63
slli a3, a3, 1
or a3, a3, a5
sd a4, 112(sp)
ld a4, 56(sp)
sd t0, 104(sp)
ld t0, 88(sp)
sd a2, 16(sp)
ld a2, 120(sp)
ld a5, 24(a1)
add a0, a0, a4
add a0, a0, a5
xor a2, a2, a0
srli a5, a2, 32
slli a2, a2, 32
or a2, a2, a5
add t0, t0, a2
xor a4, a4, t0
srli a5, a4, 24
slli a4, a4, 40
or a4, a4, a5
ld a5, 72(a1)
add a0, a0, a4
add a0, a0, a5
xor a2, a2, a0
srli a5, a2, 16
slli a2, a2, 48
or a2, a2, a5
add t0, t0, a2
xor a4, a4, t0
srli a5, a4, 63
slli a4, a4, 1
or a4, a4, a5
ld a5, 40(a1)
add ra, ra, s1
add ra, ra, a5
xor a2, a2, ra
srli a5, a2, 32
slli a2, a2, 32
or a2, a2, a5
add t1, t1, a2
xor s1, s1, t1
srli a5, s1, 24
slli s1, s1, 40
or s1, s1, a5
ld a5, 0(a1)
add ra, ra, s1
add ra, ra, a5
xor a2, a2, ra
srli a5, a2, 16
slli a2, a2, 48
or a2, a2, a5
add t1, t1, a2
xor s1, s1, t1
srli a5, s1, 63
slli s1, s1, 1
or s1, s1, a5
ld a5, 120(a1)
add s0, s0, a3
add s0, s0, a5
xor t2, t2, s0
srli a5, t2, 32
slli t2, t2, 32
or t2, t2, a5
add t0, t0, t2
xor a3, a3, t0
srli a5, a3, 24
slli a3, a3, 40
or a3, a3, a5
ld a5, 32(a1)
add s0, s0, a3
add s0, s0, a5
xor t2, t2, s0
srli a5, t2, 16
slli t2, t2, 48
or t2, t2, a5
add t0, t0, t2
xor a3, a3, t0
srli a5, a3, 63
slli a3, a3, 1
or a3, a3, a5
sd t0, 88(sp)
ld t0, 16(sp)
sd a2, 120(sp)
ld a2, 64(sp)
sd a3, 48(sp)
ld a3, 104(sp)
ld a5, 64(a1)
add t0, t0, a4
add t0, t0, a5
xor a3, a3, t0
srli a5, a3, 32
slli a3, a3, 32
or a3, a3, a5
add a2, a2, a3
xor a4, a4, a2
srli a5, a4, 24
slli a4, a4, 40
or a4, a4, a5
ld a5, 48(a1)
add t0, t0, a4
add t0, t0, a5
xor a3, a3, t0
srli a5, a3, 16
slli a3, a3, 48
or a3, a3, a5
add a2, a2, a3
xor a4, a4, a2
srli a5, a4, 63
slli a4, a4, 1
or a4, a4, a5
sd a4, 56(sp)
ld a4, 32(sp)
sd t1, 80(sp)
ld t1, 72(sp)
sd t0, 16(sp)
ld t0, 112(sp)
ld a5, 16(a1)
add a0, a0, a4
add a0, a0, a5
xor t0, t0, a0
srli a5, t0, 32
slli t0, t0, 32
or t0, t0, a5
add t1, t1, t0
xor a4, a4, t1
srli a5, a4, 24
slli a4, a4, 40
or a4, a4, a5
ld a5, 80(a1)
add a0, a0, a4
add a0, a0, a5
xor t0, t0, a0
srli a5, t0, 16
slli t0, t0, 48
or t0, t0, a5
add t1, t1, t0
xor a4, a4, t1
srli a5, a4, 63
slli a4, a4, 1
or a4, a4, a5
ld a5, 48(a1)
add ra, ra, a4
add ra, ra, a5
xor t2, t2, ra
srli a5, t2, 32
slli t2, t2, 32
or t2, t2, a5
add a2, a2, t2
xor a4, a4, a2
srli a5, a4, 24
slli a4, a4, 40
or a4, a4, a5
ld a5, 120(a1)
add ra, ra, a4
add ra, ra, a5
xor t2, t2, ra
srli a5, t2, 16
slli t2, t2, 48
or t2, t2, a5
add a2, a2, t2
xor a4, a4, a2
srli a5, a4, 63
slli a4, a4, 1
or a4, a4, a5
ld a5, 112(a1)
add s0, s0, s1
add s0, s0, a5
xor a3, a3, s0
srli a5, a3, 32
slli a3, a3, 32
or a3, a3, a5
add t1, t1, a3
xor s1, s1, t1
srli a5, s1, 24
slli s1, s1, 40
or s1, s1, a5
ld a5, 72(a1)
add s0, s0, s1
add s0, s0, a5
xor a3, a3, s0
srli a5, a3, 16
slli a3, a3, 48
or a3, a3, a5
add t1, t1, a3
xor s1, s1, t1
srli a5, s1, 63
slli s1, s1, 1
or s1, s1, a5
sd a4, 32(sp)
ld a4, 16(sp)
sd t1, 72(sp)
ld t1, 48(sp)
sd a2, 64(sp)
ld a2, 80(sp)
ld a5, 88(a1)
add a4, a4, t1
add a4, a4, a5
xor t0, t0, a4
srli a5, t0, 32
slli t0, t0, 32
or t0, t0, a5
add a2, a2, t0
xor t1, t1, a2
srli a5, t1, 24
slli t1, t1, 40
or t1, t1, a5
ld a5, 24(a1)
add a4, a4, t1
add a4, a4, a5
xor t0, t0, a4
srli a5, t0, 16
slli t0, t0, 48
or t0, t0, a5
add a2, a2, t0
xor t1, t1, a2
srli a5, t1, 63
slli t1, t1, 1
or t1, t1, a5
sd t0, 112(sp)
ld t0, 56(sp)
sd a3, 104(sp)
ld a3, 88(sp)
sd a4, 16(sp)
ld a4, 120(sp)
ld a5, 0(a1)
add a0, a0, t0
add a0, a0, a5
xor a4, a4, a0
srli a5, a4, 32
slli a4, a4, 32
or a4, a4, a5
add a3, a3, a4
xor t0, t0, a3
srli a5, t0, 24
slli t0, t0, 40
or t0, t0, a5
ld a5, 64(a1)
add a0, a0, t0
add a0, a0, a5
xor a4, a4, a0
srli a5, a4, 16
slli a4, a4, 48
or a4, a4, a5
add a3, a3, a4
xor t0, t0, a3
srli a5, t0, 63
slli t0, t0, 1
or t0, t0, a5
ld a5, 96(a1)
add ra, ra, s1
add ra, ra, a5
xor a4, a4, ra
srli a5, a4, 32
slli a4, a4, 32
or a4, a4, a5
add a2, a2, a4
xor s1, s1, a2
srli a5, s1, 24
slli s1, s1, 40
or s1, s1, a5
ld a5, 16(a1)
add ra, ra, s1
add ra, ra, a5
xor a4, a4, ra
srli a5, a4, 16
slli a4, a4, 48
or a4, a4, a5
add a2, a2, a4
xor s1, s1, a2
srli a5, s1, 63
slli s1, s1, 1
or s1, s1, a5
ld a5, 104(a1)
add s0, s0, t1
add s0, s0, a5
xor t2, t2, s0
srli a5, t2, 32
slli t2, t2, 32
or t2, t2, a5
add a3, a3, t2
xor t1, t1, a3
srli a5, t1, 24
slli t1, t1, 40
or t1, t1, a5
ld a5, 56(a1)
add s0, s0, t1
add s0, s0, a5
xor t2, t2, s0
srli a5, t2, 16
slli t2, t2, 48
or t2, t2, a5
add a3, a3, t2
xor t1, t1, a3
srli a5, t1, 63
slli t1, t1, 1
or t1, t1, a5
sd a3, 88(sp)
ld a3, 16(sp)
sd a4, 120(sp)
ld a4, 64(sp)
sd t1, 48(sp)
ld t1, 104(sp)
ld a5, 8(a1)
add a3, a3, t0
add a3, a3, a5
xor t1, t1, a3
srli a5, t1, 32
slli t1, t1, 32
or t1, t1, a5
add a4, a4, t1
xor t0, t0, a4
srli a5, t0, 24
slli t0, t0, 40
or t0, t0, a5
ld a5, 32(a1)
add a3, a3, t0
add a3, a3, a5
xor t1, t1, a3
srli a5, t1, 16
slli t1, t1, 48
or t1, t1, a5
add a4, a4, t1
xor t0, t0, a4
srli a5, t0, 63
slli t0, t0, 1
or t0, t0, a5
sd t0, 56(sp)
ld t0, 32(sp)
sd a2, 80(sp)
ld a2, 72(sp)
sd a3, 16(sp)
ld a3, 112(sp)
ld a5, 80(a1)
add a0, a0, t0
add a0, a0, a5
xor a3, a3, a0
srli a5, a3, 32
slli a3, a3, 32
or a3, a3, a5
add a2, a2, a3
xor t0, t0, a2
srli a5, t0, 24
slli t0, t0, 40
or t0, t0, a5
ld a5, 40(a1)
add a0, a0, t0
add a0, a0, a5
xor a3, a3, a0
srli a5, a3, 16
slli a3, a3, 48
or a3, a3, a5
add a2, a2, a3
xor t0, t0, a2
srli a5, t0, 63
slli t0, t0, 1
or t0, t0, a5
ld a5, 80(a1)
add ra, ra, t0
add ra, ra, a5
xor t2, t2, ra
srli a5, t2, 32
slli t2, t2, 32
or t2, t2, a5
add a4, a4, t2
xor t0, t0, a4
srli a5, t0, 24
slli t0, t0, 40
or t0, t0, a5
ld a5, 16(a1)
add ra, ra, t0
add ra, ra, a5
xor t2, t2, ra
srli a5, t2, 16
slli t2, t2, 48
or t2, t2, a5
add a4, a4, t2
xor t0, t0, a4
srli a5, t0, 63
slli t0, t0, 1
or t0, t0, a5
ld a5, 64(a1)
add s0, s0, s1
add s0, s0, a5
xor t1, t1, s0
srli a5, t1, 32
slli t1, t1, 32
or t1, t1, a5
add a2, a2, t1
xor s1, s1, a2
srli a5, s1, 24
slli s1, s1, 40
or s1, s1, a5
ld a5, 32(a1)
add s0, s0, s1
add s0, s0, a5
xor t1, t1, s0
srli a5, t1, 16
slli t1, t1, 48
or t1, t1, a5
add a2, a2, t1
xor s1, s1, a2
srli a5, s1, 63
slli s1, s1, 1
or s1, s1, a5
sd t0, 32(sp)
ld t0, 16(sp)
sd a2, 72(sp)
ld a2, 48(sp)
sd a4, 64(sp)
ld a4, 80(sp)
ld a5, 56(a1)
add t0, t0, a2
add t0, t0, a5
xor a3, a3, t0
srli a5, a3, 32
slli a3, a3, 32
or a3, a3, a5
add a4, a4, a3
xor a2, a2, a4
srli a5, a2, 24
slli a2, a2, 40
or a2, a2, a5
ld a5, 48(a1)
add t0, t0, a2
add t0, t0, a5
xor a3, a3, t0
srli a5, a3, 16
slli a3, a3, 48
or a3, a3, a5
add a4, a4, a3
xor a2, a2, a4
srli a5, a2, 63
slli a2, a2, 1
or a2, a2, a5
sd a3, 112(sp)
ld a3, 56(sp)
sd t1, 104(sp)
ld t1, 88(sp)
sd t0, 16(sp)
ld t0, 120(sp)
ld a5, 8(a1)
add a0, a0, a3
add a0, a0, a5
xor t0, t0, a0
srli a5, t0, 32
slli t0, t0, 32
or t0, t0, a5
add t1, t1, t0
xor a3, a3, t1
srli a5, a3, 24
slli a3, a3, 40
or a3, a3, a5
ld a5, 40(a1)
add a0, a0, a3
add a0, a0, a5
xor t0, t0, a0
srli a5, t0, 16
slli t0, t0, 48
or t0, t0, a5
add t1, t1, t0
xor a3, a3, t1
srli a5, a3, 63
slli a3, a3, 1
or a3, a3, a5
ld a5, 120(a1)
add ra, ra, s1
add ra, ra, a5
xor t0, t0, ra
srli a5, t0, 32
slli t0, t0, 32
or t0, t0, a5
add a4, a4, t0
xor s1, s1, a4
srli a5, s1, 24
slli s1, s1, 40
or s1, s1, a5
ld a5, 88(a1)
add ra, ra, s1
add ra, ra, a5
xor t0, t0, ra
srli a5, t0, 16
slli t0, t0, 48
or t0, t0, a5
add a4, a4, t0
xor s1, s1, a4
srli a5, s1, 63
slli s1, s1, 1
or s1, s1, a5
ld a5, 72(a1)
add s0, s0, a2
add s0, s0, a5
xor t2, t2, s0
srli a5, t2, 32
slli t2, t2, 32
or t2, t2, a5
add t1, t1, t2
xor a2, a2, t1
srli a5, a2, 24
slli a2, a2, 40
or a2, a2, a5
ld a5, 112(a1)
add s0, s0, a2
add s0, s0, a5
xor t2, t2, s0
srli a5, t2, 16
slli t2, t2, 48
or t2, t2, a5
add t1, t1, t2
xor a2, a2, t1
srli a5, a2, 63
slli a2, a2, 1
or a2, a2, a5
sd t1, 88(sp)
ld t1, 16(sp)
sd t0, 120(sp)
ld t0, 64(sp)
sd a2, 48(sp)
ld a2, 104(sp)
ld a5, 24(a1)
add t1, t1, a3
add t1, t1, a5
xor a2, a2, t1
srli a5, a2, 32
slli a2, a2, 32
or a2, a2, a5
add t0, t0, a2
xor a3, a3, t0
srli a5, a3, 24
slli a3, a3, 40
or a3, a3, a5
ld a5, 96(a1)
add t1, t1, a3
add t1, t1, a5
xor a2, a2, t1
srli a5, a2, 16
slli a2, a2, 48
or a2, a2, a5
add t0, t0, a2
xor a3, a3, t0
srli a5, a3, 63
slli a3, a3, 1
or a3, a3, a5
sd a3, 56(sp)
ld a3, 32(sp)
sd a4, 80(sp)
ld a4, 72(sp)
sd t1, 16(sp)
ld t1, 112(sp)
ld a5, 104(a1)
add a0, a0, a3
add a0, a0, a5
xor t1, t1, a0
srli a5, t1, 32
slli t1, t1, 32
or t1, t1, a5
add a4, a4, t1
xor a3, a3, a4
srli a5, a3, 24
slli a3, a3, 40
or a3, a3, a5
ld a5, 0(a1)
add a0, a0, a3
add a0, a0, a5
xor t1, t1, a0
srli a5, t1, 16
slli t1, t1, 48
or t1, t1, a5
add a4, a4, t1
xor a3, a3, a4
srli a5, a3, 63
slli a3, a3, 1
or a3, a3, a5
ld a5, 0(a1)
add ra, ra, a3
add ra, ra, a5
xor t2, t2, ra
srli a5, t2, 32
slli t2, t2, 32
or t2, t2, a5
add t0, t0, t2
xor a3, a3, t0
srli a5, a3, 24
slli a3, a3, 40
or a3, a3, a5
ld a5, 8(a1)
add ra, ra, a3
add ra, ra, a5
xor t2, t2, ra
srli a5, t2, 16
slli t2, t2, 48
or t2, t2, a5
add t0, t0, t2
xor a3, a3, t0
srli a5, a3, 63
slli a3, a3, 1
or a3, a3, a5
ld a5, 16(a1)
add s0, s0, s1
add s0, s0, a5
xor a2, a2, s0
srli a5, a2, 32
slli a2, a2, 32
or a2, a2, a5
add a4, a4, a2
xor s1, s1, a4
srli a5, s1, 24
slli s1, s1, 40
or s1, s1, a5
ld a5, 24(a1)
add s0, s0, s1
add s0, s0, a5
xor a2, a2, s0
srli a5, a2, 16
slli a2, a2, 48
or a2, a2, a5
add a4, a4, a2
xor s1, s1, a4
srli a5, s1, 63
slli s1, s1, 1
or s1, s1, a5
sd a3, 32(sp)
ld a3, 16(sp)
sd a4, 72(sp)
ld a4, 48(sp)
sd t0, 64(sp)
ld t0, 80(sp)
ld a5, 32(a1)
add a3, a3, a4
add a3, a3, a5
xor t1, t1, a3
srli a5, t1, 32
slli t1, t1, 32
or t1, t1, a5
add t0, t0, t1
xor a4, a4, t0
srli a5, a4, 24
slli a4, a4, 40
or a4, a4, a5
ld a5, 40(a1)
add a3, a3, a4
add a3, a3, a5
xor t1, t1, a3
srli a5, t1, 16
slli t1, t1, 48
or t1, t1, a5
add t0, t0, t1
xor a4, a4, t0
srli a5, a4, 63
slli a4, a4, 1
or a4, a4, a5
sd t1, 112(sp)
ld t1, 56(sp)
sd a2, 104(sp)
ld a2, 88(sp)
sd a3, 16(sp)
ld a3, 120(sp)
ld a5, 48(a1)
add a0, a0, t1
add a0, a0, a5
xor a3, a3, a0
srli a5, a3, 32
slli a3, a3, 32
or a3, a3, a5
add a2, a2, a3
xor t1, t1, a2
srli a5, t1, 24
slli t1, t1, 40
or t1, t1, a5
ld a5, 56(a1)
add a0, a0, t1
add a0, a0, a5
xor a3, a3, a0
srli a5, a3, 16
slli a3, a3, 48
or a3, a3, a5
add a2, a2, a3
xor t1, t1, a2
srli a5, t1, 63
slli t1, t1, 1
or t1, t1, a5
ld a5, 64(a1)
add ra, ra, s1
add ra, ra, a5
xor a3, a3, ra
srli a5, a3, 32
slli a3, a3, 32
or a3, a3, a5
add t0, t0, a3
xor s1, s1, t0
srli a5, s1, 24
slli s1, s1, 40
or s1, s1, a5
ld a5, 72(a1)
add ra, ra, s1
add ra, ra, a5
xor a3, a3, ra
srli a5, a3, 16
slli a3, a3, 48
or a3, a3, a5
add t0, t0, a3
xor s1, s1, t0
srli a5, s1, 63
slli s1, s1, 1
or s1, s1, a5
ld a5, 80(a1)
add s0, s0, a4
add s0, s0, a5
xor t2, t2, s0
srli a5, t2, 32
slli t2, t2, 32
or t2, t2, a5
add a2, a2, t2
xor a4, a4, a2
srli a5, a4, 24
slli a4, a4, 40
or a4, a4, a5
ld a5, 88(a1)
add s0, s0, a4
add s0, s0, a5
xor t2, t2, s0
srli a5, t2, 16
slli t2, t2, 48
or t2, t2, a5
add a2, a2, t2
xor a4, a4, a2
srli a5, a4, 63
slli a4, a4, 1
or a4, a4, a5
sd a2, 88(sp)
ld a2, 16(sp)
sd a3, 120(sp)
ld a3, 64(sp)
sd a4, 48(sp)
ld a4, 104(sp)
ld a5, 96(a1)
add a2, a2, t1
add a2, a2, a5
xor a4, a4, a2
srli a5, a4, 32
slli a4, a4, 32
or a4, a4, a5
add a3, a3, a4
xor t1, t1, a3
srli a5, t1, 24
slli t1, t1, 40
or t1, t1, a5
ld a5, 104(a1)
add a2, a2, t1
add a2, a2, a5
xor a4, a4, a2
srli a5, a4, 16
slli a4, a4, 48
or a4, a4, a5
add a3, a3, a4
xor t1, t1, a3
srli a5, t1, 63
slli t1, t1, 1
or t1, t1, a5
sd t1, 56(sp)
ld t1, 32(sp)
sd t0, 80(sp)
ld t0, 72(sp)
sd a2, 16(sp)
ld a2, 112(sp)
ld a5, 112(a1)
add a0, a0, t1
add a0, a0, a5
xor a2, a2, a0
srli a5, a2, 32
slli a2, a2, 32
or a2, a2, a5
add t0, t0, a2
xor t1, t1, t0
srli a5, t1, 24
slli t1, t1, 40
or t1, t1, a5
ld a5, 120(a1)
add a0, a0, t1
add a0, a0, a5
xor a2, a2, a0
srli a5, a2, 16
slli a2, a2, 48
or a2, a2, a5
add t0, t0, a2
xor t1, t1, t0
srli a5, t1, 63
slli t1, t1, 1
or t1, t1, a5
ld a5, 112(a1)
add ra, ra, t1
add ra, ra, a5
xor t2, t2, ra
srli a5, t2, 32
slli t2, t2, 32
or t2, t2, a5
add a3, a3, t2
xor t1, t1, a3
srli a5, t1, 24
slli t1, t1, 40
or t1, t1, a5
ld a5, 80(a1)
add ra, ra, t1
add ra, ra, a5
xor t2, t2, ra
srli a5, t2, 16
slli t2, t2, 48
or t2, t2, a5
add a3, a3, t2
xor t1, t1, a3
srli a5, t1, 63
slli t1, t1, 1
or t1, t1, a5
ld a5, 32(a1)
add s0, s0, s1
add s0, s0, a5
xor a4, a4, s0
srli a5, a4, 32
slli a4, a4, 32
or a4, a4, a5
add t0, t0, a4
xor s1, s1, t0
srli a5, s1, 24
slli s1, s1, 40
or s1, s1, a5
ld a5, 64(a1)
add s0, s0, s1
add s0, s0, a5
xor a4, a4, s0
srli a5, a4, 16
slli a4, a4, 48
or a4, a4, a5
add t0, t0, a4
xor s1, s1, t0
srli a5, s1, 63
slli s1, s1, 1
or s1, s1, a5
sd t1, 32(sp)
ld t1, 16(sp)
sd t0, 72(sp)
ld t0, 48(sp)
sd a3, 64(sp)
ld a3, 80(sp)
ld a5, 72(a1)
add t1, t1, t0
add t1, t1, a5
xor a2, a2, t1
srli a5, a2, 32
slli a2, a2, 32
or a2, a2, a5
add a3, a3, a2
xor t0, t0, a3
srli a5, t0, 24
slli t0, t0, 40
or t0, t0, a5
ld a5, 120(a1)
add t1, t1, t0
add t1, t1, a5
xor a2, a2, t1
srli a5, a2, 16
slli a2, a2, 48
or a2, a2, a5
add a3, a3, a2
xor t0, t0, a3
srli a5, t0, 63
slli t0, t0, 1
or t0, t0, a5
sd a2, 112(sp)
ld a2, 56(sp)
sd a4, 104(sp)
ld a4, 88(sp)
sd t1, 16(sp)
ld t1, 120(sp)
ld a5, 104(a1)
add a0, a0, a2
add a0, a0, a5
xor t1, t1, a0
srli a5, t1, 32
slli t1, t1, 32
or t1, t1, a5
add a4, a4, t1
xor a2, a2, a4
srli a5, a2, 24
slli a2, a2, 40
or a2, a2, a5
ld a5, 48(a1)
add a0, a0, a2
add a0, a0, a5
xor t1, t1, a0
srli a5, t1, 16
slli t1, t1, 48
or t1, t1, a5
add a4, a4, t1
xor a2, a2, a4
srli a5, a2, 63
slli a2, a2, 1
or a2, a2, a5
ld a5, 8(a1)
add ra, ra, s1
add ra, ra, a5
xor t1, t1, ra
srli a5, t1, 32
slli t1, t1, 32
or t1, t1, a5
add a3, a3, t1
xor s1, s1, a3
srli a5, s1, 24
slli s1, s1, 40
or s1, s1, a5
ld a5, 96(a1)
add ra, ra, s1
add ra, ra, a5
xor t1, t1, ra
srli a5, t1, 16
slli t1, t1, 48
or t1, t1, a5
add a3, a3, t1
xor s1, s1, a3
srli a5, s1, 63
slli s1, s1, 1
or s1, s1, a5
ld a5, 0(a1)
add s0, s0, t0
add s0, s0, a5
xor t2, t2, s0
srli a5, t2, 32
slli t2, t2, 32
or t2, t2, a5
add a4, a4, t2
xor t0, t0, a4
srli a5, t0, 24
slli t0, t0, 40
or t0, t0, a5
ld a5, 16(a1)
add s0, s0, t0
add s0, s0, a5
xor t2, t2, s0
srli a5, t2, 16
slli t2, t2, 48
or t2, t2, a5
add a4, a4, t2
xor t0, t0, a4
srli a5, t0, 63
slli t0, t0, 1
or t0, t0, a5
sd ra, 0(sp)
ld ra, 16(sp)
sd t2, 96(sp)
ld t2, 64(sp)
sd s0, 8(sp)
ld s0, 104(sp)
ld a5, 88(a1)
add ra, ra, a2
add ra, ra, a5
xor s0, s0, ra
srli a5, s0, 32
slli s0, s0, 32
or s0, s0, a5
add t2, t2, s0
xor a2, a2, t2
srli a5, a2, 24
slli a2, a2, 40
or a2, a2, a5
ld a5, 56(a1)
add ra, ra, a2
add ra, ra, a5
xor s0, s0, ra
srli a5, s0, 16
slli s0, s0, 48
or s0, s0, a5
add t2, t2, s0
xor a2, a2, t2
srli a5, a2, 63
slli a2, a2, 1
or a2, a2, a5
sd s1, 40(sp)
ld s1, 32(sp)
sd t0, 48(sp)
ld t0, 72(sp)
sd a3, 80(sp)
ld a3, 112(sp)
ld a5, 40(a1)
add a0, a0, s1
add a0, a0, a5
xor a3, a3, a0
srli a5, a3, 32
slli a3, a3, 32
or a3, a3, a5
add t0, t0, a3
xor s1, s1, t0
srli a5, s1, 24
slli s1, s1, 40
or s1, s1, a5
ld a5, 24(a1)
add a0, a0, s1
add a0, a0, a5
xor a3, a3, a0
srli a5, a3, 16
slli a3, a3, 48
or a3, a3, a5
add t0, t0, a3
xor s1, s1, t0
srli a5, s1, 63
slli s1, s1, 1
or s1, s1, a5
sd ra, 16(sp)
sd a0, 24(sp)
sd s1, 32(sp)
sd a2, 56(sp)
sd t2, 64(sp)
sd t0, 72(sp)
sd a4, 88(sp)
sd s0, 104(sp)
sd a3, 112(sp)
sd t1, 120(sp)
ld a0, 152(sp)
ld t0, 0(a0)
ld t1, 0(sp)
ld t2, 64(sp)
xor t0, t0, t1
xor t0, t0, t2
sd t0, 0(a0)
ld t0, 8(a0)
ld t1, 8(sp)
ld t2, 72(sp)
xor t0, t0, t1
xor t0, t0, t2
sd t0, 8(a0)
ld t0, 16(a0)
ld t1, 16(sp)
ld t2, 80(sp)
xor t0, t0, t1
xor t0, t0, t2
sd t0, 16(a0)
ld t0, 24(a0)
ld t1, 24(sp)
ld t2, 88(sp)
xor t0, t0, t1
xor t0, t0, t2
sd t0, 24(a0)
ld t0, 32(a0)
ld t1, 32(sp)
ld t2, 96(sp)
xor t0, t0, t1
xor t0, t0, t2
sd t0, 32(a0)
ld t0, 40(a0)
ld t1, 40(sp)
ld t2, 104(sp)
xor t0, t0, t1
xor t0, t0, t2
sd t0, 40(a0)
ld t0, 48(a0)
ld t1, 48(sp)
ld t2, 112(sp)
xor t0, t0, t1
xor t0, t0, t2
sd t0, 48(a0)
ld t0, 56(a0)
ld t1, 56(sp)
ld t2, 120(sp)
xor t0, t0, t1
xor t0, t0, t2
sd t0, 56(a0)
ld ra, 128(sp)
ld s0, 136(sp)
ld s1, 144(sp)
addi sp, sp, 176
ret
.pushsection .rodata,"a",@progbits
.p2align 3
1:
.dword 0x6a09e667f3bcc908
.dword 0xbb67ae8584caa73b
.dword 0x3c6ef372fe94f82b
.dword 0xa54ff53a5f1d36f1
.dword 0x510e527fade682d1
.dword 0x9b05688c2b3e6c1f
.dword 0x1f83d9abfb41bd6b
.dword 0x5be0cd19137e2179
.popsection
