#!/usr/bin/env python3
"""Interpret the generated compression (the subset of RV64 it uses) against a reference
BLAKE2b compression, for random states and both finalization flags."""
import re, struct, hashlib, sys
M64=(1<<64)-1
IV=[0x6A09E667F3BCC908,0xBB67AE8584CAA73B,0x3C6EF372FE94F82B,0xA54FF53A5F1D36F1,0x510E527FADE682D1,0x9B05688C2B3E6C1F,0x1F83D9ABFB41BD6B,0x5BE0CD19137E2179]
def run(asm, h, m, t, last):
    mem={}
    def st(a,v): mem[a]=v&M64
    def ld(a): return mem[a]
    R={r:0 for r in "ra sp t0 t1 t2 s0 s1 a0 a1 a2 a3 a4 a5".split()}
    R['sp']=0x100000; HB=0x2000; MB=0x3000; IVB=0x4000
    for i in range(8): st(HB+8*i,h[i]); st(IVB+8*i,IV[i])
    for i in range(16): st(MB+8*i,m[i])
    R['a0']=HB;R['a1']=MB;R['a2']=t;R['a3']=last
    for line in asm:
        line=line.strip()
        if not line or line.startswith('.') or line.endswith(':'): continue
        op,*args=re.split(r'[ ,]+',line)
        def mo(s):
            off,reg=re.match(r'(-?\d+)\((\w+)\)',s).groups(); return R[reg]+int(off)
        if op=='addi': R[args[0]]=(R[args[1]]+int(args[2]))&M64
        elif op=='sd': st(mo(args[1]),R[args[0]])
        elif op=='ld': R[args[0]]=ld(mo(args[1]))
        elif op=='neg': R[args[0]]=(-R[args[1]])&M64
        elif op=='lla': R[args[0]]=IVB
        elif op in ('.pushsection','.popsection'): continue
        elif op=='xor': R[args[0]]=R[args[1]]^R[args[2]]
        elif op=='add': R[args[0]]=(R[args[1]]+R[args[2]])&M64
        elif op=='or': R[args[0]]=R[args[1]]|R[args[2]]
        elif op=='srli': R[args[0]]=R[args[1]]>>int(args[2])
        elif op=='slli': R[args[0]]=(R[args[1]]<<int(args[2]))&M64
        elif op=='ret': break
        else: raise Exception(op)
    return [ld(HB+8*i) for i in range(8)]
SIG=[[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],[14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],[11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4],[7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],[9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13],[2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],[12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11],[13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],[6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5],[10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0]]
def ror(x,n): return ((x>>n)|(x<<(64-n)))&M64
def ref(h,m,t,last):
    v=h[:]+IV[:]; v[12]^=t; 
    if last: v[14]^=M64
    def G(a,b,c,d,x,y):
        v[a]=(v[a]+v[b]+x)&M64; v[d]=ror(v[d]^v[a],32); v[c]=(v[c]+v[d])&M64; v[b]=ror(v[b]^v[c],24)
        v[a]=(v[a]+v[b]+y)&M64; v[d]=ror(v[d]^v[a],16); v[c]=(v[c]+v[d])&M64; v[b]=ror(v[b]^v[c],63)
    for r in range(12):
        s=SIG[r%10]
        G(0,4,8,12,m[s[0]],m[s[1]]);G(1,5,9,13,m[s[2]],m[s[3]]);G(2,6,10,14,m[s[4]],m[s[5]]);G(3,7,11,15,m[s[6]],m[s[7]])
        G(0,5,10,15,m[s[8]],m[s[9]]);G(1,6,11,12,m[s[10]],m[s[11]]);G(2,7,8,13,m[s[12]],m[s[13]]);G(3,4,9,14,m[s[14]],m[s[15]])
    return [h[i]^v[i]^v[i+8] for i in range(8)]
asm=open(sys.argv[1]).read().split('\n')
import random
ok=True
for seed in range(32):
    random.seed(seed)
    h=[random.getrandbits(64) for _ in range(8)]; m=[random.getrandbits(64) for _ in range(16)]; t=random.getrandbits(64)
    for last in (0,1):
        ok &= run(asm,h,m,t,last)==ref(h,m,t,last)
print('ok' if ok else 'MISMATCH'); sys.exit(0 if ok else 1)
