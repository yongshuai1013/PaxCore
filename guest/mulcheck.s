    .arch armv8-a
    .thumb
    .text
    .globl _start
    .thumb_func
_start:
    @ 1: MLA 0x118*1 + 0x99d0 = 0x9ae8 (the linker soinfo case)
    movw r1, #0x118
    movs r2, #1
    movw r3, #0x99d0
    mla r0, r1, r2, r3
    movw r4, #0x9ae8
    cmp r0, r4
    bne fail1
    @ 2: MLS 0x99d0 - 0x118*1 = 0x98b8
    movw r3, #0x99d0
    mls r0, r1, r2, r3
    movw r4, #0x98b8
    cmp r0, r4
    bne fail2
    @ 3: MUL 0x12345 * 0x100 = 0x1234500
    movw r1, #0x2345
    movt r1, #0x1
    movw r2, #0x100
    mul r0, r1, r2
    movw r4, #0x4500
    movt r4, #0x123
    cmp r0, r4
    bne fail3
    @ 4: SDIV -100 / 7 = -14
    movw r1, #0xff9c
    movt r1, #0xffff
    movs r2, #7
    sdiv r0, r1, r2
    movw r4, #0xfff2
    movt r4, #0xffff
    cmp r0, r4
    bne fail4
    @ 5: SDIV 100 / 0 = 0
    movs r1, #100
    movs r2, #0
    sdiv r0, r1, r2
    cmp r0, #0
    bne fail5
    @ 6: UDIV 0xfffffff0 / 16 = 0x0fffffff
    movw r1, #0xfff0
    movt r1, #0xffff
    movs r2, #16
    udiv r0, r1, r2
    movw r4, #0xffff
    movt r4, #0x0fff
    cmp r0, r4
    bne fail6
    @ 7: SMULL -2 * 3 = -6 (lo fffffffa, hi ffffffff)
    movw r2, #0xfffe
    movt r2, #0xffff
    movs r3, #3
    smull r0, r1, r2, r3
    movw r4, #0xfffa
    movt r4, #0xffff
    cmp r0, r4
    bne fail7
    movw r4, #0xffff
    movt r4, #0xffff
    cmp r1, r4
    bne fail7
    @ 8: UMULL 0xffffffff * 0xffffffff (lo 1, hi fffffffe)
    movw r2, #0xffff
    movt r2, #0xffff
    movw r3, #0xffff
    movt r3, #0xffff
    umull r0, r1, r2, r3
    cmp r0, #1
    bne fail8
    movw r4, #0xfffe
    movt r4, #0xffff
    cmp r1, r4
    bne fail8
    @ 9: SMLAL acc=5, + (-1 * 2) = 3
    movs r0, #5
    movs r1, #0
    movw r2, #0xffff
    movt r2, #0xffff
    movs r3, #2
    smlal r0, r1, r2, r3
    cmp r0, #3
    bne fail9
    cmp r1, #0
    bne fail9
    @ 10: UMLAL acc=(1,0)=2^32, + 2*3 (lo 6, hi 1)
    movs r0, #0
    movs r1, #1
    movs r2, #2
    movs r3, #3
    umlal r0, r1, r2, r3
    cmp r0, #6
    bne fail10
    cmp r1, #1
    bne fail10
    @ 11: SMULBB (3 * 4) = 12 ; Rn halves hi=2 lo=3, Rm hi=5 lo=4
    movw r1, #0x0003
    movt r1, #0x0002
    movw r2, #0x0004
    movt r2, #0x0005
    smulbb r0, r1, r2
    cmp r0, #12
    bne fail11
    @ 12: SMULTT (2 * 5) = 10
    smultt r0, r1, r2
    cmp r0, #10
    bne fail12
    @ 13: SMLABB 3*4 + 100 = 112
    movs r3, #100
    smlabb r0, r1, r2, r3
    cmp r0, #112
    bne fail13
    @ 14: SMULWB 0x10000 * 0x2000 >> 16 = 0x2000
    movw r1, #0x0000
    movt r1, #0x0001
    movw r2, #0x2000
    smulwb r0, r1, r2
    movw r4, #0x2000
    cmp r0, r4
    bne fail14
    @ 15: SMUAD 3*4 + 2*5 = 22
    movw r1, #0x0003
    movt r1, #0x0002
    movw r2, #0x0004
    movt r2, #0x0005
    smuad r0, r1, r2
    cmp r0, #22
    bne fail15
    @ 16: SMUADX 3*5 + 2*4 = 23
    smuadx r0, r1, r2
    cmp r0, #23
    bne fail16
    @ 17: SMUSD 3*4 - 2*5 = 2
    smusd r0, r1, r2
    cmp r0, #2
    bne fail17
    @ 18: SMMUL (0x60000000 * 4) >> 32 = 1
    movw r1, #0x0000
    movt r1, #0x6000
    movs r2, #4
    smmul r0, r1, r2
    cmp r0, #1
    bne fail18
    @ 19: SMMULR rounded = 2
    smmulr r0, r1, r2
    cmp r0, #2
    bne fail19
    @ 20: SMMLA (0x40000000 * 4) >> 32 + 41 = 42
    movw r1, #0x0000
    movt r1, #0x4000
    movs r3, #41
    smmla r0, r1, r2, r3
    cmp r0, #42
    bne fail20
    @ 21: SMMLS 50 - ((0x40000000 * 4) >> 32) = 49
    movs r3, #50
    smmls r0, r1, r2, r3
    cmp r0, #49
    bne fail21
    @ 22: UMAAL lo=ffffffff hi=0x10, 2*3 -> lo 0x15, hi 1
    movw r0, #0xffff
    movt r0, #0xffff
    movw r1, #0x0010
    movs r2, #2
    movs r3, #3
    umaal r0, r1, r2, r3
    cmp r0, #0x15
    bne fail22
    cmp r1, #1
    bne fail22
    @ 23: SMLALBB acc=100 + 3*4 = 112
    movs r0, #100
    movs r1, #0
    movs r2, #3
    movs r3, #4
    smlalbb r0, r1, r2, r3
    cmp r0, #112
    bne fail23
    cmp r1, #0
    bne fail23
    @ all pass
    movs r0, #0
    movs r7, #1
    svc #0
fail1: movs r0, #1
    b die
fail2: movs r0, #2
    b die
fail3: movs r0, #3
    b die
fail4: movs r0, #4
    b die
fail5: movs r0, #5
    b die
fail6: movs r0, #6
    b die
fail7: movs r0, #7
    b die
fail8: movs r0, #8
    b die
fail9: movs r0, #9
    b die
fail10: movs r0, #10
    b die
fail11: movs r0, #11
    b die
fail12: movs r0, #12
    b die
fail13: movs r0, #13
    b die
fail14: movs r0, #14
    b die
fail15: movs r0, #15
    b die
fail16: movs r0, #16
    b die
fail17: movs r0, #17
    b die
fail18: movs r0, #18
    b die
fail19: movs r0, #19
    b die
fail20: movs r0, #20
    b die
fail21: movs r0, #21
    b die
fail22: movs r0, #22
    b die
fail23: movs r0, #23
    b die
die:
    movs r7, #1
    svc #0
