	.text
	.syntax unified
	.arm
	.globl _start
_start:
	ldr	r10, =outbuf
	@ umull: 0xFFFFFFFF * 0xFFFFFFFF = 0xFFFFFFFE00000001
	ldr	r0, =0xFFFFFFFF
	ldr	r1, =0xFFFFFFFF
	umull	r2, r3, r0, r1
	str	r2, [r10, #0]	@ expect 0x00000001
	str	r3, [r10, #4]	@ expect 0xFFFFFFFE
	@ umull: 1000000007 * 10 = 10000000070 = 0x2_540BE3FE
	ldr	r0, =1000000007
	mov	r1, #10
	umull	r2, r3, r0, r1
	str	r2, [r10, #8]	@ expect 0x540BE3FE
	str	r3, [r10, #12]	@ expect 0x2
	@ smull: -2 * 3 = -6 = 0xFFFFFFFFFFFFFFFA
	mov	r0, #-2
	mov	r1, #3
	smull	r2, r3, r0, r1
	str	r2, [r10, #16]	@ expect 0xFFFFFFFA
	str	r3, [r10, #20]	@ expect 0xFFFFFFFF
	@ umlal: acc 0x100000002 + 0x10000*0x10000 = 0x200000002
	mov	r2, #2
	mov	r3, #1
	ldr	r0, =0x10000
	ldr	r1, =0x10000
	umlal	r2, r3, r0, r1
	str	r2, [r10, #24]	@ expect 0x00000002
	str	r3, [r10, #28]	@ expect 0x2
	@ smlal: acc -1 + (-2*3) = -7
	mov	r2, #-1
	mov	r3, #-1
	mov	r0, #-2
	mov	r1, #3
	smlal	r2, r3, r0, r1
	str	r2, [r10, #32]	@ expect 0xFFFFFFF9
	str	r3, [r10, #36]	@ expect 0xFFFFFFFF
	@ mul (32-bit): 0x12345 * 0x100 = 0x1234500
	ldr	r0, =0x12345
	mov	r1, #0x100
	mul	r2, r0, r1
	str	r2, [r10, #40]	@ expect 0x01234500
	@ mla: 3*4 + 5 = 17
	mov	r0, #3
	mov	r1, #4
	mov	r2, #5
	mla	r3, r0, r1, r2
	str	r3, [r10, #44]	@ expect 17
	mov	r0, #0
	mov	r7, #1
	svc	#0
	.data
outbuf:
	.space	64
