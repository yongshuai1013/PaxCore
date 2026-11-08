	.text
	.syntax unified
	.arm
	.globl _start
_start:
	@ 1) wait4 with no children -> -ECHILD (0xFFFFFFF6)
	mov	r0, #-1
	ldr	r1, =status
	mov	r2, #1		@ WNOHANG (ECHILD comes first anyway)
	mov	r3, #0
	mov	r7, #114
	svc	#0
	ldr	r1, =0xFFFFFFF6
	cmp	r0, r1
	bne	fail1
	@ 2) fork
	mov	r7, #190
	svc	#0
	cmp	r0, #0
	blt	fail2
	beq	child
	mov	r4, r0
	@ 3) WNOHANG while child alive -> 0
	mov	r0, #-1
	ldr	r1, =status
	mov	r2, #1
	mov	r3, #0
	mov	r7, #114
	svc	#0
	cmp	r0, #0
	bne	fail3
	@ 4) blocking wait -> reaps child, code 9
	mov	r0, #-1
	ldr	r1, =status
	mov	r2, #0
	mov	r3, #0
	mov	r7, #114
	svc	#0
	cmp	r0, r4
	bne	fail4
	ldr	r0, =status
	ldr	r0, [r0]
	lsr	r0, r0, #8
	cmp	r0, #9
	bne	fail5
	@ 5) getpid in parent must be 100
	mov	r7, #20
	svc	#0
	cmp	r0, #100
	bne	fail6
	mov	r0, #0
	mov	r7, #248
	svc	#0
child:
	@ busy-wait a while so the parent's WNOHANG sees us alive
	ldr	r5, =300000
1:	subs	r5, r5, #1
	bne	1b
	mov	r0, #9
	mov	r7, #248
	svc	#0
fail1:	mov	r0, #1
	b	die
fail2:	mov	r0, #2
	b	die
fail3:	mov	r0, #3
	b	die
fail4:	mov	r0, #4
	b	die
fail5:	mov	r0, #5
	b	die
fail6:	mov	r0, #6
die:	mov	r7, #248
	svc	#0
	.data
status:	.word 0
