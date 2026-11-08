	.text
	.syntax unified
	.arm
	.globl _start
_start:
	mov	r7, #190	@ fork
	svc	#0
	cmp	r0, #0
	beq	child
	@ parent: wait4(-1, &status, 0, NULL)
	mov	r5, r0
	mov	r0, #-1
	ldr	r1, =status
	mov	r2, #0
	mov	r3, #0
	mov	r7, #114
	svc	#0
	cmp	r0, r5
	bne	fail1
	ldr	r0, =status
	ldr	r0, [r0]
	@ signaled death: low 7 bits = 15, next byte = 0
	and	r1, r0, #0x7f
	cmp	r1, #15
	bne	fail2
	mov	r1, r0, lsr #8
	and	r1, r1, #0xff
	cmp	r1, #0
	bne	fail2
	ldr	r1, =msg_ok
	mov	r2, #3
	mov	r0, #1
	mov	r7, #4
	svc	#0
	mov	r0, #0
	mov	r7, #248
	svc	#0
child:
	@ kill self with SIGTERM, no handler installed
	mov	r7, #20
	svc	#0
	mov	r1, #15
	mov	r7, #37
	svc	#0
	@ should never reach here
	mov	r0, #9
	mov	r7, #248
	svc	#0
fail1:	mov	r0, #1
	b	die
fail2:	mov	r0, #2
die:	mov	r7, #248
	svc	#0
	.data
msg_ok:	.ascii "OK\n"
status:	.word 0
