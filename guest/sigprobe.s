	.text
	.syntax unified
	.arm
	.globl _start
_start:
	@ rt_sigaction(SIGUSR1=10, &act, NULL, 8)
	mov	r0, #10
	ldr	r1, =act
	mov	r2, #0
	mov	r3, #8
	mov	r7, #174
	svc	#0
	cmp	r0, #0
	bne	fail1
	@ magic value the handler will clobber; sigreturn must
	@ restore it
	ldr	r5, =0xABCD
	@ kill(getpid(), 10)
	mov	r7, #20
	svc	#0
	mov	r1, #10
	mov	r7, #37
	svc	#0
	@ by the time kill returns, the handler has already run
	ldr	r0, =flag
	ldr	r0, [r0]
	cmp	r0, #1
	bne	fail2
	ldr	r0, =0xABCD
	cmp	r5, r0
	bne	fail3
	ldr	r1, =msg_ok
	mov	r2, #3
	mov	r0, #1
	mov	r7, #4
	svc	#0
	mov	r0, #0
	mov	r7, #248
	svc	#0
handler:
	@ clobber r5 on purpose, set the flag, print H
	mov	r5, #0
	mov	r0, #1
	ldr	r1, =flag
	str	r0, [r1]
	ldr	r1, =msg_h
	mov	r2, #1
	mov	r0, #1
	mov	r7, #4
	svc	#0
	bx	lr		@ lr points at the restorer
restorer:
	mov	r7, #173	@ rt_sigreturn
	svc	#0
fail1:	mov	r0, #1
	b	die
fail2:	mov	r0, #2
	b	die
fail3:	mov	r0, #3
die:	mov	r7, #248
	svc	#0
	.data
msg_ok:	.ascii "OK\n"
msg_h:	.ascii "H"
flag:	.word 0
act:	.word handler
	.word 0x04000000	@ SA_RESTORER
	.word restorer
	.word 0, 0		@ mask
