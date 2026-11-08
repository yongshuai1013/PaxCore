	.text
	.syntax unified
	.arm
	.globl _start
_start:
	@ clone(CLONE_VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|
	@   PARENT_SETTID|CHILD_SETTID|CHILD_CLEARTID = 0x3250F00,
	@   stack_top, &ptid_buf, tls=0, &ctid_buf)
	ldr	r0, =0x3250F00
	ldr	r1, =stack_buf + 8192
	ldr	r2, =ptid_buf
	mov	r3, #0
	ldr	r4, =ctid_buf
	mov	r7, #120
	svc	#0
	cmp	r0, #0
	blt	fail1
	beq	thread_main
	mov	r5, r0		@ r5 = child tid
	@ parent: ptid_buf must already hold the tid
	ldr	r0, =ptid_buf
	ldr	r0, [r0]
	cmp	r0, r5
	bne	fail2
	@ wait until futex_word == 1
1:	ldr	r0, =futex_word
	ldr	r0, [r0]
	cmp	r0, #1
	beq	2f
	ldr	r0, =futex_word
	mov	r1, #0		@ FUTEX_WAIT
	mov	r2, #0
	mov	r3, #0
	mov	r7, #240
	svc	#0
	b	1b
2:	@ join: wait until ctid_buf == 0
	ldr	r0, =ctid_buf
	ldr	r0, [r0]
	cmp	r0, #0
	beq	3f
	ldr	r0, =ctid_buf
	mov	r1, #0
	mov	r2, r5
	mov	r3, #0
	mov	r7, #240
	svc	#0
	b	2b
3:	@ checks: shared_var written by the thread, and the
	@ thread saw getpid() == 100 (the group id)
	ldr	r0, =shared_var
	ldr	r0, [r0]
	ldr	r1, =0x1234
	cmp	r0, r1
	bne	fail3
	ldr	r0, =shared_pid
	ldr	r0, [r0]
	cmp	r0, #100
	bne	fail4
	ldr	r1, =msg_ok
	mov	r2, #3
	mov	r0, #1
	mov	r7, #4
	svc	#0
	mov	r0, #0
	mov	r7, #248
	svc	#0
thread_main:
	@ runs on the new stack, shared memory
	mov	r7, #20		@ getpid -> must be tgid 100
	svc	#0
	ldr	r1, =shared_pid
	str	r0, [r1]
	ldr	r0, =0x1234
	ldr	r1, =shared_var
	str	r0, [r1]
	@ futex_word = 1, then FUTEX_WAKE
	mov	r0, #1
	ldr	r1, =futex_word
	str	r0, [r1]
	ldr	r0, =futex_word
	mov	r1, #1		@ FUTEX_WAKE
	mov	r2, #1
	mov	r7, #240
	svc	#0
	@ thread exit (nr 1): group must survive
	mov	r0, #0
	mov	r7, #1
	svc	#0
fail1:	mov	r0, #1
	b	die
fail2:	mov	r0, #2
	b	die
fail3:	mov	r0, #3
	b	die
fail4:	mov	r0, #4
die:	mov	r7, #248
	svc	#0
	.data
msg_ok:	.ascii "OK\n"
ptid_buf:	.word 0
ctid_buf:	.word 0
futex_word:	.word 0
shared_var:	.word 0
shared_pid:	.word 0
	.bss
stack_buf:	.space 8192
