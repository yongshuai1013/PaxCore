	.text
	.syntax unified
	.thumb
	.globl _start
	.thumb_func
_start:
	@ Stage 1: TBH with index 2 must land on Lt2.
	movs	r3, #2
	tbh	[pc, r3, lsl #1]
Ltbh:
	.hword	(Lt0 - Ltbh) / 2
	.hword	(Lt1 - Ltbh) / 2
	.hword	(Lt2 - Ltbh) / 2
	.hword	(Lt3 - Ltbh) / 2
Lt0:
	movs	r0, #11
	b.w	fail
Lt1:
	movs	r0, #12
	b.w	fail
Lt3:
	movs	r0, #14
	b.w	fail
Lt2:
	@ Stage 2: TBB with index 1 must land on Lb1.
	@ TBB entries are halfword units (target = base +
	@ 2 * byte), exactly like TBH -- verified against a
	@ clang-generated switch table, not assumed.
	movs	r3, #1
	tbb	[pc, r3]
Ltbb:
	.byte	(Lb0 - Ltbb) / 2
	.byte	(Lb1 - Ltbb) / 2
	.byte	(Lb2 - Ltbb) / 2
	.align	1
Lb0:
	movs	r0, #21
	b.w	fail
Lb2:
	movs	r0, #23
	b.w	fail
Lb1:
	movs	r0, #0
fail:
	movs	r7, #1
	svc	#0
