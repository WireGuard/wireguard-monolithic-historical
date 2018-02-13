/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2016-2018 René van Dorst <opensource@vdorst.com>. All Rights Reserved.
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#define MASK_U32	0x3c
#define MASK_BYTES	0x03
#define CHACHA20_BLOCK_SIZE 64
#define STACK_SIZE	4*16

#define X0  $t0
#define X1  $t1
#define X2  $t2
#define X3  $t3
#define X4  $t4
#define X5  $t5
#define X6  $t6
#define X7  $t7
#define X8  $v1
#define X9  $fp
#define X10 $s7
#define X11 $s6
#define X12 $s5
#define X13 $s4
#define X14 $s3
#define X15 $s2
/* Use regs which are overwritten on exit for Tx so we don't leak clear data. */
#define T0  $s1
#define T1  $s0
#define T(n) T ## n
#define X(n) X ## n

/* Input arguments */
#define OUT		$a0
#define IN		$a1
#define BYTES		$a2
/* KEY and NONCE argument must be u32 aligned */
#define KEY		$a3
/* NONCE pointer is given via stack */
#define NONCE		$t9

/* Output argument */
/* NONCE[0] is kept in a register and not in memory.
 * We don't want to touch original value in memory.
 * Must be incremented every loop iteration.
 */
#define NONCE_0		$v0

/* SAVED_X and SAVED_CA are set in the jump table.
 * Use regs which are overwritten on exit else we don't leak clear data.
 * They are used to handling the last bytes which are not multiple of 4.
 */
#define SAVED_X		X15
#define SAVED_CA	$ra

#define PTR_LAST_ROUND	$t8

/* ChaCha20 constants and stack location */
#define CONSTANT_OFS_SP	48
#define UNALIGNED_OFS_SP 40

#define CONSTANT_1	0x61707865
#define CONSTANT_2	0x3320646e
#define CONSTANT_3	0x79622d32
#define CONSTANT_4	0x6b206574

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define MSB 0
#define LSB 3
#define ROTx rotl
#define ROTR(n) rotr n, 24
#define	CPU_TO_LE32(n) \
	wsbh	n; \
	rotr	n, 16;
#else
#define MSB 3
#define LSB 0
#define ROTx rotr
#define CPU_TO_LE32(n)
#define ROTR(n)
#endif

#define STORE_UNALIGNED(x, a, s, o) \
.Lchacha20_mips_xor_unaligned_ ## x ## _b: ; \
	.if ((s != NONCE) || (o != 0)); \
		lw	T0, o(s); \
	.endif; \
	lwl	T1, x-4+MSB ## (IN); \
	lwr	T1, x-4+LSB ## (IN); \
	.if ((s == NONCE) && (o == 0)); \
		addu	X ## a, NONCE_0; \
	.else; \
		addu	X ## a, T0; \
	.endif; \
	CPU_TO_LE32(X ## a); \
	xor	X ## a, T1; \
	swl	X ## a, x-4+MSB ## (OUT); \
	swr	X ## a, x-4+LSB ## (OUT);

#define STORE_ALIGNED(x, a, s, o) \
.Lchacha20_mips_xor_aligned_ ## x ## _b: ; \
	.if ((s != NONCE) || (o != 0)); \
		lw	T0, o(s); \
	.endif; \
	lw	T1, x-4 ## (IN); \
	.if ((s == NONCE) && (o == 0)); \
		addu	X ## a, NONCE_0; \
	.else; \
		addu	X ## a, T0; \
	.endif; \
	CPU_TO_LE32(X ## a); \
	xor	X ## a, T1; \
	sw	X ## a, x-4 ## (OUT);

/* Jump table macro.
 * Used for setup and handling the last bytes, which are not multiple of 4.
 * X15 is free to store Xn
 * Every jumptable entry must be equal in size.
 */
#define JMPTBL_ALIGNED(x, a, s, o) \
.Lchacha20_mips_jmptbl_aligned_ ## a: ; \
	.if ((s == NONCE) && (o == 0)); \
		move	SAVED_CA, NONCE_0; \
	.else; \
		lw	SAVED_CA, o(s);\
	.endif; \
	b	.Lchacha20_mips_xor_aligned_ ## x ## _b; \
	move	SAVED_X, X ## a;

#define JMPTBL_UNALIGNED(x, a, s, o) \
.Lchacha20_mips_jmptbl_unaligned_ ## a: ; \
	.if ((s == NONCE) && (o == 0)); \
		move	SAVED_CA, NONCE_0; \
	.else; \
		lw	SAVED_CA, o(s);\
	.endif; \
	b	.Lchacha20_mips_xor_unaligned_ ## x ## _b; \
	move	SAVED_X, X ## a;

#define AXR(A, B, C, D,  K, L, M, N,  V, W, Y, Z,  S) \
	addu	X(A), X(K); \
	addu	X(B), X(L); \
	addu	X(C), X(M); \
	addu	X(D), X(N); \
	xor	X(V), X(A); \
	xor	X(W), X(B); \
	xor	X(Y), X(C); \
	xor	X(Z), X(D); \
	rotl	X(V), S;    \
	rotl	X(W), S;    \
	rotl	X(Y), S;    \
	rotl	X(Z), S;

.text
.set reorder
.set noat
.globl chacha20_mips
.ent   chacha20_mips
chacha20_mips:
	.frame $sp, STACK_SIZE, $ra
	/* This is in the fifth argument */
	lw	NONCE, 16($sp)

	/* Return bytes = 0. */
	.set noreorder
	beqz	BYTES, .Lchacha20_mips_end
	addiu	$sp, -STACK_SIZE
	.set reorder

	/* Calculate PTR_LAST_ROUND */
	addiu	PTR_LAST_ROUND, BYTES, -1
	ins	PTR_LAST_ROUND, $zero, 0, 6
	addu	PTR_LAST_ROUND, OUT

	/* Save s0-s7, fp, ra. */
	sw	$ra,  0($sp)
	sw	$fp,  4($sp)
	sw	$s0,  8($sp)
	sw	$s1, 12($sp)
	sw	$s2, 16($sp)
	sw	$s3, 20($sp)
	sw	$s4, 24($sp)
	sw	$s5, 28($sp)
	sw	$s6, 32($sp)
	sw	$s7, 36($sp)

	lw	NONCE_0, 0(NONCE)
	/* Test IN or OUT is unaligned.
	 * UNALIGNED (T1) = ( IN | OUT ) & 0x00000003
	 */
	or	T1, IN, OUT
	andi	T1, 0x3

	/* Load constant */
	lui	X0, %hi(CONSTANT_1)
	lui	X1, %hi(CONSTANT_2)
	lui	X2, %hi(CONSTANT_3)
	lui	X3, %hi(CONSTANT_4)
	ori	X0, %lo(CONSTANT_1)
	ori	X1, %lo(CONSTANT_2)
	ori	X2, %lo(CONSTANT_3)
	ori	X3, %lo(CONSTANT_4)

	/* Store constant on stack. */
	sw	X0,  0+CONSTANT_OFS_SP($sp)
	sw	X1,  4+CONSTANT_OFS_SP($sp)
	sw	X2,  8+CONSTANT_OFS_SP($sp)
	sw	X3, 12+CONSTANT_OFS_SP($sp)

	sw	T1, UNALIGNED_OFS_SP($sp)

	.set	noreorder
	b	.Lchacha20_rounds_start
	andi	BYTES, (CHACHA20_BLOCK_SIZE-1)
	.set	reorder

.align 4
.Loop_chacha20_rounds:
	addiu	IN,  CHACHA20_BLOCK_SIZE
	addiu	OUT, CHACHA20_BLOCK_SIZE
	addiu	NONCE_0, 1

	lw	X0,  0+CONSTANT_OFS_SP($sp)
	lw	X1,  4+CONSTANT_OFS_SP($sp)
	lw	X2,  8+CONSTANT_OFS_SP($sp)
	lw	X3, 12+CONSTANT_OFS_SP($sp)
	lw	T1,   UNALIGNED_OFS_SP($sp)

.Lchacha20_rounds_start:
	lw	X4,   0(KEY)
	lw	X5,   4(KEY)
	lw	X6,   8(KEY)
	lw	X7,  12(KEY)
	lw	X8,  16(KEY)
	lw	X9,  20(KEY)
	lw	X10, 24(KEY)
	lw	X11, 28(KEY)

	move	X12, NONCE_0
	lw	X13,  4(NONCE)
	lw	X14,  8(NONCE)
	lw	X15, 12(NONCE)

	li	$at, 9
.Loop_chacha20_xor_rounds:
	AXR( 0, 1, 2, 3,  4, 5, 6, 7, 12,13,14,15, 16);
	AXR( 8, 9,10,11, 12,13,14,15,  4, 5, 6, 7, 12);
	AXR( 0, 1, 2, 3,  4, 5, 6, 7, 12,13,14,15,  8);
	AXR( 8, 9,10,11, 12,13,14,15,  4, 5, 6, 7,  7);
	AXR( 0, 1, 2, 3,  5, 6, 7, 4, 15,12,13,14, 16);
	AXR(10,11, 8, 9, 15,12,13,14,  5, 6, 7, 4, 12);
	AXR( 0, 1, 2, 3,  5, 6, 7, 4, 15,12,13,14,  8);
	AXR(10,11, 8, 9, 15,12,13,14,  5, 6, 7, 4,  7);
	.set noreorder
	bnez	$at, .Loop_chacha20_xor_rounds
	addiu	$at, -1

	/* Unaligned? Jump */
	bnez	T1, .Loop_chacha20_unaligned
	andi	$at, BYTES, MASK_U32

	/* Last round? No jump */
	bne	OUT, PTR_LAST_ROUND, .Lchacha20_mips_xor_aligned_64_b
	/* Load upper half of jump table addr */
	lui	T0, %hi(.Lchacha20_mips_jmptbl_aligned_0)

	/* Full block? Jump */
	beqz	BYTES, .Lchacha20_mips_xor_aligned_64_b
	/* Calculate lower half jump table addr and offset */
	ins	T0, $at, 2, 6

	subu	T0, $at
	addiu	T0, %lo(.Lchacha20_mips_jmptbl_aligned_0)

	jr	T0
	/* Delay slot */
	nop

	.set	reorder

.Loop_chacha20_unaligned:
	.set noreorder

	/* Last round? no jump */
	bne	OUT, PTR_LAST_ROUND, .Lchacha20_mips_xor_unaligned_64_b
	/* Load upper half of jump table addr */
	lui	T0, %hi(.Lchacha20_mips_jmptbl_unaligned_0)

	/* Full block? Jump */
	beqz	BYTES, .Lchacha20_mips_xor_unaligned_64_b

	/* Calculate lower half jump table addr and offset */
	ins     T0, $at, 2, 6
	subu	T0, $at
	addiu	T0, %lo(.Lchacha20_mips_jmptbl_unaligned_0)

	jr	T0
	/* Delay slot */
	nop

	.set	reorder

/* Aligned code path
 */
.align 4
	STORE_ALIGNED(64, 15, NONCE,12)
	STORE_ALIGNED(60, 14, NONCE, 8)
	STORE_ALIGNED(56, 13, NONCE, 4)
	STORE_ALIGNED(52, 12, NONCE, 0)
	STORE_ALIGNED(48, 11, KEY, 28)
	STORE_ALIGNED(44, 10, KEY, 24)
	STORE_ALIGNED(40,  9, KEY, 20)
	STORE_ALIGNED(36,  8, KEY, 16)
	STORE_ALIGNED(32,  7, KEY, 12)
	STORE_ALIGNED(28,  6, KEY,  8)
	STORE_ALIGNED(24,  5, KEY,  4)
	STORE_ALIGNED(20,  4, KEY,  0)
	STORE_ALIGNED(16,  3, $sp, 12+CONSTANT_OFS_SP)
	STORE_ALIGNED(12,  2, $sp,  8+CONSTANT_OFS_SP)
	STORE_ALIGNED( 8,  1, $sp,  4+CONSTANT_OFS_SP)
.Lchacha20_mips_xor_aligned_4_b:
	/* STORE_ALIGNED( 4,  0, $sp, 0+CONSTANT_OFS_SP) */
	lw	T0, 0+CONSTANT_OFS_SP($sp)
	lw	T1, 0(IN)
	addu	X0, T0
	CPU_TO_LE32(X0)
	xor	X0, T1
	.set noreorder
	bne	OUT, PTR_LAST_ROUND, .Loop_chacha20_rounds
	sw	X0, 0(OUT)
	.set reorder

	.set noreorder
	bne	$at, BYTES, .Lchacha20_mips_xor_bytes
	/* Empty delayslot, Increase NONCE_0, return NONCE_0 value */
	addiu	NONCE_0, 1
	.set noreorder

.Lchacha20_mips_xor_done:
	/* Restore used registers */
	lw	$ra,  0($sp)
	lw	$fp,  4($sp)
	lw	$s0,  8($sp)
	lw	$s1, 12($sp)
	lw	$s2, 16($sp)
	lw	$s3, 20($sp)
	lw	$s4, 24($sp)
	lw	$s5, 28($sp)
	lw	$s6, 32($sp)
	lw	$s7, 36($sp)
.Lchacha20_mips_end:
	.set noreorder
	jr	$ra
	addiu	$sp, STACK_SIZE
	.set reorder

	.set noreorder
	/* Start jump table */
	JMPTBL_ALIGNED( 0,  0, $sp,  0+CONSTANT_OFS_SP)
	JMPTBL_ALIGNED( 4,  1, $sp,  4+CONSTANT_OFS_SP)
	JMPTBL_ALIGNED( 8,  2, $sp,  8+CONSTANT_OFS_SP)
	JMPTBL_ALIGNED(12,  3, $sp, 12+CONSTANT_OFS_SP)
	JMPTBL_ALIGNED(16,  4, KEY,  0)
	JMPTBL_ALIGNED(20,  5, KEY,  4)
	JMPTBL_ALIGNED(24,  6, KEY,  8)
	JMPTBL_ALIGNED(28,  7, KEY, 12)
	JMPTBL_ALIGNED(32,  8, KEY, 16)
	JMPTBL_ALIGNED(36,  9, KEY, 20)
	JMPTBL_ALIGNED(40, 10, KEY, 24)
	JMPTBL_ALIGNED(44, 11, KEY, 28)
	JMPTBL_ALIGNED(48, 12, NONCE, 0)
	JMPTBL_ALIGNED(52, 13, NONCE, 4)
	JMPTBL_ALIGNED(56, 14, NONCE, 8)
	JMPTBL_ALIGNED(60, 15, NONCE,12)
	/* End jump table */
	.set reorder

/* Unaligned code path
 */
	STORE_UNALIGNED(64, 15, NONCE,12)
	STORE_UNALIGNED(60, 14, NONCE, 8)
	STORE_UNALIGNED(56, 13, NONCE, 4)
	STORE_UNALIGNED(52, 12, NONCE, 0)
	STORE_UNALIGNED(48, 11, KEY, 28)
	STORE_UNALIGNED(44, 10, KEY, 24)
	STORE_UNALIGNED(40,  9, KEY, 20)
	STORE_UNALIGNED(36,  8, KEY, 16)
	STORE_UNALIGNED(32,  7, KEY, 12)
	STORE_UNALIGNED(28,  6, KEY,  8)
	STORE_UNALIGNED(24,  5, KEY,  4)
	STORE_UNALIGNED(20,  4, KEY,  0)
	STORE_UNALIGNED(16,  3, $sp, 12+CONSTANT_OFS_SP)
	STORE_UNALIGNED(12,  2, $sp,  8+CONSTANT_OFS_SP)
	STORE_UNALIGNED( 8,  1, $sp,  4+CONSTANT_OFS_SP)
.Lchacha20_mips_xor_unaligned_4_b:
	/* STORE_UNALIGNED( 4,  0, $sp, 0+CONSTANT_OFS_SP) */
	lw	T0, 0+CONSTANT_OFS_SP($sp)
	lwl	T1, 0+MSB(IN)
	lwr	T1, 0+LSB(IN)
	addu	X0, T0
	CPU_TO_LE32(X0)
	xor	X0, T1
	swl	X0, 0+MSB(OUT)
	.set noreorder
	bne	OUT, PTR_LAST_ROUND, .Loop_chacha20_rounds
	swr	X0, 0+LSB(OUT)
	.set reorder

	/* Fall through to byte handling */
	.set noreorder
	beq	$at, BYTES, .Lchacha20_mips_xor_done
	/* Empty delayslot, increase NONCE_0, return NONCE_0 value */
.Lchacha20_mips_xor_unaligned_0_b:
.Lchacha20_mips_xor_aligned_0_b:
	addiu	NONCE_0, 1
	.set reorder

.Lchacha20_mips_xor_bytes:
	addu	OUT, $at
	addu	IN, $at
	addu	SAVED_X, SAVED_CA
	/* First byte */
	lbu	T1, 0(IN)
	andi	$at, BYTES, 2
	CPU_TO_LE32(SAVED_X)
	ROTR(SAVED_X)
	xor	T1, SAVED_X
	.set noreorder
	beqz	$at, .Lchacha20_mips_xor_done
	sb	T1, 0(OUT)
	.set reorder
	/* Second byte */
	lbu	T1, 1(IN)
	andi	$at, BYTES, 1
	ROTx	SAVED_X, 8
	xor	T1, SAVED_X
	.set noreorder
	beqz	$at, .Lchacha20_mips_xor_done
	sb	T1, 1(OUT)
	.set reorder
	/* Third byte */
	lbu	T1, 2(IN)
	ROTx	SAVED_X, 8
	xor	T1, SAVED_X
	.set noreorder
	b	.Lchacha20_mips_xor_done
	sb	T1, 2(OUT)
	.set reorder
.set noreorder

.Lchacha20_mips_jmptbl_unaligned:
	/* Start jump table */
	JMPTBL_UNALIGNED( 0,  0, $sp,  0+CONSTANT_OFS_SP)
	JMPTBL_UNALIGNED( 4,  1, $sp,  4+CONSTANT_OFS_SP)
	JMPTBL_UNALIGNED( 8,  2, $sp,  8+CONSTANT_OFS_SP)
	JMPTBL_UNALIGNED(12,  3, $sp, 12+CONSTANT_OFS_SP)
	JMPTBL_UNALIGNED(16,  4, KEY,  0)
	JMPTBL_UNALIGNED(20,  5, KEY,  4)
	JMPTBL_UNALIGNED(24,  6, KEY,  8)
	JMPTBL_UNALIGNED(28,  7, KEY, 12)
	JMPTBL_UNALIGNED(32,  8, KEY, 16)
	JMPTBL_UNALIGNED(36,  9, KEY, 20)
	JMPTBL_UNALIGNED(40, 10, KEY, 24)
	JMPTBL_UNALIGNED(44, 11, KEY, 28)
	JMPTBL_UNALIGNED(48, 12, NONCE, 0)
	JMPTBL_UNALIGNED(52, 13, NONCE, 4)
	JMPTBL_UNALIGNED(56, 14, NONCE, 8)
	JMPTBL_UNALIGNED(60, 15, NONCE,12)
	/* End jump table */
.set reorder

.end chacha20_mips
.set at
