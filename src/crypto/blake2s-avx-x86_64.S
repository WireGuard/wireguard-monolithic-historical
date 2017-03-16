/*
 * Copyright (C) 2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Based on algorithms from Samuel Neves <sneves@dei.uc.pt>
 */

#include <linux/linkage.h>

.data
.align 32
IV:	.octa 0xA54FF53A3C6EF372BB67AE856A09E667
	.octa 0x5BE0CD191F83D9AB9B05688C510E527F
.align 16
ARG1:	.octa 0x0D0C0F0E09080B0A0504070601000302
ARG2:	.octa 0x0C0F0E0D080B0A090407060500030201

.text
ENTRY(blake2s_compress_avx)
	vmovdqu		IV+16(%rip), %xmm1
	vmovdqu		(%rsi), %xmm4
	vpxor		32(%rdi), %xmm1, %xmm1
	vmovdqu		16(%rsi), %xmm3
	vshufps		$136, %xmm3, %xmm4, %xmm6
	vmovdqa		ARG1(%rip), %xmm7
	vpaddd		(%rdi), %xmm6, %xmm6
	vpaddd		16(%rdi), %xmm6, %xmm6
	vpxor		%xmm6, %xmm1, %xmm1
	vmovdqu		IV(%rip), %xmm8
	vpshufb		%xmm7, %xmm1, %xmm1
	vmovdqu		48(%rsi), %xmm5
	vpaddd		%xmm1, %xmm8, %xmm8
	vpxor		16(%rdi), %xmm8, %xmm9
	vmovdqu		32(%rsi), %xmm2
	vpblendw	$12, %xmm3, %xmm5, %xmm13
	vshufps		$221, %xmm5, %xmm2, %xmm12
	vpunpckhqdq	%xmm2, %xmm4, %xmm14
	vpslld		$20, %xmm9, %xmm0
	vpsrld		$12, %xmm9, %xmm9
	vpxor		%xmm0, %xmm9, %xmm0
	vshufps		$221, %xmm3, %xmm4, %xmm9
	vpaddd		%xmm9, %xmm6, %xmm9
	vpaddd		%xmm0, %xmm9, %xmm9
	vpxor		%xmm9, %xmm1, %xmm1
	vmovdqa		ARG2(%rip), %xmm6
	vpshufb		%xmm6, %xmm1, %xmm1
	vpaddd		%xmm1, %xmm8, %xmm8
	vpxor		%xmm8, %xmm0, %xmm0
	vpshufd		$147, %xmm1, %xmm1
	vpshufd		$78, %xmm8, %xmm8
	vpslld		$25, %xmm0, %xmm10
	vpsrld		$7, %xmm0, %xmm0
	vpxor		%xmm10, %xmm0, %xmm0
	vshufps		$136, %xmm5, %xmm2, %xmm10
	vpshufd		$57, %xmm0, %xmm0
	vpaddd		%xmm10, %xmm9, %xmm9
	vpaddd		%xmm0, %xmm9, %xmm9
	vpxor		%xmm9, %xmm1, %xmm1
	vpaddd		%xmm12, %xmm9, %xmm9
	vpblendw	$12, %xmm2, %xmm3, %xmm12
	vpshufb		%xmm7, %xmm1, %xmm1
	vpaddd		%xmm1, %xmm8, %xmm8
	vpxor		%xmm8, %xmm0, %xmm10
	vpslld		$20, %xmm10, %xmm0
	vpsrld		$12, %xmm10, %xmm10
	vpxor		%xmm0, %xmm10, %xmm0
	vpaddd		%xmm0, %xmm9, %xmm9
	vpxor		%xmm9, %xmm1, %xmm1
	vpshufb		%xmm6, %xmm1, %xmm1
	vpaddd		%xmm1, %xmm8, %xmm8
	vpxor		%xmm8, %xmm0, %xmm0
	vpshufd		$57, %xmm1, %xmm1
	vpshufd		$78, %xmm8, %xmm8
	vpslld		$25, %xmm0, %xmm10
	vpsrld		$7, %xmm0, %xmm0
	vpxor		%xmm10, %xmm0, %xmm0
	vpslldq		$4, %xmm5, %xmm10
	vpblendw	$240, %xmm10, %xmm12, %xmm12
	vpshufd		$147, %xmm0, %xmm0
	vpshufd		$147, %xmm12, %xmm12
	vpaddd		%xmm9, %xmm12, %xmm12
	vpaddd		%xmm0, %xmm12, %xmm12
	vpxor		%xmm12, %xmm1, %xmm1
	vpshufb		%xmm7, %xmm1, %xmm1
	vpaddd		%xmm1, %xmm8, %xmm8
	vpxor		%xmm8, %xmm0, %xmm11
	vpslld		$20, %xmm11, %xmm9
	vpsrld		$12, %xmm11, %xmm11
	vpxor		%xmm9, %xmm11, %xmm0
	vpshufd		$8, %xmm2, %xmm9
	vpblendw	$192, %xmm5, %xmm3, %xmm11
	vpblendw	$240, %xmm11, %xmm9, %xmm9
	vpshufd		$177, %xmm9, %xmm9
	vpaddd		%xmm12, %xmm9, %xmm9
	vpaddd		%xmm0, %xmm9, %xmm11
	vpxor		%xmm11, %xmm1, %xmm1
	vpshufb		%xmm6, %xmm1, %xmm1
	vpaddd		%xmm1, %xmm8, %xmm8
	vpxor		%xmm8, %xmm0, %xmm9
	vpshufd		$147, %xmm1, %xmm1
	vpshufd		$78, %xmm8, %xmm8
	vpslld		$25, %xmm9, %xmm0
	vpsrld		$7, %xmm9, %xmm9
	vpxor		%xmm0, %xmm9, %xmm0
	vpslldq		$4, %xmm3, %xmm9
	vpblendw	$48, %xmm9, %xmm2, %xmm9
	vpblendw	$240, %xmm9, %xmm4, %xmm9
	vpshufd		$57, %xmm0, %xmm0
	vpshufd		$177, %xmm9, %xmm9
	vpaddd		%xmm11, %xmm9, %xmm9
	vpaddd		%xmm0, %xmm9, %xmm9
	vpxor		%xmm9, %xmm1, %xmm1
	vpshufb		%xmm7, %xmm1, %xmm1
	vpaddd		%xmm1, %xmm8, %xmm11
	vpxor		%xmm11, %xmm0, %xmm0
	vpslld		$20, %xmm0, %xmm8
	vpsrld		$12, %xmm0, %xmm0
	vpxor		%xmm8, %xmm0, %xmm0
	vpunpckhdq	%xmm3, %xmm4, %xmm8
	vpblendw	$12, %xmm10, %xmm8, %xmm12
	vpshufd		$177, %xmm12, %xmm12
	vpaddd		%xmm9, %xmm12, %xmm9
	vpaddd		%xmm0, %xmm9, %xmm9
	vpxor		%xmm9, %xmm1, %xmm1
	vpshufb		%xmm6, %xmm1, %xmm1
	vpaddd		%xmm1, %xmm11, %xmm11
	vpxor		%xmm11, %xmm0, %xmm0
	vpshufd		$57, %xmm1, %xmm1
	vpshufd		$78, %xmm11, %xmm11
	vpslld		$25, %xmm0, %xmm12
	vpsrld		$7, %xmm0, %xmm0
	vpxor		%xmm12, %xmm0, %xmm0
	vpunpckhdq	%xmm5, %xmm2, %xmm12
	vpshufd		$147, %xmm0, %xmm0
	vpblendw	$15, %xmm13, %xmm12, %xmm12
	vpslldq		$8, %xmm5, %xmm13
	vpshufd		$210, %xmm12, %xmm12
	vpaddd		%xmm9, %xmm12, %xmm9
	vpaddd		%xmm0, %xmm9, %xmm9
	vpxor		%xmm9, %xmm1, %xmm1
	vpshufb		%xmm7, %xmm1, %xmm1
	vpaddd		%xmm1, %xmm11, %xmm11
	vpxor		%xmm11, %xmm0, %xmm0
	vpslld		$20, %xmm0, %xmm12
	vpsrld		$12, %xmm0, %xmm0
	vpxor		%xmm12, %xmm0, %xmm0
	vpunpckldq	%xmm4, %xmm2, %xmm12
	vpblendw	$240, %xmm4, %xmm12, %xmm12
	vpblendw	$192, %xmm13, %xmm12, %xmm12
	vpsrldq		$12, %xmm3, %xmm13
	vpaddd		%xmm12, %xmm9, %xmm9
	vpaddd		%xmm0, %xmm9, %xmm9
	vpxor		%xmm9, %xmm1, %xmm1
	vpshufb		%xmm6, %xmm1, %xmm1
	vpaddd		%xmm1, %xmm11, %xmm11
	vpxor		%xmm11, %xmm0, %xmm0
	vpshufd		$147, %xmm1, %xmm1
	vpshufd		$78, %xmm11, %xmm11
	vpslld		$25, %xmm0, %xmm12
	vpsrld		$7, %xmm0, %xmm0
	vpxor		%xmm12, %xmm0, %xmm0
	vpblendw	$60, %xmm2, %xmm4, %xmm12
	vpblendw	$3, %xmm13, %xmm12, %xmm12
	vpshufd		$57, %xmm0, %xmm0
	vpshufd		$78, %xmm12, %xmm12
	vpaddd		%xmm9, %xmm12, %xmm9
	vpaddd		%xmm0, %xmm9, %xmm9
	vpxor		%xmm9, %xmm1, %xmm1
	vpshufb		%xmm7, %xmm1, %xmm1
	vpaddd		%xmm1, %xmm11, %xmm11
	vpxor		%xmm11, %xmm0, %xmm12
	vpslld		$20, %xmm12, %xmm13
	vpsrld		$12, %xmm12, %xmm0
	vpblendw	$51, %xmm3, %xmm4, %xmm12
	vpxor		%xmm13, %xmm0, %xmm0
	vpblendw	$192, %xmm10, %xmm12, %xmm10
	vpslldq		$8, %xmm2, %xmm12
	vpshufd		$27, %xmm10, %xmm10
	vpaddd		%xmm9, %xmm10, %xmm9
	vpaddd		%xmm0, %xmm9, %xmm9
	vpxor		%xmm9, %xmm1, %xmm1
	vpshufb		%xmm6, %xmm1, %xmm1
	vpaddd		%xmm1, %xmm11, %xmm11
	vpxor		%xmm11, %xmm0, %xmm0
	vpshufd		$57, %xmm1, %xmm1
	vpshufd		$78, %xmm11, %xmm11
	vpslld		$25, %xmm0, %xmm10
	vpsrld		$7, %xmm0, %xmm0
	vpxor		%xmm10, %xmm0, %xmm0
	vpunpckhdq	%xmm2, %xmm8, %xmm10
	vpshufd		$147, %xmm0, %xmm0
	vpblendw	$12, %xmm5, %xmm10, %xmm10
	vpshufd		$210, %xmm10, %xmm10
	vpaddd		%xmm9, %xmm10, %xmm9
	vpaddd		%xmm0, %xmm9, %xmm9
	vpxor		%xmm9, %xmm1, %xmm1
	vpshufb		%xmm7, %xmm1, %xmm1
	vpaddd		%xmm1, %xmm11, %xmm11
	vpxor		%xmm11, %xmm0, %xmm10
	vpslld		$20, %xmm10, %xmm0
	vpsrld		$12, %xmm10, %xmm10
	vpxor		%xmm0, %xmm10, %xmm0
	vpblendw	$12, %xmm4, %xmm5, %xmm10
	vpblendw	$192, %xmm12, %xmm10, %xmm10
	vpunpckldq	%xmm2, %xmm4, %xmm12
	vpshufd		$135, %xmm10, %xmm10
	vpaddd		%xmm9, %xmm10, %xmm9
	vpaddd		%xmm0, %xmm9, %xmm9
	vpxor		%xmm9, %xmm1, %xmm1
	vpshufb		%xmm6, %xmm1, %xmm1
	vpaddd		%xmm1, %xmm11, %xmm13
	vpxor		%xmm13, %xmm0, %xmm0
	vpshufd		$147, %xmm1, %xmm1
	vpshufd		$78, %xmm13, %xmm13
	vpslld		$25, %xmm0, %xmm10
	vpsrld		$7, %xmm0, %xmm0
	vpxor		%xmm10, %xmm0, %xmm0
	vpblendw	$15, %xmm3, %xmm4, %xmm10
	vpblendw	$192, %xmm5, %xmm10, %xmm10
	vpshufd		$57, %xmm0, %xmm0
	vpshufd		$198, %xmm10, %xmm10
	vpaddd		%xmm9, %xmm10, %xmm10
	vpaddd		%xmm0, %xmm10, %xmm10
	vpxor		%xmm10, %xmm1, %xmm1
	vpshufb		%xmm7, %xmm1, %xmm1
	vpaddd		%xmm1, %xmm13, %xmm13
	vpxor		%xmm13, %xmm0, %xmm9
	vpslld		$20, %xmm9, %xmm0
	vpsrld		$12, %xmm9, %xmm9
	vpxor		%xmm0, %xmm9, %xmm0
	vpunpckhdq	%xmm2, %xmm3, %xmm9
	vpunpcklqdq	%xmm12, %xmm9, %xmm15
	vpunpcklqdq	%xmm12, %xmm8, %xmm12
	vpblendw	$15, %xmm5, %xmm8, %xmm8
	vpaddd		%xmm15, %xmm10, %xmm15
	vpaddd		%xmm0, %xmm15, %xmm15
	vpxor		%xmm15, %xmm1, %xmm1
	vpshufd		$141, %xmm8, %xmm8
	vpshufb		%xmm6, %xmm1, %xmm1
	vpaddd		%xmm1, %xmm13, %xmm13
	vpxor		%xmm13, %xmm0, %xmm0
	vpshufd		$57, %xmm1, %xmm1
	vpshufd		$78, %xmm13, %xmm13
	vpslld		$25, %xmm0, %xmm10
	vpsrld		$7, %xmm0, %xmm0
	vpxor		%xmm10, %xmm0, %xmm0
	vpunpcklqdq	%xmm2, %xmm3, %xmm10
	vpshufd		$147, %xmm0, %xmm0
	vpblendw	$51, %xmm14, %xmm10, %xmm14
	vpshufd		$135, %xmm14, %xmm14
	vpaddd		%xmm15, %xmm14, %xmm14
	vpaddd		%xmm0, %xmm14, %xmm14
	vpxor		%xmm14, %xmm1, %xmm1
	vpunpcklqdq	%xmm3, %xmm4, %xmm15
	vpshufb		%xmm7, %xmm1, %xmm1
	vpaddd		%xmm1, %xmm13, %xmm13
	vpxor		%xmm13, %xmm0, %xmm0
	vpslld		$20, %xmm0, %xmm11
	vpsrld		$12, %xmm0, %xmm0
	vpxor		%xmm11, %xmm0, %xmm0
	vpunpckhqdq	%xmm5, %xmm3, %xmm11
	vpblendw	$51, %xmm15, %xmm11, %xmm11
	vpunpckhqdq	%xmm3, %xmm5, %xmm15
	vpaddd		%xmm11, %xmm14, %xmm11
	vpaddd		%xmm0, %xmm11, %xmm11
	vpxor		%xmm11, %xmm1, %xmm1
	vpshufb		%xmm6, %xmm1, %xmm1
	vpaddd		%xmm1, %xmm13, %xmm13
	vpxor		%xmm13, %xmm0, %xmm0
	vpshufd		$147, %xmm1, %xmm1
	vpshufd		$78, %xmm13, %xmm13
	vpslld		$25, %xmm0, %xmm14
	vpsrld		$7, %xmm0, %xmm0
	vpxor		%xmm14, %xmm0, %xmm14
	vpunpckhqdq	%xmm4, %xmm2, %xmm0
	vpshufd		$57, %xmm14, %xmm14
	vpblendw	$51, %xmm15, %xmm0, %xmm15
	vpaddd		%xmm15, %xmm11, %xmm15
	vpaddd		%xmm14, %xmm15, %xmm15
	vpxor		%xmm15, %xmm1, %xmm1
	vpshufb		%xmm7, %xmm1, %xmm1
	vpaddd		%xmm1, %xmm13, %xmm13
	vpxor		%xmm13, %xmm14, %xmm14
	vpslld		$20, %xmm14, %xmm11
	vpsrld		$12, %xmm14, %xmm14
	vpxor		%xmm11, %xmm14, %xmm14
	vpblendw	$3, %xmm2, %xmm4, %xmm11
	vpslldq		$8, %xmm11, %xmm0
	vpblendw	$15, %xmm5, %xmm0, %xmm0
	vpshufd		$99, %xmm0, %xmm0
	vpaddd		%xmm15, %xmm0, %xmm15
	vpaddd		%xmm14, %xmm15, %xmm15
	vpxor		%xmm15, %xmm1, %xmm0
	vpaddd		%xmm12, %xmm15, %xmm15
	vpshufb		%xmm6, %xmm0, %xmm0
	vpaddd		%xmm0, %xmm13, %xmm13
	vpxor		%xmm13, %xmm14, %xmm14
	vpshufd		$57, %xmm0, %xmm0
	vpshufd		$78, %xmm13, %xmm13
	vpslld		$25, %xmm14, %xmm1
	vpsrld		$7, %xmm14, %xmm14
	vpxor		%xmm1, %xmm14, %xmm14
	vpblendw	$3, %xmm5, %xmm4, %xmm1
	vpshufd		$147, %xmm14, %xmm14
	vpaddd		%xmm14, %xmm15, %xmm15
	vpxor		%xmm15, %xmm0, %xmm0
	vpshufb		%xmm7, %xmm0, %xmm0
	vpaddd		%xmm0, %xmm13, %xmm13
	vpxor		%xmm13, %xmm14, %xmm14
	vpslld		$20, %xmm14, %xmm12
	vpsrld		$12, %xmm14, %xmm14
	vpxor		%xmm12, %xmm14, %xmm14
	vpsrldq		$4, %xmm2, %xmm12
	vpblendw	$60, %xmm12, %xmm1, %xmm1
	vpaddd		%xmm1, %xmm15, %xmm15
	vpaddd		%xmm14, %xmm15, %xmm15
	vpxor		%xmm15, %xmm0, %xmm0
	vpblendw	$12, %xmm4, %xmm3, %xmm1
	vpshufb		%xmm6, %xmm0, %xmm0
	vpaddd		%xmm0, %xmm13, %xmm13
	vpxor		%xmm13, %xmm14, %xmm14
	vpshufd		$147, %xmm0, %xmm0
	vpshufd		$78, %xmm13, %xmm13
	vpslld		$25, %xmm14, %xmm12
	vpsrld		$7, %xmm14, %xmm14
	vpxor		%xmm12, %xmm14, %xmm14
	vpsrldq		$4, %xmm5, %xmm12
	vpblendw	$48, %xmm12, %xmm1, %xmm1
	vpshufd		$33, %xmm5, %xmm12
	vpshufd		$57, %xmm14, %xmm14
	vpshufd		$108, %xmm1, %xmm1
	vpblendw	$51, %xmm12, %xmm10, %xmm12
	vpaddd		%xmm15, %xmm1, %xmm15
	vpaddd		%xmm14, %xmm15, %xmm15
	vpxor		%xmm15, %xmm0, %xmm0
	vpaddd		%xmm12, %xmm15, %xmm15
	vpshufb		%xmm7, %xmm0, %xmm0
	vpaddd		%xmm0, %xmm13, %xmm1
	vpxor		%xmm1, %xmm14, %xmm14
	vpslld		$20, %xmm14, %xmm13
	vpsrld		$12, %xmm14, %xmm14
	vpxor		%xmm13, %xmm14, %xmm14
	vpslldq		$12, %xmm3, %xmm13
	vpaddd		%xmm14, %xmm15, %xmm15
	vpxor		%xmm15, %xmm0, %xmm0
	vpshufb		%xmm6, %xmm0, %xmm0
	vpaddd		%xmm0, %xmm1, %xmm1
	vpxor		%xmm1, %xmm14, %xmm14
	vpshufd		$57, %xmm0, %xmm0
	vpshufd		$78, %xmm1, %xmm1
	vpslld		$25, %xmm14, %xmm12
	vpsrld		$7, %xmm14, %xmm14
	vpxor		%xmm12, %xmm14, %xmm14
	vpblendw	$51, %xmm5, %xmm4, %xmm12
	vpshufd		$147, %xmm14, %xmm14
	vpblendw	$192, %xmm13, %xmm12, %xmm12
	vpaddd		%xmm12, %xmm15, %xmm15
	vpaddd		%xmm14, %xmm15, %xmm15
	vpxor		%xmm15, %xmm0, %xmm0
	vpsrldq		$4, %xmm3, %xmm12
	vpshufb		%xmm7, %xmm0, %xmm0
	vpaddd		%xmm0, %xmm1, %xmm1
	vpxor		%xmm1, %xmm14, %xmm14
	vpslld		$20, %xmm14, %xmm13
	vpsrld		$12, %xmm14, %xmm14
	vpxor		%xmm13, %xmm14, %xmm14
	vpblendw	$48, %xmm2, %xmm5, %xmm13
	vpblendw	$3, %xmm12, %xmm13, %xmm13
	vpshufd		$156, %xmm13, %xmm13
	vpaddd		%xmm15, %xmm13, %xmm15
	vpaddd		%xmm14, %xmm15, %xmm15
	vpxor		%xmm15, %xmm0, %xmm0
	vpshufb		%xmm6, %xmm0, %xmm0
	vpaddd		%xmm0, %xmm1, %xmm1
	vpxor		%xmm1, %xmm14, %xmm14
	vpshufd		$147, %xmm0, %xmm0
	vpshufd		$78, %xmm1, %xmm1
	vpslld		$25, %xmm14, %xmm13
	vpsrld		$7, %xmm14, %xmm14
	vpxor		%xmm13, %xmm14, %xmm14
	vpunpcklqdq	%xmm2, %xmm4, %xmm13
	vpshufd		$57, %xmm14, %xmm14
	vpblendw	$12, %xmm12, %xmm13, %xmm12
	vpshufd		$180, %xmm12, %xmm12
	vpaddd		%xmm15, %xmm12, %xmm15
	vpaddd		%xmm14, %xmm15, %xmm15
	vpxor		%xmm15, %xmm0, %xmm0
	vpshufb		%xmm7, %xmm0, %xmm0
	vpaddd		%xmm0, %xmm1, %xmm1
	vpxor		%xmm1, %xmm14, %xmm14
	vpslld		$20, %xmm14, %xmm12
	vpsrld		$12, %xmm14, %xmm14
	vpxor		%xmm12, %xmm14, %xmm14
	vpunpckhqdq	%xmm9, %xmm4, %xmm12
	vpshufd		$198, %xmm12, %xmm12
	vpaddd		%xmm15, %xmm12, %xmm15
	vpaddd		%xmm14, %xmm15, %xmm15
	vpxor		%xmm15, %xmm0, %xmm0
	vpaddd		%xmm15, %xmm8, %xmm15
	vpshufb		%xmm6, %xmm0, %xmm0
	vpaddd		%xmm0, %xmm1, %xmm1
	vpxor		%xmm1, %xmm14, %xmm14
	vpshufd		$57, %xmm0, %xmm0
	vpshufd		$78, %xmm1, %xmm1
	vpslld		$25, %xmm14, %xmm12
	vpsrld		$7, %xmm14, %xmm14
	vpxor		%xmm12, %xmm14, %xmm14
	vpsrldq		$4, %xmm4, %xmm12
	vpshufd		$147, %xmm14, %xmm14
	vpaddd		%xmm14, %xmm15, %xmm15
	vpxor		%xmm15, %xmm0, %xmm0
	vpshufb		%xmm7, %xmm0, %xmm0
	vpaddd		%xmm0, %xmm1, %xmm1
	vpxor		%xmm1, %xmm14, %xmm14
	vpslld		$20, %xmm14, %xmm8
	vpsrld		$12, %xmm14, %xmm14
	vpxor		%xmm14, %xmm8, %xmm14
	vpblendw	$48, %xmm5, %xmm2, %xmm8
	vpblendw	$3, %xmm12, %xmm8, %xmm8
	vpunpckhqdq	%xmm5, %xmm4, %xmm12
	vpshufd		$75, %xmm8, %xmm8
	vpblendw	$60, %xmm10, %xmm12, %xmm10
	vpaddd		%xmm15, %xmm8, %xmm15
	vpaddd		%xmm14, %xmm15, %xmm15
	vpxor		%xmm0, %xmm15, %xmm0
	vpshufd		$45, %xmm10, %xmm10
	vpshufb		%xmm6, %xmm0, %xmm0
	vpaddd		%xmm15, %xmm10, %xmm15
	vpaddd		%xmm0, %xmm1, %xmm1
	vpxor		%xmm1, %xmm14, %xmm14
	vpshufd		$147, %xmm0, %xmm0
	vpshufd		$78, %xmm1, %xmm1
	vpslld		$25, %xmm14, %xmm8
	vpsrld		$7, %xmm14, %xmm14
	vpxor		%xmm14, %xmm8, %xmm8
	vpshufd		$57, %xmm8, %xmm8
	vpaddd		%xmm8, %xmm15, %xmm15
	vpxor		%xmm0, %xmm15, %xmm0
	vpshufb		%xmm7, %xmm0, %xmm0
	vpaddd		%xmm0, %xmm1, %xmm1
	vpxor		%xmm8, %xmm1, %xmm8
	vpslld		$20, %xmm8, %xmm10
	vpsrld		$12, %xmm8, %xmm8
	vpxor		%xmm8, %xmm10, %xmm10
	vpunpckldq	%xmm3, %xmm4, %xmm8
	vpunpcklqdq	%xmm9, %xmm8, %xmm9
	vpaddd		%xmm9, %xmm15, %xmm9
	vpaddd		%xmm10, %xmm9, %xmm9
	vpxor		%xmm0, %xmm9, %xmm8
	vpshufb		%xmm6, %xmm8, %xmm8
	vpaddd		%xmm8, %xmm1, %xmm1
	vpxor		%xmm1, %xmm10, %xmm10
	vpshufd		$57, %xmm8, %xmm8
	vpshufd		$78, %xmm1, %xmm1
	vpslld		$25, %xmm10, %xmm12
	vpsrld		$7, %xmm10, %xmm10
	vpxor		%xmm10, %xmm12, %xmm10
	vpblendw	$48, %xmm4, %xmm3, %xmm12
	vpshufd		$147, %xmm10, %xmm0
	vpunpckhdq	%xmm5, %xmm3, %xmm10
	vpshufd		$78, %xmm12, %xmm12
	vpunpcklqdq	%xmm4, %xmm10, %xmm10
	vpblendw	$192, %xmm2, %xmm10, %xmm10
	vpshufhw	$78, %xmm10, %xmm10
	vpaddd		%xmm10, %xmm9, %xmm10
	vpaddd		%xmm0, %xmm10, %xmm10
	vpxor		%xmm8, %xmm10, %xmm8
	vpshufb		%xmm7, %xmm8, %xmm8
	vpaddd		%xmm8, %xmm1, %xmm1
	vpxor		%xmm0, %xmm1, %xmm9
	vpslld		$20, %xmm9, %xmm0
	vpsrld		$12, %xmm9, %xmm9
	vpxor		%xmm9, %xmm0, %xmm0
	vpunpckhdq	%xmm5, %xmm4, %xmm9
	vpblendw	$240, %xmm9, %xmm2, %xmm13
	vpshufd		$39, %xmm13, %xmm13
	vpaddd		%xmm10, %xmm13, %xmm10
	vpaddd		%xmm0, %xmm10, %xmm10
	vpxor		%xmm8, %xmm10, %xmm8
	vpblendw	$12, %xmm4, %xmm2, %xmm13
	vpshufb		%xmm6, %xmm8, %xmm8
	vpslldq		$4, %xmm13, %xmm13
	vpblendw	$15, %xmm5, %xmm13, %xmm13
	vpaddd		%xmm8, %xmm1, %xmm1
	vpxor		%xmm1, %xmm0, %xmm0
	vpaddd		%xmm13, %xmm10, %xmm13
	vpshufd		$147, %xmm8, %xmm8
	vpshufd		$78, %xmm1, %xmm1
	vpslld		$25, %xmm0, %xmm14
	vpsrld		$7, %xmm0, %xmm0
	vpxor		%xmm0, %xmm14, %xmm14
	vpshufd		$57, %xmm14, %xmm14
	vpaddd		%xmm14, %xmm13, %xmm13
	vpxor		%xmm8, %xmm13, %xmm8
	vpaddd		%xmm13, %xmm12, %xmm12
	vpshufb		%xmm7, %xmm8, %xmm8
	vpaddd		%xmm8, %xmm1, %xmm1
	vpxor		%xmm14, %xmm1, %xmm14
	vpslld		$20, %xmm14, %xmm10
	vpsrld		$12, %xmm14, %xmm14
	vpxor		%xmm14, %xmm10, %xmm10
	vpaddd		%xmm10, %xmm12, %xmm12
	vpxor		%xmm8, %xmm12, %xmm8
	vpshufb		%xmm6, %xmm8, %xmm8
	vpaddd		%xmm8, %xmm1, %xmm1
	vpxor		%xmm1, %xmm10, %xmm0
	vpshufd		$57, %xmm8, %xmm8
	vpshufd		$78, %xmm1, %xmm1
	vpslld		$25, %xmm0, %xmm10
	vpsrld		$7, %xmm0, %xmm0
	vpxor		%xmm0, %xmm10, %xmm10
	vpblendw	$48, %xmm2, %xmm3, %xmm0
	vpblendw	$15, %xmm11, %xmm0, %xmm0
	vpshufd		$147, %xmm10, %xmm10
	vpshufd		$114, %xmm0, %xmm0
	vpaddd		%xmm12, %xmm0, %xmm0
	vpaddd		%xmm10, %xmm0, %xmm0
	vpxor		%xmm8, %xmm0, %xmm8
	vpshufb		%xmm7, %xmm8, %xmm8
	vpaddd		%xmm8, %xmm1, %xmm1
	vpxor		%xmm10, %xmm1, %xmm10
	vpslld		$20, %xmm10, %xmm11
	vpsrld		$12, %xmm10, %xmm10
	vpxor		%xmm10, %xmm11, %xmm10
	vpslldq		$4, %xmm4, %xmm11
	vpblendw	$192, %xmm11, %xmm3, %xmm3
	vpunpckldq	%xmm5, %xmm4, %xmm4
	vpshufd		$99, %xmm3, %xmm3
	vpaddd		%xmm0, %xmm3, %xmm3
	vpaddd		%xmm10, %xmm3, %xmm3
	vpxor		%xmm8, %xmm3, %xmm11
	vpunpckldq	%xmm5, %xmm2, %xmm0
	vpblendw	$192, %xmm2, %xmm5, %xmm2
	vpshufb		%xmm6, %xmm11, %xmm11
	vpunpckhqdq	%xmm0, %xmm9, %xmm0
	vpblendw	$15, %xmm4, %xmm2, %xmm4
	vpaddd		%xmm11, %xmm1, %xmm1
	vpxor		%xmm1, %xmm10, %xmm10
	vpshufd		$147, %xmm11, %xmm11
	vpshufd		$201, %xmm0, %xmm0
	vpslld		$25, %xmm10, %xmm8
	vpsrld		$7, %xmm10, %xmm10
	vpxor		%xmm10, %xmm8, %xmm10
	vpshufd		$78, %xmm1, %xmm1
	vpaddd		%xmm3, %xmm0, %xmm0
	vpshufd		$27, %xmm4, %xmm4
	vpshufd		$57, %xmm10, %xmm10
	vpaddd		%xmm10, %xmm0, %xmm0
	vpxor		%xmm11, %xmm0, %xmm11
	vpaddd		%xmm0, %xmm4, %xmm0
	vpshufb		%xmm7, %xmm11, %xmm7
	vpaddd		%xmm7, %xmm1, %xmm1
	vpxor		%xmm10, %xmm1, %xmm10
	vpslld		$20, %xmm10, %xmm8
	vpsrld		$12, %xmm10, %xmm10
	vpxor		%xmm10, %xmm8, %xmm8
	vpaddd		%xmm8, %xmm0, %xmm0
	vpxor		%xmm7, %xmm0, %xmm7
	vpshufb		%xmm6, %xmm7, %xmm6
	vpaddd		%xmm6, %xmm1, %xmm1
	vpxor		%xmm1, %xmm8, %xmm8
	vpshufd		$78, %xmm1, %xmm1
	vpshufd		$57, %xmm6, %xmm6
	vpslld		$25, %xmm8, %xmm2
	vpsrld		$7, %xmm8, %xmm8
	vpxor		%xmm8, %xmm2, %xmm8
	vpxor		(%rdi), %xmm1, %xmm1
	vpshufd		$147, %xmm8, %xmm8
	vpxor		%xmm0, %xmm1, %xmm0
	vmovups		%xmm0, (%rdi)
	vpxor		16(%rdi), %xmm8, %xmm0
	vpxor		%xmm6, %xmm0, %xmm6
	vmovups		%xmm6, 16(%rdi)
	ret
ENDPROC(blake2s_compress_avx)
