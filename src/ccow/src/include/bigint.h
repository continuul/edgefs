/*
 * Copyright (c) 2015-2018 Nexenta Systems, inc.
 *
 * This file is part of EdgeFS Project
 * (see https://github.com/Nexenta/edgefs).
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
/*
 * Source Code Copyright (C) 2013 Nexenta Systems, Inc.
 * Use is subject Nexenta Open Source License Agreement
 */
#ifndef __BIGINT_H__
#define __BIGINT_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>

#include "ccowutil.h"

/*
 * The routines in this library are based on ideas found at:
 *
 * http://www.cs.utexas.edu/users/djimenez/utsa/cs3343/lecture20.html
 *
 * and
 *
 * Donald Knuth's Long Division Algorithm D
 */

/*
 * The tests for Endian ordering are taken from:
 * http://gcc.gnu.org/onlinedocs/cpp/Common-Predefined-Macros.html
 *
 * The assumption here is that we are compiling on the target
 * architecture.  If you have to cross-compile to an architecture
 * that has a different architecture, more sophisticated techniques
 * will be required.
 */

/* The basic idea here is to support very large integers by defining
 * union overlays on 64 bit integers, 32 bit integers and 16 bit
 * integers.  All operations will be done in 16 bit quantities to
 * allow for implementation on 16 bit CPUs which will at least have
 * math for 32 bit quantities.  For efficiency, this could be upleveled
 * to the 32 bit quantities, but that may require re-thinking some of
 * the code for machines that are limited to 32 bit numbers.
 */

// FIXME: enable use of compiler optimized __uint128_t
//#if defined(__GNUC__) && UINTPTR_MAX == 0xffffffffffffffff
//	typedef __uint128_t uint128_t;
//#else
//	typedef uint64_t uint128_t[2];
//#endif
#define SZ128   128
#define SZ128_128   SZ128/128   // = 1
#define SZ128_64    SZ128/64    // = 2
#define SZ128_32    SZ128/32    // = 4
#define SZ128_16    SZ128/16    // = 8
typedef struct {
    uint64_t    big64[SZ128_64];
} uint128_t;
typedef union {
    uint128_t big128[SZ128_128];
    uint64_t big64[SZ128_64];
    uint32_t big32[SZ128_32];
    uint16_t big16[SZ128_16];
} uuint128_t;

/*
 * The number of 16-bit "digits" in a 128 bit unsigned int.  Used
 * in math routines.
 */
#define N128 SZ128_16

#define SZ256   256
#define SZ256_128   SZ256/128   // = 2
#define SZ256_64    SZ256/64    // = 4
#define SZ256_32    SZ256/32    // = 8
#define SZ256_16    SZ256/16    // =16
typedef struct {
    uint64_t    big64[SZ256_64];
} uint256_t;
typedef union {
    uint128_t big128[SZ256_128];
    uint64_t big64[SZ256_64];
    uint32_t big32[SZ256_32];
    uint16_t big16[SZ256_16];
} uuint256_t;

/*
 * The number of 16-bit "digits" in a 128 bit unsigned int.  Used
 * in math routines.
 */
#define N256 SZ256_16

#define SZ512   512
#define SZ512_128   SZ512/128   // = 4
#define SZ512_64    SZ512/64    // = 8
#define SZ512_32    SZ512/32    // =16
#define SZ512_16    SZ512/16    // =32
typedef struct {
    uint64_t    big64[SZ512_64];
} uint512_t;
typedef union {
    uint128_t big128[SZ512_128];
    uint64_t big64[SZ512_64];
    uint32_t big32[SZ512_32];
    uint16_t big16[SZ512_16];
} uuint512_t;
typedef union {
	int dummy_op;
	uint16_t op;
	struct {
		char byte1;
		char byte2;
	} op2char;
} op_t;
/*
 * The number of 16-bit "digits" in a 128 bit unsigned int.  Used
 * in math routines.
 */
#define N512 SZ512_16

/*
 * This is the workhorse routine that supports the following interfaces
 * and the shown syntax:
 *
 * R = op128(R, OP1, '+', OP2);
 * R = op128(R, OP1, '-', OP2);
 * R = op128(R, OP1, '*', OP2);
 * R = op128(R, OP1, '/', OP2);
 * R = op128(R, OP1, '++', NULL); increment (unary) Op1 unchanged
 * R = op128(R, OP1, '--', NULL); decrement (unary) Op1 unchanged
 * R = op128(R, OP1, '<-', NULL); assignment! (unary)
 * R = op128(R, OP1, '|', OP2);
 * R = op128(R, OP1, '&', OP2);
 * R = op128(R, OP1, '^', OP2);
 * R = op128(R, OP1, '~', NULL); One's Complement (unary)
 * R = op128(R, OP1, '<<', OP2); 0 << OP2 << Bitsize
 * R = op128(R, OP1, '<<', OP2);
 */
uuint128_t *op128(uuint128_t *result, uuint128_t *op1, op_t op,
    uuint128_t *op2);

/*
 * This is the ancillary routine that allows initializing a constant
 * value into bigint which is made up of a series of 64 bit quantities.
 */
uuint128_t *set128(uuint128_t *result, uint64_t op1, uint64_t op2);

/*
 * These are the logical routines used for testing bigint values.
 * They all return true or false and are suitable for if and while
 * statements.
 *
 * cmp128(OP1 '==' OP2 )
 * cmp128(OP1 '!=' OP2 )
 * cmp128(OP1 '&&' OP2 )
 * cmp128(OP1 '||' OP2 )
 * cmp128(OP1 '>' OP2 )
 * cmp128(OP1 '<' OP2 )
 * cmp128(OP1 '>=' OP2 )
 * cmp128(OP1 '<=' OP2 )
 */
bool cmp128(uuint128_t *op1, op_t op, uuint128_t *op2);

/*
 * This is the workhorse routine that supports the following interfaces
 * and the shown syntax:
 *
 * R = op256(R, OP1, '+', OP2);
 * R = op256(R, OP1, '-', OP2);
 * R = op256(R, OP1, '*', OP2);
 * R = op256(R, OP1, '/', OP2);
 * R = op256(R, OP1, '++', NULL); increment (unary) Op1 unchanged
 * R = op256(R, OP1, '--', NULL); decrement (unary) Op1 unchanged
 * R = op256(R, OP1, '<-', NULL); assignment! (unary)
 * R = op256(R, OP1, '|', OP2 );
 * R = op256(R, OP1, '&', OP2 );
 * R = op256(R, OP1, '^', OP2 );
 * R = op256(R, OP1, '~', NULL ); One's Complement (unary)
 * R = op256(R, OP1, '<<', OP2 ); 0 << OP2 << Bitsize
 * R = op256(R, OP1, '<<', OP2 );
 */
uuint256_t *op256(uuint256_t *result, uuint256_t *op1, op_t op,
    uuint256_t *op2);
/*
 * This is the ancillary routine that allows initializing a constant
 * value into bigint which is made up of a series of 64 bit quantities.
 */
uuint256_t *set256(uuint256_t *result, uint64_t op1, uint64_t op2,
    uint64_t op3, uint64_t op4);

/*
 * These are the logical routines used for testing bigint values.
 * They all return true or false and are suitable for if and while
 * statements.
 *
 * cmp256(OP1 '==' OP2);
 * cmp256(OP1 '!=' OP2);
 * cmp256(OP1 '&&' OP2);
 * cmp256(OP1 '||' OP2);
 * cmp256(OP1 '>' OP2);
 * cmp256(OP1 '<' OP2);
 * cmp256(OP1 '>=' OP2);
 * cmp256(OP1 '<=' OP2);
 */
bool cmp256(uuint256_t *op1, op_t op, uuint256_t *op2);

/*
 * This is the workhorse routine that supports the following interfaces
 * and the shown syntax:
 *
 * R = op512(R, OP1, '+', OP2);
 * R = op512(R, OP1, '-', OP2);
 * R = op512(R, OP1, '*', OP2);
 * R = op512(R, OP1, '/', OP2);
 * R = op512(R, OP1, '++', NULL); increment (unary) Op1 unchanged
 * R = op512(R, OP1, '--', NULL); decrement (unary) Op1 unchanged
 * R = op512(R, OP1, '<-', NULL); assignment! (unary)
 * R = op512(R, OP1, '|', OP2);
 * R = op512(R, OP1, '&', OP2);
 * R = op512(R, OP1, '^', OP2);
 * R = op512(R, OP1, '~', NULL); One's Complement (unary)
 * R = op512(R, OP1, '<<', OP2); 0 << OP2 << Bitsize
 * R = op512(R, OP1, '<<', OP2);
 */
uuint512_t *op512(uuint512_t *result, uuint512_t *op1, op_t op,
    uuint512_t *op2);

/*
 * This is the ancillary routine that allows initializing a constant
 * value into bigint which is made up of a series of 64 bit quantities.
 */
uuint512_t *set512(uuint512_t *result, uint64_t op1, uint64_t op2,
    uint64_t op3, uint64_t op4, uint64_t op5, uint64_t op6, uint64_t op7,
    uint64_t op8);

/*
 * These are the logical routines used for testing bigint values.
 * They all return true or false and are suitable for if and while
 * statements.
 *
 * cmp512(OP1 '==' OP2);
 * cmp512(OP1 '!=' OP2);
 * cmp512(OP1 '&&' OP2);
 * cmp512(OP1 '||' OP2);
 * cmp512(OP1 '>' OP2);
 * cmp512(OP1 '<' OP2);
 * cmp512(OP1 '>=' OP2);
 * cmp512(OP1 '<=' OP2);
 */
bool cmp512(uuint512_t *op1, op_t op, uuint512_t *op2);

#define ___BIGINT_BASE__    0x10000 /* 32,768 */

static inline char *
sdump_uuint128(uuint128_t *value, char *out, int len)
{	int index;
	int zz = 0;
	assert(len >= SZ128_16 *2 + 1);
	for (index = 128/16-1; index >= 0; index--) {
		sprintf(&out[zz], "%4X", value->big16[index]);
		zz += 4;
	}
}

static inline char *
sdump_uuint256(uuint256_t *value, char *out, int len)
{	int index;
	int zz = 0;
	assert(len >= SZ256_16 *2 + 1);
	for (index = 256/16-1; index >= 0; index--) {
		sprintf(&out[zz], "%4X", value->big16[index]);
		zz += 4;
	}
}

static inline char *
sdump_uuint512(uuint512_t *value, char *out, int len)
{	int index;
	int zz = 0;
	assert(len >= SZ512_16 *2 + 1);
	for (index = 512/16-1; index >= 0; index--) {
		sprintf(&out[zz], "%4X", value->big16[index]);
		zz += 4;
	}
}

#ifdef __cplusplus
}
#endif

#endif /* __BIGINT_H__ */
