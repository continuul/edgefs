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
#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <errno.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef VIM_INDENT_COMP
}
#endif

#include "ccowutil.h"
/*
 * FIXME: implement...
 *
 * - add SHA-256 SSE2
 * - add SIMD/SSE2 detection
 */

int zeroblock_cmp(int hash_type, uint64_t chunklen, uint512_t *chid);

/* NOTICE: Need to match an order in crypto_table (see crypto.c) */
typedef enum {
	CRYPTO_BLAKE2B,
	CRYPTO_SHA2,
	CRYPTO_EDONR,
	CRYPTO_XXHASH,
	CRYPTO_BLAKE2BP,
	CRYPTO_END
} crypto_t;

typedef enum {
	HASH_TYPE_BEGIN,
	HASH_TYPE_BLAKE2B_256,		/* default */
	HASH_TYPE_BLAKE2B_512,
	HASH_TYPE_SHA_256,
	HASH_TYPE_SHA_512,
	HASH_TYPE_EDONR_256,
	HASH_TYPE_EDONR_512,
	HASH_TYPE_XXHASH_64,
	HASH_TYPE_XXHASH_128,
	HASH_TYPE_XXHASH_256,
	HASH_TYPE_BLAKE2BP_256,
	HASH_TYPE_BLAKE2BP_512,
	HASH_TYPE_END
} crypto_hash_t;

static char *hash_type_name[] = {
	"INVALID",
	"HASH_TYPE_BLAKE2B_256",
	"HASH_TYPE_BLAKE2B_512",
	"HASH_TYPE_SHA_256",
	"HASH_TYPE_SHA_512",
	"HASH_TYPE_EDONR_256",
	"HASH_TYPE_EDONR_512",
	"HASH_TYPE_XXHASH_64",
	"HASH_TYPE_XXHASH_128",
	"HASH_TYPE_XXHASH_256",
	"HASH_TYPE_BLAKE2BP_256",
	"HASH_TYPE_BLAKE2BP_512",
	"INVALID"
};

typedef struct crypto_type_to_method {
	crypto_t	method;
	int		keylen;
} crypto_type_to_method_t;

#define HASH_TYPE_DEFAULT		HASH_TYPE_BLAKE2B_256
#define CRYPTO_MAXKEYLEN	64	/* max key length in bytes */
#define CRYPTO_STATE_SIZE	4096

typedef struct {
	uint8_t S[CRYPTO_STATE_SIZE];
	int keylen;
	crypto_t method;
} crypto_state_t;

extern struct crypto_method_def *crypto_table;
struct crypto_method_def {
	char *name;
	int (*init)(crypto_state_t *state, crypto_t method, int keylen);
	int (*update)(crypto_state_t *state, const uint8_t *in, uint64_t len);
	int (*final)(crypto_state_t *state, uint8_t *out);
	int (*simple)(int keylen, const uint8_t *in, uint64_t len,
	    uint8_t *out);
};

/* Important: the order has to match the crypto_hash_t enum */
static crypto_type_to_method_t crypto_type_to_method[] = {
	{0,			0},	/* HASH_TYPE_BEGIN		*/
	{CRYPTO_BLAKE2B,	32},	/* HASH_TYPE_BLAKE2B_256	*/
	{CRYPTO_BLAKE2B,	64},	/* HASH_TYPE_BLAKE2B_512	*/
	{CRYPTO_SHA2,		32},	/* HASH_TYPE_SHA2_256		*/
	{CRYPTO_SHA2,		64},	/* HASH_TYPE_SHA2_512		*/
	{CRYPTO_EDONR,		32},	/* HASH_TYPE_EDONR_256		*/
	{CRYPTO_EDONR,		64},	/* HASH_TYPE_EDONR_512		*/
	{CRYPTO_XXHASH,		8},	/* HASH_TYPE_XXHASH_64		*/
	{CRYPTO_XXHASH,		16},	/* HASH_TYPE_XXHASH_128		*/
	{CRYPTO_XXHASH,		32},	/* HASH_TYPE_XXHASH_256		*/
	{CRYPTO_BLAKE2BP,	32},	/* HASH_TYPE_BLAKE2BP_256	*/
	{CRYPTO_BLAKE2BP,	64},	/* HASH_TYPE_BLAKE2BP_512	*/
};

#define CRYPTO_HASH_TYPE(_ht) ((_ht) & ~(1<<7))	/* clear enc bit */
#define CRYPTO_ENC_EN(_ht) ((_ht) & (1<<(7)))   /* check enc bit */
#define CRYPTO_ENC_SET(_ht) ((_ht) |= (1<<(7))) /* set enc bit */

static inline int
crypto_type_to_methodkey(crypto_hash_t hash_type, crypto_t *method,
    int *keylen) {
	int ht = CRYPTO_HASH_TYPE(hash_type);
	if (ht <= HASH_TYPE_BEGIN || ht >= HASH_TYPE_END)
		return -EINVAL;
	*method = crypto_type_to_method[ht].method;
	*keylen = crypto_type_to_method[ht].keylen;
	return 0;
}
static inline int
crypto_init(crypto_state_t *state, crypto_t method, int keylen) {
	return (&crypto_table[method])->init(state, method, keylen);
}
static inline int
crypto_init_with_type(crypto_state_t *state, crypto_hash_t hash_type) {
	crypto_t method;
	int keylen;
	if (crypto_type_to_methodkey(hash_type, &method, &keylen) != 0)
		return -ENOENT;
	return (&crypto_table[method])->init(state, method, keylen);
}
static inline int
crypto_update(crypto_state_t *state, const uint8_t *in, uint64_t len) {
	return (&crypto_table[state->method])->update(state, in, len);
}
static inline int
crypto_final(crypto_state_t *state, uint8_t *out) {
	return (&crypto_table[state->method])->final(state, out);
}
static inline int
crypto_hash(crypto_t method, int keylen, const uint8_t *in, uint64_t len,
    uint8_t *out) {
	return (&crypto_table[method])->simple(keylen, in, len, out);
}
static inline int
crypto_hash_with_type(crypto_hash_t hash_type, const uint8_t *in, uint64_t len,
    uint8_t *out) {
	crypto_t method;
	int keylen;
	if (crypto_type_to_methodkey(hash_type, &method, &keylen) != 0)
		return -ENOENT;
	return (&crypto_table[method])->simple(keylen, in, len, out);
}

uint32_t crc32c(uint32_t prev_crc, const void *buf, size_t len);
void crc32c_init();

#ifdef VIM_INDENT_COMP
{
#endif

#ifdef	__cplusplus
}
#endif

#endif
