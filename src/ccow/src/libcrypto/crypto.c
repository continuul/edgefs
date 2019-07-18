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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "blake2.h"
#include "edonr.h"
#include "xxhash.h"

#include "crypto.h"

int (*blake2b_init_dyn)(blake2b_state*, size_t);
int (*blake2b_update_dyn)(blake2b_state *S, const void *in, size_t inlen);
int (*blake2b_final_dyn)(blake2b_state *S, void *out, size_t outlen);
int (*blake2b_dyn)(void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen);

int (*blake2bp_init_dyn)(blake2bp_state *S, size_t outlen);
int (*blake2bp_update_dyn)(blake2bp_state *S, const void *in, size_t inlen);
int (*blake2bp_final_dyn)(blake2bp_state *S, void *out, size_t outlen);
int (*blake2bp_dyn)(void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen);


typedef union {
	edonr_ctx edonr[1];
	blake2b_state blake2b[1];
	blake2bp_state blake2bp[1];
	EVP_MD_CTX evp[1];
	XXH256_state_t xxhash;
} S_u;

/*
 * BLAKE2BP implementation
 */
static int
m_blake2bp_init(crypto_state_t *state, crypto_t method, int keylen)
{
	S_u *S = (S_u *)&state->S;
	state->keylen = keylen;
	state->method = method;
	return blake2bp_init_dyn(S->blake2bp, keylen);
}

static int
m_blake2bp_update(crypto_state_t *state, const uint8_t *in, uint64_t len)
{
	S_u *S = (S_u *)&state->S;
	return blake2bp_update_dyn(S->blake2bp, in, len);
}

static int
m_blake2bp_final(crypto_state_t *state, uint8_t *out)
{
	S_u *S = (S_u *)&state->S;
	if (state->keylen == 32)
		memset(out + 32, 0, 32);
	return blake2bp_final_dyn(S->blake2bp, out, state->keylen);
}

static int
m_blake2bp(int keylen, const uint8_t *in, uint64_t len, uint8_t *out)
{
	if (keylen == 32)
		memset(out + 32, 0, 32);
	return blake2bp_dyn(out, keylen, in, len, NULL, 0);
}

/*
 * BLAKE2B implementation
 */
static int
m_blake2b_init(crypto_state_t *state, crypto_t method, int keylen)
{
	S_u *S = (S_u *)&state->S;
	state->keylen = keylen;
	state->method = method;
	return blake2b_init_dyn(S->blake2b, keylen);
}

static int
m_blake2b_update(crypto_state_t *state, const uint8_t *in, uint64_t len)
{
	S_u *S = (S_u *)&state->S;
	return blake2b_update_dyn(S->blake2b, in, len);
}

static int
m_blake2b_final(crypto_state_t *state, uint8_t *out)
{
	S_u *S = (S_u *)&state->S;
	if (state->keylen == 32)
		memset(out + 32, 0, 32);
	return blake2b_final_dyn(S->blake2b, out, state->keylen);
}

static int
m_blake2b(int keylen, const uint8_t *in, uint64_t len, uint8_t *out)
{
	if (keylen == 32)
		memset(out + 32, 0, 32);
	return blake2b_dyn(out, keylen, in, len, NULL, 0);
}

/*
 * SHA2 non-SSE
 */
static int
m_sha2_init(crypto_state_t *state, crypto_t method, int keylen)
{
	S_u *S = (S_u *)&state->S;
	if (!keylen || keylen > 64)
		return -1;
	state->keylen = keylen;
	state->method = method;
	EVP_MD_CTX_init(S->evp);
	return EVP_DigestInit_ex(S->evp,
	    keylen == 64 ? EVP_sha512() : EVP_sha256(), NULL) == 0 ? -1 : 0;
}

static int
m_sha2_update(crypto_state_t *state, const uint8_t *in, uint64_t len)
{
	S_u *S = (S_u *)&state->S;
	return EVP_DigestUpdate(S->evp, in, len) == 0 ? -1 : 0;
}

static int
m_sha2_final(crypto_state_t *state, uint8_t *out)
{
	S_u *S = (S_u *)&state->S;
	if (state->keylen == 32)
		memset(out + 32, 0, 32);
	int success = EVP_DigestFinal_ex(S->evp, out, NULL);
	EVP_MD_CTX_cleanup(S->evp);
	return success == 0 ? -1 : 0;
}

static int
m_sha2(int keylen, const uint8_t *in, uint64_t len, uint8_t *out)
{
	if (keylen == 32)
		memset(out + 32, 0, 32);
	return EVP_Digest(in, len, out, NULL,
	    keylen == 64 ? EVP_sha512() : EVP_sha256(), NULL) == 0 ? -1 : 0;
}

/*
 * EDON-R
 */
static int
m_edonr_init(crypto_state_t *state, crypto_t method, int keylen)
{
	S_u *S = (S_u *)&state->S;
	state->keylen = keylen;
	state->method = method;
	if (keylen == 32)
		rhash_edonr256_init(S->edonr);
	else if (keylen == 64)
		rhash_edonr512_init(S->edonr);
	else
		return -1;
	return 0;
}

static int
m_edonr_update(crypto_state_t *state, const uint8_t *in, uint64_t len)
{
	S_u *S = (S_u *)&state->S;
	if (state->keylen == 32)
		rhash_edonr256_update(S->edonr, in, len);
	else
		rhash_edonr512_update(S->edonr, in, len);
	return 0;
}

static int
m_edonr_final(crypto_state_t *state, uint8_t *out)
{
	S_u *S = (S_u *)&state->S;
	if (state->keylen == 32) {
		memset(out + 32, 0, 32);
		rhash_edonr256_final(S->edonr, out);
	} else
		rhash_edonr512_final(S->edonr, out);
	return 0;
}

static int
m_edonr(int keylen, const uint8_t *in, uint64_t len, uint8_t *out)
{
	edonr_ctx ctx;

	if (keylen == 32) {
		memset(out + 32, 0, 32);
		rhash_edonr256_init(&ctx);
		rhash_edonr256_update(&ctx, in, len);
		rhash_edonr256_final(&ctx, out);
	} else if (keylen == 64) {
		rhash_edonr512_init(&ctx);
		rhash_edonr512_update(&ctx, in, len);
		rhash_edonr512_final(&ctx, out);
	} else
		return -1;
	return 0;
}

/*
 * XXHASH
 */
static int
m_xxhash_init(crypto_state_t *state, crypto_t method, int keylen)
{
	S_u *S = (S_u *)&state->S;
	if (keylen == 8)
		XXH64_reset((XXH64_state_t *)&S->xxhash, 0);
	else if (keylen == 16)
		XXH128_reset((XXH128_state_t *)&S->xxhash, 0);
	else if (keylen == 32)
		XXH256_reset((XXH256_state_t *)&S->xxhash, 0);
	else
		return -1;
	state->keylen = keylen;
	state->method = method;
	return 0;
}

static int
m_xxhash_update(crypto_state_t *state, const uint8_t *in, uint64_t len)
{
	S_u *S = (S_u *)&state->S;
	if (state->keylen == 8)
		XXH64_update((XXH64_state_t *)&S->xxhash, in, len);
	else if (state->keylen == 16)
		XXH128_update((XXH128_state_t *)&S->xxhash, in, len);
	else if (state->keylen == 32)
		XXH256_update((XXH256_state_t *)&S->xxhash, in, len);
	return 0;
}

static int
m_xxhash_final(crypto_state_t *state, uint8_t *out)
{
	S_u *S = (S_u *)&state->S;

	memset(out, 0, 64);
	if (state->keylen == 8)
		*(uint64_t *)out = XXH64_digest((XXH64_state_t *)&S->xxhash);
	else if (state->keylen == 16)
		XXH128_digest((XXH128_state_t *)&S->xxhash, out);
	else if (state->keylen == 32)
		XXH256_digest((XXH256_state_t *)&S->xxhash, out);
	return 0;
}

static int
m_xxhash(int keylen, const uint8_t *in, uint64_t len, uint8_t *out)
{
	memset(out, 0, 64);
	if (keylen == 8)
		*(uint64_t *)out = XXH64(in, len, 0);
	else if (keylen == 16)
		XXH128(in, len, 0, out);
	else if (keylen == 32)
		XXH256(in, len, 0, out);
	return 0;
}

static struct crypto_method_def table[] = {
	{
		.name = "blake2b",
		.init = m_blake2b_init,
		.update = m_blake2b_update,
		.final = m_blake2b_final,
		.simple = m_blake2b
	},
	{
		.name = "sha2",
		.init = m_sha2_init,
		.update = m_sha2_update,
		.final = m_sha2_final,
		.simple = m_sha2
	},
	{
		.name = "edonr",
		.init = m_edonr_init,
		.update = m_edonr_update,
		.final = m_edonr_final,
		.simple = m_edonr
	},
	{
		.name = "xxhash",
		.init = m_xxhash_init,
		.update = m_xxhash_update,
		.final = m_xxhash_final,
		.simple = m_xxhash
	},
	{
		.name = "blake2bp",
		.init = m_blake2bp_init,
		.update = m_blake2bp_update,
		.final = m_blake2bp_final,
		.simple = m_blake2bp
	},
};

struct crypto_method_def *crypto_table = table;
