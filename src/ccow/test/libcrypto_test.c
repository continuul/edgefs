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
#include <unistd.h>
#include <string.h>
#include <math.h>
#include <ctype.h>

#include "ccowutil.h"
#include "cmocka.h"
#include "common.h"
#include "crypto.h"
#include "fastlzlib.h"


Logger lg;

#define TC(f, len, alg) \
	{ #f"_"#len"_"#alg, f ## _##len ## _##alg, \
		UNIT_TEST_FUNCTION_TYPE_TEST }

static void
flipbit(void *block, int len, uint32_t bit)
{
	uint8_t * b = (uint8_t *)block;

	int byte = bit >> 3;
	bit = bit & 0x7;

	if (byte < len)
		b[byte] ^= (1 << bit);
}

/*
 * Basic sanity checks -
 * A hash function should not be reading outside the bounds of the key.
 * Flipping a bit of a key should, with overwhelmingly high probability,
 * result in a different hash.
 * Hashing the same key twice should always produce the same result.
 * The memory alignment of the key should not affect the hash result.
 */
static void
_test_sanity1(int alglen, int alg, void **state)
{
	const int reps = 3;
	const int keymax = 128;
	const int pad = 16;
	const size_t buflen = keymax + pad * 3;

	uint8_t buffer1[buflen];
	uint8_t buffer2[buflen];

	uint8_t hash1[64] = { 0 };
	uint8_t hash2[64] = { 0 };

	for (int irep = 0; irep < reps; irep++) {
		if(irep % (reps/3) == 0)
				printf(".");
		for (int len = 4; len <= keymax; len++) {
			for (int offset = pad; offset < pad * 2; offset++) {
				uint8_t *key1 = &buffer1[pad];
				uint8_t *key2 = &buffer2[pad + offset];

				unsigned int v = rand(),
					     *ptr1 = (unsigned int *)buffer1,
					     *ptr2 = (unsigned int *)buffer2;
				for (size_t j = 0; j < buflen / 4; j++) {
					ptr1[j] = (v << 16) ^ rand();
					ptr2[j] = (v << 16) ^ rand();
				}

				memcpy(key2, key1, len);

				crypto_hash(alg, alglen, key1, len, hash1);

				for(int bit = 0; bit < (len * 8); bit++) {
					/* Flip a bit, hash the key -> we
					 * should get a different result. */
					flipbit(key2, len, bit);
					crypto_hash(alg, alglen, key2, len, hash2);

					assert_int_not_equal(memcmp(hash1, hash2, 64), 0);

					/*
					 * Flip it back, hash again -> we
					 * should get the original result. */
					flipbit(key2, len, bit);
					crypto_hash(alg, alglen, key2, len, hash2);

					assert_int_equal(memcmp(hash1, hash2, 64), 0);
				}
			}
		}
	}

}
#define test_sanity1(len, alg) \
	static void test_sanity1 ## _##len ## _##alg(void **state) { \
		_test_sanity1(len, CRYPTO_ ## alg, state); \
	}
test_sanity1(32, BLAKE2B)
test_sanity1(64, BLAKE2B)
test_sanity1(32, EDONR)
test_sanity1(64, EDONR)
test_sanity1(32, SHA2)
test_sanity1(64, SHA2)
test_sanity1(8, XXHASH)
test_sanity1(16, XXHASH)
test_sanity1(32, XXHASH)
test_sanity1(32, BLAKE2BP)
test_sanity1(64, BLAKE2BP)

/*
 * Appending zero bytes to a key should always cause it to produce a different
 * hash value
 */
static void
_test_sanity2(int alglen, int alg, void **state)
{
	for(int rep = 0; rep < 100; rep++) {
		if(rep % 10 == 0)
			printf(".");

		unsigned char key[256];

		memset(key,0,sizeof(key));

		unsigned int v = rand(), *ptr = (unsigned int *)key;
		for (size_t j = 0; j < 32 / 4; j++)
			ptr[j] = (v << 16) ^ rand();

		uint32_t h1[16];
		uint32_t h2[16];

		memset(h1, 0, 64);
		memset(h2, 0, 64);

		for(int i = 0; i < 32; i++) {
			crypto_hash(alg, alglen, key, 32 + i, (uint8_t *)h1);

			assert_int_not_equal(memcmp(h1, h2, 64), 0);

			memcpy(h2, h1, 64);
		}
	}
}
#define test_sanity2(len, alg) \
	static void test_sanity2 ## _##len ## _##alg(void **state) { \
		_test_sanity2(len, CRYPTO_ ## alg, state); \
	}
test_sanity2(32, BLAKE2B)
test_sanity2(64, BLAKE2B)
test_sanity2(32, EDONR)
test_sanity2(64, EDONR)
test_sanity2(32, SHA2)
test_sanity2(64, SHA2)
test_sanity2(8, XXHASH)
test_sanity2(16, XXHASH)
test_sanity2(32, XXHASH)

static void
_test_keylen(int len, int alg, void **state)
{
#define BUFSIZE (10 * 1024 * 1024)
	uint8_t *buf = je_malloc(BUFSIZE);
	uint8_t out[64];
	crypto_state_t S;

	// make it pseudo random data
	memcpy(buf, (void*)memcpy, 1024);

	assert_int_equal(crypto_init(&S, alg, len), 0);
	assert_int_equal(crypto_update(&S, buf, BUFSIZE), 0);
	assert_int_equal(crypto_final(&S, out), 0);

	je_free(buf);
}
#define test_keylen(len, alg) \
	static void test_keylen ## _##len ## _##alg(void **state) { \
		_test_keylen(len, CRYPTO_ ## alg, state); \
	}
test_keylen(1, BLAKE2B)
test_keylen(8, BLAKE2B)
test_keylen(32, BLAKE2B)
test_keylen(33, BLAKE2B)
test_keylen(64, BLAKE2B)
test_keylen(32, EDONR)
test_keylen(64, EDONR)
test_keylen(32, SHA2)
test_keylen(64, SHA2)
test_keylen(8, XXHASH)
test_keylen(16, XXHASH)
test_keylen(32, XXHASH)

static void
_test_buflen(int len, int alg, void **state)
{
	uint8_t out[64];
	crypto_state_t S;

	uint8_t *buf = je_malloc(len);
	assert_non_null(buf);

	/* make it random data */
	memcpy(buf, (void*)memcpy, len);

	assert_int_equal(crypto_init(&S, alg, alg == CRYPTO_XXHASH ? 32 : 64), 0);
	assert_int_equal(crypto_update(&S, buf, len), 0);
	assert_int_equal(crypto_final(&S, out), 0);

	je_free(buf);
}
#define test_buflen(len, alg) \
	static void test_buflen ## _##len ## _##alg(void **state) { \
		_test_buflen(len, CRYPTO_ ## alg, state); \
	}
test_buflen(1, BLAKE2B)
test_buflen(31, BLAKE2B)
test_buflen(65, BLAKE2B)
test_buflen(1024, BLAKE2B)
test_buflen(65000, BLAKE2B)
test_buflen(1, EDONR)
test_buflen(31, EDONR)
test_buflen(65, EDONR)
test_buflen(1024, EDONR)
test_buflen(65000, EDONR)
test_buflen(1, SHA2)
test_buflen(31, SHA2)
test_buflen(65, SHA2)
test_buflen(1024, SHA2)
test_buflen(65000, SHA2)
test_buflen(1, XXHASH)
test_buflen(31, XXHASH)
test_buflen(65, XXHASH)
test_buflen(1024, XXHASH)
test_buflen(65000, XXHASH)

static void
test_hex2bin512(void **state)
{
	int err;
	uint512_t n1;
	char oid1[UINT512_BYTES * 2 + 1];
	char oid2[UINT512_BYTES * 2 + 1];

	err = crypto_hash_with_type(HASH_TYPE_DEFAULT, (uint8_t *)"test",
	    4, (uint8_t *)&n1);
	assert_int_equal(err, 0);

	uint512_dump(&n1, oid1, UINT512_BYTES * 2 + 1);
	printf("n1: %s\n", oid1);

	uint512_t n2;
	uint512_fromhex(oid1, UINT512_BYTES * 2 + 1, &n2);
	uint512_dump(&n2, oid2, UINT512_BYTES * 2 + 1);
	printf("n2: %s\n", oid2);

	assert_int_equal(memcmp(&n1, &n2, UINT512_BYTES), 0);
}

static uint64_t
get_ticks(void) {
	uint32_t lo, hi;
	__asm__ __volatile__("rdtsc" : "=a" (lo), "=d" (hi));
	return ((uint64_t)lo | ((uint64_t)hi << 32));
}

static void
_test_perf(int len, int alg, void **state)
{
#define trialsmax 4096
	size_t j, i, pass;
	static size_t trials[] = {1024, trialsmax, 0};
	static size_t lengths[] = {524288, 32768, 0};

	uint64_t allticks[trialsmax + 1] = {0};

	for (i = 0; lengths[i] != 0; i++) {
		uint8_t out[64];
		uint8_t *buffer = je_malloc(lengths[i]);
		assert_non_null(buffer);
		memset(buffer, 0x5c, lengths[i]);

		uint64_t minticks[32] = {0};
		uint64_t avgticks[32] = {0};

		/* discard the first samples while warming up */
		for (j = 0; j < trials[i]; j++) {
			crypto_hash(alg, len, buffer, lengths[i], out);
		}

		for (pass = 0; pass < trials[i]; pass++) {
			allticks[pass] = get_ticks();
			crypto_hash(alg, len, buffer, lengths[i], out);
		}
		allticks[pass] = get_ticks();
		for (pass = 0; pass < trials[i]; pass++)
			allticks[pass] = allticks[pass + 1] - allticks[pass];

		for (pass = 0, avgticks[i] = ~0ull; pass < trials[i]; pass++) {
			avgticks[i] += allticks[pass];
		}
		avgticks[i] = avgticks[i] / trials[i];

		for (pass = 0, minticks[i] = ~0ull; pass < trials[i]; pass++) {
			if (allticks[pass] < minticks[i] && allticks[pass] > 0.05 * avgticks[i]) {
				minticks[i] = allticks[pass];
			}
		}

		je_free(buffer);
		printf("%u bytes, %.0f cycles, %.2f cycles/byte\n",
		    (uint32_t)lengths[i], (double)minticks[i],
		    (double)minticks[i] / lengths[i]);
	}
}
#define test_perf(len, alg) \
	static void test_perf ## _##len ## _##alg(void **state) { \
		_test_perf(len, CRYPTO_ ## alg, state); \
	}
test_perf(32, BLAKE2B)
test_perf(64, BLAKE2B)
test_perf(32, BLAKE2BP)
test_perf(64, BLAKE2BP)
test_perf(32, EDONR)
test_perf(64, EDONR)
test_perf(32, SHA2)
test_perf(64, SHA2)
test_perf(8, XXHASH)
test_perf(16, XXHASH)
test_perf(32, XXHASH)

#define NUM_POWERS	24
#define NUM_HASHES	11
static void
zeroblock_generate(void **state)
{
	uint512_t	**chids;
	uint64_t	chid_buffer;
	int alg = 1;
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
	printf("{ \n");
	for (int h = 1; h < NUM_HASHES + 1; h++)
	{
		printf("//Hashtype: %s\n", hash_type_name[h]);
		printf("{ ");
		uint64_t start = uv_hrtime();
		for (int i = 9; i < 9 + NUM_POWERS; i++)
		{
			size_t buflen = pow(2, i);
			uint8_t *buf = je_malloc(buflen);
			uint8_t out[64] = { 0 };
			memset(buf, 0, buflen);
			//
			// compress first.. using only LZ
			//
			zfast_stream stream;
			zfast_stream_state state;
			int method = COMPRESSOR_LZ4;
			memset(&stream, 0, sizeof(stream));

			int err = fastlzlibCompressInit(&stream, &state);
			if (err) {
				log_error(lg, "Error in compress init: %d", err);
				continue;
			}

			err = fastlzlibSetCompressor(&stream, method);
			if (err) {
				log_error(lg, "Error in compress set method: %d", err);
				continue;
			}

			/*
			 *  Compress the incoming iovec, the outgoing iovec chunk must
			 *  be pre-allocated to fit the compressed data, it will be
			 *  preallocated with the same size as the input iovec.
			 */
			uint8_t *bbase = je_malloc(buflen + COMPRESSOR_NUL_HEADLEN);
			if (!bbase) {
				log_error(lg, "Error in compression out alloc");
				continue;
			}

			int have = 0, success;
			stream.next_in = buf;
			stream.avail_in = buflen;
			do {
				stream.next_out = bbase + have;
				int left = (buflen + COMPRESSOR_NUL_HEADLEN) - have;
				stream.avail_out = left;
				success = fastlzlibCompress(&stream, Z_FINISH);
				have += left - stream.avail_out;
			} while (success == Z_OK);

			fastlzlibEnd(&stream);
			int total_len = stream.total_out;
			err = crypto_hash_with_type(h, bbase, total_len, out);
			assert_int_equal(err, 0);
			je_free(buf);
			je_free(bbase);

			int j = 0;
			printf("{ { { %luLU, %luLU }, { %luLU, %luLU } }, { { %luLU, %luLU }, { %luLU, %luLU } } }",
			    *(uint64_t *)(out + 0),*(uint64_t *)(out + 8),
			    *(uint64_t *)(out + 16),*(uint64_t *)(out + 24),
			    *(uint64_t *)(out + 32), *(uint64_t *)(out + 40),
			    *(uint64_t *)(out + 48), *(uint64_t *)(out + 54));
			if (i != 8 + NUM_POWERS)
				printf (", \n");
		}
		uint64_t stop = uv_hrtime();
		fprintf(stderr, "Elapsed time: %lu ms\n", (stop - start) / (1024 * 1024));
		if (h != NUM_HASHES)
			printf(" },\n");
		else printf(" }");

	}
	printf(" };\n");

}
static void
zeroblock_verify(void **state)
{
	uint8_t test1[1024], test2[4096], test3[65536];
	uint512_t chid;
	int err;

	memset(test1, 0, 1024);
	memset(test2, 0, 4096);
	memset(test3, 0, 65536);
	// disabled until we rewrite the test to include different compression
	// types
#if 0
	err = crypto_hash_with_type(1, test1, 1024, (uint8_t *)&chid);
	assert_int_equal(err, 0);
	assert_int_equal(zeroblock_cmp(1, 1024, &chid), 0);

	err = crypto_hash_with_type(1, test2, 4096, (uint8_t *)&chid);
	assert_int_equal(err, 0);
	assert_int_equal(zeroblock_cmp(1, 4096, &chid), 0);

	err = crypto_hash_with_type(1, test3, 65536, (uint8_t *)&chid);
	assert_int_equal(err, 0);
	assert_int_equal(zeroblock_cmp(1, 65536, &chid), 0);

	err = crypto_hash_with_type(8, test1, 1024, (uint8_t *)&chid);
	assert_int_equal(err, 0);
	assert_int_equal(zeroblock_cmp(8, 1024, &chid), 0);

	err = crypto_hash_with_type(8, test2, 4096, (uint8_t *)&chid);
	assert_int_equal(err, 0);
	assert_int_equal(zeroblock_cmp(8, 4096, &chid), 0);

	err = crypto_hash_with_type(8, test3, 65536, (uint8_t *)&chid);
	assert_int_equal(err, 0);
	assert_int_equal(zeroblock_cmp(8, 65536, &chid), 0);
#endif
}
#if 0
typedef struct { uint256_t u; uint256_t l; } uint512_t;
typedef struct { uint128_t u; uint128_t l; } uint256_t;
typedef struct { uint64_t u; uint64_t l; } uint128_t;

{ { { a, b }, { c, d } }, { { e, f }, { g, h } } }
#endif

int
main()
{
	const UnitTest tests[] = {
		unit_test(test_hex2bin512),

		unit_test(zeroblock_generate),
		unit_test(zeroblock_verify),
		TC(test_perf, 32, BLAKE2B),

		TC(test_perf, 64, BLAKE2B),
		TC(test_perf, 32, BLAKE2BP),
		TC(test_perf, 64, BLAKE2BP),
		TC(test_perf, 32, EDONR),
		TC(test_perf, 64, EDONR),
		TC(test_perf, 32, SHA2),
		TC(test_perf, 64, SHA2),
		TC(test_perf, 8, XXHASH),
		TC(test_perf, 16, XXHASH),
		TC(test_perf, 32, XXHASH),
		TC(test_sanity1, 32, BLAKE2B),
		TC(test_sanity1, 64, BLAKE2B),
		TC(test_sanity1, 32, BLAKE2BP),
		TC(test_sanity1, 64, BLAKE2BP),
		TC(test_sanity1, 32, EDONR),
		TC(test_sanity1, 64, EDONR),
		TC(test_sanity1, 32, SHA2),
		TC(test_sanity1, 64, SHA2),
		TC(test_sanity1, 8, XXHASH),
		TC(test_sanity1, 16, XXHASH),
		TC(test_sanity1, 32, XXHASH),

		TC(test_sanity2, 32, BLAKE2B),
		TC(test_sanity2, 64, BLAKE2B),
		TC(test_sanity2, 32, EDONR),
		TC(test_sanity2, 64, EDONR),
		TC(test_sanity2, 32, SHA2),
		TC(test_sanity2, 64, SHA2),
		TC(test_sanity2, 8, XXHASH),
		TC(test_sanity2, 16, XXHASH),
		TC(test_sanity2, 32, XXHASH),

		TC(test_buflen, 1, BLAKE2B),
		TC(test_buflen, 31, BLAKE2B),
		TC(test_buflen, 65, BLAKE2B),
		TC(test_buflen, 1024, BLAKE2B),
		TC(test_buflen, 65000, BLAKE2B),
		TC(test_buflen, 1, EDONR),
		TC(test_buflen, 31, EDONR),
		TC(test_buflen, 65, EDONR),
		TC(test_buflen, 1024, EDONR),
		TC(test_buflen, 65000, EDONR),
		TC(test_buflen, 1, SHA2),
		TC(test_buflen, 31, SHA2),
		TC(test_buflen, 65, SHA2),
		TC(test_buflen, 1024, SHA2),
		TC(test_buflen, 65000, SHA2),
		TC(test_buflen, 1, XXHASH),
		TC(test_buflen, 31, XXHASH),
		TC(test_buflen, 65, XXHASH),
		TC(test_buflen, 1024, XXHASH),
		TC(test_buflen, 65000, XXHASH),

		TC(test_keylen, 1, BLAKE2B),
		TC(test_keylen, 8, BLAKE2B),
		TC(test_keylen, 32, BLAKE2B),
		TC(test_keylen, 33, BLAKE2B),
		TC(test_keylen, 64, BLAKE2B),
		TC(test_keylen, 32, EDONR),
		TC(test_keylen, 64, EDONR),
		TC(test_keylen, 32, SHA2),
		TC(test_keylen, 64, SHA2),
		TC(test_keylen, 8, XXHASH),
		TC(test_keylen, 16, XXHASH),
		TC(test_keylen, 32, XXHASH),
	};
	lg = Logger_create("libcrypto_test");
	load_crypto_lib();
	int err = run_tests(tests);
	unload_crypto_lib();
	return err;
}
