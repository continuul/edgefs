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
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#include "ccowutil.h"
#include "cmocka.h"
#include "common.h"
#include "fastlzlib.h"

#define DPRINT	0

#define TC(f, len, part, alg) \
	{ #f"_"#len"_"#part"_"#alg, f ## _##len ## _##part ## _##alg, \
		UNIT_TEST_FUNCTION_TYPE_TEST }

static void
_test_buflen(int size, int part, int alg, void **state)
{
	int err, i;
	int chunk_size = size;		/* input split bytes */
	int chunk_size2 = part;		/* output split bytes */
	zfast_stream stream;
	zfast_stream_state zstate;
	int success;
	uint64_t before, after;

	uint8_t *in = je_malloc(size);
	assert_non_null(in);

	/*
	 * Randomize data a bit...
	 */
	for (i = 0; i < size/8; i++)
		*((uint32_t *)in + i) = rand();

	uint8_t *out = je_malloc(size + COMPRESSOR_NUL_HEADLEN);
	assert_non_null(out);

	before = uv_hrtime();

	/*
	 * Testing stream compression
	 */
	memset(&stream, 0, sizeof(stream));

	err = fastlzlibCompressInit(&stream, &zstate);
	assert_int_equal(err, Z_OK);

	err = fastlzlibSetCompressor(&stream, alg);
	assert_int_equal(err, Z_OK);

	int last_chunk_size = size % chunk_size;
	int have = 0;
	int chunks = size / chunk_size + !!last_chunk_size;
	for (i = 0; i < chunks; i++) {

		int flush = 0;
		int is_eof = (i == chunks - 1);
		stream.next_in = in + i * chunk_size;
		stream.avail_in = (is_eof && last_chunk_size) ?
			last_chunk_size : chunk_size;
		do {
			stream.next_out = out + have;
			int left = (size + COMPRESSOR_NUL_HEADLEN) - have;
			stream.avail_out = left;

			success = fastlzlibCompress(&stream, is_eof ? Z_FINISH
			    : ( flush ? Z_SYNC_FLUSH : Z_NO_FLUSH ));

			have += left - stream.avail_out;

#if DPRINT
			printf("C: success %d have %d avail_in %d avail_out %d\n",
			    success, have, stream.avail_in, stream.avail_out);
#endif

			if (success == Z_STREAM_END) {
				/* premature EOF before end of stream */
				assert_false(stream.avail_in > 0 || !is_eof);
			}
		} while (success == Z_OK);

		/* Z_BUF_ERROR means that we need to feed more */
		if (success == Z_BUF_ERROR) {
			/* premature end of stream */
			assert_false(is_eof && stream.avail_out != 0);
			continue;
		}

		/* other stream error */
		assert_false(success < 0);
	}

	fastlzlibEnd(&stream);

	size_t csize = stream.total_out;

	after = uv_hrtime();
	printf("compressed (%.02f%%) in %"PRIu64"us\n", (100.0*csize)/(1.0*size),
	    (after - before)/1000);
	fflush(stdout);

	before = uv_hrtime();

	/*
	 * Testing stream decompression
	 */
	memset(&stream, 0, sizeof(stream));

	err = fastlzlibDecompressInit(&stream, &zstate);
	assert_int_equal(err, Z_OK);

	err = fastlzlibSetCompressor(&stream, alg);
	assert_int_equal(err, Z_OK);

	uint8_t *out2 = je_malloc(size);
	assert_non_null(out2);

	last_chunk_size = csize % chunk_size2;
	have = 0;
	chunks = csize / chunk_size2 + !!last_chunk_size;
	for (i = 0; i < chunks; i++) {

		int is_eof = (i == chunks - 1);
		stream.next_in = out + i * chunk_size2;
		stream.avail_in = (is_eof && last_chunk_size) ?
			last_chunk_size : chunk_size2;
		do {
			stream.next_out = out2 + have;
			int left = size - have;
			stream.avail_out = left;

			success = fastlzlibDecompress(&stream);

			have += left - stream.avail_out;

#if DPRINT
			printf("D: i %d success %d have %d avail_in %d avail_out %d\n",
			    i, success, have, stream.avail_in, stream.avail_out);
#endif

			if (success == Z_STREAM_END) {
				/* premature EOF before end of stream */
				assert_false(stream.avail_in > 0 || !is_eof);
			}

		} while (success == Z_OK && stream.avail_in > 0);

		/* Z_BUF_ERROR means that we need to feed more */
		if (success == Z_BUF_ERROR) {
			/* premature end of stream */
			assert_false(is_eof && stream.avail_out != 0);
			continue;
		}

		/* other stream error */
		assert_false(success < 0);
	}

	fastlzlibEnd(&stream);

	after = uv_hrtime();
	printf("decompressed in %"PRIu64"us\n", (after - before)/1000);
	fflush(stdout);

	err = memcmp(in, out2, size);
	assert_int_equal(err, 0);

	je_free(in);
	je_free(out);
	je_free(out2);
}
#define test_buflen(len, part, alg) \
	static void test_buflen ## _##len ## _##part ## _##alg(void **state) { \
		_test_buflen(len, part, COMPRESSOR_ ## alg, state); \
	}
test_buflen(1, 40000, NUL)
test_buflen(31, 40000, NUL)
test_buflen(65, 40000, NUL)
test_buflen(1024, 40000, NUL)
test_buflen(2048, 40000, NUL)
test_buflen(1048576, 40000, NUL)
test_buflen(1048576, 3000, NUL)
test_buflen(2097152, 40000, NUL)
test_buflen(3145728, 40000, NUL)
test_buflen(8388608, 40000, NUL)

test_buflen(1, 40000, FASTLZ)
test_buflen(31, 40000, FASTLZ)
test_buflen(65, 40000, FASTLZ)
test_buflen(1024, 40000, FASTLZ)
test_buflen(2048, 40000, FASTLZ)
test_buflen(3333, 40000, FASTLZ)
test_buflen(65536, 40000, FASTLZ)
test_buflen(131072, 40000, FASTLZ)
test_buflen(262144, 40000, FASTLZ)
test_buflen(1048576, 40000, FASTLZ)
test_buflen(1048576, 3000, FASTLZ)
test_buflen(2097152, 40000, FASTLZ)
test_buflen(3145728, 40000, FASTLZ)
test_buflen(8388608, 40000, FASTLZ)

test_buflen(1, 40000, LZ4)
test_buflen(31, 40000, LZ4)
test_buflen(65, 40000, LZ4)
test_buflen(1024, 40000, LZ4)
test_buflen(2048, 40000, LZ4)
test_buflen(3333, 40000, LZ4)
test_buflen(65536, 40000, LZ4)
test_buflen(131072, 40000, LZ4)
test_buflen(262144, 40000, LZ4)
test_buflen(1048576, 40000, LZ4)
test_buflen(1048576, 3000, LZ4)
test_buflen(2097152, 40000, LZ4)
test_buflen(3145728, 40000, LZ4)
test_buflen(8388608, 40000, LZ4)
test_buflen(8380000, 64821, LZ4)
test_buflen(512000, 64821, LZ4)
test_buflen(512000, 500000, LZ4)

test_buflen(1, 40000, LZ4HC)
test_buflen(31, 40000, LZ4HC)
test_buflen(65, 40000, LZ4HC)
test_buflen(1024, 40000, LZ4HC)
test_buflen(2048, 40000, LZ4HC)
test_buflen(3333, 40000, LZ4HC)
test_buflen(65536, 40000, LZ4HC)
test_buflen(131072, 40000, LZ4HC)
test_buflen(262144, 40000, LZ4HC)
test_buflen(1048576, 40000, LZ4HC)
test_buflen(1048576, 3000, LZ4HC)
test_buflen(2097152, 40000, LZ4HC)
test_buflen(3145728, 40000, LZ4HC)
test_buflen(8388608, 40000, LZ4HC)

test_buflen(1, 40000, SNAPPY)
test_buflen(31, 40000, SNAPPY)
test_buflen(65, 40000, SNAPPY)
test_buflen(1024, 40000, SNAPPY)
test_buflen(2048, 40000, SNAPPY)
test_buflen(3333, 40000, SNAPPY)
test_buflen(65536, 40000, SNAPPY)
test_buflen(131072, 40000, SNAPPY)
test_buflen(262144, 40000, SNAPPY)
test_buflen(1048576, 40000, SNAPPY)
test_buflen(1048576, 3000, SNAPPY)
test_buflen(2097152, 40000, SNAPPY)
test_buflen(3145728, 40000, SNAPPY)
test_buflen(8388608, 40000, SNAPPY)

int
main()
{
	const UnitTest tests[] = {
		TC(test_buflen, 1, 40000, NUL),
		TC(test_buflen, 31, 40000, NUL),
		TC(test_buflen, 65, 40000, NUL),
		TC(test_buflen, 1024, 40000, NUL),
		TC(test_buflen, 2048, 40000, NUL),
		TC(test_buflen, 1048576, 40000, NUL),
		TC(test_buflen, 1048576, 3000, NUL), // extream NUL stress case
		TC(test_buflen, 2097152, 40000, NUL),
		TC(test_buflen, 3145728, 40000, NUL),
		TC(test_buflen, 8388608, 40000, NUL),

		TC(test_buflen, 1, 40000, FASTLZ),
		TC(test_buflen, 31, 40000, FASTLZ),
		TC(test_buflen, 65, 40000, FASTLZ),
		TC(test_buflen, 1024, 40000, FASTLZ),
		TC(test_buflen, 2048, 40000, FASTLZ),
		TC(test_buflen, 3333, 40000, FASTLZ),
		TC(test_buflen, 65536, 40000, FASTLZ),
		TC(test_buflen, 131072, 40000, FASTLZ),
		TC(test_buflen, 262144, 40000, FASTLZ),
		TC(test_buflen, 1048576, 40000, FASTLZ),
		TC(test_buflen, 1048576, 3000, FASTLZ), // extream FASTLZ stress case
		TC(test_buflen, 2097152, 40000, FASTLZ),
		TC(test_buflen, 3145728, 40000, FASTLZ),
		TC(test_buflen, 8388608, 40000, FASTLZ),

		TC(test_buflen, 1, 40000, LZ4),
		TC(test_buflen, 31, 40000, LZ4),
		TC(test_buflen, 65, 40000, LZ4),
		TC(test_buflen, 1024, 40000, LZ4),
		TC(test_buflen, 2048, 40000, LZ4),
		TC(test_buflen, 3333, 40000, LZ4),
		TC(test_buflen, 65536, 40000, LZ4),
		TC(test_buflen, 131072, 40000, LZ4),
		TC(test_buflen, 262144, 40000, LZ4),
		TC(test_buflen, 1048576, 40000, LZ4),
		TC(test_buflen, 1048576, 3000, LZ4), // extream LZ4 stress case
		TC(test_buflen, 2097152, 40000, LZ4),
		TC(test_buflen, 3145728, 40000, LZ4),
		TC(test_buflen, 8388608, 40000, LZ4),
		TC(test_buflen, 8380000, 64821, LZ4),
		TC(test_buflen, 512000, 64821, LZ4),
		TC(test_buflen, 512000, 500000, LZ4),

		TC(test_buflen, 1, 40000, LZ4HC),
		TC(test_buflen, 31, 40000, LZ4HC),
		TC(test_buflen, 65, 40000, LZ4HC),
		TC(test_buflen, 1024, 40000, LZ4HC),
		TC(test_buflen, 2048, 40000, LZ4HC),
		TC(test_buflen, 3333, 40000, LZ4HC),
		TC(test_buflen, 65536, 40000, LZ4HC),
		TC(test_buflen, 131072, 40000, LZ4HC),
		TC(test_buflen, 262144, 40000, LZ4HC),
		TC(test_buflen, 1048576, 40000, LZ4HC),
		TC(test_buflen, 1048576, 3000, LZ4HC), // extream LZ4HC stress case
		TC(test_buflen, 2097152, 40000, LZ4HC),
		TC(test_buflen, 3145728, 40000, LZ4HC),
		TC(test_buflen, 8388608, 40000, LZ4HC),

		TC(test_buflen, 1, 40000, SNAPPY),
		TC(test_buflen, 31, 40000, SNAPPY),
		TC(test_buflen, 65, 40000, SNAPPY),
		TC(test_buflen, 1024, 40000, SNAPPY),
		TC(test_buflen, 2048, 40000, SNAPPY),
		TC(test_buflen, 3333, 40000, SNAPPY),
		TC(test_buflen, 65536, 40000, SNAPPY),
		TC(test_buflen, 131072, 40000, SNAPPY),
		TC(test_buflen, 262144, 40000, SNAPPY),
		TC(test_buflen, 1048576, 40000, SNAPPY),
		TC(test_buflen, 1048576, 3000, SNAPPY), // extream SNAPPY stress case
		TC(test_buflen, 2097152, 40000, SNAPPY),
		TC(test_buflen, 3145728, 40000, SNAPPY),
		TC(test_buflen, 8388608, 40000, SNAPPY),
	};
	return run_tests(tests);
}
