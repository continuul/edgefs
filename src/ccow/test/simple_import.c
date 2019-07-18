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
#include <errno.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/types.h>
#include <stdio.h>

#include "ccowutil.h"
#include "cmocka.h"
#include "common.h"
#include "ccow.h"
#include "ccowd.h"

ccow_t cl = NULL;

static void
libccow_setup(void **state)
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
	int fd = open(path, O_RDONLY);
	assert_true(fd >= 0);
	char *buf = je_calloc(1, 16384);
	assert_non_null(buf);
	assert_true(read(fd, buf, 16383) != -1);
	assert_int_equal(close(fd), 0);
	assert_int_equal(ccow_tenant_init(buf, "cltest", 7, "test", 5, &cl), 0);
	je_free(buf);
}

static void
libccow_teardown(void **state)
{
	assert_non_null(cl);
	ccow_tenant_term(cl);
}
static void
simple_import(char *input_object, char *cid, char *tid, char *bid, char *oid,
    int blocksize)
{
	int err;
	struct iovec *iov;
	FILE *fd;
	struct stat fd_info;

	/* Determing input object size. */
	stat(input_object, &fd_info);
	uint64_t size = fd_info.st_size;
	/* Open the input object. */
	printf("input_object: %s\n", input_object);
	fd = fopen(input_object, "r");

	iov = je_malloc(256 * sizeof (struct iovec));

	/* Init the tenant and create the bucket if necessary. */
	libccow_setup(NULL);
	err = ccow_bucket_create(cl, bid, strlen(bid) + 1, NULL);
	if (err != -EEXIST)
		assert_int_equal(err, 0);

	uint64_t before = uv_hrtime();

	uint64_t i = 0;
	/* Chunk out the input file in memory. */
	for (i = 0; i < size / (256 * blocksize); i++) {

		int j;
		for (j = 0; j < 256; j++) {
			iov[j].iov_len = blocksize;
			iov[j].iov_base = je_malloc(iov[j].iov_len);
			assert(iov[j].iov_base != NULL);

			err = fread(iov[j].iov_base, blocksize, 1, fd);
			if (err ==0) {
				printf("ERROR READING OBJECT\n");
				abort();
			}
		}

		/* read j blocks at this point */

		ccow_completion_t c;
		err = ccow_create_completion(cl, NULL, NULL, 1, &c);
		assert_int_equal(err, 0);

		/* Put the data. */
		err = ccow_put(bid, strlen(bid) + 1, oid, strlen(oid) + 1, c, iov,
		    256, i * 256 * blocksize);
		assert_int_equal(err, 0);

		err = ccow_wait(c, -1);
		assert_int_equal(err, 0);
	}

	uint64_t after = uv_hrtime();

	printf("Wrote: %ld bytes in %.2fs : (%.2fB/s)\n", size,
	    (after - before) / 1e9, (1.0 * size) / ((after - before) / 1e9));
	fflush(stdout);

	for (uint64_t i = 0; i < 256; i++) {
		je_free(iov[i].iov_base);
	}
	je_free(iov);
	libccow_teardown(NULL);
	usleep(200000);
}



int
main(int argc, char **argv)
{
	if (argc != 4) {
		printf("Usage : simple_import [/path/to/img] [cid/tid/bid/oid of new object] [blocksize]\n \
		    Example: simple_import /tmp/data/centos.img cltest/test/bk1/vol_img 4096\n");
		return -1;
	}
	char *cid, *tid, *bid, *oid;
	char *p;
	char *output[4];
	int i = 0;
	char *sp = NULL;
	p = strtok_r(argv[2], "/", &sp);
	while (p != NULL) {
		output[i++] = p;
		p = strtok_r(NULL, "/", &sp);
	}

	simple_import(argv[1], output[0], output[1], output[2], output[3], atoi(argv[3]));
	return 0;
}

