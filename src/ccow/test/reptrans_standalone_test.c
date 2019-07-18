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

#include "ccow.h"
#include "ccowutil.h"
#include "cmocka.h"
#include "common.h"
#include "reptrans.h"
#include "ccow-impl.h"


#define TRANS_RTRD	"rtrd"
#define TRANS_RTKVS	"rtkvs"
#define MAX_DEV		256
#define N_VERSIONS	10
#define N_OLD_VERSIONS	5

struct enum_dev_arg {
	int n_dev;
	struct repdev **dev;
};

Logger lg;
struct repdev *devices[MAX_DEV];
const char *transport[] = { "rtlfs" };

static int chunk_write_read_delete_test(struct repdev *dev,
	size_t n_chunks, type_tag_t ttype, size_t chunks_size) {

	uint512_t* chids = je_calloc(chunks_size, sizeof(uint512_t));
	int err = 0;
	rtbuf_t *rb = rtbuf_init_alloc_one(chunks_size);
	srand(clock());

	/* Put required number of blobs */
	for(size_t i=0; i < n_chunks; i++) {
		for(size_t n=0; n < chunks_size; n++) {
			rb->bufs->base[n] = rand() % 256;
		}
		uint64_t ts = get_timestamp_us(), attr2 = 0;
		err = reptrans_put_blob_with_attr(dev, ttype, HASH_TYPE_DEFAULT, rb, &chids[i], 1, ts);
		assert_int_equal(err, 0);
		err = reptrans_get_blob_attr(dev, ttype, HASH_TYPE_DEFAULT, chids + i, &attr2);
		assert_int_equal(err, 0);
		assert_int_equal(ts, attr2);
		uint64_t attr = get_timestamp_us();
		err = reptrans_set_blob_attr(dev, ttype, HASH_TYPE_DEFAULT, chids + i, attr);
		assert_int_equal(err, 0);
		err = reptrans_get_blob_attr(dev, ttype, HASH_TYPE_DEFAULT, chids + i, &attr2);
		assert_int_equal(err, 0);
		assert_int_equal(attr, attr2);
	}
	/* Get status */
	for(size_t i=0; i < n_chunks; i++) {
		struct blob_stat bstat;
		err = reptrans_blob_stat(dev, ttype, HASH_TYPE_DEFAULT,
				&chids[i], &bstat);
		assert_int_equal(err, 0);
		assert_int_equal(bstat.size, chunks_size);
	}
	/* Read blobs */
	for(size_t i=0; i < n_chunks; i++) {
		rtbuf_t* rb_rd;
		uint512_t hid;
		err = reptrans_get_blob(dev, ttype, HASH_TYPE_DEFAULT,
				chids + i, &rb_rd);
		assert_int_equal(err, 0);

		err = rtbuf_hash(rb_rd, HASH_TYPE_DEFAULT, &hid);
		assert_int_equal(err, 0);
		err = uint512_cmp(chids + i, &hid);
		assert_int_equal(err, 0);
		rtbuf_destroy(rb_rd);
	}
	/* Change blob attributes */
	for(size_t i=0; i < n_chunks; i++) {
		uint64_t attr = 0, attr2 = 0;
		attr = get_timestamp_us();
		err = reptrans_set_blob_attr(dev, ttype, HASH_TYPE_DEFAULT, chids + i, attr);
		assert_int_equal(err, 0);
		err = reptrans_get_blob_attr(dev, ttype, HASH_TYPE_DEFAULT, chids + i, &attr2);
		assert_int_equal(err, 0);
		assert_int_equal(attr, attr2);
	}
	/* Delete blobs */
	for(size_t i=0; i < n_chunks; i++) {
		int lerr = reptrans_delete_blob(dev, ttype, HASH_TYPE_DEFAULT, &chids[i]);
		assert_int_equal(err, 0);
	}

	/* Get status */
	int n_left = 0;
	for(size_t i=0; i < n_chunks; i++) {
		struct blob_stat bstat;
		err = reptrans_blob_stat(dev, ttype, HASH_TYPE_DEFAULT,
				&chids[i], &bstat);
		if (!err) {
			printf("Chunk %lX isn't removed!\n", chids[i].u.u.u);
			n_left++;
		}
	}
	assert_int_equal(n_left, 0);
	je_free(chids);
	rtbuf_destroy(rb);
	return 0;
}

static void
enum_dev__done_cb(struct repdev *dev, void *arg, int status)
{
	struct enum_dev_arg *da = (struct enum_dev_arg *)arg;
	assert_non_null(da);
	if (status == 0)
		da->dev[da->n_dev++] = dev;
	assert_true(da->n_dev < MAX_DEV);
}

static int
libreptrans_enum(void)
{
	struct enum_dev_arg enum_arg = {0, devices};

	assert_int_equal(reptrans_enum(NULL, &enum_arg,
		    enum_dev__done_cb, 0), 0);
	return enum_arg.n_dev;
}

static int
compare_buf_version_timestamps(const void *a, const void *b)
{
	struct vlentry *aver = (struct vlentry *)a;
	struct vlentry *bver = (struct vlentry *)b;
	return bver->uvid_timestamp - aver->uvid_timestamp;
}

static void
reptrans_put_version__test(void **state)
{
	struct vmmetadata md;
	struct timeval tv;
	struct vlentry **vers = NULL;

	int err =  reptrans_init(0, NULL, NULL,
		RT_FLAG_STANDALONE | RT_FLAG_CREATE, 1, (char**)transport, NULL);

	assert_true(err > 0);

	if (err <= 0)
		return;

	err = libreptrans_enum();

	assert_true(err > 0);

	size_t i;
	uint512_t nhid = { { {0, 1}, {2, 3} }, { {4, 5}, {6, 7} } };
	memset(&md, 0, sizeof(struct vmmetadata));
	for (i = 0; i < N_VERSIONS; ++i) {
		(void)gettimeofday(&tv, NULL);
		md.uvid_timestamp = tv.tv_sec * 1000000L + tv.tv_usec;
		md.nhid = nhid;
		md.replication_count = 3;
		md.txid_generation = 1;
		assert_int_equal(reptrans_put_version(devices[0], &md, &nhid, 0), 0);
	}

	struct vlentry query = {
		.uvid_timestamp = ~0ULL,
		.generation = 0ULL
	};
	rtbuf_t *rb_vers = NULL;
	err = reptrans_get_versions(devices[0], &md.nhid, &query, &rb_vers);
	char nhidbuf[UINT512_BYTES * 2 + 1];
	uint512_dump(&md.nhid, nhidbuf, UINT512_BYTES * 2 + 1);
	log_debug(lg, "dev %s nhid %s number_of_versions %d nbufs %d\n",
		devices[0]->path, nhidbuf, (int)md.number_of_versions,
		rb_vers ? (int)rb_vers->nbufs : 0);
	assert_int_equal(err, 0);
	vers = je_malloc(sizeof(struct vlentry *) * rb_vers->nbufs);
	assert_non_null(vers);
	for (i = 0; i < rb_vers->nbufs; ++i)
		vers[i] = (struct vlentry *)rtbuf(rb_vers, i).base;

	qsort(vers, rb_vers->nbufs, sizeof(struct vlentry *),
		compare_buf_version_timestamps);

	for (i = N_OLD_VERSIONS; !err && i < rb_vers->nbufs; ++i) {
		log_debug(lg, "dev %s nhid %s delete version uvid_timestamp=%lu\n",
			devices[0]->path, nhidbuf, vers[i]->uvid_timestamp);
		err = reptrans_delete_version_entry(devices[0],
			HASH_TYPE_DEFAULT, &md.nhid, vers[i]);
		if (err)
			log_error(lg,
				"dev %s nhid %s delete version vers[%ld]->uvid_timestamp=%lu failed %d\n",
				devices[0]->path, nhidbuf, i, vers[i]->uvid_timestamp, err);
	}

	if (vers)
		je_free(vers);

	if (rb_vers)
		rtbuf_destroy(rb_vers);
	err = reptrans_get_versions(devices[0], &md.nhid, &query, &rb_vers);
	assert_int_equal(err, 0);
	assert_non_null(rb_vers);
	assert_int_equal(rb_vers->nbufs, N_OLD_VERSIONS);
	if (rb_vers)
		rtbuf_destroy(rb_vers);
}

static void
reptrans_put_getlast_version__test(void **state) {
	struct vmmetadata md;
	rtbuf_t *rb_vers = NULL;

	int err =  reptrans_init(0, NULL, NULL,
		RT_FLAG_STANDALONE | RT_FLAG_CREATE, 1, (char**)transport, NULL);

	assert_true(err > 0);

	if (err <= 0)
		return;

	err = libreptrans_enum();

	assert_true(err > 0);

	size_t i;
	srand(get_timestamp_us());
	uint512_t nhid = { { {rand(), 1}, {2, 3} }, { {4, 5}, {6, 7} } };
	struct vlentry query = {
		.uvid_timestamp = ~0ULL,
		.generation = 0ULL
	};
	memset(&md, 0, sizeof(struct vmmetadata));
	for (size_t i = 1; i < 10; ++i) {
		md.uvid_timestamp = get_timestamp_us() + 10000 - (rand() % 20000);
		md.nhid = nhid;
		md.replication_count = 3;
		md.txid_generation = i;
		assert_int_equal(reptrans_put_version(devices[0], &md, &nhid, 0), 0);
		err = reptrans_get_versions(devices[0], &nhid, &query, &rb_vers);
		assert_int_equal(err,0);
		assert_non_null(rb_vers);
		assert_int_equal(rb_vers->nbufs,i);
		struct vlentry* vlast = (struct vlentry*)rb_vers->bufs[0].base;
		assert_int_equal(vlast->generation, i);
		rtbuf_destroy(rb_vers);
	}
	err = reptrans_delete_blob(devices[0], TT_NAMEINDEX, HASH_TYPE_DEFAULT, &nhid);
	assert_int_equal(err,0);
	rb_vers = NULL;
	err = reptrans_get_versions(devices[0], &nhid, &query, &rb_vers);
	assert_int_equal(err,-ENOENT);
}


int dd = 0;

static void
libreptrans_standalone_full_test(void **state)
{
	if (dd) {
		printf("Skipped...\n");
		return;
	}

	int err =  reptrans_init(0, NULL, NULL,
			RT_FLAG_STANDALONE | RT_FLAG_CREATE, 1, (char**)transport, NULL);

	assert_true(err > 0);

	err = libreptrans_enum();

	assert_true(err > 0);

	err = chunk_write_read_delete_test(devices[0], 100, TT_CHUNK_PAYLOAD,
		4*1024);

	assert_int_equal(err,0);

}

static void
libreptrans_standalone_rw_test(void **state)
{
	int err =  reptrans_init(0, NULL, NULL,
			RT_FLAG_STANDALONE, 1, (char**)transport, NULL);

	assert_true(err > 0);

	if (err <= 0)
		return;

	err = libreptrans_enum();

	assert_true(err > 0);

	if (err <= 0)
		return;

	err = chunk_write_read_delete_test(devices[0], 100, TT_CHUNK_PAYLOAD,
			4*1024);

	assert_int_equal(err,0);
}

static void
libreptrans_standalone_ro_test(void **state)
{
	uint512_t chid;
	int err =  reptrans_init(0, NULL, NULL,
			RT_FLAG_STANDALONE | RT_FLAG_RDONLY, 1, (char**)transport, NULL);

	assert_true(err > 0);

	err = libreptrans_enum();

	assert_true(err > 0);

	rtbuf_t *rb = rtbuf_init_alloc_one(4096);
	srand(clock());
	for(size_t n=0; n < rb->bufs->len; n++) {
		rb->bufs->base[n] = rand() % 256;
	}
	uint64_t ts = get_timestamp_us(), attr2 = 0;
	err = reptrans_put_blob_with_attr(devices[0], TT_CHUNK_PAYLOAD,
		HASH_TYPE_DEFAULT, rb, &chid, 1, ts);

	assert_true(err < 0);

	rtbuf_destroy(rb);
}

static void
libreptrans_standalone_vbr_stat_test(void **state)
{
	int err =  reptrans_init(0, NULL, NULL,
			RT_FLAG_STANDALONE, 1, (char**)transport, NULL);

	assert_true(err > 0);

	if (err <= 0)
		return;

	err = libreptrans_enum();

	assert_true(err > 0);

	if (err <= 0)
		return;

	uint512_t nhid = { { {0, 0}, {1, 1} }, { {2, 2}, {3, 3} } };
	uint512_t chid = { { {0, 1}, {2, 3} }, { {4, 5}, {6, 7} } };
	chid.u.u.u = rand();
	chid.u.u.l = rand();
	uint512_t ref_chid = { { {10, 11}, {12, 13} }, { {14, 15}, {16, 17} } };
	struct backref br = {
		.name_hash_id = nhid,
		.ref_chid = ref_chid,
		.generation = 0,
		.uvid_timestamp = 0,
		.ref_type = TT_CHUNK_MANIFEST,
		.ref_hash = HASH_TYPE_DEFAULT,
		.rep_count = 1,
		.attr = VBR_ATTR_CP
	};

	rtbuf_t *rb = rtbuf_init_alloc_one(4096);
	assert_non_null(rb);

	/* this will add entry in the log */
	err = reptrans_put_blob_with_attr(devices[0], TT_CHUNK_PAYLOAD,
	    HASH_TYPE_DEFAULT, rb, &chid, 0, 111);
	assert_int_equal(err, 0);

	uint64_t attr;
	err = reptrans_get_blob_attr(devices[0], TT_CHUNK_PAYLOAD,
	    HASH_TYPE_DEFAULT, &chid, &attr);
	assert_int_equal(err, 0);
	assert_int_equal(attr, 111);

	/* should exist in the log, but we will update attr it anyways */
	err = reptrans_put_blob_with_attr(devices[0], TT_CHUNK_PAYLOAD,
	    HASH_TYPE_DEFAULT, rb, &chid, 0, 222);
	assert_int_equal(err, 0);

	/* we should be able to update attr in the log */
	err = reptrans_get_blob_attr(devices[0], TT_CHUNK_PAYLOAD,
	    HASH_TYPE_DEFAULT, &chid, &attr);
	assert_int_equal(err, 0);
	assert_int_equal(attr, 222);

	/* should be able to find and touch in the log */
	err = reptrans_set_blob_attr(devices[0], TT_CHUNK_PAYLOAD,
	    HASH_TYPE_DEFAULT, &chid, 333);
	assert_int_equal(err, 0);

	err = reptrans_get_blob_attr(devices[0], TT_CHUNK_PAYLOAD,
	    HASH_TYPE_DEFAULT, &chid, &attr);
	assert_int_equal(err, 0);
	assert_int_equal(attr, 333);

	reptrans_flush(RD_FLUSH_FORCE);
	usleep(500000);

	/* should be able to find it after flush */
	err = reptrans_get_blob_attr(devices[0], TT_CHUNK_PAYLOAD,
	    HASH_TYPE_DEFAULT, &chid, &attr);
	assert_int_equal(err, 0); /* exists! */
	assert_int_equal(attr, 333);

	struct blob_stat stat;
	err = reptrans_blob_stat(devices[0], TT_CHUNK_PAYLOAD, HASH_TYPE_DEFAULT,
	    &chid, &stat);
	assert_int_equal(err, 0); /* exists! */
	assert_int_equal(stat.size, 4096);

	/* should exist in the main, but we will update attr anyways */
	err = reptrans_put_blob_with_attr(devices[0], TT_CHUNK_PAYLOAD,
	    HASH_TYPE_DEFAULT, rb, &chid, 0, 555);
	assert_int_equal(err, 0);

	reptrans_flush(RD_FLUSH_FORCE);
	usleep(500000);

	err = reptrans_get_blob_attr(devices[0], TT_CHUNK_PAYLOAD,
	    HASH_TYPE_DEFAULT, &chid, &attr);
	assert_int_equal(err, 0);
	assert_int_equal(attr, 555);

	/* should be able to find and touch in the main */
	err = reptrans_set_blob_attr(devices[0], TT_CHUNK_PAYLOAD,
	    HASH_TYPE_DEFAULT, &chid, 444);
	assert_int_equal(err, 0);

	err = reptrans_get_blob_attr(devices[0], TT_CHUNK_PAYLOAD,
	    HASH_TYPE_DEFAULT, &chid, &attr);
	assert_int_equal(err, 0);
	assert_int_equal(attr, 444);

	br.rep_count = 1;
	br.generation = 1;
	err = reptrans_put_backref(devices[0], &chid, HASH_TYPE_DEFAULT, &br);
	assert_int_equal(err, 0);

	br.rep_count = 2;
	br.generation = 2;
	err = reptrans_put_backref(devices[0], &chid, HASH_TYPE_DEFAULT, &br);
	assert_int_equal(err, 0);

	br.rep_count = 0;
	br.generation = 2;
	err = reptrans_put_backref(devices[0], &chid, HASH_TYPE_DEFAULT, &br);
	assert_int_equal(err, 0);

	/* should return max(rep_count) */
	err = reptrans_get_chunk_rep_count(devices[0], HASH_TYPE_DEFAULT, &chid);
	assert_int_equal(err, 2);

	br.rep_count = 3;
	br.generation = 3;
	err = reptrans_put_backref(devices[0], &chid, HASH_TYPE_DEFAULT, &br);
	assert_int_equal(err, 0);

	/* should return max(rep_count) */
	err = reptrans_get_chunk_rep_count(devices[0], HASH_TYPE_DEFAULT, &chid);
	assert_int_equal(err, 3);

	size_t dupcount;
	err = reptrans_get_chunk_count(devices[0], HASH_TYPE_DEFAULT,
	    TT_VERIFIED_BACKREF, &chid, &dupcount);
	assert_int_equal(err, 0);
	assert_int_equal(dupcount, 4);
	dupcount = 0;
	err = reptrans_get_chunk_count_limited(devices[0], HASH_TYPE_DEFAULT,
	    TT_VERIFIED_BACKREF, &chid, 2, &dupcount);
	assert_int_equal(err, 0);
	assert_int_equal(dupcount, 2);
	/* Cleaning up */
	err = reptrans_delete_blob(devices[0], TT_VERIFIED_BACKREF,
		HASH_TYPE_DEFAULT, &chid);
	assert_int_equal(err, 0);
	err = reptrans_delete_blob(devices[0], TT_CHUNK_PAYLOAD,
		HASH_TYPE_DEFAULT, &chid);
	assert_int_equal(err, 0);
	srand(get_timestamp_us());
	chid.u.u.u = rand();
	for (int k = 1; k < 10000; k++) {
		chid.u.u.u += k;
		/* One more VBR put/delete/put test */
		struct backref br2 = br;
		br2.ref_chid.u.u.u += k;
		printf("Iteration %d, CHID %lX, refCHID1 %lX, refCHID2 %lX\n",
			k, chid.u.u.u, br.ref_chid.u.u.u, br2.ref_chid.u.u.u);
		/* Add two backreferences */
		err = reptrans_put_backref(devices[0], &chid, HASH_TYPE_DEFAULT, &br);
		assert_int_equal(err, 0);
		dupcount = 0;
		err = reptrans_get_chunk_count(devices[0], HASH_TYPE_DEFAULT,
		    TT_VERIFIED_BACKREF, &chid, &dupcount);
		assert_int_equal(dupcount, 1);
		err = reptrans_put_backref(devices[0], &chid, HASH_TYPE_DEFAULT, &br2);
		assert_int_equal(err, 0);
		dupcount = 0;
		/* Ensure both are there */
		err = reptrans_get_chunk_count(devices[0], HASH_TYPE_DEFAULT,
		    TT_VERIFIED_BACKREF, &chid, &dupcount);
		assert_int_equal(dupcount, 2);
		dupcount = 0;
		err = reptrans_get_chunk_count_limited(devices[0], HASH_TYPE_DEFAULT,
		    TT_VERIFIED_BACKREF, &chid, 2, &dupcount);
		assert_int_equal(err, 0);
		assert_int_equal(dupcount, 2);
		/* Put second one again and check */
		err = reptrans_put_backref(devices[0], &chid, HASH_TYPE_DEFAULT, &br);
		assert_int_equal(err, 0);
		dupcount = 0;
		err = reptrans_get_chunk_count(devices[0], HASH_TYPE_DEFAULT,
		    TT_VERIFIED_BACKREF, &chid, &dupcount);
		assert_int_equal(dupcount, 2);
		int nvbrs = 0;
		/* remove second VBR ensure it's deleted*/
		err = reptrans_delete_vbrs_all_repcounts(devices[0], &chid,
			HASH_TYPE_DEFAULT, &br2, &nvbrs);
		assert_int_equal(err, 0);
		assert_int_equal(nvbrs, 1);
		dupcount = 0;
		err = reptrans_get_chunk_count(devices[0], HASH_TYPE_DEFAULT,
		    TT_VERIFIED_BACKREF, &chid, &dupcount);
		assert_int_equal(dupcount, 1);
		/* Put both again and check */
		err = reptrans_put_backref(devices[0], &chid, HASH_TYPE_DEFAULT, &br);
		assert_int_equal(err, 0);
		dupcount = 0;
		err = reptrans_get_chunk_count(devices[0], HASH_TYPE_DEFAULT,
		    TT_VERIFIED_BACKREF, &chid, &dupcount);
		assert_int_equal(err, 0);
		assert_int_equal(dupcount, 1);
		err = reptrans_put_backref(devices[0], &chid, HASH_TYPE_DEFAULT, &br2);
		assert_int_equal(err, 0);
		dupcount = 0;
		err = reptrans_get_chunk_count(devices[0], HASH_TYPE_DEFAULT,
		    TT_VERIFIED_BACKREF, &chid, &dupcount);
		assert_int_equal(dupcount, 2);
	}
	chid.u.u.u = rand();
	for (int k = 1; k < 20; k++) {
		chid.u.u.u += k;
		/* One more VBR put/delete/put test */
		struct backref br2 = br;
		br2.ref_chid.u.u.u += k;
		printf("Iteration(flush) %d, CHID %lX, refCHID1 %lX, refCHID2 %lX\n",
			k, chid.u.u.u, br.ref_chid.u.u.u, br2.ref_chid.u.u.u);
		/* Add two backreferences */
		err = reptrans_put_backref(devices[0], &chid, HASH_TYPE_DEFAULT, &br);
		assert_int_equal(err, 0);
		dupcount = 0;
		err = reptrans_get_chunk_count(devices[0], HASH_TYPE_DEFAULT,
		    TT_VERIFIED_BACKREF, &chid, &dupcount);
		assert_int_equal(dupcount, 1);
		err = reptrans_put_backref(devices[0], &chid, HASH_TYPE_DEFAULT, &br2);
		assert_int_equal(err, 0);
		/* Ensure both are there */
		dupcount = 0;
		err = reptrans_get_chunk_count(devices[0], HASH_TYPE_DEFAULT,
		    TT_VERIFIED_BACKREF, &chid, &dupcount);
		assert_int_equal(dupcount, 2);
		reptrans_flush(RD_FLUSH_FORCE);
		usleep(500000);
		dupcount = 0;
		err = reptrans_get_chunk_count(devices[0], HASH_TYPE_DEFAULT,
		    TT_VERIFIED_BACKREF, &chid, &dupcount);
		assert_int_equal(dupcount, 2);

		/* Put second one again and check */
		err = reptrans_put_backref(devices[0], &chid, HASH_TYPE_DEFAULT, &br);
		assert_int_equal(err, 0);
		dupcount = 0;
		err = reptrans_get_chunk_count(devices[0], HASH_TYPE_DEFAULT,
		    TT_VERIFIED_BACKREF, &chid, &dupcount);
		assert_int_equal(dupcount, 2);
		reptrans_flush(RD_FLUSH_FORCE);
		usleep(500000);
		dupcount = 0;
		err = reptrans_get_chunk_count(devices[0], HASH_TYPE_DEFAULT,
		    TT_VERIFIED_BACKREF, &chid, &dupcount);
		assert_int_equal(dupcount, 2);

		int nvbrs = 0;
		/* remove second VBR ensure it's deleted*/
		err = reptrans_delete_vbrs_all_repcounts(devices[0], &chid,
			HASH_TYPE_DEFAULT, &br2, &nvbrs);
		assert_int_equal(err, 0);
		assert_int_equal(nvbrs, 1);
		dupcount = 0;
		err = reptrans_get_chunk_count(devices[0], HASH_TYPE_DEFAULT,
		    TT_VERIFIED_BACKREF, &chid, &dupcount);
		assert_int_equal(dupcount, 1);
		reptrans_flush(RD_FLUSH_FORCE);
		usleep(500000);
		dupcount = 0;
		err = reptrans_get_chunk_count(devices[0], HASH_TYPE_DEFAULT,
		    TT_VERIFIED_BACKREF, &chid, &dupcount);
		assert_int_equal(dupcount, 1);

		/* Put both again and check */
		err = reptrans_put_backref(devices[0], &chid, HASH_TYPE_DEFAULT, &br);
		assert_int_equal(err, 0);
		dupcount = 0;
		err = reptrans_get_chunk_count(devices[0], HASH_TYPE_DEFAULT,
		    TT_VERIFIED_BACKREF, &chid, &dupcount);
		assert_int_equal(err, 0);
		assert_int_equal(dupcount, 1);
		err = reptrans_put_backref(devices[0], &chid, HASH_TYPE_DEFAULT, &br2);
		assert_int_equal(err, 0);
		dupcount = 0;
		err = reptrans_get_chunk_count(devices[0], HASH_TYPE_DEFAULT,
		    TT_VERIFIED_BACKREF, &chid, &dupcount);
		assert_int_equal(dupcount, 2);

		reptrans_flush(RD_FLUSH_FORCE);
		usleep(500000);
		dupcount = 0;
		err = reptrans_get_chunk_count(devices[0], HASH_TYPE_DEFAULT,
		    TT_VERIFIED_BACKREF, &chid, &dupcount);
		assert_int_equal(dupcount, 2);

	}
	rtbuf_destroy(rb);
}

static void
random_buffer(uv_buf_t buf) {
	for (size_t n = 0; n < buf.len/sizeof(uint32_t); n++) {
		if (buf.len >= sizeof(uint32_t)) {
			uint32_t val = random();
			memcpy(buf.base, &val, sizeof(uint32_t));
			buf.base += sizeof(uint32_t);
			buf.len -= sizeof(uint32_t);
		}
	}
}

struct del_args {
	int n_blobs;
	int n_iters;
	type_tag_t ttag;
};

static void
delete_blobs_test(void **state) {
	int err =  reptrans_init(0, NULL, NULL,
		RT_FLAG_STANDALONE | RT_FLAG_CREATE, 1,
		(char**)transport, NULL);

	struct del_args targ[] = {
			{ .n_blobs = 1, .n_iters = 31, .ttag = TT_CHUNK_PAYLOAD},
			{ .n_blobs = 2, .n_iters = 30, .ttag = TT_CHUNK_PAYLOAD},
			{ .n_blobs = 2, .n_iters = 100, .ttag = TT_CHUNK_PAYLOAD},
			{ .n_blobs = 2, .n_iters = 1000, .ttag = TT_CHUNK_PAYLOAD },
			{ .n_blobs = 15, .n_iters = 100, .ttag = TT_CHUNK_PAYLOAD },
			{ .n_blobs = 39, .n_iters = 100, .ttag = TT_CHUNK_PAYLOAD },
			{ .n_blobs = 62, .n_iters = 100, .ttag = TT_CHUNK_PAYLOAD },
			{ .n_blobs = 64, .n_iters = 100, .ttag = TT_CHUNK_PAYLOAD },
			{ .n_blobs = 100, .n_iters = 50, .ttag = TT_CHUNK_PAYLOAD },
			{ .n_blobs = 128, .n_iters = 40, .ttag = TT_CHUNK_PAYLOAD },
			{ .n_blobs = 250, .n_iters = 10, .ttag = TT_CHUNK_PAYLOAD },
			{ .n_blobs = 1000, .n_iters = 5, .ttag = TT_CHUNK_PAYLOAD },
			{ .n_blobs = 1, .n_iters = 31, .ttag = TT_CHUNK_MANIFEST},
			{ .n_blobs = 2, .n_iters = 30, .ttag = TT_CHUNK_MANIFEST},
			{ .n_blobs = 2, .n_iters = 100, .ttag = TT_CHUNK_MANIFEST},
			{ .n_blobs = 2, .n_iters = 1000, .ttag = TT_CHUNK_MANIFEST },
			{ .n_blobs = 15, .n_iters = 100, .ttag = TT_CHUNK_MANIFEST },
			{ .n_blobs = 39, .n_iters = 100, .ttag = TT_CHUNK_MANIFEST },
			{ .n_blobs = 62, .n_iters = 100, .ttag = TT_CHUNK_MANIFEST },
			{ .n_blobs = 64, .n_iters = 100, .ttag = TT_CHUNK_MANIFEST },
			{ .n_blobs = 100, .n_iters = 50, .ttag = TT_CHUNK_MANIFEST },
			{ .n_blobs = 128, .n_iters = 40, .ttag = TT_CHUNK_MANIFEST },
			{ .n_blobs = 250, .n_iters = 10, .ttag = TT_CHUNK_MANIFEST },
			{ .n_blobs = 1000, .n_iters = 5, .ttag = TT_CHUNK_MANIFEST },

	};

	assert_true(err > 0);

	if (err <= 0)
		return;

	err = libreptrans_enum();

	assert_true(err > 0);

	if (err <= 0)
		return;
	struct repdev* dev = devices[0];


	srand(get_timestamp_us());

	for (size_t i = 0; i < sizeof(targ)/sizeof(targ[0]); i++) {
		size_t n_blobs = targ[i].n_blobs;
		size_t n_iters = targ[i].n_iters;
		type_tag_t ttag = targ[i].ttag;
		printf("Test %lu: %lu iteration %lu chunks each, ttag %s\n", i,
			n_iters, n_blobs, type_tag_name[ttag]);
		uint64_t del_time = 0;
		uint64_t put_time = 0;
		uint64_t stat_time = 0;
		uint64_t get_time = 0;
		for (size_t k = 0; k < n_iters; k++) {
			uint512_t* chids = je_calloc(n_blobs, sizeof(uint512_t));
			assert_non_null(chids);
			uint64_t ts = 0;
			/* Adding chunks */
			for (size_t n = 0; n < n_blobs; n++) {
				size_t len = 4096;
				uv_buf_t usr_data = { .base = je_malloc(len), .len = len};
				random_buffer(usr_data);
				rtbuf_t* rb = rtbuf_init(&usr_data, 1);
				assert_non_null(rb);
				uint512_t chid = uint512_null;
				ts = get_timestamp_us();
				int err = reptrans_put_blob_with_attr(dev, ttag,
					HASH_TYPE_DEFAULT, rb, &chid, 1, 123456LL);
				put_time += get_timestamp_us() - ts;
				assert_int_equal(err, 0);
				chids[n] = chid;
				rtbuf_destroy(rb);
			}
			/* Check presences */
			int n_got = 0;
			for (size_t n = 0; n < n_blobs; n++) {
				struct blob_stat bstat;
				ts = get_timestamp_us();
				err = reptrans_blob_stat(dev, ttag,
					HASH_TYPE_DEFAULT, chids + n, &bstat);
				stat_time += get_timestamp_us() - ts;
				if (!err)
					n_got++;
				ts = get_timestamp_us();
				rtbuf_t* rb = NULL;
				err = reptrans_get_blob(dev, ttag,
					HASH_TYPE_DEFAULT, chids + n, &rb);
				get_time += get_timestamp_us() - ts;
				assert_int_equal(err, 0);
				if (rb)
					rtbuf_destroy(rb);
			}
			assert_int_equal(n_blobs, n_got);
			/* Removing */
			for (size_t n = 0; n < n_blobs; n++) {
				ts = get_timestamp_us();
				err = reptrans_delete_blob(dev, ttag,
					HASH_TYPE_DEFAULT, chids + n);
				assert_int_equal(err, 0);
				del_time += get_timestamp_us() - ts;
			}
			/* Stat blobs again, They have to be removed */
			uint64_t n_stat = 0;
			uint64_t n_get = 0;
			for (size_t n = 0; n < n_blobs; n++) {
				rtbuf_t* rb = NULL;
				err = reptrans_get_blob(dev, ttag,
					HASH_TYPE_DEFAULT, chids + n, &rb);
				if (err != -ENOENT)
					n_get++;
				if (rb)
					rtbuf_destroy(rb);
				struct blob_stat bstat;
				ts = get_timestamp_us();
				err = reptrans_blob_stat(dev, ttag,
					HASH_TYPE_DEFAULT, chids + n, &bstat);
				stat_time += get_timestamp_us() - ts;
				if (!err)
					n_stat++;
			}
			if (n_stat)
				printf("ERROR: %lu blobs weren't removed (stat)!\n", n_stat);
			if (n_get)
				printf("ERROR: %lu blobs weren't removed (get)!\n", n_get);
			assert_int_equal(n_stat, 0);
			assert_int_equal(n_get, 0);
			je_free(chids);
		}
		printf("PUT %lu uS, GET %lu uS, STAT %lu uS, DEL %lu uS\n",
			put_time/(n_blobs*n_iters), get_time/((n_blobs*n_iters)),
			stat_time/(2*n_blobs*n_iters), del_time/(n_blobs*n_iters));
	}

	for (int i = 0; i < 100; i++) {
		/* delete/put/get pattern test */
		uv_buf_t usr_data = { .base = je_malloc(1024), .len = 1024};
		random_buffer(usr_data);
		rtbuf_t* rb = rtbuf_init(&usr_data, 1);
		assert_non_null(rb);
		uint512_t chid;
		err = rtbuf_hash(rb, HASH_TYPE_DEFAULT, &chid);
		assert_int_equal(err, 0);
		err = reptrans_delete_blob(dev, TT_CHUNK_MANIFEST, HASH_TYPE_DEFAULT, &chid);
		assert_int_equal(err, 0);
		err = reptrans_put_blob_with_attr(dev, TT_CHUNK_MANIFEST, HASH_TYPE_DEFAULT, rb, &chid, 0, 123456);
		assert_int_equal(err, 0);
		rtbuf_t* rb_get = NULL;
		err = reptrans_get_blob(dev, TT_CHUNK_MANIFEST, HASH_TYPE_DEFAULT, &chid, &rb_get);
		assert_int_equal(err, 0);
		assert_non_null(rb_get);
		assert_int_equal(rb_get->bufs->len, 1024);
		err = reptrans_delete_blob(dev, TT_CHUNK_MANIFEST, HASH_TYPE_DEFAULT, &chid);
		assert_int_equal(err, 0);
		rtbuf_destroy(rb_get);
		rtbuf_destroy(rb);
	}
}

#define N_VBRS 1024

static int
reptrans_validate_br_cb(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *chid, uv_buf_t *val, void *param)
{
	uint512_t* chids = param;
	for (int i = 0; i < N_VBRS - 1; i++) {
		if (uint512_cmp(chid, chids + i) == 0) {
			printf("Found VBR %016lX which is supposed to be deleted\n", chid->u.u.u);
			return -EINVAL;
		}
	}
	return 0;
}


static void
putall_then_delete_vbr_test(void **state) {
	int err =  reptrans_init(0, NULL, NULL,
			RT_FLAG_STANDALONE | RT_FLAG_CREATE, 1, (char**)transport, NULL);

	assert_true(err > 0);

	if (err <= 0)
		return;

	err = libreptrans_enum();

	assert_true(err > 0);

	if (err <= 0)
		return;
	struct repdev* dev = devices[0];
	size_t n_blobs = N_VBRS;
	uint512_t* chids = je_calloc(n_blobs, sizeof(uint512_t));
	assert_non_null(chids);
	srand(get_timestamp_us());
	printf("Adding %lu VBRs\n", n_blobs);
	for (size_t n = 0; n < n_blobs; n++) {
		chids[n].u.u.u = random();
		uint512_t nhid = { { {0, n}, {1, 1} }, { {2, 2}, {3, 3} } };
		uint512_t ref_chid = { { {10, 11}, {12, n} }, { {14, n}, {16, 17} } };
		struct backref br = {
			.name_hash_id = nhid,
			.ref_chid = ref_chid,
			.generation = 1,
			.uvid_timestamp = 0,
			.ref_type = TT_CHUNK_MANIFEST,
			.ref_hash = HASH_TYPE_DEFAULT,
			.rep_count = 1,
			.attr = VBR_ATTR_CP
		};
		struct blob_stat bstat;
		rtbuf_t* vbr_rb = NULL;
		err = reptrans_put_backref(dev, chids + n, HASH_TYPE_DEFAULT, &br);
		assert_int_equal(err, 0);
		err = reptrans_blob_stat(dev, TT_VERIFIED_BACKREF, HASH_TYPE_DEFAULT, chids + n, &bstat);
		assert_int_equal(err, 0);
		err = reptrans_get_blob(dev, TT_VERIFIED_BACKREF, HASH_TYPE_DEFAULT, chids + n, &vbr_rb);
		assert_int_equal(err, 0);
		assert_non_null(vbr_rb);
		rtbuf_destroy(vbr_rb);
		br.rep_count = 2;
		err = reptrans_put_backref(dev, chids + n, HASH_TYPE_DEFAULT, &br);
		assert_int_equal(err, 0);
		err = reptrans_blob_stat(dev, TT_VERIFIED_BACKREF, HASH_TYPE_DEFAULT, chids + n, &bstat);
		assert_int_equal(err, 0);
		br.rep_count = 3;
		err = reptrans_put_backref(dev, chids + n, HASH_TYPE_DEFAULT, &br);
		assert_int_equal(err, 0);
		err = reptrans_blob_stat(dev, TT_VERIFIED_BACKREF, HASH_TYPE_DEFAULT, chids + n, &bstat);
		assert_int_equal(err, 0);
	}
	/* Check presences */
	printf("Verify chunks presence\n");
	for (size_t n = 0; n < n_blobs; n++) {
		err = retrans_count_vbrs_all_repcount(dev, chids + n,
			HASH_TYPE_DEFAULT, NULL, 0, NULL, 10);
		assert_int_equal(err, 3);
	}

	printf("Deleting\n");
	/* Delete all but one VBR keys */
	uint64_t del_time = 0;
	for (size_t n = 0; n < n_blobs -1; n++) {
		uint64_t ts = get_timestamp_us();
		err = reptrans_delete_blob(dev, TT_VERIFIED_BACKREF, HASH_TYPE_DEFAULT, chids + n);
		assert_int_equal(err, 0);
		del_time += get_timestamp_us() - ts;
	}
	printf("%lu chunks deleted within %lu uS\n", n_blobs, del_time);
	/* Stat blobs again */
	printf("Verify chunks presence\n");
	size_t n_vbrs = 0;
	for (size_t n = 0; n < n_blobs; n++) {
		err = retrans_count_vbrs_all_repcount(dev, chids + n,
			HASH_TYPE_DEFAULT, NULL, 0, NULL, 10);
		n_vbrs += err;
	}
	assert_int_equal(n_vbrs, 3);

	err = reptrans_iterate_blobs(dev, TT_VERIFIED_BACKREF,
		reptrans_validate_br_cb, chids, 1);

	assert_int_equal(err, 0);


	je_free(chids);
}


static int
vbr_all_filter_cb(void *arg, void **data, size_t *size, int set) {
	if (set) {
		*data = NULL;
		*size = 0;
	}
	return 1;
}

struct vdtv {
	size_t n_blobs;
	size_t n_gens;
	uint8_t dupop_test;
};

static void
putall_then_delete_value_vbr_test(void **state) {
	struct vdtv bsrc[] = {
			{ .n_blobs = 16, .n_gens = 14 },
			{ .n_blobs = 16, .n_gens = 30 },
			{ .n_blobs = 16, .n_gens = 62 },
			{ .n_blobs = 16, .n_gens = 125 },
			{ .n_blobs = 16, .n_gens = 253 },
			{ .n_blobs = 16, .n_gens = 510 },
			{ .n_blobs = 16, .n_gens = 1020 },
			{ .n_blobs = 16, .n_gens = 2040 },
			{ .n_blobs = 16, .n_gens = 4093 },
			{ .n_blobs = 16, .n_gens = 8190 },
			{ .n_blobs = 16, .n_gens = 16380 },
			{ .n_blobs = 16, .n_gens = 1020, .dupop_test = 1},
			{ .n_blobs = 30, .n_gens = 2 },
			{ .n_blobs = 30, .n_gens = 5 },
			{ .n_blobs = 30, .n_gens = 10 },
			{ .n_blobs = 30, .n_gens = 100 },
			{ .n_blobs = 50, .n_gens = 2 },
			{ .n_blobs = 50, .n_gens = 5 },
			{ .n_blobs = 50, .n_gens = 10 },
			{ .n_blobs = 50, .n_gens = 100 },
			{ .n_blobs = 100, .n_gens = 2 },
			{ .n_blobs = 100, .n_gens = 5 },
			{ .n_blobs = 100, .n_gens = 10 },
			{ .n_blobs = 100, .n_gens = 100 },
			{ .n_blobs = 1000, .n_gens = 2 },
			{ .n_blobs = 1000, .n_gens = 5 },
			{ .n_blobs = 1000, .n_gens = 10 },
			{ .n_blobs = 1000, .n_gens = 100 },
	};

	int err =  reptrans_init(0, NULL, NULL,
			RT_FLAG_STANDALONE | RT_FLAG_CREATE, 1, (char**)transport, NULL);

	assert_true(err > 0);

	if (err <= 0)
		return;

	err = libreptrans_enum();

	assert_true(err > 0);

	if (err <= 0)
		return;
	struct repdev* dev = devices[0];
	srand(get_timestamp_us());
	sleep(15);
	for (size_t k = 0; k < sizeof(bsrc)/sizeof(bsrc[0]); k++) {
		size_t n_blobs = bsrc[k].n_blobs;
		size_t n_gen = bsrc[k].n_gens;
		printf("#VBRS %lu, #dups %lu\n", n_blobs, n_gen);
		uint512_t* chids = je_calloc(n_blobs, sizeof(uint512_t));
		assert_non_null(chids);
		printf("Adding %lu VBRs\n", n_blobs*n_gen);
		for (size_t n = 0; n < n_blobs; n++) {
			chids[n].u.u.u = random();
			uint512_t nhid = { { {0, n}, {1, 1} }, { {2, 2}, {3, 3} } };
			uint512_t ref_chid = { { {10, 11}, {12, n} }, { {14, n}, {16, 17} } };
			struct backref br = {
				.name_hash_id = nhid,
				.ref_chid = ref_chid,
				.generation = 1,
				.uvid_timestamp = 0,
				.ref_type = TT_CHUNK_MANIFEST,
				.ref_hash = HASH_TYPE_DEFAULT,
				.rep_count = 1,
				.attr = VBR_ATTR_CP
			};
			for (size_t m = 0; m < n_gen; m++) {
				err = reptrans_put_backref(dev, chids + n, HASH_TYPE_DEFAULT, &br);
				assert_int_equal(err, 0);
				if(bsrc[k].dupop_test) {
					err = reptrans_put_backref(dev, chids + n, HASH_TYPE_DEFAULT, &br);
					assert_int_equal(err, 0);
				}
				br.rep_count = 2 + m;
				br.ref_chid.l.l.l = m;
			}

			size_t vbr_count = 0;

			err = reptrans_get_chunk_count(dev, HASH_TYPE_DEFAULT,
				TT_VERIFIED_BACKREF, chids + n, &vbr_count);
			assert_int_equal(err, 0);
			assert_true(vbr_count >= n_gen);

			vbr_count = 0;
			err = reptrans_get_depcount_coarse(dev, TT_VERIFIED_BACKREF,
				HASH_TYPE_DEFAULT, chids + n, 1000000, &vbr_count);
			assert_true(vbr_count >= n_gen);
		}
		/* Check presences */
		printf("Verify\n");
		for (size_t n = 0; n < n_blobs; n++) {
			err = retrans_count_vbrs_all_repcount(dev, chids + n,
				HASH_TYPE_DEFAULT, NULL, 0, NULL, n_gen*2);
			assert_int_equal(err, n_gen);
			if(bsrc[k].dupop_test) {
				err = retrans_count_vbrs_all_repcount(dev, chids + n,
					HASH_TYPE_DEFAULT, NULL, 0, NULL, n_gen*2);
				assert_int_equal(err, n_gen);
			}
		}
		printf("Deleting\n");
		/* Delete all but one VBR keys */
		uint64_t del_time = 0;
		uint64_t get_time = 0;
		for (size_t n = 0; n < n_blobs; n++) {
			rtbuf_t* rb = NULL;
			uint64_t ts = get_timestamp_us();
			int err = reptrans_get_blobs(dev, TT_VERIFIED_BACKREF,
				HASH_TYPE_DEFAULT, chids + n, &rb, 0, vbr_all_filter_cb,
				NULL);
			get_time += get_timestamp_us() - ts;
			assert_int_equal(err, 0);
			assert_non_null(rb);
			assert_int_equal(rb->nbufs, n_gen);
			get_timestamp_us();
			err = reptrans_delete_blob_value(dev, TT_VERIFIED_BACKREF, HASH_TYPE_DEFAULT, chids + n, rb->bufs, rb->nbufs-1);
			assert_int_equal(err, 0);
			del_time += get_timestamp_us() - ts;
			if(bsrc[k].dupop_test) {
				err = reptrans_delete_blob_value(dev, TT_VERIFIED_BACKREF, HASH_TYPE_DEFAULT, chids + n, rb->bufs, rb->nbufs-1);
				assert_int_equal(err, 0);
			}
			rtbuf_destroy(rb);
		}
		printf("%lu chunks got/del within %lu/%lu uS\n", n_blobs*(n_gen-1), get_time, del_time);
		/* Stat blobs again */
		printf("Verify2\n");
		size_t n_vbrs = 0;
		for (size_t n = 0; n < n_blobs; n++) {
			err = retrans_count_vbrs_all_repcount(dev, chids + n,
				HASH_TYPE_DEFAULT, NULL, 0, NULL, n_gen+10);
			if (err != 1) {
				printf("#VBR[%lu]=%d\n", n, err);
			}
			n_vbrs += err;
			if(bsrc[k].dupop_test) {
				int err1 = retrans_count_vbrs_all_repcount(dev, chids + n,
					HASH_TYPE_DEFAULT, NULL, 0, NULL, n_gen+10);
				assert_int_equal(err, err1);
			}
		}
		assert_int_equal(n_vbrs, n_blobs);
		je_free(chids);
	}
}

struct count_vbr_arg {
	uint512_t chid;
	size_t count;
};

static int
count_vbrs_cb(struct repdev *dev, type_tag_t ttag, crypto_hash_t hash_type,
	uint512_t *key, uv_buf_t *val, void *param) {
	struct count_vbr_arg* arg = param;
	if (uint512_cmp(&arg->chid, key) == 0) {
		arg->count++;
	}
	return 0;
}

static void
reptrans_vbr_iterator_test(void **state)
{

	int err =  reptrans_init(0, NULL, NULL,
			RT_FLAG_STANDALONE | RT_FLAG_CREATE, 1, (char**)transport, NULL);

	assert_true(err > 0);

	if (err <= 0)
		return;

	err = libreptrans_enum();

	assert_true(err > 0);

	if (err <= 0)
		return;
	struct repdev* dev = devices[0];

	size_t n_vbrs = 1000;
	uint512_t chid;
	chid.u.u.u = random();
	struct backref br = {
		.name_hash_id = { { {0, 1}, {1, 1} }, { {2, 2}, {3, 3} } },
		.ref_chid = { { {10, 11}, {12, 12} }, { {14, 15}, {16, 17} } },
		.generation = 1,
		.uvid_timestamp = 0,
		.ref_type = TT_CHUNK_MANIFEST,
		.ref_hash = HASH_TYPE_DEFAULT,
		.rep_count = 3,
		.attr = VBR_ATTR_CP
	};
	for (size_t n = 0; n < n_vbrs; n++) {
		br.ref_chid.u.u.u = n*123;
		int err = reptrans_put_backref(dev, &chid, HASH_TYPE_DEFAULT, &br);
		assert_int_equal(err, 0);
	}


	rtbuf_t* rb = NULL;
	uint64_t ts = get_timestamp_us();
	err = reptrans_get_blobs(dev, TT_VERIFIED_BACKREF,
		HASH_TYPE_DEFAULT, &chid, &rb, 0, vbr_all_filter_cb,
		NULL);
	assert_int_equal(err, 0);
	assert_non_null(rb);
	assert_int_equal(rb->nbufs, n_vbrs);

	size_t vbr_count = 0;
	err = reptrans_get_depcount_coarse(dev, TT_VERIFIED_BACKREF,
		HASH_TYPE_DEFAULT, &chid, 1000000, &vbr_count);
	assert_int_equal(err, 0);
	assert_int_equal(vbr_count, n_vbrs);

	for (size_t n = 0; n < n_vbrs; n++) {
		err = reptrans_delete_blob_value(dev, TT_VERIFIED_BACKREF,
			HASH_TYPE_DEFAULT, &chid, rb->bufs+n, 1);
		assert_int_equal(err, 0);
	}
	rtbuf_destroy(rb);
	struct count_vbr_arg arg = { .chid = chid, .count = 0 };
	err = reptrans_iterate_blobs(dev, TT_VERIFIED_BACKREF, count_vbrs_cb,
		&arg, 1);
	assert_int_equal(arg.count, 0);

}


#define IBQ_ENTRIES 512
#define BATCH_SIZE (48*1024 - 40)

static void
reptrans_enqueue_batch_local(struct repdev *dev, char *msg, size_t msg_len)
{
	assert_non_null(dev != NULL);
	uint64_t ts = get_timestamp_us();

	msgpack_u u;
	msgpack_unpack_init_b(&u, msg, msg_len, 0);
	int err = msgpack_unpack_uint64(&u, &ts);
	assert_int_equal(err, 0);

	uint512_t key = uint512_null;
	key.u.u.u = ts;
	key.u.u.l = get_timestamp_us() + rand() % 65563;

	uv_buf_t data = { .base = msg, .len = msg_len };
	rtbuf_t *rb = rtbuf_init_mapped(&data, 1);
	assert_non_null(rb);

	err = reptrans_put_blob(dev, TT_BATCH_INCOMING_QUEUE,
		HASH_TYPE_DEFAULT, rb, &key, 0);
	rtbuf_destroy(rb);
	assert_int_equal(err, 0);
}

struct incoming_bach_queue_arg {
	char** buffs;
	uint512_t* keys;
	volatile uint64_t ts_prev;
	volatile int n;
	int mode;
};

static int
incoming_batch_callback(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *key, uv_buf_t *val, void *param) {
	struct incoming_bach_queue_arg* arg = param;
	int err = 0;

	if (arg->mode == 0) {
		/* First pass, remove old entries */
		err = reptrans_delete_blob(dev, TT_BATCH_INCOMING_QUEUE, HASH_TYPE_DEFAULT, key);
		assert_int_equal(err, 0);
	} else if (arg->mode == 1) {
		uint64_t ts = 0;
		const uint8_t* dptr = NULL;
		uint32_t dl = 0;
		msgpack_u* u = msgpack_unpack_init(val->base, val->len, 0);
		int err = msgpack_unpack_uint64(u, &ts);
		assert_int_equal(0, err);
		if (arg->ts_prev > ts)
			printf("TS(prev) %lu vs TS(curr) %lu iter %d\n", arg->ts_prev, ts, arg->n);
		assert_true(arg->ts_prev <= ts);
		arg->ts_prev = ts;
		err = msgpack_unpack_raw(u, &dptr, &dl);
		assert_int_equal(err, 0);
		msgpack_unpack_free(u);
#if 0
		err = memcmp(dptr, arg->buffs[arg->n], dl);
		assert_int_equal(0, err);
#endif
		err = reptrans_delete_blob(dev, TT_BATCH_INCOMING_QUEUE,
			HASH_TYPE_DEFAULT, key);
		assert_int_equal(err, 0);
		arg->keys[arg->n] = *key;
		arg->n++;
	} else {
		arg->n++;
	}

	return 0;
}

static void
batch_incoming_queue_test(void **state) {
	/* stopping device background tasks */
	int err =  reptrans_init(0, NULL, NULL,
			RT_FLAG_STANDALONE | RT_FLAG_CREATE, 1, (char**)transport, NULL);

	assert_true(err > 0);

	if (err <= 0)
		return;

	err = libreptrans_enum();

	assert_true(err > 0);

	if (err <= 0)
		return;

	struct repdev* dev = devices[0];
	char* ibq_buffs[IBQ_ENTRIES];
	uint512_t* keys = je_calloc(IBQ_ENTRIES, sizeof(uint512_t));

	struct incoming_bach_queue_arg arg = {
			.buffs = ibq_buffs,
			.keys = keys,
			.n = 0,
			.ts_prev = 0,
			.mode = 0
	};
	/* Clean the queue */
	err = reptrans_iterate_blobs_strict_order(dev,
		TT_BATCH_INCOMING_QUEUE, incoming_batch_callback,
		&arg, 1);
	/* Append new entries to the queue */
	uint64_t ts_offset = 0;
	for (uint32_t i = 0; i < IBQ_ENTRIES; i++) {
		if (i % 10 == 0)
			ts_offset = rand() % 65536;
		ibq_buffs[i] = je_calloc(1, BATCH_SIZE);
		assert_non_null(ibq_buffs[i]);
		uv_buf_t ub = { .base = ibq_buffs[i], .len = BATCH_SIZE};
		random_buffer(ub);
		msgpack_p* pack = msgpack_pack_init();
		assert_non_null(pack);
		uint64_t ts = get_timestamp_us() + ts_offset;
		int err = msgpack_pack_uint64(pack, ts);
		assert_int_equal(err, 0);
		err = msgpack_pack_raw(pack, ibq_buffs[i], BATCH_SIZE);
		assert_int_equal(err, 0);
		uv_buf_t pb;
		msgpack_get_buffer(pack, &pb);
		reptrans_enqueue_batch_local(dev, pb.base, pb.len);
		msgpack_pack_free(pack);
	}
	arg.mode = 1;
	arg.n = 0;

	/* Verify the queue order and entries number. Empty the queue */
	err = reptrans_iterate_blobs_strict_order_limited(dev,
		TT_BATCH_INCOMING_QUEUE, incoming_batch_callback,
		&arg, 1, IBQ_ENTRIES);
	assert_int_equal(err, 0);
	assert_int_equal(arg.n, IBQ_ENTRIES);
	/* Ensure the queue is empty */
	arg.mode = 2;
	arg.n = 0;
	err = reptrans_iterate_blobs_strict_order(dev,
		TT_BATCH_INCOMING_QUEUE, incoming_batch_callback,
		&arg, 1);
	assert_int_equal(arg.n, 0);
	je_free(keys);
	for (uint32_t i = 0; i < IBQ_ENTRIES; i++)
		if (ibq_buffs[i])
			je_free(ibq_buffs[i]);
}


#define IBQ_ENTRIES_RO	128

static void
batch_incoming_queue_ro_test(void **state) {
	/* stopping device background tasks */
	int err =  reptrans_init(0, NULL, NULL,
			RT_FLAG_STANDALONE | RT_FLAG_CREATE, 1, (char**)transport, NULL);

	assert_true(err > 0);

	if (err <= 0)
		return;

	err = libreptrans_enum();

	assert_true(err > 0);

	if (err <= 0)
		return;

	struct repdev* dev = devices[0];
	char* ibq_buffs[IBQ_ENTRIES_RO];
	uint512_t* keys = je_calloc(IBQ_ENTRIES_RO, sizeof(uint512_t));

	struct incoming_bach_queue_arg arg = {
			.buffs = ibq_buffs,
			.keys = keys,
			.n = 0,
			.ts_prev = 0,
			.mode = 0
	};
	/* Clean the queue */
	err = reptrans_iterate_blobs_strict_order(dev,
		TT_BATCH_INCOMING_QUEUE, incoming_batch_callback,
		&arg, 1);
	/* Append new entries to the queue */
	uint64_t ts_offset = 0;
	for (uint32_t i = 0; i < IBQ_ENTRIES_RO; i++) {
		if (i % 10 == 0)
			ts_offset = rand() % 65536;
		ibq_buffs[i] = je_calloc(1, BATCH_SIZE);
		assert_non_null(ibq_buffs[i]);
		uv_buf_t ub = { .base = ibq_buffs[i], .len = BATCH_SIZE};
		random_buffer(ub);
		msgpack_p* pack = msgpack_pack_init();
		assert_non_null(pack);
		uint64_t ts = get_timestamp_us() + ts_offset;
		int err = msgpack_pack_uint64(pack, ts);
		assert_int_equal(err, 0);
		err = msgpack_pack_raw(pack, ibq_buffs[i], BATCH_SIZE);
		assert_int_equal(err, 0);
		uv_buf_t pb;
		msgpack_get_buffer(pack, &pb);
		reptrans_enqueue_batch_local(dev, pb.base, pb.len);
		msgpack_pack_free(pack);
	}
	arg.mode = 1;
	arg.n = 0;
	reptrans_dev_set_status(dev, REPDEV_STATUS_READONLY_DATA);
	/* Verify the queue order and entries number. Empty the queue */
	err = reptrans_iterate_blobs_strict_order(dev,
		TT_BATCH_INCOMING_QUEUE, incoming_batch_callback,
		&arg, 1);
	assert_int_equal(err, 0);
	assert_int_equal(arg.n, IBQ_ENTRIES_RO);
	/* Ensure the queue is empty */
	arg.mode = 2;
	arg.n = 0;
	err = reptrans_iterate_blobs_strict_order(dev,
		TT_BATCH_INCOMING_QUEUE, incoming_batch_callback,
		&arg, 1);
	assert_int_equal(arg.n, 0);
	je_free(keys);
	for (uint32_t i = 0; i < IBQ_ENTRIES_RO; i++)
		if (ibq_buffs[i])
			je_free(ibq_buffs[i]);
}


static void
reptrans_teardown(void **state)
{
	assert_int_equal(reptrans_destroy(),0);
	reptrans_close_all_rt();
}

#define TRLOG_ENTRIES 100000

static int
trlog_cb_limited(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *key, uv_buf_t *val, void *param) {
	int* count = param;
	++(*count);
	return 0;
}

static int
trlog_callback(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *key, uv_buf_t *val, void *param) {
	struct incoming_bach_queue_arg* arg = param;
	int err = 0;

	if (arg->mode == 0) {
		/* First pass, remove old entries */
		err = reptrans_delete_blob(dev, TT_TRANSACTION_LOG, HASH_TYPE_DEFAULT, key);
		assert_int_equal(err, 0);
	} else if (arg->mode == 1) {
		uint64_t ts = 0;
		const uint8_t* dptr = NULL;
		uint32_t dl = 0;
		msgpack_u* u = msgpack_unpack_init(val->base, val->len, 0);
		int err = msgpack_unpack_uint64(u, &ts);
		assert_int_equal(0, err);
		assert_int_equal(ts, key->u.u.l);
		if (arg->ts_prev > ts)
			printf("TS(prev) %lu vs TS(curr) %lu iter %d\n", arg->ts_prev, ts, arg->n);
		assert_true(arg->ts_prev <= ts);
		arg->ts_prev = ts;
		err = msgpack_unpack_raw(u, &dptr, &dl);
		assert_int_equal(err, 0);
		msgpack_unpack_free(u);
#if 0
		err = memcmp(dptr, arg->buffs[arg->n], dl);
		assert_int_equal(0, err);
#endif
		err = reptrans_delete_blob(dev, TT_TRANSACTION_LOG,
			HASH_TYPE_DEFAULT, key);
		assert_int_equal(err, 0);
		arg->keys[arg->n] = *key;
		arg->n++;
	} else {
		arg->n++;
	}

	return 0;
}
static void
batch_trlog_queue_test(void **state) {
	/* stopping device background tasks */
	int err =  reptrans_init(0, NULL, NULL,
			RT_FLAG_STANDALONE | RT_FLAG_CREATE, 1, (char**)transport, NULL);

	assert_true(err > 0);

	if (err <= 0)
		return;

	err = libreptrans_enum();

	assert_true(err > 0);

	if (err <= 0)
		return;

	struct repdev* dev = devices[0];

	char* ibq_buffs[TRLOG_ENTRIES];
	uint512_t* keys = je_calloc(TRLOG_ENTRIES, sizeof(uint512_t));

	struct incoming_bach_queue_arg arg = {
			.buffs = ibq_buffs,
			.keys = keys,
			.n = 0,
			.ts_prev = 0,
			.mode = 0
	};
	/* Clean the queue */
	err = reptrans_iterate_blobs(dev, TT_TRANSACTION_LOG, trlog_callback,
		&arg, 0);
	/* Append new entries to the queue */
	uint64_t ts_offset = 0;
	printf("Adding %d entries to trlog\n", TRLOG_ENTRIES);

	for (uint32_t i = 0; i < TRLOG_ENTRIES; i++) {
		if (i % 10 == 0)
			ts_offset = rand() % 65536;
		ibq_buffs[i] = je_calloc(1, BATCH_SIZE);
		assert_non_null(ibq_buffs[i]);
		uv_buf_t ub = { .base = ibq_buffs[i], .len = BATCH_SIZE};
		random_buffer(ub);
		msgpack_p* pack = msgpack_pack_init();
		assert_non_null(pack);
		uint64_t ts = get_timestamp_us() + ts_offset;
		int err = msgpack_pack_uint64(pack, ts);
		assert_int_equal(err, 0);
		err = msgpack_pack_raw(pack, ibq_buffs[i], BATCH_SIZE);
		assert_int_equal(err, 0);
		uv_buf_t pb;
		msgpack_get_buffer(pack, &pb);

		uint512_t key;
		key.u.u.u = rand();
		key.u.u.l = ts;
		rtbuf_t* rb = rtbuf_init_mapped(&pb, 1);
		err = reptrans_put_blob(dev, TT_TRANSACTION_LOG, HASH_TYPE_DEFAULT, rb, &key, 0);
		assert_int_equal(err, 0);
		rtbuf_destroy(rb);
		msgpack_pack_free(pack);
	}
	int limited_count = 0;
	uint64_t ts = get_timestamp_us();
	/* Verify the strict iterator */
	err = reptrans_iterate_blobs_strict_order_limited(dev, TT_TRANSACTION_LOG, trlog_cb_limited,
		&limited_count, 0, 2256);
	printf("strict_itertor: %d entries, duration %lu mS\n", limited_count, (get_timestamp_us() - ts)/1000);

	arg.mode = 1;
	arg.n = 0;

	/* Verify the queue order and entries number. Empty the queue */
	err = reptrans_iterate_blobs_strict_order(dev,
		TT_TRANSACTION_LOG, trlog_callback,
		&arg, 1);
	assert_int_equal(err, 0);
	assert_int_equal(arg.n, TRLOG_ENTRIES);
	/* Ensure the queue is empty */
	arg.mode = 2;
	arg.n = 0;
	err = reptrans_iterate_blobs_strict_order(dev,
		TT_TRANSACTION_LOG, trlog_callback,
		&arg, 1);
	assert_int_equal(arg.n, 0);
	je_free(keys);
	for (uint32_t i = 0; i < TRLOG_ENTRIES; i++)
		if (ibq_buffs[i])
			je_free(ibq_buffs[i]);
}

static void
blob_touch_test(void **state) {
	int err =  reptrans_init(0, NULL, NULL,
		RT_FLAG_STANDALONE | RT_FLAG_CREATE, 1, (char**)transport, NULL);

	assert_true(err > 0);
	if (err <= 0)
		return;

	err = libreptrans_enum();
	assert_true(err > 0);

	if (err <= 0)
		return;
	struct repdev* dev = devices[0];
	type_tag_t ttype = TT_CHUNK_PAYLOAD;
	srand(clock());
	uint512_t chid_x;
	chid_x.u.u.u = get_timestamp_us();
	chid_x.u.u.l = rand();
	const char* data = "my perfect string";
	uv_buf_t ub = { .base = (char*)data, .len = strlen(data)+1 };
	rtbuf_t* rb = rtbuf_init_mapped(&ub, 1);
	err = reptrans_put_blob_with_attr(dev, ttype, HASH_TYPE_DEFAULT, rb, &chid_x, 0, get_timestamp_us());
	assert_int_equal(err, 0);

	reptrans_flush(RD_FLUSH_FORCE);
	usleep(500000);
	err = reptrans_blob_stat(dev, ttype, HASH_TYPE_DEFAULT, &chid_x, NULL);
	assert_int_equal(err, 0);
	err = reptrans_set_blob_ts(dev, ttype, HASH_TYPE_DEFAULT, &chid_x, get_timestamp_us() +123456);
	assert_int_equal(err, 0);
	rtbuf_t* rb_rd = NULL;
	err = reptrans_get_blob(dev, ttype, HASH_TYPE_DEFAULT, &chid_x, &rb_rd);
	assert_int_equal(err, 0);
	assert_non_null(rb_rd);
	assert_int_equal(strlen(data)+1, rb_rd->bufs->len);
}

static void
random_uint512(uint512_t* val) {
	val->u.u.u = random();
	val->u.u.l = random();
	val->u.l.u = random();
	val->u.l.l = random();
	val->l.u.u = random();
	val->l.u.l = random();
	val->l.l.u = random();
	val->l.l.l = random();
}

static void
vbr_stat_test(void **state) {
	int err =  reptrans_init(0, NULL, NULL,
		RT_FLAG_STANDALONE | RT_FLAG_CREATE, 1, (char**)transport, NULL);

	assert_true(err > 0);
	if (err <= 0)
		return;

	err = libreptrans_enum();
	assert_true(err > 0);

	if (err <= 0)
		return;
	struct repdev* dev = devices[0];

	uint512_t nhid, chid, ref_chid;
	random_uint512(&nhid);
	random_uint512(&chid);
	random_uint512(&ref_chid);
	struct backref br1 = {
		.name_hash_id = nhid,
		.ref_chid = ref_chid,
		.generation = 123,
		.uvid_timestamp = get_timestamp_us(),
		.ref_type = TT_NAMEINDEX,
		.ref_hash = HASH_TYPE_DEFAULT,
		.rep_count = 3,
		.attr = VBR_ATTR_EC | VBR_ATTR_CP
	};

	assert_int_equal(0, reptrans_put_backref(dev, &chid, HASH_TYPE_DEFAULT,
		&br1));

	assert_int_equal(0, reptrans_vbr_stat(dev, HASH_TYPE_DEFAULT, &chid, &br1));

	br1.rep_count = 1;
	assert_int_equal(-ENOENT, reptrans_vbr_stat(dev, HASH_TYPE_DEFAULT, &chid, &br1));
}

struct vm_get_arg {
	rtbuf_t* rb;
	uint512_t vmchid;
};

static int
vm_find_iterator(struct repdev *dev, type_tag_t ttag, crypto_hash_t hash_type,
	uint512_t *key, uv_buf_t *val, void *param) {
	struct vm_get_arg* p = param;
	if (p->rb == NULL) {
		uv_buf_t ub = {.base = je_memdup(val->base, val->len), .len = val->len};
		p->rb = rtbuf_init(&ub, 1);
		p->vmchid = *key;
	}
	return -1;
}

static void
vm_override_test(void **state) {
	int err =  reptrans_init(0, NULL, NULL,
		RT_FLAG_STANDALONE | RT_FLAG_CREATE, 1, (char**)transport, NULL);

	assert_true(err > 0);
	if (err <= 0)
		return;

	err = libreptrans_enum();
	assert_true(err > 0);

	if (err <= 0)
		return;
	struct repdev* dev = devices[1];
	struct vm_get_arg arg = {.rb = NULL };
	reptrans_iterate_blobs(dev, TT_VERSION_MANIFEST, vm_find_iterator, &arg, 1);
	if (!arg.rb) {
		printf("No VMs found, test skipped\n");
		return;
	}
	for (int i = 0; i < 100; i++) {
		struct vmmetadata md;
		rtbuf_t* vm_new = NULL;
		rtbuf_t* vm_read = NULL;

		assert_int_equal(0, ccow_edit_md_overrides(arg.rb, RT_SYSKEY_ONDEMAND, ondemandPolicyUnpin, &vm_new));
		assert_non_null(vm_new);
		assert_int_equal(0, reptrans_put_blob_with_attr_opts(dev, TT_VERSION_MANIFEST,
			HASH_TYPE_DEFAULT, vm_new, &arg.vmchid, 0, get_timestamp_us(),
			REPDEV_PUT_OPT_OVERWRITE));
		rtbuf_destroy(vm_new);

		assert_int_equal(0, reptrans_get_blob(dev, TT_VERSION_MANIFEST, HASH_TYPE_DEFAULT,
			&arg.vmchid, &vm_read));

		err = replicast_get_metadata(vm_read, &md);
		if (err) {
			printf("error getting metadata %d, VM size %lu\n", err,
				vm_read->bufs->len);
			assert_int_equal(err, 0);
		}
		uint16_t ondemand_flags = RT_ONDEMAND_GET(md.inline_data_flags);
		assert_int_equal(ondemand_flags, ondemandPolicyUnpin);



		assert_int_equal(0, ccow_edit_md_overrides(vm_read, RT_SYSKEY_ONDEMAND, ondemandPolicyPin, &vm_new));
		assert_non_null(vm_new);
		assert_int_equal(0, reptrans_put_blob_with_attr_opts(dev, TT_VERSION_MANIFEST,
			HASH_TYPE_DEFAULT, vm_new, &arg.vmchid, 0, get_timestamp_us(),
			REPDEV_PUT_OPT_OVERWRITE));
		rtbuf_destroy(vm_new);
		rtbuf_destroy(vm_read);

		assert_int_equal(0, reptrans_get_blob(dev, TT_VERSION_MANIFEST, HASH_TYPE_DEFAULT,
			&arg.vmchid, &vm_read));

		assert_int_equal(0, replicast_get_metadata(vm_read, &md));
		ondemand_flags = RT_ONDEMAND_GET(md.inline_data_flags);
		assert_int_equal(ondemand_flags, ondemandPolicyPin);
		rtbuf_destroy(vm_read);
	}
	if (arg.rb)
		rtbuf_destroy(arg.rb);
}

int
main(int argc, char *argv[])
{
	lg = Logger_create("reptrans");
	if (argc > 1 && strcmp(argv[1], "-s") == 0) {
		dd = 1;
	}
	char cmd[PATH_MAX];
	snprintf(cmd, sizeof(cmd), "cat %s/etc/ccow/ccowd.json|grep rtrd 2>/dev/null >/dev/null",
			nedge_path());
	if (system(cmd) == 0)
		transport[0] = TRANS_RTRD;
	else {
		snprintf(cmd, sizeof(cmd), "cat %s/etc/ccow/ccowd.json|grep rtkvs 2>/dev/null >/dev/null",
				nedge_path());
		if (system(cmd) == 0)
			transport[0] = TRANS_RTKVS;
	}


	const UnitTest tests[] = {
		unit_test(vm_override_test),
		unit_test(reptrans_teardown),
		unit_test(batch_trlog_queue_test),
		unit_test(reptrans_teardown),
		unit_test(blob_touch_test),
		unit_test(reptrans_teardown),
		unit_test(reptrans_vbr_iterator_test),
		unit_test(reptrans_teardown),
		unit_test(reptrans_put_getlast_version__test),
		unit_test(reptrans_teardown),
		unit_test(batch_incoming_queue_test),
		unit_test(reptrans_teardown),
		unit_test(batch_incoming_queue_ro_test),
		unit_test(reptrans_teardown),
		unit_test(delete_blobs_test),
		unit_test(reptrans_teardown),
		unit_test(putall_then_delete_vbr_test),
		unit_test(reptrans_teardown),
		unit_test(putall_then_delete_value_vbr_test),
		unit_test(reptrans_teardown),
		unit_test(libreptrans_standalone_vbr_stat_test),
		unit_test(reptrans_teardown),
		unit_test(libreptrans_standalone_full_test),
		unit_test(reptrans_teardown),
		unit_test(libreptrans_standalone_rw_test),
		unit_test(reptrans_teardown),
		unit_test(libreptrans_standalone_ro_test),
		unit_test(reptrans_teardown),
		unit_test(reptrans_put_version__test),
		unit_test(reptrans_teardown),
	};
	return run_tests(tests);
}

