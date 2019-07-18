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

#include "ccowutil.h"
#include "cmocka.h"
#include "common.h"
#include "ccow.h"
#include "ccowd.h"
#include "ccowd-impl.h"
#include "reptrans.h"
#include "erasure-coding.h"

/*
 * CAUTION: non-production internal unit test for reptrans debugging only
 */
extern struct ccowd *ccow_daemon;

#define TEST_BUCKET_NAME        "reptrans-bucket-test"
#define MAX_DEV 256
ccow_t cl;

struct repdev *devices[MAX_DEV];
struct enum_dev_arg {
	int n_dev;
	struct repdev **dev;
};

static int n_dev = 0;
static int dd = 0;
static int n_iterations = 100;
static unsigned int seed = 0;

static void
libccowd_setup(void **state)
{
	if (!dd) {
		assert_int_equal(ccow_daemon_init(NULL), 0);
		usleep(2 * 1000000L);
	}
}

static void
libccow_setup(void **state)
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
	int fd = open(path, O_RDONLY);
	assert_true(fd >= 0);
	char *buf = je_calloc(1, 16384);
	assert_non_null(buf);
	assert_true(read(fd, buf, 16384) != -1);
	assert_int_equal(close(fd), 0);
	assert_int_equal(ccow_tenant_init(buf, "cltest", 7, "test", 5, &cl), 0);
	je_free(buf);
#if 0
	/* initialize 0x0 sys object */
	assert_int_equal(ccow_system_init(cl), 0);

	/* check if 0x0 sys object exists */
	get(cl, "", "", NULL, 0, 0, NULL, NULL, NULL);
#endif
}

static void
libccow_teardown(void **state)
{
	assert_non_null(cl);
	usleep(100000L);
	ccow_tenant_term(cl);
}

static void
libccowd_teardown(void **state) {
	usleep(100000L);
	if (!dd) {
		ccow_daemon_term();
	}
}

static void
bucket_create(void **state)
{
	assert_non_null(cl);
	int err = ccow_bucket_create(cl, TEST_BUCKET_NAME,
		strlen(TEST_BUCKET_NAME) + 1, NULL);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void
bucket_delete(void **state)
{
	assert_non_null(cl);
	int err = ccow_bucket_delete(cl, TEST_BUCKET_NAME,
		strlen(TEST_BUCKET_NAME) + 1);
	assert_int_equal(err, 0);
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

static void
libreptrans_setup(void **state)
{
	struct enum_dev_arg enum_arg = {0, devices};
	assert_int_equal(reptrans_enum(NULL, &enum_arg,
		    enum_dev__done_cb, 0), 0);
	n_dev = enum_arg.n_dev;
}

static int
compare_buf_version_timestamps(const void *a, const void *b)
{
	struct vlentry *aver = (struct vlentry *)a;
	struct vlentry *bver = (struct vlentry *)b;
	return bver->uvid_timestamp - aver->uvid_timestamp;
}

int
reptrans_delete_version_entry(struct repdev *dev, crypto_hash_t hash_type,
	const uint512_t *chid, struct vlentry *ver);

#define N_VERSIONS	12
#define N_OLD_VERSIONS	10

static void
reptrans_put_version__test(void **state)
{
	assert_int_not_equal(n_dev, 0);
	struct vmmetadata md;
	struct timeval tv;
	struct vlentry **vers = NULL;

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
	int err = reptrans_get_versions(devices[0], &md.nhid, &query, &rb_vers);
	char nhidbuf[UINT512_BYTES * 2 + 1];
	uint512_dump(&md.nhid, nhidbuf, UINT512_BYTES * 2 + 1);
	log_trace(lg, "dev %s nhid %s number_of_versions %d nbufs %d\n",
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
		log_trace(lg, "dev %s nhid %s delete version %lu\n",
			devices[0]->path, nhidbuf, vers[i]->uvid_timestamp);
		err = reptrans_delete_version_entry(devices[0],
			HASH_TYPE_DEFAULT, &md.nhid, vers[i]);
		if (err)
			log_error(lg,
				"dev %s nhid %s delete version failed %d\n",
				devices[0]->path, nhidbuf, err);
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
	assert_int_equal(reptrans_delete_index(devices[0], HASH_TYPE_DEFAULT,
			&md.nhid), 0);
}

#define MAX_CHIDS 1000
#define NUM_ENTRIES 1000
struct _child_list
{
	uint512_t *chids;
	uint32_t  max;
	uint32_t  current;
};

static int
blob_iterator(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *key, uv_buf_t *val, void *param)
{
	struct _child_list* pList = (struct _child_list*)param;
	assert_non_null(pList);
	pList->chids[pList->current++] = *key;
	if(pList->current >= pList->max)
	{
		pList->chids = je_realloc(pList->chids, (pList->max + MAX_CHIDS)*sizeof(uint512_t));
		pList->max += MAX_CHIDS;
	}
	return 0;
}

static void
reptrans_iterator__test(void **state)
{
	struct vmmetadata md;
	struct timeval tv;
	struct _child_list _list = { .max = MAX_CHIDS, .current = 0 };

	size_t i;
	_list.chids = je_malloc(MAX_CHIDS*sizeof(uint512_t));
	assert_non_null(_list.chids);

	/*
	 * Put several chunks with an equal CHID to the storage. Two dupsort keys.
	 */
	uint512_t nhid1 = { { {0, 1}, {2, 3} }, { {4, 5}, {6, 7} } };
	uint512_t nhid2 = { { {5, 5}, {5, 5} }, { {4, 4}, {7, 7} } };
	memset(&md, 0, sizeof(struct vmmetadata));
	for (i = 0; i < NUM_ENTRIES; ++i) {
		(void)gettimeofday(&tv, NULL);
		md.uvid_timestamp = tv.tv_sec * 1000000L + tv.tv_usec;
		md.nhid = i < NUM_ENTRIES/2 ? nhid1 : nhid2;
		md.replication_count = 3;
		md.txid_generation = i;
		assert_int_equal(reptrans_put_version(devices[0], &md, &md.nhid, i*100), 0);
	}
	printf("inserted %d unique dupsort key entries (single key)\n", NUM_ENTRIES);

	reptrans_flush(RD_FLUSH_FORCE);
	usleep(500000);

	/*
	 * Iterate over the chunks collecting their CHIDs
	 */
	assert_int_equal(reptrans_iterate_blobs(devices[0], TT_NAMEINDEX,
			blob_iterator, &_list, 0), 0);
	assert_true(_list.current >= NUM_ENTRIES);

	printf("iterated over dupsort key entries successfully\n");

	/* delete key1's data */
	assert_int_equal(reptrans_delete_blob(devices[0], TT_NAMEINDEX,
			HASH_TYPE_DEFAULT, &nhid1),0);
	/* delete key2's data */
	assert_int_equal(reptrans_delete_blob(devices[0], TT_NAMEINDEX,
			HASH_TYPE_DEFAULT, &nhid2),0);
	printf("deleted all dupsort data\n");

	/*
	 * Repeat the same with unique key DB
	 */
	uv_buf_t payload;
	int nbufs = 1;
	char *buf = je_malloc(1024);
	payload.base = buf;
	payload.len = 1024;

	uint512_t keys[NUM_ENTRIES];
	rtbuf_t *rb = rtbuf_init_mapped(&payload, nbufs);
	assert_non_null(rb);

	for (i = 0; i < NUM_ENTRIES; ++i) {
		for (uint32_t k = 0; k < payload.len; k++)
			payload.base[k] = random() % 256;
		assert_int_equal(reptrans_put_blob_with_attr(devices[0], TT_VERSION_MANIFEST,
				HASH_TYPE_DEFAULT, rb, &keys[i], 1,
				reptrans_get_timestamp(devices[0])), 0);
	}
	printf("inserted %d unique non-dupsort keys\n", NUM_ENTRIES);

	reptrans_flush(RD_FLUSH_FORCE);
	usleep(500000);

	_list.max = MAX_CHIDS;
	_list.current = 0;

	assert_int_equal(reptrans_iterate_blobs(devices[0], TT_VERSION_MANIFEST,
			blob_iterator, &_list, 0), 0);

	assert_true(_list.current >= NUM_ENTRIES);

	printf("iterated over non-dupsort successfully\n");

	for (i = 0; i < NUM_ENTRIES; ++i) {
		assert_int_equal(reptrans_delete_blob(devices[0], TT_VERSION_MANIFEST,
				HASH_TYPE_DEFAULT, &keys[i]),0);
	}
	printf("deleted all inserted keys\n");

	rtbuf_destroy(rb);
	je_free(buf);
	je_free(_list.chids);
}

static void
reptrans_delete_index__test(void **state)
{
	assert_int_not_equal(n_dev, 0);
	int i;
	uint512_t nhid = { { {0, 1}, {2, 3} }, { {4, 5}, {6, 7} } };
	assert_int_equal(reptrans_delete_index(devices[0],
			HASH_TYPE_DEFAULT, &nhid), 0);
}

struct bg_sched;

int
bg_sched_is_terminated(struct bg_sched* sched);

void
bg_sched_terminate(struct bg_sched* sched);


static void
libreptrans_disable_bg() {
	for(int i = 0; i < n_dev; i++) {
		struct repdev* dev = devices[i];
		bg_sched_terminate(dev->bg_sched);
	}

	for(int i = 0; i < n_dev; i++) {
		struct repdev* dev = devices[i];
		while (!bg_sched_is_terminated(dev->bg_sched)) {
			usleep(10000);
		}
	}
}

static void
randomize_buffer(void* buf, size_t size) {
	char* ptr = (char*)buf;

	for(size_t i=0; i < size; i++) {
		*ptr = rand() % 256;
	}
}

static int
vbrs_count_cb(void *arg, void **data, size_t *size, int set) {
	size_t* pcnt = arg;
	if (set) {
		*data = NULL;
		*size = 0;
		return 0;
	}
	(*pcnt)++;
	return 0;
}

static int
reptrans_vbr_count(struct repdev* dev, crypto_hash_t ht,uint512_t* chid, size_t* result) {
	*result = 0;
	rtbuf_t* rb = NULL;
	int err = reptrans_get_blobs(dev, TT_VERIFIED_BACKREF, ht, chid,
		&rb, 0, vbrs_count_cb, result);
	return err;
}

static void
replicate_chunks(size_t chunk_size, size_t n_chunks, size_t n_vbrs, size_t n_ec_vbrs,
	uint64_t attr, uint8_t rep_cnt, uint64_t opts) {
	uint512_t* chids = je_calloc(n_chunks, sizeof(uint512_t));
	assert_non_null(chids);
	libreptrans_disable_bg();
	for (size_t n = 1; n < n_chunks; n++) {
		uv_buf_t ub = {.len = chunk_size };
		ub.base = je_malloc(chunk_size);
		ub.len = chunk_size;
		rtbuf_t* rb = rtbuf_init(&ub, 1);
		assert_non_null(rb);
		uint512_t nhid;
		randomize_buffer(&nhid, sizeof(nhid));
		randomize_buffer(ub.base, chunk_size);
		int err = reptrans_put_blob_with_attr(devices[0],
			TT_CHUNK_PAYLOAD, HASH_TYPE_DEFAULT, rb, chids + n,
			1, reptrans_get_timestamp(devices[0]));
		if (err) {
			if (err != -EEXIST) {
				assert_int_equal(err, 0);
			} else {
				rtbuf_destroy(rb);
				continue;
			}
		}

		if (n_vbrs > 0) {
			struct backref vbr = {
				.generation = 1,
				.uvid_timestamp = get_timestamp_us(),
				.name_hash_id = uint512_null,
				.ref_type = TT_VERSION_MANIFEST,
				.ref_chid = nhid,
				.rep_count = rep_cnt,
				.ref_hash = HASH_TYPE_DEFAULT,
				.attr = VBR_ATTR_CP
			};
			for (size_t k = 0; k < n_vbrs + n_ec_vbrs; k++) {
				if (k >= n_vbrs) {
					vbr.attr |= VBR_ATTR_EC;
					vbr.rep_count = 1;
				}
				assert_int_equal(reptrans_put_backref(devices[0], chids + n,
					    HASH_TYPE_DEFAULT, &vbr), 0);
				vbr.ref_chid.l.l.l++;
			}
			/* Make sure all VBRs are there */
			size_t vbrs = 0;
			err = reptrans_vbr_count(devices[0], HASH_TYPE_DEFAULT, chids + n, &vbrs);
			assert(vbrs >= n_vbrs + n_ec_vbrs);
			vbrs = 0;
			err = reptrans_get_chunk_count_limited(devices[0],
				HASH_TYPE_DEFAULT, TT_VERIFIED_BACKREF, chids + n,
				0, &vbrs);
			assert(vbrs >= n_vbrs);
		}
		reptrans_flush(RD_FLUSH_FORCE);
		usleep(500000);
		size_t vbrs_exp = opts & REPLICATE_EC_VBR ? n_vbrs + n_ec_vbrs : n_vbrs;
		printf("%lu. Dev(%s) replicating payload %016lX\n", n,
			devices[0]->name, chids[n].u.u.u);
		uint512_t* gr = attr & RD_ATTR_TARGETED ? (uint512_t*)&devices[1]->vdevid : &nhid;
		attr |= RD_ATTR_COMPOUND | RD_ATTR_RETRY_FAILFAST | RD_ATTR_NCOMP;
		assert_int_equal(reptrans_replicate_chunk(devices[0], TT_CHUNK_PAYLOAD,
			HASH_TYPE_DEFAULT, chids + n, attr, gr, rep_cnt, opts), 0);
		/* Make sure we have created new replicas */
		size_t n_chunks = 0;
		for (int i = 0; i < n_dev; i++) {
			struct blob_stat bs = {.size = 0 };
			err = reptrans_blob_stat(devices[i], TT_CHUNK_PAYLOAD,
				HASH_TYPE_DEFAULT, chids + n, &bs);
			if (err)
				 continue;
			n_chunks++;
			if (attr & RD_ATTR_TARGETED)
				assert_true(devices[i] == devices[0] || devices[i] == devices[1]);
			/* Make sure all VBRs are there */
			size_t vbrs = 0;
			err = reptrans_vbr_count(devices[i], HASH_TYPE_DEFAULT, chids + n, &vbrs);
			assert(vbrs >= vbrs_exp);
			vbrs = 0;
			err = reptrans_get_chunk_count_limited(devices[i],
				HASH_TYPE_DEFAULT, TT_VERIFIED_BACKREF, chids + n,
				0, &vbrs);
			assert(vbrs >= vbrs_exp);
			/* Cleaning */
			err = reptrans_delete_blob(devices[i], TT_CHUNK_PAYLOAD,
				HASH_TYPE_DEFAULT, chids + n);
			assert_int_equal(err, 0);
			err = reptrans_delete_blob(devices[i], TT_VERIFIED_BACKREF,
				HASH_TYPE_DEFAULT, chids + n);
			assert_int_equal(err, 0);
		}
		if (attr & RD_ATTR_TARGETED)
			assert_int_equal(n_chunks, 2);
		else
			assert_true(n_chunks >= rep_cnt);
		rtbuf_destroy(rb);
	}
	je_free(chids);
}

static void
reptrans_replicate_primary_compound_test(void **state) {

	uint64_t attr = 0;
	replicate_chunks(1024*1024, 100, 1, 0, attr, 3, 0);
}

static void
reptrans_replicate_primary_and_secondary_small_compound_test(void **state) {

	uint64_t attr = 0;
	replicate_chunks(4*1024*1024, 100, 5, 0, attr, 3, 0);
}

static void
reptrans_replicate_primary_sec_small_override_selected(void **state) {

	uint64_t attr = 0;
	replicate_chunks(4*1024*1024, 100, 5, 0, attr, 3, COMPOUND_FLAG_OVERRIDE_SELECTED);
}

static void
reptrans_replicate_prim_sec_no_ec(void **state) {

	uint64_t attr = 0;
	replicate_chunks(4*1024*1024, 100, 5, 4, attr, 3, 0);
}

static void
reptrans_replicate_prim_sec_ec(void **state) {

	uint64_t attr = 0;
	replicate_chunks(4*1024*1024, 100, 5, 4, attr, 3, REPLICATE_EC_VBR);
}

static void
reptrans_replicate_prim_sec_targeted(void **state) {

	uint64_t attr = RD_ATTR_TARGETED;
	replicate_chunks(4*1024*1024, 100, 5, 4, attr, 3, REPLICATE_EC_VBR);
}


static void
reptrans_replicate_primary_and_secondary_middle_compound_test(void **state) {

	uint64_t attr = 0;
	replicate_chunks(4*1024*1024, 100, 100000, 0, attr, 3, 0);
}

static void
reptrans_replicate_primary_and_secondary_huge_compound_test(void **state) {

	uint64_t attr = 0;
	replicate_chunks(4*1024*1024, 30, 10000000, 0, attr, 3, 0);
}

static void
reptrans_ngrequest_locate_test(void **state) {
	libreptrans_disable_bg();
	size_t chunk_size = 4*1024*1024;
	size_t n_vbrs = 1024;
	size_t n_ec_vbrs = 10;
	uint8_t rep_cnt = 3;

	struct backref br_lookup = {
		.ref_type = 0
	};
	for (size_t n = 0; n < 100; n++) {
		uint512_t chid;
		br_lookup.ref_type = 0;
		uv_buf_t ub = {.len = chunk_size };
		ub.base = je_malloc(chunk_size);
		ub.len = chunk_size;
		rtbuf_t* rb = rtbuf_init(&ub, 1);
		assert_non_null(rb);
		uint512_t nhid;
		randomize_buffer(&nhid, sizeof(nhid));
		do {
			randomize_buffer(ub.base, chunk_size);
			int err = rtbuf_hash(rb, HASH_TYPE_DEFAULT, &chid);
			assert_int_equal(err, 0);
		} while (!flexhash_is_rowmember(SERVER_FLEXHASH, &devices[0]->vdevid, &chid));

		int err = reptrans_put_blob_with_attr(devices[0],
			TT_CHUNK_PAYLOAD, HASH_TYPE_DEFAULT, rb, &chid,
			0, reptrans_get_timestamp(devices[0]));
		assert_int_equal(err, 0);

		uint64_t bsz = 0ULL;
		err = reptrans_blob_query(devices[0], TT_CHUNK_PAYLOAD,
			HASH_TYPE_DEFAULT, &chid, &bsz);
		assert_true(err != 0);

		printf("%lu. Adding payload chid %016lX\n", n, chid.u.u.u);
		if (n_vbrs > 0) {
			struct backref vbr = {
				.generation = 1,
				.uvid_timestamp = get_timestamp_us(),
				.name_hash_id = uint512_null,
				.ref_type = TT_VERSION_MANIFEST,
				.ref_chid = nhid,
				.rep_count = rep_cnt,
				.ref_hash = HASH_TYPE_DEFAULT,
				.attr = VBR_ATTR_CP
			};
			for (size_t k = 0; k < n_vbrs + n_ec_vbrs; k++) {
				if (k >= n_vbrs) {
					vbr.attr |= VBR_ATTR_EC;
					vbr.rep_count = 1;
				}
				assert_int_equal(reptrans_put_backref(devices[0], &chid,
					    HASH_TYPE_DEFAULT, &vbr), 0);
				if (br_lookup.ref_type == 0)
					br_lookup = vbr;
				vbr.ref_chid.l.l.l++;
			}
			/* Make sure all VBRs are there */
			size_t vbrs = 0;
			err = reptrans_vbr_count(devices[0], HASH_TYPE_DEFAULT, &chid, &vbrs);
			assert(vbrs >= n_vbrs + n_ec_vbrs);
			vbrs = 0;
			err = reptrans_get_chunk_count_limited(devices[0],
				HASH_TYPE_DEFAULT, TT_VERIFIED_BACKREF, &chid,
				0, &vbrs);
			assert(vbrs >= n_vbrs);
		}

		struct chunk_info info = {
			.chid = chid,
			.ttype = TT_CHUNK_PAYLOAD,
			.hash_type = HASH_TYPE_DEFAULT
		};
		/* Try to find our chunk copies */
		err =  ec_locate_chunk(devices[1], &info, NULL, 1);
		assert_int_equal(err, 0);
		assert_int_equal(info.n_vdevs, 1);
		assert_int_equal(info.nvbrs[0], 1);

		info.n_vdevs = 0;
		err =  ec_locate_chunk(devices[1], &info, NULL, 100);
		assert_int_equal(err, 0);
		assert_int_equal(info.n_vdevs, 1);
		assert_int_equal(info.nvbrs[0], 100);

		info.n_vdevs = 0;
		err =  ec_locate_chunk(devices[1], &info, NULL, ~0LU);
		assert_int_equal(err, 0);
		assert_int_equal(info.n_vdevs, 1);
		assert_true(info.nvbrs[0] >= n_vbrs + n_ec_vbrs);

		/* Extended VBR attribute location test */
		info.n_vdevs = 0;
		struct backref br = {
			.attr = VBR_ATTR_EC
		};
		err = ec_locate_chunk_ext(devices[1], &info, NULL, &br, VBR_ATTR_EC,
			1, LOCATE_MATCH_VBR_ATTR);
		assert_int_equal(err, 0);
		assert_int_equal(info.n_vdevs, 1);
		assert_int_equal(info.nvbrs[0], 1);

		info.n_vdevs = 0;
		br.attr = 0;
		err = ec_locate_chunk_ext(devices[1], &info, NULL, &br, VBR_ATTR_EC,
			n_ec_vbrs*2, LOCATE_MATCH_VBR_ATTR);
		assert_int_equal(err, 0);
		assert_int_equal(info.n_vdevs, 1);
		/**
		 * NOTE: the current implementation of VBR iterator doesn't filter out duplicates.
		 * Can happen the same VBR is counted twice: in WAL and main table.
		 */
		assert_true(info.nvbrs[0] > n_ec_vbrs);

		/* Testing an entire VBR lookup feature */
		info.n_vdevs = 0;
		err = ec_locate_chunk_ext(devices[1], &info, NULL, &br_lookup, 0,
			n_ec_vbrs*2, LOCATE_MATCH_VBR);
		assert_int_equal(err, 0);
		assert_int_equal(info.n_vdevs, 1);
		assert_int_equal(info.nvbrs[0], 1);

		if (rb)
			rtbuf_destroy(rb);

		/* Cleaning */
		err = reptrans_delete_blob(devices[0], TT_CHUNK_PAYLOAD,
			HASH_TYPE_DEFAULT, &chid);
		assert_int_equal(err, 0);
		err = reptrans_delete_blob(devices[0], TT_VERIFIED_BACKREF,
			HASH_TYPE_DEFAULT, &chid);
		assert_int_equal(err, 0);
	}
}

static void
reptrans_replicate_one_test(void **state) {
	if (!dd) {
		assert_int_not_equal(n_dev, 0);
		/* stopping device background tasks */
		libreptrans_disable_bg();
		/*
		 * NOTE: this test doesn't cover whole replication procedure
		 * It performs sequential replication of data chunks in order to
		 * test replication data path and data integrity
		 */
		for (int n = 1; n < n_iterations; n++) {
			uv_buf_t payload;
			int nbufs = 1;
			size_t ch_size = 0;
			while ((ch_size = rand_r(&seed) % 1024*1024) < 64);
			char *buf = je_malloc(ch_size);
			payload.base = buf;
			payload.len = ch_size;

			uint512_t key, nhid;
			randomize_buffer(&nhid, sizeof(nhid));
			randomize_buffer(buf, ch_size);

			rtbuf_t *rb = rtbuf_init_mapped(&payload, nbufs);
			int err = reptrans_put_blob_with_attr(devices[0],
				TT_CHUNK_PAYLOAD, HASH_TYPE_DEFAULT, rb, &key,
				1, reptrans_get_timestamp(devices[0]));
			if (err) {
				if (err != -EEXIST) {
					assert_int_equal(err, 0);
				} else {
					rtbuf_destroy(rb);
					je_free(buf);
					continue;
				}
			}
			struct backref vbr = {
				.generation = 1,
				.uvid_timestamp = get_timestamp_us(),
				.name_hash_id = key,
				.ref_type = TT_VERSION_MANIFEST,
				.ref_chid = nhid,
				.rep_count = 3,
				.ref_hash = HASH_TYPE_DEFAULT,
				.attr = VBR_ATTR_CP
			};
			/*
			 * storing CHUNK_PAYLOAD and corresponding backref locally
			 * and start data chunk replication
			 */
			uint64_t attr = RD_ATTR_COMPOUND | RD_ATTR_RETRY_FAILFAST | RD_ATTR_NCOMP;
			assert_int_equal(reptrans_put_backref(devices[0], &key,
				    HASH_TYPE_DEFAULT, &vbr), 0);
			assert_int_equal(reptrans_replicate_chunk(devices[0], TT_CHUNK_PAYLOAD,
				    HASH_TYPE_DEFAULT, &key, attr, &nhid, 3, 0), 0);
			assert_int_equal(reptrans_delete_blob(devices[0], TT_CHUNK_PAYLOAD,
				    HASH_TYPE_DEFAULT, &key), 0);
			assert_int_equal(reptrans_delete_blob(devices[0], TT_VERIFIED_BACKREF,
				    HASH_TYPE_DEFAULT, &key), 0);
			rtbuf_destroy(rb);
			je_free(buf);
			printf("%d. replicated %lu bytes\n", n, ch_size);
		}
		usleep(100000);
	}
}

static uint512_t
get_random_chid() {
	srandom(get_timestamp_us() % 32768);
	uint512_t rc;
	int64_t* p = (int64_t*)&rc;
	for (uint32_t i = 0; i < sizeof(uint512_t)/sizeof(int64_t); i++) {
		*(p+i) = random();
	}
	return rc;
}

struct ver_queue_iter_arg {
	int n;
	int i;
	struct verification_request* vreqs;
	uint512_t* vreq_keys;
};

static int
vq_blob_callback(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *key, uv_buf_t *val, void *param) {
	struct ver_queue_iter_arg* arg = param;
	struct verification_request* vreq = (struct verification_request*)val->base;
	if (arg->i < arg->n && vreq->n_parity == 200) {
		assert_int_equal(sizeof(struct verification_request), val->len);
		assert_int_equal(uint512_cmp(key, arg->vreq_keys + arg->i), 0);
		assert_int_equal(memcmp(val->base, arg->vreqs + arg->i, val->len), 0);
		arg->i++;
	}
	return 0;
}

#define VQ_ENTRIES	2047

static void
reptrans_verification_queue_test(void **state) {
	if (!dd) {
		assert_int_not_equal(n_dev, 0);
		/* stopping device background tasks */
		libreptrans_disable_bg();

		 struct verification_request* vreqs = je_calloc(VQ_ENTRIES,
			sizeof(struct verification_request));
		 uint512_t* vbreq_keys = je_calloc(VQ_ENTRIES, sizeof(uint512_t));

		 struct verification_request vreq = {
			.chid = get_random_chid(),
			.nhid = {{{1, 2}, {3, 4}}, {{5, 6}, {7, 8}}},
			.target_vdevid = uint128_null,
			.uvid_timestamp = get_timestamp_us(),
			.generation = 1,
			.vtype = RT_VERIFY_NORMAL,
			.ttag = TT_VERSION_MANIFEST,
			.n_parity = 200, /* To distinguish test entries */
			.vbr = {
				.name_hash_id = {{{1, 2}, {3, 4}}, {{5, 6}, {7, 8}}},
				.ref_type = TT_NAMEINDEX,
				.ref_chid = get_random_chid(),
				.ref_hash = HASH_TYPE_DEFAULT
			}
		 };
		/* Adding few entries into verification queue */
		 for (int i = 0; i < VQ_ENTRIES; i++) {
			 assert_int_equal(reptrans_request_verification(devices[0],
				&vreq, vbreq_keys + i), 0);
			 vreqs[i] = vreq;
			 if (i < VQ_ENTRIES/2) {
				 vreq.generation++;
				 if (i == VQ_ENTRIES/10)
					 vreq.vtype = RT_VERIFY_DELETE;
			 } else {
				vreq.generation = 1;
				vreq.nhid = get_random_chid();
				vreq.vbr.name_hash_id.u.u.u++;
			 }
		 }
		 /* Iterate the ver. queue. Ensure the entres are fetched in a
		  * chronological order.
		  */
		 struct ver_queue_iter_arg arg = {
			.n = VQ_ENTRIES,
			.i = 0,
			.vreqs = vreqs,
			.vreq_keys = vbreq_keys
		 };
		 int err = reptrans_iterate_blobs_strict_order(devices[0],
			TT_VERIFICATION_QUEUE, vq_blob_callback, &arg, 1);
		 assert_int_equal(err ,0);
		 assert_int_equal(arg.i, VQ_ENTRIES);
		/* Remove verification queue entries */
		 for (int i = 0; i < VQ_ENTRIES; i++) {
			 err = reptrans_delete_blob(devices[0], TT_VERIFICATION_QUEUE,
				HASH_TYPE_DEFAULT, vbreq_keys + i);
			 assert_int_equal(err ,0);
		 }
		 je_free(vbreq_keys);
		 je_free(vreqs);
	}
}

static int
batch_all_filter(void *arg, void **data, size_t *size, int set) {
	return 1;
}

static void
reptrans_batch_queue_test(void **state) {
	if (!dd) {
		/* stopping device background tasks */
		libreptrans_disable_bg();
		struct repdev* dev = devices[0];
		uint64_t ng = 0;
		/* Clean batch queues */
		uint16_t n_groups = flexhash_numrows(ccow_daemon->flexhash);
		for (ng = 0; ng < n_groups; ++ng) {
			uint512_t batch_key = uint512_null;
			batch_key.u.u.u = NG_TO_KEY(ng);
			int err = reptrans_delete_blob(dev, TT_BATCH_QUEUE, HASH_TYPE_DEFAULT, &batch_key);
			assert_int_equal(err, 0);
		}
		for (int k = 0; k < 100; k++) {
			assert_int_not_equal(n_dev, 0);
			struct verification_request vreq = {
				.chid = get_random_chid(),
				.nhid = {{{1, 2}, {3, 4}}, {{5, 6}, {7, 8}}},
				.target_vdevid = uint128_null,
				.uvid_timestamp = get_timestamp_us(),
				.generation = 1,
				.vtype = RT_VERIFY_NORMAL,
				.ttag = TT_VERSION_MANIFEST,
				.vbr = {
					.name_hash_id = {{{1, 2}, {3, 4}}, {{5, 6}, {7, 8}}},
					.ref_type = TT_NAMEINDEX,
					.ref_chid = get_random_chid(),
					.ref_hash = HASH_TYPE_DEFAULT
				}
			};
			uint64_t ts = get_timestamp_us();
			int bq_entries = rand() % 2048;
			/* Adding few entries into batch queue */
			for (int i = 0; i < bq_entries; i++) {
				int err = reptrans_enqueue_batch_request(dev, NULL,
					&vreq);
				assert_int_equal(err, 0);
				if (i < bq_entries/2) {
					vreq.generation++;
					if (i == 3)
						vreq.vtype = RT_VERIFY_DELETE;
				} else {
					vreq.generation = 1;
					vreq.nhid.u.u.u++;
				}
			}
			printf("%d BATCH QUEUE entries inserted in %lu uS\n", bq_entries,
				get_timestamp_us() - ts);
			/* Fetching data from the queue for each NG and
			 * check they are ordered properly
			 */
			ts = get_timestamp_us();
			int n_bqs = 0;
			for (ng = 0; ng < n_groups; ++ng) {
				uint512_t batch_key = uint512_null;
				batch_key.u.u.u = NG_TO_KEY(ng);
				rtbuf_t *rb = NULL;
				int err = dev->__vtbl->get_blob(dev, TT_BATCH_QUEUE,
					HASH_TYPE_DEFAULT, GBF_FLAG_ALL, &batch_key, &rb,
					100000, batch_all_filter, NULL);
				if (err == -ENOENT)
					continue;
				assert_int_equal(err, 0);
				assert_non_null(rb);
				uint64_t ts_prev = 0;
				for (size_t n = 0; n < rb->nbufs; n++) {
					msgpack_u ua;
					msgpack_unpack_init_b(&ua, rtbuf(rb, n).base,
						rtbuf(rb, n).len, 0);
					uint64_t ts = 0;
					err = unpack_batch_entry(&ua, &vreq, &ts);
					if (ts_prev > ts) {
						printf("BQ: ts(prev) %lu ts(curr) %lu, ng %lu, it %lu\n",ts_prev, ts,  ng, n);
					}
					assert_true(ts >= ts_prev);
					n_bqs++;
					ts_prev = ts;
				}
				err = reptrans_delete_blob_value(dev,
					TT_BATCH_QUEUE, HASH_TYPE_DEFAULT, &batch_key,
					rb->bufs, rb->nbufs);
				rtbuf_destroy(rb);
				assert_int_equal(err ,0);
			}
			if (bq_entries != n_bqs) {
				printf("ERR: #BQ %d (exp) vs %d (act)\n", bq_entries, n_bqs);
			}
			assert_int_equal(bq_entries, n_bqs);
			printf("%d BATCH QUEUE iterate/delete test done in %lu uS\n",
				n_bqs, get_timestamp_us() - ts);
		}
	}
}

#define IBQ_ENTRIES 512
#define BATCH_SIZE (48*1024 - 40)

struct incoming_bach_queue_arg {
	char** buffs;
	uint512_t* keys;
	volatile uint64_t ts_prev;
	volatile int n;
};

static int
incoming_batch_callback(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *key, uv_buf_t *val, void *param) {
	struct incoming_bach_queue_arg* arg = param;
	if (arg->n < IBQ_ENTRIES) {
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

		/* verify that we can read the key */
		rtbuf_t* rb;
		err = reptrans_get_blob(dev, TT_BATCH_INCOMING_QUEUE,
		    HASH_TYPE_DEFAULT, key, &rb);
		assert_int_equal(err, 0);
		rtbuf_destroy(rb);
#if 0
		err = memcmp(dptr, arg->buffs[arg->n], dl);
		assert_int_equal(0, err);
#endif
		err = reptrans_delete_blob(dev, TT_BATCH_INCOMING_QUEUE,
			HASH_TYPE_DEFAULT, key);
		assert_int_equal(err, 0);
		arg->keys[arg->n] = *key;
	}
	arg->n++;
	return 0;
}

static void
reptrans_batch_incoming_queue_test(void **state) {
	if (!dd) {
		assert_int_not_equal(n_dev, 0);
		/* stopping device background tasks */
		libreptrans_disable_bg();
		struct repdev* dev = devices[0];
		char* ibq_buffs[IBQ_ENTRIES];
		uint512_t* keys = je_calloc(IBQ_ENTRIES, sizeof(uint512_t));
		uint64_t ts_offset = 0;
		for (uint32_t i = 0; i < IBQ_ENTRIES; i++) {
			if (i % 10 == 0)
				ts_offset = rand() % 65536;
			ibq_buffs[i] = je_calloc(1, BATCH_SIZE);
			assert_non_null(ibq_buffs[i]);
			randomize_buffer(ibq_buffs[i], BATCH_SIZE);
			msgpack_p* pack = msgpack_pack_init();
			assert_non_null(pack);
			uint64_t ts = get_timestamp_us() + ts_offset;
			int err = msgpack_pack_uint64(pack, ts);
			assert_int_equal(err, 0);
			err = msgpack_pack_raw(pack, ibq_buffs[i], BATCH_SIZE);
			assert_int_equal(err, 0);
			uv_buf_t pb;
			msgpack_get_buffer(pack, &pb);
			err = reptrans_enqueue_batch(dev, pb.base, pb.len);
			assert_int_equal(err ,0);
			msgpack_pack_free(pack);
		}
		struct incoming_bach_queue_arg arg = {
				.buffs = ibq_buffs,
				.keys = keys,
				.n = 0,
				.ts_prev = 0
		};

		int err = reptrans_iterate_blobs_strict_order(dev,
			TT_BATCH_INCOMING_QUEUE, incoming_batch_callback,
			&arg, 1);
		assert_int_equal(err, 0);
		assert_int_equal(arg.n, IBQ_ENTRIES);

		/* Ensure we don't iterate delete entries */
		arg.n = 0;
		err = reptrans_iterate_blobs_strict_order(dev,
			TT_BATCH_INCOMING_QUEUE, incoming_batch_callback,
			&arg, 1);
		assert_int_equal(err, 0);
		assert_int_equal(arg.n, 0);

		je_free(keys);
		for (uint32_t i = 0; i < IBQ_ENTRIES; i++)
			if (ibq_buffs[i])
				je_free(ibq_buffs[i]);
	}
}

int
main(int argc, char *argv[]) {
   int opt, err = 0;
   int ext_replication = 0;
   srand(time(NULL));
   seed = rand();
   while ((opt = getopt(argc, argv, "ni:r")) != -1) {
        switch (opt) {
        case 'i':
            n_iterations = atoi(optarg);
            break;

        case 'n':
        	dd = 1;
        	break;

        case 'r':
        	ext_replication = 1;
        	break;

        default:
        	break;
        }
    }
	if (!ext_replication) {
		const UnitTest tests[] = {
			unit_test(libccowd_setup),
			unit_test(libccow_setup),
			unit_test(bucket_create),
			unit_test(libreptrans_setup),
			unit_test(reptrans_ngrequest_locate_test),
			unit_test(reptrans_batch_incoming_queue_test),
			unit_test(reptrans_verification_queue_test),
			unit_test(reptrans_batch_queue_test),
			unit_test(reptrans_put_version__test),
			unit_test(reptrans_iterator__test),
			unit_test(reptrans_delete_index__test),
			unit_test(reptrans_replicate_one_test),
			unit_test(reptrans_replicate_primary_compound_test),
			unit_test(reptrans_replicate_primary_and_secondary_small_compound_test),
			unit_test(reptrans_replicate_primary_sec_small_override_selected),
			unit_test(reptrans_replicate_prim_sec_no_ec),
			unit_test(reptrans_replicate_prim_sec_ec),
			unit_test(reptrans_replicate_prim_sec_targeted),
			unit_test(bucket_delete),
			unit_test(libccow_teardown),
			unit_test(libccowd_teardown)
		};
		err = run_tests(tests);
	} else {
		const UnitTest tests[] = {
			unit_test(libccowd_setup),
			unit_test(libccow_setup),
			unit_test(bucket_create),
			unit_test(libreptrans_setup),
			unit_test(reptrans_replicate_primary_compound_test),
			unit_test(reptrans_replicate_prim_sec_no_ec),
			unit_test(reptrans_replicate_prim_sec_ec),
			unit_test(reptrans_replicate_prim_sec_targeted),
			unit_test(reptrans_replicate_primary_and_secondary_small_compound_test),
			unit_test(reptrans_replicate_primary_and_secondary_middle_compound_test),
			unit_test(reptrans_replicate_primary_and_secondary_huge_compound_test),
			unit_test(bucket_delete),
			unit_test(libccow_teardown),
			unit_test(libccowd_teardown)
		};
		err = run_tests(tests);
	}
	return err;
}
