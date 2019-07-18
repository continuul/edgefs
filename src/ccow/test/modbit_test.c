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
#include "ccow-impl.h"
#include "ccowd.h"
#include "reptrans.h"
#include "isgw-impl.h"

#define TEST_BUF_LEN	10240

static ccow_t tc = NULL;
int dd = 0;
struct isgw_cluster cluster;
int bufcnt = TEST_BUF_LEN;
char obj[PATH_MAX];

static char *typestr[] = { "INV", "CP", "CM", "ZB", "IN", "IN", "IN" };

struct _refitem
{
	QUEUE item;
	int type;
	uint512_t chid;
	uint64_t offset;
	int mod;
	int level;
	int match;
};

QUEUE refqueue1, refqueue2, refqueue3;

static void
refqueue_free(QUEUE *Q)
{
	QUEUE *q;
	struct _refitem *r;
	while (!QUEUE_EMPTY(Q)) {
		q = QUEUE_NEXT(Q);
		QUEUE_REMOVE(q);
		r = QUEUE_DATA(q, struct _refitem, item);
		free(r);
	}
}

static void
vm_diff_modbit(rtbuf_t *rb, QUEUE *qnew, QUEUE *qres)
{
	QUEUE *p, *q;
	struct _refitem *rnew, *rres;
	char out[129];
	printf("Differential CHIDS based on modbit\n");
	QUEUE_FOREACH(q, qnew) {
		rnew = QUEUE_DATA(q, struct _refitem, item);
		if (rnew->type == RT_REF_TYPE_MANIFEST && rnew->mod) {
			uint512_dump(&rnew->chid, out, 129);
			out[32] = 0;
			printf("%s Offset %lu chidnew %s level %d\n",
				typestr[rnew->type], rnew->offset, out, rnew->level);
		}
	}
	printf("\n");

	int found, err = 0;
	QUEUE_FOREACH(p, qres) {
		rres = QUEUE_DATA(p, struct _refitem, item);
		found = 0;
		QUEUE_FOREACH(q, qnew) {
			rnew = QUEUE_DATA(q, struct _refitem, item);
			if (uint512_cmp(&rres->chid, &rnew->chid) == 0) {
				found = 1;
				break;
			}
		}
		if (!found) {
			printf("ERROR %s Offset %lu chidnew %s level %d not detected by mod bit\n",
				typestr[rres->type], rres->offset, out, rres->level);
			err = 1;
		}
	}
	if (!err)
		printf("All CM changes detected by DFS are also found by mod bit.\n");
}

static void
vm_diff(QUEUE *qold, QUEUE *qnew, QUEUE *qres)
{
	struct _refitem *rold, *rnew;
	QUEUE *p, *q;
	char out[129];
	printf("Differential CHIDS based on DFS comparison\n");
	QUEUE_FOREACH(q, qnew) {
		rnew = QUEUE_DATA(q, struct _refitem, item);
		QUEUE_FOREACH(p, qold) {
			rold = QUEUE_DATA(p, struct _refitem, item);
			if (rold->offset == rnew->offset &&
			    rold->type == rnew->type &&
			    rold->type == RT_REF_TYPE_MANIFEST &&
			    rold->level == rnew->level &&
			    uint512_cmp(&rold->chid, &rnew->chid) == 0) {
				rnew->match = 1;
			}
		}
	}
	QUEUE_FOREACH(q, qnew) {
		rnew = QUEUE_DATA(q, struct _refitem, item);
		if (!rnew->match &&
		    rnew->type == RT_REF_TYPE_MANIFEST) {
			uint512_dump(&rnew->chid, out, 129);
			out[32] = 0;
			printf("%s Offset %lu chidnew %s level %d\n",
			    typestr[rnew->type], rnew->offset, out, rnew->level);

			struct _refitem *r = calloc(1, sizeof(*r));
			assert(r != NULL);
			*r = *rnew;
			QUEUE_INIT(&r->item);
			QUEUE_INSERT_TAIL(qres, &r->item);
		}
	}
	printf("\n");
}

static void
cm_traverse(struct refentry *cmre, QUEUE *q, int level)
{
	char out[129];
	rtbuf_t *rb = NULL;
	rtbuf_t *refs = NULL;
	struct refentry *re;
	assert_int_equal(isgw_get_chunk_manifest(&cluster, cmre, &rb), 0);
	assert_int_equal(replicast_unpack_cm_refs(rb, &refs, 1), 0);
	for (unsigned int i = 0; i < refs->nbufs; i++) {
		re = (struct refentry *) rtbuf(refs, i).base;
		uint512_dump(&re->content_hash_id, out, 129);
		out[32] = 0;
		if (RT_REF_TYPE(re) == RT_REF_TYPE_MANIFEST)
			printf("%s offset %lu length %lu CHID %s MOD %d comp %d hash %d enc %d level %d\n",
				typestr[RT_REF_TYPE(re)], re->offset, re->length, out,
				RT_REF_MOD(re), RT_REF_COMPRESS_TYPE(re), RT_REF_HASH_TYPE(re),
				RT_REF_ENCRYPT_TYPE(re), level);

		struct _refitem *r = calloc(1, sizeof(*r));
		assert(r != NULL);
		r->type = RT_REF_TYPE(re);
		r->chid = re->content_hash_id;
		r->offset = re->offset;
		r->mod = RT_REF_MOD(re);
		r->level = level;
		QUEUE_INIT(&r->item);
		QUEUE_INSERT_TAIL(q, &r->item);

		if (RT_REF_TYPE(re) == RT_REF_TYPE_MANIFEST) {
			cm_traverse(re, q, level + 1);
		}
	}
	if (rb)
		rtbuf_destroy(rb);
	if (refs)
		rtbuf_destroy(refs);
}

static void
vm_traverse(rtbuf_t *rb, QUEUE *q)
{
	char out[129];
	rtbuf_t *rl;
	struct refentry *re;

	assert_int_equal(replicast_get_refs(rb, &rl, 1), 0);
	printf("VM nbufs %lu\n", rl->nbufs);
	for (unsigned int i = 0; i < rl->nbufs; i++) {
		re = (struct refentry *) rtbuf(rl, i).base;
		uint512_dump(&re->content_hash_id, out, 129);
		out[32] = 0;
		if (RT_REF_TYPE(re) == RT_REF_TYPE_MANIFEST)
			printf("%s offset %lu length %lu CHID %s MOD %d comp %d hash %d enc %d level 1\n",
				typestr[RT_REF_TYPE(re)], re->offset, re->length, out,
				RT_REF_MOD(re), RT_REF_COMPRESS_TYPE(re), RT_REF_HASH_TYPE(re),
				RT_REF_ENCRYPT_TYPE(re));

		struct _refitem *r = calloc(1, sizeof(*r));
		assert(r != NULL);
		r->type = RT_REF_TYPE(re);
		r->chid = re->content_hash_id;
		r->offset = re->offset;
		r->mod = RT_REF_MOD(re);
		r->level = 1;
		QUEUE_INIT(&r->item);
		QUEUE_INSERT_TAIL(q, &r->item);

		if (RT_REF_TYPE(re) == RT_REF_TYPE_MANIFEST) {
			cm_traverse(re, q, 2);
		}
	}
}

static void
modbit_test(void **state)
{
	int err, ret, i, j;
	uint512_t vmchid1, vmchid2, nhid;
	char vmchid_str1[129], vmchid_str2[129];
	uint64_t genid1, genid2, ts1, ts2;
	struct iovec iov[TEST_BUF_LEN];
	ccow_completion_t c;
	rtbuf_t *rb1, *rb2;
	struct vmmetadata md1, md2;
	char *buf[TEST_BUF_LEN];
	uint16_t bto = 16;
	uint32_t bs = 4096;

	srandom((unsigned int)time(NULL));
	for (i = 0; i < bufcnt; i++) {
		buf[i] = je_calloc(1, 4096);
		assert(buf[i] != NULL);
		for (j = 0; j < 4096; j++)
			buf[i][j] = 'a' + (random() % 26);
		iov[i].iov_base = buf[i];
		iov[i].iov_len = 4096;
	}

	QUEUE_INIT(&refqueue1);
	QUEUE_INIT(&refqueue2);
	QUEUE_INIT(&refqueue3);
	assert_int_equal(isgw_cluster_init(&cluster), 0);

	printf("Put first\n");

	assert_int_equal(ccow_create_completion(tc, NULL, NULL, bufcnt, &c), 0);
	assert_int_equal(ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE, (void *)&bs, NULL), 0);
	assert_int_equal(ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER, (void *)&bto, NULL), 0);
	assert_int_equal(ccow_put("modbit_bucket", 14, obj, strlen(obj) + 1, c, iov, bufcnt, 0), 0);
	assert_int_equal(ccow_wait(c, -1), 0);

	assert_int_equal(isgw_get_object_ids(&cluster, "cltest", "test",
		"modbit_bucket", obj, &vmchid1, &nhid, &genid1), 0);
	assert_int_equal(isgw_get_version_manifest(&cluster, &vmchid1, &nhid, &md1, &rb1), 0);
	uint512_dump(&vmchid1, vmchid_str1, 129);
	vmchid_str1[32] = 0;
	ts1 = md1.uvid_timestamp;
	printf("genid %lu ts %lu vmchid %s\n", genid1, ts1, vmchid_str1);

	vm_traverse(rb1, &refqueue1);
	printf("\n");

	/*for (i = 0; i < 10; i++) {
		buf[i][0] = 'A';
	}
	for (i = bufcnt / 2; i < bufcnt / 2 + 10; i++) {
		buf[i][2024] = 'B';
	}
	for (i = bufcnt - 10; i < bufcnt; i++) {
		buf[i][4090] = 'C';
	}*/

	printf("Sleeping 60s\n");
	sleep(60);
	printf("Put second\n");


	assert_int_equal(ccow_create_completion(tc, NULL, NULL, bufcnt, &c), 0);
	assert_int_equal(ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE, (void *)&bs, NULL), 0);
	assert_int_equal(ccow_attr_modify_default(c, CCOW_ATTR_BTREE_ORDER, (void *)&bto, NULL), 0);
	assert_int_equal(ccow_put("modbit_bucket", 14, obj, strlen(obj) + 1, c, iov, bufcnt, 0), 0);
	assert_int_equal(ccow_wait(c, -1), 0);

	assert_int_equal(isgw_get_object_ids(&cluster, "cltest", "test",
		"modbit_bucket", obj, &vmchid2, &nhid, &genid2), 0);
	assert_int_equal(isgw_get_version_manifest(&cluster, &vmchid2, &nhid, &md2, &rb2), 0);
	uint512_dump(&vmchid2, vmchid_str2, 129);
	vmchid_str2[32] = 0;
	ts2 = md2.uvid_timestamp;
	printf("genid %lu ts %lu vmchid %s\n", genid2, ts2, vmchid_str2);

	vm_traverse(rb2, &refqueue2);
	printf("\n");

	vm_diff(&refqueue1, &refqueue2, &refqueue3);
	vm_diff_modbit(rb2, &refqueue2, &refqueue3);

	refqueue_free(&refqueue1);
	refqueue_free(&refqueue2);
	refqueue_free(&refqueue3);

	rtbuf_destroy(rb1);
	rtbuf_destroy(rb2);

	isgw_cluster_destroy(&cluster);

	for (i = 0; i < bufcnt; i++)
		je_free(buf[i]);
}

static void
libccowd_setup(void **state)
{
	if(!dd) {
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
	assert_true(read(fd, buf, 16383) != -1);
	assert_int_equal(close(fd), 0);
	assert_int_equal(ccow_tenant_init(buf, "cltest", 7, "test", 5, &tc), 0);
	je_free(buf);
}

static void
bucket_create(void **state)
{
	int err;
	assert_non_null(tc);

	err = ccow_bucket_create(tc, "modbit_bucket", 14, NULL);
	assert(err == 0 || err == -EEXIST);
}

static void
bucket_delete(void **state)
{
	assert_non_null(tc);
	ccow_bucket_delete(tc, "modbit_bucket", 14);
}

static void
libccow_teardown(void **state)
{
	assert_non_null(tc);
	ccow_tenant_term(tc);
}

static void
libccowd_teardown(void **state)
{
	if(!dd)
		ccow_daemon_term();
}

int
main(int argc, char **argv)
{
	int opt;

	snprintf(obj, PATH_MAX, "%s", "obj");
	while ((opt = getopt(argc, argv, "nb:o:")) != -1) {
		switch(opt) {
		case 'n':
			dd = 1;
			break;
		case 'b':
			bufcnt = atoi(optarg);
			break;
		case 'o':
			snprintf(obj, PATH_MAX, "%s", optarg);
			break;
		}
	}

	const UnitTest tests[] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(bucket_create),
		unit_test(modbit_test),
		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
