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
#include <time.h>

#include "ccowutil.h"
#include "cmocka.h"
#include "common.h"
#include "ccow.h"
#include "ccow-impl.h"
#include "ccowd.h"
#include "reptrans.h"

#define TEST_BUCKET_NAME	"version-bucket-test"
ccow_t tc;

char object_name[64];
char object_copy[64];
int dd = 0;
char version_vm_content_hash_id[512];
char del_vm_content_hash_id[512];

uint64_t version_uvid_timestamp, del_uvid_timestamp;
uint16_t num_vers = 3;
uint64_t genid_version = 3;
uint64_t genid_del = 4;


static void
libccowd_setup(void **state)
{
    if(!dd){
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
	assert_non_null(tc);
	int err = ccow_bucket_create(tc, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1, NULL);
	if (err != -EEXIST)
		assert_int_equal(err, 0);
}

static void
bucket_delete(void **state)
{
	assert_non_null(tc);
	int err = ccow_bucket_delete(tc, TEST_BUCKET_NAME,
	    strlen(TEST_BUCKET_NAME) + 1);
	assert_int_equal(err, 0);
}


static void
object_delete(void **state)
{
	assert_non_null(tc);
	delete(tc, TEST_BUCKET_NAME, object_name, NULL, NULL);
}

static void
clone_delete(void **state)
{
	assert_non_null(tc);
	delete(tc, TEST_BUCKET_NAME, object_copy, NULL, NULL);
}


static void
put_version(void **state)
{
	int err;
	assert_non_null(tc);

	struct iovec iov[1];

	ccow_completion_t c;
	err = ccow_create_completion(tc, NULL, NULL, num_vers, &c);
	assert_int_equal(err, 0);

	err = ccow_attr_modify_default(c, CCOW_ATTR_NUMBER_OF_VERSIONS,
	    (void *)&num_vers, NULL);
	assert_int_equal(err, 0);

	uint64_t expunge_time = get_timestamp_us() + 10l*3600*1000*1000; // 10 hours
	err = ccow_attr_modify_default(c, CCOW_ATTR_OBJECT_DELETE_AFTER,
		    (void *)&expunge_time, NULL);
	assert_int_equal(err, 0);

	for (int i=0; i<num_vers; i++) {
		iov[0].iov_len = 1024*(i+1);
		iov[0].iov_base = je_malloc(iov[0].iov_len);

		assert_non_null(iov[0].iov_base);

		put_simple(c, TEST_BUCKET_NAME, object_name, &iov[0], 1, 0);
		err = ccow_wait(c, i);
		assert_int_equal(err, 0);

		je_free(iov[0].iov_base);
	}
}

static void
clone_test_clone(void **state)
{
	assert_non_null(tc);
	int err;

	ccow_completion_t c;
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	struct ccow_copy_opts copy_opts;
	copy_opts.tid = "test";
	copy_opts.bid = TEST_BUCKET_NAME;
	copy_opts.oid = object_copy;
	copy_opts.tid_size = 5;
	copy_opts.bid_size = strlen(TEST_BUCKET_NAME) + 1;
	copy_opts.oid_size = strlen(object_copy) + 1;
	copy_opts.genid = &genid_version;
	copy_opts.version_uvid_timestamp = version_uvid_timestamp;
	copy_opts.version_vm_content_hash_id = version_vm_content_hash_id;


	err = ccow_clone(c, "test", 5, TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
	    object_name, strlen(object_name) + 1, &copy_opts);
	assert_int_equal(err, 0);

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);
}

static void
object_versions(void **state)
{
    ccow_lookup_t iter;
    int err;
    uint64_t genid;
    uint64_t timestamp;

    assert_non_null(tc);

	ccow_completion_t c;
    err = ccow_create_completion(tc, NULL, NULL, 1, &c);
    assert_int_equal(err, 0);

    err = ccow_get_versions(TEST_BUCKET_NAME,
    		strlen(TEST_BUCKET_NAME) + 1, object_name, strlen(object_name) + 1,  c, &iter);
    assert_int_equal(err, 0);

    err = ccow_wait(c, 0);
    assert_int_equal(err, 0);

	struct ccow_metadata_kv *kv = NULL;
	int pos = 0;
	char *c512;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_VERSIONS, pos++))) {
		char *b = je_malloc(kv->key_size + 1);
		char *c = je_malloc(kv->value_size + 1);
		memcpy(b, kv->key, kv->key_size);
		b[kv->key_size] = '\0';
		memcpy(c, kv->value, kv->value_size);
		c[kv->value_size] = '\0';
		printf("%d: %s: %s\n", pos, b, c);
		char *sp;
		c512 = strtok_r(b,"|", &sp);
		timestamp = atol(c512);
		c512 = strtok_r(NULL,"|", &sp);
		int g = atoi(c512);
		genid = (g >= 0 ? g : -g);
		c512 = strtok_r(c,"|", &sp);
		c512 = strtok_r(NULL,"|", &sp);
		if (genid == genid_version) {
			printf("genid: %lu: genid_version: %lu\n", genid, genid_version);
			strcpy(version_vm_content_hash_id, c512);
			version_uvid_timestamp = timestamp;
		}
		if (genid == genid_del) {
			printf("genid: %lu: genid_del: %lu\n", genid, genid_del);
			strcpy(del_vm_content_hash_id, c512);
			del_uvid_timestamp = timestamp;
		}
		je_free(b);
		je_free(c);
	}

    ccow_lookup_release(iter);
}

static void
opps_get_chunk_manifest_cb(struct getcommon_client_req *r)
{
	if (r->rb) {
		rtbuf_t *rbcopy = rtbuf_init_alloc(r->rb->bufs, r->rb->nbufs);
		rtbuf_t **rbuf = r->chunkmap_data;
		*rbuf = rbcopy;
	}
}

static int
blobfind_get_chunk(ccow_t cl, type_tag_t ttag, const uint512_t* nhid, const uint512_t* chid, rtbuf_t **rbuf) {
	int err;
	struct ccow_op *get_op;
	struct ccow_io *get_io;
	ccow_completion_t c;

	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	if (err)
		return err;

	err = ccow_operation_create(c, CCOW_GET, &get_op);
	if (err) {
		ccow_release(c);
		return err;
	}

	err = ccow_unnamedget_create(c, opps_get_chunk_manifest_cb,
		get_op, &get_io, NULL);
	if (err) {
		ccow_operation_destroy(get_op, 1);
		ccow_release(c);
		return err;
	}


	struct getcommon_client_req *req = CCOW_IO_REQ(get_io);
	rtbuf_t *rb = NULL;

	req->chid = *chid;
	req->hash_type = HASH_TYPE_DEFAULT;
	req->chunkmap_data = &rb;

	if (ttag == TT_CHUNK_MANIFEST)
		get_io->attributes |= RD_ATTR_CHUNK_MANIFEST;
	else if (ttag == TT_VERSION_MANIFEST) {
		assert(nhid);
		req->ng_chid = *nhid;
		get_io->attributes |= RD_ATTR_VERSION_MANIFEST;
	} else
		get_io->attributes |= RD_ATTR_CHUNK_PAYLOAD;

	get_io->attributes |= RD_ATTR_RETRY_FAILFAST;

	err = ccow_start_io(get_io);
	if (err) {
		ccow_operation_destroy(get_op, 1);
		ccow_release(c);
		return err;
	}
	err = ccow_timed_wait(c, 0, 5000);
	if (err) {
		if (err == -EBUSY) {
			uv_mutex_lock(&c->operations_mutex);
			req->done_cb = NULL;
			uv_mutex_unlock(&c->operations_mutex);
		}
		return err;
	}

	if (rb == NULL)
		return -ENOMEM;

	*rbuf = rb;
	return 0;
}

static void
test_deleted_blob(void **state)
{
	assert_non_null(tc);
	int err;

	uint512_t chid;
	uint512_t nhid = uint512_null;
	rtbuf_t* rb = NULL;
	type_tag_t ttag = TT_VERSION_MANIFEST;
	uint512_fromhex(del_vm_content_hash_id, UINT512_BYTES * 2 + 1, &chid);

	err = blobfind_get_chunk(tc, ttag, &nhid, &chid, &rb);
	assert_int_equal(err, 0);

	struct vmmetadata md;
	char chidstr[UINT512_BYTES*2+1];
	err = replicast_get_metadata(rb, &md);
	assert_int_equal(err, 0);
	printf("CHID:\t\t%s\n", version_vm_content_hash_id);
	printf("CID:\t\t%s\n", md.cid);
	printf("TID:\t\t%s\n", md.tid);
	printf("BID:\t\t%s\n", md.bid);
	printf("OID:\t\t%s\n", md.oid);
	uint512_dump(&md.nhid, chidstr, UINT512_BYTES*2+1);
	printf("NHID:\t\t%s\n", chidstr);
	uint128_dump(&md.uvid_src_guid, chidstr, UINT128_BYTES*2+1);
	printf("SRVID:\t\t%s\n", chidstr);
	printf("Log. size:\t%lu\n", md.logical_size);
	printf("UVID:\t\t%lu\n", md.uvid_timestamp);
	printf("GEN:\t\t%lu\n", md.txid_generation);
	printf("Obj. deleted:\t%u\n", md.object_deleted);
	printf("RepCount:\t%u\n", md.replication_count);
	printf("Num.vers:\t%u\n", md.number_of_versions);
	printf("Btree order:\t%u\n", md.chunkmap_btree_order);
	printf("Chunk size:\t%u\n", md.chunkmap_chunk_size);
	printf("Chunk map type:\t%s\n", md.chunkmap_type);

}


static void
object_attributes(void **state)
{
    ccow_lookup_t iter;
    int err;

    assert_non_null(tc);

	ccow_completion_t c;

	printf("Generation: %lu version_uvid_timestamp: %lu version_vm_content_hash_id: %s\n",
			genid_version, version_uvid_timestamp, version_vm_content_hash_id);

    err = ccow_create_stream_completion_versioned(tc, NULL, NULL, 1, &c,
		TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
			object_name, strlen(object_name) + 1,
			&genid_version, version_uvid_timestamp, version_vm_content_hash_id, NULL, &iter);
    assert_int_equal(err, 0);

	dump_iter_to_stdout(iter, CCOW_MDTYPE_METADATA);

    ccow_lookup_release(iter);
}

static void
clone_attributes(void **state)
{
    ccow_lookup_t iter;
    int err;

    assert_non_null(tc);

	ccow_completion_t c;

    err = ccow_create_stream_completion(tc, NULL, NULL, 1, &c,
		TEST_BUCKET_NAME, strlen(TEST_BUCKET_NAME) + 1,
		object_copy, strlen(object_name) + 1,
		NULL, NULL, &iter);
    assert_int_equal(err, 0);

	dump_iter_to_stdout(iter, CCOW_MDTYPE_METADATA);

    ccow_lookup_release(iter);
}


static void
libccow_teardown(void **state)
{
	assert_non_null(tc);
	ccow_tenant_term(tc);
}

static void
libccowd_teardown(void **state) {
    if(!dd)
	    ccow_daemon_term();
}

int
main(int argc, char **argv)
{
    if (argc == 2) {
        if (strcmp(argv[1], "-n") == 0)
             dd = 1;
    }

    time_t seconds= time(NULL);
    sprintf(object_name,"vobj.%ld", (long) seconds);
    sprintf(object_copy,"cobj.%ld", (long) seconds);

    printf("Object name: %s Object copy: %s\n\n", object_name, object_copy);


	const UnitTest tests[] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(bucket_create),
		unit_test(put_version),
		unit_test(object_versions),
		unit_test(object_attributes),
		unit_test(clone_test_clone),
		unit_test(clone_attributes),
		unit_test(object_delete),
		unit_test(object_versions),
		unit_test(test_deleted_blob),
		unit_test(clone_delete),
		unit_test(bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
