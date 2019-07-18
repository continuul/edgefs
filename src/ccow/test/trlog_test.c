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
#include "trlog.h"
#include "reptrans.h"

static ccow_t cl = NULL;
int dd = 0;

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
	char ccowbuf[16384];
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
	int fd = open(path, O_RDONLY);
	assert_true(fd >= 0);
	assert_true(read(fd, ccowbuf, 16383) != -1);
	assert_int_equal(close(fd), 0);
	assert_int_equal(ccow_admin_init(ccowbuf, "", 1, &cl), 0);
}

static int
trlog_test_get_vm(ccow_t tc, void *arg_vmchid, void *arg_nhid, void *arg_md)
{
	int err;
	uint512_t *vmchid = arg_vmchid;
	uint512_t *nhid = arg_nhid;
	struct vmmetadata *md = arg_md;
	struct ccow_op *ug_op;
	struct ccow_io *get_io;
	ccow_completion_t c;
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err)
		return err;

	// FIXME: Hack to disallow chaining
	err = ccow_operation_create(c, CCOW_CLONE, &ug_op);
	if (err) {
		ccow_release(c);
		return err;
	}

	err = ccow_unnamedget_create(c, NULL, ug_op, &get_io,
		NULL);
	if (err) {
		ccow_operation_destroy(ug_op, 1);
		ccow_release(c);
		return err;
	}

	ug_op->optype = CCOW_GET;
	ug_op->iov_in = NULL;
	ug_op->iovcnt_in = 0;
	ug_op->offset = 0;

	get_io->attributes |= (RD_ATTR_VERSION_MANIFEST | RD_ATTR_GET_CONSENSUS);

	struct getcommon_client_req *req = CCOW_IO_REQ(get_io);
	req->ng_chid = *nhid;
	req->chid = *vmchid;

	err = ccow_start_io(get_io);
	if (err) {
		ccow_operation_destroy(ug_op, 1);
		ccow_release(c);
		return err;
	}
	err = ccow_wait(c, 0);
	if (err)
		return err;

	*md = ug_op->metadata;
	return 0;
}

static void
trlog_test_trlog(char *tid, char *bid, char *oid)
{
	int err;
	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	char buf[CCOW_CLUSTER_CHUNK_SIZE];
	struct iovec iov;
	buf[0]= 0;
	iov.iov_base = buf;
	iov.iov_len = 1;

	ccow_lookup_t iter;
	err = ccow_tenant_get("", 1, tid, strlen(tid) + 1,
		bid, strlen(bid) + 1, oid, strlen(oid) + 1,
		c, &iov, 1, 10000, CCOW_GET_LIST, &iter);
	assert_int_equal(err, 0);
	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);

	struct trlog_data data;
	struct vmmetadata md;
	char key[TRLOG_KEY_LEN];

	int count = 0;
	struct ccow_metadata_kv *kv = NULL;
	while (1) {
		kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX, -1);
		if (!kv)
			break;
		count++;

		snprintf(key, TRLOG_KEY_LEN, "%s", kv->key);
		err = trlog_extract_key(key, strlen(key), &data, 0);
		assert_int_equal(err, 0);

		if (data.trtype == TRLOG_SKIP_BTN_UPDATE ||
		    data.trtype == TRLOG_OBJ_DELETE ||
		    data.trtype == TRLOG_DIR_DELETE) {
			MEMFREE_TRLOG_DATA(data);
			continue;
		}

		memset(&md, 0, sizeof(md));
		err = trlog_test_get_vm(cl, &data.vmchid, &data.nhid, &md);
		if (err) {
			MEMFREE_TRLOG_DATA(data);
			continue;
		}
		printf("\tObject: %s/%s/%s/%s ts: %lu gen: %lu delta: %lu type: %d\n",
			md.cid, md.tid, md.bid, md.oid,
			data.timestamp, data.generation, data.deltasize, data.trtype);
		MEMFREE_TRLOG_DATA(data);
	}

	printf("Timestamp object: %s key count: %d\n", oid, count);
	ccow_lookup_release(iter);
}

static int
trlog_test_timestamp_objects(char *serverid, char *vdevid)
{
	int err;
	char tid[140], *trlog_tid_prefix = "TRLOG-";
	snprintf(tid, 140, "%s%s", trlog_tid_prefix, serverid);

	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	assert_int_equal(err, 0);

	char buf[CCOW_CLUSTER_CHUNK_SIZE];
	struct iovec iov;
	buf[0]= 0;
	iov.iov_base = buf;
	iov.iov_len = 1;

	ccow_lookup_t iter;
	err = ccow_tenant_get("", 1, tid, strlen(tid) + 1,
		vdevid, strlen(vdevid) + 1, "", 1,
		c, &iov, 1, 10000, CCOW_GET_LIST, &iter);
	assert_int_equal(err, 0);
	err = ccow_wait(c, -1);
	if (err == -ENOENT)
		return 0;

	assert_int_equal(err, 0);

	int objcount = 0;
	struct ccow_metadata_kv *kv = NULL;
	while (1) {
		kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX, -1);
		if (!kv)
			break;
		trlog_test_trlog(tid, vdevid, kv->key);
		objcount++;
	}

	ccow_lookup_release(iter);
	return objcount;
}

static int
trlog_traverse()
{
	int count = 0, objcount = 0;
	char serverid[129], vdevid[129];
	struct fhserver *fhserver = cl->flexhash->serverlist;
	while (fhserver) {
		uint128_dump(&fhserver->id, serverid, 129);
		struct fhdev *fhdev = fhserver->vdevlist.devlist;
		while (fhdev) {
			struct lvdev *lvdev = fhdev->vdev;
			uint128_dump(&lvdev->vdevid, vdevid, 129);
			count = trlog_test_timestamp_objects(serverid, vdevid);
			fhdev = fhdev->next;
			printf("Server: %s Vdev: %s Timestamp objects: %d\n",
				serverid, vdevid, count);
			objcount += count;
		}

		fhserver = fhserver->next;
	}

	return objcount;
}

static void
trlog_traverse_lib()
{
	int err;
	char entry[TRLOG_KEY_LEN];
	struct trlog_data data;
	struct trlog_handle hdl;
	uint64_t rec_count;
	uint64_t limit;
	struct vmmetadata md;
	ccow_completion_t c;
	struct mlist_node *result_head = NULL, *res_node;
	uint64_t batch_seq_ts = 0;

	trlog_init(&hdl);

	while (1) {
		err = trlog_mlist_get(&hdl, cl, batch_seq_ts, &result_head,
		    &rec_count, NULL, NULL);
		if (err == -ENOENT || rec_count == 0) {
			printf("No new entries found in transaction log\n");
			break;
		}

		assert(err == 0);

		printf("Timestamp object\n");
		res_node = result_head;
		while (res_node) {
			assert(strlen(res_node->data) <= TRLOG_KEY_LEN);
			strcpy(entry, (char*)res_node->data);
			assert_int_equal(trlog_extract_key(entry, strlen(entry), &data, 0), 0);

			if (data.trtype == TRLOG_SKIP_BTN_UPDATE ||
			    data.trtype == TRLOG_OBJ_DELETE ||
			    data.trtype == TRLOG_DIR_DELETE) {
				res_node = res_node->next;
				MEMFREE_TRLOG_DATA(data);
				continue;
			}

			memset(&md, 0, sizeof(md));
			err = trlog_test_get_vm(cl, &data.vmchid, &data.nhid, &md);
			if (err == 0) {
				printf("\tObject: %s/%s/%s/%s ts: %lu gen: %lu delta: %lu type: %d\n",
					md.cid, md.tid, md.bid, md.oid,
					data.timestamp, data.generation, data.deltasize, data.trtype);
			}
			res_node = res_node->next;
			MEMFREE_TRLOG_DATA(data);
		}

		trlog_mlist_done(&hdl, cl, result_head, 0);
	}

	trlog_destroy(&hdl);
}

static void
trlog_test(void **state)
{
	printf("Traversing timestamp objects for all server/vdev\n");
	trlog_traverse();

	printf("\nTraversing TRLOG using libtrlog\n");
	trlog_traverse_lib();
}

static void
libccow_teardown(void **state)
{
	assert_non_null(cl);
	ccow_tenant_term(cl);
}

static void
libccowd_teardown(void **state)
{
	if(!dd)
		ccow_daemon_term();
}

static void
usage(char *program)
{
	printf("\n"
		"USAGE:\n"
		"    ./trlog_test [-n] \n"
		"\n"
		"    -n   Disable ccowserv startup.\n"
	      );
}

int
main(int argc, char **argv)
{
	int opt;

	while ((opt = getopt(argc, argv, "hnv")) != -1) {
		switch(opt) {
		case 'n':
			dd = 1;
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
		}
	}

	const UnitTest tests[] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(trlog_test),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}

