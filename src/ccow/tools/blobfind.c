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
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <time.h>

#include "ccowutil.h"
#include "ccow.h"
#include "ccow-impl.h"
#include "blob-lookup.h"
#include "reptrans-data.h"

const char* ref_type_name[] = {
	"UNDEFINED",
	"RT_REF_TYPE_NORMAL",
	"RT_REF_TYPE_MANIFEST",
	"RT_REF_TYPE_ZEROBLOCK",
	"RT_REF_TYPE_INLINE_PAYLOAD",	/* content_hash_id is NULL */
	"RT_REF_TYPE_INLINE_VERSION",	/* content_hash_id points to VM */
	"RT_REF_TYPE_INLINE_MANIFEST"	/* content_hash_id points to CM */
};

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

void usage() {
	printf("\nUsage: blobfind <CHID> <TYPETAG> <HASHTYPE> [NHID|NAME] [OPTIONS]\n");
	printf("  -h, --help\t\t display this help message\n\n");
	printf("  -v, --verbose\t\t decode manifest's metadata and refEntries\n\n");
	printf("  -n, --name\t\t calculate NHID from object name\n\n");
	printf("Lookup for a blob with specified CHID, TYPETAG and HASHTYPE (e.g. HASH_TYPE_BLAKE2B_256)\n\n");
}

int
main(int argc, char* argv[]) {
	static struct option long_opts[] = {
			{ "help", 0, 0, 'h'},
			{ "verbose", 0, 0, 'v'},
			{ "name", 0, 0, 'n'},
			{ 0, 0, 0, 0}
	};

	uint512_t chid;
	uint512_t nhid = uint512_null;
	type_tag_t ttag = TT_LAST;
	crypto_hash_t htype = HASH_TYPE_END;
	int p, i, id = 0, err = 0;
	int verbose = 0, name = 0;

	if (argc < 4) {
		fprintf(stderr, "Wrong number of arguments\n");
		usage();
		return -EINVAL;
	}

	char *chid_in = argv[1];
	char *ttag_in = argv[2];
	char *htype_in = argv[3];
	char *nhid_in = 0;
	if (argc > 4) {
		nhid_in = argv[4];
		uint512_fromhex(nhid_in, UINT512_BYTES * 2 + 1, &nhid);
	}

	uint512_fromhex(chid_in, UINT512_BYTES * 2 + 1, &chid);

	for (i = TT_NAMEINDEX; i < TT_LAST; ++i) {
		if (!strncmp(ttag_in, type_tag_name[i],
				strlen(type_tag_name[i]))) {
			ttag = (type_tag_t)i;
			break;
		}
	}
	if (ttag == TT_LAST) {
		fprintf(stderr, "Wrong TYPETAG\n");
		usage();
		return -EINVAL;
	}

	for (i = HASH_TYPE_DEFAULT; i < HASH_TYPE_END; ++i) {
		if (!strncmp(htype_in, hash_type_name[i],
				strlen(hash_type_name[i]))) {
			htype = (crypto_hash_t)i;
			break;
		}
	}
	if (htype == HASH_TYPE_END) {
		fprintf(stderr, "Wrong HASHTYPE\n");
		usage();
		return -EINVAL;
	}

	while ((p = getopt_long (argc, argv, "hvn", long_opts, &id)) >= 0) {
		switch (p) {
			case 'h':
				usage();
				return 0;
				break;

			case 'v':
				verbose = 1;
				break;

			case 'n':
				name = 1;
				break;

			default:
				return -EINVAL;
		}
	}

	static ccow_t cl;
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Cannot open ccow.json\n");
		return err;
	}
	char *buf = je_calloc(1, 16384);
	if (read(fd, buf, 16384) == -1) {
		fprintf(stderr, "Cannot read ccow.json\n");
		close(fd);
		return -1;
	}
	close(fd);
	err = ccow_admin_init(buf, "", 1, &cl);
	if (err) {
		fprintf(stderr, "Cannot create admin context\n");
		je_free(buf);
		return err;
	}
	je_free(buf);

	if (name) {
		char cid[2048], tid[2048], bid[2048], oid[2048];
		if (sscanf(nhid_in, "%2047[^/]/%2047[^/]/%2047[^/]/%2047[^\n]",
			    cid, tid, bid, oid) < 4) {
			fprintf(stderr, "NHID calc error: wrong object path format\n");
			return -1;
		}
		load_crypto_lib();
		err = ccow_calc_nhid(cid, tid, bid, oid, &nhid);
		if (err) {
			fprintf(stderr, "NHID calc error: %d\n", err);
			return err;
		}
	}

	struct ccow_completion *c;
	err = ccow_create_completion(cl, NULL, NULL, 1, (ccow_completion_t *)&c);
	if (err) {
		fprintf(stderr, "Cannot create CCOW completion\n");
		ccow_tenant_term(cl);
		return err;
	}

	size_t n_vdevs = RT_SYSVAL_REPLICATION_COUNT*4;
	uint128_t vdevs[RT_SYSVAL_REPLICATION_COUNT*4];
	err = ccow_blob_lookup_request(cl->netobj, &chid, ttag, htype, c,
		vdevs, &n_vdevs);
	if (err) {
		fprintf(stderr, "Cannot send blob lookup request\n");
		ccow_release(c);
		ccow_tenant_term(cl);
		return err;
	}
	err = ccow_wait(c, 0);
	if (err) {
		printf("Error: %d\n", err);
	} else {
		if (!n_vdevs)
			printf("Blob not found\n");
		else {
			char vdevstr[UINT128_BYTES*2+1];
			printf("Blob found on %lu VDEVs: ", n_vdevs);
			for (size_t i = 0; i < n_vdevs; i++) {
				uint128_dump(vdevs + i, vdevstr, UINT128_BYTES*2+1);
				if (i < n_vdevs - 1)
					printf("%s, ", vdevstr);
				else
					printf("%s\n", vdevstr);
			}
		}
		if (verbose && (ttag == TT_CHUNK_MANIFEST || ttag == TT_VERSION_MANIFEST)) {
	/* Trying to get the chunk */
		rtbuf_t* rb = NULL;
		err = blobfind_get_chunk(cl, ttag, &nhid, &chid, &rb);
		if (err)
			printf("Manifest get error: %d\n", err);
		else {
			printf("Manifest size:\t%lu bytes\n", rb->bufs->len);
			if (ttag == TT_VERSION_MANIFEST) {
				struct vmmetadata md;
				char chidstr[UINT512_BYTES*2+1];
				int err = replicast_get_metadata(rb, &md);
				printf("CID:\t\t%s\n", md.cid);
				printf("TID:\t\t%s\n", md.tid);
				printf("BID:\t\t%s\n", md.bid);
				printf("OID:\t\t%s\n", md.oid);
				uint512_dump(&md.nhid, chidstr, UINT512_BYTES*2+1);
				printf("NHID:\t\t%s\n", chidstr);
				uint128_dump(&md.uvid_src_guid, chidstr, UINT128_BYTES*2+1);
				printf("SRCGUID:\t\t%s\n", chidstr);
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
			rtbuf_t* refs = NULL;
			err = ttag == TT_CHUNK_MANIFEST ?
				replicast_unpack_cm_refs(rb, &refs, 0) :
				replicast_get_refs(rb, &refs, 0);
			if (err)
				fprintf(stderr, "Manifest unpack error\n");
			else {
				assert(refs);
				printf("refEntries:\n");
				for (size_t i = 0; i < refs->nbufs; ++i) {
					struct refentry* le = (struct refentry *)rtbuf(refs, i).base;
					int refType = RT_REF_TYPE(le);
					crypto_hash_t ht = RT_REF_HASH_TYPE(le);
					char refchidstr[UINT512_BYTES*2+1];
					uint512_dump(&le->content_hash_id, refchidstr, UINT512_BYTES*2+1);
					printf("%lu:\t%s %s %lu %lu\t%s\n", i, ref_type_name[refType],
						hash_type_name[ht], le->offset, le->length, refchidstr);
				}
			}
		}
		}
	}
	ccow_tenant_term(cl);
	return 0;
}
