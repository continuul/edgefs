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
#include "ccowd.h"
#include "reptrans.h"
#include "erasure-coding.h"

#define MAX_DEV 256
struct repdev *devices[MAX_DEV];
int n_dev = 0;
int n_chunks = 0;
int parity = 0;
int nset = -1;

struct enum_dev_arg {
	int n_dev;
	struct repdev **dev;
};

const char *transport[] = { "rtlfs" };
Logger lg;

static int
delete_all_blobs(struct repdev** devs, int n, const uint512_t* chid,
	type_tag_t tt, crypto_hash_t ht) {
	int rc = 0, err = 0;
	for (int i = 0; i < n; i++) {
		int err = reptrans_delete_blob(devs[i], tt, ht, chid);
		if (err)
			return err;
		err = reptrans_delete_blob(devs[i], TT_VERIFIED_BACKREF, ht, chid);
		if (err && (err != -ENOENT))
			return err;
		rc++;
	}
	return rc;
}

static int
blob_iterator(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *key, uv_buf_t *val, void *param)
{
	struct ec_pset* psets = NULL;
	int32_t domain;
	int npsets = 0;
	uint32_t algo = 0, fmt = 0;
	char chidstr[UINT512_BYTES*2+1];
	rtbuf_t* rb = NULL, *refs = NULL, *rb_pmap = NULL;

	msgpack_u* u = msgpack_unpack_init(val->base, val->len, 1);
	int err = ec_unpack_parity_map(u, &psets, &npsets, &domain, &algo,
			&fmt);
	if (err) {
		printf("Error unpacking parity manifest %d", err);
		return -EFAULT;
	}

	uint512_dump(key, chidstr, UINT512_BYTES*2+1);
	chidstr[31] = 0;

	err = reptrans_get_blob(dev, TT_CHUNK_MANIFEST, HASH_TYPE_DEFAULT,
					key, &rb);
	if (err || !rb) {
		printf("Dev(%s): couldn't find a manifest CHID %s type %s",
				dev->path, chidstr, type_tag_name[TT_CHUNK_MANIFEST]);
		return -EFAULT;
	}

	/* Extract manifest's refentries */
	replicast_unpack_cm_refs(rb, &refs, 0);
	if (err || !refs) {
		printf("Dev(%s) error unpacking manifest chid %s type "
				"%s: %d", dev->path, chidstr, type_tag_name[TT_CHUNK_MANIFEST],
				err);
		if (!err)
			return -EINVAL;
		return -EFAULT;
	}


	printf("Processing manifest %s with %d parity sets\n", chidstr, npsets);

	for(int i = 0; i < npsets; i++) {
		if ((nset != -1) && (i != nset))
			continue;
		for(int c = 0; c < n_chunks; c++) {
			crypto_hash_t ht = HASH_TYPE_DEFAULT;
			uint512_t *chid = (parity) ? &psets[i].parity[c].chid : &psets[i].entries[c].chid;
			for (size_t k = 0; k < refs->nbufs; k++) {
				struct refentry* e = (struct refentry*)rtbuf(refs, k).base;
				if (!uint512_cmp(&e->content_hash_id, chid)) {
					ht =  RT_REF_HASH_TYPE(e);
					break;
				}
			}
			int j = delete_all_blobs(devices, n_dev, chid,
					TT_CHUNK_PAYLOAD, (parity) ? HASH_TYPE_DEFAULT : ht);
			if( j > 0) {
				uint512_dump(chid, chidstr, UINT512_BYTES*2+1);
				chidstr[31] = 0;
				printf("\tChunk %s in pset %d was deleted from %d "
						"devices\n", chidstr, i, j);
			}
		}
	}
	return 0;
}

int find_dev(struct repdev** devs, int n, char *path)
{
	int i = 0;
	for (int i = 0; i < n; i++) {
		if(strcmp(devs[i]->path, path) == 0)
			return i;
	}
	return -ENOENT;
}

static void
enum_dev__done_cb(struct repdev *dev, void *arg, int status)
{
	struct enum_dev_arg *da = (struct enum_dev_arg *)arg;
	assert(da);
	if (status == 0)
		da->dev[da->n_dev++] = dev;
	assert(da->n_dev < MAX_DEV);
}

int
main(int argc, char* argv[])
{
	int opt;
	struct repdev* dev = NULL;
	char dev_name[256] = {0};

	while ((opt = getopt(argc, argv, "pn:d:s:")) != -1) {
		switch (opt) {
			case 'n':
				n_chunks = atoi(optarg);
				break;

			case 'p':
				parity = 1;
				break;
			case 'd':
				strncpy(dev_name, optarg, sizeof(dev_name));
				break;
			case 's':
				nset = atoi(optarg);
				break;
			default:
				break;
		}
	}

	lg = Logger_create("reptrans");
	int err =  reptrans_init(0, NULL, NULL,
		RT_FLAG_STANDALONE | RT_FLAG_CREATE, 1, (char**)transport, NULL);
	if (err <= 0) {
		fprintf(stderr, "Error opening reptrans: %d\n", err);
		return err;
	}

	struct enum_dev_arg enum_arg = {0, devices};
	err = reptrans_enum(NULL, &enum_arg, enum_dev__done_cb, 0);
	if (err) {
		fprintf(stderr, "Error enumerating repdevs: %d\n", err);
		return err;
	}
	n_dev = enum_arg.n_dev;

	dev = devices[0];
	if (dev_name[0]) {
		int i = find_dev(devices, n_dev, dev_name);
		if (i != -ENOENT) {
			dev = devices[i];
			printf("Using repdev %s\n", dev->name);
			reptrans_iterate_blobs(dev, TT_PARITY_MANIFEST, blob_iterator, NULL, 1);
		}
	} else {
		for(int i = 0; i < n_dev; i++) {
			printf("Using repdev %s\n", devices[i]->name);
			reptrans_iterate_blobs(devices[i], TT_PARITY_MANIFEST, blob_iterator, NULL, 1);
		}
	}
	return 0;
}
