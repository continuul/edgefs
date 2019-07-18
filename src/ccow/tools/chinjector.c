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
#include "reptrans.h"

#define MAX_DEV			256
#define MAX_VERB_LEVEL	3
#define N_CHIDS 		1000

#define dimof(x) (sizeof((x))/sizeof((x)[0]))

struct enum_dev_arg {
	int n_dev;
	struct repdev **dev;
};

Logger lg;
struct repdev *devices[MAX_DEV];

static void
enum_dev__done_cb(struct repdev *dev, void *arg, int status)
{
	struct enum_dev_arg *da = (struct enum_dev_arg *)arg;
	if (status == 0)
		da->dev[da->n_dev++] = dev;
}

static void
random_uint512_t(uint512_t* out)
{
	uint8_t fill [sizeof(uint512_t)/sizeof(uint8_t)];
	for (size_t n = 0; n < sizeof(fill); n++) {
		fill[n] = rand() % 256;
	}
	memcpy(out,fill,sizeof(fill));
}

void usage() {
	printf("\nUsage: chinjector -d <path> [OPTIONS]\n");
	printf("  -D, --device\t\t path to a storage mount point\n");
	printf("  -v, --vm\t\t number of VERSION_MANIFEST chunks to inject\n");
	printf("  -n, --nidex\t\t number of NAMEINDEX chunks to inject\n");
	printf("  -c, --corrupt\t\t broke chunks integrity\n");
	printf("  -s, --speculative\t put a speculative backrefs\n");
	printf("  -b, --backref\t\t put a verified backrefs\n");
	printf("  -d, --data\t\t put specified number of data chunks\n");
	printf("  -h, --help\t\t display this help message\n");
	printf("If -n and -v options are specified together, then NAMEINDEX chunks\n"
			"will have references to corresponding VERSION_MANIFEST chunks\n");
	printf("If -s or -b options are specified along with -v or -d options,\n");
	printf("then new backref will refer to the added VERSION_MANIFEST or data chunk\n\n");

}

#define VM_CHUNK_SIZE	8*1024
#define DATA_CHUNK_SIZE 128*1024

static int
put_data_chunks(struct repdev* dev, int num, int broke, type_tag_t br_type) {
	uv_buf_t payload;
	uint512_t chid;
	int nbufs = 1, err = 0;
	char *buf = je_malloc(DATA_CHUNK_SIZE);
	struct backref bref;
	struct timeval tv;

	payload.base = buf;
	payload.len = DATA_CHUNK_SIZE;

	rtbuf_t *rb = rtbuf_init_mapped(&payload, nbufs);

	for (int n = 0; n < num; n++) {
		/*
		 * Create random CHID
		 */
		random_uint512_t(&chid);
		/*
		 * Fill the chunk with random data
		 */
		for (size_t i=0; i < rb->bufs->len; i++) {
			rb->bufs->base[i] = rand() % 256;
		}
		/*
		 * Store the chunk
		 */
		err = reptrans_put_blob_with_attr(dev, TT_CHUNK_PAYLOAD,
			HASH_TYPE_DEFAULT, rb, &chid, !broke, 1234577);
		if (err) {
			fprintf(stderr, "Couldn't put TT_VERSION_MANIFEST\n");
			goto _chexit;
		} else {
			/*
			 * Check if we need to add backref
			 */
			switch (br_type) {
				case TT_VERIFIED_BACKREF:
					/*
					 * all the backref data are fake at the moment
					 */
					bref.generation = 1;
					random_uint512_t(&bref.name_hash_id);
					(void)gettimeofday(&tv, NULL);
					bref.uvid_timestamp = tv.tv_sec
							* 1000000L + tv.tv_usec;
					bref.ref_hash = HASH_TYPE_DEFAULT;
					bref.ref_type = TT_CHUNK_MANIFEST;
					random_uint512_t(&bref.ref_chid);
					bref.attr = VBR_ATTR_CP;
					err = reptrans_put_backref(dev, &chid, HASH_TYPE_DEFAULT, &bref);
					if (err) {
						fprintf(stderr,"Couldn't put speculative "
								"backref(%d)\n",err);
						goto _chexit;
					}
					break;

				default:
					break;
			}
		}
	}

_chexit:
	je_free(buf);
	return err;
}

static int
create_index_version_manifest(struct repdev* dev, int broke,
		size_t num_version, size_t num_index, type_tag_t br_type)
{
	uv_buf_t payload;
	int nbufs = 1, err = 0;
	char *buf = je_malloc(VM_CHUNK_SIZE);
	uint512_t nhid;
	payload.base = buf;
	payload.len = VM_CHUNK_SIZE;

	random_uint512_t(&nhid);

	uint512_t* keys = je_malloc(
				(num_version > num_index ? num_version : num_index)*sizeof(uint512_t));
	rtbuf_t *rb = rtbuf_init_mapped(&payload, nbufs);

	struct backref* brefs = NULL;
	if (br_type != TT_LAST) {
		brefs = je_malloc(num_version*sizeof(struct backref));
		memset(brefs, 0, num_version*sizeof(struct backref));
	}
	/*
	 * Create specified number of VERSION_MANIFEST chunks
	 * Store their CHIDs in keys
	 */
	for (size_t n = 0; n < num_version; n++) {
		for (size_t i=0; i < rb->bufs->len; i++) {
			rb->bufs->base[i] = rand() % 256;
		}
		if (broke) {
			printf("Adding VM\n");
			random_uint512_t(&keys[n]);
			err = reptrans_put_blob_with_attr(dev, TT_VERSION_MANIFEST,
				HASH_TYPE_DEFAULT, rb, &keys[n], 0, 1234577);
		} else {
			err = reptrans_put_blob_with_attr(dev, TT_VERSION_MANIFEST,
				HASH_TYPE_DEFAULT, rb, &keys[n], 1, 1234577);
		}
		if (err) {
			fprintf(stderr, "Couldn't put TT_VERSION_MANIFEST\n");
		} else {
			/*
			 * Append backref, if required
			 */
			switch (br_type) {
				case TT_VERIFIED_BACKREF:
				{
					struct timeval tv;
					brefs[n].generation = 1;
					brefs[n].name_hash_id = nhid;
					brefs[n].ref_chid = nhid;
					brefs[n].rep_count = 3;
					brefs[n].ref_type = TT_NAMEINDEX;
					brefs[n].ref_hash = HASH_TYPE_DEFAULT;
					brefs[n].attr = VBR_ATTR_VM;
					(void)gettimeofday(&tv, NULL);
					brefs[n].uvid_timestamp = tv.tv_sec
							* 1000000L + tv.tv_usec;
					err = reptrans_put_backref(dev, &keys[n],
						HASH_TYPE_DEFAULT, &brefs[n]);
					if (err) {
						fprintf(stderr,"Couldn't put speculative "
								"backref(%d)\n",err);
					}
				}
					break;

				default:
					break;
			}
		}
	}

	/*
	 * Fill up rest of CHIDS
	 */
	for (size_t i = num_version; i < num_index; i++) {
		random_uint512_t(&keys[i]);
	}
	/*
	 * Create NAMEINDEX entries which refers to
	 * previously stored VERSION_MANIFESTs
	 */
	struct vmmetadata md;
	struct timeval tv;

	memset(&md, 0, sizeof(struct vmmetadata));
	for (size_t i = 0; i < num_index; ++i) {
		if (i >= num_version) {
			(void)gettimeofday(&tv, NULL);
			md.uvid_timestamp = tv.tv_sec * 1000000L + tv.tv_usec;
			md.nhid = nhid;
			md.replication_count = 3;
			md.txid_generation = 1;
		}
		err = reptrans_put_version(dev, &md, &keys[i], 0);
		if (err) {
			fprintf(stderr, "Couldn't put NAMEINDEX\n");
		}
	}
	je_free(buf);
	je_free(keys);
	if (brefs)
		je_free(brefs);
	return err;
}

int
main(int argc, char* argv[]) {
	static struct option long_opts[] = {
			{ "device", 1, 0, 'D' },
			{ "nidex", 1, 0, 'n'},
			{ "vm", 1, 0, 'v'},
			{ "corrupt", 0, 0, 'c'},
			{ "backref", 0, 0, 'b' },
			{ "data", 1, 0, 'd' },
			{ "help", 0, 0, 'h'},
			{ 0, 0, 0, 0}
	};
	int id = 0, c = 0, err = 0, n_dev = 0;
	int vm_n = 0;
	int nidex_n = 0;
	char device_path[256] = {0};
	int broke_chid = 0;
	type_tag_t backref_type = TT_LAST;
	int data_chunks_n = 0;

	while ((c = getopt_long (argc, argv, "D:n:v:cbd:", long_opts, &id)) >= 0) {
		switch (c) {
			case 'v':
				vm_n = strtol(optarg, NULL, 10);
				if (errno || vm_n < 0) {
					fprintf(stderr, "VERSION_MANIFEST chunks number must be specified\n");
					return -EINVAL;
				}
				break;

			case 'n':
				nidex_n = strtol(optarg, NULL, 10);
				if (errno || vm_n < 0) {
					fprintf(stderr, "VERSION_MANIFEST chunks number must be specified\n");
					return -EINVAL;
				}
				break;

			case 'D':
				if (strlen(optarg) >= dimof(device_path)) {
					fprintf(stderr, "device path string is too long\n");
					return -EINVAL;
				}
				strncpy(device_path, optarg, dimof(device_path)-1);
				break;

			case 'c':
				broke_chid = 1;
				break;

			case 'b':
				backref_type = TT_VERIFIED_BACKREF;
				break;

			case 'd':
				data_chunks_n = strtol(optarg, NULL, 10);
				if (errno || data_chunks_n < 0) {
					fprintf(stderr, "you need to specify a positive "
							"number of data chunks to be add\n");
					return -EINVAL;
				}
				break;

			case 'h':
				usage();
				return 0;
				break;

			default:
				return -EINVAL;
		}
	}

	if (!strlen(device_path)) {
		usage();
		return -EINVAL;
	}

	if (!vm_n && !nidex_n && !data_chunks_n && backref_type == TT_LAST)
		return 0;

	srand(clock());
	/*
	 * Preparing device operations
	 */
	lg = Logger_create("chijector");
	char *transport[] = { "rtlfs" };
	err =  reptrans_init(0, NULL, NULL, RT_FLAG_STANDALONE,
		1, transport, NULL);

	if (err <= 0) {
		fprintf(stderr,"Couldn't init reptrans: %d\n", err );
		goto _exit_;
	}
	/*
	 * Enumerating reptrans devices
	 */
	struct enum_dev_arg enum_arg = {0, devices};
	reptrans_enum(NULL, &enum_arg, enum_dev__done_cb, 0);
	n_dev = enum_arg.n_dev;

	if (!n_dev) {
		fprintf(stderr,"Couldn't detect any reptrans devices\n");
		goto _destroy_;
	}
	/*
	 * Looking for the device by name specified by user
	 */
	struct repdev *dev = NULL;
	for (int n = 0; n < n_dev; n++) {
		if (!strcmp(enum_arg.dev[n]->path,device_path)) {
			dev = enum_arg.dev[n];
			break;
		}
	}

	if (!dev) {
		fprintf(stderr,"Couldn't locate a device at %s\n", device_path);
		goto _destroy_;
	}

	err = nice(19);
	if (err < 0) {
		fprintf(stderr,"Couldn't change process priority\n");
		goto _destroy_;
	}

	if (vm_n | nidex_n) {
		err = create_index_version_manifest(dev, broke_chid, vm_n, nidex_n, backref_type);
		if (err) {
			fprintf(stderr,"Couldn't create version manifest/index entries\n");
			goto _destroy_;
		}

	}

	if (data_chunks_n > 0) {
		err = put_data_chunks(dev, data_chunks_n, broke_chid, backref_type);
		if (err) {
			fprintf(stderr,"Couldn't put data chunk\n");
			goto _destroy_;
		}
	}
	/*
	 * Put stale backref if they weren't put before
	 */
	if (!vm_n && !nidex_n && !data_chunks_n && backref_type != TT_LAST) {
		uint512_t chid;
		random_uint512_t(&chid);
		switch (backref_type) {
			case TT_VERIFIED_BACKREF:
			{
				struct backref br;
				struct timeval tv;
				br.generation = 1;
				random_uint512_t(&br.name_hash_id);
				(void)gettimeofday(&tv, NULL);
				br.uvid_timestamp = tv.tv_sec * 1000000L + tv.tv_usec;
				random_uint512_t(&br.ref_chid);
				br.ref_type = TT_CHUNK_MANIFEST;
				br.ref_hash = HASH_TYPE_DEFAULT;
				br.attr = VBR_ATTR_CP;
				err = reptrans_put_backref(dev, &chid,
					HASH_TYPE_DEFAULT, &br);
				if (err) {
					fprintf(stderr,"Couldn't put speculative "
							"backref(%d)\n",err);
					goto _destroy_;
				}
			}
			break;

			default:
				break;
		}
	}

_destroy_:
	reptrans_destroy();
	reptrans_close_all_rt();

_exit_:
	return err;

}
