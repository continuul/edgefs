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
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>

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

static int
index_check(struct repdev *dev, int vlevel);

static int
chunk_integrity_check(struct repdev *dev, int vlevel);

static int
backref_check(struct repdev *dev, int vlevel);

static int
hashcount_check(struct repdev *dev, int vlevel);

static void
enum_dev__done_cb(struct repdev *dev, void *arg, int status) {
	struct enum_dev_arg *da = (struct enum_dev_arg *)arg;
	if (status == 0)
		da->dev[da->n_dev++] = dev;
}

void
usage() {
	printf("\nUsage: rdchk -D <path> [-o <operation>] [-v level]\n");
	printf("  -D, --device\t\t path to a storage mount point\n");
	printf("  -o, --ops\t\t operations string, e.g. -o \"ico\"\n");
	printf("  \t\t\t 'i' NAMEINDEX and VERSION_MANIFEST "
			"consistency check(default)\n");
	printf("  \t\t\t 'c' check chunks integrity\n");
	printf("  \t\t\t 'o' back reference integrity check\n");
	printf("  \t\t\t 'h' TT_HASHCOUNT check\n");
	printf("  -v, --verbosity\t verbosity level 1(default)..3\n");
	printf("  -h, --help\t\t display this help message\n\n");

}

int
main(int argc, char* argv[]) {
	static struct option long_opts[] = {
			{ "device", 1, 0, 'D' },
			{ "verbosity", 1, 0, 'v'},
			{ "ops", 1, 0, 'o'},
			{ "help", 0, 0, 'h'},
			{ 0, 0, 0, 0}
	};
	int id = 0, c = 0, err = 0, n_dev=0;
	int verb = 1;
	char device_path[256] = {0};
	char ops[20] = "i";

	while ((c = getopt_long (argc, argv, "v:o:D:h", long_opts, &id)) >= 0) {
		switch (c) {
			case 'v':
				verb = strtol(optarg, NULL, 10);
				if (!verb || verb > MAX_VERB_LEVEL) {
					fprintf(stderr, "verbosity level have to be in range 1..3\n");
					return -EINVAL;
				}
				break;

			case 'o':
				if (strlen(optarg) >= dimof(ops)) {
					fprintf(stderr, "operation string is too long\n");
					return -EINVAL;
				}
				strncpy(ops, optarg, dimof(ops)-1);
				break;

			case 'D':
				if (strlen(optarg) >= dimof(device_path)) {
					fprintf(stderr, "device path string is too long\n");
					return -EINVAL;
				}
				strncpy(device_path, optarg, dimof(device_path)-1);
				break;

			case 'h':
				usage();
				return 0;
				break;

			default:
				usage();
				return -EINVAL;
		}
	}

	if (!strlen(device_path)) {
		usage();
		return -EINVAL;
	}
	/*
	 * Preparing device operations
	 */
	lg = Logger_create("rdchk");
	char *transport[] = { "rtlfs" };
	err =  reptrans_init(0, NULL, NULL, RT_FLAG_STANDALONE | RT_FLAG_RDONLY,
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
	/*
	 * Iterate over ops string and execute corresponding test
	 */
	for (size_t n = 0; n < strlen(ops); n++) {
		switch(ops[n]) {
		case 'i':
			index_check(dev, verb);
			break;

		case 'c':
			chunk_integrity_check(dev, verb);
			break;

		case 'o':
			backref_check(dev, verb);
			break;

		case 'h':
			hashcount_check(dev, verb);
			break;
		default:
			fprintf(stderr,"skipping unknown operation %c\n", ops[n]);
		}
	}

_destroy_:
	reptrans_destroy();
	reptrans_close_all_rt();

_exit_:
	return 0;
}

struct _chids_collection
{
	uint512_t* chids;
	size_t   max;
	size_t   current;
};


static int
chid_counter__callback(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *key, uv_buf_t *val, void *param)
{
	struct _chids_collection* coll = (struct _chids_collection*) param;
	for (int i = coll->current - 1; i >= 0; i--) {
		if(memcmp(key, &coll->chids[i], sizeof(uint512_t)) == 0)
			return 0;
	}
	coll->chids[coll->current++] = *key;
	if (coll->current >= coll->max)
	{
		coll->chids = je_realloc(coll->chids, (coll->max + N_CHIDS)*sizeof(uint512_t));
		coll->max += N_CHIDS;
	}

	return 0;
}

struct ivm_entry {
	struct vlentry  version;
	uint512_t		nhid;
	uint512_t		vmchid;
};

struct ivm {
	struct ivm_entry* entries;
	size_t	current;
	size_t	max;
};

static int
index_check(struct repdev *dev, int vlevel) {
	int err = 0;
	struct _chids_collection coll = {.max = N_CHIDS, .current = 0};
	/*
	 * Extract NAMEINDEX's CHIDS
	 */
	coll.chids = je_malloc(N_CHIDS*sizeof(uint512_t));

	err = reptrans_iterate_blobs(dev, TT_NAMEINDEX,
				chid_counter__callback, &coll, 0);
	if (err) {
		fprintf(stderr,"Error at reptrans_iterate_blobs: %d\n", err);
		goto _isexit1;
	}

	/*
	 * Extract all the vlentries from  TT_NAMEINDEX
	 */
	size_t n_nhid = coll.current;

	struct ivm ivm = { .current = 0, .max = 1000 };
	ivm.entries = je_malloc(ivm.max*sizeof(struct ivm_entry));
	uint512_t zchid =  { { {0, 0}, {0, 0} }, { {0, 0}, {0, 0} } };;

	for (size_t n = 0; n < n_nhid; n++) {
		struct vlentry query = {
			.uvid_timestamp = ~0ULL,
			.generation = 0ULL
		};

		rtbuf_t *rb_vers = NULL;

		err = reptrans_get_versions(dev, &coll.chids[n], &query, &rb_vers);
		if (err) {
			fprintf(stderr,"Error at reptrans_get_versions: %d\n", err);
			goto _isexit;
		}
		/*
		 * Copy found vlentries to a map,
		 * adding NHIDs, CHIDs set to zero (unitilized)
		 */
		if (rb_vers->nbufs) {
			for(size_t i = 0; i < rb_vers->nbufs; i++) {
				memcpy(&ivm.entries[ivm.current].version,
						rb_vers->bufs[i].base,
						sizeof(struct vlentry));
				ivm.entries[ivm.current].nhid = coll.chids[n];
				ivm.entries[ivm.current++].vmchid = zchid;
				if(ivm.current >= ivm.max) {
					ivm.max += 1000;
					ivm.entries = je_realloc(ivm.entries, ivm.max*sizeof(struct ivm_entry));
				}
			}
		}
		if (rb_vers)
			rtbuf_destroy(rb_vers);
	}
	printf("INFO: detected %lu entries in NAMEINDEX with %lu different NHIDs\n",
			ivm.current, n_nhid);
	/*
	 * Extracting TT_VERSION_MANIFEST CHIDs
	 */
	coll.current = 0;
	err = reptrans_iterate_blobs(dev, TT_VERSION_MANIFEST,
					chid_counter__callback, &coll, 0);
	if (err) {
		fprintf(stderr,"Error at reptrans_iterate_blobs: %d\n", err);
		return err;
	}
	printf("INFO: detected %lu entries in VERSION_MANIFEST\n", coll.current);
	/*
	 * Performs analysis
	 */
	size_t index_no_vm = 0;
	for (size_t i = 0; i < ivm.current; i++) {
		int found = 0;
		size_t j = 0;
		for (j=0; j < coll.current; j++) {
			if (!uint512_cmp(&coll.chids[j],
					&ivm.entries[i].version.content_hash_id)) {
				ivm.entries[i].vmchid = coll.chids[j];
				memmove(&coll.chids[j], &coll.chids[j+1], (coll.current - j - 1)*sizeof(uint512_t));
				coll.current--;
				found = 1;
				break;
			}
		}
		if (!found) {
			index_no_vm++;
		}
	}

	if (!index_no_vm && !coll.current) {
		printf("INFO: NAMEINDEX and VERSION MANIFEST DBs are in consistent state\n");
	} else {
		if (vlevel <= 1) {
			printf("ERROR: NAMEINDEX and VERSION MANIFEST "
					"logical structure problem detected\n");
		} else {
			if (index_no_vm) {
				printf("ERROR: detected %lu NAMEINDEX entries"
						" without VERSION_MANIFEST\n", index_no_vm);
				if (vlevel > 2) {
					printf("Orphaned NAMEINDEX entries:\n");
					size_t n = 1;
					for (size_t i=0; i < ivm.current; i++) {
						if (!uint512_cmp(&ivm.entries[i].vmchid,&zchid)) {
							char nhidbuf[UINT512_BYTES * 2 + 1];
							char vmchidbuf[UINT512_BYTES * 2 + 1];
							uint512_dump(&ivm.entries[i].nhid,
									nhidbuf, UINT512_BYTES * 2 + 1);
							uint512_dump(
									&ivm.entries[i].version.content_hash_id,
									vmchidbuf, UINT512_BYTES * 2 + 1);

							printf("%lu.\tHNID:    %s\n\tVERSION: "
									"%lu\n\tVMCHID:  %s\n",
								n++, nhidbuf,
								ivm.entries[i].version.uvid_timestamp,
								vmchidbuf);
						}
					}
				}
			}

			if (coll.current) {
				printf("ERROR: detected %lu VERSION_MANIFEST entries"
						" without NAMEINDEX\n", coll.current);
				if (vlevel > 2) {
					printf("Orphaned VERSION_MANIFEST entries:\n");
					for (size_t i=0; i < coll.current; i++) {
						char chidbuf[UINT512_BYTES * 2 + 1];
						uint512_dump(&coll.chids[i],
								chidbuf, UINT512_BYTES * 2 + 1);
						printf("%lu.\tCHID: %s\n", i+1, chidbuf);
					}
				}
			}
		}
	}
_isexit:
	je_free(ivm.entries);

_isexit1:
	je_free(coll.chids);

	return err;
}

static int
chunk_integrity_check(struct repdev *dev, int vlevel) {
	int err = 0;
	struct _chids_collection coll = {.max = N_CHIDS, .current = 0};
	coll.chids = je_malloc(N_CHIDS*sizeof(uint512_t));

	static type_tag_t tags_to_check[] = {
		TT_CHUNK_PAYLOAD,
		TT_CHUNK_MANIFEST,
		TT_VERSION_MANIFEST,
		TT_REPLICATION_QUEUE
	};

	for (size_t i = 0; i < dimof(tags_to_check); i++) {
		type_tag_t ttag = tags_to_check[i];

		coll.current = 0;
		/*
		 * Extract CHIDs
		 */
		err = reptrans_iterate_blobs(dev, ttag,
					chid_counter__callback, &coll, 0);
		if (err) {
			fprintf(stderr,"Error at reptrans_iterate_blobs: %d\n", err);
			goto _exit_;
		}
		/*
		 * Checking the integrity
		 */
		rtbuf_t* rb;
		size_t n_corrupted = 0;
		for (size_t n = 0; n < coll.current; n++) {
			/*
			 * Extract a blob
			 */
			err = reptrans_get_blob(dev, ttag,
					HASH_TYPE_DEFAULT, &coll.chids[n], &rb);
			if (err) {
				fprintf(stderr,"Error at reptrans_get_blob: %d\n", err);
				goto _exit_;
			}
			/*
			 * Check integrity
			 */
			uint512_t cchid;
			err = rtbuf_hash(rb, HASH_TYPE_DEFAULT, &cchid);
			if (err) {
				fprintf(stderr,"Error at rtbuf_hash: %d\n", err);
				goto _exit_;
			}
			if (uint512_cmp(&cchid,&coll.chids[n])) {
				n_corrupted++;
				if (vlevel > 2) {
					if(n_corrupted == 1) {
						printf("ERROR: checking integrity of %s chunks:\n",
								type_tag_name[ttag]);
					}
					char chidbuf_stored[UINT512_BYTES * 2 + 1];
					char chidbuf_calc[UINT512_BYTES * 2 + 1];
					uint512_dump(&coll.chids[n],
							chidbuf_stored, UINT512_BYTES * 2 + 1);
					uint512_dump(&cchid,
							chidbuf_calc, UINT512_BYTES * 2 + 1);
					printf("%lu.\tCHID: %s\n\tHASH: %s\n", n_corrupted,
							chidbuf_stored, chidbuf_calc);
				}
			}
		}

		if (n_corrupted) {
			if (vlevel == 2) {
				printf("ERROR: checking integrity of %s chunks: "
						"%lu out of %lu are defective\n",
						type_tag_name[ttag],
						n_corrupted, coll.current);
			} else if (vlevel == 1) {
				printf("ERROR: checking integrity of %s chunks, "
						"processed %lu entries\n",
						type_tag_name[ttag], coll.current);
			}
		} else {
			printf("INFO: checking integrity of %s chunks done, "
					"processed %lu entries\n",
					type_tag_name[ttag], coll.current);
		}
	}
_exit_:
	je_free(coll.chids);

	return err;
}

struct _refentry {
	uint512_t	chid;
	size_t		n_sref;
	size_t		n_vref;
};

struct _refs {
	struct _refentry* entries;
	struct _chids_collection* srefs; // Spec. backref CHIDs
	struct _chids_collection* vrefs; // Verif. backref CHIDs
	size_t	current;
	size_t	max;
};


static int
ref_counter__callback(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *key, uv_buf_t *val, void *param)
{
	struct _chids_collection* coll = (struct _chids_collection*) param;
	coll->chids[coll->current++] = *key;
	if (coll->current >= coll->max)
	{
		coll->chids = je_realloc(coll->chids, (coll->max + N_CHIDS)*sizeof(uint512_t));
		coll->max += N_CHIDS;
	}

	return 0;
}

static int
chunk_counter__callback(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *key, uv_buf_t *val, void *param)
{
	struct _refs* ref = (struct _refs*) param;
	/* store CHID */
	ref->entries[ref->current].n_sref = 0;
	ref->entries[ref->current].n_vref = 0;
	ref->entries[ref->current].chid = *key;

	/* Count references */
	for (size_t i=0; i < ref->srefs->current; i++) {
		if (!uint512_cmp(key, &ref->srefs->chids[i])) {
			ref->entries[ref->current].n_sref++;
			memmove(&ref->srefs->chids[i], &ref->srefs->chids[i+1],
					(ref->srefs->current - i)*sizeof(uint512_t));
			ref->srefs->current--;
		}
	}

	for (size_t i=0; i < ref->vrefs->current; i++) {
		if (!uint512_cmp(key, &ref->vrefs->chids[i])) {
			ref->entries[ref->current].n_vref++;
			memmove(&ref->vrefs->chids[i], &ref->vrefs->chids[i+1],
					(ref->vrefs->current - i)*sizeof(uint512_t));
			ref->vrefs->current--;
		}
	}
	/*
	 * re-alloc memory if required
	 */
	if (++ref->current >= ref->max)
	{
		ref->entries = je_realloc(ref->entries, (ref->max + N_CHIDS)
				* sizeof(struct _refentry));
		ref->max += N_CHIDS;
	}
	return 0;
}

static int
backref_check(struct repdev *dev, int vlevel) {
	int err = 0;
	char chidbuf[UINT512_BYTES * 2 + 1];
	static type_tag_t tags_to_check[] = {
		TT_CHUNK_PAYLOAD,
		TT_CHUNK_MANIFEST,
		TT_VERSION_MANIFEST
	};

	struct _chids_collection srefs = { .current = 0, .max = N_CHIDS };
	struct _chids_collection vrefs = { .current = 0, .max = N_CHIDS };

	srefs.chids = je_malloc(srefs.max*sizeof(uint512_t));
	vrefs.chids = je_malloc(vrefs.max*sizeof(uint512_t));
	/*
	 * Collect CHIDs of all verified back references
	 */
	err = reptrans_iterate_blobs(dev, TT_VERIFIED_BACKREF,
			ref_counter__callback, &vrefs, 0);
	if (err) {
		fprintf(stderr,"Error at reptrans_iterate_blobs: %d\n", err);
		goto _isexit2;
	}
	/*
	 * Iterate over chunks and count references
	 */
	struct _refs refs = { .current = 0, .max = N_CHIDS };
	refs.entries = je_malloc(refs.max * sizeof(struct _refentry));
	refs.srefs = &srefs;
	refs.vrefs = &vrefs;
	for (size_t n=0; n < dimof(tags_to_check); n++) {
		/*
		 * Collect reference chunks
		 */
		refs.current = 0;
		err = reptrans_iterate_blobs(dev, tags_to_check[n],
				chunk_counter__callback, &refs, 0);
		if (err) {
			fprintf(stderr,"Error at reptrans_iterate_blobs: %d\n", err);
			goto _isexit1;
		}

		/* Calculated number of orphaned chunks */
		int n_orphans = 0;
		for (size_t i=0; i < refs.current; i++) {
			if (refs.entries[i].n_sref == 0 &&
				refs.entries[i].n_vref == 0) {
				n_orphans++;
			}
		}
		/*
		 * Output to user
		 */
		if (n_orphans) {
			printf("ERROR: %s scanned, %d out of %lu don't"
					" have any references\n"
					,type_tag_name[tags_to_check[n]] ,n_orphans, refs.current);
			if (vlevel == 2) {
				int n_ref=1;
				printf("INFO: orphaned chunks:\n");
				for (size_t i=0; i < refs.current; i++) {
					if (refs.entries[i].n_sref == 0 &&
							refs.entries[i].n_vref == 0) {
						uint512_dump(&refs.entries[i].chid,
								chidbuf, UINT512_BYTES * 2 + 1);
						printf("%d.\tCHID: %s\n", n_ref++,chidbuf);
					}
				}
			}
		} else {
			printf("INFO: %lu chunk of type %s are consistent "
					"with their backrefs\n"
					,refs.current, type_tag_name[tags_to_check[n]]);
		}
		/*
		 * Display full chunk list with reference numbers
		 */
		if (vlevel == 3) {
			printf("INFO: chunks list:\n");
			for (size_t i=0; i < refs.current; i++) {
				uint512_dump(&refs.entries[i].chid,
						chidbuf, UINT512_BYTES * 2 + 1);

				printf("%lu.\tCHID: %s\n", i+1,chidbuf);
				printf("\tSREFs COUNT: %lu\n",refs.entries[i].n_sref);
				printf("\tVREFs COUNT: %lu\n",refs.entries[i].n_vref);
			}
		}
	}
	/*
	 * Display stalled back reference info
	 */
	int n_stale = vrefs.current + srefs.current;
	if (!n_stale) {
		printf("INFO: stalled back references weren't detected\n");
	} else {
		if (srefs.current) {
			printf("ERROR: detected %lu stalled "
					"speculative back references\n",srefs.current);
			if (vlevel > 1) {
				printf("INFO: stalled speculative references:\n");
				for (size_t i=0; i < srefs.current; i++) {
					uint512_dump(&srefs.chids[i],
							chidbuf, UINT512_BYTES * 2 + 1);
					printf("%lu.\tCHID: %s\n", i+1,chidbuf);
				}
			}
		}
		if (vrefs.current) {
			printf("ERROR: detected %lu stalled "
					"verified back references\n",vrefs.current);
			if (vlevel > 1) {
				printf("INFO: stalled verified references:\n");
				for (size_t i=0; i < vrefs.current; i++) {
					uint512_dump(&vrefs.chids[i],
							chidbuf, UINT512_BYTES * 2 + 1);
					printf("%lu.\tCHID: %s\n", i+1,chidbuf);
				}
			}
		}
	}

_isexit1:
	je_free(refs.entries);

_isexit2:
		je_free(vrefs.chids);

	je_free(srefs.chids);
	return err;
}

static int
hashcount_check(struct repdev *dev, int vlevel) {
	int err = 0;
	uint512_t chid;
	rtbuf_t* rb;
	/*
	 * Current implementation of reptrans_get_blob for TT_HASHCOUNT
	 * doesn't use neither chid, nor rbuf_t, but we provide it to be
	 * compatible with the call convention.
	 * reptrans_get_blob(..,TT_HASHCOUNT,..) fills dev->stats.hashcount
	 * array with a blob content
	 */
	err = reptrans_get_blob(dev, TT_HASHCOUNT, HASH_TYPE_DEFAULT,
	     &chid, &rb);

	if (err) {
		if (err == -ENOENT)
			printf("INFO: TT_HASHCOUNT is not initialized\n");
		else
			fprintf(stderr,"Error at reptrans_get_blob: %d\n", err);
		goto _isexit1;
	}

	size_t hcount = 0;
	for (size_t i=0; i < HASHCOUNT_TAB_LENGTH; i++) {
		if (dev->stats.hashcount[i]) {
			hcount++;
			if (vlevel > 1) {
				printf("INFO: HASHCOUNT[%lu]=%lu\n", hcount,
						dev->stats.hashcount[i]);
			}
		}
	}
	printf("INFO: HASHCOUN array has %lu non-zero entries\n", hcount);

_isexit1:
		return err;
}

