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
#include <math.h>

#include "ccowutil.h"
#include "common.h"
#include "logger.h"
#include "crypto.h"
#include "reptrans.h"
#include "serverid.h"
#include "flexhash.h"
#include "hashcount.h"
#include "clengine.h"

#define FLEXHASH_TEST_NUM_VDEVS		90 // FLEXHASH_MAX_VDEVS
#define FLEXHASH_TEST_SERVER_COUNT	9 // FLEXHASH_MAX_SERVERS
#define FLEXHASH_TEST_NUMHASHIDS	10

int random_hashcount = 1;

Logger lg;
struct simctx {
	int	numservers;
	int	numdevices;
	int	count;
	int	dpr;
	int	rpd;
	int	spr;
	int	rps;
	volatile struct flexhash *flexhash;
	struct cl_node *nodelist;
};


struct cl_node *
sims_allocnodelist(int numservers)
{
	struct cl_node *node;
	node = (struct cl_node *) je_calloc(numservers,
						sizeof (struct cl_node));
	assert(node);
	return node;
}

void
init_serverid(int num, uint128_t *serverid)
{
	uint8_t input[128];
	// create a random id
	sprintf((char *)input, "a random Server Id using cryptohash %d", num);
	int ret = crypto_hash(CRYPTO_BLAKE2B, 16, input,
	    strlen((char *)input), (uint8_t *)serverid);
}

void
init_vdevid(int num, uint128_t *vdevid)
{
	uint8_t input[128];
	// create a random id
	sprintf((char *)input, "a vdev Id using cryptohash %d %d %d", num,
	    rand(), rand());
	int ret = crypto_hash(CRYPTO_BLAKE2B, 16, input,
	    strlen((char *)input), (uint8_t *)vdevid);
}

void
libflexhash_random_hashcount(struct cl_vdev *vdevptr, uint16_t *hashcount, int n)
{

	if (n > 1) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		unsigned long tmm = 1000000 * tv.tv_sec + tv.tv_usec;
		srand(tmm);

		for (int i = 0; i < n - 1; i++) {
			int j = i + rand() / (RAND_MAX / (n - i) + 1);
			hashcount[j] = 1;
		}

		vdevptr->activerows = 0;
		for (int i = 0; i < n; i++) {
			if (vdevptr->hashcount[i] > 0)
				vdevptr->activerows++;
		}

	}
}

void
init_vdevs(struct cl_vdev *vdevs, int nr_vdevs, uint16_t baseport)
{
	struct cl_vdev *vdevptr;
	for (int i = 0; i < nr_vdevs; i++) {
		vdevptr = &vdevs[i];
		init_vdevid(i, &vdevptr->vdevid);
		vdevptr->port = baseport + 1;
		vdevptr->size = 1099511627776;
		vdevptr->avail = 494780232499;
		if (random_hashcount)
			libflexhash_random_hashcount(vdevptr, &vdevptr->hashcount[0], FLEXCOUNT_TAB_LENGTH);
		else
			flexhash_sumsquares_seeded(&vdevptr->vdevid, &vdevptr->hashcount[0], FLEXCOUNT_TAB_LENGTH);
		vdevptr->activerows = 0;
		vdevptr->numrows = FLEXCOUNT_TAB_LENGTH;
	}
}

static void
sims_initnodelist(int numservers, int numdevices, struct cl_node *lnode)
{
	struct sockaddr_in6 recv_addr;
	struct cl_node *node = lnode;
	assert(numdevices > numservers);
	for (int i = 0; i < numservers; i++) {
		init_serverid(i, &node->serverid);
		char *ipaddr_str = "fd00::d011%eth1";
		uint16_t port = 5405;
		recv_addr  = uv_ip6_addr(ipaddr_str, port);
		memcpy(&node->addr, &recv_addr.sin6_addr, sizeof (struct in6_addr));
		node->port = port;
		int vdevsperserver = numdevices/numservers;
		node->vdevs = (struct cl_vdev *) je_calloc(vdevsperserver, sizeof (struct cl_vdev));
		assert(node->vdevs);
		node->nr_vdevs = vdevsperserver;
		init_vdevs(node->vdevs, node->nr_vdevs, port);
		node++;
	}
}


static void
libflexhash_rowchid(struct simctx *simctx)
{

	uint8_t input[128];
	uint512_t cchid;
	char cchidstr[UINT512_BYTES*2 + 1];

	for (int i = 0; i < FLEXHASH_TEST_NUMHASHIDS; i++) {
		// create a random id
		sprintf((char *)input, "a chid using cryptohash %d %d %d", i,
		    rand(), rand());
		int err = crypto_hash_with_type((crypto_hash_t)1,
			    (uint8_t *)input, strlen((char *) input),
			    (uint8_t *)&cchid);

		uint512_dump(&cchid, cchidstr, UINT512_BYTES*2 + 1);
		struct flexhash *fhtable = (struct flexhash *) simctx->flexhash;
		fhrow_t rowid = HASHROWID(&cchid, fhtable);
#if 0
		log_info(lg, "chid: %s row: %d hashmask: 0x%x", cchidstr,
				rowid, fhtable->hashmask);
#endif
	}

}


static void
libflexhash_join(void **state)
{
//	flexhash_summary(g_flexhash_table);
	// later
}

static void
libflexhash_leave(void **state)
{
// 	flexhash_summary(g_flexhash_table);
	// later
}

static void
sims_remove_serverlist(struct simctx *simctx)
{

	struct cl_node *node = simctx->nodelist;
	for (int i = 0 ; i < simctx->numservers; i++) {
		flexhash_remove_server(simctx->flexhash, node);
		node++;
	}
	clengine_destroy_cl_node(simctx->nodelist, simctx->numservers);
}

static void
libflexhash_access(struct simctx *simctx)
{
	struct dlist *dl = NULL;
	fhrow_t rowid;
	volatile struct flexhash *fhtable = simctx->flexhash;
	struct fhdev *fdev = NULL;
	int count = 0;

	for (rowid = 0; rowid < fhtable->numrows; rowid++) {
		dl = flexhash_devicelist(fhtable, rowid);
		count = 0;
		for (fdev = dl->devlist; fdev != NULL; fdev = fdev->next) {
			count++;
		}
	}

}

static void
sims_rebalance(struct simctx *simctx)
{
	volatile struct flexhash *fhtable = simctx->flexhash;

	flexhash_rebuild_start(fhtable, simctx->numservers, simctx->numdevices);

	flexhash_add_serverlist(fhtable->rebuild_ctx.fhtable, simctx->nodelist,
		simctx->numservers, FH_REBUILD_NEXT);
	// flexhash_dump(rb_ctx->fhtable, 1);

	flexhash_rebuild_done(&simctx->flexhash, 0, 0, 0);

	flexhash_dump(simctx->flexhash, 1);

	FILE *fp = fopen("flexhash.json", "w+");
	flexhash_json_dump(fp, simctx->flexhash, 1, "test");
	fclose(fp);
}

static void
libflexhash_sumsquares(void **state)
{
	uint8_t input[128];
	uint128_t serverid1;
	int ret, i, hcsz;
	char out[64];
	uint16_t *hashcount1;
	uint16_t *hashcount2;

	sprintf((char *)input, "random string for id generation");
	ret = crypto_hash(CRYPTO_BLAKE2B, 16,
			input, strlen((char *)input), (uint8_t *)&serverid1);
	uint128_dump(&serverid1, out, 64);
	assert(!ret);

	/* get the row count for the number of vdevs */
	hcsz = flexhash_hashrowcount(FLEXHASH_MAX_VDEVS);
	hashcount1 = je_calloc(hcsz, sizeof (uint16_t));
	hashcount2 = je_calloc(hcsz, sizeof (uint16_t));
	flexhash_sumsquares_seeded(&serverid1, hashcount1, hcsz);
	flexhash_sumsquares_seeded(&serverid1, hashcount2, hcsz);
	for (i = 0; i < hcsz; i++) {
		// assert_int_equal(hashcount1[i], hashcount2[i]);
	}
	je_free(hashcount1);
	je_free(hashcount2);
}

struct simctx *
init_sims(int numservers, int numdevices)
{
	struct simctx *rsim = je_calloc(1, sizeof (struct simctx));
	if (!rsim)
		return NULL;
	rsim->numservers = numservers;
	rsim->numdevices = numdevices;
	rsim->flexhash = flexhash_table_create(numdevices, FH_SERVER_SIDE);
	rsim->count = flexhash_hashrowcount(numdevices);
	rsim->dpr = flexhash_devs_perrow(rsim->flexhash, numdevices);
	rsim->rpd = (rsim->dpr * rsim->count)/numdevices;
	rsim->nodelist = sims_allocnodelist(numservers);
	sims_initnodelist(numservers, numdevices, rsim->nodelist);
	flexhash_add_serverlist(rsim->flexhash, rsim->nodelist, numservers,
		FH_NO_REBUILD);
	rsim->spr = flexhash_spr(rsim->flexhash);
	rsim->rps = (rsim->spr * rsim->count)/numservers;

	return rsim;
}

void
dump_sims(struct simctx *simctx)
{
	printf("simctx: %p numservers: %d numdevices: %d\n",
	    simctx, simctx->numservers, simctx->numdevices);
	printf("#devs: %d #servers: %d #rows: %d dpr: %d rpd: %d spr: %d rps: %d\n",
	    simctx->numdevices, simctx->numservers, simctx->count, simctx->dpr,
	    simctx->rpd, simctx->spr, simctx->rps);
}


int
run_sims(struct simctx *simctx)
{
	sims_rebalance(simctx);
	return 0;
}

int
finish_sims(struct simctx *simctx)
{

	if (simctx) {
		sims_remove_serverlist(simctx);
		flexhash_table_destroy(simctx->flexhash);
		je_free(simctx);
	}
	return 0;
}



int
main(int argc, char **argv)
{
	extern char *optarg;
	extern int optind;
	int c, err = 0;
	static char usage[] = "usage: %s [-d <#vdevs>] [-s <#servers>]\n";
	int srvp = 0, vdevp = 0;
	char *fname = NULL;
	int numdevices = 0;
	int numservers = 0;

	lg = Logger_create("flexhash_sim");
	load_crypto_lib();
	while ((c = getopt(argc, argv, "d:s:")) != -1) {
		switch (c) {
		case 'd':
			vdevp = 1;
			if (optarg)
				numdevices = (int) strtoul(optarg, NULL, 10);
			else {
				fprintf(stderr, usage, argv[0]);
				exit(1);
			}
			break;
		case 's':
			srvp = 1;
			if (optarg) {
				numservers = (int) strtoul(optarg, NULL, 10);
			}
			break;
		case '?':
		default:
			err = 1;
			break;
		}
	}
	if (err) {
		fprintf(stderr, usage, argv[0]);
		exit(1);
	}
	if (vdevp) {
		if (!srvp) {
			numservers = numdevices/4;
			numservers = (numservers <= 1) ? 1 : numservers;
		} else {
			numservers = (numservers <= 1) ? 1 : numservers;
		}
	} else {
		numdevices = FLEXHASH_TEST_NUM_VDEVS;
		numservers = FLEXHASH_TEST_SERVER_COUNT;
	}

	if (numdevices < numservers) {
		log_error(lg, "numdevices: %d is less than numservers: %d", numdevices, numservers);
		assert(0);
	}

	struct simctx *simctx = init_sims(numservers, numdevices);
	if (!simctx) {
		log_error(lg, "init_sims returned NULL");
		return -1;
	}
	dump_sims(simctx);
	run_sims(simctx);

	return finish_sims(simctx);
}
