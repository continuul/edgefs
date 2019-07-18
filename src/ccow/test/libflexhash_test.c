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
#include "cmocka.h"
#include "common.h"
#include "logger.h"
#include "crypto.h"
#include "reptrans.h"
#include "serverid.h"
#include "flexhash.h"
#include "hashcount.h"
#include "clengine.h"

#include "fhprivate.h"

volatile struct flexhash *g_flexhash_table;
struct cl_node *g_serverlist;

#define FLEXHASH_TEST_NUM_VDEVS		90 // FLEXHASH_MAX_VDEVS
#define FLEXHASH_TEST_SERVER_COUNT	9 // FLEXHASH_MAX_SERVERS
#define FLEXHASH_TEST_ZONE_COUNT	3
#define FLEXHASH_TEST_NUMHASHIDS	10

int numdevices;
int numservers;
int numzones;
int random_hashcount = 1;

#define FLEXHASH_TEST_VDEV_PER_SERVER	(numdevices/numservers)

Logger lg;
struct flexhash *
flexhash_default()
{
	if (g_flexhash_table == NULL) {
		log_error(lg, "Attempt to access uninitialized flexhash table");
		assert(0);
	}
	return (struct flexhash *) g_flexhash_table;
}

struct cl_node *
libflexhash_allocserverlist()
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
	assert_int_equal(ret, 0);
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
	assert_int_equal(ret, 0);
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
libflexhash_initserverlist(struct cl_node *lnode)
{
	struct sockaddr_in6 recv_addr;
	struct cl_node *node = lnode;
	int spz = numservers/numzones;
	int zcount=1;
	for (int i = 0; i < numservers; i++) {
		node->zone = zcount;
		if (zcount == spz)
			zcount = 1;
		else
			zcount++;
		init_serverid(i, &node->serverid);
		char *ipaddr_str = "fd00::d011%eth1";
		uint16_t port = 5405;
		recv_addr  = uv_ip6_addr(ipaddr_str, port);
		memcpy(&node->addr, &recv_addr.sin6_addr, sizeof (struct in6_addr));
		node->port = port;
		node->vdevs = (struct cl_vdev *) je_calloc(FLEXHASH_TEST_VDEV_PER_SERVER, sizeof (struct cl_vdev));
		assert(node->vdevs);
		node->nr_vdevs = FLEXHASH_TEST_VDEV_PER_SERVER;
		init_vdevs(node->vdevs, node->nr_vdevs, port);
		node++;
	}
}

void
libflexhash_test_modeldata(int numdevices, int numservers, int numzones)
{
	int count = flexhash_hashrowcount(numdevices);
	int dpr = flexhash_devs_perrow(g_flexhash_table, numdevices);
	int zpr = flexhash_zpr(numdevices, numzones);
	int rpd = (dpr * count)/numdevices;
	log_info(lg, "#devs: %d #servers: %d #zones: %d #rows: %d dpr: %d rpd: %d ",
	    numdevices, numservers, numzones, count, dpr, rpd);
}

void
flexhash_testsetup_zones(struct flexhash *fhtable, int numservers, int numzones)
{
	int srvperzone = numservers/numzones;
	int zcount = 1, scount = 0;
	struct fhserver *fhserver = fhtable->serverlist;

	int c = 1;
	for (; fhserver != NULL; fhserver = fhserver->next, scount++) {
		fhserver->zone = zcount;
		if (c == srvperzone) {
			c = 1;
			zcount++;
		} else {
			c++;
		}
	}
	assert(scount == numservers);
}

static void
libflexhash_setup(void **state)
{
	lg = Logger_create("libflexhash_test");
	g_flexhash_table = flexhash_table_create(numdevices, FH_SERVER_SIDE);
	libflexhash_test_modeldata(numdevices, numservers, numzones);
	g_serverlist = libflexhash_allocserverlist();
	libflexhash_initserverlist(g_serverlist);
	flexhash_summary(g_flexhash_table);
}

static void
libflexhash_init(void **state)
{
	// now add all of these back into the flexhash
	flexhash_add_serverlist(flexhash_default(), g_serverlist, numservers,
		FH_NO_REBUILD);
	flexhash_testsetup_zones(flexhash_default(), numservers, numzones);
	assert_int_equal(g_flexhash_table->servercount, numservers);
	flexhash_dump(flexhash_default(), 1);
}

static void
libflexhash_rowchid(void **state)
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
		assert_int_equal(err, 0);

		uint512_dump(&cchid, cchidstr, UINT512_BYTES*2 + 1);
		struct flexhash *fhtable = flexhash_default();
		fhrow_t rowid = HASHROWID(&cchid, fhtable);
#if 0
		log_info(lg, "chid: %s row: %d hashmask: 0x%x", cchidstr,
				rowid, fhtable->hashmask);
#endif
		assert_true(rowid < fhtable->numrows);
	}

}


static void
libflexhash_join(void **state)
{
	flexhash_summary(g_flexhash_table);
	// later
}

static void
libflexhash_leave(void **state)
{
	flexhash_summary(g_flexhash_table);
	// later
}

static void
libflexhash_remove_serverlist()
{

	struct cl_node *node = g_serverlist;
	for (int i = 0 ; i < numservers; i++) {
		flexhash_remove_server(flexhash_default(), node);
		node++;
	}
	assert_int_equal(g_flexhash_table->servercount, 0);
	clengine_destroy_cl_node(g_serverlist, numservers);
}

static void
libflexhash_finish(void **state)
{
	struct flexhash *fhtable = flexhash_default();
	libflexhash_remove_serverlist();
	flexhash_table_destroy(fhtable);
}

static void
libflexhash_zone(void **state)
{
	struct fhserver *server;
	printf("servercount: %d\n", g_flexhash_table->servercount);
	int i =0;
	for (server = g_flexhash_table->serverlist; server != NULL; server = server->next, i++) {
		printf("server index: %d zone index: %d\n", i, server->zone);
	}
	assert(i == g_flexhash_table->servercount);
}

static void
libflexhash_checkpoint_fddelta(void **state)
{
	char cmd[256];
	int err;
	int prev_checkpoint = 0;

	struct flexhash *fhtable = flexhash_default();
	int fddelta_val;
	struct fddelta fddelta;
	err = flexhash_fddelta_checkpoint(fhtable, &fddelta_val, &fddelta);
	if (fddelta_val > 0) {
		prev_checkpoint = 1;
		sprintf(cmd, "mv %s/var/run/flexhash-checkpoint.json /tmp", nedge_path());
		int rc = system(cmd);
		if (rc != 0) {
			log_error(lg, "Unable to run the command: %s Error: %s", cmd,
			    strerror(errno));
			return;
		}
	}
	sprintf(cmd, "cp %s/var/run/flexhash.json"
	    " %s/var/run/flexhash-checkpoint.json", nedge_path(), nedge_path());
	int rc = system(cmd);
	if (rc != 0) {
		log_error(lg, "Unable to run the command: %s Error: %s", cmd,
		    strerror(errno));
		return;
	}
	err = flexhash_fddelta_checkpoint(fhtable, &fddelta_val, &fddelta);
	assert_int_equal(err, 0);
	assert_int_equal(fddelta_val, 0);
	if (prev_checkpoint) {
		sprintf(cmd, "mv /tmp/flexhash-checkpoint.json %s/var/run/flexhash-checkpoint.json",
				nedge_path());
		int rc = system(cmd);
		if (rc != 0) {
			log_error(lg, "Unable to run the command: %s Error: %s", cmd,
			    strerror(errno));
			return;
		}
	} else {
		sprintf(cmd, "rm %s/var/run/flexhash-checkpoint.json", nedge_path());
		int rc = system(cmd);
		if (rc != 0) {
			log_error(lg, "Unable to run the command: %s Error: %s", cmd,
			    strerror(errno));
			return;
		}
	}
}

static void
libflexhash_access(void **state)
{
	struct dlist *dl = NULL;
	fhrow_t rowid;
	struct flexhash *fhtable = flexhash_default();
	struct fhdev *fdev = NULL;
	int count = 0;

	for (rowid = 0; rowid < fhtable->numrows; rowid++) {
		dl = flexhash_devicelist(fhtable, rowid);
		count = 0;
		for (fdev = dl->devlist; fdev != NULL; fdev = fdev->next) {
			count++;
		}
		assert_int_equal(count, dl->numdevs);
	}

}

void
evac_cb(int rowsperdev, hashtable_t *src_t, hashtable_t *tgt_t)
{
	unsigned int sc, tc;
	char vdevstr[64];

	uint128_t **src_vidl = (uint128_t **) hashtable_keys(src_t, &sc);
	uint128_t **tgt_vidl = (uint128_t **) hashtable_keys(tgt_t, &tc);

	printf("Source vdevs\n");
	for (unsigned int i = 0; i < sc; i++) {
		uint128_dump(src_vidl[i], vdevstr, 64);
		printf("%u. vdev %s\n", i, vdevstr);
	}

	printf("Target vdevs\n");
	for (unsigned int i = 0; i < tc; i++) {
		uint128_dump(tgt_vidl[i], vdevstr, 64);
		printf("%u. vdev %s\n", i, vdevstr);
	}
}

static void
libflexhash_evac(void **state)
{
	struct flexhash *fhtable = flexhash_default();
	fhtable->devsperrow = flexhash_devs_perrow(fhtable, fhtable->numdevices);
	int rowsperdev = (fhtable->devsperrow * fhtable->numrows)/fhtable->numdevices;

	flexhash_evac(EVAC_ROW_PARTICIPATION, fhtable, rowsperdev, evac_cb);
}

void
libflexhash_compare_tables(struct flexhash *fhtable1, struct flexhash *fhtable2)
{
	if (fhtable1->genid != fhtable2->genid) {
		log_error(lg, "Genid %lu and %lu do not match ",
		    fhtable1->genid, fhtable2->genid);
		return;
	}

	if (fhtable1->numdevices != fhtable2->numdevices) {
		log_error(lg, "Numdevices %d and %d do not match ",
		    fhtable1->numdevices, fhtable2->numdevices);
		return;
	}

	if (fhtable1->numrows != fhtable2->numrows) {
		log_error(lg, "Numrows %d and %d do not match ",
		    fhtable1->numrows, fhtable2->numrows);
		return;
	}

	if (fhtable1->servercount != fhtable2->servercount) {
		log_error(lg, "Servercount %d and %d do not match ",
		    fhtable1->servercount, fhtable2->servercount);
		return;
	}

	if (fhtable1->zonecount != fhtable2->zonecount) {
		log_error(lg, "Zonecount %d and %d do not match ",
		    fhtable1->zonecount, fhtable2->zonecount);
		return;
	}

	// TODO: compare each vdevs

	// TODO: compare each server

	// TODO: compare each zone configuration
}

static void
libflexhash_checkpoint(void **state)
{
	char cmd[256];
	struct flexhash *fhtable = flexhash_default();


	sprintf(cmd, "cp %s/var/run/flexhash.json"
	    " %s/var/run/flexhash-checkpoint.json", nedge_path(), nedge_path());
	int rc = system(cmd);
	if (rc != 0) {
		log_error(lg, "Unable to run the command: %s Error: %s", cmd,
		    strerror(errno));
		return;
	}

	struct flexhash *fhtable_c = flexhash_read_checkpoint(NULL, 0);
	if (!fhtable) {
		sprintf(cmd, "cp %s/var/run/flexhash.json"
		    " %s/var/run/flexhash-checkpoint.json", nedge_path(), nedge_path());
		int rc = system(cmd);
		if (rc != 0) {
			log_error(lg, "Unable to run the command: %s Error: %s", cmd,
			    strerror(errno));
			return;
		}
		fhtable_c = flexhash_read_checkpoint(NULL, 0);
	}
	if (fhtable && fhtable_c) {
		libflexhash_compare_tables(fhtable, fhtable_c);
		flexhash_table_destroy(fhtable_c);
	}
}

static void
libflexhash_rebalance(void **state)
{
	struct flexhash *fhtable = flexhash_default();

	struct rebuild_ctx *rb_ctx = &fhtable->rebuild_ctx;

	flexhash_rebuild_start(fhtable, numservers, numdevices);

	flexhash_add_serverlist(rb_ctx->fhtable, g_serverlist, numservers,
		FH_REBUILD_NEXT);
	flexhash_dump(rb_ctx->fhtable, 1);

	flexhash_rebuild_done(&g_flexhash_table, 0, 0, 0);

	flexhash_dump(g_flexhash_table, 1);

	FILE *fp = fopen("flexhash.json", "w+");
	flexhash_json_dump(fp, g_flexhash_table, 1, "test");
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
	assert_int_equal(ret, 0);
	uint128_dump(&serverid1, out, 64);

	/* get the row count for the number of vdevs */
	hcsz = flexhash_hashrowcount(FLEXHASH_MAX_VDEVS);
	hashcount1 = je_calloc(hcsz, sizeof (uint16_t));
	hashcount2 = je_calloc(hcsz, sizeof (uint16_t));
	flexhash_sumsquares_seeded(&serverid1, hashcount1, hcsz);
	flexhash_sumsquares_seeded(&serverid1, hashcount2, hcsz);
	for (i = 0; i < hcsz; i++) {
		assert_int_equal(hashcount1[i], hashcount2[i]);
	}
	je_free(hashcount1);
	je_free(hashcount2);
}

int
main(int argc, char **argv)
{
	extern char *optarg;
	extern int optind;
	int c, err = 0;
	static char usage[] = "usage: %s [-d <#vdevs>] [-s <#servers>] [-z <#zones>]\n";
	int srvp = 0, vdevp = 0;
	char *fname = NULL;

	while ((c = getopt(argc, argv, "d:s:z:")) != -1) {
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
			case 'z':
				if (optarg) {
					numzones = (int) strtoul(optarg, NULL, 10);
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
		numzones = FLEXHASH_TEST_ZONE_COUNT;
	}

	const UnitTest tests[] = {
		unit_test(libflexhash_setup),
		unit_test(libflexhash_sumsquares),
		unit_test(libflexhash_init),
		unit_test(libflexhash_access),
		unit_test(libflexhash_zone),
		unit_test(libflexhash_rebalance),
		unit_test(libflexhash_join),
		unit_test(libflexhash_checkpoint_fddelta),
		unit_test(libflexhash_rowchid),
		unit_test(libflexhash_checkpoint),
		unit_test(libflexhash_leave),
		unit_test(libflexhash_evac),
		unit_test(libflexhash_finish),
	};
	return run_tests(tests);
}
