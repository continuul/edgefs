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

Logger lg;
#define DEFAULT_SCENARIO_FILE	"zone_test_scenario.json"
char *test_scenario_file = NULL;
char *fhdir = "fhdata";
#define FLEXHASH_TEST_VDEV_PER_SERVER	(numdevices/numservers)

#define FH_FILE(str, x)		sprintf(str, "%s/flexhash-%d.json", fhdir, (x));
#define FH_FAILED_FILE(str, x, y)	sprintf(str, "%s/flexhash-failed-%u-%d.json", fhdir, (x), (y));
#define FH_REBALANCE(str, x)	sprintf(str, "%s/flexhash-rebalanced-%d.json", fhdir, (x));

#define FH_DEV_FAILURE	1
#define FH_SERV_FAILURE	2
#define FH_ZONE_FAILURE	3

int scen_max;

/* generate a random number */
int rand_number(int min, int max)
{

	int r = rand() % (max + 1 - min) + min;
	return r;
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
fhz_test_random_hashcount(struct cl_vdev *vdevptr, uint16_t *hashcount, int n)
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
init_vdevs(struct cl_vdev *vdevs, int nr_vdevs,
	   int numrows, uint16_t baseport, int used)
{
	struct cl_vdev *vdevptr;
	for (int i = 0; i < nr_vdevs; i++) {
		vdevptr = &vdevs[i];
		init_vdevid(i, &vdevptr->vdevid);
		vdevptr->port = baseport + 1;
		vdevptr->size = 1099511627776;
		vdevptr->avail = 494780232499;
		vdevptr->state = VDEV_STATE_ALIVE;
		vdevptr->activerows = 0;
		if (used) {
			flexhash_sumsquares_seeded(&vdevptr->vdevid, &vdevptr->hashcount[0], numrows);
		} else {
			for (int i=0; i < numrows; i++) {
				vdevptr->hashcount[i] = 0;
			}
		}
		vdevptr->numrows = numrows;
	}
}

struct cl_node *
fhz_test_initserverlist(int numrows, int numdevices,
			int numservers, int numzones,
			int used)
{
	struct cl_node *node;
	struct sockaddr_in6 recv_addr;
	int spz = numservers/numzones;
	int zcount=1;

	node =
	(struct cl_node *) je_calloc(numservers, sizeof(struct cl_node));

	assert(node);

	for (int i = 0; i < numservers; i++) {
		node[i].zone = zcount;
		zcount = zcount == spz ? 1 : (zcount + 1) % numzones;

		init_serverid(i, &node[i].serverid);
		char *ipaddr_str = "fd00::d011%eth1";
		uint16_t port = 5405;
		recv_addr  = uv_ip6_addr(ipaddr_str, port);
		memcpy(&node[i].addr, &recv_addr.sin6_addr, sizeof (struct in6_addr));
		node[i].port = port;
		node[i].vdevs = (struct cl_vdev *) je_calloc(FLEXHASH_TEST_VDEV_PER_SERVER, sizeof (struct cl_vdev));
		assert(node[i].vdevs);
		node[i].nr_vdevs = FLEXHASH_TEST_VDEV_PER_SERVER;
		init_vdevs(node[i].vdevs, node[i].nr_vdevs, numrows, port, used);
	}
	return node;
}

void
fhz_test_test_modeldata(struct flexhash *fh, int numdevices, int numservers, int numzones)
{
	int count = flexhash_hashrowcount(numdevices);
	int dpr = flexhash_devs_perrow(fh, numdevices);
	int zpr = flexhash_zpr(numdevices, numzones);
	int rpd = (dpr * count)/numdevices;
	printf("#devs: %d #servers: %d #zones: %d #rows: %d dpr: %d rpd: %d \n",
	    numdevices, numservers, numzones, count, dpr, rpd);
}

void
flexhash_testsetup_zones(struct flexhash *fhtable, int numservers, int numzones)
{
	int srvperzone = numservers/numzones;
	int zcount = 1, scount = 0;
	struct fhserver *fhserver;

	if (!numzones)
		return;

	int c = 0;
	for (fhserver = fhtable->serverlist; fhserver != NULL;
		fhserver = fhserver->next, scount++) {
		fhserver->zone = zcount;
		if (c == srvperzone - 1)
			zcount++;
		c = (c + 1) % srvperzone;
	}
	fhtable->zonecount = numzones;
	for (c = 0; c < fhtable->zonecount; c++)
		fhtable->zonelist[c] = c + 1;
	assert(scount == numservers);
}

static void
fhz_test_remove_serverlist(struct flexhash *fh, struct cl_node *slist,
			   int numservers)
{
	for (int i = 0 ; i < numservers; i++)
		flexhash_remove_server(fh, &slist[i]);
	assert_int_equal(fh->servercount, 0);
	clengine_destroy_cl_node(slist, numservers);
}

struct flexhash *
fhz_build_fh(int ndevs, int nservs, int nzones, int scen_no, int used)
{
	char filename[64];
	struct flexhash *fh;
	struct cl_node *servlist;
	struct timeval start_tv, end_tv;

	gettimeofday(&start_tv, NULL);
	fh = flexhash_table_create(ndevs, FH_SERVER_SIDE);
	fhz_test_test_modeldata(fh, ndevs, nservs, nzones);
	assert(fh != NULL);

	servlist = fhz_test_initserverlist(fh->numrows, ndevs, nservs, nzones, used);
	flexhash_add_serverlist(fh, servlist, nservs, FH_NO_REBUILD);
	flexhash_testsetup_zones(fh, nservs, nzones);

	FH_FILE(filename, scen_no);
	FILE *fp = fopen(filename, "w+");
	flexhash_json_dump(fp, fh, 1, "test");
	fclose(fp);
	gettimeofday(&end_tv, NULL);
	printf("Time to build flexhash(%d) %lu sec %lu usec\n", scen_no,
		end_tv.tv_sec - start_tv.tv_sec,
		end_tv.tv_usec - start_tv.tv_usec);
	return fh;
}

static void
fhz_test_verify_fh(struct flexhash *fh, int scen_no)
{
	char cmd[256];
	for (int row = 0; row < fh->numrows; row++) {
		struct dlist *dl = &fh->dl[row];
		if (fh->zonecount)
			assert(dl->ngstat.zonecount >= FH_MIN_ZONE_COUNT);
		assert(dl->ngstat.servercount >= FH_MIN_SERVER_COUNT);
	}
	sprintf(cmd, "diff flexhash-%d.json flexhash-rebalanced-%d.json > flexhash-%d.diff", scen_no, scen_no, scen_no);
	system(cmd);
}

static void
fhz_test_rebalance(volatile struct flexhash *fh,
		   int nservs, int ndevs, int scen_no)
{
	char filename[64];
	flexhash_rebalance((struct flexhash *) fh);
	FH_REBALANCE(filename, scen_no);
	FILE *fp = fopen(filename, "w+");
	flexhash_json_dump(fp, fh, 1, "test");
	fclose(fp);
}

static void
fhz_test_scen(json_value *config, int scen_no)
{
	int ndevs = 0;
	int nservs = 0;
	int nzones = 0;
	int used_drives = 1;
	struct flexhash *fh;

	assert(config->u.integer > 0);
	assert(config->type == json_object);
	for (size_t i = 0; i < config->u.object.length; i++) {
		char *name = config->u.object.values[i].name;
		json_value *v = config->u.object.values[i].value;
		if (strncmp(name, "devices", 7) == 0) {
			assert(v->type == json_integer);
			ndevs = v->u.integer;
		} else if (strncmp(name, "servers", 7) == 0) {
			assert(v->type == json_integer);
			nservs = v->u.integer;
		} else if (strncmp(name, "zones", 5) == 0) {
			assert(v->type == json_integer);
			nzones = v->u.integer;
		} else  if (strcmp(name, "used_state") == 0) {
			assert(v->type == json_integer);
			used_drives = v->u.integer;
		}
	}
	log_info(lg, "#devs %d #servers %d #zones %d\n", ndevs, nservs, nzones);
	assert(ndevs <= FLEXHASH_MAX_VDEVS);
	assert(nservs <= FLEXHASH_MAX_SERVERS);
	assert(nzones <= FLEXHASH_MAX_ZONES);
	fh = fhz_build_fh(ndevs, nservs, nzones, scen_no, used_drives);
	assert(fh != NULL);
	fhz_test_rebalance(fh, nservs, nservs, scen_no);
	flexhash_table_destroy(fh);
}

json_value *
fhz_z_setup()
{
	json_value *scen;
	FILE *fp = NULL;
	struct stat statbuf;
	size_t sz;
	char *buf;
	int err;

	lg = Logger_create("fhz_test");
	err = stat(test_scenario_file, &statbuf);
	assert(err == 0);

	fp = fopen(test_scenario_file, "r");
	assert(fp != NULL);

	buf = je_calloc(1, statbuf.st_size);
	assert(buf != NULL);

	sz = fread(buf, sizeof(char), statbuf.st_size, fp);
	assert(sz == (size_t)statbuf.st_size);
	fclose(fp);

	scen = json_parse(buf, sz);
	assert(scen != NULL);
	assert(scen->type == json_object);

	char scmd[256];
	sprintf(scmd, "/bin/mkdir -p %s", fhdir);
	err = system(scmd);
	if (err) {
		log_error(lg, "Error running %s Error: %s", scmd, strerror(err));
		json_value_free(scen);
		return NULL;
	}
	return scen;
}

void
fhz_makefh_scenarios()
{
	json_value *scen = fhz_z_setup();
	if (scen) {
		printf("Number of scenarios: %u\n", scen->u.object.length);
		for (size_t i = 0; i < scen->u.object.length; i++) {
			if (strcmp(scen->u.object.values[i].name, "scenarios") == 0) {
				json_value *v = scen->u.object.values[i].value;
				assert(v->type == json_array);
				size_t j;
				for (j = 0 ; j < v->u.array.length; j++) {
					json_value *cfg = v->u.array.values[j];
					printf("Running use case: %lu\n", j + 1);
					fhz_test_scen(cfg, j);
				}
				scen_max = j;
			}
		}
	}
}

static void
fhz_run_test_scenarios(void **state)
{
	fhz_makefh_scenarios();
}

void
fhz_clean_test_scenarios()
{
	int err;
	char scmd[256];
	sprintf(scmd, "rm -rf %s", fhdir);
	err = system(scmd);
	if (err) {
		log_error(lg, "Error running %s Error: %s", scmd, strerror(err));
	}
}

void
fhz_test_sim_devfailure(struct flexhash *fh)
{
	// randomly remove some devices
	int fail_drives = fh->numdevices/3;
	if (fail_drives < 1)
		fail_drives = 1;

	int r = (int) rand_number(0, fail_drives);
	if (r > fail_drives/2)
		r = r/4;
	if (r == 0)
		r = 1;

	uint128_t nullid;
	memset(&nullid, 0, sizeof (uint128_t));
	printf("Total drives : %d\n", fh->numdevices);

	for (int j = 0; j < r; j++) {
		unsigned int fd = rand_number(0, fh->numdevices);
		uint128_t vdevid = vdevstore_getvdev_id(fh->vdevstore, fd);
		if (uint128_cmp(&nullid, &vdevid) == 0)
			continue;
		flexhash_leave(fh, &vdevid);
		vdevstore_remove_vdev(fh, &vdevid);
	}
	printf("Simulate %d failed drives, total drives : %d\n", r, fh->numdevices);
}

struct fhserver *
fhz_get_server(struct flexhash *fh, int index)
{
	struct fhserver *srv = fh->serverlist;

	for (int i = 0; i < fh->servercount; i++, srv = srv->next) {
		if (i == index)
			return srv;
	}
	return NULL;
}

void
fhz_test_sim_servfailure(struct flexhash *fh)
{
	// randomly remove some devices
	int fail_servs = fh->servercount/3;
	if (fail_servs < 1)
		fail_servs = 1;

	int s = (int) rand_number(0, fail_servs);
	if (s > fail_servs/2)
		s /= 4;
	if (s == 0)
		s = 1;
	for (int j = 0; j < s; j++) {
		int fd = rand_number(0, fh->servercount);
		struct fhserver *srv = fhz_get_server(fh, fd);
		if (srv) {
			struct cl_node node;
			node.serverid = srv->id;
			flexhash_remove_server(fh, &node);
		}
	}
	printf("Simulate %d failed servers\n", s);
}

struct fhserver *
fhz_get_zone_server(struct flexhash *fh, uint32_t zone)
{
	struct fhserver *srv = fh->serverlist;

	for (int i = 0; i < fh->servercount; i++, srv = srv->next) {
		if (srv->zone == zone)
			return srv;
	}
	return NULL;
}


void
fhz_test_sim_zonefailure(struct flexhash *fh)
{
	// randomly remove some devices
	int fail_zones = fh->zonecount/3;
	if (fail_zones < 1)
		fail_zones = 1;

	int z = (int) rand_number(0, fail_zones);
	if (z > fail_zones/2)
		z /= 4;
	if (z == 0)
		z = 1;
	for (int j = 0; j < z; j++) {
		int fd = rand_number(0, fh->zonecount);
		for (int i = 0; i < fh->servercount; i++) {
			struct fhserver *srv = fhz_get_zone_server(fh, fd);
			if (srv) {
				struct cl_node node;
				node.serverid = srv->id;
				flexhash_remove_server(fh, &node);
			}
		}
	}
	printf("Simulate %d failed zones\n", z);
}
void
fhz_test_simfailure(int i, uint8_t fail_type)
{
	char filename[64];
	char failedfile[64];
	char *desc = NULL;
	FH_REBALANCE(filename, i);
	struct flexhash *fh = flexhash_read_checkpoint(filename, 1);
	assert(fh != NULL);

	switch(fail_type) {
	case FH_DEV_FAILURE:
		desc = "failed_drives";
		fhz_test_sim_devfailure(fh);
		break;
	case FH_SERV_FAILURE:
		desc = "failed_servers";
		fhz_test_sim_servfailure(fh);
		break;
	case FH_ZONE_FAILURE:
		desc = "failed_zones";
		fhz_test_sim_zonefailure(fh);
		break;
	default:
		printf("Unkown failure type: %d\n", fail_type);
		return;
		break;
	}

	FH_FAILED_FILE(failedfile, fail_type, i);
	flexhash_rebalance(fh);
	// leader is not known for tests so we put 0
	flexhash_disk_dump(fh, failedfile, 0, desc);
	flexhash_table_destroy(fh);
}

void
fhz_z_simulate_failures(uint8_t fail_type)
{
	for (int i=0; i < scen_max; i++) {
		fhz_test_simfailure(i, fail_type);
	}
}

void
show_fddelta(struct fddelta *fddelta)
{
	printf("\n");
	printf("vdev_delta: %d\t", fddelta->vdev_delta);
	printf("server_delta: %d\t", fddelta->server_delta);
	printf("zone_delta: %d\t", fddelta->zone_delta);
	printf("affected_vdevs: %d\t", fddelta->affected_vdevs);
	printf("affected_servers: %d\t", fddelta->affected_servers);
	printf("affected_zones: %d\n", fddelta->affected_zones);
}

void
fhz_z_generate_fddeltas(uint8_t fail_type)
{
	char filename[64];
	char failedfile[64];
	struct timeval start_tv, end_tv;

	for (int i=0; i < scen_max; i++) {
		FH_FILE(filename, i);
		FH_FAILED_FILE(failedfile, fail_type, i);
		volatile struct flexhash *fh = flexhash_read_checkpoint(filename, 1);
		struct fddelta fddelta;
		gettimeofday(&start_tv, NULL);
		int err = flexhash_fddelta(fh, failedfile, &fddelta);
		if (err == 0) {
		gettimeofday(&end_tv, NULL);
		printf("Time to calculate delta flexhash(%d) %lu sec %lu usec\n", i,
			end_tv.tv_sec - start_tv.tv_sec,
			end_tv.tv_usec - start_tv.tv_usec);
			printf("%d %s\t%s\n", i, filename, failedfile);
			show_fddelta(&fddelta);
		}
		flexhash_table_destroy(fh);
	}
}

int
main(int argc, char **argv)
{
	extern char *optarg;
	extern int optind;
	int c, err = 0;
	static char usage[] = "usage: %s [-f <zone-test-scen-file>]\n";
	struct stat statbuf;
	int clean=0; int nounit=0;

	while ((c = getopt(argc, argv, "cf:z")) != -1) {
		switch (c) {
			case 'f':
				if (optarg)
					test_scenario_file = optarg;
				break;
			case 'c':
				clean=1;
				break;
			case 'z':
				if (optarg)
					test_scenario_file = optarg;
				nounit=1;
				break;
			case '?':
			default:
				err=1;
				break;
		}
	}
	if (err) {
		fprintf(stderr, usage, argv[0]);
		exit(1);
	}

	if (clean) {
		fhz_clean_test_scenarios();
		exit(0);
	}

	if (test_scenario_file == NULL) {
		test_scenario_file = strdup(DEFAULT_SCENARIO_FILE);
	}

	err = stat(test_scenario_file, &statbuf);
	if (err) {
		fprintf(stderr, "Invalid test scenario file %s\n", test_scenario_file);
		exit(1);
	}


	if (nounit) {
		/* Simulate disk failure */
		fhz_makefh_scenarios();
		fhz_z_simulate_failures(FH_DEV_FAILURE);
		fhz_z_generate_fddeltas(FH_DEV_FAILURE);

		/* Simulate server failure */
		fhz_makefh_scenarios();
		fhz_z_simulate_failures(FH_SERV_FAILURE);
		fhz_z_generate_fddeltas(FH_SERV_FAILURE);

		/* Simulate zone failure */
		fhz_makefh_scenarios();
		fhz_z_simulate_failures(FH_ZONE_FAILURE);
		fhz_z_generate_fddeltas(FH_ZONE_FAILURE);
		exit(0);
	}

	const UnitTest tests[] = {
		unit_test(fhz_run_test_scenarios),
	};
	return run_tests(tests);
}
