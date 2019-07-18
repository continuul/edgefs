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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "ccowutil.h"
#include "ccow.h"
#include "ccow-impl.h"
#include "ccowd.h"
#include "opp-status.h"
#include "replicast.h"

#define CID_DEFAULT	"cltest"
#define TID_DEFAULT	"test"
#define BID_DEFAULT	"put-file-bucket-test"
#define OID_DEFAULT	"file-put"
#define	PARALLEL_OPS_N	50
static void
usage(const char *argv0)
{
	printf(	"\n"
		"USAGE:\n"
		"	%s [-h] [-s] [-b bucket_name] [-o obj_id]\n"
		"		[-t tenent_name] [-c cluster_name] [-l log_str]\n"
		"\n"
		"	-h	Display this message and exit\n"
		"\n"
		"	-o	Specify object name\n"
		"\n"
		"	-b	Specify bucket name\n"
		"\n"
		"	-c	Specify cluster name\n"
		"\n"
		"	-t	Specify tenant name\n"
		"\n"
		"	-V	Get verification progress\n"
		"\n"
		"	-s	Short output\n"
		"\n"
		"	-x	eXtended info (valid only with -V)\n"
		"\n"
		"	-p	add Parity chunk info (valid only with -x)\n"
		"\n"
		"	-l <str> log requested info to server's log file\n"
		"		<str> can be made of:\n"
		"		- 'L' log lost CHIDs,\n"
		"		- 'N' log CHIDs if #VBRs = 0\n"
		"		- 'O' log CHIDs if #VBRs < #Replicas\n"
		"		- 'P' log CHIDs of leaf manifests that have no parity manifest\n"
		"\n"
		"	-j	output in JSON format\n"
		"\n"
		"\n", argv0);

	exit(EXIT_SUCCESS);
}

static uint64_t vdev_usage_summ = 0;
static uint32_t vdev_usage_number = 0;
static uint128_t* known_hosts = NULL;
static uint32_t n_known_hosts = 0;

static int
vdev_usage_avg_update(const uint128_t* host, uint64_t* vdev_usage,
	uint32_t n_vdevs) {
	static uint32_t hosts_max = 0;
	if (!known_hosts) {
		known_hosts = je_calloc(10, sizeof(uint128_t));
		if (!known_hosts) {
			fprintf(stderr, "Memory allocation error\n");
			return -ENOMEM;
		}
		hosts_max = 10;
	}
	/* Don't add the same host twice */
	for (uint32_t i = 0; i < n_known_hosts; i++) {
		if (!uint128_cmp(known_hosts + i, host))
			return 0;
	}
	if (n_known_hosts >= hosts_max) {
		known_hosts = je_realloc(known_hosts, hosts_max*2*sizeof(uint128_t));
		if (!known_hosts) {
			fprintf(stderr, "Memory allocation error\n");
			return -ENOMEM;
		}
		hosts_max *= 2;
	}
	known_hosts[n_known_hosts++] = *host;
	for (uint32_t i = 0; i < n_vdevs; i++)
		vdev_usage_summ += vdev_usage[i];
	vdev_usage_number += n_vdevs;
	return 0;
}

static uint64_t
vdev_usage_avg_get() {
	return vdev_usage_number ? vdev_usage_summ/vdev_usage_number : 0;
}

static void dump_json(const opp_status_t* ostat) {
	printf("{\"n_cpar\":%lu, \"n_cp\":%lu, \"n_cm_zl\":%lu, \"n_cm_tl\":%lu, "
		"\"n_cm_zl_pp\":%lu, \"n_cm_zl_verified\":%lu, \"n_cm_tl_verified\":%lu, "
		"\"n_cp_verified\":%lu, \"n_cpar_verified\":%lu, \"n_cm_zl_1vbr\":%lu, "
		"\"n_cm_tl_1vbr\":%lu, \"n_cp_1vbr\":%lu, \"n_cm_zl_lost\":%lu, "
		"\"n_cm_tl_lost\":%lu, \"n_cp_lost\":%lu, \"n_cpar_lost\":%lu, "
		"\"n_cm_zl_erc_err\":%lu, \"n_cm_tl_erc_err\":%lu, ", ostat->n_cpar,
		ostat->n_cp, ostat->n_cm_zl, ostat->n_cm_tl, ostat->n_cm_zl_pp,
		ostat->n_cm_zl_verified, ostat->n_cm_tl_verified, ostat->n_cp_verified,
		ostat->n_cpar_verified, ostat->n_cm_zl_1vbr, ostat->n_cm_tl_1vbr,
		ostat->n_cp_1vbr, ostat->n_cm_zl_lost, ostat->n_cm_tl_lost,
		ostat->n_cp_lost, ostat->n_cpar_lost, ostat->n_cm_zl_erc_err,
		ostat->n_cm_tl_erc_err);
	char hoststr[UINT128_BYTES*2+1];
	uint128_dump(&ostat->hostid, hoststr, UINT128_BYTES*2+1);
	printf("\"hostid\":\"%s\", \"pp_algo\":%d, \"pp_data_number\":%d, "
		"\"pp_parity_number\":%d, \"pp_domain\":%d, \"vdevs_usage\":%lu,"
		" \"n_hosts\":%u}", hoststr, ostat->pp_algo,
		ostat->pp_data_number, ostat->pp_parity_number,
		ostat->pp_domain, vdev_usage_avg_get(), n_known_hosts);
}

static int
ecstat_calc_nhid(const char* cid, const char* tid, const char* bid,
	const char* oid, uint512_t* nhid) {
	int err = 0;
	crypto_state_t S;
	err = crypto_init_with_type(&S, HASH_TYPE_DEFAULT);
	if (err) {
		log_error(lg, "crypto_init: object hash id %d", err);
		return err;
	}

	err = crypto_update(&S, (uint8_t *)cid, strlen(cid) + 1);
	if (err) {
		log_error(lg, "crypto_update: object hash id %d", err);
		return err;
	}

	err = crypto_update(&S, (uint8_t *)tid, strlen(tid) + 1);
	if (err) {
		log_error(lg, "crypto_update: object hash id %d", err);
		return err;
	}

	err = crypto_update(&S, (uint8_t *)bid, strlen(bid) + 1);
	if (err) {
		log_error(lg, "crypto_update: object hash id %d", err);
		return err;
	}

	err = crypto_update(&S, (uint8_t *)oid, strlen(oid) + 1);
	if (err) {
		log_error(lg, "crypto_update: object hash id %d", err);
		return err;
	}

	crypto_final(&S, (uint8_t *)nhid);
	if (err)
		log_error(lg, "crypto_final: object hash id %d", err);
	return err;
}

struct vminfo {
	uint512_t vmchid;
	uint512_t nhid;
};

int
main(int argc, char** argv) {

	int opt;
	int o_short = 0;
	char* cid = NULL;
	char* tid = NULL;
	char* bid = NULL;
	char* oid = NULL;
	int verify = 0;
	int ext = 0;
	int p_info = 0;
	char* lerr = 0;
	int json = 0;
	struct vminfo* vms = NULL;
	int n_vms = 0;
	uint512_t vmchid, nhid;
	int multipart = 0;
	uint64_t size = 0;
	uint32_t chunk_size = 0;
	uint64_t gen = 0;
	int verbose = 0;

	while ((opt = getopt(argc, argv, "ho:b:c:t:sVxpl:jv")) != -1) {
		switch(opt) {

			case 'o':
				oid = strdup(optarg);
				break;

			case 'b':
				bid = strdup(optarg);
				break;

			case 'c':
				cid = strdup(optarg);
				break;

			case 't':
				tid = strdup(optarg);
				break;

			case 'V':
				verify = 1;
				break;

			case 's':
				o_short = 1;
				break;

			case 'x':
				ext = 1;
				break;

			case 'p':
				p_info = 1;
				break;

			case 'l':
				lerr = strdup(optarg);;
				break;

			case 'j':
				json = 1;
				break;

			case 'v':
				verbose = 1;
				break;

			case 'h':
			default:
				usage(argv[0]);
				break;
		}
	}

	if (!oid)
		oid = "";
	if (!tid)
		tid = strdup(TID_DEFAULT);
	if (!cid)
		cid = strdup(CID_DEFAULT);
	if (!bid)
		bid = strdup(BID_DEFAULT);


	ccow_t cl;
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
	int ccow_fd = open(path, O_RDONLY);
	if (ccow_fd < 0) {
		fprintf(stderr, "ccow.json open error %d: %s\n",
			-errno, strerror(errno));
		return -errno;
	}

	char buf[16384];
	int err = read(ccow_fd, buf, 16383);
	if (err < 0) {
		fprintf(stderr, "\nccow.json read error %d: %s\n",
			-errno, strerror(errno));
		close(ccow_fd);
		return -EIO;
	}
	close(ccow_fd);
	buf[err] = 0;
	err = ccow_tenant_init(buf, cid, strlen(cid) + 1, tid, strlen(tid)+1,
		&cl);
	if (err) {
		fprintf(stderr, "\nccow init error: cluster or tenant ID is wrong\n");
		return -EINVAL;
	}
	ccow_completion_t c;
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	if (err) {
		fprintf(stderr, "\nccow_create_completion error: %d\n", err);
		ccow_tenant_term(cl);
		return err;
	}

	ccow_lookup_t iter;
	err = ccow_get(bid, strlen(bid) + 1, oid, strlen(oid) + 1, c, NULL, 0,
		0, &iter);
	if (err) {
		fprintf(stderr, "\nObject information retrieval error: %d\n", err);
		ccow_release(c);
		ccow_tenant_term(cl);
		return err;
	}
	err = ccow_wait(c, -1);
	if (err) {
		fprintf(stderr, "\nCan't get object info: bucket or object ID is"
			" wrong\n");
		ccow_tenant_term(cl);
		return -EINVAL;
	}
	struct ccow_metadata_kv *kv = NULL;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA | CCOW_MDTYPE_CUSTOM, -1))) {
		if (strcmp(kv->key, RT_SYSKEY_VM_CONTENT_HASH_ID) == 0) {
			memcpy(&vmchid, kv->value, sizeof(uint512_t));
		} else if (strcmp(kv->key, RT_SYSKEY_NAME_HASH_ID) == 0) {
			memcpy(&nhid, kv->value, sizeof(uint512_t));
		} else if (strcmp(kv->key, "multipart") == 0) {
			char* cptr = kv->value;
			multipart = *cptr == '2';
		} else if (strcmp(kv->key, RT_SYSKEY_LOGICAL_SIZE) == 0) {
			ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, &size);
		} else if (strcmp(kv->key, RT_SYSKEY_CHUNKMAP_CHUNK_SIZE) == 0) {
			ccow_iterator_kvcast(CCOW_KVTYPE_UINT32, kv, &chunk_size);
		} else if (strcmp(kv->key, RT_SYSKEY_TX_GENERATION_ID) == 0) {
			ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, &gen);
		}
	}
	ccow_lookup_release(iter);
	if (multipart) {
		/* The multipart object has a JSON string as a content.
		 * The JSON provides detailed info on parts.
		 * Collect all the part VMs, calculate their NHIDs
		 */
		int iovcnt = size / chunk_size + !!(size % chunk_size);
		char* iob = je_calloc(1, iovcnt*chunk_size);
		if (!iob) {
			ccow_tenant_term(cl);
			fprintf(stderr, "Memory allcoation error");
			return -ENOMEM;
		}
		struct iovec *iov = je_malloc(iovcnt * sizeof(struct iovec));
		if (!iob) {
			je_free(iob);
			ccow_tenant_term(cl);
			fprintf(stderr, "Memory allcoation error");
			return -ENOMEM;
		}
		for (int i = 0; i < iovcnt; i++) {
			iov[i].iov_len = chunk_size;
			iov[i].iov_base = iob + i*chunk_size;
		}
		err = ccow_create_completion(cl, NULL, NULL, 1, &c);
		if (err) {
			je_free(iob);
			je_free(iov);
			ccow_tenant_term(cl);
			fprintf(stderr, "ccow_create_completion error: %d\n", err);
			return -EIO;
		}
		err = ccow_get(bid, strlen(bid) + 1, oid, strlen(oid) + 1, c, iov, iovcnt,
			0, &iter);
		if (err) {
			je_free(iob);
			je_free(iov);
			ccow_release(c);
			fprintf(stderr, "ccow_get error: %d\n", err);
			return -EIO;
		}
		err = ccow_wait(c, -1);
		if (err) {
			je_free(iob);
			je_free(iov);
			fprintf(stderr, "ccow wait error: %d\n", err);
			return -EIO;
		}
		json_value* opts = json_parse(iob, size+1);
		je_free(iob);
		je_free(iov);
		if (!opts) {
			fprintf(stderr, "Error parsing multipart VM's content");
			return -EINVAL;
		}
		if (opts->type != json_array) {
			json_value_free(opts);
			printf("VM's JSON isn't an array: %d\n", opts->type);
			return -EINVAL;
		}
		vms = je_calloc(opts->u.array.length + 1, sizeof(*vms));
		for (uint32_t i = 0; i < opts->u.array.length; i++) {
			json_value* item = opts->u.array.values[i];
			assert(item->type == json_object);
			struct vminfo* cur = vms + i;
			for (uint32_t j = 0; j < item->u.object.length; j++) {
				char *namekey = item->u.object.values[j].name;
				json_value *v = item->u.object.values[j].value;
				if (strcmp(namekey, "vm_content_hash_id") == 0) {
					uint512_fromhex(v->u.string.ptr,
						UINT512_BYTES*2+1, &cur->vmchid);
				} else if (strcmp(namekey, "name") == 0) {
					err = ecstat_calc_nhid(cid, tid, bid,
						v->u.string.ptr,&cur->nhid);
					if (err) {
						json_value_free(opts);
						je_free(vms);
						fprintf(stderr, "Error calculating NHID");
						return err;
					}
				}
			}
			n_vms++;
		}
		json_value_free(opts);
	}
	if (!vms) {
		vms = je_calloc(1, sizeof(*vms));
		vms[n_vms].vmchid = vmchid;
		vms[n_vms++].nhid = nhid;
		if (verbose) {
			char chidstr[UINT512_BYTES*2+1];
			uint512_dump(&vmchid, chidstr, UINT512_BYTES*2+1);
			printf("VMCHID:\t%s\n", chidstr);
			uint512_dump(&nhid, chidstr, UINT512_BYTES*2+1);
			printf("NHID:\t%s\n", chidstr);
			printf("GEN:\t%lu\n", gen);
		}

	}
	opp_status_t ostat = {.n_cp = 0};
	int flags = 0; /* EC-information only */
	if (verify)
		flags |= OPP_STATUS_FLAG_VERIFY;
	if (ext)
		flags |= OPP_STATUS_FLAG_ERC;
	if (p_info)
		flags |= OPP_STATUS_FLAG_CPAR;
	if (lerr) {
		if (strchr(lerr, 'L'))
			flags |= OPP_STATUS_FLAG_LERR;
		if (strchr(lerr, 'N'))
			flags |= OPP_STATUS_FLAG_LACKVBR;
		if (strchr(lerr, 'O'))
			flags |= OPP_STATUS_FLAG_MISSVBR;
		if (strchr(lerr, 'P'))
			flags |= OPP_STATUS_FLAG_NOPM;
	}
	int vdev_usage_count = 0;
	uint64_t vdev_usage_summ = 0;
	opp_status_t* req_stat = je_calloc(PARALLEL_OPS_N, sizeof(opp_status_t));
	if (!req_stat) {
		fprintf(stderr, "Memory allocation error");
		ccow_tenant_term(cl);
		return err;
	}
	int cnt = 0;
	err = ccow_create_completion(cl, NULL, NULL, PARALLEL_OPS_N, &c);
	if (err) {
		fprintf(stderr, "\nccow_create_completion error: %d\n", err);
		ccow_tenant_term(cl);
		je_free(req_stat);
		return err;
	}
	for (int i = 0; i < n_vms; i++) {
		err = ccow_opp_satus_request(cl, &vms[i].vmchid, &vms[i].nhid, c,
			flags, req_stat + cnt);
		if (err) {
			fprintf(stderr, "\nError getting parity protection status: %d\n",
				err);
			ccow_tenant_term(cl);
			je_free(req_stat);
			return err;
		}
		cnt++;
		if ((cnt == PARALLEL_OPS_N) || (i == n_vms - 1)) {
			err = ccow_wait(c, -1);
			if (err) {
				fprintf(stderr, "\nIO error: %d\n", err);
				ccow_tenant_term(cl);
				je_free(req_stat);
				return err;
			}
			for (int j = 0; j < cnt; j++) {
				ostat.n_cm_tl += req_stat[j].n_cm_tl;
				ostat.n_cm_zl += req_stat[j].n_cm_zl;
				ostat.n_cp += req_stat[j].n_cp;
				ostat.n_cpar += req_stat[j].n_cpar;
				ostat.n_cm_zl_verified += req_stat[j].n_cm_zl_verified;
				ostat.n_cm_tl_verified += req_stat[j].n_cm_tl_verified;
				ostat.n_cp_verified += req_stat[j].n_cp_verified;
				ostat.n_cpar_verified += req_stat[j].n_cpar_verified;
				ostat.n_cm_zl_1vbr += req_stat[j].n_cm_zl_1vbr;
				ostat.n_cm_tl_1vbr += req_stat[j].n_cm_tl_1vbr;
				ostat.n_cp_1vbr += req_stat[j].n_cp_1vbr;
				ostat.n_cm_zl_lost += req_stat[j].n_cm_zl_lost;
				ostat.n_cm_tl_lost += req_stat[j].n_cm_tl_lost;
				ostat.n_cp_lost += req_stat[j].n_cp_lost;
				ostat.n_cpar_lost += req_stat[j].n_cpar_lost;
				ostat.n_cm_zl_pp += req_stat[j].n_cm_zl_pp;
				ostat.n_cm_zl_erc_err += req_stat[j].n_cm_zl_erc_err;
				ostat.n_cm_tl_erc_err += req_stat[j].n_cm_tl_erc_err;
				if (ostat.n_cm_zl_pp && !ostat.pp_data_number) {
					ostat.pp_algo = req_stat[j].pp_algo;
					ostat.pp_data_number = req_stat[j].pp_data_number;
					ostat.pp_parity_number = req_stat[j].pp_parity_number;
					ostat.pp_domain = req_stat[j].pp_domain;
				}
				ostat.hostid = req_stat[j].hostid;
				err = vdev_usage_avg_update(&req_stat[j].hostid,
					req_stat[j].vdevs_usage,
					req_stat[j].n_vdevs);
				je_free(req_stat[j].vdevs_usage);
				if (err) {
					ccow_tenant_term(cl);
					je_free(req_stat);
					return err;
				}
			}
			cnt = 0;
			memset(req_stat, 0, sizeof(opp_status_t)*PARALLEL_OPS_N);
			if (i != n_vms - 1) {
				err = ccow_create_completion(cl, NULL, NULL, PARALLEL_OPS_N, &c);
				if (err) {
					fprintf(stderr, "\nccow_create_completion error: %d\n", err);
					ccow_tenant_term(cl);
					je_free(req_stat);
					return err;
				}
			}
		}
	}
	je_free(req_stat);
	double ep = ostat.n_cm_zl ? (ostat.n_cm_zl_pp*100.0f/ostat.n_cm_zl) : 0.0f;
	size_t total_chunks = ostat.n_cp + ostat.n_cm_zl + ostat.n_cm_tl;
	size_t total_verified = ostat.n_cp_verified + ostat.n_cm_zl_verified + ostat.n_cm_tl_verified;
	size_t total_1vbr = ostat.n_cp_1vbr + ostat.n_cm_zl_1vbr + ostat.n_cm_tl_1vbr;
	double vp = total_chunks ? (total_verified*100.0f/total_chunks) : 0.0f;
	double vp1vbr = total_chunks ? (total_1vbr*100.0f/total_chunks) : 0.0f;

	if (o_short) {
		printf("%.2f %.2f %d:%d:%d:%d\n", vp, ep, ostat.pp_data_number,
			ostat.pp_parity_number, ostat.pp_algo, ostat.pp_domain);
	} else if (json) {
		dump_json(&ostat);
	} else {
		printf("EC encoding progress:\t\t%.2f%% (%lu/%lu)\n",
			ep, ostat.n_cm_zl_pp, ostat.n_cm_zl);
		if (ostat.n_cm_zl_pp) {
			printf("EC format:\t\t\t%d(D):%d(P):%d(A):%d(FD)\n",
				ostat.pp_data_number, ostat.pp_parity_number,
				ostat.pp_algo, ostat.pp_domain);
		}
		if (verify) {
			printf("Verification progress:\t\t%.2f%% (%lu/%lu)\n",
				vp, total_verified, total_chunks);
			if (ext) {
				printf("1VBR verify progress:\t\t%.2f%% (%lu/%lu)\n",
					vp1vbr, total_1vbr, total_chunks);
				uint64_t usage = vdev_usage_avg_get();
				printf("VDEVs usage (%u):\t\t%.5f%%\t\n",
					n_known_hosts, ((double)usage)/10000.0);
				printf("    \tTotal\t\tVerified\tLost\tERC err\n");
				printf("CM TL\t%lu\t\t%lu\t\t%lu\t\t%lu\n", ostat.n_cm_tl,
					ostat.n_cm_tl_verified, ostat.n_cm_tl_lost,
					ostat.n_cm_tl_erc_err);
				printf("CM ZL\t%lu\t\t%lu\t\t%lu\t\t%lu\n", ostat.n_cm_zl,
					ostat.n_cm_zl_verified, ostat.n_cm_zl_lost,
					ostat.n_cm_zl_erc_err);
				printf("CP  \t%lu\t\t%lu\t\t%lu\n", ostat.n_cp,
					ostat.n_cp_verified, ostat.n_cp_lost);
				if (p_info) {
					printf("PARITY \t%lu\t\t%lu\t\t%lu\n", ostat.n_cpar,
						ostat.n_cpar_verified, ostat.n_cpar_lost);
				}
			}
		}
	}
	if (known_hosts)
		je_free(known_hosts);
	ccow_tenant_term(cl);
	return 0;
}

