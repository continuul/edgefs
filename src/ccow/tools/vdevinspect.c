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
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <getopt.h>

#include "ccowutil.h"
#include "reptrans.h"

#define MAX_DEV 256
Logger lg;
struct enum_dev_arg {
	int n_dev;
	struct repdev **dev;
};

struct timeval g_start;
uint512_t *g_chid;
FILE * out;
void (*print_format)(double avg_read_lat, double avg_read_tpt,
    double avg_write_lat, double avg_write_tpt);

struct opt {
	char *cmd;
	char *dev_name;
	uint512_t chid;
	type_tag_t ttag;
	crypto_hash_t htype;
	unsigned int blob_size;
	unsigned int blob_num;
	int duration;
	int utilization;
	int skip_utilization;
	int rand_key_utilization;
	int ratio;
	unsigned int interval;
	int format;
} opt = {
	.ratio = 50,
	.utilization = 1,
	.interval = 1,
	.duration = 60,
	.blob_size = 8192,
	.blob_num = 0,
};

struct devinfo {
	struct repdev *dev;
	uint64_t hashcount_calc[HASHCOUNT_TAB_LENGTH + 1];
	pthread_t thread_id;
	int fix_hc;
	uint64_t chids_nr;	/* For stats */
};

static unsigned int g_util_blobs;

static void
usage() {
	printf("Usage: vdevinspect [OPTIONS]\n");
	printf("OPTIONS:\n");
	printf("	--help -q Help\n");
	printf("	[--dev-name | -d] Device name\n");
	printf("	--cmd	Command (hc | chc | dump | rtlat | nidump | nicheck | nifix | vcheck | vbrv)\n");
	printf("	--chid -c CHID\n");
	printf("	--type_tag -t TYPETAG\n");
	printf("	--hash_type -h HASH TYPE (deafult TT_CHUNK_PAYLOAD)\n");
	printf("	--blobsize -s BLOB SIZE (default 8k)\n");
	printf("	--blobnum -k Number of blobs to be processed (default use duration)\n");
	printf("	--duration -l Duration of benchmark in seconds (default 60)\n");
	printf("	--utilization -u Device utilization before start of benchmark (default 1)\n");
	printf("	--rwratio -r percent of read/write operations (default 50)\n");
	printf("	--interval -i interval in seconds between measurements (default 1)\n");
	printf("	--format -f Output format (csv) (default disabled)\n");
	printf("	--output -o file name\n");
}

static void
enum_dev__done_cb(struct repdev *dev, void *arg, int status)
{
	struct enum_dev_arg *da = (struct enum_dev_arg *)arg;
	if (status == 0)
		da->dev[da->n_dev++] = dev;
}

static int
dump_chunk_payload(struct repdev *dev, uint512_t *chid, crypto_hash_t htype)
{
	uint64_t attr;
	int err = reptrans_get_blob_ts(dev, TT_CHUNK_PAYLOAD, htype, chid, &attr);
	printf("Result: %d\n", err);
	if (err)
		return err;
	printf("Timestamp: %ld\n", attr);
	return 0;
}

static int
dump_chunk_manifest(struct repdev *dev, uint512_t *chid, crypto_hash_t htype)
{
	uint64_t attr;
	int err = reptrans_get_blob_ts(dev, TT_CHUNK_MANIFEST, htype, chid, &attr);
	printf("Result: %d\n", err);
	if (err)
		return err;
	printf("Timestamp: %ld\n", attr);

	rtbuf_t *rb;
	err = reptrans_get_blob(dev, TT_CHUNK_MANIFEST, htype, chid, &rb);
	if (err) {
		printf("Cannot read manifest\n");
		return err;
	}

	rtbuf_t *refs = NULL;
	err = replicast_unpack_cm_refs(rb, &refs, 0);
	if (err) {
		printf("Corrupted manifest\n");
		rtbuf_destroy(rb);
		return err;
	}

	for (size_t i = 0; i < refs->nbufs; ++i) {
		struct refentry *e = (struct refentry *)rtbuf(refs, i).base;
		uint8_t ref_ttag = ref_to_ttag[RT_REF_TYPE(e)];

		if (ref_ttag == TT_INVALID)
			continue;

		char nhidbuf[UINT512_BYTES * 2 + 1];
		char chidbuf[UINT512_BYTES * 2 + 1];
		uint512_dump(&e->name_hash_id, nhidbuf, UINT512_BYTES * 2 + 1);
		uint512_dump(&e->content_hash_id, chidbuf, UINT512_BYTES * 2 + 1);

		printf("NHID      : %s\n", nhidbuf);
		printf("CHID      : %s\n", chidbuf);
		printf("LENGTH    : %ld\n", e->length);
		printf("OFFSET    : 0x%lX\n", e->offset);
		printf("COMPLEN   : %ld\n", e->compressed_length);
		printf("REF_ATTR  : 0x%X\n", e->ref_attr);
		printf("\n");
	}

	rtbuf_destroy(rb);
	return 0;
}

static int
vbr_all_filter_cb(void *arg, void **data, size_t *size, int set) {
	return 1;
}

static int
dump_vbr(struct repdev *dev, uint512_t *chid, crypto_hash_t htype)
{
	int err;

	/* Extract VBRs */
	rtbuf_t *rb = NULL;
	err = reptrans_get_blobs(dev, TT_VERIFIED_BACKREF, htype, chid, &rb,
		0, vbr_all_filter_cb, NULL);
	printf("Result: %d\n", err);
	if (err < 0)
		return err;
	if (!rb)
		return -1;

	for (size_t n = 0; n < rb->nbufs; n++) {
		struct backref vbr;
		msgpack_u *u;

		u = msgpack_unpack_init(rtbuf(rb, n).base, rtbuf(rb, n).len, 0);
		err = reptrans_unpack_vbr(u, &vbr);
		msgpack_unpack_free(u);

		if (err) {
			printf("Warning: cannot unpack VBR: %d\n", err);
			continue;
		}

		char nhidbuf[UINT512_BYTES * 2 + 1];
		char refchidbuf[UINT512_BYTES * 2 + 1];
		uint512_dump(&vbr.name_hash_id, nhidbuf, UINT512_BYTES * 2 + 1);
		uint512_dump(&vbr.ref_chid, refchidbuf, UINT512_BYTES * 2 + 1);

		printf("NHID      : %s\n", nhidbuf);
		printf("GENID     : %ld\n", vbr.generation);
		printf("UVID_TS   : %ld\n", vbr.uvid_timestamp);
		printf("REP_COUNT : %d\n", vbr.rep_count);
		printf("REF_CHID  : %s\n", refchidbuf);
		printf("REF_TYPE  : %s\n", type_tag_name[vbr.ref_type]);
		printf("REF_HASH  : %s\n", hash_type_name[vbr.ref_hash]);
		printf("ATTR      : %lX\n", vbr.attr);
		printf("\n");
	}
	return 0;
}

int dump(struct repdev *dev) {
	int err = -EINVAL;

	if ((uint512_cmp(&opt.chid, &uint512_null) == 0) || !opt.ttag || !opt.htype) {
		fprintf(stderr, "Expecting: dump <CHID> <TYPE_TAG> <HASH_TYPE>\n");
		usage();
		goto _exit;
	}

	uint512_t chid = opt.chid;
	type_tag_t ttag = opt.ttag;
	crypto_hash_t htype = opt.htype;
	int p, i, id = 0;

	if (ttag == TT_CHUNK_PAYLOAD) {
		err = dump_chunk_payload(dev, &chid, htype);
		goto _exit;
	} else if (ttag == TT_CHUNK_MANIFEST) {
		err = dump_chunk_manifest(dev, &chid, htype);
		goto _exit;
	} else if (ttag == TT_VERIFIED_BACKREF) {
		err = dump_vbr(dev, &chid, htype);
		goto _exit;
	} else
		fprintf(stderr, "Wrong TYPE_TAG\n");
_exit:
	return err;
}

int printf_rate_limit(int interval, const char *format, ...)
{
	static uint64_t ival = 0;
	static uint64_t before = 0, after = 0;
	int ret = 0;
	va_list args;
	va_start(args, format);

	after = uv_hrtime();
	ival += after - before;
	before = uv_hrtime();

	if (ival > (interval * 1e9)) {
		vprintf(format, args);
		ival = 0;
		ret = 1;
	}
	va_end(args);
	return ret;
}

int utilization(struct repdev *dev) {
	char bar[] = {'|', '/', '-', '\\'};
	int err = 0;
	unsigned int k = 1;
	rtbuf_t *rb = rtbuf_init_alloc_one(opt.blob_size);
	if (rb == NULL) {
		fprintf(stderr, "No memory\n");
		err = -ENOMEM;
		return err;
	}
	memset(rtbuf(rb, 0).base, 0, opt.blob_size);
	for (unsigned int i = 0; err == 0 && i < g_util_blobs; ++i) {
		((uint32_t *)rtbuf(rb, 0).base)[0] = g_start.tv_usec + i;
		((uint32_t *)rtbuf(rb, 0).base)[1] = g_start.tv_sec;
		uint64_t attr = -1;
		err = reptrans_put_blob_with_attr(dev,
				TT_CHUNK_PAYLOAD, HASH_TYPE_XXHASH_256, rb, &g_chid[i], 0, attr);
		if (printf_rate_limit(1, "\rUtilization target %d%%/%u... written %d blobs %c",
			    opt.utilization, g_util_blobs, i, bar[k % 4]))
			k++;
	}
	if (err) {
		fprintf(stderr, "reptrans_put_blob failed %d\n", err);
		goto _exit;
	}
_exit:
	rtbuf_destroy(rb);
	return err;
}

void default_print(double avg_read_lat, double avg_read_tpt,
    double avg_write_lat, double avg_write_tpt)
{
	fprintf(out,"Read latency %.6fs (TpT %.2fMB/s) Write latency %.6fs (TpT %.2fMB/s) \n",
	    avg_read_lat, avg_read_tpt, avg_write_lat, avg_write_tpt);
	fflush(out);
}

void csv_print(double avg_read_lat, double avg_read_tpt,
    double avg_write_lat, double avg_write_tpt) {
	fprintf(out,"%.5f,%.2f,%.5f,%.2f", avg_read_lat, avg_read_tpt,
	    avg_write_lat, avg_write_tpt);
	fflush(out);
}

struct avg_ring avg_read_lat;
struct avg_ring avg_write_lat;

int rtlat(struct repdev *dev) {
	int err = 0;
	unsigned int num_blobs_write, num_blobs_read, num_blobs_util;
	unsigned int period_num_blobs = 100;
	uint64_t duration = 0;
	unsigned int p = 1, i;
	uint64_t avg_rl = 0, avg_wl = 0;

	num_blobs_read = period_num_blobs * opt.ratio / 100;
	num_blobs_write = period_num_blobs - num_blobs_read;

	duration = opt.duration * 1e9;

	rtbuf_t *get_rb;
	rtbuf_t *put_rb = rtbuf_init_alloc_one(opt.blob_size);
	if (put_rb == NULL) {
		fprintf(stderr, "No memory\n");
		err = -ENOMEM;
		goto _exit;
	}
	memset(rtbuf(put_rb, 0).base, 0, opt.blob_size);

	printf("\nStarting benchmark\n");
	uint64_t interval = 0;
	while(opt.blob_num || duration) {
		uint64_t before = uv_hrtime();

		for (i = 0; err == 0 && i < num_blobs_read; i++) {
			uint64_t start = uv_hrtime();
			err = reptrans_get_blob(dev, TT_CHUNK_PAYLOAD, HASH_TYPE_XXHASH_256,
			    &g_chid[p++], &get_rb);
			uint64_t lat = (uv_hrtime() - start);
			avg_rl = avg_ring_update(&avg_read_lat, lat / 1000);

			if (!err)
				rtbuf_destroy(get_rb);
		}
		if (err) {
			fprintf(stderr, "reptrans_get_blob %d failed %d\n", p, err);
			goto _exit;
		}

		for (i = 0; err == 0 && i < num_blobs_write; i++) {
			((uint32_t *)rtbuf(put_rb, 0).base)[0] = g_start.tv_usec + p;
			((uint32_t *)rtbuf(put_rb, 0).base)[1] = g_start.tv_sec;
			uint64_t start = uv_hrtime();
			uint64_t attr = -1;
			err = reptrans_put_blob_with_attr(dev, TT_CHUNK_PAYLOAD,
			    HASH_TYPE_XXHASH_256, put_rb, &g_chid[p++], 0, attr);
			uint64_t lat = (uv_hrtime() - start);
			avg_wl = avg_ring_update(&avg_write_lat, lat / 1000);
		}
		if (err) {
			fprintf(stderr, "reptrans_put_blob failed %d\n", err);
			goto _exit;
		}

		uint64_t read = (uv_hrtime() - before);
		uint64_t written = opt.blob_size * period_num_blobs;
		interval += read;
		if (opt.interval && ((interval / 1e9) > opt.interval)) {
			printf("\r");
			print_format((1.0 * avg_rl) / 1e6, (1.0 * opt.blob_size) / (avg_rl / 1e6) / 1024 / 1024 ,
			    (1.0 * avg_wl) / 1e6, (1.0 * opt.blob_size) / (avg_wl / 1e6) / 1024 / 1024 );
			interval = 0;
		}

		opt.blob_num = (opt.blob_num < period_num_blobs) ? 0 : opt.blob_num - period_num_blobs;
		duration = (read < duration) ? duration - read : 0;
	}

	fflush(out);
	printf("End of benchmark\n");
_exit:
	if (put_rb)
		rtbuf_destroy(put_rb);
	return err;

}

static void
check_chid_hc(struct devinfo *dinfo, type_tag_t ttag, uint512_t *chid)
{
	char keystr[UINT512_BYTES*2+1];
	uint16_t hashkey = HASHCALC(chid, HASHCOUNT_MASK);
	struct repdev *dev = dinfo->dev;

	dinfo->hashcount_calc[hashkey]++;
	dinfo->chids_nr++;

	if (dev->stats.hashcount[hashkey] == 0) {
		uint512_dump(chid, keystr, UINT512_BYTES*2+1);
		fprintf(stderr, "Dev(%s) hc[%u] isn't set for CHID %s TYPE %s\n",
			dev->name, hashkey, keystr, type_tag_name[ttag]);
	}
}

static int
hc_check_cb(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *chid, uv_buf_t *val, void *param)
{
	struct devinfo *dinfo = (struct devinfo *)param;

	assert(dinfo->dev == dev);
	check_chid_hc(dinfo, ttag, chid);
	return 0;
}

void *
dev_check_hc(void *arg)
{
	int err, changed = 0;
	struct devinfo *dinfo = (struct devinfo *)arg;
	struct repdev *dev = dinfo->dev;

	type_tag_t ttags[] = {TT_CHUNK_PAYLOAD, TT_CHUNK_MANIFEST, TT_NAMEINDEX};
	for (size_t i = 0; i < sizeof(ttags)/sizeof(ttags[0]); i++) {
		err = reptrans_iterate_blobs(dinfo->dev, ttags[i],
					hc_check_cb, (void *)dinfo, 0);
		if (err) {
			fprintf(stderr, "Error (%d) while reading device %s\n",
					err, dinfo->dev->name);
			break;
		}
	}
	for (int n = 0; n < HASHCOUNT_TAB_LENGTH; n++) {
		if (dinfo->hashcount_calc[n] != dev->stats.hashcount[n]) {
			fprintf(stderr, "Dev(%s) hc[%u]: %lu vs %lu (calc)\n",
				dev->name, n, dev->stats.hashcount[n],
				dinfo->hashcount_calc[n]);
			if (dinfo->fix_hc) {
				changed = 1;
				dev->stats.hashcount[n] =
					dinfo->hashcount_calc[n];
				fprintf(stderr, "Dev(%s) resetting "
						"hc[%u]: %lu\n",
						dev->name, n,
						dev->stats.hashcount[n]);
			}
		}
	}
	if (dinfo->fix_hc && changed) {
		dev->hc_flush = 1;
		err = reptrans_put_hashcount(dev);
		if (err)
			fprintf(stderr, "Dev(%s) failed to write corrected"
					" hashcount - err %d\n",
					dev->name, err);
		else
			fprintf(stderr, "Dev(%s) write of corrected"
					" hashcount  successful\n",
					dev->name);
		changed = 0;
	}
	printf("Dev(%s): verified %lu blobs\n", dev->name, dinfo->chids_nr);
	return 0;
}

static int
threaded_check_hc(struct repdev **devices, int n_dev, int fix_hc)
{
	int thr_nr, err;
	void *res;
	struct devinfo *dinfo;

	dinfo = je_calloc(n_dev, sizeof (*dinfo));
	if (!dinfo) {
		fprintf(stderr, "Ran out of memory\n");
		return -ENOMEM;
	}

	for (thr_nr = 0; thr_nr < n_dev; thr_nr++) {
		err = pthread_create(&dinfo[thr_nr].thread_id, NULL,
				     dev_check_hc, &dinfo[thr_nr]);
		if (err) {
			fprintf(stderr, "Failed to start threads\n");
			exit(-1);
		}
		dinfo[thr_nr].fix_hc = fix_hc;
		dinfo[thr_nr].dev = devices[thr_nr];
	}
	for (thr_nr = 0; thr_nr < n_dev; thr_nr++) {
		err = pthread_join(dinfo[thr_nr].thread_id, &res);
		if (err) {
			fprintf(stderr, "Thread for dev %s failed with "
					"error %s\n",
					dinfo[thr_nr].dev->name, (char *)res);
			exit(-1);
		}
	}
	return 0;
}

struct nicheck_arg {
	int fix;
	size_t n_checked;
	size_t n_fixed;
};

static int
nameindex_check_cb(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *key, uv_buf_t *val, void *param) {

	char nhidstr[UINT512_BYTES*2+1];
	char chidstr[UINT512_BYTES*2+1];
	struct nicheck_arg* arg = param;
	struct vlentry vle;
	msgpack_u u;

	arg->n_checked++;
	uint512_dump(key, nhidstr, UINT512_BYTES*2+1);
	msgpack_unpack_init_b(&u, val->base, val->len, 0);

	int err = replicast_unpack_vlentry(&u, &vle);
	if (err) {
		fprintf(stderr, "Cannot decode version entry %lX: %d", key->u.u.u, err);
		return 0;
	}

	uint512_dump(&vle.content_hash_id, chidstr, UINT512_BYTES*2+1);

	struct blob_stat bstat = {0};
	err = reptrans_blob_stat(dev, TT_VERSION_MANIFEST, HASH_TYPE_DEFAULT,
		&vle.content_hash_id, &bstat);
#if 0
	static int del_cnt = 0;
	if (!err && ((++del_cnt % 10) == 0)) {
		reptrans_delete_blob(dev, TT_VERSION_MANIFEST, HASH_TYPE_DEFAULT,
			&vle.content_hash_id);
		err = reptrans_blob_stat(dev, TT_VERSION_MANIFEST, HASH_TYPE_DEFAULT,
			&vle.content_hash_id, &bstat);
	}
#endif
	if (err && bstat.size == 0) {
		arg->n_fixed++;
		if (arg->fix != 0) {
			err = reptrans_delete_blob_value(dev, ttag, hash_type, key, val, 1);
			if (err) {
				fprintf(stderr, "ERROR: Dev(%s) error while "
					"deleting vlentry for NHID %s GEN %lu\n",
					dev->name, nhidstr, vle.generation);
			} else {
				fprintf(stdout, "INFO: Dev(%s) removed orphaned "
					"vlentry NHID %s GEN %lu VM CHID %s\n",
					dev->name, nhidstr, vle.generation, chidstr);
			}
		} else {
			fprintf(stderr, "ERROR: Dev(%s) cannot find a VM %s for "
				"NHID %s GEN %lu\n", dev->name, chidstr, nhidstr,
				vle.generation);
		}
	} else {
#if 0
		fprintf(stdout, "INFO: Dev(%s) found a VM CHID %s for "
			"vlentry NHID %s GEN %lu\n", dev->name, chidstr,
			nhidstr, vle.generation);
#endif
	}
	return 0;
}


static void
nameindex_check(struct enum_dev_arg* arg, int nifix) {
	struct nicheck_arg cb_arg = { .fix = nifix };
	for (int i = 0; i < arg->n_dev; i++) {
		struct repdev* dev = arg->dev[i];
		assert(dev);
		int err = reptrans_iterate_blobs(dev, TT_NAMEINDEX,
			nameindex_check_cb, &cb_arg, 1);
	}
	if (nifix) {
		fprintf(stdout, "Verified %lu nameindex entries, "
			"removed %lu entries without a VM\n", cb_arg.n_checked,
			cb_arg.n_fixed);
	} else {
		fprintf(stdout, "Verified %lu nameindex entries, "
			"found %lu entries without a VM\n", cb_arg.n_checked,
			cb_arg.n_fixed);
	}
}

struct vbr_check_arg {
	size_t n_checked;
	size_t n_orhans;
	size_t n_vbrs_total;
};

static int
vbr_check_cb(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *key, uv_buf_t *val, void *param) {

	struct vbr_check_arg* cb_arg = param;
	size_t count = 0;
	int err = reptrans_get_depcount_coarse(dev, TT_VERIFIED_BACKREF, HASH_TYPE_DEFAULT,
		key, ~0, &count);
	cb_arg->n_checked++;
	if (!count || err) {
		cb_arg->n_orhans++;
	} else if (ttag == TT_CHUNK_PAYLOAD) {
		size_t size = val ? val->len : 0;
		printf("Dev(%s) chunk %s %016lX size %lu has %lu VBRs\n", dev->name,
			type_tag_name[ttag], key->u.u.u, size, count);
		cb_arg->n_vbrs_total += count;
	}
	return 0;
}

static void
vbr_check(struct enum_dev_arg* arg) {
	struct vbr_check_arg cb_arg = {.n_checked = 0, .n_orhans = 0 };
	for (int i = 0; i < arg->n_dev; i++) {
		struct repdev* dev = arg->dev[i];
		assert(dev);
		int err = reptrans_iterate_blobs(dev, TT_VERSION_MANIFEST,
			vbr_check_cb, &cb_arg, 0);
		if (err)
			printf("TT_VERSION_MANIFEST iterate error %d\n", err);
		err = reptrans_iterate_blobs(dev, TT_CHUNK_MANIFEST,
			vbr_check_cb, &cb_arg, 0);
		if (err)
			printf("TT_CHUNK_MANIFEST iterate error %d\n", err);
		err = reptrans_iterate_blobs(dev, TT_CHUNK_PAYLOAD,
			vbr_check_cb, &cb_arg, 1);
		if (err)
			printf("TT_CHUNK_PAYLOAD iterate error %d\n", err);
	}
	printf("Processed %lu chunks, found %lu (%lu%%) VBRs\n",
		cb_arg.n_checked, cb_arg.n_orhans,
		cb_arg.n_checked ? cb_arg.n_orhans*100/cb_arg.n_checked : 0);
}

struct nidump_cb_arg {
	FILE* out;
	int n_iters;
};

static int
nameindex_dump_cb(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *key, uv_buf_t *val, void *param) {
	struct nidump_cb_arg* arg = param;
	FILE* out = arg->out;;
	char str[UINT512_BYTES*2+1];

	struct vlentry vle;
	struct vmmetadata md;
	msgpack_u u;
	int skip_json = out == stdout;


	msgpack_unpack_init_b(&u, val->base, val->len, 0);

	int err = replicast_unpack_vlentry(&u, &vle);
	if (err) {
		fprintf(stderr, "Cannot decode version entry %lX: %d", key->u.u.u, err);
		return 0;
	}

	if (vle.object_deleted)
		return 0;

	struct blob_stat vm_bstat = {0};
	err = reptrans_blob_stat(dev, TT_VERSION_MANIFEST, HASH_TYPE_DEFAULT,
		&vle.content_hash_id, &vm_bstat);
	if (vm_bstat.size) {
		rtbuf_t* rb = NULL;
		err = reptrans_get_blob(dev, TT_VERSION_MANIFEST, HASH_TYPE_DEFAULT,
			&vle.content_hash_id, &rb);
		if (err) {
			uint512_dump(&vle.content_hash_id, str, UINT512_BYTES*2+1);
			fprintf(stderr, "Dev(%s) error getting VM %s: %d",
				dev->name, str, err);
			vm_bstat.size = 0;
		} else {
			err = replicast_get_metadata(rb, &md);
			if (err) {
				uint512_dump(&vle.content_hash_id, str, UINT512_BYTES*2+1);
				fprintf(stderr, "Dev(%s) error unpack VM %s: %d",
					dev->name, str, err);
				vm_bstat.size = 0;
			}
			rtbuf_destroy(rb);
		}
	}

	if (skip_json) {
		if (md.cid_size) {
			fwrite(md.cid, 1, md.cid_size-1, out);
		}
		fprintf(out, "/");

		if (md.tid_size) {
			fwrite(md.tid, 1, md.tid_size-1, out);
		}
		fprintf(out, "/");

		if (md.bid_size) {
			fwrite(md.bid, 1, md.bid_size-1, out);
		}
		fprintf(out, "/");
		if (md.oid_size) {
			fwrite(md.oid, 1, md.oid_size-1, out);
		}
		fprintf(out, "\n");
		return 0;
	}

	int n_vbrs = retrans_count_vbrs_all_repcount(dev, &vle.content_hash_id,
		HASH_TYPE_DEFAULT, NULL, 0, NULL, 1);

	uint512_dump(key, str, UINT512_BYTES*2+1);
	fprintf(out, "{\"nhid\":\"%s\", \"uvid_timestamp\": %lu,", str, vle.uvid_timestamp);
	uint128_dump(&vle.uvid_src_guid, str, UINT128_BYTES*2+1);
	fprintf(out, "\"uvid_src_guid\":\"%s\",\"uvid_src_cookie\": %u,", str, vle.uvid_src_cookie);
	uint512_dump(&vle.content_hash_id, str, UINT512_BYTES*2+1);
	fprintf(out, "\"generation\": %lu, \"content_hash_id\":\"%s\",", vle.generation, str);
	fprintf(out, "\"logical_size\": %lu,\"object_deleted\": %u,\"vm_packed_length\": %u,",
		vle.logical_size, vle.object_deleted, vle.vm_packed_length);
	fprintf(out, "\"has_vm\": %s, \"has_vbr\": %s",
		(vm_bstat.size ? "true" : "false"),
		(n_vbrs ? "true" : "false"));
	if (vm_bstat.size) {
		fprintf(out, ",\"tid\": \"");
		if (md.tid_size) {
			fwrite(md.tid, 1, md.tid_size-1, out);
		}

		fprintf(out, "\", \"cid\": \"");
		if (md.cid_size) {
			fwrite(md.cid, 1, md.cid_size-1, out);
		}

		fprintf(out, "\", \"bid\": \"");
		if (md.bid_size) {
			fwrite(md.bid, 1, md.bid_size-1, out);
		}

		fprintf(out, "\" ,\"oid\": \"");
		if (md.oid_size) {
			fwrite(md.oid, 1, md.oid_size-1, out);
		}
		fprintf(out, "\"},\n");
	} else {
		fprintf(out, "},\n");
	}
	arg->n_iters++;
	usleep(100);
	return 0;
}

static void
nameindex_dump(struct enum_dev_arg* arg, FILE* out) {
	struct nidump_cb_arg cb_arg = { .out = out, .n_iters = 0 };
	int skip_json = out == stdout;
	if (!skip_json)
		fprintf(out, "[\n");
	for (int i = 0; i < arg->n_dev; i++) {
		struct repdev* dev = arg->dev[i];
		assert(dev);
		if (!skip_json)
			fprintf(out, "{\"vdev\": \"%s\",\"nameindex\":[\n", dev->name);
		int err = reptrans_iterate_blobs(dev, TT_NAMEINDEX,
			nameindex_dump_cb, &cb_arg, 1);
		if (!skip_json && cb_arg.n_iters) {
			err = fseek(out, -2, SEEK_CUR);
			if (err)
				printf("fseek error: %d\n", err);
		}
		if (!skip_json) {
			fprintf(out, "\n]}");
			if (i < arg->n_dev - 1)
				fprintf(out, ",\n");
		}
	}
	if (!skip_json)
		fprintf(out, "]\n");
}

static int
transport_autodetect(char **out)
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccowd.json", nedge_path());
	int fd = open(path, O_RDONLY);
	if (fd == -1) {
		return -errno;
	}
	char buf[16384];
	int len = read(fd, buf, 16384);
	if (len == -1) {
		close(fd);
		return -errno;
	}
	close(fd);
	json_value *ccowd = json_parse(buf, len);

	if (!ccowd)
		return -1;

	json_value *transport = NULL;
	for (unsigned i = 0; i < ccowd->u.object.length; i++) {
		if (strncmp(ccowd->u.object.values[i].name,
						   "transport", 9) == 0) {
			json_value *v = ccowd->u.object.values[i].value;
			if (v->type != json_array) {
				log_error(lg, "Syntax error: transport is "
						"not an array: -EINVAL");
				return -EINVAL;
			}
			transport = v;
			break;
		}
	}
	if (!transport || !transport->u.array.length)
		return -EINVAL;
	if (transport->u.array.length > 1)
		return -EINVAL;
	json_value *v = transport->u.array.values[0];
	if (v->type != json_string)
		return -EINVAL;

	*out = je_strdup(v->u.string.ptr);
	json_value_free(ccowd);
	return 0;
}

struct mfix_arg {
	size_t n_checked;
	size_t n_removed;
};

static int
manifest_fix_cb(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *key, uv_buf_t *val, void *param) {

	struct mfix_arg* arg = param;
	uint512_t hash_id = uint512_null;
	char chidstr[UINT512_BYTES*2+1];

	rtbuf_t* rb = rtbuf_init_mapped(val, 1);
	if (!rb) {
		printf("rtbuf allocation error\n");
		return 0;
	}
	int err = rtbuf_hash(rb, hash_type, &hash_id);
	if (err) {
		uint512_dump(key, chidstr, UINT512_BYTES*2+1);
		printf("Dev(%s) %s ttag %s hashID calculation error\n",
			dev->name, chidstr, type_tag_name[ttag]);
		return 0;
	}
	arg->n_checked++;

	if (uint512_cmp(key, &hash_id)) {
		uint512_dump(key, chidstr, UINT512_BYTES*2+1);
		int md_corrupted = 0;
		int refs_corrupted = 0;
		rtbuf_t* refs = NULL;

		arg->n_removed++;

		if (ttag == TT_VERSION_MANIFEST) {
			struct vmmetadata md;
			err = replicast_get_metadata(rb, &md);
			if (err)
				md_corrupted = 1;
		}

		if (ttag == TT_CHUNK_MANIFEST)
			err = replicast_unpack_cm_refs(rb, &refs, 0);
		else
			err = replicast_get_refs(rb, &refs, 0);
		if (err)
			refs_corrupted = 1;

		if (refs)
			rtbuf_destroy(refs);

		printf("Dev(%s) %s ttag %s hash_type %s hashID "
			"verification error %s %s, removing\n", dev->name, chidstr,
			type_tag_name[ttag], hash_type_name[hash_type],
			(md_corrupted ? ", corrupted md" : ""),
			(refs_corrupted ? ", corrupted refs" : ""));


		/* Remove the manifest */
		err = reptrans_delete_blob(dev, ttag, hash_type, key);
		if (!err) {
			struct blob_stat bstat =  { .size = 0 };
			/* Remove also parity manifest (if exists) */
			err = reptrans_blob_stat(dev, TT_PARITY_MANIFEST, hash_type,
				key, &bstat);
			if (!err && bstat.size > 0) {
				err = reptrans_delete_blob(dev, TT_PARITY_MANIFEST,
					hash_type, key);
				if (!err)
					printf("Dev(%s) removed parity manifest %s\n",
						dev->name, chidstr);
				else
					printf("Dev(%s) ERROR removing parity manifest %s\n",
						dev->name, chidstr);
			} else
				err = 0;
			rtbuf_t* vbr_rb = NULL;
			err = reptrans_get_blobs(dev, TT_VERIFIED_BACKREF, hash_type,
				key, &vbr_rb, 0, vbr_all_filter_cb, NULL);
			if (!err && vbr_rb) {
				err = reptrans_delete_blob_value(dev, TT_VERIFIED_BACKREF,
					hash_type, key, vbr_rb->bufs, vbr_rb->nbufs);
				if (!err)
					printf("Dev(%s) removed %lu VBRs for %s\n",
						dev->name, vbr_rb->nbufs, chidstr);
				else
					printf("Dev(%s) ERROR removing %lu VBRs for %s: %d\n",
						dev->name, vbr_rb->nbufs, chidstr, err);
				rtbuf_destroy(vbr_rb);
			}
		} else {
			printf("Dev(%s) ERROR deleting %s %s\n", dev->name, chidstr,
				type_tag_name[ttag]);
		}
	}
	rtbuf_destroy(rb);
	return 0;
}

static void
manifest_check_and_fix(struct enum_dev_arg* arg) {
	struct mfix_arg cb_arg = {0};
	for (int i = 0; i < arg->n_dev; i++) {
		struct repdev* dev = arg->dev[i];
		assert(dev);

		int err = reptrans_iterate_blobs(dev, TT_VERSION_MANIFEST,
			manifest_fix_cb, &cb_arg, 1);
		if (err) {
			printf("Iterator returned a error %d, exiting", err);
			exit(err);
		}
		err = reptrans_iterate_blobs(dev, TT_CHUNK_MANIFEST,
				manifest_fix_cb, &cb_arg, 1);
		if (err) {
			printf("Iterator returned a error %d, exiting", err);
			exit(err);
		}
	}
	printf("Checked %lu manifests, removed %lu\n", cb_arg.n_checked,
		cb_arg.n_removed);
}

struct mvmni_arg {
	size_t total;
	size_t no_ni;
	size_t errs;
	uint64_t genid_max;
};

static int
manifest_vs_ni_cb(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *key, uv_buf_t *val, void *param) {

	struct mvmni_arg* arg = param;
	uint512_t hash_id = uint512_null;
	struct vmmetadata md;
	char chidstr[UINT512_BYTES*2+1];
	uint512_dump(key, chidstr, UINT512_BYTES*2+1);

	rtbuf_t* rb = rtbuf_init_mapped(val, 1);
	if (!rb) {
		printf("rtbuf allocation error\n");
		return 0;
	}
	arg->total++;
	int err = replicast_get_metadata(rb, &md);
	if (err) {
		printf("VM %s get metadata error %d\n", chidstr, err);
		arg->errs++;
		return 0;
	}

	struct vlentry query = {
		.uvid_timestamp = ~0ULL,
		.generation =  md.txid_generation
	};

	rtbuf_t* rb_vers = NULL;
	err = reptrans_get_versions(dev, &md.nhid, &query,
		&rb_vers);

	if ((err || !rb_vers) && (md.txid_generation <= arg->genid_max) &&
		strlen(md.oid) && memcmp_quick(md.oid, md.oid_size, "marker", 7) &&
		!strstr(md.tid, "TRLOG")) {
		char oname[2048];
		sprintf(oname, "%s/%s/%s/%s", md.cid, md.tid, md.bid, md.oid);
		printf("Dev(%s) found a VM %s object %s gen %lu without a version\n",
			dev->name, chidstr, oname, md.txid_generation);
		arg->no_ni++;
	}
	if (rb_vers)
		rtbuf_destroy(rb_vers);
	if (rb)
		rtbuf_destroy(rb);
	return 0;
}


static void
manifest_vs_ni_check(struct enum_dev_arg* arg, uint64_t genid_max) {
	struct mvmni_arg cb_arg = {0};
	cb_arg.genid_max = genid_max;
	for (int i = 0; i < arg->n_dev; i++) {
		struct repdev* dev = arg->dev[i];
		assert(dev);

		int err = reptrans_iterate_blobs(dev, TT_VERSION_MANIFEST,
			manifest_vs_ni_cb, &cb_arg, 1);
		if (err) {
			printf("Iterator returned a error %d, exiting", err);
			exit(err);
		}
	}
	printf("Checked %lu VMs, found %lu without NI\n", cb_arg.total,
		cb_arg.no_ni);
}

int
main(int argc, char* argv[])
{
	int err = 0;
	struct repdev *devices[MAX_DEV];
	struct enum_dev_arg enum_arg = {0, devices};
	char *tr_str = "rtrd";
	struct timeval tv_start, tv_end;
	time_t check_secs;
	suseconds_t check_usecs = 0;
	uint64_t genid = 1;

	out = stdout;
	print_format = &default_print;

	while (1) {
		int option_index = 0;
		int c;
		static struct option long_options[] = {
			{"help",	0,		0,  'h' },
			{"dev-name", required_argument, 0,  'd' },
			{"cmd", required_argument, 0,  0 },
			{"chid", required_argument, 0,  'c' },
			{"type_tag", required_argument, 0,  't' },
			{"hash_type", required_argument, 0,  'H' },
			{"blobsize", required_argument, 0,  's' },
			{"blobnum", required_argument, 0,  'k' },
			{"skip-utilization", no_argument, 0, 'S' },
			{"rand-key-utilization", no_argument, 0, 'K' },
			{"duration", required_argument, 0,  'l' },
			{"utilization", required_argument, 0,  'u' },
			{"rwratio", required_argument, 0,  'r' },
			{"interval", required_argument, 0,  'i' },
			{"format", required_argument, 0,  'f' },
			{"output", required_argument, 0,  'o' },
			{"gen", required_argument, 0,  'g' },
			{0,         0,	                 0,  0 }
		};

		c = getopt_long(argc, argv, "hd:c:t:H:s:k:l:u:r:i:f:o:ST:g:",
				long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
			case 0:
				opt.cmd = optarg;
				break;
			case 'd':
				opt.dev_name = optarg;
				break;
			case 'c':
				{
					uint512_t tmp_chid;
					uint512_fromhex(optarg, UINT512_BYTES * 2 + 1, &tmp_chid);
					opt.chid = tmp_chid;
				}
				break;
			case 't':
				{
					type_tag_t ttag = TT_LAST;
					for (int i = TT_NAMEINDEX; i < TT_LAST; ++i) {
						if (!strncmp(optarg, type_tag_name[i],
									strlen(type_tag_name[i]))) {
							ttag = (type_tag_t)i;
							break;
						}
					}
					if (ttag == TT_LAST) {
						fprintf(stderr, "Wrong TYPETAG %s\n", optarg);
						usage();
						return -EINVAL;
					}
					opt.ttag = ttag;
				}
				break;
			case 'H':
				{
					crypto_hash_t htype = HASH_TYPE_END;
					for (int i = HASH_TYPE_DEFAULT; i < HASH_TYPE_END; ++i) {
						if (!strncmp(optarg, hash_type_name[i],
									strlen(hash_type_name[i]))) {
							htype = (crypto_hash_t)i;
							break;
						}
					}
					if (htype == HASH_TYPE_END) {
						fprintf(stderr, "Wrong HASHTYPE %s\n", optarg);
						usage();
						return -EINVAL;
					}
					opt.htype = htype;
				}
				break;
			case 's':
				opt.blob_size = atol(optarg);
				break;

			case 'g':
				genid = atol(optarg);
				break;

			case 'k':
				opt.blob_num = atol(optarg);
				break;
			case 'S':
				opt.skip_utilization = 1;
				break;
			case 'K':
				opt.rand_key_utilization = 1;
				break;
			case 'u':
				opt.utilization = atol(optarg);
				break;
			case 'r':
				opt.ratio = atol(optarg);
				break;
			case 'i':
				opt.interval = atol(optarg);
				break;
			case 'l':
				opt.duration = atol(optarg);
				break;
			case 'f':
				if (strcmp("csv", optarg) == 0)
					print_format = &csv_print;
				break;
			case 'o':
				out = fopen (optarg, "w+");
				if (!out) {
					fprintf(stderr, "fopen error\n");
					exit(-1);
				}
				break;
			case '?':
			case 'h':
				usage();
				exit(0);
				break;
			default:
				fprintf(stderr, "cmdline parse error\n");
				exit(-1);
		}
	}
	if (!opt.cmd) {
		fprintf(stderr, "Invalid command\n");
		usage();
		return -1;
	}

	int is_hc_check = !strcmp(opt.cmd, "hc");
	int fix_hc = !strcmp(opt.cmd, "chc");
	int version_check = !strcmp(opt.cmd, "vcheck");
	int nicheck = !strcmp(opt.cmd, "nicheck");
	int nifix = !strcmp(opt.cmd, "nifix");
	int nidump = !strcmp(opt.cmd, "nidump");
	int mfix = !strcmp(opt.cmd, "mfix");
	int vbrv = !strcmp(opt.cmd, "vbrv");
	int mvsni = !strcmp(opt.cmd, "mvsni");
	if (!opt.dev_name && !is_hc_check && !fix_hc && !version_check && !nicheck && !nifix && !nidump && !mfix && !vbrv && !mvsni) {
		fprintf(stderr, "Invalid dev name\n");
		usage();
		return -1;
	}

	lg = Logger_create("reptrans");
	if (!lg) {
		fprintf(stderr, "Logger create error\n");
		return -1;
	}


	int flags = RT_FLAG_STANDALONE;
	if (version_check) {
		flags |= RT_FLAG_VERSION_CHECK;
	} else if (fix_hc) {
		// FIXME: check to disallow run while ccow-daemon is running
	} else if (!nicheck && !nifix && !mfix){
		flags |= RT_FLAG_RDONLY;
	}

	char *transport[1] = { 0 };
	err = transport_autodetect(&transport[0]);
	if (err) {
		fprintf(stderr, "Cannot autodetect ccowd.json transport: %d\n", err);
		usage();
		return -1;
	}
	err =  reptrans_init(0, NULL, NULL, flags, 1,
	    (char**)transport, NULL);
	if (err <= 0) {
		fprintf(stderr, "Cannot initiailze reptrans: %d\n", err);
		usage();
		return -1;
	}
	je_free(transport[0]);

	if (version_check)
		goto _exit;

	err = reptrans_enum(NULL, &enum_arg, enum_dev__done_cb, 0);
	if (err) {
		fprintf(stderr, "Cannot enumerate reptrans: %d\n", err);
		usage();
		goto _exit;
	}

	if (mvsni) {
		manifest_vs_ni_check(&enum_arg, genid);
		goto _exit;
	}

	if (vbrv) {
		vbr_check(&enum_arg);
		goto _exit;
	}
	if (nicheck || nifix) {
		/* Iterate nameindex and remove ones without corresponding VMs */
		nameindex_check(&enum_arg, nifix);
		goto _exit;
	}

	if (mfix) {
		manifest_check_and_fix(&enum_arg);
		goto _exit;
	}

	if (nidump) {
		nameindex_dump(&enum_arg, out);
		fclose(out);
		goto _exit;
	}


	if (is_hc_check || fix_hc) {
		gettimeofday(&tv_start, NULL);
		threaded_check_hc(devices, enum_arg.n_dev, fix_hc);
		gettimeofday(&tv_end, NULL);
		check_secs = tv_end.tv_sec - tv_start.tv_sec;
		if (tv_end.tv_usec > tv_start.tv_usec)
			check_usecs = tv_end.tv_usec - tv_start.tv_usec;
		printf("Time for verification/fixing %lu sec %lu usec\n",
			check_secs, check_usecs);
		goto _exit;
	}

	int i;
	for (i = 0; i < enum_arg.n_dev; i++) {
		if (strcmp(opt.dev_name, devices[i]->name) == 0)
		    break;
	}
	if (i == enum_arg.n_dev) {
		fprintf(stderr, "Devname %s not found\n", opt.dev_name);
		usage();
		err = -EINVAL;
		goto _exit;
	}
	struct repdev *dev = devices[i];

	if (strcmp(opt.cmd, "dump") == 0) {
		dump(dev);
	} else if (strcmp(opt.cmd, "rtlat") == 0) {
		g_util_blobs = (dev->stats.physical_capacity * opt.utilization / 100 / opt.blob_size);
		g_chid = je_calloc(g_util_blobs, sizeof(uint512_t));
		if (!g_chid) {
			fprintf(stderr, "No memory\n");
			err = -ENOMEM;
			goto _exit;
		}
		printf("Calculating %d CHIDs ... ", g_util_blobs);
		uint64_t start = uv_hrtime();
		rtbuf_t *rb = rtbuf_init_alloc_one(opt.blob_size);
		if (rb == NULL) {
			fprintf(stderr, "No memory\n");
			err = -ENOMEM;
			goto _exit;
		}
		memset(rtbuf(rb, 0).base, 0, opt.blob_size);
		if (!opt.skip_utilization && opt.rand_key_utilization) {
			gettimeofday (&g_start, NULL);
		} else {
			g_start.tv_usec = 10000;
			g_start.tv_sec = 34545;
		}
		for (unsigned int i = 0; i < g_util_blobs; i++) {

			((uint32_t *)rtbuf(rb, 0).base)[0] = g_start.tv_usec + i;
			((uint32_t *)rtbuf(rb, 0).base)[1] = g_start.tv_sec;

			err = rtbuf_hash(rb, HASH_TYPE_XXHASH_256, &g_chid[i]);
			if (err) {
				fprintf(stderr, "Error calc hash: %d\n", err);
				rtbuf_destroy(rb);
				goto _exit;
			}
		}
		rtbuf_destroy(rb);
		printf("took %lus\n", (uint64_t)((uv_hrtime() - start) / 1e9));
		if (!opt.skip_utilization)
			utilization(dev); /*  Utilization put blobs until utilization limit reached*/
		rtlat(dev);
	} else {
		fprintf(stderr, "Wrong CMD\n");
		usage();
	}

_exit:
	reptrans_destroy();
	reptrans_close_all_rt();
	return err;
}
