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
/*
 * reptrans_pattern_test.c
 *
 *  Created on: Jun 6, 2018
 *      Author: root
 */



#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "ccowutil.h"
#include "cmocka.h"
#include "common.h"
#include "reptrans.h"

#define TRANS_RTRD	"rtrd"
#define TRANS_RTKVS	"rtkvs"
#define MAX_DEV		256
#define N_VERSIONS	10
#define N_OLD_VERSIONS	5

int no_asserts = 0;
int verbosity = 1;
int interval = 30;
int verify = 1;

struct enum_dev_arg {
	int n_dev;
	struct repdev **dev;
};

Logger lg;
struct repdev *devices[MAX_DEV];
const char *transport[] = { "rtlfs" };

#define LOG(...) if (verbosity) printf(__VA_ARGS__)

static void
enum_dev__done_cb(struct repdev *dev, void *arg, int status)
{
	struct enum_dev_arg *da = (struct enum_dev_arg *)arg;
	assert_non_null(da);
	if (status == 0)
		da->dev[da->n_dev++] = dev;
	assert_true(da->n_dev < MAX_DEV);
}

static int
libreptrans_enum(void)
{
	struct enum_dev_arg enum_arg = {0, devices};

	assert_int_equal(reptrans_enum(NULL, &enum_arg,
		    enum_dev__done_cb, 0), 0);
	return enum_arg.n_dev;
}


static void
uint128_deserialize(const uint8_t* buf, uint128_t* val) {
	val->u = be64toh(*(uint64_t*)buf);
	val->l = be64toh(*((uint64_t*)buf+1));
}


static void
uint256_deserialize(const uint8_t* buf, uint256_t* val) {
	uint128_deserialize(buf, &val->u);
	uint128_deserialize(buf + sizeof(uint64_t)*2, &val->l);
}

static void
uint512_deserialize(const uint8_t* buf, uint512_t* val) {
	uint256_deserialize(buf, &val->u);
	uint256_deserialize(buf + sizeof(uint64_t)*4, &val->l);
}

typedef enum {
	patSeq,
	patRand
} kv_seq;

struct pattern_desc {
	size_t pattern_len; /* Number of put transactions */
	crypto_hash_t hash_type;
	type_tag_t ttag;
	/* Key generator configuration */
	size_t key_size_min; /* Minimum size of the key 1..64*/
	size_t key_size_max; /* Maximum size of the key 1..64*/
	size_t key_size_div; /* key must match condition key_size % key_size_div == 0 */
	kv_seq k_seq;	/* Key ordering: sequential or random */
	/* Value generator configuration */
	size_t value_size_min;
	size_t value_size_max;
	size_t value_size_div;
	kv_seq v_seq;
	/* Delete pattern */
	size_t del_nth; /* Delete every Nth element*/
	size_t del_fifo_size; /*Deferred delete. Remove the first when fifo is full */
	uint8_t del_batch; /* If set, delete all elements from the fifo at once */
	uint8_t del_verify; /* Get and verify value before delete */
	kv_seq d_seq; /* Generate delete request randomly or use del_nth */
};

struct pattern_job {
	int id;
	struct pattern_desc* desc;
	struct repdev* dev;
	pthread_t thr;
	size_t bytes_written;
	size_t bytes_written_prev;
	size_t chunks_written;
	size_t chunks_deleted;
	size_t chunks_verified;
};

struct put_item {
	QUEUE item;
	uint512_t key;
	uv_buf_t val;
};

static void
make_key(struct pattern_desc* desc, uint32_t* klen_prev, uint512_t* key) {
	uint8_t kb[sizeof(uint512_t)] = { 0 };
	uint32_t len = *klen_prev;
	if (desc->d_seq == patSeq) {
		if (!len)
			len = desc->key_size_min;
		else {
			len += desc->key_size_div;
			if (len > desc->key_size_max || len > sizeof(kb))
				len = desc->key_size_min;
		}
	} else {
		do {
			len = random() % sizeof(kb);
		} while (len < desc->key_size_min || len > desc->key_size_max || len % desc->key_size_div != 0);
	}
	for (uint32_t t = 0; t < len; t++)
		kb[t] = random();
	/* Convert to little-endian */
	uint512_deserialize(kb, key);
	*klen_prev = len;
}

static void
make_value_size(struct pattern_desc* desc, uint32_t* klen_prev_new) {
	uint32_t len = *klen_prev_new;
	if (desc->v_seq == patSeq) {
		if (!len)
			len = (desc->value_size_min/desc->value_size_div)*desc->value_size_div;
		else {
			len += desc->value_size_div;
			if (len > desc->value_size_max)
				len = (desc->value_size_min/desc->value_size_div)*desc->value_size_div;
		}
	} else {
		do {
			len = random() % desc->value_size_max;
		} while (len < desc->value_size_min  || len % desc->value_size_div != 0);
	}
	*klen_prev_new = len;
}

static void
make_vbr(struct pattern_desc* desc, uv_buf_t* vbr_value) {
	uint32_t k_len = 0;
	struct backref vbr;
	make_key(desc,&k_len, &vbr.name_hash_id);
	make_key(desc,&k_len, &vbr.ref_chid);
	vbr.generation = random() % 32768;
	vbr.uvid_timestamp = get_timestamp_us();
	vbr.rep_count = rand() % 3;
	vbr.ref_hash = HASH_TYPE_DEFAULT;
	vbr.ref_type = vbr.rep_count ? TT_CHUNK_MANIFEST : TT_VERSION_MANIFEST;
	vbr.attr = (rand () & 1) ? VBR_ATTR_EC : 0;
	msgpack_p *p = msgpack_pack_init();
	int err = reptrans_pack_vbr(p, &vbr);
	/* Don't forget to free vbr_value->base */
	msgpack_get_buffer(p, vbr_value);
}

#define MAX_CHUNK	(2*1024*1024)

volatile uint64_t threads = 0;

static void*
pattern_thread(void* arg) {

	struct pattern_job* job = arg;
	struct pattern_desc* desc = job->desc;
	char* val_base= je_malloc(MAX_CHUNK*2);
	size_t val_offset = rand() % MAX_CHUNK;
	QUEUE del_head;
	QUEUE_INIT(&del_head);
	uint32_t key_len = 0;
	uint32_t val_len = 0;
	size_t nth = desc->d_seq == patSeq ? desc->del_nth : rand() % desc->del_nth;
	size_t del_queue_len = 0;

	printf("pattern_thread %d dev %s\n", job->id, job->dev->name);

	for (size_t i = 0; i < MAX_CHUNK*2; i++)
		val_base[i] = rand() % 256;

	for (size_t i = 0; i < desc->pattern_len; i++) {
		struct put_item e;
		QUEUE_INIT(&e.item);
		make_key(desc, &key_len, &e.key);
		if (desc->ttag != TT_VERIFIED_BACKREF) {
			make_value_size(desc, &val_len);
			e.val.len = val_len;
			e.val.base = val_base + val_offset;
			val_offset = rand() % MAX_CHUNK;
			rtbuf_t* rb = rtbuf_init_mapped(&e.val,1);
			if (no_asserts) {
				if (!rb) LOG("rtbuf_init_mapped(&e.val,1) at %d\n", __LINE__);
			} else
				assert_non_null(rb);
			int err = reptrans_put_blob_with_attr(job->dev, desc->ttag,
				desc->hash_type, rb, &e.key, 0, get_timestamp_us());
			if (no_asserts) {
				if (err) LOG("reptrans_put_blob_with_attr() %d at %d\n", err, __LINE__);
			} else
				assert_int_equal(err, 0);
			job->bytes_written += val_len;
		} else {
			make_vbr(desc, &e.val);
			rtbuf_t* rb = rtbuf_init_mapped(&e.val,1);
			if (no_asserts) {
				if (!rb) LOG("rtbuf_init_mapped(&e.val,1) at %d\n", __LINE__);
			} else
				assert_non_null(rb);
			int err =reptrans_put_blob(job->dev, desc->ttag,
				HASH_TYPE_DEFAULT, rb, &e.key, 0);
			if (no_asserts) {
				if (err) LOG("reptrans_put_blob() %d at %d\n", err, __LINE__);
			} else
				assert_int_equal(err, 0);
			job->bytes_written += e.val.len;
		}
		job->chunks_written++;
		if (i == nth) {
			nth += desc->d_seq == patSeq ? desc->del_nth : rand() % desc->del_nth;
			struct put_item* ne = je_malloc(sizeof(*ne));
			if (no_asserts) {
				if (!ne) LOG("memory alloc at %d\n", __LINE__);
			} else
				assert_non_null(ne);

			memcpy(ne, &e, sizeof(e));
			QUEUE_INSERT_TAIL(&del_head, &ne->item);
			if (++del_queue_len >= desc->del_fifo_size) {
				if (desc->del_batch) {
					del_queue_len = 0;
					/* Verify/delete a batch */
					rtbuf_t* vbr_rb = rtbuf_init(NULL, del_queue_len);
					if (no_asserts) {
						if (!vbr_rb) printf("rtbuf_init(NULL, del_queue_len) at %d\n", __LINE__);
					} else
						assert_non_null(vbr_rb);

					QUEUE *q;
					while (!QUEUE_EMPTY(&del_head)) {
						q = QUEUE_HEAD(&del_head);
						QUEUE_REMOVE(q);
						QUEUE_INIT(q);
						struct put_item* it = QUEUE_DATA(q, struct put_item, item);
						if (verify && desc->del_verify) {
							rtbuf_t* rb_g = NULL;
							int err = reptrans_get_blob(job->dev, desc->ttag,
								desc->hash_type, &it->key, &rb_g);
							if (no_asserts) {
								if (err)
									LOG("reptrans_get_blob() %d at %d\n", err, __LINE__);
								if (!rb_g) {
									LOG("void rtbuf at %d\n", __LINE__);
								} else {
									if (rb_g->bufs->len != it->val.len)
										LOG("value size differs at %d: %lu vs %lu\n",
											__LINE__, rb_g->bufs->len, it->val.len);
									err = memcmp(rb_g->bufs->base, it->val.base, it->val.len);
									if (err)
										LOG("Value comparator error %d at %d\n", err, __LINE__);
								}
							} else {
								assert_int_equal(err, 0);
								assert_non_null(rb_g);
								assert_int_equal(rb_g->bufs->len, it->val.len);
								assert_int_equal(memcmp(rb_g->bufs->base, it->val.base,
									it->val.len), 0);
							}
							rtbuf_destroy(rb_g);
							job->chunks_verified++;
						}
						/* Deleting */
						if (desc->ttag != TT_VERIFIED_BACKREF) {
							int err = reptrans_delete_blob(job->dev, desc->ttag, HASH_TYPE_DEFAULT, &it->key);
							if (no_asserts) {
								if (err) LOG("reptrans_delete_blob %d at %d\n", err, __LINE__);
							} else
								assert_int_equal(err, 0);
							job->chunks_deleted++;
						} else {
							int err = reptrans_delete_blob_value(job->dev, desc->ttag,
								HASH_TYPE_DEFAULT, &it->key, &it->val, 1);
							if (no_asserts) {
								if (err) LOG("delete_blob_value %d at %d\n", err, __LINE__);
							} else
								assert_int_equal(err, 0);
							je_free(it->val.base);
							job->chunks_deleted++;
						}
						je_free(it);
					}
				} else {
					del_queue_len--;
					QUEUE* ptr = QUEUE_HEAD(&del_head);
					QUEUE_REMOVE(ptr);
					struct put_item* it = QUEUE_DATA(ptr, struct put_item, item);
					if (verify && desc->del_verify) {
						rtbuf_t* rb_g = NULL;
						int err = reptrans_get_blob(job->dev, desc->ttag,
							desc->hash_type, &it->key, &rb_g);
						if (no_asserts) {
							if (err)
								LOG("reptrans_get_blob() %d at %d\n", err, __LINE__);
							if (!rb_g) {
								LOG("void rtbuf at %d\n", __LINE__);
							} else {
								if (rb_g->bufs->len != it->val.len)
									LOG("value size differs at %d: %lu vs %lu\n",
										__LINE__, rb_g->bufs->len, it->val.len);
								err = memcmp(rb_g->bufs->base, it->val.base, it->val.len);
								if (err)
									LOG("Value comparator error %d at %d\n", err, __LINE__);
							}
						} else {
							assert_int_equal(err, 0);
							assert_non_null(rb_g);
							assert_int_equal(rb_g->bufs->len, it->val.len);
							assert_int_equal(memcmp(rb_g->bufs->base, it->val.base,
								it->val.len), 0);
						}
						rtbuf_destroy(rb_g);
						job->chunks_verified++;
					}
					/* Deleting */
					if (desc->ttag != TT_VERIFIED_BACKREF) {
						int err = reptrans_delete_blob(job->dev, desc->ttag, HASH_TYPE_DEFAULT, &it->key);
						if (no_asserts) {
							if (err) LOG("reptrans_delete_blob %d at %d\n", err, __LINE__);
						} else
							assert_int_equal(err, 0);
						job->chunks_deleted++;
					} else {
						int err = reptrans_delete_blob_value(job->dev, desc->ttag,
							HASH_TYPE_DEFAULT, &it->key, &it->val, 1);
						if (no_asserts) {
							if (err) LOG("delete_blob_value %d at %d\n", err, __LINE__);
						} else
							assert_int_equal(err, 0);
						je_free(it->val.base);
						job->chunks_deleted++;
					}
					je_free(it);
				}
			}
		} else if (desc->ttag == TT_VERIFIED_BACKREF)
			je_free(e.val.base);
	}
	je_free(val_base);
	printf("pattern_thread done %d\n", job->id);
	atomic_dec64(&threads);
	return 0;
}


static void
libreptrans_pattern_test(void **state)
{
	int err =  reptrans_init(0, NULL, NULL,
			RT_FLAG_STANDALONE | RT_FLAG_CREATE, 1, (char**)transport, NULL);
	struct pattern_desc tests[] = {
		{.pattern_len = 32*1024*1024, .ttag = TT_CHUNK_PAYLOAD, .hash_type = HASH_TYPE_DEFAULT, .key_size_min = 8, .key_size_max = 64, .key_size_div = 2, .k_seq = patSeq,
		.value_size_min = 4*1024, .value_size_max = 16*1024, .value_size_div = 16, .v_seq = patSeq,
		.del_nth = 8, .del_fifo_size = 128, .del_verify = 1, .del_batch = 0, .d_seq = patSeq},

		{.pattern_len = 32*1024*1024, .ttag = TT_CHUNK_PAYLOAD, .hash_type = HASH_TYPE_DEFAULT, .key_size_min = 9, .key_size_max = 16, .key_size_div = 2, .k_seq = patSeq,
		.value_size_min = 128*1024, .value_size_max = 256*1024, .value_size_div = 16, .v_seq = patSeq,
		.del_nth = 2, .del_fifo_size = 16, .del_verify = 1, .del_batch = 1, .d_seq = patSeq},

		{.pattern_len = 24*1024*1024, .ttag = TT_CHUNK_MANIFEST, .hash_type = HASH_TYPE_DEFAULT, .key_size_min = 32, .key_size_max = 64, .key_size_div = 3, .k_seq = patRand,
		.value_size_min = 128*1024, .value_size_max = 256*1024, .value_size_div = 16, .v_seq = patSeq,
		.del_nth = 16, .del_fifo_size = 256, .del_verify = 1, .del_batch = 0, .d_seq = patSeq},

		{.pattern_len = 16*1024*1024, .ttag = TT_CHUNK_MANIFEST, .hash_type = HASH_TYPE_DEFAULT, .key_size_min = 32, .key_size_max = 64, .key_size_div = 3, .k_seq = patRand,
		.value_size_min = 512*1024, .value_size_max = 1024*1024, .value_size_div = 16, .v_seq = patSeq,
		.del_nth = 16, .del_fifo_size = 1024, .del_verify = 1, .del_batch = 1, .d_seq = patSeq},

		{.pattern_len = 64*1024*1024, .ttag = TT_VERIFIED_BACKREF, .hash_type = HASH_TYPE_DEFAULT, .key_size_min = 32, .key_size_max = 64, .key_size_div = 3, .k_seq = patRand,
		.del_nth = 16, .del_fifo_size = 256, .del_verify = 1, .del_batch = 1, .d_seq = patSeq},

	};
	size_t n_tests = sizeof(tests)/sizeof(tests[0]);


	assert_true(err > 0);

	size_t n_dev = libreptrans_enum();

	assert_true(n_dev > 0);
	srand(clock());

	struct pattern_job* jobs = je_calloc(n_tests*n_dev, sizeof(*jobs));
	for (size_t n = 0; n < n_dev; n++) {
		for (size_t i = 0; i < n_tests; i++) {
			struct pattern_job* job = jobs + n*n_tests + i;
			job->dev = devices[n];
			job->id = n*n_tests + i;
			job->desc = tests + i;
			atomic_inc64(&threads);
			int err = pthread_create(&job->thr, NULL, pattern_thread, job);
			assert_int_equal(err, 0);
		}
	}

	size_t processed[n_dev];
	size_t len[n_dev];
	size_t perf[n_dev];
	size_t processed_total = 0;
	size_t len_total = 0;
	size_t perf_total = 0;
	size_t bytes_written_total = 0;
	do {
		usleep(interval*1000000);
		if (verbosity) {
			printf("\n\n");
			processed_total = 0;
			perf_total = 0;
			len_total = 0;
			bytes_written_total = 0;
			for (size_t n = 0; n < n_dev; n++) {
				processed[n] = 0;
				perf[n] = 0;
				len[n] = 0;
				for (size_t i = 0; i < n_tests; i++) {
					struct pattern_job* job = jobs + n*n_tests + i;
					processed[n] += job->chunks_written;
					len[n] += job->desc->pattern_len;
					size_t written = job->bytes_written;
					perf[n] += written - job->bytes_written_prev;
					job->bytes_written_prev = written;
					bytes_written_total += written;
				}
				if (verbosity > 1) {
					printf("Dev(%s)\t%.4f%%\t%.2f MB/s\n", devices[n]->name,
						(double)processed[n]*100.0/len[n],
						(double)perf[n]/interval/1000000.0f);
				}
				processed_total +=  processed[n];
				len_total += len[n];
				perf_total += perf[n];
			}
			printf("Total:\t%.4f%%\t%.2f MB/s %lu MB\n", (double)processed_total*100.0/len_total,
				(double)perf_total/interval/1000000.0f, bytes_written_total / (1024UL*1024UL));
		}
	} while (threads);
	printf("Terminating..\n");
	je_free(jobs);
}

static void
reptrans_teardown(void **state)
{
	assert_int_equal(reptrans_destroy(),0);
	reptrans_close_all_rt();
}

int
main(int argc, char *argv[])
{
	lg = Logger_create("reptrans");
	char cmd[PATH_MAX];
	snprintf(cmd, sizeof(cmd), "cat %s/etc/ccow/ccowd.json|grep rtrd 2>/dev/null >/dev/null",
			nedge_path());
	if (system(cmd) == 0)
		transport[0] = TRANS_RTRD;
	else {
		snprintf(cmd, sizeof(cmd), "cat %s/etc/ccow/ccowd.json|grep rtkvs 2>/dev/null >/dev/null",
				nedge_path());
		if (system(cmd) == 0)
			transport[0] = TRANS_RTKVS;
	}



	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"help",	0,	0,  'h' },
			{"verbosity", required_argument, 0,  'v' },
			{"no-assert",	0,	0,  'a' },
			{"interval", required_argument, 0, 'i' },
			{"verify", required_argument, 0, 'c' },
			{0,         0,	                 0,  0 }
		};

		int c = getopt_long(argc, argv, "hv:ai:c:",
				long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
			case 'h':
				printf("\tUsage: [--verbosity=<0..2>], [--no-asserrt] [--interval=<seconds>]\n");
				exit(0);

			case 'v':
				verbosity = strtol(optarg, NULL ,10);
				break;


			case 'i':
				interval = strtol(optarg, NULL ,10);
				break;


			case 'c':
				verify = strtol(optarg, NULL ,10);
				break;


			case 'a':
				no_asserts = 1;
				break;

			default:
				fprintf(stderr, "cmdline parse error\n");
				exit(-1);
		}
	}

	printf("Verification is %s\n", verify ? "ON" : "OFF");

	const UnitTest tests[] = {
		unit_test(libreptrans_pattern_test),
		unit_test(reptrans_teardown),
	};
	return run_tests(tests);
}

