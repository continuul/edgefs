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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "lmdb.h"
#include "reptrans-data.h"
#include "reptrans-device.h"
#include "rtrd/reptrans-rd.h"

#define MAX_DBS 30
#define MAX_VALUE_SIZE (8*1024UL*1024UL + 512)
#define MIN_KEY_SIZE 8
#define MAX_KEY_SIZE 90
#define REVERT_DBI_NAME "revert"
#define LMDB_FORMAT_LENGTH (1024*1024)
static int g_refresh = 0;
static int g_rtrd_wal = 0;

/** Compare two backref-like items */
static int
rd_lmdb_vbr_cmp_val(const MDB_val *a, const MDB_val *b, int* cmp_err)
{
	return vbr_cmp(a->mv_data, a->mv_size, b->mv_data, b->mv_size, cmp_err);
}

/** Compare two trlog items */
static int
rd_lmdb_trlog_cmp_key(const MDB_val *a, const MDB_val *b, int* cmp_err)
{
	return trlog_cmp(a->mv_data, a->mv_size, b->mv_data, b->mv_size, cmp_err);
}

/** Compare two batch items */
static int
rd_lmdb_batch_cmp_val(const MDB_val *a, const MDB_val *b, int* cmp_err)
{
	return batch_cmp(a->mv_data, a->mv_size, b->mv_data, b->mv_size, cmp_err);
}

/** compare two TT_VERIFICATION_QUEUE keys where UVID and GenID embeeded
 *  into CHID */
static int
rd_lmdb_verqueue_cmp_key(const MDB_val *a, const MDB_val *b, int* cmp_err)
{
	return verqueue_cmp(a->mv_data, a->mv_size, b->mv_data, b->mv_size, cmp_err);
}

static int
rd_lmdb_incomig_batch_cmp_key(const MDB_val *a, const MDB_val *b, int* cmp_err)
{
	return incomig_queue_cmp(a->mv_data, a->mv_size, b->mv_data, b->mv_size, cmp_err);
}

/** Compare two TT_NAMEINDEX items, match UVIDs and GenIDs in reverse order */
static int
rd_lmdb_nameindex_cmp_val(const MDB_val *a, const MDB_val *b, int* cmp_err)
{
	return nameindex_cmp(a->mv_data, a->mv_size, b->mv_data, b->mv_size, cmp_err);
}

/* RTRD WAL data comparators */
static int
rd_log_cmp(const MDB_val *a, const MDB_val *b, int (*blob_cmp)(const void *,
	const size_t, const void *, const size_t, int* cmp_err), int* cmp_err)
{
	/* In log we follow an additional rule:
	 * if dupsort's value has a delete request without payload,
	 * then such a request has a higher priority
	 */
	int a_prio = 0, b_prio = 0;
	if (a->mv_size == DUPSORT_DEL_MAGIC_SIZE && IS_DUPSORT_DEL(a->mv_data))
		a_prio = 1;
	if (b->mv_size == DUPSORT_DEL_MAGIC_SIZE && IS_DUPSORT_DEL(b->mv_data))
		b_prio = 1;

	if (a_prio || b_prio)
		return b_prio - a_prio;
	int err = blob_cmp(a->mv_data, a->mv_size, b->mv_data, b->mv_size, cmp_err);
	if (*cmp_err != 0)
		return 0;
	if (!err && (a->mv_size != b->mv_size)) {
		if (a->mv_size > b->mv_size)
			return 1;
		else if (a->mv_size < b->mv_size)
			return -1;
	}
	return err;
}

static int
rd_log_vbr_cmp(const MDB_val *a, const MDB_val *b, int* cmp_err) {
	return rd_log_cmp(a, b, vbr_cmp, cmp_err);
}

static int
rd_log_batch_cmp(const MDB_val *a, const MDB_val *b, int* cmp_err) {
	return rd_log_cmp(a, b, batch_cmp, cmp_err);
}

static int
rd_log_nameindex_cmp(const MDB_val *a, const MDB_val *b, int* cmp_err) {
	return rd_log_cmp(a, b, nameindex_cmp, cmp_err);
}

static int
rd_log_generic_cmp(const MDB_val *a, const MDB_val *b, int* cmp_err) {
	return rd_log_cmp(a, b, generic_cmp, cmp_err);
}

enum {
	gStateIdle,
	gStateReadVerifyKeys,
	gStateReadVerifyValues,
	gStateWriteTest,
	gStateCopy
};

enum {
	gErrorNone = 0,
	gErrorOpenDB,
	gErrorReadDBInternals,
	gErrorReadDBStructure,
	gErrorReadKey,
	gErrorReadValue,
	gErrorPut,
	gErrorCopySrcCorrupted,
	gErrorCopyDstCorrupted,
	gErrorInProgress,
	gErrorFreeDBICorrupted,
	gErrorFormat
};

volatile int g_state = 0;

static void
showProgress(FILE* f, int err, const char* err_str, size_t entries,
	size_t max_entries, size_t corrupted) {
	char* c = strchr(err_str, '\n');
	if (c) {
		*c = '\0';
	}
	fprintf(f, "{\"error\": %d, \"errorstr\": \"%s\", \"entries\": %lu, "
		"\"progress\":%lu, \"corrupted\": %lu}\n",
		err, err_str, entries, max_entries ? 100*entries/max_entries : 0, corrupted);
	fflush(f);
}

static void
signal_handler(int signum) {
	if (signum == SIGINT && (g_state == gStateWriteTest || g_state == gStateCopy)) {
		/* Ignore Ctrl+C while a modify test is in progress */
		return;
	}
	if (signum == SIGBUS || signum == SIGSEGV || signum == SIGABRT) {
		char buf[128];
		sprintf(buf, "disgnal %d on %s", signum, g_state == gStateReadVerifyKeys ?
			"KeyVerify" : "ValueVerify");
		showProgress(stdout, -10, buf, 0, 100, 0);
	}
	exit(1);
}

static int
is_main_dbi(const char* dbi_name, char* ttag_str) {
	/* DBI name on main partition named in a special way */
	int plevel = -1;
	int rc = sscanf(dbi_name, "bd-part%d-%[A-Z_]-0", &plevel, ttag_str);
	return rc == 2 && plevel >= 0 && strlen(ttag_str);
}

static int
is_rdkeys_dbi(const char* dbi_name, char* ttag_str) {
	int rc = sscanf(dbi_name, "keys-%s", ttag_str);
	return rc == 1;
}

static int
is_mdcache_dbi(const char* dbi_name, char* ttag_str) {
	int rc = sscanf(dbi_name, "mdcache-%s", ttag_str);
	return rc == 1;
}

static int
is_hashcount_dbi(const char* dbi_name) {
	return strstr(dbi_name, "TT_HASHCOUNT") != NULL;
}

static const char*
get_dbi_type(const char* dbi_name) {
	char ttag_str[128];
	const char* rc = "mdoffload";
	if (is_main_dbi(dbi_name, ttag_str))
		rc = "main";
	else if (is_rdkeys_dbi(dbi_name, ttag_str))
		rc = "keys";
	else if (is_mdcache_dbi(dbi_name, ttag_str))
		rc = "mdcache";
	return rc;
}

static int
du_env_open(const char* path, MDB_env* ref_env, unsigned int opts,
	MDB_env** out_env, char* errstr) {
	MDB_env* env = NULL;
	MDB_envinfo mei;
	int rc = mdb_env_create(&env);
	if (rc) {
		sprintf(errstr, "mdb_env_create failed: (%d) %s\n", rc,
			mdb_strerror(rc));
		rc = gErrorOpenDB;
	}

	mdb_env_set_maxdbs(env, MAX_DBS);
	if (ref_env) {
		MDB_stat mstat;
		mdb_env_stat(ref_env, &mstat);
		mdb_env_info(ref_env, &mei);
		rc = mdb_env_set_psize(env, mstat.ms_psize);
		if (rc) {
			sprintf(errstr, "mdb_env_set_psize failed to %lu: (%d) %s",
				mei.me_mapsize, rc, mdb_strerror(rc));
			rc = gErrorOpenDB;
			goto _close;
		}
		rc = mdb_env_set_mapsize(env, mei.me_mapsize);
		if (rc) {
			sprintf(errstr, "mdb_env_set_mapsize failed to %lu: (%d) %s",
				mei.me_mapsize, rc, mdb_strerror(rc));
			rc = gErrorOpenDB;
			goto _close;
		}

		mdb_env_set_maxreaders(env, mei.me_maxreaders);

	}

	rc = mdb_env_open(env, path, opts, 0664);
	if (rc) {
		if (rc == MDB_INVALID) {
			/* Make sure the environment isn't formatted */
			char* buf = je_malloc(LMDB_FORMAT_LENGTH);
			int fd = open(path, O_RDONLY);
			if (fd < 0) {
				sprintf(errstr, "Couldn't open %s for reading, error %d %s",
					path, errno, strerror(errno));
				rc = gErrorOpenDB;
			} else {
				int n = read(fd, buf, LMDB_FORMAT_LENGTH);
				if (n != LMDB_FORMAT_LENGTH) {
					sprintf(errstr, "Partition %s read error %d",
						path, n == -1 ? errno : n);
					rc = gErrorOpenDB;
				} else {
					int formatted = 1;
					for (size_t i = 0; i < LMDB_FORMAT_LENGTH; i++) {
						if (buf[i] != 0) {
							formatted = 0;
							break;
						}
					}
					if (formatted) {
						sprintf(errstr, "Partition %s is clean",path);
						rc = gErrorFormat;
					} else {
						sprintf(errstr, "mdb_env_open %s failed, error %d %s",
							path, rc, mdb_strerror(rc));
						rc = gErrorOpenDB;
					}
				}
			}
			je_free(buf);
		} else {
			sprintf(errstr, "mdb_env_open %s failed, error %d %s",
				path, rc, mdb_strerror(rc));
			rc = gErrorOpenDB;
		}
		goto _close;
	}
	*out_env = env;
	return 0;

_close:
	if (env)
		mdb_env_close(env);
	return rc;
}


static int
du_env_dump_info(MDB_env* env, FILE* f) {
	MDB_txn* txn = NULL;
	MDB_cursor* cur = NULL;
	int err = 0, n_dbis = 0;
	char* src_dbis[MAX_DBS] = {NULL};
	char errstr[1024] = {0};
	size_t total_entries = 0;
	MDB_envinfo mei;
	MDB_stat mstat;
	mdb_env_info(env, &mei);
	mdb_env_stat(env, &mstat);
	fprintf(f, "{\n"
	"     \"psize\": %u,\n"
	"     \"mapsize\": %lu,\n"
	"     \"mapused\": %lu,\n"
	"     \"dbi\": [\n",
	mstat.ms_psize, mei.me_mapsize / mstat.ms_psize, mei.me_last_pgno);

	err = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
	if (err) {
		err = gErrorOpenDB;
		sprintf(errstr, "mdb_txn_begin failed, error (%d) %s",
			err, mdb_strerror(err));
		fprintf(f, "]\n");
		goto txn_abort;
	}
	MDB_dbi dbi = 0;
	MDB_val dbi_name_key;
	/* Fetch a DBI list */
	err = mdb_open(txn, NULL, 0, &dbi);
	if (err) {
		err = gErrorOpenDB;
		sprintf(errstr, "mdb_open failed, error (%d) %s",
			err, mdb_strerror(err));
		fprintf(f, "]\n");
		goto txn_abort;
	}

	err = mdb_cursor_open(txn, dbi, &cur);
	if (err) {
		sprintf(errstr, "mdb_cursor_open failed, error (%d) %s",
			err, mdb_strerror(err));
		fprintf(f, "]\n");
		err = gErrorOpenDB;
		goto txn_abort;
	}
	while ((err = mdb_cursor_get(cur, &dbi_name_key, NULL, MDB_NEXT_NODUP)) == 0) {
		MDB_cursor* cur2,* new_cur = NULL;
		MDB_val key2, val2;
		MDB_dbi db2;
		if (memchr(dbi_name_key.mv_data, '\0', dbi_name_key.mv_size))
			continue;
		char* name = malloc(dbi_name_key.mv_size + 1);
		memcpy(name, dbi_name_key.mv_data, dbi_name_key.mv_size);
		name[dbi_name_key.mv_size] = '\0';
		/* skip the revert DBI */
		if (!strcmp(name, REVERT_DBI_NAME)) {
			free(name);
			continue;
		}
		src_dbis[n_dbis++] = name;
	}
	mdb_cursor_close(cur);

	for (int i =0; i < n_dbis; i++) {
		err = mdb_dbi_open(txn, src_dbis[i], 0, &dbi);
		if (err)  {
			sprintf(errstr, "Unable to open source DBI %s", src_dbis[i]);
			fprintf(f, "]\n");
			err = gErrorOpenDB;
			goto txn_abort;
		}
		if (i) {
			fprintf(f,",\n");
		}

		mdb_stat(txn, dbi, &mstat);

		fprintf(f,
		"        {\"name\": \"%s\", \"type\": \"%s\", \"entries\": %lu, \"pages\": %lu}",
		src_dbis[i], get_dbi_type(src_dbis[i]), mstat.ms_entries,
		mstat.ms_branch_pages + mstat.ms_leaf_pages + mstat.ms_overflow_pages);
		total_entries += mstat.ms_entries;
		mdb_dbi_close(env, dbi);
	}
	fprintf(f,"\n    ]");
	/* Open and check the FREE_DBI */
	MDB_val key, data;
	cur = NULL;
	dbi = 0;
	size_t free_dbi_pages = 0;
	err = mdb_cursor_open(txn, dbi, &cur);
	if (err) {
		sprintf(errstr, "FREE_DBI mdb_cursor_open failed, error (%d) %s",
			err, mdb_strerror(err));
		err = gErrorFreeDBICorrupted;
		goto txn_abort;
	}
	while ((err = mdb_cursor_get(cur, &key, &data, MDB_NEXT)) == 0) {
		size_t* iptr = data.mv_data;
		free_dbi_pages += *iptr;
	}
	mdb_cursor_close(cur);
	if (err && err != MDB_NOTFOUND) {
		sprintf(errstr, "the FREE_DBI is corrupted (%d) %s\n",
			err, mdb_strerror(err));
		err = gErrorFreeDBICorrupted;
		goto txn_abort;
	}
	err = 0;
	fprintf(f,",\n    \"freelist_size\": %lu", free_dbi_pages);
	fprintf(f,",\n    \"entries\": %lu", total_entries);

txn_abort:
	if (txn)
		mdb_txn_abort(txn);
	char* c = strchr(errstr, '\n');
	if (c) {
		*c = '\0';
	}
	fprintf(f, ",\n    \"error\": %d,\n    \"errorstr\": \"%s\"\n}\n",
		err, errstr);
	for (int i =0; i < n_dbis; i++)
		if (src_dbis[i])
			free(src_dbis[i]);
	return err;
}

static int
du_dbi_open(MDB_env* env, const char* dbi_name, int readonly,
	unsigned int dbi_flags, MDB_txn** txn_out,
	MDB_dbi* dbi_out, MDB_cursor** cur_out, char* errstr) {
	MDB_txn* txn = NULL;
	MDB_dbi dbi = 0;
	MDB_cursor* cur = NULL;
	int err = 0;

	err = mdb_txn_begin(env, NULL, readonly ? MDB_RDONLY : 0, &txn);
	if (err) {
		sprintf(errstr,"mdb_txn_begin failed: (%d) %s", err,
			mdb_strerror(err));
		return err;
	}
	err = mdb_dbi_open(txn, dbi_name, dbi_flags, &dbi);
	if (err)  {
		sprintf(errstr, "mdb_dbi_open failed: (%d) %s\n", err,
			mdb_strerror(err));
		goto _exit;
	}
	/* Attache custom data/value comparators */
	if (g_rtrd_wal) {
		if (strstr(dbi_name, "TT_NAMEINDEX")) {
			mdb_set_dupsort(txn, dbi, rd_log_nameindex_cmp);
		} else if (strstr(dbi_name, "TT_VERIFIED_BACKREF")) {
			mdb_set_dupsort(txn, dbi, rd_log_vbr_cmp);
		} else if (strstr(dbi_name, "TT_BATCH_QUEUE")) {
			mdb_set_dupsort(txn, dbi, rd_log_batch_cmp);
		} else if (strstr(dbi_name, "TT_VERIFICATION_QUEUE")) {
			mdb_set_compare(txn, dbi, rd_lmdb_verqueue_cmp_key);
		} else if (strstr(dbi_name, "TT_TRANSACTION_LOG")) {
			mdb_set_compare(txn, dbi, rd_lmdb_trlog_cmp_key);
		} else if (strstr(dbi_name, "TT_BATCH_INCOMING_QUEUE")) {
			mdb_set_compare(txn, dbi, rd_lmdb_incomig_batch_cmp_key);
		}
	} else {
		if (strstr(dbi_name, "TT_NAMEINDEX")) {
			mdb_set_dupsort(txn, dbi, rd_lmdb_nameindex_cmp_val);
		} else if (strstr(dbi_name, "TT_VERIFIED_BACKREF")) {
			mdb_set_dupsort(txn, dbi, rd_lmdb_vbr_cmp_val);
		} else if (strstr(dbi_name, "TT_BATCH_QUEUE")) {
			mdb_set_dupsort(txn, dbi, rd_lmdb_batch_cmp_val);
		} else if (strstr(dbi_name, "TT_VERIFICATION_QUEUE")) {
			mdb_set_compare(txn, dbi, rd_lmdb_verqueue_cmp_key);
		} else if (strstr(dbi_name, "TT_TRANSACTION_LOG")) {
			mdb_set_compare(txn, dbi, rd_lmdb_trlog_cmp_key);
		} else if (strstr(dbi_name, "TT_BATCH_INCOMING_QUEUE")) {
			mdb_set_compare(txn, dbi, rd_lmdb_incomig_batch_cmp_key);
		}
	}


	err = mdb_cursor_open(txn, dbi, &cur);
	if (err) {
		sprintf(errstr, "mdb_cursor_open failed: (%d) %s\n", err,
			mdb_strerror(err));
	}
_exit:
	if (err) {
		if (cur)
			mdb_cursor_close(cur);
		if (dbi)
			mdb_dbi_close(env, dbi);
		if (txn)
			mdb_txn_abort(txn);
	} else {
		*txn_out = txn;
		*dbi_out = dbi;
		*cur_out = cur;
	}
	return err;
}

static int
is_key_encoded(const char* dbi_name) {
	char ttag_str[256] = {0};
	int rc = is_main_dbi(dbi_name, ttag_str);
	if (!rc) {
		if (is_rdkeys_dbi(dbi_name, ttag_str))
			return 0;
		if (is_mdcache_dbi(dbi_name, ttag_str))
			return 0;
		strcpy(ttag_str, dbi_name);
	}

	return !strcmp(ttag_str, "TT_CHUNK_PAYLOAD") ||
		!strcmp(ttag_str, "TT_CHUNK_MANIFEST") ||
		!strcmp(ttag_str, "TT_VERSION_MANIFEST") ||
		!strcmp(ttag_str, "TT_VERIFIED_BACKREF") ||
		!strcmp(ttag_str, "TT_PARITY_MANIFEST");
}

static int
is_value_hashed(const char* dbi_name) {
	char ttag_str[256] = {0};
	int rc = is_main_dbi(dbi_name, ttag_str);
	if (!rc) {
		if (is_rdkeys_dbi(dbi_name, ttag_str))
			return 0;
		if (is_mdcache_dbi(dbi_name, ttag_str))
			return 0;
		strcpy(ttag_str, dbi_name);
	}

	return !strcmp(ttag_str, "TT_CHUNK_PAYLOAD") ||
		!strcmp(ttag_str, "TT_CHUNK_MANIFEST");
}

int
du_key_check(const MDB_val* key, type_tag_t *ttag, crypto_hash_t *hash_type,
	uint512_t *chid) {
	int err;
	uint32_t u_ttag = 0;
	uint8_t u_hash_type = 0;
	uint512_t u_chid;

	msgpack_u u;
	msgpack_unpack_init_b(&u, key->mv_data, key->mv_size, 0);

	err = msgpack_unpack_uint32(&u, &u_ttag);
	if (err)
		return err;
	if (ttag)
		*ttag = u_ttag;

	err = msgpack_unpack_uint8(&u, &u_hash_type);
	if (err)
		return err;
	if (hash_type)
		*hash_type = u_hash_type;

	err = replicast_unpack_uint512(&u, &u_chid);
	if (chid)
		*chid = u_chid;
	return err;
}


static int
du_check_dbi_read(const char* env_path, const char* dbi_name, int opts,
	int level, int factor, int skip_corrupted, FILE* f) {
	MDB_env* env = NULL;
	MDB_txn* txn = NULL;
	MDB_dbi dbi = 0;
	MDB_cursor* cur = NULL;
	int ret = gErrorNone;
	if (factor <= 0 || !f)
		return -EINVAL;

	MDB_val val = { 0, NULL };
	MDB_val key = { 0, NULL };
	int get_index = 128;
	int deep_check_index = random() % factor;
	size_t corrupted_count = 0;
	size_t entries = 0;
	MDB_stat dbi_stat;

	char errstr[1024] = {0};
	uint64_t ts = get_timestamp_us();

	int err = du_env_open(env_path, NULL, opts | MDB_RDONLY, &env, errstr);
	if (err) {
		ret = err;
		goto _exit;
	}

	MDB_stat mstat;
	mdb_env_stat(env, &mstat);

	err = du_dbi_open(env, dbi_name, 1, 0, &txn, &dbi, &cur, errstr);
	if (err) {
		ret = gErrorOpenDB;
		goto _exit;
	}

	int op = MDB_FIRST;
	mdb_stat(txn, dbi, &dbi_stat);
	unsigned int dbi_flags = 0;
	mdb_dbi_flags(txn, dbi, &dbi_flags);
	while ((err=mdb_cursor_get(cur, &key, &val, op)) == 0) {
		entries++;
		if (entries > dbi_stat.ms_entries) {
			sprintf(errstr, "an expected number of entries exceeded: %lu vs %lu",
				dbi_stat.ms_entries, entries);
			ret = gErrorReadDBStructure;
			goto _exit;
		}
		if (g_refresh && get_timestamp_us() - ts > (uint64_t)g_refresh) {
			showProgress(f, gErrorInProgress, "", entries, dbi_stat.ms_entries,
				corrupted_count);
			ts = get_timestamp_us();
		}
		op = MDB_NEXT;
		/* Level == 0 - just make sure iterator and get work */
		if (!level)
			continue;
		/* if factor == 1, then extended check fill be applied to
		 * every value (if level > 0). Otherwise some random
		 * values will be checked
		 */
		if (deep_check_index-- > 0)
			continue;
		if (!(dbi_flags & MDB_DUPSORT) && --get_index <= 0) {
			/*
			 * The iterator doesn't traverse the tree.
			 * Doing get by a key to we verify some
			 * branch pages
			 */
			MDB_val g_val = { 0, NULL };
			MDB_val g_key = key;

			err = mdb_get(txn, dbi, &g_key, &g_val);
			if (err) {
				sprintf(errstr, "mdb_get failed: (%d) %s", err,
					mdb_strerror(err));
				ret = gErrorReadDBStructure;
				goto _exit;
			}
			if (g_val.mv_size != val.mv_size || g_val.mv_data != val.mv_data) {
				sprintf(errstr, "mdb_get value doesn't match");
				ret = gErrorReadDBStructure;
				goto _exit;
			}
			get_index = 128;
		}
		deep_check_index = random() % factor;

		type_tag_t ttag = TT_INVALID;
		crypto_hash_t hash_type;
		uint512_t chid;
		/* make sure the key is correct */
		g_state = gStateReadVerifyKeys;
		if (is_key_encoded(dbi_name)) {
			err = du_key_check(&key, &ttag, &hash_type, &chid);
			if (err || ttag <= TT_INVALID || ttag >= TT_LAST) {
				sprintf(errstr, "key_decode failed: %d", err);
				ret = gErrorReadKey;
				corrupted_count++;
				if (!skip_corrupted)
					goto _exit;
			}
		} else {
			/* The bloom key size may vary and depends on VDEV name size */
			size_t key_size_max = is_hashcount_dbi(dbi_name) ? 2048 : MAX_KEY_SIZE;
			if (key.mv_size < MIN_KEY_SIZE || key.mv_size > key_size_max) {
				sprintf(errstr, "invalid key size: %lu", key.mv_size);
				ret = gErrorReadKey;
				corrupted_count++;
				if (!skip_corrupted)
					goto _exit;
			}
		}
		if (val.mv_size > MAX_VALUE_SIZE) {
			sprintf(errstr, "invalid value size: %lu", val.mv_size);
			ret = gErrorReadValue;
			corrupted_count++;
			if (!skip_corrupted)
				goto _exit;

		}
		if (g_rtrd_wal)
			continue;
		if (level == 2 && val.mv_size >= mstat.ms_psize / 2) {
			/* If data reside on an overflow page - trying to fetch a part of it
			 * If kernel is unable to cache a page, then the application will crash.
			 * We should be able to track this fact in a signal handler
			 */
			g_state = gStateReadVerifyValues;
			char buf[16];
			size_t n = val.mv_size > 16 ? 16 : val.mv_size;
			memcpy(buf, val.mv_data, n);
		} else if (level == 3 && is_value_hashed(dbi_name)) {
			/* Some values have theirs hashID as part of a key.
			 * We can verify a payload in this case.
			 * Note: this operation takes a very long while
			 */
			uint512_t u_chid = uint512_null;
			uv_buf_t ub = {.base = val.mv_data, .len = val.mv_size };
			rtbuf_t* rb = rtbuf_init_mapped(&ub, 1);
			assert(rb);
			err = rtbuf_hash(rb, hash_type, &u_chid);
			rtbuf_destroy(rb);
			if (err) {
				sprintf(errstr, "rtbuf_hash error: %d", err);
				ret = gErrorReadValue;
				corrupted_count++;
				if (!skip_corrupted)
					goto _exit;
			}
			if (uint512_cmp(&chid, &u_chid)) {
				sprintf(errstr, "hashID compare error");
				corrupted_count++;
				ret = gErrorReadValue;
				if (!skip_corrupted)
					goto _exit;
			}
		}
		g_state = gStateIdle;
	}
	if (err && err != MDB_NOTFOUND) {
		sprintf(errstr, "mdb_cursor_get: failed: (%d) %s", err,
			mdb_strerror(err));
		ret = gErrorReadDBStructure;
	}

_exit:
	showProgress(f, ret, errstr, entries, dbi_stat.ms_entries, corrupted_count);
	if (cur)
		mdb_cursor_close(cur);
	if (dbi)
		mdb_dbi_close(env, dbi);
	if (txn)
		mdb_txn_abort(txn);
	if (env)
		mdb_env_close(env);
	return ret;
}

static int
du_check_dbi_modify(const char* env_path, const char* dbi_name,
	unsigned int env_opts, int level, int factor, FILE* f) {

	MDB_env* env = NULL;
	MDB_txn* rd_txn = NULL, *wr_txn = NULL;
	MDB_dbi dbi = 0;
	MDB_cursor* cur = NULL;
	char errstr[1024] = {0};
	MDB_val ukey = { .mv_data = malloc(128), .mv_size = 128 };
	MDB_val uval = { .mv_data = malloc (MAX_VALUE_SIZE), .mv_size = MAX_VALUE_SIZE};
	int op = MDB_FIRST;
	MDB_val val = { 0, NULL };
	MDB_val key = { 0, NULL };
	int idx = 1;
	size_t entries = 0;
	MDB_stat dbi_stat;
	uint64_t ts = get_timestamp_us();


	int ret = gErrorNone;
	if (factor <= 0 || !f)
		return -EINVAL;

	g_state = gStateWriteTest;
	int err = du_env_open(env_path, NULL, env_opts, &env, errstr);
	if (err) {
		ret = gErrorOpenDB;
		goto _exit;
	}

	MDB_stat mstat;
	mdb_env_stat(env, &mstat);

	err = du_dbi_open(env, dbi_name, 0, 0, &wr_txn, &dbi, &cur, errstr);
	if (err) {
		ret = gErrorOpenDB;
		goto _exit;
	}
	// Preserve DBI access. It will close the cursor
	err = mdb_txn_commit(wr_txn);
	if (err) {
		sprintf(errstr,"mdb_txn_commit failed: (%d) %s", err,
			mdb_strerror(err));
		ret = gErrorOpenDB;
		goto _exit;
	}
	/* Open read-only transaction for iterator*/
	err = mdb_txn_begin(env, NULL, MDB_RDONLY, &rd_txn);
	if (err) {
		sprintf(errstr,"mdb_txn_begin failed: (%d) %s", err,
			mdb_strerror(err));
		ret = gErrorOpenDB;
		goto _exit;
	}
	err = mdb_cursor_open(rd_txn, dbi, &cur);
	if (err) {
		sprintf(errstr,"mdb_cursor_open failed: (%d) %s", err,
			mdb_strerror(err));
		ret = gErrorOpenDB;
		goto _exit;
	}
	/* Open the write transaction as well */
	err = mdb_txn_begin(env, NULL, 0, &wr_txn);
	if (err) {
		sprintf(errstr,"mdb_txn_begin failed: (%d) %s", err,
			mdb_strerror(err));
		ret = gErrorOpenDB;
		goto _exit;
	}

	unsigned int dbi_flags = 0;
	mdb_dbi_flags(rd_txn,dbi, &dbi_flags);


	size_t put_count = 0;
	mdb_stat(rd_txn, dbi, &dbi_stat);


	/* Replacing entries */
	while ((err=mdb_cursor_get(cur, &key, &val, op)) == 0) {
		entries++;
		if (g_refresh && get_timestamp_us() - ts > (uint64_t)g_refresh) {
			showProgress(f, gErrorInProgress, "", entries, dbi_stat.ms_entries,0);
			ts = get_timestamp_us();
		}
		uint64_t attr = 0 ;
		if (!(dbi_flags & MDB_DUPSORT)) {
			err = mdb_cursor_get_attr(cur, &key, &val, &attr);
			if (err) {
				sprintf(errstr,"mdb_cursor_get_attr failed: (%d) %s", err,
					mdb_strerror(err));
				ret = gErrorReadDBStructure;
				goto _exit;
			}
		}
		op = MDB_NEXT;
		if (--idx <= 0) {
			memcpy(ukey.mv_data, key.mv_data, key.mv_size);
			memcpy(uval.mv_data, val.mv_data, val.mv_size);
			ukey.mv_size = key.mv_size;
			uval.mv_size = val.mv_size;
			if (dbi_flags & MDB_DUPSORT)
				err = mdb_put(wr_txn, dbi, &ukey, &uval, 0);
			else
				err = mdb_put_attr(wr_txn, dbi, &ukey, &uval, attr, 0);
			if (err) {
				sprintf(errstr,"mdb_put failed: (%d) %s", err,
					mdb_strerror(err));
				ret = gErrorPut;
				goto _exit;
			}
			idx = rand() % factor;
			if (++put_count > 1000) {
				err = mdb_txn_commit(wr_txn);
				wr_txn = NULL;
				if (err) {
					sprintf(errstr,"mdb_txn_commit failed: (%d) %s", err,
						mdb_strerror(err));
					ret = gErrorPut;
					goto _exit;
				}
				err = mdb_txn_begin(env, NULL, 0, &wr_txn);
				if (err) {
					sprintf(errstr,"mdb_txn_begin failed: (%d) %s", err,
						mdb_strerror(err));
					ret = gErrorOpenDB;
					goto _exit;
				}
				put_count = 0;
			}
		}
	}
	if (err && err != MDB_NOTFOUND) {
		if (err) {
			sprintf(errstr,"mdb_cursor_get failed: (%d) %s", err,
				mdb_strerror(err));
			ret = gErrorReadDBStructure;
			goto _exit;
		}
	}
	err = 0;
	if (put_count) {
		err = mdb_txn_commit(wr_txn);
		wr_txn = NULL;
		if (err) {
			sprintf(errstr,"mdb_txn_commit failed: (%d) %s", err,
				mdb_strerror(err));
			ret = gErrorPut;
			goto _exit;
		}
	}
	mdb_dbi_close(env, dbi);
	dbi = 0;

_exit:
	g_state = gStateIdle;
	if (cur)
		mdb_cursor_close(cur);
	if (rd_txn)
		mdb_txn_abort(rd_txn);
	if (wr_txn)
		mdb_txn_abort(wr_txn);
	if (dbi)
		mdb_dbi_close(env, dbi);
	if (env)
		mdb_env_close(env);
	showProgress(f, ret, errstr, entries, dbi_stat.ms_entries,0);
	free(ukey.mv_data);
	free(uval.mv_data);
	return ret;
}

static int
du_dbi_copy(const char* src_path, const char* dest_path, const char* dbi_name,
	int env_opts, FILE* f) {
	MDB_env* src_env = NULL, *dst_env = NULL;
	MDB_txn* src_txn = NULL, *dst_txn = NULL;
	MDB_dbi src_dbi = 0, dst_dbi = 0;
	MDB_cursor* src_cur = NULL, *dst_cur = NULL;
	char errstr[1024] = {0};
	MDB_val ukey = { .mv_data = malloc(128), .mv_size = 128 };
	MDB_val uval = { .mv_data = malloc (MAX_VALUE_SIZE), .mv_size = MAX_VALUE_SIZE};
	int op = MDB_FIRST;
	MDB_val val = { 0, NULL };
	MDB_val key = { 0, NULL };
	int idx = 1;

	size_t entries = 0;
	MDB_stat dbi_stat;
	uint64_t ts = get_timestamp_us();

	int ret = gErrorNone;
	g_state = gStateCopy;
	int err = du_env_open(src_path, NULL, env_opts | MDB_RDONLY, &src_env, errstr);
	if (err) {
		ret = gErrorOpenDB;
		goto _exit;
	}

	err = du_env_open(dest_path, src_env, env_opts, &dst_env, errstr);
	if (err) {
		ret = gErrorOpenDB;
		goto _exit;
	}

	MDB_stat mstat;
	mdb_env_stat(src_env, &mstat);

	err = du_dbi_open(src_env, dbi_name, 1, 0, &src_txn, &src_dbi, &src_cur,
		errstr);
	if (err) {
		ret = gErrorOpenDB;
		goto _exit;
	}
	unsigned int dbi_flags = 0;
	mdb_dbi_flags(src_txn,src_dbi, &dbi_flags);

	err = du_dbi_open(dst_env, dbi_name, 0, dbi_flags | MDB_CREATE, &dst_txn,
		&dst_dbi, &dst_cur, errstr);
	if (err) {
		ret = gErrorOpenDB;
		goto _exit;
	}
	mdb_stat(src_txn, src_dbi, &dbi_stat);
	while ((err = mdb_cursor_get(src_cur, &key, &val, op)) == 0) {
		op = MDB_NEXT;
		if (++entries > dbi_stat.ms_entries) {
			ret = gErrorCopySrcCorrupted;
			sprintf(errstr, "Iterator exceeded number of expected entries");
			goto _exit;
		}

		if (g_refresh && get_timestamp_us() - ts > (uint64_t)g_refresh) {
			showProgress(f, gErrorInProgress, "", entries, dbi_stat.ms_entries,0);
			ts = get_timestamp_us();
		}
		if (dbi_flags & MDB_DUPSORT) {
			err = mdb_cursor_put(dst_cur, &key, &val, 0);
			if (err && err != MDB_KEYEXIST) {
				ret = gErrorCopyDstCorrupted;
				sprintf(errstr, "mdb_cursor_put failed: (%d) %s",
					err, mdb_strerror(err));
				goto _exit;
			}
		} else {
			uint64_t attr = 0;
			err = mdb_cursor_get_attr(src_cur, &key, &val, &attr);
			if (err) {
				ret = gErrorCopySrcCorrupted;
				sprintf(errstr, "mdb_cursor_get_attr failed: (%d) %s",
					err, mdb_strerror(err));
				goto _exit;
			}
			err = mdb_cursor_put_attr(dst_cur, &key, &val, attr, MDB_APPEND);
			if (err && err != MDB_KEYEXIST) {
				ret = gErrorCopyDstCorrupted;
				sprintf(errstr, "mdb_cursor_put_attr failed: (%d) %s\n",
					err, mdb_strerror(err));
				goto _exit;
			}
		}
	}
	if (err && err != MDB_NOTFOUND) {
		sprintf(errstr,"mdb_cursor_get failed: (%d) %s", err,
			mdb_strerror(err));
		ret = gErrorCopySrcCorrupted;
	}
_exit:
	if (dst_cur)
		mdb_cursor_close(dst_cur);
	if (dst_txn) {
		if (ret == gErrorNone) {
			err = mdb_txn_commit(dst_txn);
			if (err) {
				sprintf(errstr,"mdb_txn_commit failed: (%d) %s", err,
					mdb_strerror(err));
				ret = gErrorCopyDstCorrupted;
			}
		} else
			mdb_txn_abort(dst_txn);
	}
	g_state = gStateIdle;
	if (dst_dbi)
		mdb_dbi_close(dst_env, dst_dbi);
	if (dst_env)
		mdb_env_close(dst_env);

	if (src_cur)
		mdb_cursor_close(src_cur);
	if (src_txn)
		mdb_txn_abort(src_txn);
	if (src_env)
		mdb_env_close(src_env);
	showProgress(f, ret, errstr, entries, dbi_stat.ms_entries,0);
	return ret;
}

/* A DBI has to be modifiedIn order to revert a transaction and store the change.
 * To not touch any data tables, we create an additional one with name "revert"
 * which keeps a KV pairs where the key is a timestamp and a value is empty.
 */
static int
du_revert(const char* envpath, int env_opts, FILE* f) {
	MDB_env* env = NULL;
	MDB_txn* txn = NULL;
	MDB_dbi dbi = 0;
	MDB_cursor* cur = NULL;
	time_t val = time(NULL);
	MDB_val dbi_key = {.mv_data = &val, .mv_size = sizeof(val)};
	MDB_val dbi_val = {.mv_data = NULL, .mv_size = 0};
	int ret = 0;
	char errstr[1024] = {0};

	int err = du_env_open(envpath, NULL, env_opts | MDB_PREVSNAPSHOT, &env,
		errstr);
	if (err) {
		ret = gErrorOpenDB;
		goto _exit;
	}

	err = mdb_txn_begin(env, NULL, 0, &txn);
	if (err) {
		sprintf(errstr, "mdb_txn_begin failed: (%d) %s", err,
			mdb_strerror(err));
		ret = gErrorReadDBStructure;
		goto _exit;
	}

	/* Fetch a DBI list */
	err = mdb_dbi_open(txn, REVERT_DBI_NAME, MDB_CREATE, &dbi);
	if (err) {
		err = gErrorOpenDB;
		sprintf(errstr, "mdb_open failed, error (%d) %s",
			err, mdb_strerror(err));
		goto _exit;
	}

	err = mdb_put(txn, dbi, &dbi_key, &dbi_val, 0);
	if (err) {
		sprintf(errstr, "mdb_put failed, error (%d) %s",
			err, mdb_strerror(err));
		fprintf(f, "]\n");
		err = gErrorPut;
		goto _exit;
	}

	err = mdb_txn_commit(txn);
	if (err) {
		sprintf(errstr, "mdb_txn_commit failed: (%d) %s", err,
			mdb_strerror(err));
		ret = gErrorPut;
	}
_exit:
	if (dbi)
		mdb_dbi_close(env, dbi);
	if (env)
		mdb_env_close(env);
	fprintf(f, "{\"error\": %d, \"errorstr\": \"%s\"}\n",
		ret, errstr);
	return ret;
}
static void
usage() {
	printf("\n    Usage: dbi_util [options] <src_env> [tgt_env]\n"
		"    Common options:\n"
		"           -r               open environment with MDB_RAW flag\n"
		"           -p               use the last but one transaction (MDB_PREVSNAPSHOT flag)\n"
		"           -l <time>        display job progress every <time> seconds\n"
		"           -W               environment is an RTRD WAL\n"
		"           src_env          path to the source LMDB environment\n"
		"           dst_env          path to the destination LMDB environment (for copy only)\n\n"
		"    Usage scenarios:\n\n"
		"    LMDB DBI get info:  dbi_util -i <src_env>\n\n"
		"    LMDB DBI read test:  dbi_copy -c <level> -n <dbi_name> [-f <factor>] [-s] <src_env>\n"
		"       Options:\n"
		"           -n <dbi_name>    name of a DBI to be tested\n"
		"           -c   <level>     start verification with complexity set to <level>\n"
		"                            Where <level>:\n"
		"                                 0   quick check of leaf nodes presence\n"
		"                                 1   check validity of each key and max. value size\n"
		"                                 2   fetch values from disk\n"
		"                                 3   verify value's hash ID whenever it's possible\n"
		"           -f   <factor>    verify at least every <factor>-th key-value. Default is 1 (each KV)\n"
		"           -s               continue test if a key or value error detected\n\n"
		"    LMDB DBI modify test:  dbi_copy -w -n <dbi_name> [-f <factor>] <src_env>\n"
		"       Options:\n"
		"           -n <dbi_name>    name of a DBI to be tested\n"
		"           -f   <factor>    verify at least every <factor>-th key-value. Default is 1000 (each KV)\n\n"
		"    LMDB DBI copy:  dbi_copy -d -n <dbi_name> <src_env> <dst_env>\n\n"
		"    LMDB revert last transaction:  dbi_copy -u <src_env>\n\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	int i, rc;
	MDB_env *env = NULL, *new_env = NULL;
	MDB_txn *txn = NULL, *new_txn = NULL;
	MDB_dbi dbi, dbi_new;
	MDB_envinfo mei;
	char *prog = argv[0];
	char *envname;
	char *subname = NULL;
	int new_env_flags = 0;
	char* new_env_path = NULL;
	char* src_dbis[MAX_DBS] = {NULL};
	int n_dbis = 0;
	int env_info = 0;
	int commit_damaged = 0;
	int rd_check = 0, wr_check = 0, dbi_copy = 0;
	int skip_corrupted = 0, revert = 0;
	size_t check_errs = 0;
	int check_factor = 0; /* Check each key/value pair by default */

	if (argc < 2) {
		usage(prog);
	}

	while ((i = getopt(argc, argv, "n:irc:wWf:sdpul:")) != EOF) {
		switch(i) {
		case 'r':
			new_env_flags |= MDB_RAW;
			break;

		case 'n':
			subname = strdup(optarg);
			break;

		case 'i':
			env_info = 1;
			break;

		case 'c':
			rd_check = strtol(optarg, NULL, 10);
			break;

		case 's':
			skip_corrupted = 1;
			break;

		case 'u':
			revert = 1;
			break;

		case 'f':
			check_factor = strtol(optarg, NULL, 10);
			if (check_factor <= 0) {
				usage(prog);
			}
			break;

		case 'w':
			wr_check = 1;
			break;

		case 'W':
			g_rtrd_wal = 1;
			break;

		case 'd':
			dbi_copy = 1;
			break;

		case 'p':
			new_env_flags |= MDB_PREVSNAPSHOT;
			break;

		case 'l':
			g_refresh = strtol(optarg, NULL, 10);
			if (g_refresh < 0 || g_refresh > 30) {
				usage(prog);
			}
			g_refresh *= 1000000;
			break;

		default:
			usage();
		}
	}

	if (env_info || revert) {
		if (optind != argc - 1)
			usage();
	} else if (rd_check){
		if (optind != argc - 1 || !subname)
			usage();
	} else if (wr_check){
		if (optind != argc - 1 || !subname)
			usage();
	} else if (dbi_copy){
		if (optind != argc - 2 || !subname)
			usage();
	}

	signal(SIGABRT, signal_handler);
	signal(SIGSEGV, signal_handler);
	signal(SIGBUS, signal_handler);

	lg = Logger_create("dbi_util");
	if (!lg)
		return -ENOMEM;

	load_crypto_lib();
	srand(time(NULL));

	unsigned int env_opt = MDB_COALESCE | MDB_LIFORECLAIM | MDB_NOTLS
		| MDB_NOSUBDIR | new_env_flags;

	envname = argv[optind];

	if (env_info) {
		char errstr[1024] = {0};
		rc = du_env_open(envname, NULL, env_opt | MDB_RDONLY, &env, errstr);
		if (rc) {
			printf("{\"error\": %d, \"errorstr\": \"%s\"}\n",
				rc, errstr);

			return rc;
		}
		rc = du_env_dump_info(env, stdout);
		mdb_env_close(env);
		return rc;
	} else if (rd_check) {
		if (!check_factor)
			check_factor = 1;
		return du_check_dbi_read(envname, subname, env_opt, rd_check,
			check_factor, skip_corrupted, stdout);
	} else if (wr_check) {
		if (!check_factor)
			check_factor = 1000;
		return du_check_dbi_modify(envname, subname, env_opt, rd_check,
			check_factor, stdout);
	} else if (dbi_copy) {
		const char* dst_env = argv[optind + 1];
		return du_dbi_copy(envname, dst_env, subname, env_opt, stdout);
	}  else if (revert) {
		return du_revert(envname, env_opt, stdout);
	}
	return 0;
}

