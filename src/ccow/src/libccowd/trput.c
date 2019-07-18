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

#include "queue.h"
#include "ccow-impl.h"
#include "ccowd-impl.h"
#include "clengine.h"
#include "reptrans.h"
#include "trput.h"
#include "flexhash.h"
#include "trlog.h"

extern int ccowd_terminating;

#define TRLOG_HT_SIZE (8 * 1024)
#define RUN_TOTAL_INTERVAL 60000000UL
#define TRLOG_HT_MAX_LOAD_FACTOR (0.085)
#define SENT_LOGICAL_SIZE_FREQ 12
#define TRLOG_TS_KEY "X-TRLOG-TS"

hashtable_t * trlog_tenant_acct_ht = NULL;
struct ccow_cluster_stats *stats_data = NULL;

static uint64_t last_processed_time_ms;
static uint64_t last_processed_entries;
static volatile uint64_t batch_seq_prev_ts = 0;

// Static global totals
static int64_t cluster_total_run_time = 0;


static int
trput_process_hashtable_update(struct trlog_data *data,
	double factor,
    int64_t *delta_size)
{
	int err = 0;
	char nhidstr[UINT512_BYTES*2+1];
	ccow_completion_t c;
	ccow_metadata_kv_t kv;
	struct ccow_metadata_kv attr_kv;
	char *tid = NULL;
	uint64_t prev_logical_size = 0, logical_size = 0;

	*delta_size = data->deltasize;

	assert((data->trtype & TRLOG_OBJ_CREATE) ||
		(data->trtype & TRLOG_OBJ_UPDATE) ||
		(data->trtype & TRLOG_OBJ_DELETE));

	tid = data->tid;
	/* skip tenant starting from TRLOG- */
	if (tid && *tid != 0 && strlen(tid) > strlen(TRLOG_TID_PREFIX) &&
	    memcmp(tid, TRLOG_TID_PREFIX, strlen(TRLOG_TID_PREFIX)) == 0) {
		err = -ENOEXEC;
		goto _err;
	}
	/* skip tenant root */
	if (tid && *tid != 0 && strlen(tid) == strlen(RT_SYSVAL_TENANT_ADMIN) &&
	    memcmp(tid, RT_SYSVAL_TENANT_ADMIN, strlen(RT_SYSVAL_TENANT_ADMIN)) == 0) {
		err = -ENOEXEC;
		goto _err;
	}
	/* skip tenant svcs */
	if (tid && *tid != 0 && strlen(tid) == strlen(RT_SYSVAL_TENANT_SVCS) &&
	    memcmp(tid,RT_SYSVAL_TENANT_SVCS, strlen(RT_SYSVAL_TENANT_SVCS)) == 0) {
		err = -ENOEXEC;
		goto _err;
	}
	/* skip empty oid */
	if (data->oid && *data->oid == 0) {
		err = -ENOEXEC;
		goto _err;
	}

	//
	// Add the hashtable entry for the tenant accounting,
	// the key is : 'cid/tid'
	//
	char cid_tid[4096];
	memset(cid_tid, 0, 4096);
	sprintf(cid_tid, "%s/%s", data->cid, data->tid);
	trlog_entry_t *tmp = NULL;

	if (trlog_ht_get(cid_tid, &tmp)) {
		// RMW
		tmp->delta_size += *delta_size;
		tmp->delta_objs += (data->trtype & TRLOG_OBJ_CREATE) ? 1 :
			(data->trtype & TRLOG_OBJ_DELETE) ? -1 : 0;
		tmp->delta_used += (int64_t) (*delta_size * factor);
		err = trlog_ht_put(cid_tid, tmp);
	} else {
		trlog_entry_t ent ;
		ent.delta_size = *delta_size;
		ent.delta_objs = (data->trtype & TRLOG_OBJ_CREATE) ? 1 :
			(data->trtype & TRLOG_OBJ_DELETE) ? -1 : 0;
		ent.delta_used = (int64_t) (*delta_size * factor);
		err = trlog_ht_put(cid_tid, &ent);
	}
	if (err)
		goto _err;

	return err;
_err:
	if (err && err != -ENOEXEC)
		log_error(lg, "Failed to update stats - err: %d", err);
	return err;
}

int
pack_container_value(msgpack_p * p, struct trlog_data *data) {
	int err;

	uint8_t ver = 1;
	err = msgpack_pack_uint8(p, ver);
	if (err)
	   return err;

	err = msgpack_pack_uint8(p, data->object_deleted);
	if (err)
		return err;

	err = msgpack_pack_uint64(p, data->timestamp);
	if (err)
		return err;

	err = msgpack_pack_uint64(p, data->generation);
	if (err)
		return err;

	err = replicast_pack_uint512(p, &data->vmchid);
	if (err)
		return err;

	err = msgpack_pack_str(p, (data->etag ? data->etag : ""));
	if (err)
		return err;

	err = msgpack_pack_str(p, (data->content_type ? data->content_type : ""));
	if (err)
		return err;

	uint64_t size = (data->multipart_size == 0 ? data->size : data->multipart_size);
	err = msgpack_pack_uint64(p, size);
	if (err)
		return err;

	err = msgpack_pack_uint64(p, data->inode);
    if (err)
        return err;

    err = msgpack_pack_str(p, (data->owner ? data->owner : ""));
    if (err)
        return err;

    err = msgpack_pack_str(p, (data->srcip ? data->srcip: ""));
    return err;
}

int
pack_inode_value(msgpack_p * p, struct trlog_data *data) {
	int err;

	uint8_t ver = 2;
	err = msgpack_pack_uint8(p, ver);
	if (err)
	   return err;

	err = msgpack_pack_str(p, data->oid);

	return err;
}


static int
trput_process_version_expunge(ccow_t tc, struct trlog_data *data)
{
	int err = 0;
	ccow_lookup_t iter = NULL;

	uint64_t dsize = (data->multipart_size ? data->multipart_size : data->size);

	log_trace(lg, "TRLOG: trput_process_version_expunge: cid: %s, tid: %s, oid: %s gen: %lu, del: %u, dsize: %ld\n",
		data->cid, data->tid, data->oid, data->generation, data->object_deleted, dsize);

	ccow_completion_t c = NULL;
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err)
		goto _exit;

	struct iovec *iov = NULL;
	err = ccow_admin_pseudo_get(data->cid, strlen(data->cid) + 1,
			data->tid, strlen(data->tid) + 1,
			data->bid, strlen(data->bid) + 1,
			data->oid, strlen(data->oid) + 1,
			iov, 0, 0,
			CCOW_GET_VERSIONS, c, &iter);
	if (err) {
		ccow_release(c);
		goto _exit;
	}

	err = ccow_wait(c, 0);
	if (err) {
		if (err == -ENOENT) {
			err = -ENOEXEC;
		}
		goto _exit;
	}

	struct ccow_metadata_kv *kv = NULL;
	int pos = 0;
	char *c512;
	char b[REPLICAST_STR_MAXLEN];
	char d[REPLICAST_STR_MAXLEN*2];
	int64_t genid, size, del, genid_last = 0, size_last = 0, del_last = 0;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_VERSIONS, pos++))) {
		memcpy(b, kv->key, kv->key_size);
		b[kv->key_size] = '\0';
		memcpy(d, kv->value, kv->value_size);
		d[kv->value_size] = '\0';
		char *sp;
		c512 = strtok_r(b,"|", &sp);
		c512 = strtok_r(NULL,"|", &sp);
		genid = atoi(c512);
		if (genid < 0) {
			genid = -genid;
			del = 1;
		} else {
			del = 0;
		}
		c512 = strtok_r(d, "|", &sp);
		size = atoi(c512);
		if (genid > genid_last) {
			genid_last = genid;
			size_last = size;
			del_last = del;
		}
	}
	if (genid_last > 0 && (uint64_t)genid_last < data->generation) {
		data->size = size_last;
		data->generation = (uint64_t)genid_last;
		data->trtype = TRLOG_OBJ_UPDATE;
		data->deltasize = size_last - dsize;
		data->object_deleted = del_last;
	} else {
		err = -ENOEXEC;
	}

_exit:
	if (iter)
		ccow_lookup_release(iter);
	if (err && err != -ENOEXEC)
		log_error(lg, "Failed to process version expunge - err: %d", err);
	return err;
}

static int
need_bucket_update(struct trlog_data *data) {
	if (data->trtype & TRLOG_SKIP_BTN_UPDATE)
		return 0;

	if (data->oid[0] == '\xEF' && data->oid[1] == '\xBF' && data->oid[2] == '\xBF' &&
		data->oid[3] == '\x7B' && strlen(data->oid) > 132 && data->oid[132] == '\x7D') {
		return 0;
	}

	return 1;
}

static int
trput_process_object(ccow_t tc, struct trlog_data *data,
    ccow_completion_t c_inprog, ccow_completion_t c_fot, int *index,
    int *index_fot, struct mlist_node *res_node, int *one_bucket_updates)
{
	static uint64_t process_counter = 0;
	int err = 0;
	struct iovec iov[2];
	ccow_op_t optype;
	char buf[64];
	int64_t delta_size = 0;
	int c_flags = 0;
	struct ccow_completion *c = (struct ccow_completion *)c_inprog;


	double factor = used_factor(tc->replication_count, tc->ec_enabled, tc->ec_data_mode);

	log_trace(lg, "TRLOG: type:%d, factor: %f, rc: %d, ec_enabled: %d, ec_data_mode: %d",
			data->trtype, factor, tc->replication_count, tc->ec_enabled, tc->ec_data_mode);

	// Handle expunge as delete
	if (data->trtype & TRLOG_EXPUNGE) {
		data->trtype = TRLOG_OBJ_DELETE;
	}

	// Handle version expunge
	if (data->trtype & TRLOG_VERSION_EXPUNGE) {
		err = trput_process_version_expunge(tc, data);
		if (err == -ENOEXEC) {
			log_debug(lg, "TRLOG: no object update");
			return 0;
		}
		if (err)
			return err;
	}

	// Go check to see if this is a skippable event
	err = trput_process_hashtable_update(data, factor, &delta_size);
	if (err == -ENOEXEC)
		return 0;
	if (err)
		return err;

	msgpack_p *p = msgpack_pack_init();
	if (!p)
		return -ENOMEM;
	msgpack_p *p_fot = msgpack_pack_init();
	if (!p_fot)
		return -ENOMEM;

	process_counter++;

	log_debug(lg, "TRLOG[%lu]: entering trlog update type:%d delta: %ld data-delta: %ld"
	    " c->size: %lu", process_counter, data->trtype, delta_size, data->deltasize,
	    c->logical_sz);

	// Pack data
	err = pack_container_value(p, data);
	if (err)
		goto _err;

	uv_buf_t uv_b;
	msgpack_get_buffer(p, &uv_b);

	iov[0].iov_base = data->oid;
	iov[0].iov_len = strlen(data->oid) + 1;

	iov[1].iov_base = uv_b.base;
	iov[1].iov_len = uv_b.len;


	/* Update bucket list */
	if ((data->trtype & TRLOG_OBJ_CREATE) || (data->trtype & TRLOG_OBJ_DELETE)) {
		optype = (data->trtype & TRLOG_OBJ_CREATE) ?
				CCOW_INSERT_LIST : CCOW_DELETE_LIST;


		log_debug(lg, "TRLOG[%lu]: Updating (%s trtype=0x%x optype=%d c=%p idx=%d vmchid.u.u.u=%lX genid=%lu ts=%lu): %s/%s/%s : %s",
			process_counter, optype == CCOW_INSERT_LIST ? "INSERT": "DELETE", data->trtype, optype,
		    c, *index, data->vmchid.u.u.u, data->generation, data->timestamp, data->cid, data->tid, data->bid, data->oid);

		struct ccow_op *op = NULL;
		if (need_bucket_update(data)) {
			if (optype == CCOW_INSERT_LIST) {
				c_flags = CCOW_CONT_F_INSERT_LIST_OVERWRITE;
				ccow_stream_flags(c_inprog, &c_flags);
				err = ccow_insert_list_cont(c_inprog, iov, 2, 1, index);
			} else {
				c_flags = 0;
				ccow_stream_flags(c_inprog, &c_flags);
				err = ccow_delete_list_cont(c_inprog, iov, 1, 1, index);
			}
			if (err)
				goto _err;

			err = ccow_wait(c, *index);
			if (err)
				goto _err;
			(*one_bucket_updates)++;
			op = c->operations[*index];
		}
		if (op && (op->status == -EEXIST || op->status == -ENOENT)) {
			log_warn(lg, "TRLOG: ignore op->status %d for %s/%s/%s : %s ht_exists %d",
			    op->status, data->cid, data->tid, data->bid, data->oid,
			    trlog_mlist_ht_exists(&ccow_daemon->trhdl, res_node));
			op->status = 0;
		} else {
			if ((c->logical_sz < (uint64_t)labs(delta_size)) && (data->trtype & TRLOG_OBJ_DELETE))
				log_debug(lg, "TRLOG : Unable to process a duplicate request");
			else {
				c->logical_sz_mod = 1;
				c->logical_sz += delta_size;
				(*one_bucket_updates)++;
				c->needs_final_put = 1;
			}
			if (data->trtype & TRLOG_OBJ_CREATE) {
				c->object_count_mod = 1;
				c->object_count++;
				(*one_bucket_updates)++;
				c->needs_final_put = 1;
			}
			else if (data->trtype & TRLOG_OBJ_DELETE) {
				if (c->object_count >= 1) {
					c->object_count_mod = 1;
					c->object_count--;
					(*one_bucket_updates)++;
					c->needs_final_put = 1;
				}
			}
		}

		if (c_fot && need_bucket_update(data)) {
			log_debug(lg, "TRLOG FOT: add");
			// Pack inode data
			err = pack_inode_value(p_fot, data);
			if (err)
				goto _err;

			uv_buf_t uv_b_fot;
			msgpack_get_buffer(p_fot, &uv_b_fot);

			char inode_str[UINT128_STR_BYTES];
			sprintf(inode_str, "%lu", data->inode);

			iov[0].iov_base = inode_str;
			iov[0].iov_len = strlen(inode_str) + 1;

			iov[1].iov_base = uv_b_fot.base;
			iov[1].iov_len = uv_b_fot.len;

			c_flags = 0;
			ccow_stream_flags(c_fot, &c_flags);
			if (optype == CCOW_INSERT_LIST) {
				c_flags = CCOW_CONT_F_INSERT_LIST_OVERWRITE;
				err = ccow_insert_list_cont(c_fot, iov, 2, 1, index_fot);
			} else {
				err = ccow_delete_list_cont(c_fot, iov, 1, 1, index_fot);
			}
			if (err)
				goto _err;

			err = ccow_wait(c_fot, *index_fot);
			if (err)
				goto _err;
			(*one_bucket_updates)++;
		}
	} else {
		log_debug(lg, "TRLOG[%lu]: Updating (UPDATE trtype=0x%x) delta_size=%ld: %s/%s/%s : %s",
		    process_counter, data->trtype, delta_size, data->cid, data->tid, data->bid, data->oid);

		if (need_bucket_update(data)) {
			c_flags = CCOW_CONT_F_INSERT_LIST_OVERWRITE;
			ccow_stream_flags(c_inprog, &c_flags);
			err = ccow_insert_list_cont(c_inprog, iov, 2, 1, index);
			if (err)
				goto _err;

			err = ccow_wait(c, *index);
			if (err)
				goto _err;
			(*one_bucket_updates)++;
		}

		/*
		 * Update size if transaction is update and insert/delete object succeeds.
		 * This means object has not been previously inserted or deleted
		 */
		int64_t new_size = c->logical_sz;
		new_size += delta_size;
		if (new_size < 0) {
			log_debug(lg, "TRLOG : Negative size update request, setting size to zero");
			new_size = 0;
		} else if (new_size) {
			(*one_bucket_updates)++;
			c->needs_final_put = 1;
		}
		c->logical_sz_mod = 1;
		c->logical_sz = new_size;
	}

	/* pass-through */
_err:
	if (p)
		msgpack_pack_free(p);
	if (p_fot)
		msgpack_pack_free(p_fot);
	if (err)
		log_error(lg, "Failed to update stats - err: %d", err);
	return err;
}

static int
trput_shard_check(uint512_t *phid, void *arg)
{
	uint128_t id;
	int found;

	flexhash_lock(SERVER_FLEXHASH);
	found = flexhash_serverid_by_key(SERVER_FLEXHASH, &phid->u.u, &id);
	flexhash_unlock(SERVER_FLEXHASH);

	if (found && uint128_cmp(&id, &server_get()->id) == 0)
		return 1;

	/* fallback to leader */
	if (!found && ccow_daemon->leader)
		return 1;

	return 0;
}

static int
trput_process_result(ccow_t tc, struct mlist_node *result_head,
		uint64_t rec_count, uint64_t batch_seq_ts)
{
	int err = 0;
	struct mlist_node *res_node = result_head;
	int entries = 0;
	int one_bucket_updates = 0;
	int index = 0, index_fot;
	uint64_t genid = 0, genid_fot = 0;
	uint64_t last_batch_seq_ts = 0;
	uint64_t from_batch_seq_ts = batch_seq_ts - 10 * 1000000UL;
	ccow_completion_t c_inprog = NULL, c_fot = NULL;
	uint512_t inprog_phid = uint512_null;
	uint512_t skip_phid = uint512_null;
	ccow_lookup_t iter = NULL;
	struct trlog_data rec;

	if (!rec_count)
		return 0;

	rec.cid = rec.tid = rec.bid = rec.oid = rec.etag = rec.content_type = rec.owner = rec.srcip = NULL;

	while (res_node) {
		char entry[TRLOG_KEY_LEN];

		/* this would be insertion or data corruption bug if it hits */
		if (strlen(res_node->data) >= TRLOG_KEY_LEN) {
			log_warn(lg, "Wrong entry size, skip");
			res_node = res_node->next;
			continue;
		}

		strcpy(entry, (char*)res_node->data);
		err = trlog_extract_key(entry, strlen(entry), &rec, 0);
		if (err) {
			log_error(lg, "Error extracting TSOBJ entry %s: %d",
			    entry, err);
			goto _err;
		}

		// Don't filter isgw updates
		if (rec.trtype & TRLOG_ISGW_UPDATE) { // isgw record
			if (trlog_mlist_ht_exists(&ccow_daemon->trhdl, res_node)) {
				res_node = res_node->next;
				continue;
			}
		} else { // regular record
			if (rec.timestamp > batch_seq_ts) {
				// log_error(lg, "Skip future %s ts: %lu from: %lu, to %lu",
				// 	rec.oid, rec.timestamp, from_batch_seq_ts, batch_seq_ts);
				res_node = res_node->next;
				continue;
			} else if (trlog_mlist_ht_exists(&ccow_daemon->trhdl, res_node)) {
				// log_error(lg, "Skip processed %s ts: %lu from: %lu, to %lu",
				// 	rec.oid, rec.timestamp, from_batch_seq_ts, batch_seq_ts);
				res_node = res_node->next;
				continue;
			} else {
				// log_error(lg, "Process %s ts: %lu from: %lu, to %lu",
				// 	rec.oid, rec.timestamp, from_batch_seq_ts, batch_seq_ts);
			}
		}
		err = hashtable_put(ccow_daemon->trhdl.old_result_ht, res_node->data,
				strlen(res_node->data), NULL, 0);
		if (err) {
			log_error(lg, "Error adding TSOBJ entry: %d", err);
			goto _err;
		}

		if (!(rec.trtype & TRLOG_OBJ_CREATE) &&
			!(rec.trtype & TRLOG_OBJ_UPDATE) &&
			!(rec.trtype & TRLOG_OBJ_DELETE) &&
			!(rec.trtype & TRLOG_VERSION_EXPUNGE)) {
			res_node = res_node->next;
			MEMFREE_TRLOG_DATA(rec);
			continue;
		}

		if (uint512_cmp(&rec.phid, &uint512_null) == 0) {
			res_node = res_node->next;
			MEMFREE_TRLOG_DATA(rec);
			continue;
		}

		if (uint512_cmp(&skip_phid, &rec.phid) == 0) {
			res_node = res_node->next;
			MEMFREE_TRLOG_DATA(rec);
			continue;
		}

		err = ccow_object_inode_number(&rec.nhid, sizeof(rec.nhid), &rec.inode);
		if (err) {
			log_error(lg, "Error getting inode number entry: %s err: %d",
			    entry, err);
			goto _err;
		}

		if (uint512_cmp(&inprog_phid, &rec.phid) != 0) {
			if (one_bucket_updates > 0) {
				log_debug(lg, "finalize one_bucket_updates: %d", one_bucket_updates);
				assert(iter);
				err = ccow_finalize(c_inprog, &iter);
				index = 0;
				one_bucket_updates = 0;
				c_inprog = NULL;
				skip_phid = uint512_null;
				if (err) {
					if (c_fot) {
						err = ccow_cancel(c_fot);
						c_fot = NULL;
						index_fot = 0;
					}
					goto _err;
				}
				if (c_fot) {
					err = ccow_finalize(c_fot, NULL);
					if (err)
						log_warn(lg, "cannot finalize FOT: %d", err);
					c_fot = NULL;
					index_fot = 0;
				}
				if (iter) {
					ccow_lookup_release(iter);
					iter = NULL;
				}
			} else if (one_bucket_updates <= 0) {
				log_debug(lg, "cancel one_bucket_updates: %d", one_bucket_updates);
				one_bucket_updates = 0;
				if (c_inprog) {
					ccow_cancel(c_inprog);
					index = 0;
					iter = NULL;
				}
				if (c_fot) {
					ccow_cancel(c_fot);
					c_fot = NULL;
					index_fot = 0;
				}
			}


			genid = 0;
			int flags = 0;
			err = ccow_admin_pseudo_create_stream_completion(tc,
			    NULL, NULL, rec_count + 10, &c_inprog,
			    rec.cid, strlen(rec.cid) + 1,
			    rec.tid, strlen(rec.tid) + 1, rec.bid, strlen(rec.bid) + 1,
			    "", 1, &genid, &flags, &iter);
			if (err) {
				goto _err;
			}

			if (strlen(rec.bid) > 0 && !(flags & CCOW_CONT_F_EXIST)) {
				log_warn(lg, "bucket %s/%s/%s does not exist, skip it", rec.cid, rec.tid, rec.bid);
				if (c_inprog) {
					ccow_cancel(c_inprog);
					index = 0;
					iter = NULL;
					c_inprog = NULL;
				}
				skip_phid = rec.phid;
				res_node = res_node->next;
				MEMFREE_TRLOG_DATA(rec);
				continue;
			}

			ccow_metadata_kv_t kv;
			uint8_t sz_found = 0, cnt_found = 0;
			uint8_t ec_enabled_found = 0, ec_data_mode_found = 0;
			uint8_t rc_found = 0, fot_found = 0;
			c_inprog->ec_enabled = 0;
			last_batch_seq_ts = 0;
			while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA | CCOW_MDTYPE_CUSTOM, -1))) {
				if (!sz_found && !strcmp(kv->key, RT_SYSKEY_LOGICAL_SIZE)) {
					c_inprog->logical_sz = *(uint64_t *)kv->value;
					sz_found = 1;
				}
				if (!cnt_found && !strcmp(kv->key, RT_SYSKEY_OBJECT_COUNT)) {
					c_inprog->object_count = *(uint64_t *)kv->value;
					cnt_found = 1;
				}
				if (!ec_enabled_found && !strcmp(kv->key, RT_SYSKEY_EC_ENABLED)) {
					c_inprog->ec_enabled = *(uint8_t *)kv->value;
					ec_enabled_found = 1;
				}
				if (!ec_data_mode_found && !strcmp(kv->key, RT_SYSKEY_EC_DATA_MODE)) {
					c_inprog->ec_data_mode = *(uint32_t *)kv->value;
					ec_data_mode_found = 1;
				}
				if (!rc_found && !strcmp(kv->key, RT_SYSKEY_REPLICATION_COUNT)) {
					c_inprog->replication_count = *(uint8_t *)kv->value;
					rc_found = 1;
				}
				if (!fot_found && !strcmp(kv->key, RT_SYSKEY_FILE_OBJECT_TRANSPARANCY)) {
					c_inprog->file_object_transparency = *(uint8_t *)kv->value;
					fot_found = 1;
				}
				if (!last_batch_seq_ts && !strcmp(kv->key, TRLOG_TS_KEY)) {
					last_batch_seq_ts = *(uint64_t *)kv->value;
				}

				if (last_batch_seq_ts && sz_found && cnt_found && ec_enabled_found &&
				    ec_data_mode_found && rc_found && fot_found)
					break;
			}

			/* starting new bucket (parent) processing */
			inprog_phid = rec.phid;

			/* skip by timestamp */
			if (batch_seq_ts <= last_batch_seq_ts) {
				log_info(lg, "SKIP bucket update batch_seq_ts: %lu, last_batch_seq_ts: %lu",
				    batch_seq_ts, last_batch_seq_ts);
				one_bucket_updates = -1;
				skip_phid = rec.phid;
				res_node = res_node->next;
				MEMFREE_TRLOG_DATA(rec);
				continue;
			}

			char trlog_ts_key[] = TRLOG_TS_KEY;
			err = ccow_attr_modify_custom(c_inprog, CCOW_KVTYPE_UINT64,
			    trlog_ts_key, strlen(trlog_ts_key) + 1, &batch_seq_ts, 0, iter);
			if (err) {
				goto _err;
			}

			tc->replication_count = c_inprog->replication_count;
			tc->ec_enabled = c_inprog->ec_enabled;
			tc->ec_data_mode =  c_inprog->ec_data_mode;

			if (c_inprog->file_object_transparency) {
				genid_fot = 0;
				err = ccow_admin_pseudo_create_stream_completion(tc,
				    NULL, NULL, rec_count + 10, &c_fot,
				    rec.cid, strlen(rec.cid) + 1,
				    rec.tid, strlen(rec.tid) + 1,
				    rec.bid, strlen(rec.bid) + 1,
				    RT_SYSVAL_FOT_INODE2OID, strlen(RT_SYSVAL_FOT_INODE2OID) + 1,
				    &genid_fot, 0, NULL);
				if (err) {
					goto _err;
				}
			}
		} // next bucket


		err = trput_process_object(tc, &rec, c_inprog, c_fot,
		    &index, &index_fot, res_node, &one_bucket_updates);
		if (err) {
			log_error(lg, "Error processing TSOBJ entry %s: %d",
			    entry, err);
			goto _err;
		}
		res_node = res_node->next;
		entries++;
		MEMFREE_TRLOG_DATA(rec);
	}

	/* pass-through */
_err:
	MEMFREE_TRLOG_DATA(rec);
	log_debug(lg, "exit one_bucket_updates: %d error: %d", one_bucket_updates, err);
	if (one_bucket_updates > 0) {
		int orig_err = err;
		if (err) {
			err = ccow_cancel(c_inprog);
			iter = NULL;
			if (c_fot) {
				(void) ccow_cancel(c_fot);
			}
		} else {
			err = ccow_finalize(c_inprog, &iter);
			if (c_fot) {
				if (err) {
					(void) ccow_cancel(c_fot);
				} else {
					err = ccow_finalize(c_fot, NULL);
					if (err) {
						log_error(lg, "cannot to finalize FOT: %d", err);
						err = 0;
					}
				}
			}
		}
		if (err) {
			log_error(lg, "Error while finalizing/canceling %d "
			    "orig_err %d", err, orig_err);
		}
	} else { // no bucket entries
		if (c_inprog)
			err = ccow_cancel(c_inprog);
		if (c_fot)
			err = ccow_cancel(c_fot);

		iter = NULL;
	}

	if (iter)
		ccow_lookup_release(iter);
	if (!err) {
		last_processed_entries = entries;
	}
	return 0;
}


static void
ccowd_tenant_send(ccow_t tc)
{
	// Locals
	int err;
	char buf[64];

	// Calculate cluster total logical size every SENT_LOGICAL_SIZE_FREQ updates (onece a minute)
	uint64_t delta = get_timestamp_us() - cluster_total_run_time;
	if (ccow_daemon->leader && delta >  RUN_TOTAL_INTERVAL) {
		if (stats_data)
			je_free(stats_data);
		stats_data = (struct ccow_cluster_stats *) je_calloc(1, sizeof(struct ccow_cluster_stats));
		if (!stats_data) {
			log_error(lg, "Cluster accounting initialization");
			return;
		}

		cluster_total_run_time = get_timestamp_us();

		// Lookup clusters
		ccow_lookup_t iter = NULL;
		err = ccow_cluster_lookup(tc, NULL, 0, INT32_MAX, &iter);
		if (err) {
			log_error(lg, "Cluster lookup error %d", err);
			if (iter)
				ccow_lookup_release(iter);
			je_free(stats_data);
			stats_data = NULL;
			return;
		}

		int pos = 0;
		struct ccow_metadata_kv *kv;
		while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX, pos++))) {
			/* Iterate through all the clusters */
			char *cid = (char *)kv->key;
			uint16_t cid_size = kv->key_size;

			err = ccow_cluster_accounting(tc, cid,  cid_size,
			    NULL, 0, 0, stats_data);
			if (err) {
				log_error(lg, "Cluster accounting error: %d", err);
				je_free(stats_data);
				stats_data = NULL;
				break;
			}
		}
		if (iter)
			ccow_lookup_release(iter);

		// Send total
		if (stats_data) {
			sprintf(buf, "%lu", stats_data->cluster_logical_size);
			log_info(lg, "Sending cluster_logical_size: %s, cluster_objects: %lu", buf, stats_data->cluster_objects);
			clengine_update_others(&uint128_null, CLENGINE_STAT_LOGICAL_USED,
			    buf);

			// Now we have total logical size and total estimated used - send it to AAS
			//
			auditc_objid(gauge, "cluster.total_logical_used", &uint128_null,
					stats_data->cluster_logical_size);
			auditc_objid(gauge, "cluster.total_estimated_used", &uint128_null,
					stats_data->cluster_estimated_used);
			auditc_objid(gauge, "cluster.total_objects", &uint128_null,
					stats_data->cluster_objects);
		}
	}

}


static void
ccowd_tenant_update(ccow_t tc)
{
	// Locals
	int err;
	int64_t tmp;
	char **keys;
	unsigned int key_count = 0;
	size_t val_size;
	char *ta_cid = NULL, *ta_tid = NULL;
	hashtable_t *ht = trlog_tenant_acct_ht;
	assert(ht);

	char buf[64];

	// Process transactions
	keys = (char **) hashtable_keys(ht, &key_count);
	for (unsigned int i = 0; i < key_count; i++) {
		// grab an entry by cid/tid
		size_t key_size = strlen(keys[i]) + 1;
		char *key_copy = je_malloc(key_size);
		if (!key_copy) {
			log_error(lg, "Unable to process key %s, out of memory", keys[i]);
			continue;
		}
		memcpy(key_copy, keys[i], key_size);
		trlog_entry_t *ent = hashtable_get(ht, keys[i], key_size, &val_size);
		log_debug(lg, "retrieved following: keys[i] : %s, ent: %p", keys[i], ent);
		if (!ent) {
			log_error(lg, "Unable to build hashtable info for %s", keys[i]);
			continue;
		}

		char *sp = NULL;
		char *token = strtok_r(key_copy, "/", &sp);
		if (!token) {
			log_error(lg, "Unable to process tenant accounting %s", keys[i]);
			continue;
		}
		ta_cid = token;
		token = strtok_r(NULL, "/", &sp);
		if (!token) {
			log_error(lg, "Unable to process tenant accounting %s", keys[i]);
			continue;
		}
		ta_tid = token;

		log_debug(lg, "Calling trlog_update_tenant_obj  %s/%s with delta_size: %ld deltaobs: %ld deltaused %ld",
				ta_cid, ta_tid, ent->delta_size, ent->delta_objs, ent->delta_used);

		err = trlog_update_tenant_obj(tc, ta_cid, ta_tid, ent->delta_size, ent->delta_objs, ent->delta_used);
		je_free(key_copy);
		if (err) {
			log_error(lg, "Unable to process tenant accounting %s, will retry later", keys[i]);
			continue;
		}

		log_debug(lg, "Removing key %s", keys[i]);
		hashtable_remove(ht, keys[i], key_size);
	}

	if (keys)
		je_free(keys);
}

//
// Serially update a cluster and tenant
//
int
trlog_update_tenant_obj(ccow_t tc, char *cid, char *tid,
		int64_t delta_size, int64_t delta_objs, int64_t delta_used)
{
	int err;
	ccow_completion_t c;
	if (delta_size == 0 && delta_objs == 0)
		return 0;
	// fill in the IOV
	struct iovec iov[3];
	msgpack_p *p[3];
	uv_buf_t ubuf[3];

	struct ccow_metadata_kv attr[3];
	uint64_t d_size = labs(delta_size) + 0LLU;
	uint64_t d_objs = labs(delta_objs) + 0LLU;
	uint64_t d_used = labs(delta_used) + 0LLU;

	log_debug(lg, "Putting %s/%s with delta_size: %ld deltaobs: %ld, deltaused: %ld",
			cid, tid, delta_size, delta_objs, delta_used);

	attr[0].mdtype = CCOW_MDTYPE_METADATA;
	attr[0].type = CCOW_KVTYPE_UINT64;
	attr[0].key = RT_SYSKEY_LOGICAL_SIZE;
	attr[0].key_size = strlen(RT_SYSKEY_LOGICAL_SIZE);
	attr[0].value = &d_size;
	attr[0].value_size = sizeof(d_size);
	err = ccow_pack_mdkv(&attr[0], &p[0]);
	if (err) {
		log_error(lg, "Invalid mdkv packing p[0] %d", err);
		return err;
	}
	err = msgpack_get_buffer(p[0], &ubuf[0]);
	if (err) {
		log_error(lg, "Invalid msgpacking p[0], err: %d", err);
		return -ENOMEM;;
	}
	iov[0].iov_base = ubuf[0].base;
	iov[0].iov_len = ubuf[0].len;

	attr[1].mdtype = CCOW_MDTYPE_METADATA;
	attr[1].type = CCOW_KVTYPE_UINT64;
	attr[1].key = RT_SYSKEY_OBJECT_COUNT;
	attr[1].key_size = strlen(RT_SYSKEY_OBJECT_COUNT);
	attr[1].value = &d_objs;
	attr[1].value_size = sizeof(d_objs);
	err = ccow_pack_mdkv(&attr[1], &p[1]);
	if (err) {
		log_error(lg, "Invalid mdkv packing p[1] %d", err);
		return err;
	}
	err = msgpack_get_buffer(p[1], &ubuf[1]);
	if (err) {
		log_error(lg, "Invalid msgpacking p[1], err: %d", err);
		msgpack_pack_free(p[0]);
		return -ENOMEM;;
	}
	iov[1].iov_base = ubuf[1].base;
	iov[1].iov_len = ubuf[1].len;

	attr[2].mdtype = CCOW_MDTYPE_METADATA;
	attr[2].type = CCOW_KVTYPE_UINT64;
	attr[2].key = RT_SYSKEY_ESTIMATED_USED;
	attr[2].key_size = strlen(RT_SYSKEY_ESTIMATED_USED);
	attr[2].value = &d_used;
	attr[2].value_size = sizeof(d_used);
	err = ccow_pack_mdkv(&attr[2], &p[2]);
	if (err) {
		log_error(lg, "Invalid mdkv packing p[2] %d", err);
		return err;
	}
	err = msgpack_get_buffer(p[2], &ubuf[2]);
	if (err) {
		log_error(lg, "Invalid msgpacking p[2], err: %d", err);
		msgpack_pack_free(p[0]);
		msgpack_pack_free(p[1]);
		return -ENOMEM;;
	}
	iov[2].iov_base = ubuf[2].base;
	iov[2].iov_len = ubuf[2].len;

	ccow_op_t optype = (delta_size < 0 || delta_objs < 0) ? CCOW_DELETE_MD : CCOW_INSERT_MD;

	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err)
		goto _local_err;
	err = ccow_container_update_list(cid, strlen(cid) + 1, tid, strlen(tid) + 1,
					 "", 1, "", 1, c, iov, 3, optype);
	if (err) {
		log_error(lg, "Err: %d Failed to update tenant %s/%s", err, cid, tid);
		ccow_release(c);
		goto _local_err;
	}
	err = ccow_wait(c, 0);
	if (err)
		log_error(lg, "Err: %d Failed to update tenant %s/%s", err, cid, tid);
_local_err:
	msgpack_pack_free(p[0]);
	msgpack_pack_free(p[1]);
	msgpack_pack_free(p[2]);
	return err;
}

static void
ccowd_tran_done(void *arg, int status)
{
	trlog_ht_free();
	ccow_daemon->tran_running = 0;
	log_debug(lg, "TRLOG processing complete");
}


static int
ccowd_tran_process(ccow_t tc, uint64_t batch_seq_ts)
{
	int err;
	struct mlist_node *result_head = NULL;
	uint64_t rec_count, cur_count;
	uint64_t time_spent_start = get_timestamp_us();

	log_debug(lg, "TRLOG merge %lu sort process is in progress", batch_seq_ts);

	err = trlog_mlist_get(&ccow_daemon->trhdl, tc, batch_seq_ts,
	    &result_head, &cur_count, trput_shard_check, NULL);
	if (err && err != -ENOENT) {
		log_warn(lg, "Error getting transaction log");
		return err;
	}

	struct mlist_node *merge_head = NULL;
	ccow_daemon->trhdl.back[ccow_daemon->trhdl.back_cnt] = result_head;
	rec_count = trlog_mlist_msort(ccow_daemon->trhdl.back, ccow_daemon->trhdl.back_cnt + 1,
		trlog_mlist_compare, &merge_head);

	log_debug(lg, "TRLOG cur_count: %lu merge count: %lu",
		cur_count, rec_count);

	/* actually process the final result */
	err = trput_process_result(tc, merge_head, rec_count,
		batch_seq_ts - (ccow_daemon->trlog_quarantine * ccow_daemon->trlog_interval_us));
	msort_free_list(merge_head, NULL);
	if (err) {
		msort_free_list(result_head, je_free);
		return err;
	}

	trlog_mlist_done(&ccow_daemon->trhdl, tc, result_head, 1);

	last_processed_time_ms = (get_timestamp_us() - time_spent_start) / 1000;
	log_info(lg, "TRLOG: processed result: %ld entries in %ldms",
		last_processed_entries, last_processed_time_ms);

	return 0;
}

/* Update inprog_seqid worker's completion on success */
static void
ccowd_tran_inprog_finished(uint64_t batch_seq_ts)
{
	uint128_t serverid = server_get()->id;
	char serveridstr[64];
	uint128_dump(&serverid, serveridstr, 64);
	char buf[128];
	sprintf(buf, "TRLOG_INPROG_BATCH_FINISHED.%s.%lu", serveridstr, batch_seq_ts);
	clengine_notify(buf);
}

static void
ccowd_tran_inprog_start(uint64_t batch_seq_ts)
{
	/* and send signal to all the workers */
	char buf[128];
	sprintf(buf, "TRLOG_INPROG_BATCH.%lu", batch_seq_ts);
	clengine_notify(buf);
}

static void
ccowd_tran_leader_exec(void *arg)
{
	int err;
	QUEUE *q;
	struct reptrans *rt = NULL;
	uint64_t batch_seq_ts = 0;
	ccow_t tc;
	uint64_t cts = 0;

	/* done - reset in progress shard marker, but only write it if we've init'd */
	if (flexhash_checkpoint_exists() == 0) {
		log_warn(lg, "TRLOG: checkpoint doesn't exist, skip operation");
		return;
	}

	QUEUE_FOREACH(q, &all_rts) {
		rt = QUEUE_DATA(q, struct reptrans, item);
		break;
	}
	if (!rt)
		return;

	pthread_setname_np(pthread_self(), "tran_lead");

_restart_behind:

	/* we will force timer restart here */
	if (!is_cluster_healthy(rt, RT_SYSVAL_REPLICATION_COUNT)) {
		log_warn(lg, "TRLOG: check warning - cluster is not healthy, "
		    "need a way to store at least %d replicas",
		    RT_SYSVAL_REPLICATION_COUNT);
		if (!ccow_daemon->leader || ccowd_terminating)
			return;

		usleep(3000000);

		/** Loop until cluster is not healthy */
		goto _restart_behind;
	}

	// Send tenant accounting
	tc = reptrans_get_tenant_context(rt, 0);
	if (!tc)
		return;

	ccowd_tenant_send(tc);

	reptrans_put_tenant_context(rt, tc);


	/*
	 * Send coordinated TRLOG batch CTS (coordinated time stamp) from
	 * the leader. CTS is used merely to synchronize time on all the nodes
	 * to the leader's time (based on CTS w/ by default
	 * of 10s intervals).
	 *
	 * It is responsibility of VDEVs to quickly "flush" batches,
	 * independently of a leader.
	 */
	if (!cts && ccow_daemon->role_changed) {
		char buf[128];

		cts = get_nondecreasing_timestamp_us();
		sprintf(buf, "TRLOG_CTS.%lu", cts);
		clengine_notify(buf);
		ccow_daemon->role_changed = 0;
	}

	tc = reptrans_get_tenant_context(rt, 0);
	if (!tc)
		return;

	err = trlog_read_marker_seq_tss(tc, NULL, SHARD_LEADER_PREFIX,
			&batch_seq_ts, (uint64_t*)&batch_seq_prev_ts);
	if (err) {
		log_warn(lg, "TRLOG flush check postponed - cannot read %s",
		    SHARD_LEADER_PREFIX);
		goto _err;
	}
	/*
	 * States:
	 * =======
	 *		batch_seq_ts	batch_seq_prev_ts
	 * ------------ --------------- -----------------
	 * INIT		0		0
	 * INPROG	TS		PREV_TS
	 * READY	0		TS
	 */
	if (batch_seq_ts == 0) {
		if (batch_seq_prev_ts == 0) {
			/* INIT, transition to INPROG */
			batch_seq_ts = cts - (cts % ccow_daemon->trlog_interval_us);
		} else {
			/* READY, transition to INPROG */
			batch_seq_ts = batch_seq_prev_ts + ccow_daemon->trlog_interval_us;
		}
		log_info(lg, "New TRLOG batch seq %lu seq_prev %lu",
		    batch_seq_ts, batch_seq_prev_ts);

		/* now in-progress - update shard marker */
		err = trlog_write_marker_seq_tss(tc, SHARD_LEADER_PREFIX,
				batch_seq_ts, batch_seq_prev_ts);
		if (err) {
			log_error(lg, "Failed to update write marker for %s",
			    SHARD_LEADER_PREFIX);
			goto _err;
		}

		/* and send signal to all the workers */
		ccowd_tran_inprog_start(batch_seq_ts);
	} else {
		/* INPROG, continue */
		log_info(lg, "Previous TRLOG batch seq %lu seq_prev %lu - continue",
		    batch_seq_ts, batch_seq_prev_ts);
	}

	reptrans_put_tenant_context(rt, tc);

	/* Wait for stable batch sequence point in time */
	do {
		flexhash_lock(SERVER_FLEXHASH);
		err = flexhash_check_seqid(SERVER_FLEXHASH, batch_seq_ts);
		flexhash_unlock(SERVER_FLEXHASH);
		if (!ccow_daemon->leader || ccowd_terminating ||
		    !is_cluster_healthy(rt, RT_SYSVAL_REPLICATION_COUNT)) {
			return;
		}
		if (err)
			usleep(1000000);
	} while (err);

	tc = reptrans_get_tenant_context(rt, 0);
	if (!tc)
		return;

	err = ccowd_tran_process(tc, batch_seq_ts);
	if (err)
		goto _err;

	reptrans_put_tenant_context(rt, tc);

	/* Update inprog_seqid leader's completion */
	ccowd_tran_inprog_finished(batch_seq_ts);

	/* Wait for batch sequence completion */
	int wait_cnt = 0;
	do {
		flexhash_lock(SERVER_FLEXHASH);
		err = flexhash_check_inprog_seqid(SERVER_FLEXHASH, batch_seq_ts);
		flexhash_unlock(SERVER_FLEXHASH);
		if (!ccow_daemon->leader || ccowd_terminating ||
		    !is_cluster_healthy(rt, RT_SYSVAL_REPLICATION_COUNT)) {
			return;
		}
		if (err) {
			usleep(100000);
			/* startup corner case: insist on our current batch_seq_ts
			 * by reminding it every 10s here.. */
			if ((wait_cnt++ % 100) == 0) {
				ccowd_tran_inprog_finished(batch_seq_ts);
				ccowd_tran_inprog_start(batch_seq_ts);
			}
		}
	} while (err);

	tc = reptrans_get_tenant_context(rt, 0);
	if (!tc)
		return;

_write_again:
	err = trlog_write_marker_seq_tss(tc, SHARD_LEADER_PREFIX, 0LU, batch_seq_ts);
	if (err) {
		if (err != -ENOSPC)
			log_error(lg, "Failed to update write marker for %s",
				SHARD_LEADER_PREFIX);
		else
			log_warn(lg, "Failed to update write marker for %s: "
				"out of space", SHARD_LEADER_PREFIX);

		if (!ccowd_terminating) {
			usleep(1000000);
			goto _write_again;
		}
	} else {
		/* Now perform tenant accounting */
		ccowd_tenant_update(tc);
	}

_err:
	reptrans_put_tenant_context(rt, tc);

	cts = get_nondecreasing_timestamp_us();

	/* need to keep 2 x trlog_interval_us window to avoid stale entries */
	if (!err && batch_seq_ts && (batch_seq_ts + 2 * ccow_daemon->trlog_interval_us) < cts) {
		log_info(lg, "Continue TRLOG leader processing due to its beign behind current time by %lds",
		    (cts - (batch_seq_ts + 2 * ccow_daemon->trlog_interval_us))/1000000UL);
		trlog_ht_free();
		trlog_ht_create();
		goto _restart_behind;
	}
}

static void
ccowd_tran_worker_exec(void *arg)
{
	int err;
	QUEUE *q;
	struct reptrans *rt = NULL;
	uint64_t batch_seq_ts;

	/* done - reset in progress shard marker, but only write it if we've init'd */
	if (flexhash_checkpoint_exists() == 0) {
		log_warn(lg, "TRLOG: checkpoint doesn't exist, skip operation");
		return;
	}

	QUEUE_FOREACH(q, &all_rts) {
		rt = QUEUE_DATA(q, struct reptrans, item);
		break;
	}
	if (!rt)
		return;

	pthread_setname_np(pthread_self(), "tran_wrk");

_restart_behind:

	/* we will force timer restart here */
	if (!is_cluster_healthy(rt, RT_SYSVAL_REPLICATION_COUNT)) {
		log_warn(lg, "TRLOG: check warning - cluster is not healthy, "
		    "need a way to store at least %d replicas",
		    RT_SYSVAL_REPLICATION_COUNT);
		return;
	}

	int wait_cnt = 0;
	ccowd_fhready_lock(FH_LOCK_READ);
	while (ccow_daemon->local_batch_seq_ts == ccow_daemon->leader_batch_seq_ts) {
		ccowd_fhready_unlock(FH_LOCK_READ);
		/* Wait for coordinated start signal which will update
		 * leader_batch_seq_ts (increment) */
		usleep(100000);
		if (ccow_daemon->leader || ccowd_terminating ||
		    !is_cluster_healthy(rt, RT_SYSVAL_REPLICATION_COUNT))
			return;
		/* worker coordination corner case: insist on our current
		 * local batch_seq_ts by reminding it every 10s here.. */
		if ((wait_cnt++ % 100) == 0 && ccow_daemon->local_batch_seq_ts)
			ccowd_tran_inprog_finished(ccow_daemon->local_batch_seq_ts);
		ccowd_fhready_lock(FH_LOCK_READ);
	}

	batch_seq_ts = ccow_daemon->leader_batch_seq_ts;
	ccowd_fhready_unlock(FH_LOCK_READ);

	/* Wait for stable batch sequence point in time */
	do {
		flexhash_lock(SERVER_FLEXHASH);
		err = flexhash_check_seqid(SERVER_FLEXHASH, batch_seq_ts);
		flexhash_unlock(SERVER_FLEXHASH);
		if (ccowd_terminating ||
		    !is_cluster_healthy(rt, RT_SYSVAL_REPLICATION_COUNT)) {
			return;
		}
		if (err)
			usleep(1000000);
	} while (err);

	ccow_t tc = reptrans_get_tenant_context(rt, 0);
	if (!tc)
		return;

	err = ccowd_tran_process(tc, batch_seq_ts);
	if (err)
		goto _err;

	/* Now perform tenant accounting */
	ccowd_tenant_update(tc);

	/* Update inprog_seqid worker's completion on success */
	ccowd_tran_inprog_finished(batch_seq_ts);

	ccow_daemon->local_batch_seq_ts = batch_seq_ts;

_err:
	reptrans_put_tenant_context(rt, tc);

	uint64_t cts = get_timestamp_us();

	/* need to keep 2 x trlog_interval_us window to avoid stale entries */
	if (!err && batch_seq_ts && (batch_seq_ts + 2 * ccow_daemon->trlog_interval_us) < cts) {
		log_info(lg, "Continue TRLOG worker processing due to its beign behind current time by %lds",
		    (cts - (batch_seq_ts + 2 * ccow_daemon->trlog_interval_us))/1000000UL);
		trlog_ht_free();
		trlog_ht_create();
		goto _restart_behind;
	}
}

/** Entry point */
void
ccowd_tran_start(void)
{
	trlog_ht_create();

	if (ccow_daemon->leader) {
		ccowtp_work_queue(ccow_daemon->tp, CCOWD_TP_PRIO_HI, ccowd_tran_leader_exec,
		    ccowd_tran_done, NULL);
	} else {
		ccowtp_work_queue(ccow_daemon->tp, CCOWD_TP_PRIO_HI, ccowd_tran_worker_exec,
		    ccowd_tran_done, NULL);
	}
}

/** TrLog HashTable create */
void
trlog_ht_create(void)
{
	if (trlog_tenant_acct_ht != NULL)
		return;
	trlog_tenant_acct_ht = hashtable_create(TRLOG_HT_SIZE, 0,
	    TRLOG_HT_MAX_LOAD_FACTOR);
	assert(trlog_tenant_acct_ht);

}

int
trlog_ht_put(char *cid_tid, trlog_entry_t *ent)
{
	assert(trlog_tenant_acct_ht != NULL);
	assert(cid_tid != NULL);
	assert(ent != NULL);
	int err = hashtable_put(trlog_tenant_acct_ht, cid_tid, strlen(cid_tid) + 1,
	    ent, sizeof(trlog_entry_t));
	return err;
}

int
trlog_ht_get(char *cid_tid, trlog_entry_t **ent)
{
	assert(trlog_tenant_acct_ht != NULL);
	assert(cid_tid != NULL);
	assert(ent != NULL);

	uint32_t hv;
	size_t ent_size;
	*ent = hashtable_get(trlog_tenant_acct_ht, cid_tid, strlen(cid_tid) + 1, &ent_size);

	if (*ent != NULL)
		assert(ent_size == sizeof(trlog_entry_t));
	return (*ent != NULL);
}

void
trlog_ht_free(void)
{
	hashtable_t *ht = trlog_tenant_acct_ht;
	if (!ht)
		return;
	char **keys;
	unsigned int key_count;

	keys = (char **) hashtable_keys(ht, &key_count);

	log_debug(lg, "Free tenant accounting table, key_count: %u", key_count);

	if (key_count > 0)
		return;

	trlog_tenant_acct_ht = NULL;
	if (keys)
		je_free(keys);
	hashtable_destroy(ht);
}
