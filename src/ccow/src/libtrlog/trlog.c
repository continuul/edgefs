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

#include "trlog.h"
#include "ccow.h"
#include "ccowutil.h"
#include "rtbuf.h"
#include "replicast.h"
#include "flexhash.h"
#include "ccow-impl.h"


#define TRLOG_OLD_RESULT_HT_SIZE	32768

#define TRLOG_KEY_UNIQUE_LEN \
		/* phid   */ (UINT512_STR_BYTES + \
		/* nhid   */  UINT512_STR_BYTES + \
		/* genid  */  UINT128_STR_BYTES + \
		/* ts     */  UINT128_STR_BYTES + \
		/* vmchid */  UINT512_STR_BYTES + \
		/* sepa   */  5)

int
trlog_read_marker(ccow_t tc, char *name, char **marker_arr, int *marker_arr_len)
{
	int err = 0;
	uint32_t i = 0;
	ccow_completion_t c;
	msgpack_u *u = NULL;
	char buf[TRLOG_MARKER_MAXSIZE];
	struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };

	*marker_arr_len = 0;

	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err)
		return err;

	char markerbuf[1024];
	snprintf(markerbuf, 1024, TRLOG_TID_PREFIX "%s", name);
        err = ccow_admin_pseudo_get("", 1, markerbuf, strlen(markerbuf) + 1,
	    "marker", 7, "marker", 7, &iov, 1, 0, CCOW_GET, c, NULL);
	if (err) {
		ccow_release(c);
		return err;
	}
	err = ccow_wait(c, 0);
	if (err == -ENOENT) {
		/* we still have to have marker_arr preallocated */
		return err;
	}
	if (err)
		goto _err;

	u = msgpack_unpack_init(iov.iov_base, iov.iov_len, 0);
	if (!u) {
		err = -ENOMEM;
		goto _err;
	}

	uint32_t n;
	err = msgpack_unpack_array(u, &n);
	if (err)
		goto _err;
	for (i = 0; i < n; i++) {
		char *tmp = marker_arr[i];
		if (!tmp) {
			err = -ENOMEM;
			goto _err;
		}
		err = msgpack_unpack_str(u, tmp, REPLICAST_STR_MAXLEN);
		if (err)
			goto _err;

		marker_arr[i] = tmp;
	}

	*marker_arr_len = n;

_err:
	if (err) {
		for (uint32_t j = 0; j < i; j++)
			je_free(marker_arr[j]);
	}
	if (u)
		msgpack_unpack_free(u);
	return err;
}

static int
trlog_fetch_buckets(ccow_t tc, char *tid, char ***bid_arr, int *bid_arr_len)
{
	int err = 0, pos = 0;
	char **arr = NULL;
	struct iovec iov = { .iov_base = "", .iov_len = 1 };
	ccow_lookup_t bkt_iter;

	*bid_arr = NULL;
	*bid_arr_len = 0;

        ccow_completion_t c;
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "Unable to create completion for trlog processing "
		    "while fetching tenants: %d", err);
		return err;
	}

	// Fetch the list of buckets (vdevs) for the node
        err = ccow_admin_pseudo_get("", 1, tid, strlen(tid) + 1, "", 1, "", 1,
	    &iov, 1, FLEXHASH_MAX_VDEVS, CCOW_GET_LIST, c, &bkt_iter);
	if (err) {
		ccow_release(c);
		return err;
	}
	err = ccow_wait(c, 0);
	if (err) {
		if (bkt_iter)
			ccow_lookup_release(bkt_iter);
		if (err != -ENOENT)
			log_error(lg, "Cannot list TRLOG vdev buckets under "
			    "serverid %s error %d", tid, err);
		return err;
	}

	arr = je_malloc(FLEXHASH_MAX_VDEVS * sizeof(char *));
	if (!arr) {
		err = -ENOMEM;
		log_error(lg, "%s: out of memory", __func__);
		goto _err;
	}

	struct ccow_metadata_kv *kv = NULL;
	while ((kv = ccow_lookup_iter(bkt_iter, CCOW_MDTYPE_NAME_INDEX, pos))) {
		arr[pos] = je_strdup(kv->key);
		if (!arr[pos]) {
			err = -ENOMEM;
			log_error(lg, "%s: out of memory", __func__);
			goto _err;
		}
		pos++;
	}
	if (pos == 0) {
		je_free(arr);
		arr = NULL;
	}

	*bid_arr = arr;
	*bid_arr_len = pos;
_err:
	if (err && arr) {
		for (int j = 0; j < pos; j++)
			je_free(arr[j]);
		je_free(arr);
	}
	if (bkt_iter)
		ccow_lookup_release(bkt_iter);
	return err;
}

//
// /TRLOG-ABC/vdev1/tsobj1
// /TRLOG-DEF/vdev1/tsobj2
//
// We will search for /TRLOG-DEF/vdev1/ and the marker will be "tsobj2"
// This will find the last processed tsobj within vdev1/ bucket and will be then
// used as the PREFIX for the search of the next object (returns next larger/newer)
//
static int
trlog_find_marker(ccow_t tc, char **marker_arr, int marker_arr_len,
    char *tid, char *bid, char **prev_marker, int *prev_marker_pos)
{
	char buf[1024];
	int i;

	*prev_marker = NULL;
	*prev_marker_pos = -1;

	sprintf(buf, "%s/%s/", tid, bid);
	for (i = 0; i < marker_arr_len; i++) {
		uint32_t pos = strlen(buf);
		if (memcmp(marker_arr[i], buf, pos) == 0) {
			*prev_marker = je_strdup(marker_arr[i] + pos);
			if (!*prev_marker)
				return -ENOMEM;
			*prev_marker_pos = i;
			return 0;
		}
	}
	return -ENOENT;
}

static int
trlog_fetch_tenants(ccow_t tc, char ***tid_arr, int *tid_arr_len)
{
	int err = 0;
	char **arr = NULL;
	int pos = 0;
	struct ccow_metadata_kv *kv = NULL;
	ccow_lookup_t iter = NULL;

	*tid_arr = NULL;
	*tid_arr_len = 0;

        ccow_completion_t c;
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "Unable to create completion for trlog processing "
		    "while fetching tenants: %d", err);
		return err;
	}

	struct iovec iov = { .iov_base = TRLOG_TID_PREFIX,
		.iov_len = strlen(TRLOG_TID_PREFIX) + 1};
        err = ccow_admin_pseudo_get("", 1, "", 1, "", 1, "", 1,
	    &iov, 1, FLEXHASH_MAX_SERVERS, CCOW_GET_LIST, c, &iter);
	if (err) {
		ccow_release(c);
		return err;
	}

	err = ccow_wait(c, 0);
	if (err) {
		if (iter)
			ccow_lookup_release(iter);
		if (err != -ENOENT)
			log_error(lg, "Tenant lookup error: %d", err);
		return err;
	}

	if (iter == 0) {
		log_warn(lg, "Tenant lookup error: %d (invalid param)", -EINVAL);
		return -EINVAL;
	}

	arr = je_calloc(FLEXHASH_MAX_SERVERS, sizeof(char *));
	if (!arr) {
		log_error(lg, "%s: out of memory", __func__);
		goto _err;
	}

	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX, pos))) {
		if (strspn(kv->key, TRLOG_TID_PREFIX) != strlen(TRLOG_TID_PREFIX))
			break;
		arr[pos] = je_strdup(kv->key);
		if (!arr[pos]) {
			log_error(lg, "%s: out of memory", __func__);
			goto _err;
		}
		pos++;
	}
	if (pos == 0) {
		je_free(arr);
		arr = NULL;
	}

	*tid_arr = arr;
	*tid_arr_len = pos;

_err:
	if (err && arr) {
		for (int i = 0; i < pos; i++)
			je_free(arr[i]);
		je_free(arr);
	}
	if (iter)
		ccow_lookup_release(iter);
	return err;
}

int
trlog_write_marker(ccow_t tc, char *name, char **marker_arr, int marker_arr_len)
{
	int err = 0;
	struct iovec iov;
	ccow_completion_t c;
	ccow_lookup_t iter;
	msgpack_p *p = NULL;

	if (marker_arr_len == 1)
		log_debug(lg, "Updating TRLOG marker %s: %s",
		    name, marker_arr[0]);
	else if (marker_arr_len == 2)
		log_debug(lg, "Updating TRLOG marker %s: %s %s",
		    name, marker_arr[0], marker_arr[1]);
	else
		log_debug(lg, "Updating TRLOG marker %s: %s %s %s",
		    name, marker_arr[0], marker_arr[1], marker_arr[2]);

	p = msgpack_pack_init();
	if (!p)
		return -ENOMEM;

	err = msgpack_pack_array(p, marker_arr_len);
	if (err) {
		err = -ENOMEM;
		goto _err;
	}

	for (int i = 0; i < marker_arr_len; i++) {
		err = msgpack_pack_str(p, marker_arr[i]);
		if (err)
			goto _err;
	}

	/*
	 * libuv header file says uv_buf_t and struct iovec can be used
	 * interchangeably.
	 */
	msgpack_get_buffer(p, (uv_buf_t *)&iov);

	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err)
		goto _err;

	uint16_t num_vers = 1;
	err = ccow_attr_modify_default(c, CCOW_ATTR_NUMBER_OF_VERSIONS,
	    (void *)&num_vers, NULL);
	if (err) {
		ccow_release(c);
		goto _err;
	}

	uint16_t dis = 1;
	err = ccow_attr_modify_default(c, CCOW_ATTR_TRACK_STATISTICS,
	    (void *)&dis, NULL);
	if (err) {
		ccow_release(c);
		goto _err;
	}

	char *chunkmap_type = "btree_map";
	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_TYPE,
	    (void *)chunkmap_type, NULL);
	if (err) {
		ccow_release(c);
		goto _err;
	}

	uint32_t bs = TRLOG_MARKER_MAXSIZE;
	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
	    (void *)&bs, NULL);
	if (err) {
		ccow_release(c);
		goto _err;
	}

	char markerbuf[1024];
	snprintf(markerbuf, 1024, TRLOG_TID_PREFIX "%s", name);
	err = ccow_tenant_put("", 1, markerbuf, strlen(markerbuf) + 1,
			"marker", 7, "marker", 7,
			c, &iov, 1, 0, CCOW_PUT, NULL, RD_ATTR_OBJECT_REPLACE);
	if (err) {
		ccow_release(c);
		goto _err;
	}
	err = ccow_wait(c, 0);
	if (err)
		goto _err;

_err:
	if (p)
		msgpack_pack_free(p);
	return err;
}

static int
trlog_get_next_tsobj(ccow_t tc, char *tid, char *bid, char *prev_marker,
    char **tsobj)
{
	int err = 0;
	char **arr = NULL;
	struct iovec iov;
	ccow_lookup_t bkt_iter = NULL;

	if (prev_marker) {
		iov.iov_base = prev_marker;
		iov.iov_len = strlen(prev_marker) + 1;
	} else {
		/* search from the beginning */
		iov.iov_base = "";
		iov.iov_len = 1;
	}

	if (tsobj)
		*tsobj = NULL;

        ccow_completion_t c;
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "Unable to create completion for trlog processing "
		    "while fetching tsobj: %d", err);
		goto _err;
	}

	// Fetch the list of buckets (vdevs) for the node
        err = ccow_admin_pseudo_get("", 1, tid, strlen(tid) + 1, bid,
	    strlen(bid) + 1, "", 1, &iov, 1, 2, CCOW_GET_LIST, c, &bkt_iter);
	if (err) {
		ccow_release(c);
		goto _err;
	}
	err = ccow_wait(c, 0);
	if (err) {
		if (err != -ENOENT)
			log_error(lg, "Cannot list TSOBJ error %d", err);
		goto _err;
	}

	struct ccow_metadata_kv *kv = NULL;
	int pos = 0;
	while ((kv = ccow_lookup_iter(bkt_iter, CCOW_MDTYPE_NAME_INDEX, pos))) {
		if (prev_marker && strcmp(kv->key, prev_marker) == 0) {
			if (!tsobj) {
				/* found, get out */
				err = 0;
				goto _err;
			}
			if (pos++ == 0) {
				/* found and return next tsobj */
				continue;
			}
		}
		if (!tsobj) {
			/* not found, get out */
			err = -ENOENT;
			goto _err;
		}
		*tsobj = je_strdup(kv->key);
		if (!*tsobj) {
			err = -ENOMEM;
			goto _err;
		}
		break;
	}
	if (!*tsobj)
		err = -ENOENT;
_err:
	if (bkt_iter)
		ccow_lookup_release(bkt_iter);
	return err;
}

static int
trlog_read_tsobj(ccow_t tc, char *tid, char *bid, char *tsobj,
    struct mlist_node **tsobj_head, int *nread,
    trlog_phid_check_cb_t check_func, void *check_func_phid)
{
	int err = 0, pos = 0, added = 0;
	ccow_lookup_t iter;
	struct mlist_node *head = NULL, *tail = NULL;

	*tsobj_head = NULL;
	*nread = 0;

	log_debug(lg, "Reading TSOBJ: %s/%s/%s", tid, bid, tsobj);

        ccow_completion_t c;
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "Unable to create completion for trlog processing "
		    "while retrieving tsobj %s/%s/%s: %d", tid, bid, tsobj, err);
		return err;
	}

	// Fetch TRLOG contents for this tsobj epoch
	// Use check_func PHID filter if supplied to speed up index lookups
	char phidstr[UINT512_BYTES*2+1];
	struct iovec iov = { .iov_base = "", .iov_len = 1 };
	if (check_func_phid) {
		uint512_t *phid_filter = check_func_phid;
		uint512_dump(phid_filter, phidstr, UINT512_BYTES*2+1);
		iov.iov_base = phidstr;
		iov.iov_len = strlen(phidstr);
	}

	err = ccow_admin_pseudo_get("", 1, tid, strlen(tid) + 1,
	    bid, strlen(bid) + 1, tsobj, strlen(tsobj) + 1,
	    &iov, 1, 10*TRLOG_TSOBJ_MAX_ENTRIES, CCOW_GET_LIST, c, &iter);
	if (err) {
		ccow_release(c);
		return err;
	}
	err = ccow_wait(c, 0);
	if (err) {
		if (iter)
			ccow_lookup_release(iter);
		if (err != -ENOENT)
			log_error(lg, "Cannot list TRLOG vdev buckets under "
			    "serverid %s error %d", tid, err);
		return err;
	}

	int prev_ok = -1;
	uint512_t phid_prev = uint512_null;
	struct ccow_metadata_kv *kv = NULL;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX, pos))) {
		if (check_func) {
			uint512_t phid;

			uint512_fromhex(kv->key, UINT512_STR_BYTES, &phid);

			if (uint512_cmp(&phid, &uint512_null) == 0) {
				pos++;
				continue;
			}

			/* optimization to avoid check_func() calls if prev
			 * is same phid as we just tested */
			if (prev_ok != -1 && uint512_cmp(&phid, &phid_prev) == 0) {
				if (prev_ok == 0) {
					pos++;
					continue;
				}
			} else {
				phid_prev = phid;
				if (check_func(&phid, check_func_phid) == 0) {
					pos++;
					prev_ok = 0;
					continue;
				}
				prev_ok = 1;
			}
		}
		struct mlist_node *mn = je_malloc(sizeof (*mn));
		if (!mn) {
			err = -ENOMEM;
			goto _err;
		}
		mn->next = NULL;
		mn->data = je_strdup(kv->key);
		if (!mn->data) {
			err = -ENOMEM;
			je_free(mn);
			goto _err;
		}
		/* TODO: Sort the list here?? */
		if (!head)
			head = tail = mn;
		else {
			/* Use tail to append the record */
			tail->next = mn;
			tail = mn;
		}
		pos++;
		added++;
	}

	*nread = added;
	*tsobj_head = head;
	head = NULL;

_err:
	if (err && head) {
		msort_free_list(head, je_free);
	}
	if (iter)
		ccow_lookup_release(iter);
	return err;
}

uint64_t
trlog_mlist_count(struct mlist_node *head)
{
	struct mlist_node *t = head;
	uint64_t count = 0;

	while (t != NULL) {
		count++;
		t = t->next;
	}

	return count;
}

int
trlog_mlist_compare(void *d1, void *d2)
{
	return strncmp(d1, d2, TRLOG_KEY_UNIQUE_LEN);
}


static int
find_list_min(struct mlist_node *l[], int num, msort_compare_fn compare_cb) {
	int rc;
	int imin = -1;
	void *dmin = NULL;
	for (int i=0; i<num; i++) {
		if (!l[i])
			continue;
		if (!dmin) {
			imin = i;
			dmin = l[i]->data;
			continue;
		}
		rc = compare_cb(l[i]->data, dmin);
		if (rc < 0) {
			imin = i;
			dmin = l[i]->data;
			continue;
		}
		if (rc == 0) {
			l[i] = l[i]->next;
		}
	}
	return imin;
}

/* Merge of num sorted lists (each list must have been sorted first) */
int
trlog_mlist_msort(struct mlist_node *list[], int num,
	msort_compare_fn compare_cb, struct mlist_node **merge_head)
{
	int rc;
	int count = 0;
	struct mlist_node *l[num];

	for (int i=0; i < num; i++) {
		l[i] = list[i];
	}

	/* Set the merge list head */
	*merge_head = NULL;

	int imin = find_list_min(l, num, compare_cb);

	if (imin < 0)
		return count;

	struct mlist_node *cur = NULL;

	while (imin >= 0) {
		if (!cur) {
			cur = (struct mlist_node *)je_calloc(1, sizeof(struct mlist_node));
			*merge_head = cur;
		} else {
			cur->next = (struct mlist_node *)je_calloc(1, sizeof(struct mlist_node));
			cur = cur->next;
		}
		count++;
		cur->data = l[imin]->data;
		l[imin] = l[imin]->next;
		imin = find_list_min(l, num, compare_cb);
	}
	return count;
}

static void
trlog_mlist_remove_dup(struct mlist_node *start)
{
	struct mlist_node *p, *tmp;

	p = start;
	while (p != NULL && p->next != NULL) {
		if (trlog_mlist_compare(p->data, p->next->data) == 0) {
			log_debug(lg, "TRLOG: delete dup %s", (char*)p->data);
			tmp = p->next;
			p->next = p->next->next;
			je_free(tmp->data);
			je_free(tmp);
		} else
			p = p->next;
	}
}

int
trlog_mlist_ht_exists(struct trlog_handle *hdl, struct mlist_node *node)
{
	return hashtable_contains(hdl->old_result_ht, node->data, strlen(node->data));
}

static struct mlist_node *
trlog_mlist_find_remove(struct trlog_handle *hdl, struct mlist_node *result_head)
{
	struct mlist_node *t = result_head, *prev = NULL, *result = result_head;

	while (t != NULL) {
		if (hashtable_contains(hdl->old_result_ht,
			    t->data, strlen(t->data))) {
			log_debug(lg, "TRLOG: delete overlap %s", (char*)t->data);
			if (t == result)
				result = t->next;
			if (prev)
				prev->next = t->next;
			struct mlist_node *tmp = t->next;
			je_free(t->data);
			je_free(t);
			t = tmp;
		} else {
			prev = t;
			t = t->next;
		}
	}

	return result;
}

static struct mlist_node *
trlog_mlist_skip_insdel(struct mlist_node *start)
{
	struct mlist_node *p, *tmp, *prev = NULL, *result = start;
	int err;

	p = start;
	while (p != NULL && p->next != NULL) {
		struct trlog_data rec1, rec2;
		char entry[TRLOG_KEY_LEN];

		strcpy(entry, (char*)p->data);
		err = trlog_extract_key(entry, strlen(entry), &rec1, 1);
		if (err)
			return result;
		strcpy(entry, (char*)p->next->data);
		err = trlog_extract_key(entry, strlen(entry), &rec2, 1);
		if (err) {
			MEMFREE_TRLOG_DATA(rec1);
			return result;
		}

		if (uint512_cmp(&rec1.phid, &rec2.phid) == 0 &&
		    uint512_cmp(&rec1.nhid, &rec2.nhid) == 0 &&
		    rec1.generation + 1 == rec2.generation &&
		    (rec1.trtype & TRLOG_OBJ_CREATE) &&
		    (rec2.trtype & TRLOG_OBJ_DELETE)) {
			log_debug(lg, "TRLOG: skip insdel %s", (char*)p->data);
			log_debug(lg, "TRLOG: skip insdel %s", (char*)p->next->data);

			/* set p to the entry after delete */
			tmp = p->next->next;

			/* head? update... we have new start */
			if (p == start) {
				start = result = tmp;
			}

			/* update prev pointer */
			if (prev)
				prev->next = tmp;

			/* delete delete entry */
			je_free(p->next->data);
			je_free(p->next);

			/* delete insert entry */
			je_free(p->data);
			je_free(p);

			p = tmp;
		} else {
			prev = p;
			p = p->next;
		}
		MEMFREE_TRLOG_DATA(rec1);
		MEMFREE_TRLOG_DATA(rec2);
	}

	return result;
}

static int
trlog_mlist_get_all(ccow_t tc, uint64_t batch_seq_ts,
    struct mlist_node **all_result_head, int *tsobj_added,
    trlog_phid_check_cb_t check_func, void *check_func_phid)
{
	int err;
	char **tid_arr = NULL;
	int tid_arr_len = 0;
	char **bid_arr = NULL;
	int bid_arr_len = 0;
	char tsobj[24];
	struct mlist_node *result_head = NULL;

	*tsobj_added = 0;
	err = trlog_fetch_tenants(tc, &tid_arr, &tid_arr_len);
	if (err)
		goto _err;

	//
	// Lookup for specific TSObj
	//
	snprintf(tsobj, 24, "%023lu", batch_seq_ts);

	bid_arr = NULL;
	bid_arr_len = 0;
	for (int i = 0; i < tid_arr_len; i++) {
		//
		//  We have a list of TRLOG-serverid, fetch the vdevs into bid_arr
		//
		bid_arr_len = 0;
		bid_arr = NULL;
		err = trlog_fetch_buckets(tc, tid_arr[i], &bid_arr, &bid_arr_len);
		if (err == -ENOENT) {
			continue;
		} else if (err) {
			goto _err;
		}

		for (int j = 0; j < bid_arr_len; j++) {
			//
			// Read this new TSobj and add its btn contents to mlist_node
			//
			struct mlist_node *tsobj_head;
			int nread;
			err = trlog_read_tsobj(tc, tid_arr[i], bid_arr[j], tsobj,
			    &tsobj_head, &nread, check_func, check_func_phid);
			if (err || nread == 0)
				continue;

			//
			// Merge the tsobj entries into our running sorted mlist
			//
			assert(result_head != NULL || tsobj_head != NULL);
			result_head = msort_merge_lists(result_head,
			    tsobj_head, trlog_mlist_compare);
			assert(result_head);

			(*tsobj_added)++;
		}

		for (int i = 0; i < bid_arr_len; i++) {
			assert(bid_arr[i]);
			je_free(bid_arr[i]);
			bid_arr[i] = NULL;
		}
		je_free(bid_arr);
		bid_arr = NULL;
	}

	err = 0;
	*all_result_head = result_head;

_err:
	if (err)
		msort_free_list(result_head, je_free);

	if (bid_arr) {
		for (int i = 0; i < bid_arr_len; i++) {
			assert(bid_arr[i]);
			je_free(bid_arr[i]);
		}
		je_free(bid_arr);
	}
	if (tid_arr) {
		for (int i = 0; i < tid_arr_len; i++) {
			assert(tid_arr[i]);
			je_free(tid_arr[i]);
		}
		je_free(tid_arr);
	}

	return err;
}

int
trlog_mlist_get(struct trlog_handle *hdl, ccow_t tc, uint64_t batch_seq_ts,
    struct mlist_node **final_result_head, uint64_t *count,
    trlog_phid_check_cb_t check_func, void *check_func_phid)
{
	int err, tsobj_added;
	struct mlist_node *result_head = NULL;

	*count = 0;

	err = trlog_mlist_get_all(tc, batch_seq_ts, &result_head, &tsobj_added,
	    check_func, check_func_phid);
	if (err && err != -ENOENT) {
		log_warn(lg, "Failed to read transaction logs");
		return err;
	}
	if (tsobj_added == 0 || !result_head) {
		return -ENOENT;
	}

	/* remove duplicate records */
	trlog_mlist_remove_dup(result_head);

	/* remove overlaping records vs. previous timer runs */
	if (hdl->old_result_head) {
		result_head = trlog_mlist_find_remove(hdl, result_head);
	}

	// FIXME: May cause fantom records appear in case of create v1, create v1, delete
	//result_head = trlog_mlist_skip_insdel(result_head);

	*count = trlog_mlist_count(result_head);
	*final_result_head = result_head;

	return 0;
}

static void
trlog_old_result_ht_add(struct trlog_handle *hdl,
    struct mlist_node *result_head)
{
	struct mlist_node *node = result_head;
	int entries = 0;
	while (node) {
		int err = hashtable_put(hdl->old_result_ht, node->data,
		    strlen(node->data), NULL, 0);
		if (err) {
			log_warn(lg, "Cannot add entry to ht");
		} else
			entries++;
		node = node->next;
	}
	log_debug(lg, "added %d entries to historic data, now %d",
	    entries, hdl->old_result_ht->key_count);
}

static void
trlog_old_result_ht_remove(struct trlog_handle *hdl,
    struct mlist_node *result_head)
{
	struct mlist_node *node = result_head;
	int entries = 0;
	while (node) {
		hashtable_remove(hdl->old_result_ht, node->data,
		    strlen(node->data));
		node = node->next;
		entries++;
	}
	log_debug(lg, "removed %d entries from historic data, now %d",
	    entries, hdl->old_result_ht->key_count);
}

void
trlog_mlist_done(struct trlog_handle *hdl, ccow_t tc,
    struct mlist_node *result_head, int no_add)
{
	if (!result_head)
		return;
	if (hdl->old_result_head) {
		/* keep up to OLD_RESULT_MAX, free last one */
		hdl->old_result_last->cont = result_head;
		hdl->old_result_last = result_head;
		hdl->old_result_last->cont = NULL;
		if (hdl->back_cnt <= (long)tc->trlog_quarantine) {
			hdl->back[hdl->back_cnt] = result_head;
			hdl->back_cnt++;
		} else { // shift
			for (int i=1; i < hdl->back_cnt; i++) {
				hdl->back[i-1] = hdl->back[i];
			}
			hdl->back[hdl->back_cnt - 1] = result_head;
		}

		if (!no_add)
			trlog_old_result_ht_add(hdl, result_head);
		if (hdl->old_result_cnt >= TRLOG_OLD_RESULT_MAX) {
			struct mlist_node *node = hdl->old_result_head;
			hdl->old_result_head = node->cont;
			trlog_old_result_ht_remove(hdl, node);
			msort_free_list(node, je_free);
		} else {
			hdl->old_result_cnt++;
		}
	} else {
		hdl->old_result_head = hdl->old_result_last = result_head;
		hdl->old_result_head->cont = NULL;
		hdl->back[0] = result_head;
		hdl->back_cnt = 1;
		if (!no_add)
			trlog_old_result_ht_add(hdl, result_head);
	}
}

void
trlog_mlist_log(char *header, struct mlist_node *head)
{
	struct mlist_node *t = head;
	struct trlog_data rec;
	char entry[TRLOG_KEY_LEN];
	int err;

	log_info(lg, "%s:", header);
	while (t != NULL) {
		strcpy(entry, (char*)t->data);
		err = trlog_extract_key(entry, strlen(entry), &rec, 0);
		if (err) {
			log_error(lg, "Error extracting TSOBJ entry %s: %d",
			    entry, err);
			return;
		}
		log_info(lg, "List rec oid: %s, ts: %lu", rec.oid, rec.timestamp);
		t = t->next;
	}
	log_info(lg,"");
}

void
trlog_init(struct trlog_handle *hdl)
{
	hdl->old_result_head = NULL;
	hdl->old_result_last = NULL;
	hdl->old_result_cnt = 0;
	hdl->back_cnt = 0;
	hdl->old_result_ht = hashtable_create(TRLOG_OLD_RESULT_HT_SIZE,
	    HT_VALUE_CONST, 0.05);
	assert(hdl->old_result_ht);
}

void
trlog_destroy(struct trlog_handle *hdl)
{
	if (!hdl)
		return;
	if (hdl->old_result_head) {
		struct mlist_node *node = hdl->old_result_head;
		while (node) {
			struct mlist_node *tmp = node->cont;
			msort_free_list(node, je_free);
			node = tmp;
		}
	}
	if (hdl->old_result_ht)
		hashtable_destroy(hdl->old_result_ht);
}

static int
trlog_filter_result(ccow_t tc, char *cid, char *tid, char *bid, char *oid,
    struct mlist_node *result_head, uint64_t rec_count, const char *tenant_uri,
    const char *userid, rtbuf_t* rb)
{
	int err = 0;
	struct mlist_node *res_node = result_head;
	struct trlog_data rec;

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

		if (uint512_cmp(&rec.phid, &uint512_null) == 0) {
			res_node = res_node->next;
			MEMFREE_TRLOG_DATA(rec);
			continue;
		}

		if ((rec.cid && *cid && strcmp(rec.cid, cid) != 0)) {
			res_node = res_node->next;
			MEMFREE_TRLOG_DATA(rec);
			continue;
		}

		if ((rec.tid && *tid && strcmp(rec.tid, tid) != 0)) {
			res_node = res_node->next;
			MEMFREE_TRLOG_DATA(rec);
			continue;
		}

		if ((rec.bid && *bid && strcmp(rec.bid, bid) != 0)) {
			res_node = res_node->next;
			MEMFREE_TRLOG_DATA(rec);
			continue;
		}

		if ((rec.oid && *oid && strcmp(rec.oid, oid) != 0)) {
			res_node = res_node->next;
			MEMFREE_TRLOG_DATA(rec);
			continue;
		}

		uv_buf_t buf = { .base = (char *)&rec, .len = sizeof (struct trlog_data) };
		err = rtbuf_add_alloc(rb, &buf, 1);
		if (err) {
			goto _err;
		}

		res_node = res_node->next;
	}

	/* pass-through */
_err:
	return err;
}

void
trlog_search_free(trlog_search_t handle)
{
	rtbuf_t *rb = handle;
	for (size_t i = 0; i < rb->nbufs; ++i) {
		struct trlog_data rec = *(struct trlog_data *)rb->bufs[i].base;
		MEMFREE_TRLOG_DATA(rec);
	}
	rtbuf_destroy(rb);
}

static int
trlog_search_phid_filter(uint512_t *phid, void *arg)
{
	uint512_t *phid_filter = arg;
	return uint512_cmp(phid, phid_filter) == 0;
}

static int
trlog_search_cmp(const void *a, const void *b)
{
	struct trlog_data *rec1 = (struct trlog_data *)((uv_buf_t *)a)->base;
	struct trlog_data *rec2 = (struct trlog_data *)((uv_buf_t *)b)->base;

	return rec1->timestamp - rec2->timestamp;
}

int
trlog_search(ccow_t tc, uint64_t trlog_increment_ms,
    const char *tenant_uri, const char *userid, uint64_t cts_from, uint64_t cts_to,
    int max_batches, struct iovec **iov, size_t *iovcnt, trlog_search_t *handle)
{
	int err = 0;
	uint64_t rec_count;
	struct mlist_node *result_head = NULL;
	uint64_t time_spent_start = get_timestamp_us();
	uint64_t batch_seq_ts = cts_from - (cts_from % (trlog_increment_ms * 1000));
	struct trlog_handle trhdl;	/* Transaction log handle */
	char cid[2048], tid[2048], bid[2048] = "", oid[2048] = "";

	*iov = NULL;

	int nargs = sscanf(tenant_uri, "%2047[^/]/%2047[^/]/%2047[^/]/%2047[^\n]",
		    cid, tid, bid, oid);
	if (nargs < 2) {
		log_error(lg, "Wrong tenant_uri, expecting c/t/b?/o?, got %s",
		    tenant_uri);
		return -EBADF;
	}

	trlog_init(&trhdl);

	rtbuf_t* rb = rtbuf_init_empty();
	if (!rb) {
		err = -ENOMEM;
		goto _err;
	}

	/* get PHID */
	ccow_completion_t c;

	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err)
		goto _err;

	ccow_lookup_t iter;
        err = ccow_admin_pseudo_get(cid, strlen(cid) + 1, tid, strlen(tid) + 1,
	    bid, strlen(bid) + 1, oid, strlen(oid) + 1, NULL, 0, 0, CCOW_GET, c, &iter);
	if (err) {
		ccow_release(c);
		goto _err;
	}
	err = ccow_wait(c, 0);
	if (err) {
		if (iter)
			ccow_lookup_release(iter);
		goto _err;
	}

	uint512_t phid = uint512_null;
	ccow_metadata_kv_t kv;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_METADATA, -1))) {
		if (!strcmp(kv->key, *oid ? RT_SYSKEY_PARENT_HASH_ID : RT_SYSKEY_NAME_HASH_ID)) {
			phid = *(uint512_t *)kv->value;
			break;
		}
	}
	if (iter)
		ccow_lookup_release(iter);

	if (uint512_cmp(&phid, &uint512_null) == 0) {
		log_error(lg, "Cannot find tenant_uri PHID, unknown error");
		err = -EBADF;
		goto _err;
	}

	int found_batches = 0;
	while (batch_seq_ts < cts_to) {

		log_debug(lg, "TRLOG merge %lu sort process is in progress", batch_seq_ts);

		result_head = NULL;
		err = trlog_mlist_get(&trhdl, tc, batch_seq_ts,
		    &result_head, &rec_count, trlog_search_phid_filter, &phid);
		if (err && err != -ENOENT) {
			goto _err;
		}
		if (!(err == -ENOENT || rec_count == 0)) {

			size_t rb_nbufs_prev = rb->nbufs;

			/* actually iterate and filter the final result */
			err = trlog_filter_result(tc, cid, tid, bid, oid,
			    result_head, rec_count, tenant_uri, userid, rb);
			if (err) {
				msort_free_list(result_head, je_free);
				goto _err;
			}

			trlog_mlist_done(&trhdl, tc, result_head, 0);

			log_debug(lg, "max_batch: curr %ld prev %ld found %d",
			    rb->nbufs, rb_nbufs_prev, found_batches);
			/* collect up to max_batches containing search cond */
			if (rb->nbufs > rb_nbufs_prev && ++found_batches >= max_batches)
				break;
		} else
			err = 0;

		batch_seq_ts += trlog_increment_ms * 1000UL;
	}

	if (rb->nbufs)
		qsort(rb->bufs, rb->nbufs, sizeof (uv_buf_t), trlog_search_cmp);

	log_info(lg, "TRLOG: processed result in %ldms",
	    (get_timestamp_us() - time_spent_start) / 1000);

	*handle = rb;
	*iov = (struct iovec *)rb->bufs;
	*iovcnt = rb->nbufs;

_err:
	trlog_destroy(&trhdl);
	if (err && rb)
		trlog_search_free(rb);
	return err;
}

int
trlog_pack(msgpack_p *p, struct trlog_data *data)
{
	int err;
	err = msgpack_pack_array(p, 18);
	if (err)
		return err;

	err = replicast_pack_uint512(p, &data->vmchid);
	if (err)
		return err;

	err = replicast_pack_uint128(p, &data->serverid);
	if (err)
		return err;

	err = replicast_pack_uint128(p, &data->vdevid);
	if (err)
		return err;

	err = msgpack_pack_uint32(p, data->trtype);
	if (err)
		return err;

	err = replicast_pack_uint512(p, &data->nhid);
	if (err)
		return err;

	err = replicast_pack_uint512(p, &data->phid);
	if (err)
		return err;

	err = msgpack_pack_uint64(p, data->timestamp);
	if (err)
		return err;

	err = msgpack_pack_uint64(p, data->generation);
	if (err)
		return err;

	err = msgpack_pack_int64(p, data->deltasize);
	if (err)
		return err;
	char empty = 0;;
	err = msgpack_pack_str(p, data->cid == NULL ? &empty : data->cid);
	if (err)
		return err;

	err = msgpack_pack_str(p, data->tid == NULL ? &empty : data->tid);
	if (err)
		return err;

	err = msgpack_pack_str(p, data->bid == NULL ? &empty : data->bid);
	if (err)
		return err;

	err = msgpack_pack_str(p, data->oid == NULL ? &empty : data->oid);
	if (err)
		return err;

	err = msgpack_pack_uint64(p, data->size);
	if (err)
		return err;

	err = msgpack_pack_uint8(p, data->object_deleted);
	if (err)
		return err;

	err = msgpack_pack_str(p, data->etag == NULL ? &empty : data->etag);
	if (err)
		return err;

	err = msgpack_pack_str(p, data->content_type == NULL ? &empty : data->content_type);
	if (err)
		return err;

	err = msgpack_pack_uint64(p, data->multipart_size);
	if (err)
		return err;

	err = msgpack_pack_str(p, data->owner == NULL ? &empty : data->owner);
	if (err)
		return err;

	err = msgpack_pack_str(p, data->srcip == NULL ? &empty : data->srcip);
	if (err)
		return err;

	return 0;
}

int
trlog_unpack(msgpack_u *u, struct trlog_data *data)
{
	int err;
	uint32_t n;
	err = msgpack_unpack_array(u, &n);
	if (err)
		return err;
	if (n != 18)
		return -EBADF;

	err = replicast_unpack_uint512(u, &data->vmchid);
	if (err)
		return err;

	err = replicast_unpack_uint128(u, &data->serverid);
	if (err)
		return err;

	err = replicast_unpack_uint128(u, &data->vdevid);
	if (err)
		return err;

	err = msgpack_unpack_uint32(u, &data->trtype);
	if (err)
		return err;

	err = replicast_unpack_uint512(u, &data->nhid);
	if (err)
		return err;

	err = replicast_unpack_uint512(u, &data->phid);
	if (err)
		return err;

	err = msgpack_unpack_uint64(u, &data->timestamp);
	if (err)
		return err;

	err = msgpack_unpack_uint64(u, &data->generation);
	if (err)
		return err;

	err = msgpack_unpack_int64(u, &data->deltasize);
	if (err)
		return err;
	char cid[REPLICAST_STR_MAXLEN], tid[REPLICAST_STR_MAXLEN],
	     bid[REPLICAST_STR_MAXLEN], oid[REPLICAST_STR_MAXLEN],
		etag[REPLICAST_STR_MAXLEN], content_type[REPLICAST_STR_MAXLEN],
		owner[REPLICAST_STR_MAXLEN], srcip[REPLICAST_STR_MAXLEN];

	err = msgpack_unpack_str(u, cid, REPLICAST_STR_MAXLEN);
	if (err)
		return err;
	if (strlen(cid))
		data->cid = je_strdup(cid);
	else
		data->cid = NULL;
	err = msgpack_unpack_str(u, tid, REPLICAST_STR_MAXLEN);
	if (err)
		goto _lcl_err_handling;
	if (strlen(tid))
		data->tid = je_strdup(tid);
	else
		data->tid = NULL;

	err = msgpack_unpack_str(u, bid, REPLICAST_STR_MAXLEN);
	if (err)
		goto _lcl_err_handling;
	if (strlen(bid))
		data->bid = je_strdup(bid);
	else
		data->bid = NULL;

	err = msgpack_unpack_str(u, oid, REPLICAST_STR_MAXLEN);
	if (err)
		goto _lcl_err_handling;
	if (strlen(oid))
		data->oid = je_strdup(oid);
	else
		data->oid = NULL;

	err = msgpack_unpack_uint64(u, &data->size);
	if (err)
		goto _lcl_err_handling;

	err = msgpack_unpack_uint8(u, &data->object_deleted);
	if (err)
		goto _lcl_err_handling;

	err = msgpack_unpack_str(u, etag, REPLICAST_STR_MAXLEN);
	if (err)
		goto _lcl_err_handling;
	if (strlen(etag)) {
		data->etag = je_strdup(etag);
		if (!data->etag) {
			err = -ENOMEM;
			goto _lcl_err_handling;
		}
	} else
		data->etag = NULL;

	err = msgpack_unpack_str(u, content_type, REPLICAST_STR_MAXLEN);
	if (err)
		goto _lcl_err_handling;
	if (strlen(content_type)) {
		data->content_type = je_strdup(content_type);
		if (!data->content_type) {
			err = -ENOMEM;
			goto _lcl_err_handling;
		}
	} else
		data->content_type = NULL;

	err = msgpack_unpack_uint64(u, &data->multipart_size);
	if (err)
		goto _lcl_err_handling;

	err = msgpack_unpack_str(u, owner, REPLICAST_STR_MAXLEN);
	if (err)
		goto _lcl_err_handling;
	if (strlen(owner)) {
		data->owner = je_strdup(owner);
		if (!data->owner) {
			err = -ENOMEM;
			goto _lcl_err_handling;
		}
	} else
		data->owner = NULL;

	err = msgpack_unpack_str(u, srcip, REPLICAST_STR_MAXLEN);
	if (err)
		goto _lcl_err_handling;
	if (strlen(srcip)) {
		data->srcip = je_strdup(srcip);
		if (!data->srcip) {
			err = -ENOMEM;
			goto _lcl_err_handling;
		}
	} else
		data->srcip = NULL;

	return 0;
_lcl_err_handling:
	if (data->cid)
		je_free(data->cid);
	if (data->tid)
		je_free(data->tid);
	if (data->bid)
		je_free(data->bid);
	if (data->oid)
		je_free(data->oid);
	if (data->etag)
		je_free(data->etag);
	if (data->content_type)
		je_free(data->content_type);
	if (data->owner)
		je_free(data->owner);
	if (data->srcip)
		je_free(data->srcip);
	return err;
}

int
trlog_extract_key(char *key, int len, struct trlog_data *data, int partial)
{
	char *token, *delim = "\1", *sp;
	int err = -EINVAL;
	char nhid_str[UINT512_STR_BYTES];
	char phid_str[UINT512_STR_BYTES];
	char vmchid_str[UINT512_STR_BYTES];
	char timestamp_str[UINT128_STR_BYTES];
	char generation_str[UINT128_STR_BYTES];
	char deltasize_str[UINT128_STR_BYTES];
	char trtype_str[UINT128_STR_BYTES];
	char cid_str[REPLICAST_STR_MAXLEN];
	char tid_str[REPLICAST_STR_MAXLEN];
	char bid_str[REPLICAST_STR_MAXLEN];
	char oid_str[REPLICAST_STR_MAXLEN];
	char size_str[UINT128_STR_BYTES];
	char object_deleted_str[UINT128_STR_BYTES];
	char etag_str[REPLICAST_STR_MAXLEN];
	char content_type_str[REPLICAST_STR_MAXLEN];
	char multipart_size_str[UINT128_STR_BYTES];
	char serverid_str[UINT128_STR_BYTES] = "";
	char owner_str[REPLICAST_STR_MAXLEN];
	char srcip_str[REPLICAST_STR_MAXLEN];

	data->cid = data->tid = data->bid = data->oid = data->etag = data->content_type = data->owner = data->srcip = NULL;

	log_debug(lg, "Extracting trlog key %s", key);

	token = strtok_r(key, delim, &sp);
	if (token == NULL)
		return err;
	snprintf(phid_str, UINT512_STR_BYTES, "%s", token);

	token = strtok_r(NULL, delim, &sp);
	if (token == NULL)
		return err;
	snprintf(nhid_str, UINT512_STR_BYTES, "%s", token);

	token = strtok_r(NULL, delim, &sp);
	if (token == NULL)
		return err;
	snprintf(generation_str, UINT128_STR_BYTES, "%s", token);

	token = strtok_r(NULL, delim, &sp);
	if (token == NULL)
		return err;
	snprintf(timestamp_str, UINT128_STR_BYTES, "%s", token);

	token = strtok_r(NULL, delim, &sp);
	if (token == NULL)
		return err;
	snprintf(vmchid_str, UINT512_STR_BYTES, "%s", token);

	token = strtok_r(NULL, delim, &sp);
	if (token == NULL)
		return err;
	snprintf(trtype_str, UINT128_STR_BYTES, "%s", token);

	token = strtok_r(NULL, delim, &sp);
	if (token == NULL)
		return err;
	snprintf(deltasize_str, UINT128_STR_BYTES, "%s", token);

	uint512_fromhex(phid_str, UINT512_STR_BYTES, &data->phid);
	uint512_fromhex(nhid_str, UINT512_STR_BYTES, &data->nhid);
	uint512_fromhex(vmchid_str, UINT512_STR_BYTES, &data->vmchid);
	data->timestamp = strtoul(timestamp_str, NULL, 10);
	data->generation = strtoul(generation_str, NULL, 10);
	data->deltasize = strtol(deltasize_str, NULL, 10);
	data->trtype = strtol(trtype_str, NULL, 10);

	if (partial)
		return 0;

	token = strtok_r(NULL, delim, &sp);
	if (token == NULL)
		return err;
	snprintf(cid_str, REPLICAST_STR_MAXLEN, "%s", token);

	token = strtok_r(NULL, delim, &sp);
	if (token == NULL)
		return err;
	snprintf(tid_str, REPLICAST_STR_MAXLEN, "%s", token);

	token = strtok_r(NULL, delim, &sp);
	if (token == NULL)
		return err;
	snprintf(bid_str, REPLICAST_STR_MAXLEN, "%s", token);

	token = strtok_r(NULL, delim, &sp);
	if (token == NULL)
		return err;
	snprintf(oid_str, REPLICAST_STR_MAXLEN, "%s", token);

	token = strtok_r(NULL, delim, &sp);
	if (token == NULL)
		return err;
	snprintf(size_str, UINT128_STR_BYTES, "%s", token);

	token = strtok_r(NULL, delim, &sp);
	if (token == NULL)
		return err;
	snprintf(object_deleted_str, UINT128_STR_BYTES, "%s", token);

	token = strtok_r(NULL, delim, &sp);
	if (token == NULL) {
		return err;
	}
	snprintf(multipart_size_str, UINT128_STR_BYTES, "%s", token);

	token = strtok_r(NULL, delim, &sp);
	if (token == NULL) {
		return err;
	}
	snprintf(etag_str, REPLICAST_STR_MAXLEN, "%s", token);

	token = strtok_r(NULL, delim, &sp);
	if (token == NULL) {
		return err;
	}
	snprintf(content_type_str, REPLICAST_STR_MAXLEN, "%s", token);

	token = strtok_r(NULL, delim, &sp);
	if (token != NULL) {
		snprintf(serverid_str, UINT128_STR_BYTES, "%s", token);
		uint128_fromhex(serverid_str, UINT128_STR_BYTES, &data->serverid);
	} else {
		data->serverid = uint128_null;
	}

	token = strtok_r(NULL, delim, &sp);
	if (token == NULL) {
		return err;
	}
	snprintf(owner_str, REPLICAST_STR_MAXLEN, "%s", token);

	token = strtok_r(NULL, delim, &sp);
	if (token == NULL) {
		return err;
	}
	snprintf(srcip_str, REPLICAST_STR_MAXLEN, "%s", token);

	data->cid = strlen(cid_str) > 0 ? je_strdup(cid_str) : NULL;
	if (!data->cid && strlen(cid_str))
		goto _local_err_memclean;
	data->tid = strlen(tid_str) > 0 ? je_strdup(tid_str) : NULL;
	if (!data->tid && strlen(tid_str))
		goto _local_err_memclean;
	data->bid = strlen(bid_str) > 0 ? je_strdup(bid_str) : NULL;
	if (!data->bid && strlen(bid_str))
		goto _local_err_memclean;
	data->oid = strlen(oid_str) > 0 ? je_strdup(oid_str) : NULL;
	if (!data->oid && strlen(oid_str))
		goto _local_err_memclean;
	data->size = strtol(size_str, NULL, 10);
	data->object_deleted = (uint8_t)(object_deleted_str[0] - '0');
	data->multipart_size = strtol(multipart_size_str, NULL, 10);
	data->etag = strlen(etag_str) > 0 ? je_strdup(etag_str) : NULL;
	data->content_type = strlen(content_type_str) > 0 ? je_strdup(content_type_str) : NULL;
	data->owner = strlen(owner_str) > 0 ? je_strdup(owner_str) : NULL;
	data->srcip = strlen(srcip_str) > 0 ? je_strdup(srcip_str) : NULL;

	if (data->trtype == 0)
		goto _local_err_memclean;;

	return 0;

_local_err_memclean:
	if (data->cid)
		je_free(data->cid);
	if (data->tid)
		je_free(data->tid);
	if (data->bid)
		je_free(data->bid);
	if (data->oid)
		je_free(data->oid);
	if (data->etag)
		je_free(data->etag);
	if (data->content_type)
		je_free(data->content_type);
	if (data->owner)
		je_free(data->owner);
	if (data->srcip)
		je_free(data->srcip);
	return err ? err : -ENOMEM;
}
