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

#include "rt_locks.h"
#include "skiplist.h"

#define LOCKS_TABLE_SZ	1024

int
rt_locks_init(struct repdev *dev)
{
	dev->lock_tbl = hashtable_create(LOCKS_TABLE_SZ, HT_VALUE_CONST, 0.001);
	if (!dev->lock_tbl) {
		log_debug(lg, "failed to allocate locks table\n");
		return -ENOMEM;
	}
	return 0;
}

void
rt_locks_destroy(struct repdev *dev)
{
	if (dev->lock_tbl)
		hashtable_destroy(dev->lock_tbl);
}

static int
regioncmp(const void *region_a, const size_t region_a_len,
	  const void *region_b, const size_t region_b_len)
{
	ccow_region_t aregion = (ccow_region_t) region_a;
	ccow_region_t bregion = (ccow_region_t) region_b;

	return aregion->off >= bregion->off + bregion->len ? 1 :
		aregion->off + aregion->len <= bregion->off ? -1 : 0;
}

/*
 * Clone the lock on request and add to the skip list.
 * This is essential as we split the lock later, if necessary and free the memory.
 */
static inline int
rt_lock_to_skiplist(struct skiplist *list, struct ccow_obj_lock *lk, int clone)
{
	struct ccow_obj_lock *new_lk;

	if (clone) {
		new_lk = je_malloc(sizeof(*new_lk));
		if (!new_lk)
			return -ENOMEM;

		*new_lk = *lk;
		new_lk->lk_ref_count++;
	} else
		new_lk = lk;

	return msl_set(list, &lk->lk_region, sizeof(lk->lk_region), new_lk,
		       sizeof(*new_lk), NULL);
}

/* Check if the shared lock has any exclusive lock for overlapping regions */
int
rt_sh_ex_conflicts(struct skiplist *list, struct ccow_obj_lock *lk_req)
{
	struct skiplist_iter iter;
	struct ccow_obj_lock *lk;

	iter = msl_iter_next(list, NULL);
	while (iter.v != NULL) {
		lk = msl_iter_getv(&iter, NULL);
		if (ccow_region_intersects(&lk->lk_region, &lk_req->lk_region) &&
		    lk->lk_mode & CCOW_LOCK_EXCL)
			return 1;

		iter = msl_iter_next(list, &iter);
	}
	return 0;
}

/* Get the overlapping lock */
struct ccow_obj_lock *
rt_get_lock(struct repdev *dev, struct ccow_obj_lock *lk_req)
{
	struct skiplist *lk_list;
	struct ccow_obj_lock *lk;
	size_t sz;

	/* Get the list of locked regions */
	lk_list = hashtable_get(dev->lock_tbl, &lk_req->lk_nhid,
				sizeof(uint512_t), &sz);
	if (!lk_list)
		return NULL;

	/* Get the overlapping region */
	lk = msl_get(lk_list, &lk_req->lk_region,
		     sizeof(lk_req->lk_region), NULL);

	return lk;
}

/* Does region have a lock (shared or exclusive) */
int
rt_is_locked(struct repdev *dev, struct ccow_obj_lock *lk_req)
{
	struct ccow_obj_lock *lk;

	lk = rt_get_lock(dev, lk_req);
	/* TODO: Check lock owner id */
	return lk ? 1 : 0;
}

int
rt_lock_conflicts(struct repdev *dev, struct ccow_obj_lock *lk_req)
{
	struct skiplist *lk_list;
	struct ccow_obj_lock *lk;
	size_t sz;

	/* Get the list of locked regions */
	lk_list = hashtable_get(dev->lock_tbl, &lk_req->lk_nhid,
				sizeof(uint512_t), &sz);
	if (!lk_list)
		return 0;

	if (lk_req->lk_mode & CCOW_LOCK_EXCL) {
		/* Get the overlapping region */
		lk = msl_get(lk_list, &lk_req->lk_region,
			     sizeof(lk_req->lk_region), NULL);

		return lk ? 1 : 0;
	}
	assert(lk_req->lk_mode & CCOW_LOCK_SHARED);
	return rt_sh_ex_conflicts(lk_list, lk_req);
}

static int
rt_locks_split_regions(struct ccow_obj_lock *lk,struct ccow_obj_lock *lk_req,
		       struct ccow_obj_lock **left_lk,
		       struct ccow_obj_lock **right_lk)
{
	struct ccow_region in_region, left_region, right_region;

	assert(left_lk != NULL);
	assert(right_lk != NULL);

	*left_lk = *right_lk = NULL;

	ccow_region_intersection(&lk->lk_region, &lk_req->lk_region, &in_region);
	ccow_region_diff(&lk->lk_region, &lk_req->lk_region,
			 &left_region, &right_region);

	if (!ccow_is_region_empty(&left_region)) {
		*left_lk = je_malloc(sizeof(struct ccow_obj_lock));
		if (*left_lk == NULL)
			return -ENOMEM;
	}

	if (!ccow_is_region_empty(&right_region)) {
		*right_lk = je_malloc(sizeof(struct ccow_obj_lock));
		if (*right_lk == NULL) {
			je_free(*left_lk);
			return -ENOMEM;
		}
	}
	lk_req->lk_region = in_region;
	lk_req->lk_ref_count = lk->lk_ref_count + 1;

	if (*left_lk != NULL) {
		(*left_lk)->lk_mode = lk->lk_mode;
		(*left_lk)->lk_region = left_region;
		(*left_lk)->lk_ref_count =
			ccow_region_intersects(&left_region, &lk->lk_region) ? 
			lk->lk_ref_count : 1;
	}

	if (*right_lk != NULL) {
		(*right_lk)->lk_mode = lk->lk_mode;
		(*right_lk)->lk_region = right_region;
		(*right_lk)->lk_ref_count =
			ccow_region_intersects(&right_region, &lk->lk_region) ? 
			lk->lk_ref_count : 1;
	}

	return 0;
}

static void
rt_lock_list_destroy(struct skiplist *lk_list)
{
	struct ccow_obj_lock *lk;
	struct skiplist_iter iter;

	iter = msl_iter_next(lk_list, NULL);
	while (iter.v != NULL) {
		lk = msl_iter_getv(&iter, NULL);
		iter = msl_iter_next(lk_list, &iter);
		je_free(lk);
	}
	msl_destroy(lk_list);
}

/*
 * Exiting lock(s) intersect, hence split the regions and adjust ref counts.
 * Create a new skip list to create a consistent region locks list.
 * This step may be necessary, if file region is locked and only part of
 * it is unlocked.
 */
int
rt_lock_add_overlap_regions(struct repdev *dev, struct skiplist *lk_list,
			     struct ccow_obj_lock *lk_req)
{
	int err;
	int clone;
	struct skiplist *new_list;
	struct skiplist_iter iter;
	struct ccow_obj_lock *lk;
	struct ccow_obj_lock *in_lk = lk_req;
	struct ccow_obj_lock *left_lk = NULL;
	struct ccow_obj_lock *right_lk = NULL;

	/*
	 * We have to create a new skiplist to handle failures.
	 * If there is a failure while adding parts of new region,
	 * lock consistency is maintained and clean-up is easy.
	 */
	new_list = msl_create(regioncmp);
	if (!new_list)
		return -ENOMEM;

	/* Iterate through existing list and process overlapping regions */
	iter = msl_iter_next(lk_list, NULL);
	while (iter.v != NULL) {
		lk = msl_iter_getv(&iter, NULL);
		if (ccow_region_intersects(&lk->lk_region, &in_lk->lk_region)) {
			/*
			 * Since requesting lock region is intersecting with
			 * the current lock region, split the locks into
			 * - intersection, left diference and right difference
			 * If any of the differences is NULL set, then the
			 * corresponding pointer will be NULL.
			 */
			err = rt_locks_split_regions(lk, in_lk,
						     &left_lk, &right_lk);
			if (err)
				goto _exit;

			/* Add intersection. If it's user lock, clone it */
			clone = 0;
			if (in_lk == lk_req) {
				clone = 1;
				/*
				 * Cloning increments ref count.
				 * Decrement ref count incremented by
				 * rt_locks_split_regions()
				 */
				in_lk->lk_ref_count--;
			}
			err = rt_lock_to_skiplist(new_list, in_lk, clone);
			if (err) {
				if (left_lk)
					je_free(left_lk);
				if (right_lk)
					je_free(right_lk);
				goto _exit;
			}

			/* Add left region lock, if not empty */
			if (left_lk) {
				err = rt_lock_to_skiplist(new_list, left_lk, 0);
				if (err) {
					je_free(left_lk);
					if (right_lk)
						je_free(right_lk);
					goto _exit;
				}
			}
			left_lk = NULL;

			/*
			 * If there is right region, check if intersects
			 * with remaining locks.
			 */
			if (right_lk)
				in_lk = right_lk;
		} else {
			if (right_lk) {
				err = rt_lock_to_skiplist(new_list, right_lk, 0);
				if (err) {
					je_free(right_lk);
					goto _exit;
				}
			}
			right_lk = NULL;
			err = rt_lock_to_skiplist(new_list, lk, 0);
			if (err)
				goto _exit;
		}
		iter = msl_iter_next(lk_list, &iter);
	}
	if (right_lk) {
		err = rt_lock_to_skiplist(new_list, right_lk, 0);
		if (err) {
			je_free(right_lk);
			goto _exit;
		}
	}
	err = hashtable_put(dev->lock_tbl,
			    &lk_req->lk_nhid, sizeof(uint512_t),
			    new_list, sizeof(new_list));
	if (err == 0) {
		rt_lock_list_destroy(lk_list);
		return err;
	}

_exit:
	rt_lock_list_destroy(new_list);
	return err;
}

/*
 * Adds lock. It may modify contents of the requesting lock and may free it
 */
int
rt_add_lock(struct repdev *dev, struct ccow_obj_lock *lk_req, free_lock_t free_lk)
{
	struct skiplist *lk_list;
	struct ccow_obj_lock *lk;
	size_t sz;
	int err;

	assert(lk_req != NULL && lk_req->lk_region.len > 0);

	/* Get the list of locked regions */
	lk_list = hashtable_get(dev->lock_tbl, &lk_req->lk_nhid,
				sizeof(uint512_t), &sz);

	/* No entry for this nhid. Create the necessary structures */
	if (!lk_list) {
		lk_list = msl_create(regioncmp);
		if (!lk_list)
			return -ENOMEM;
		err = rt_lock_to_skiplist(lk_list, lk_req, 1);
		if (err != 0) {
			msl_destroy(lk_list);
			return -ENOMEM;
		}

		err = hashtable_put(dev->lock_tbl,
				    &lk_req->lk_nhid, sizeof(uint512_t),
				    lk_list, sizeof(lk_list));
		if (err) {
			msl_erase(lk_list, &lk_req->lk_region,
				  sizeof(lk_req->lk_region), NULL);
			msl_destroy(lk_list);
		}
		return err;
	}

	/* Get the overlapping region */
	lk = msl_get(lk_list, &lk_req->lk_region,
		     sizeof(lk_req->lk_region), NULL);

	/* No overlapping region. Add the lock */
	if (!lk) {
		return rt_lock_to_skiplist(lk_list, lk_req, 1);
	}

	/*
	 * Deal with exclusive lock first.
	 * Cannot exclusively lock if there is overlapping region.
	 */
	if (lk && lk_req->lk_mode & CCOW_LOCK_EXCL)
		return -EBUSY;

	assert(lk_req->lk_mode & CCOW_LOCK_SHARED);
	/*
	 * Check for lock mode conflict.
	 * There could be multiple regions with different lock modes
	 */
	if (rt_sh_ex_conflicts(lk_list, lk_req))
		return -EBUSY;

	return rt_lock_add_overlap_regions(dev, lk_list, lk_req);
}

void
rt_remove_lock(struct repdev *dev, struct ccow_obj_lock *lk_req)
{
	struct skiplist *lk_list;
	struct ccow_obj_lock *lk;
	struct skiplist_iter iter;
	size_t sz;
	int err;

	/* Get the list of locked regions */
	lk_list = hashtable_get(dev->lock_tbl, &lk_req->lk_nhid,
				sizeof(uint512_t), &sz);

	if (lk_list == NULL) {
		log_notice(lg, "Already removed lock [%" PRIu64 ",%" PRIu64
				") mode: %u", lk_req->lk_region.off,
				lk_req->lk_region.len, lk_req->lk_mode);
		return;
	}

	/* Get the overlapping region */
	lk = msl_get(lk_list, &lk_req->lk_region,
		     sizeof(lk_req->lk_region), NULL);

	if (lk == NULL) {
		log_notice(lg, "Already removed lock [%" PRIu64 ",%" PRIu64
				") mode: %u", lk_req->lk_region.off,
				lk_req->lk_region.len, lk_req->lk_mode);
		return;
	}

	/*
	 * find all regions intersecting with this.
	 */
	struct ccow_region lk_region = lk_req->lk_region;
	iter = msl_iter_next(lk_list, NULL);
	while (iter.v != NULL) {
		lk = msl_iter_getv(&iter, NULL);
		iter = msl_iter_next(lk_list, &iter);
		if (ccow_region_intersects(&lk->lk_region, &lk_region)) {
			assert(lk->lk_ref_count > 0);
			lk->lk_ref_count--;
			if (lk->lk_ref_count == 0) {
				msl_erase(lk_list, &lk->lk_region,
					  sizeof(lk->lk_region), NULL);
				je_free(lk);
			}
		}
	}
	if (msl_count(lk_list) == 0) {
		err = hashtable_put(dev->lock_tbl,
				    &lk_req->lk_nhid, sizeof(uint512_t),
				    NULL, sizeof(lk_list));
		if (err == 0) {
			msl_destroy(lk_list);
		} else {
			printf("Could not set lock list to NULL\n");
			log_notice(lg, "Could not set lock list to NULL");
		}
	}
}

/*
 * Functions to dump locks (for debugging). Could be dumped in json format later.
 * Later on these could be enhanced to integrate with lock tracing
 */

/* Dump locked regions - given a list */
void
rt_locks_dump_regions(struct skiplist *lk_list)
{
	struct ccow_obj_lock *lk;
	struct skiplist_iter iter;

	if (!lk_list) {
		printf("No locks for this object\n");
		return;
	}

	iter = msl_iter_next(lk_list, NULL);
	while (iter.v != NULL) {
		lk = msl_iter_getv(&iter, NULL);
		iter = msl_iter_next(lk_list, &iter);
		printf("lock region [%" PRIu64 " ,%" PRIu64
			") mode: %u count: %u\n",
			lk->lk_region.off, lk->lk_region.len,
			lk->lk_mode, lk->lk_ref_count);
	}
}

/* Dump locked regions - given a device and NHID */
void
rt_locks_obj_dump_regions(struct repdev *dev, uint512_t *nhid)
{
	struct skiplist *lk_list;
	size_t sz;

	lk_list = hashtable_get(dev->lock_tbl, nhid, sizeof(uint512_t), &sz);
	if (lk_list)
		rt_locks_dump_regions(lk_list);
	else
		printf("No locks for this object\n");
}

/* Dump locked regions of all the objects for a given device */
void
rt_locks_dump(struct repdev *dev)
{
	unsigned int num_keys;
	void **keys;

	keys = hashtable_keys(dev->lock_tbl, &num_keys);
	printf("Device: %s - No. of lock object(s) in table : %u\n",
		dev->name, num_keys);

	for (unsigned int i = 0; i < num_keys; i++) {
		char nhidstr[UINT512_BYTES * 2 + 1];
		uint512_dump((uint512_t *)keys[i], nhidstr, UINT512_BYTES * 2 + 1);

		printf("%u. Printing locked regions for %s\n", i, nhidstr);
		rt_locks_obj_dump_regions(dev, (uint512_t *)keys[i]);
	}

	if (keys)
		je_free(keys);
}
