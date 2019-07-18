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
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <lfq.h>

#include <ccow.h>
#include <ccowfsio.h>

#include <fsio_system.h>
#include <tc_pool.h>

#define MAX_CLUSTER_NAME_LEN	2048
#define MAX_TENANT_NAME_LEN		2048
#define MAX_CCOW_JSON_SIZE		16383
#define MAX_NETWORK_DELAY		180000
#define MAX_CONSENSUS_DELAY		420000

struct bad_node
{
	ccow_t tc;
	struct bad_node *next;
};

typedef struct __tc_pool__
{
	char cluster[MAX_CLUSTER_NAME_LEN];
	char tenant[MAX_TENANT_NAME_LEN];
	char json[MAX_CCOW_JSON_SIZE + 1];
	uint64_t max_tc_count;
	uint64_t cursor;
	ccow_t *tcs;
	QUEUE pool_q;
	struct bad_node *bad_list;
}tc_pool;



static QUEUE tc_pool_list;

int
tc_pool_init(void)
{
	QUEUE_INIT(&tc_pool_list);
	return 0;
}

int
tc_pool_create(char *ccow_config, char *cluster, char *tenant,
		uint64_t max_tc_count, void **tc_pool_handle)
{
	int ccow_fd, err;
	tc_pool *pool = NULL;
	char buf[MAX_CCOW_JSON_SIZE + 1];

	log_trace(fsio_lg, "%s: cluster: %s tenant: %s count: %lu",
		__func__, cluster, tenant, max_tc_count);

    ccow_fd = open(ccow_config, O_RDONLY);
    if (ccow_fd < 0) {
        log_error(fsio_lg, "ccow.json open error: %s",
            strerror(errno));
        err = ccow_fd;
        goto out;
    }

    err = read(ccow_fd, buf, MAX_CCOW_JSON_SIZE);
    if (err < 0) {
        log_error(fsio_lg, "ccow.json read error: %s",
            strerror(errno));
        close(ccow_fd);
        goto out;
    }

    close(ccow_fd);
    buf[err] = 0;

	pool = (tc_pool *)je_calloc(1, sizeof(tc_pool));
	if (! pool) {
		err = ENOMEM;
		goto out;
	}

	memcpy(pool->json, buf, MAX_CCOW_JSON_SIZE + 1);
	pool->bad_list = NULL;

	pool->tcs = (ccow_t *)je_calloc(1, sizeof(ccow_t) * max_tc_count);
	if (! pool->tcs) {
		err = ENOMEM;
		goto out;
	}

	for (uint64_t i=0; i<max_tc_count; i++) {
		err = ccow_tenant_init(buf, cluster, strlen(cluster) + 1,
				tenant, strlen(tenant) + 1, &pool->tcs[i]);
		if (err) {
			log_error(fsio_lg, "ccow_tenant_init error %d for count: %lu",
				err, i);
			goto out;
		}
	}

	pool->max_tc_count = max_tc_count;
	strncpy(pool->cluster, cluster, MAX_CLUSTER_NAME_LEN);
	strncpy(pool->tenant, tenant, MAX_TENANT_NAME_LEN);

	QUEUE_INSERT_TAIL(&tc_pool_list,
        &pool->pool_q);
	*tc_pool_handle = (void *) pool;

out:
	if (err) {
		if (pool) {
			if (pool->tcs) {
				for (uint64_t i=0; i<max_tc_count; i++) {
					if (pool->tcs[i])
						ccow_tenant_term(pool->tcs[i]);
				}
				je_free(pool->tcs);
			}
			QUEUE_INIT(&pool->pool_q);
			je_free(pool);
		}
	}
	log_debug(fsio_lg, "Completed %s: with err :%d", __func__, err);
	return err;
}

int
tc_pool_get_tc(void *tc_pool_handle, inode_t ino, ccow_t *tc)
{
	uint64_t cur;
	int err = 0;
	tc_pool *pool = (tc_pool *)tc_pool_handle;

	log_trace(fsio_lg, "%s", __func__);

	if (ino == 0) {
		cur = atomic_inc64(&pool->cursor);
		if (cur >= pool->max_tc_count)
			atomic_set_uint64(&pool->cursor, 0);
	} else
		cur = ino;

	log_debug(fsio_lg, "%s got cursor: %lu", __func__, cur);
	cur = cur % pool->max_tc_count;

	uint64_t response_delay = ccow_lost_response_delay_ms(pool->tcs[cur]);
	uint64_t consensus_delay = ccow_consensus_delay_ms(pool->tcs[cur]);
	if (response_delay > MAX_NETWORK_DELAY) {
		log_error(fsio_lg, "Detected struggling tenant context %p, on delay response: %lu, consensus: %lu",
				pool->tcs[cur], response_delay, consensus_delay);
	} else if (consensus_delay > MAX_CONSENSUS_DELAY) {
		log_error(fsio_lg, "Recreating tenant context %p, on delay response: %lu, consensus: %lu",
				pool->tcs[cur], response_delay, consensus_delay);
		ccow_t tc;
		err = ccow_tenant_init(pool->json, pool->cluster, strlen(pool->cluster) + 1,
				pool->tenant, strlen(pool->tenant) + 1, &tc);
		if (err) {
			log_error(fsio_lg, "Recreating tenant context failed, err: %d", err);
		} else { // Success
			// Save bad tc
			struct bad_node *last = pool->bad_list;
			struct bad_node *bad = (struct bad_node *)je_malloc(sizeof(struct bad_node));
			bad->tc = pool->tcs[cur];
			bad->next = last;
			pool->bad_list = bad;

			// assign new
			pool->tcs[cur] = tc;
		}
	}
	*tc = pool->tcs[cur];

	log_debug(fsio_lg, "Completed %s: Giving TC number :%lu",
		__func__, cur);

	return 0;
}

static int
tc_pool_free(tc_pool *pool)
{
	log_trace(fsio_lg, "%s", __func__);
	if (pool) {
		if (pool->tcs) {
			for (uint64_t i=0; i<pool->max_tc_count; i++) {
				if (pool->tcs[i])
					ccow_tenant_term(pool->tcs[i]);
			}
			je_free(pool->tcs);
		}
		// Clean bad list
		while (pool->bad_list) {
			ccow_tenant_term(pool->bad_list->tc);
			struct bad_node *bad = pool->bad_list;
			pool->bad_list = bad->next;
			je_free(bad);
		}
		je_free(pool);
	}

	log_debug(fsio_lg, "Completed: %s", __func__);
	return 0;
}

int
tc_pool_find_handle(char *cluster, char *tenant, void **tc_pool_handle)
{
	QUEUE *q;
	tc_pool *pool = NULL;

	QUEUE_FOREACH(q, &tc_pool_list) {
		pool = QUEUE_DATA(q, tc_pool, pool_q);
		if (!strcmp(pool->tenant, tenant) && !strcmp(pool->cluster, cluster)) {
			log_debug(fsio_lg, "Pool found for cluster: %s tenant: %s",
				cluster, tenant);
			*tc_pool_handle = (void *)pool;
			break;
		}
	}
	return 0;
}

int
tc_pool_term(void)
{
	QUEUE *q;
	QUEUE *tmp_q;
	tc_pool *pool = NULL;

	QUEUE_FOREACH_SAFE(q, tmp_q, &tc_pool_list) {
		pool = QUEUE_DATA(q, tc_pool, pool_q);
		QUEUE_REMOVE(&(pool->pool_q));
		tc_pool_free(pool);
	}
	return 0;
}
