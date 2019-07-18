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
#include <errno.h>
#include "ccowutil.h"
#include "ccow-impl.h"
#include "ccow.h"
#include "queue.h"
#include "vmm_cache.h"
#include "../src/libreplicast/replicast.h"

/*
 * global vm cache
 */
#define CCOW_VMM_HT_SIZE (8 * 1024)
#define CCOW_VMM_HT_MAX_LOAD_FACTOR (0.085)

/*
 * Initialize memory of VM marker hash table
 *
 * Scope: PRIVATE
 */
hashtable_t *
ccow_vmmcache_create(void)
{
	log_info(lg, "VMM creating hash table of size %d", CCOW_VMM_HT_SIZE);

	return hashtable_create(CCOW_VMM_HT_SIZE, 0,
	    CCOW_VMM_HT_MAX_LOAD_FACTOR);
}

/*
 * Insert reflist into VM marker hash table
 *
 * Scope: private
 */
void
ccow_vmmcache_put(hashtable_t *vmm_ht, uint512_t * nhid, vmmc_entry_t * ent)
{
	size_t val_size;

	assert(nhid != NULL);
	assert(ent != NULL);
	assert(ent->rb != NULL);

	uint512_logdump(lg, "VMM put nhid", nhid);
	uint512_logdump(lg, "VMM put chid", &ent->vm_chid);
	log_debug(lg, "VMM put generation = %"PRId64"", ent->generation);
	log_debug(lg, "VMM put vmm_gen_id = %"PRId64"", ent->vmm_gen_id);

	/*
	 * remove old
	 */
	vmmc_entry_t *ent_old = hashtable_get(vmm_ht, nhid, sizeof(uint512_t), &val_size);
	if (ent_old) {
		rtbuf_destroy(ent_old->rb);
		ent_old->rb = NULL;
		hashtable_remove(vmm_ht, nhid, sizeof(uint512_t));
	}

	/*
	 * insert new
	 */
	int err = hashtable_put(vmm_ht, nhid, sizeof(uint512_t),
	    ent, sizeof(vmmc_entry_t));
	assert(err == 0);
}

/*
 * Get reflist from VM hash table
 *
 * Scope: private
 */
int
ccow_vmmcache_get(hashtable_t *vmm_ht, uint512_t *nhid, vmmc_entry_t ** ent)
{
	uint32_t hv;

	assert(nhid != NULL);
	assert(ent != NULL);

	size_t ent_size;
	*ent = hashtable_get(vmm_ht, nhid, sizeof(uint512_t), &ent_size);

	if (*ent != NULL)
		assert(ent_size == sizeof(vmmc_entry_t));

	if (*ent != 0) {
		uint512_logdump(lg, "VMM get nhid", nhid);
		uint512_logdump(lg, "VMM get chid", &(*ent)->vm_chid);
		log_debug(lg, "VMM get generation = %"PRId64"", (*ent)->generation);
		log_debug(lg, "VMM get vmm_gen_id = %"PRId64"", (*ent)->vmm_gen_id);
	}

	return (*ent != NULL);
}

/*
 * Remove hash table entry
 *
 * Scope: private
 */
void
ccow_vmmcache_remove(hashtable_t *vmm_ht, uint512_t * nhid)
{
	size_t val_size;

	vmmc_entry_t *ent = hashtable_get(vmm_ht, nhid, sizeof(uint512_t), &val_size);
	if (!ent) {
		return;
	}

	uint512_logdump(lg, "VMM remove nhid", nhid);

	rtbuf_destroy(ent->rb);
	ent->rb = NULL;
	hashtable_remove(vmm_ht, nhid, sizeof(uint512_t));
}

/*
 * Destroy VM hash table and its contents.
 *
 * Scope: private
 */
void
ccow_vmmcache_free(hashtable_t *vmm_ht)
{
	uint512_t **keys;
	unsigned int key_count;
	size_t val_size;

	keys = (uint512_t **) hashtable_keys(vmm_ht, &key_count);

	for (unsigned int i = 0; i < key_count; i++) {
		vmmc_entry_t *ent = hashtable_get(vmm_ht, keys[i], sizeof(uint512_t), &val_size);
		rtbuf_destroy(ent->rb);
		hashtable_remove(vmm_ht, keys[i], sizeof(uint512_t));
	}

	if (keys)
		je_free(keys);

	hashtable_destroy(vmm_ht);
}

