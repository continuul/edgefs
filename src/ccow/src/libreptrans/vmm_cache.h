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
#ifndef __VMM_CACHE__
#define __VMM_CACHE__

#ifdef	__cplusplus
extern "C" {
#endif

#include "rtbuf.h"

typedef struct vmmc_entry {
	uint512_t vm_chid;
	uint64_t generation;
	uint64_t vmm_gen_id;
	rtbuf_t *rb;
} vmmc_entry_t;

hashtable_t * ccow_vmmcache_create(void);
void ccow_vmmcache_free(hashtable_t *vmm_ht);

void ccow_vmmcache_put(hashtable_t *vmm_ht, uint512_t *chid, vmmc_entry_t *ent);
int  ccow_vmmcache_get(hashtable_t *vmm_ht, uint512_t *chid, vmmc_entry_t **ent);
void ccow_vmmcache_remove(hashtable_t *vmm_ht, uint512_t *chid);

#ifdef	__cplusplus
}
#endif

#endif
