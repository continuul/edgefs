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
#ifndef __RCVD_CACHE__
#define __RCVD_CACHE__

#ifdef	__cplusplus
extern "C" {
#endif

#include <uv.h>
#include "ccowutil.h"
#include "hashtable.h"


struct putcommon_srv_req;
struct repdev;

#define RCVD_CACHE_MAX_ENTRIES 10000


int reptrans_init_rcvd_cache(struct repdev *dev);
void reptrans_destroy_rcvd_cache(struct repdev *dev);

void reptrans_addto_rcvd_cache(hashtable_t *rcvd_cache, uint512_t *chid,
    struct putcommon_srv_req *req);
void reptrans_rmfrom_rcvd_cache(hashtable_t *rcvd_cache, uint512_t *chid);
struct putcommon_srv_req *reptrans_lookup_rcvd_cache(hashtable_t *rcvd_cache, uint512_t *chid);

#ifdef	__cplusplus
}
#endif

#endif
