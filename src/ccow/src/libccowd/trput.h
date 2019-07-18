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

#ifndef __TRPUT_H__
#define __TRPUT_H__

void ccowd_tran_start(void);

#include "rtbuf.h"
#include "ccow.h"

typedef struct  trlog_tn_acct_ht {
	int64_t delta_size;
	int64_t delta_objs;
	int64_t delta_used;
} trlog_entry_t;

void trlog_ht_create(void);
void trlog_ht_free(void);

int trlog_update_tenant_obj(ccow_t tc, char *cid, char *tid,
    int64_t delta_size, int64_t delta_objs, int64_t delta_used);
int trlog_ht_put(char *cid_tid, trlog_entry_t *ent);
int  trlog_ht_get(char *cid_tid, trlog_entry_t **ent);

void acct_ht_create(void);

#endif
