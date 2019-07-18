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
#ifndef __HASHCOUNT_H__
#define __HASHCOUNT_H__



#ifdef __cplusplus
extern "C" {
#endif


typedef uint16_t	hcrow_t;

struct hashcount {
	int		numrows;
	uint16_t	*entry;
};

extern struct hashcount *g_hashcount;

struct hashcount *hashcount_create(int numrows);

void   hashcount_destroy(struct hashcount *hc);

uint16_t hashcount_incr(struct hashcount *hc, hcrow_t rowid);

uint16_t hashcount_decr(struct hashcount *hc, hcrow_t rowid);

uint16_t hashcount_entry(struct hashcount *hc, hcrow_t rowid);

#define hc_incr(h, r)   (h->entry[r])++
#define hc_decr(h, r)   (h->entry[r])--
#define hc_entry(h, r)  (h->entry[r])
#define hc_set(h, r, v) (h->entry[r] = v)

struct hashcount *hashcount_default();

#ifdef __cplusplus
}
#endif



#endif /* __HASHCOUNT_H__ */
