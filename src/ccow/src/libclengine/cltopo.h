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
#ifndef __CLTOPO_H__
#define __CLTOPO_H__

#ifdef	__cplusplus
extern "C" {
#endif

#include "clengine.h"
#include "flexhash.h"

#define SERVER_LIST_GET_MAX_RETRY	20
#define SERVER_LIST_GET_TIMEOUT_MS	1000
#define START_DELAY_MAX_MS		100

int cltopo_server_list_init(struct replicast *robj, struct repctx *ctx,
    struct state *state);
int cltopo_learn(struct cl_node *cn, int expected_nr_nodes, int allnodes,
    struct cluster_engine *ceng);

#ifdef	__cplusplus
}
#endif

#endif
