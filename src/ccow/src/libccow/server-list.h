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
#ifndef __SERVER_LIST_H__
#define __SERVER_LIST_H__

#ifdef	__cplusplus
extern "C" {
#endif

#define SERVER_LIST_GET_MAX_RETRY		240
#define SERVER_LIST_GET_TIMEOUT_MS		1000
#define SERVER_LIST_GET_ERROR_RETRY_TIMEOUT_MS	250

#define SERVER_LIST_GET_CHECKPOINT	0x2

int server_list_get_init(struct ccow_network *netobj, struct ccow_completion *c,
    uint128_t serverid, struct cl_node *node, uint32_t flags);

int server_list_async_fetch(struct replicast *robj, struct repctx *ctx,
    struct state *state);

#ifdef	__cplusplus
}
#endif

#endif
