//
// Copyright (c) 2015-2018 Nexenta Systems, inc.
//
// This file is part of EdgeFS Project
// (see https://github.com/Nexenta/edgefs).
//
// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
//


#ifndef _PMU_NET_H
#define _PMU_NET_H

#include "pmu.h"

typedef struct netcfg_ {
	uv_idle_t idle_handle;
	volatile bool collect_shutdown;
} netcfg_t;

void net_init();
void net_close();

void net_loop (pmu_if_t *pi, uv_loop_t *loop, bool direct_completion);
void net_loop_idle(uv_idle_t* handle, int status);
void signal_handler_uv(uv_signal_t* handle, int signum);

void collect_replies_thread (void *arg);
void do_send ( pmu_if_t *pi, unsigned n_send, size_t fill_size, struct sockaddr_in6 *dest);

#endif /* _PMU_NET_H */
