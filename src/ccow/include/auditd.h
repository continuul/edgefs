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
#ifndef __AUDITD_H__
#define __AUDITD_H__

#ifdef	__cplusplus
extern "C" {
#endif

#include <linux/limits.h>
#include "queue.h"

#define AUDITD_TOPIC_MAXLEN	2048
#define AUDITD_PUB_PORT		10395

#define AUDITD_IPC_ADDRESS "ipc://%s/var/run/auditd.ipc"

extern int auditd_daemonize;
extern char auditd_pidfile[PATH_MAX];

struct auditd_query_resp {
	QUEUE item;
	char* entry;
};

int auditd_stats_query(const char* query, QUEUE* response);

int
auditd_stats_sharedlock(void** handle);

int
auditd_stats_sharedunlock(void* handle);

const char *auditd_setup_pidfile_var();

int auditd_init();
void auditd_term(int sigwait);

#ifdef	__cplusplus
}
#endif

#endif
