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

#include "queue.h"
#include "ccow-impl.h"
#include "ccowd-impl.h"
#include "clengine.h"
#include "gw_cache.h"
#include "flexhash.h"
#include "ccowtp.h"

extern int ccowd_terminating;

void
ccowd_gw_cache_exec(void *arg)
{
	char buf[128];
	sprintf(buf, "GW_CACHE_GC.");
	clengine_notify(buf);
}

void
ccowd_gw_cache_done(void *arg, int status)
{
}

void
ccowd_gw_cache_start(void)
{
	ccowtp_work_queue(ccow_daemon->tp, CCOWD_TP_PRIO_NORMAL, ccowd_gw_cache_exec,
	    ccowd_gw_cache_done, NULL);
}

