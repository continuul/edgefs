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
#ifndef __SERVERID_H__
#define __SERVERID_H__

#ifdef	__cplusplus
extern "C" {
#endif

#include "ccowutil.h"

#define SERVERID_CACHE_FILE "%s/var/run/serverid.cache"
#define INSTALL_TYPE_FILE "%s/.install-type"
#define SERVER_ID_MAXLEN (UINT128_BYTES * 2 + 1)
#define BAREMETAL_INSTALL_TYPE "baremetal"

extern int serverid_init();
extern void serverid_dump(char *out, int len);

#define MAX_SERVER_NAME		128
#define CONTAINERID_SIZE	128
#define MAX_INSTALLTYPE		32
struct server_stat {
	int		isaggregator;	/* whether node is aggregator */
	int		zone;		/* node zone */
	float		cpuspeed;	/* CPU MHz */
	float		loadavg1;	/* System Load Average over 1min */
	float		loadavg5;	/* System Load Average over 5min */
	float		loadavg15;	/* System Load Average over 15min */
	uint64_t	memtotal;	/* total amount of RAM in the server*/
	uint64_t	memused;	/* used amount of RAM in the server*/
	uint64_t	swapused;	/* used amount of swap in the server*/
	char		name[MAX_SERVER_NAME]; /* hostname of this server */
	char		installtype[MAX_INSTALLTYPE]; /* installtype used for this server */
	char		containerid[CONTAINERID_SIZE + 1]; /* container id of this server */
	uint128_t	id;		/* id of this server */
	uint16_t	numcpu;		/* number of CPUs */
	uint8_t		numdisks;	/* number of raw disks in edge */
};

extern int server_init();
extern struct server_stat *server_get();
extern struct server_stat *server_get_invalidate();
extern void server_dump(char *out, int len);

#define MAX_SERVER_STR_LEN	512

#ifdef	__cplusplus
}
#endif

#endif
