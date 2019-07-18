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
#ifndef __AUDITC_H__
#define __AUDITC_H__

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "lfq.h"

#define AUDITC_MSG_LFQ_DEPTH		(1 * 1024 * 1024)
#define AUDITC_MSG_LFQ_DEPTH_EMBEDDED	(64 * 1024)
#define LOW_MSG_LFQ_DEPTH_LOWAT 32	/* needs to be less then Main TP # */
#define LOW_MSG_LFQ_DEPTH_HIWAT 1024	/* needs to be reasonably high in the
					   context of single flush*/

struct _auditc_link  {
	struct sockaddr_in server;
	lfqueue_t msg_lfq;
	int eid_in;
	int sock_in;
	int eid_out;
	int sock_out;
	char *ns;
};

typedef struct _auditc_link auditc_link;

auditc_link *auditc_init(const char *host, int port);
auditc_link *auditc_init_with_namespace(const char *host, int port,
    const char *ns);
void auditc_finalize(auditc_link *link);

/*
 * write the stat line to the provided buffer,
 * type can be "c", "g" or "ms"
 * lf - whether line feed needs to be added
 */
void auditc_prepare(auditc_link *link, char *stat, size_t value,
    const char *type, float sample_rate, char *buf, size_t buflen, int lf);

/* Manually send a message, which might be composed of several lines.
 * Must be null-terminated */
int auditc_send(auditc_link *link, const char *message);

void auditc_queue(auditc_link *link, const char *message);
int auditc_flush(auditc_link *link);

void auditc_inc(auditc_link *link, char *stat, float sample_rate);
void auditc_dec(auditc_link *link, char *stat, float sample_rate);
void auditc_count(auditc_link *link, char *stat, size_t count,
    float sample_rate);
void auditc_gauge(auditc_link *link, char *stat, size_t value);
int  auditc_low_gauge(auditc_link *link, uint64_t total_pending, char *stat, size_t value);
void auditc_timer(auditc_link *link, char *stat, size_t ms);
void auditc_set(auditc_link *link, char *key, char *val);
void auditc_kv(auditc_link *link, char *key, float val);


/* subscribe/unsubscribe API */


/* subscribe to the audit server
 *
 * @param loop - uv loop
 * @param pub_address - address in the form: "tcp://ip_address:port"
 * @param topic - topic described in the dot notation
 *                e.g. "counts.ccow.namedput.bytes"
 * @param sub_fd - file descriptor for the subscription
 * @param sub_req - uv_poll_t for the subscription
 * @param sub_cb - callback when subscription is done
 * @internal
 */
int auditc_subscribe(uv_loop_t *loop, char *pub_address, char *topic,
    int *sub_fd, uv_poll_t *sub_req, uv_poll_cb sub_cb);

/* unsubscribe from a already subscribed channel
 *
 * @param sub_fd - file descriptor for the subscription
 * @param sub_req - uv_poll_t used for subscription
 * @param topic - topic to unsubscribe from. should be in the dot notation
 *		e.g. "counts.ccow.namedput.bytes"
 * @internal
 */
int auditc_unsubscribe(int *sub_fd, uv_poll_t *sub_req, char *topic);

#ifdef	__cplusplus
}
#endif

#endif
