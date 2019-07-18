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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <uv.h>
#include <wchar.h>
#include <netinet/in.h>
#include <nanomsg/nn.h>
#include <nanomsg/pubsub.h>
#include <nanomsg/pair.h>

#include "lfq.h"
#include "ccowutil.h"
#include "auditc.h"

#define MAX_MSG_LEN 2048

auditc_link *
auditc_init_with_namespace(const char *host, int port, const char *ns_)
{
	size_t len = strlen(ns_);

	auditc_link *temp = auditc_init(host, port);
	if (!temp) {
		log_error(lg, "auditc: out of memory");
		return NULL;
	}

	if ( (temp->ns = je_malloc(len + 2)) == NULL ) {
		auditc_finalize(temp);
		log_error(lg, "auditc: out of memory");
		return NULL;
	}
	strcpy(temp->ns, ns_);
	temp->ns[len++] = '.';
	temp->ns[len] = 0;

	return temp;
}

auditc_link *
auditc_init(const char *host, int port)
{
	auditc_link *temp = je_calloc(1, sizeof(auditc_link));
	if (!temp) {
		log_error(lg, "auditc_init: out of memory");
		goto err;
	}

	/*
	* we must set temp->sock_out & temp->sock_in to -1, because nn_socket can return 0 as normal good socket
	*/
	temp->sock_out = -1;
	temp->sock_in = -1;

	srandom(time(NULL));

	if (is_embedded())
		temp->msg_lfq = lfqueue_create(AUDITC_MSG_LFQ_DEPTH_EMBEDDED);
	else
		temp->msg_lfq = lfqueue_create(AUDITC_MSG_LFQ_DEPTH);
	if (!temp->msg_lfq) {
		log_error(lg, "auditc_init: msg_lfq out of memory");
		goto err;
	}

	if (port == 0) {
		/* connect as nanomsg ipc or tcp pair */

		temp->sock_out = nn_socket(AF_SP, NN_PAIR);
		if (temp->sock_out == -1) {
			log_error(lg, "auditc_init: create error: %s [%d]",
			    strerror(errno), (int)errno);
			goto err;
		}

		int linger = 100;
		nn_setsockopt(temp->sock_out, NN_SOL_SOCKET, NN_LINGER, &linger,
		    sizeof (linger));

		int millis = 200;
		nn_setsockopt(temp->sock_out, NN_SOL_SOCKET, NN_SNDTIMEO,
		    &millis, sizeof (millis));

		temp->eid_out = nn_connect(temp->sock_out, host);
		if(temp->eid_out < 0) {
			log_error(lg, "Failed connect to \"%s\": %s [%d]", host,
			    strerror(errno), (int)errno);
			nn_close(temp->sock_out);
			goto err;
		}
		log_info(lg, "Connected to auditd %s", host);
		return temp;
	}

	if ((temp->sock_out = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		log_error(lg, "auditc_init: UDP socket init error");
		goto err;
	}

	memset(&temp->server, 0, sizeof(temp->server));
	temp->server.sin_family = AF_INET;
	temp->server.sin_port = htons(port);

	struct addrinfo *result = NULL, hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;

	int error;
	if ( (error = getaddrinfo(host, NULL, &hints, &result)) ) {
		log_error(lg, "auditc_init: %s", gai_strerror(error));
		goto err;
	}
	memcpy(&(temp->server.sin_addr),
	    &((struct sockaddr_in*)result->ai_addr)->sin_addr,
	    sizeof (struct in_addr));
	freeaddrinfo(result);

	if (inet_aton(host, &(temp->server.sin_addr)) == 0) {
		log_error(lg, "auditc_init: inet_aton error");
		goto err;
	}

	return temp;

err:
	if (temp)
		je_free(temp);

	return NULL;
}

void
auditc_finalize(auditc_link *link)
{
	// close/shutdown socket

	///eid_in and eid_out can be -1
	if (link->sock_out != -1) {
		if (link->eid_out > 0) {
			nn_shutdown(link->sock_out, link->eid_out);
			nn_close(link->sock_out);
			link->eid_out = 0;
		} else
			close(link->sock_out);
		link->sock_out = -1;
	}
	if (link->sock_in != -1) {
		if (link->eid_in > 0) {
			nn_shutdown(link->sock_in, link->eid_in);
			nn_close(link->sock_in);
			link->eid_in = 0;
		} else
			close(link->sock_in);
		link->sock_in = -1;
	}
	// freeing ns
	if (link->ns) {
		je_free(link->ns);
		link->ns = NULL;
	}

	// clean up the queue
	char *msg;
	while ((msg = lfqueue_dequeue(link->msg_lfq)) != NULL) {
		je_free(msg);
	}

	lfqueue_destroy(link->msg_lfq);

	// free whole link
	je_free(link);
}

/* will change the original string */
static void
cleanup(char *stat)
{
	char *p;
	for (p = stat; *p; p++) {
		if (*p == ':' || *p == '|' || *p == '@') {
			*p = '_';
		}
	}
}

static int
should_send(float sample_rate)
{
	if (sample_rate < 1.0) {
		float p = ((float)(random() / RAND_MAX));
		return sample_rate > p;
	} else {
		return 1;
	}
}

int
auditc_send(auditc_link *link, const char *message)
{
	ssize_t len = strlen(message);
	if (link->eid_out > 0) {
		if (len != nn_send(link->sock_out, message, len, 0)) {
			log_info(lg, "auditc_send: %s", strerror(errno));
			return -1;
		}
		return 0;
	}

	int slen = sizeof(link->server);

	if (sendto(link->sock_out, message, len, 0,
		    (struct sockaddr *) &link->server, slen) == -1) {
		log_error(lg, "auditc_send: %s", strerror(errno));
		return -1;
	}
	return 0;
}

void
auditc_queue(auditc_link *link, const char *message)
{
	int err;

	char *msg = je_strdup(message);
	if (!msg) {
		log_error(lg, "auditc_queue: out of memory");
		return;
	}

	err = lfqueue_enqueue(link->msg_lfq, msg);
	if (err) {
		log_error(lg, "auditc_queue: unable to queue stat message: %d. "
		    "Queue is full?", err);
		je_free(msg);
	}
}

int
auditc_flush(auditc_link *link)
{
	int err = 0;
	char *msg;

	while ((msg = lfqueue_dequeue(link->msg_lfq)) != NULL) {
		err = auditc_send(link, msg);
		if (!err) {
			je_free(msg);
			continue;
		}

		/*
		 * This is not fatal error. It just means that this
		 * particular server having problems. Other Audit
		 * servers may compensate on the missing data.
		 *
		 * Just enqueue it back and try again later..
		 */
		int err2 = lfqueue_enqueue(link->msg_lfq, msg);
		if (err2) {
			log_error(lg, "auditc_flush: unable to enqueue "
			    "message back: %d", err2);
		}
		break;
	}

	return err;
}

static void
send_stat(auditc_link *link, char *stat, size_t value, const char *type,
    float sample_rate)
{
	char message[MAX_MSG_LEN];
	if (!should_send(sample_rate))
		return;

	auditc_prepare(link, stat, value, type, sample_rate, message,
	    MAX_MSG_LEN, 0);

	auditc_queue(link, message);
}

static int
send_stat_low(auditc_link *link, uint64_t total_pending, char *stat, size_t value,
		const char *type,  float sample_rate)
{
	char message[MAX_MSG_LEN];
	if (!should_send(sample_rate))
		return 0;

	if (total_pending > LOW_MSG_LFQ_DEPTH_HIWAT) {
		log_warn(lg, "LFQ depth too high (%lu), dropping low priority stats: %s (HIWAT)",
				total_pending, stat);
		return 0;
	}

	auditc_prepare(link, stat, value, type, sample_rate, message,
	    MAX_MSG_LEN, 0);

	auditc_queue(link, message);

	if (total_pending > LOW_MSG_LFQ_DEPTH_LOWAT) {
		log_debug(lg, "LFQ depth too high (%lu), dropping low priority stats: %s (LOWAT)",
				total_pending, stat);
		return 0;
	}
	return 1;
}


void
auditc_prepare(auditc_link *link, char *stat, size_t value, const char *type,
    float sample_rate, char *message, size_t buflen, int lf)
{
	cleanup(stat);
	if (sample_rate == 1.0) {
		snprintf(message, buflen, "%s%s:%zd|%s%s",
		    link->ns ? link->ns : "", stat, value, type,
		    lf ? "\n" : "");
	} else {
		snprintf(message, buflen, "%s%s:%zd|%s|@%.2f%s",
		    link->ns ? link->ns : "", stat, value, type, sample_rate,
		    lf ? "\n" : "");
	}
}

/* public interface */
void
auditc_count(auditc_link *link, char *stat, size_t value, float sample_rate)
{
	send_stat(link, stat, value, "c", sample_rate);
}

void
auditc_dec(auditc_link *link, char *stat, float sample_rate)
{
	auditc_count(link, stat, -1, sample_rate);
}

void
auditc_inc(auditc_link *link, char *stat, float sample_rate)
{
	auditc_count(link, stat, 1, sample_rate);
}

void
auditc_gauge(auditc_link *link, char *stat, size_t value)
{
	send_stat(link, stat, value, "g", 1.0);
}

int
auditc_low_gauge(auditc_link *link, uint64_t total_pending, char *stat, size_t value)
{
	return send_stat_low(link, total_pending, stat, value, "g", 1.0);
}

void
auditc_timer(auditc_link *link, char *stat, size_t ms)
{
	send_stat(link, stat, ms, "ms", 1.0);
}

void
auditc_set(auditc_link *link, char *key, char *val)
{
	char message[MAX_MSG_LEN];

	snprintf(message, MAX_MSG_LEN, "%s%s:%s|s", link->ns ? link->ns : "",
	    key, val);

	auditc_queue(link, message);
}

void
auditc_kv(auditc_link *link, char *stat, float val)
{
	char message[MAX_MSG_LEN];

	snprintf(message, MAX_MSG_LEN, "%s%s:%f|k", link->ns ? link->ns : "",
	    stat, val);

	auditc_queue(link, message);
}

int
auditc_subscribe(uv_loop_t *loop, char *pub_address, char *topic,
    int *sub_fd, uv_poll_t *sub_req, uv_poll_cb sub_cb)
{
	int lsub_fd;
	int err;

	lsub_fd = nn_socket(AF_SP, NN_SUB);
	if (lsub_fd < 0) {
		log_error(lg, "socket create error: %s [%d]",
		    strerror(errno), (int)errno);
		return -errno;
	}


	err = nn_connect(lsub_fd, pub_address);
	if(err < 0) {
		nn_close(lsub_fd);
		log_error(lg, "Failed connect to \"%s\": %s [%d]", pub_address,
		    strerror(errno), (int)errno);
		return -errno;
	}

	err = nn_setsockopt(lsub_fd, NN_SUB, NN_SUB_SUBSCRIBE, topic,
	    strlen(topic));
	if (err < 0) {
		nn_close(lsub_fd);
		log_error(lg, "setsockopt subscribe error: %s [%d]",
		    strerror(errno), (int)errno);
		return -errno;
	}

	int ipc_fd;
	size_t fdsz = sizeof (ipc_fd);
	err = nn_getsockopt (lsub_fd, NN_SOL_SOCKET, NN_RCVFD,
	    (char *)&ipc_fd, &fdsz);
	if (err < 0) {
		nn_close(lsub_fd);
		log_error(lg, "setsockopt rcv_fd error: %s [%d]",
		    strerror(errno), (int)errno);
		return -errno;
	}

	uv_poll_init(loop, sub_req, ipc_fd);
	uv_poll_start(sub_req, UV_READABLE, sub_cb);
	*sub_fd = lsub_fd;
	return 0;
}

int
auditc_unsubscribe(int *sub_fd, uv_poll_t *sub_req, char *topic)
{
	int err;

	int lsub_fd = *sub_fd;
	err = nn_setsockopt(lsub_fd, NN_SUB, NN_SUB_UNSUBSCRIBE, topic,
	    strlen(topic));
	if (err < 0) {
		nn_close(lsub_fd);
		log_error(lg, "setsockopt error: %s [%d]",
		    strerror(errno), (int)errno);
		return -errno;
	}

	uv_poll_stop(sub_req);
	uv_close((uv_handle_t *)sub_req, NULL);

	nn_close(lsub_fd);
	*sub_fd = -1;

	return 0;
}
