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
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <linux/limits.h>

#include <ccow.h>
#include <ccowfsio.h>
#include <logger.h>

#include <fsio_system.h>
#include <fsio_common.h>
#include <fsio_inode.h>
#include <fsio_namespace.h>
#include <fsio_s3_transparency.h>
#include <fsio_snapshot.h>

#define SKIPSPACES(s) do { while(*s && isspace(*s)) s++; } while(0)
#define MATCH(v, s) \
    (strcasestr(v, #s) == v && (isspace(v[strlen(#s)]) || v[strlen(#s)] == '\0'))

#define CLIENT_STATUS_DISCONNECT    1
#define EPOLL_ARRAY_SIZE   64

/* [TODO] decide the max command lenght.
 * Current calculation:
 * Max command is clone:
 * cluster/tenant/src_bucket/dest_bucket/src_path/dest_path/flags
 *  Assuming that each can be PATH_MAX.
 * flags will be much less
 * The '\n' at the ends of each name will be withing (PATH_MAX - strlen(flags))
 *
 */
#define MAX_COMMAND_LENGTH (7 * PATH_MAX)

struct client
{
	struct client *next;
	int fd, rp, wp, buflen;
	int status;
	char rbuf[MAX_COMMAND_LENGTH];
	char *buf;
};

typedef int (*COMMAND_HANDLER) (struct client * e, void *args,
    char **reply_msg, size_t * reply_msg_size);

typedef struct __control_thread_context__
{
	pthread_t control_thread;
	uint8_t control_thread_stop;
	COMMAND_HANDLER cmd_handler[MAX_CONTORL_COMMANDS];

} fsio_control_thread_ctx;

static int
cmd_hanlder_log_performance_stats(struct client *e, void *args,
    char **reply_msg, size_t *reply_msg_size)
{
	int err = 0;
	char *payload = (char *) args;
	char *c;
	int param_count = 0;
	char *cid, *tid, *bid;
	ci_t *ci;
	int cid_size, tid_size, bid_size;

	log_trace(fsio_lg,"e: %p, args: %p, reply_msg: %p, "
	    "reply_msg_size: %p", e, args, reply_msg, reply_msg_size);

	/*Replace all new line chars to string end */
	for (c=payload; *c != '\0'; c++) {
		if (*c == '\n'){
			*c = '\0';
			param_count++;
		}
	}

	if (param_count != LOG_STATS_PARAM_COUNT) {
		/*We expect 3 parameters */
		err = EINVAL;
		log_error(fsio_lg, "Wrong parameters count");
		goto out;
	}

	cid = payload;
	cid_size = strlen(cid) + 1;
	tid = cid + cid_size;
	tid_size = strlen(tid) + 1;
	bid = tid + tid_size;
	bid_size = strlen(bid) + 1;

	err = ccow_fsio_find_export(cid, cid_size, tid, tid_size, bid,
	    bid_size, &ci);
	if (err) {
		log_error(fsio_lg, "ccow_fsio_find_export return %d", err);
		goto out;
	}

	fsio_debug_log_api_stats(ci);

out:
	log_debug(fsio_lg,"completed e: %p, args: %p, "
	    "reply_msg: %p, reply_msg_size: %p", e, args, reply_msg,
	    reply_msg_size);

	return err;
}

static int
cmd_hanlder_set_log_level(struct client *e, void *args,
    char **reply_msg, size_t *reply_msg_size)
{
	int err = 0;
	char *payload = (char *) args;
	int param_count = 0;
	char *c, *level_str, *autoflush_str;
	int level, autoflush;

	log_trace(fsio_lg,"e: %p, args: %p, reply_msg: %p, "
	    "reply_msg_size: %p", e, args, reply_msg, reply_msg_size);

	/*Replace all new line chars to string end */
	for (c=payload; *c != '\0'; c++) {
		if (*c == '\n'){
			*c = '\0';
			param_count++;
		}
	}

	if (param_count != SET_LOG_LEVEL_PARAM_COUNT) {
		/*We expect 2 parameters */
		err = EINVAL;
		log_error(fsio_lg, "Wrong parameters count");
		goto out;
	}

	level_str = payload;
	level = atoi(level_str);
	autoflush_str = level_str + strlen(level_str) + 1;
	autoflush = atoi(autoflush_str);

	if (level > LOG_LEVEL_NOTICE)
		level = LOG_LEVEL_NOTICE;
	else if (level < 0)
		level = 0;

	log_set_level(fsio_lg, level);
	log_set_autoflush(fsio_lg, autoflush);

out:
	log_debug(fsio_lg,"completed e: %p, args: %p, "
	    "reply_msg: %p, reply_msg_size: %p", e, args, reply_msg,
	    reply_msg_size);

	return err;
}
static int
cmd_hanlder_clone_file(struct client *e, void *args, char **reply_msg,
    size_t * reply_msg_size)
{
	int err = 0;
	char *payload = (char *) args;
	char *c;
	int param_count = 0;
	char *cid, *tid, *src_bid, *dest_bid;
	char *src_path, *dest_path;
	int cid_size, tid_size, src_bid_size, dest_bid_size;
	int src_path_size, dest_path_size;
	uint32_t flags;

	log_trace(fsio_lg,"e: %p, args: %p, reply_msg: %p, "
	    "reply_msg_size: %p", e, args, reply_msg, reply_msg_size);

	/*
	 * Replace all new line chars to string end 
	 */
	for (c = payload; *c != '\0'; c++) {
		if (*c == '\n') {
			*c = '\0';
			param_count++;
		}
	}

	if (param_count != CLONE_FILE_PARAM_COUNT) {
		/*
		 * We expect 7 parameters 
		 */
		err = EINVAL;
		log_error(fsio_lg, "Wrong parameters count");
		goto out;
	}

	cid = payload;
	cid_size = strlen(cid) + 1;
	tid = cid + cid_size;
	tid_size = strlen(tid) + 1;
	src_bid = tid + tid_size;
	src_bid_size = strlen(src_bid) + 1;
	dest_bid = src_bid + src_bid_size;
	dest_bid_size = strlen(dest_bid) + 1;
	src_path = dest_bid + dest_bid_size;
	src_path_size = strlen(src_path) + 1;
	dest_path = src_path + src_path_size;
	dest_path_size = strlen(dest_path) + 1;
	flags = atoi(dest_path + dest_path_size);

	err = ccow_fsio_clone_file(cid, tid, src_bid, dest_bid,
	    src_path, dest_path, flags);
	if (err)
		log_error(fsio_lg, "ccow_fsio_clone_file return %d",
		    err);

out:
	log_debug(fsio_lg,"completed e: %p, args: %p, "
	    "reply_msg: %p, reply_msg_size: %p", e, args, reply_msg,
	    reply_msg_size);

	return err;
}

static int
cmd_hanlder_ping(struct client *e, void *args, char **reply_msg,
    size_t * reply_msg_size)
{

	log_trace(fsio_lg,"e: %p, args: %p, reply_msg: %p, "
	    "reply_msg_size: %p", e, args, reply_msg, reply_msg_size);

	/*
	 * Return the payload as response 
	 */
	*reply_msg = je_strdup((char *) args);
	*reply_msg_size = strlen(*reply_msg) + 1;

	log_debug(fsio_lg,"completed e: %p, args: %p, "
	    "reply_msg: %p, reply_msg_size: %p", e, args, reply_msg,
	    reply_msg_size);

	return 0;
}

static int
cmd_hanlder_snap_create(struct client *e, void *args,
    char **reply_msg, size_t * reply_msg_size)
{
	int err = 0;
	char *payload = (char *) args;
	char *c;
	int param_count = 0;
	char *cid, *tid, *bid;
	char *path, *snap_name;
	ci_t *ci;
	int cid_size, tid_size, bid_size;

	log_trace(fsio_lg,"e: %p, args: %p, reply_msg: %p, "
	    "reply_msg_size: %p", e, args, reply_msg, reply_msg_size);

	/*
	 * Replace all new line chars to string end 
	 */
	for (c = payload; *c != '\0'; c++) {
		if (*c == '\n') {
			*c = '\0';
			param_count++;
		}
	}

	if (param_count != SNAP_CREATE_PARAM_COUNT) {
		/*
		 * We expect 5 parameters 
		 */
		err = EINVAL;
		log_error(fsio_lg, "Wrong parameters count");
		goto out;
	}

	cid = payload;
	cid_size = strlen(cid) + 1;
	tid = cid + cid_size;
	tid_size = strlen(tid) + 1;
	bid = tid + tid_size;
	bid_size = strlen(bid) + 1;
	path = bid + bid_size;
	snap_name = path + strlen(path) + 1;

	err = ccow_fsio_find_export(cid, cid_size, tid, tid_size, bid, bid_size,
	    &ci);
	if (err) {
		log_error(fsio_lg,
		    "ccow_fsio_clone_file return %d", err);
		goto out;
	}

	err = fsio_snapshot_create(ci, path, snap_name);
	if (err)
		log_error(fsio_lg,
		    "fsio_snapshot_create return %d", err);

out:
	log_debug(fsio_lg,"completed e: %p, args: %p, "
	    "reply_msg: %p, reply_msg_size: %p", e, args, reply_msg,
	    reply_msg_size);

	return err;
}

static int
cmd_hanlder_snap_delete(struct client *e, void *args,
    char **reply_msg, size_t * reply_msg_size)
{
	int err = 0;
	char *payload = (char *) args;
	char *c;
	int param_count = 0;
	char *cid, *tid, *bid;
	int cid_size, tid_size, bid_size;
	char *path, *snap_name;
	ci_t *ci;

	log_trace(fsio_lg,"e: %p, args: %p, reply_msg: %p, "
	    "reply_msg_size: %p", e, args, reply_msg, reply_msg_size);

	/*
	 * Replace all new line chars to string end 
	 */
	for (c = payload; *c != '\0'; c++) {
		if (*c == '\n') {
			*c = '\0';
			param_count++;
		}
	}

	if (param_count != SNAP_DELETE_PARAM_COUNT) {
		/*
		 * We expect 5 parameters 
		 */
		err = EINVAL;
		log_error(fsio_lg, "Wrong parameters count");
		goto out;
	}

	cid = payload;
	cid_size = strlen(cid) + 1;
	tid = cid + cid_size;
	tid_size = strlen(tid) + 1;
	bid = tid + tid_size;
	bid_size = strlen(bid) + 1;
	path = bid + bid_size;
	snap_name = path + strlen(path) + 1;

	err = ccow_fsio_find_export(cid, cid_size, tid, tid_size, bid, bid_size,
	    &ci);
	if (err) {
		log_error(fsio_lg,
		    "fsio_snapshot_create return %d", err);
		goto out;
	}

	err = fsio_snapshot_delete(ci, path, snap_name);
	if (err)
		log_error(fsio_lg,
		    "fsio_snapshot_delete return %d", err);

out:
	log_debug(fsio_lg,"completed e: %p, args: %p, "
	    "reply_msg: %p, reply_msg_size: %p", e, args, reply_msg,
	    reply_msg_size);

	return err;
}

/** Convert the 2D string array to single buffer with '\n' separated strings.
 *  This way we can return the result over IPC
 */
static int
__convert_snap_list_to_single_string(uint64_t snap_count, char **snap_list,
    char **out_list)
{
	int err = 0;
	int sz = 0;

	log_trace(fsio_lg,"snap_count: %lu, snap_list: %p, "
	    "out_list: %p", snap_count, snap_list, out_list);

	if (snap_count == 0) {
		*out_list = je_strdup("No Snaps");
		log_debug(fsio_lg, "snap_count is 0");
		return err;
	}

	for (uint64_t i = 0; i < snap_count; i++) {
		sz += strlen(snap_list[i]);
	}

	/*
	 * Allocate space for strings of total sz size,
	 * * snap_count '\n' chars
	 * * and '\0' at the ned
	 */
	*out_list = (char *) je_calloc(1, sz + snap_count + 1);
	if (out_list == NULL || *out_list == NULL) {
		err = ENOMEM;
		log_error(fsio_lg, "Failed to allocate memory");
		goto out;
	}

	for (uint64_t i = 0; i < snap_count; i++) {
		strcat(*out_list, snap_list[i]);
		strcat(*out_list, "\n");
	}

out:
	log_debug(fsio_lg,"completed snap_count: %lu, "
	    "snap_list: %p, out_list: %p", snap_count, snap_list, out_list);

	return err;
}

static int
cmd_hanlder_snap_list(struct client *e, void *args,
    char **reply_msg, size_t * reply_msg_size)
{
	int err = 0;
	char *payload = (char *) args;
	char *c;
	int param_count = 0;
	char *cid, *tid, *bid;
	int cid_size, tid_size, bid_size;
	char *path;
	ci_t *ci;
	char **snap_list = NULL;
	uint64_t snap_count = 0;
	char *list_buf = NULL;

	log_trace(fsio_lg, "e: %p, args: %p, reply_msg: %p, "
	    "reply_msg_size: %p", e, args, reply_msg, reply_msg_size);

	/*
	 * Replace all new line chars to string end 
	 */
	for (c = payload; *c != '\0'; c++) {
		if (*c == '\n') {
			*c = '\0';
			param_count++;
		}
	}

	if (param_count != SNAP_LIST_PARAM_COUNT) {
		/*
		 * We expect 4 parameters 
		 */
		err = EINVAL;
		log_error(fsio_lg, "Wrong parameters count");
		goto out;
	}

	cid = payload;
	cid_size = strlen(cid) + 1;
	tid = cid + cid_size;
	tid_size = strlen(tid) + 1;
	bid = tid + tid_size;
	bid_size = strlen(bid) + 1;
	path = bid + bid_size;

	err = ccow_fsio_find_export(cid, cid_size, tid, tid_size, bid, bid_size,
	    &ci);
	if (err) {
		log_error(fsio_lg, "fsio_snapshot_delete return %d",
		    err);
		goto out;
	}

	err = fsio_snapshot_list(ci, path, &snap_count, &snap_list);
	if (err) {
		log_error(fsio_lg, "fsio_snapshot_list return %d",
		    err);
		goto out;
	}

	err = __convert_snap_list_to_single_string(snap_count, snap_list,
	    &list_buf);
	if (err)
		log_error(fsio_lg,
		    "__convert_snap_list_to_single_string return %d", err);

out:
	if (!err) {
		*reply_msg = list_buf;
		*reply_msg_size = strlen(list_buf) + 1;
	} else if (list_buf)
		je_free(list_buf);

	if (snap_list) {
		for (uint64_t i = 0; i < snap_count; i++)
			je_free(snap_list[i]);
		je_free(snap_list);
	}

	log_debug(fsio_lg, "completed e: %p, args: %p, "
	    "reply_msg: %p, reply_msg_size: %p", e, args, reply_msg,
	    reply_msg_size);

	return err;
}

static int
cmd_hanlder_snap_rollback(struct client *e, void *args,
    char **reply_msg, size_t * reply_msg_size)
{
	int err = 0;
	char *payload = (char *) args;
	char *c;
	int param_count = 0;
	char *cid, *tid, *bid;
	char *path, *snap_name;
	ci_t *ci;
	int cid_size, tid_size, bid_size;

	log_trace(fsio_lg, "e: %p, args: %p, reply_msg: %p, "
	    "reply_msg_size: %p", e, args, reply_msg, reply_msg_size);

	/*
	 * Replace all new line chars to string end 
	 */
	for (c = payload; *c != '\0'; c++) {
		if (*c == '\n') {
			*c = '\0';
			param_count++;
		}
	}

	if (param_count != SNAP_ROLLBACK_PARAM_COUNT) {
		/*
		 * We expect 5 parameters 
		 */
		err = EINVAL;
		log_error(fsio_lg, "Wrong parameters count");
		goto out;
	}

	cid = payload;
	cid_size = strlen(cid) + 1;
	tid = cid + cid_size;
	tid_size = strlen(tid) + 1;
	bid = tid + tid_size;
	bid_size = strlen(bid) + 1;
	path = bid + bid_size;
	snap_name = path + strlen(path) + 1;

	err = ccow_fsio_find_export(cid, cid_size, tid, tid_size, bid, bid_size,
	    &ci);
	if (err) {
		log_error(fsio_lg,
		    "ccow_fsio_find_export return %d", err);
		goto out;
	}

	err = fsio_snapshot_rollback(ci, path, snap_name);
	if (err)
		log_error(fsio_lg,
		    "fsio_snapshot_rollback return %d", err);

out:
	log_debug(fsio_lg, "completed e: %p, args: %p, "
	    "reply_msg: %p, reply_msg_size: %p", e, args, reply_msg,
	    reply_msg_size);

	return err;
}

/* Simple SLL. */
static struct client *
CLIENT_LIST_PREPEND(struct client **q, int fd)
{
	struct client *e;

	log_trace(fsio_lg,"q: %p, fd: %d", q, fd);
	e = je_calloc(1, sizeof(struct client));
	e->buf = (char *) je_malloc(MAX_COMMAND_LENGTH);
	e->fd = fd;
	e->buflen = MAX_COMMAND_LENGTH;
	if (*q != NULL)
		e->next = *q;
	*q = e;

	return (e);
}

static struct client *
CLIENT_LIST_FIND(struct client *q, int fd)
{
	struct client *c;

	log_trace(fsio_lg,"q: %p, fd: %d", q, fd);
	for (c = q; c != NULL; c = c->next) {
		if (c->fd == fd)
			return (c);
	}

	return (NULL);
}

static void
CLIENT_LIST_DESTROY(struct client *q)
{
	struct client *c, *tmp;

	log_trace(fsio_lg,"q: %p", q);
	for (c = q; c != NULL;) {
		tmp = c->next;
		shutdown(c->fd, SHUT_RDWR);
		close(c->fd);
		if (c->buf)
			je_free(c->buf);
		je_free(c);
		c = tmp;
	}
}

static void
CLIENT_LIST_REMOVE(struct client **q, struct client *e)
{
	struct client *c;

	log_trace(fsio_lg,"q: %p, e: %p", q, e);
	if (*q == NULL || e == NULL)
		return;

	/*
	 * Most frequent way.
	 */
	if ((*q)->next == NULL && *q == e) {
		*q = NULL;
		goto done;
	}

	for (c = *q; c != NULL; c = c->next) {
		if (c->next == e) {
			c->next = e->next;	/* Same as c->next->next. */
			goto done;
		}
	}

	/*
	 * Not found.
	 */
	return;
done:
	shutdown(e->fd, SHUT_RDWR);
	close(e->fd);
	je_free(e->buf);
	je_free(e);
}

void
stripcrlf(char *s)
{
	char *d;

	log_trace(fsio_lg,"s: \"%s\"", s);
	d = strchr(s, '\r');
	if (d == NULL)
		d = strchr(s, '\n');
	if (d == NULL)
		return;
	*d = '\0';
}

int
parsecmd(struct client *e, fsio_control_thread_ctx * ctx)
{
	char *cmd, *payload;
	char *reply_msg = NULL;
	fsio_control_cmds cmd_id;
	int err;

	log_trace(fsio_lg, "e: %p, ctx: %p", e, ctx);
	cmd = e->rbuf;
	size_t reply_msg_size = 0;

	/*
	 * We get the commad ID at start of the command.
	 * Remaining part of the command is the payload for the specific
	 * command.
	 */
	payload = strchr(cmd, '\n');
	if (payload) {
		*payload = '\0';
		payload++;
	}

	cmd_id = atoi(cmd);

	log_error(fsio_lg,
	    "FSIO control command received. cmd :%d, payload :%s", cmd_id,
	    payload);

	if (cmd_id >= MAX_CONTORL_COMMANDS) {
		sprintf(e->buf, "ERR: Unoknown command id: %d.", cmd_id);
		goto failed;
	}

	/*
	 * Call the cmd handler with the payload
	 */
	err = ctx->cmd_handler[cmd_id] (e, (void *) payload, &reply_msg,
	    &reply_msg_size);
	if (err)
		sprintf(e->buf, "ERR: cmd_id: %d failed with err: %d\n", cmd_id,
		    err);
	else if (reply_msg_size) {
		if (reply_msg_size > MAX_COMMAND_LENGTH) {
			/*
			 * Not enough buffer to send reply.
			 */
			je_free(e->buf);
			e->buf = (char *) je_malloc(reply_msg_size);
			if (e->buf == NULL) {
				err = ENOMEM;
				log_error(fsio_lg,
				    "Failed to allocate memory");
				goto failed;
			}
		}
		snprintf(e->buf, reply_msg_size, "%s", reply_msg);
	} else
		sprintf(e->buf, "Success: cmd_id: %d\n", cmd_id);

failed:
	*e->rbuf = '\0';
	if (reply_msg)
		je_free(reply_msg);

	log_debug(fsio_lg, "completed e: %p, ctx: %p", e, ctx);

	return 0;
}


static void *
thread_main(void *arg)
{
	fsio_control_thread_ctx *ctx = (fsio_control_thread_ctx *) arg;
	int csock, efd, fd, i, rval, sock;
	struct epoll_event ev, epoll_events[EPOLL_ARRAY_SIZE];
	struct sockaddr_un bindaddr;
	struct client *clients, *client;
	uint32_t events;
	ssize_t rc;

	clients = NULL;

	log_trace(fsio_lg, "arg: %p", arg);
	efd = epoll_create(1);
	if (efd < 0) {
		log_error(fsio_lg, "Could not create the epoll fd: %m");
		return (NULL);
	}

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		log_error(fsio_lg, "Could not create new sock: %m");
		return (NULL);
	}

	if (fcntl(sock, F_SETFL, O_NONBLOCK)) {
		log_error(fsio_lg,
		    "Could not make the socket non-blocking: %m");
		close(sock);
		return (NULL);
	}

	char fsio_ipc_path[PATH_MAX];
	snprintf(fsio_ipc_path, sizeof(fsio_ipc_path), "%s/var/run/fsio.ipc",
			nedge_path());
	memset(&bindaddr, 0, sizeof(struct sockaddr_un));
	bindaddr.sun_family = AF_UNIX;
	strcpy(bindaddr.sun_path, fsio_ipc_path);

	unlink(fsio_ipc_path);
	if (bind(sock, (struct sockaddr *) &bindaddr, SUN_LEN(&bindaddr)) < 0) {
		log_error(fsio_lg, "Could not bind socket %d for IPC", sock);
		close(sock);
		return (NULL);
	}

	if (listen(sock, SOMAXCONN)) {
		log_error(fsio_lg,
		    "Could not start listening on server socket %d: %m", sock);
		goto cleanup;
	}

	ev.events = EPOLLIN;
	ev.data.u64 = 0LL;
	ev.data.fd = sock;

	if (epoll_ctl(efd, EPOLL_CTL_ADD, sock, &ev) < 0) {
		log_error(fsio_lg,
		    "Couldn't add server socket %d to epoll set: %m", sock);
		goto cleanup;
	}

	for (;;) {
		while ((rval = epoll_wait(efd, epoll_events, EPOLL_ARRAY_SIZE,
			    100)) < 0) {
			if ((rval < 0) && (errno != EINTR)) {
				goto cleanup;
			}
		}

		for (i = 0; i < rval; i++) {
			events = epoll_events[i].events;
			fd = epoll_events[i].data.fd;

			if (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
				if (fd == sock) {
					goto cleanup;
				}
				CLIENT_LIST_REMOVE(&clients,
				    CLIENT_LIST_FIND(clients, fd));
				continue;
			}

			if (events & EPOLLIN) {
				/*
				 * Server socket.
				 */
				if (fd == sock) {
					while ((csock = accept(sock, NULL,
						    NULL)) < 0) {
						if ((csock < 0)
						    && (errno != EINTR)) {
							log_error(fsio_lg,
							    "Accept on socket "
							    "%d failed: %m",
							    sock);
							goto cleanup;
						}
					}
					/*
					 * ACK event.
					 */
					ev.events = EPOLLIN;
					ev.data.u64 = 0LL;
					ev.data.fd = csock;

					if (epoll_ctl(efd, EPOLL_CTL_ADD,
						csock, &ev) < 0) {
						log_error(fsio_lg,
						    "Couldn't add client socket"
						    " %d to epoll set: %m",
						    csock);
						goto cleanup;
					}

					CLIENT_LIST_PREPEND(&clients, csock);
					continue;
				}

				client = CLIENT_LIST_FIND(clients, fd);
				if (client == NULL) {
					goto cleanup;
				}

				/*
				 * Client socket. 
				 */
				while ((rc =
					recv(fd, client->rbuf + client->rp,
					    MAX_COMMAND_LENGTH - client->rp,
					    0)) < 0) {
					if ((rc < 0) && (errno != EINTR)) {
						CLIENT_LIST_REMOVE(&clients,
						    client);
						continue;
					}
				}

				if (rc == 0) {
					CLIENT_LIST_REMOVE(&clients, client);
					continue;
				}


				if (rc > 0) {
					client->rp += rc;
					if (client->rp > MAX_COMMAND_LENGTH) {
						/*
						 * Error in request.
						 */
						client->rp = 0;
						*client->rbuf = '\0';
					}
					client->buf[client->rp] = '\0';
					if (strchr(client->rbuf, '\n') != NULL)
						parsecmd(client, ctx);

					/*
					 * ACK event.
					 */
					ev.events = EPOLLIN | EPOLLOUT;
					ev.data.u64 = 0LL;
					ev.data.fd = fd;

					if (epoll_ctl(efd, EPOLL_CTL_MOD, fd,
						&ev) < 0) {
						log_error(fsio_lg,
						    "Couldn't modify client "
						    "socket %d in epoll set: %m",
						    fd);
						goto cleanup;
					}
				}

			}
			if ((events & EPOLLOUT) && (fd != sock)) {
				client = CLIENT_LIST_FIND(clients, fd);
				if (client == NULL) {
					goto cleanup;
				}

				while ((rc = send(fd, client->buf,
					    strlen(client->buf), 0)) < 0) {
					if ((rc < 0) && (errno != EINTR)) {
						log_error(fsio_lg,
						    "Send to socket %d failed:"
						    " %m", fd);
						CLIENT_LIST_REMOVE(&clients,
						    client);
						continue;
					}
				}

				if (rc == 0) {
					log_error(fsio_lg,
					    "Closing socket with sock %d", fd);
					CLIENT_LIST_REMOVE(&clients, client);
					continue;
				}

				if (rc > 0) {
					client->wp += rc;

					/*
					 * ACK event.
					 */
					ev.events = EPOLLIN;
					ev.data.u64 = 0LL;
					ev.data.fd = fd;

					if (epoll_ctl(efd, EPOLL_CTL_MOD, fd,
						&ev) < 0) {
						log_error(fsio_lg,
						    "Couldn't modify client "
						    "socket %d in epoll set: %m",
						    fd);
						goto cleanup;
					}
					if (client->status &
					    CLIENT_STATUS_DISCONNECT)
						CLIENT_LIST_REMOVE(&clients,
						    client);
				}
			}
		}
		if (ctx->control_thread_stop)
			goto cleanup;
	}

cleanup:
	CLIENT_LIST_DESTROY(clients);
	log_info(fsio_lg, "Shutdown control socket handler");
	shutdown(sock, SHUT_RDWR);
	close(sock);
	close(efd);

	log_trace(fsio_lg, "completed arg: %p", arg);

	return (NULL);
}

int
fsio_control_thread_start(void **handle)
{
	fsio_control_thread_ctx *ctx;
	int err = 0;

	log_trace(fsio_lg,"handle: %p", handle);

	ctx = je_calloc(1, sizeof(fsio_control_thread_ctx));
	if (!ctx) {
		log_error(fsio_lg, "Faile to allocate memory");
		err = ENOMEM;
		goto out;
	}

	/*
	 * Initialize the command handlers.
	 */
	ctx->cmd_handler[PING] = cmd_hanlder_ping;
	ctx->cmd_handler[SNAP_CREATE] = cmd_hanlder_snap_create;
	ctx->cmd_handler[SNAP_DELETE] = cmd_hanlder_snap_delete;
	ctx->cmd_handler[SNAP_LIST] = cmd_hanlder_snap_list;
	ctx->cmd_handler[SNAP_ROLLBACK] = cmd_hanlder_snap_rollback;
	ctx->cmd_handler[CLONE_FILE] = cmd_hanlder_clone_file;
	ctx->cmd_handler[LOG_PERFORMANCE_STATS] = cmd_hanlder_log_performance_stats;
	ctx->cmd_handler[SET_LOG_LEVEL] = cmd_hanlder_set_log_level;

	err = pthread_create(&ctx->control_thread, NULL, thread_main,
	    (void *) ctx);
	if (err) {
		log_error(fsio_lg, "pthread_create return %d", err);
		goto out;
	}

	*handle = ctx;
out:
	if (err && ctx) {
		je_free(ctx);
		*handle = NULL;
	}

	log_trace(fsio_lg, "completed handle: %p", handle);

	return err;
}

int
fsio_control_thread_stop(void *handle)
{
	int err = 0;
	fsio_control_thread_ctx *ctx = (fsio_control_thread_ctx *) handle;

	log_trace(fsio_lg,"handle: %p", handle);

	ctx->control_thread_stop = 1;

	err = pthread_join(ctx->control_thread, NULL);
	if (err)
		log_error(fsio_lg,"pthread_join return %d", err);

	if (ctx) {
		je_free(ctx);
	}

	log_trace(fsio_lg, "handle: %p", handle);

	return err;
}
