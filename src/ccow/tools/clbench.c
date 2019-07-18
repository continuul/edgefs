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
/*
 * Copyright (c) 2006, 2009 Red Hat, Inc.
 *
 * All rights reserved.
 *
 * Author: Steven Dake (sdake@redhat.com)
 *
 * This software licensed under BSD license, the text of which follows:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * - Neither the name of the MontaVista Software, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <config.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <linux/limits.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <qb/qblog.h>
#include <qb/qbutil.h>

#include <corosync/corotypes.h>
#include <corosync/totem/totem.h>
#include <corosync/cfg.h>
#include <corosync/cpg.h>

#include "clbench.h"
#include "ccowutil.h"

Logger lg;
static struct clbench_params params;
static cpg_handle_t handle;

static pthread_t thread;
static pthread_cond_t event = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t clmutex = PTHREAD_MUTEX_INITIALIZER;

#define PROCS_MAX 8	/* Maximum process "printed" per node */
#define NODES_SLAB 32   /* Max allocation of nodes at a time */

struct nodeinfo {
	uint32_t nodeid;
	uint8_t  procs_nr;
	uint8_t  ifs_nr;
	uint32_t pids[PROCS_MAX];
	char	 ifs[INTERFACE_MAX][INET6_ADDRSTRLEN];
};

struct groupinfo {
	uint32_t nodes_nr;
	struct nodeinfo *grp_nodes;
};

static struct groupinfo clbench_grp;

#ifndef timersub
#define timersub(a, b, result)						\
	do {								\
		(result)->tv_sec = (a)->tv_sec - (b)->tv_sec;		\
		(result)->tv_usec = (a)->tv_usec - (b)->tv_usec;	\
		if ((result)->tv_usec < 0) {				\
			--(result)->tv_sec;				\
			(result)->tv_usec += 1000000;			\
		}							\
	} while (0)
#endif /* timersub */

static int clb_stop_run;
static char *progname;

static void cpg_bm_confchg_fn (
	cpg_handle_t handle_in,
	const struct cpg_name *group_name,
	const struct cpg_address *member_list, size_t member_list_entries,
	const struct cpg_address *left_list, size_t left_list_entries,
	const struct cpg_address *joined_list, size_t joined_list_entries)
{
}

static unsigned int write_count;

static void cpg_bm_deliver_fn (
        cpg_handle_t handle_in,
        const struct cpg_name *group_name,
        uint32_t nodeid,
        uint32_t pid,
        void *msg,
        size_t msg_len)
{
	write_count++;
	if (params.cbp_msg_track && write_count == params.cbp_msg_nr) {
		pthread_mutex_lock(&clmutex);
		pthread_cond_signal(&event);
		pthread_mutex_unlock(&clmutex);
	}
}

static cpg_callbacks_t callbacks = {
	.cpg_deliver_fn 	= cpg_bm_deliver_fn,
	.cpg_confchg_fn		= cpg_bm_confchg_fn
};

#define ONE_MEG 1048576
static char data[ONE_MEG];

const char * clb_strerror(cs_error_t err)
{
	switch (err) {
	case CS_OK:
		return "operation sucessful";

	case CS_ERR_LIBRARY:
		return "unable to connect to corosync service";

	case CS_ERR_VERSION:
		return "incorrect corosync version";

	case CS_ERR_INIT:
		return "unable to initialize with corosync";

	case CS_ERR_NO_MEMORY:
		return strerror(ENOMEM);

	case CS_ERR_NAME_TOO_LONG :
		return strerror(EOVERFLOW);

	case CS_ERR_TIMEOUT:
		return strerror(ETIME);

	case CS_ERR_TRY_AGAIN:
		return strerror(EAGAIN);

	case CS_ERR_INVALID_PARAM:
		return strerror(EINVAL);

	case CS_ERR_BAD_HANDLE:
		return strerror(EBADF);

	case CS_ERR_BUSY :
		return strerror(EBUSY);

	case CS_ERR_ACCESS :
		return strerror(EACCES);

	case CS_ERR_NOT_EXIST :
		return strerror(ENOENT);

	case CS_ERR_EXIST :
		return strerror(EEXIST);

	case CS_ERR_NO_SPACE :
		return strerror(ENOSPC);

	case CS_ERR_INTERRUPT :
		return strerror(EINTR);

	case CS_ERR_NAME_NOT_FOUND :
		return "unkown resource name";

	case CS_ERR_NO_RESOURCES :
		return "resource(s) not available to complete the operation";

	case CS_ERR_NOT_SUPPORTED :
		return strerror(ENOTSUP);

	case CS_ERR_BAD_OPERATION :
		return "operation not supported";

	case CS_ERR_FAILED_OPERATION :
		return strerror(EBADE);

	case CS_ERR_MESSAGE_ERROR :
		return strerror(EBADMSG);

	case CS_ERR_QUEUE_FULL :
		return "unable to dispatch message/event - queue full";

	case CS_ERR_QUEUE_NOT_AVAILABLE :
		return "queueing service not available";

	case CS_ERR_BAD_FLAGS :
		return "invalid flags(options) for the operation";

	case CS_ERR_TOO_BIG :
		return strerror(EMSGSIZE);

	case CS_ERR_NO_SECTIONS :
		return "iterator error - corosync database might be empty";

	case CS_ERR_CONTEXT_NOT_FOUND :
		return "invalid context or handle";

	case CS_ERR_TOO_MANY_GROUPS :
		return "iovec/message count exceeds maximum multicast "
		       "capacity";

	case CS_ERR_SECURITY :
		return "permission denied to join the group";

	default:
		return "unknown error";
	}
}
static inline int
is_mask_set(uint16_t mask, uint16_t flag)
{
	return mask & flag;
}

static void
clbench_print_version()
{
	printf("%s version %d\n", progname, CLBENCH_VER);
}

static cs_error_t
clbench_add_nodeips(corosync_cfg_handle_t cfg_handle,
		    int node_idx, struct cpg_iteration_description_t *node)
{
	int numips;
	int i;
	cs_error_t res;
	corosync_cfg_node_address_t addrs[INTERFACE_MAX];

	res = corosync_cfg_get_node_addrs(cfg_handle, node->nodeid,
					  INTERFACE_MAX, &numips, addrs);
	if (res != CS_OK) {
		fprintf(stderr, "Unable not get IP for node: %d :%s\n",
				node->nodeid, clb_strerror(res));
		goto _out;
	}

	for (i=0; i < numips; i++) {
		char buf[INET6_ADDRSTRLEN];
		char *addrp = addrs[i].address;
		struct sockaddr_storage *ss = (struct sockaddr_storage *)addrp;
		struct sockaddr_in *sin4 = (struct sockaddr_in *)addrp;
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addrp;
		void *saddr;
		
		saddr = ss->ss_family == AF_INET6 ? (void *)&sin6->sin6_addr :
				(void *)&sin4->sin_addr;

		inet_ntop(ss->ss_family, saddr,
			  clbench_grp.grp_nodes[node_idx].ifs[i],
			  INET6_ADDRSTRLEN - 1);
		clbench_grp.grp_nodes[node_idx].ifs_nr++;
	}
_out:
	return res;
}

/*
 * There will be processes on the same node. Hence a node may exists.
 * Find the slot if the node exists.
 * If the node does not exist, set the nodeid in the next slot.
 * Reallocate slot array if necessary.
 */
static int
clbench_find_node_slot(uint32_t nodeid)
{
	int idx;
	int found = 0;
	size_t newsz;
	size_t slab;

	for (idx = 0; idx < (int)clbench_grp.nodes_nr; idx++) {
		if (clbench_grp.grp_nodes[idx].nodeid == nodeid) {
			found = 1;
			break;
		}
	}

	if (!found)
		idx = clbench_grp.nodes_nr++;

	if (idx >= NODES_SLAB && (idx % NODES_SLAB) == 0) {
		slab = (clbench_grp.nodes_nr / NODES_SLAB) + 1;
		newsz = slab * NODES_SLAB * sizeof (struct nodeinfo);
		clbench_grp.grp_nodes  = je_realloc(clbench_grp.grp_nodes,
						    newsz);
		if (clbench_grp.grp_nodes == NULL || errno == ENOMEM)
			idx = -ENOMEM;
	}

	if (idx != -ENOMEM)
		clbench_grp.grp_nodes[idx].nodeid = nodeid;

	return idx;
}

static cs_error_t
clbench_add_nodeinfo(corosync_cfg_handle_t cfg_handle,
		     struct cpg_iteration_description_t *node)
{
	int idx;
	size_t sz;
	uint8_t id;
	cs_error_t res = CS_OK;

	idx = clbench_find_node_slot(node->nodeid);
	if (idx == -ENOMEM) {
		res = CS_ERR_NO_MEMORY;
		goto _out;
	}

	/*
	 * The node interface are populated only once.
	 * Populate the interfaces when the first process is added
	 */
	id = clbench_grp.grp_nodes[idx].procs_nr;
	if (id == 0)
		res = clbench_add_nodeips(cfg_handle, idx, node);

	clbench_grp.grp_nodes[idx].pids[id] = node->pid;
	clbench_grp.grp_nodes[idx].procs_nr++;

_out:
	return res;
}

static void
clbench_print_nodelist(char *outbuf)
{
	int rc;
	uint32_t n;
	uint8_t count;
	uint8_t maxid;
	cs_error_t res;
	cpg_iteration_handle_t iter_handle;
	struct cpg_iteration_description_t grp_desc;
	corosync_cfg_handle_t cfg_handle;

	res = corosync_cfg_initialize(&cfg_handle, NULL);
	if (res != CS_OK) {
		fprintf(stderr, "Unable to access corosync "
				"configuration: %s\n", clb_strerror(res));
		goto _out;
	}

	res = cpg_iteration_initialize(handle, CPG_ITERATION_ONE_GROUP,
				       &params.cbp_grp_name, &iter_handle);
	if (res != CS_OK) {
		fprintf(stderr, "Unable to initialize group interator: "
				"%s\n", clb_strerror(res));
		goto _out;
	}

	while ((res = cpg_iteration_next(iter_handle, &grp_desc)) == CS_OK) {
		res = clbench_add_nodeinfo(cfg_handle, &grp_desc);
		if (res != CS_OK) {
			fprintf(stderr, "Unable to add node information: "
				"%s\n", clb_strerror(res));
			goto _err;
		}
	}

	sprintf(outbuf, "\t\"Membership\": [\n\t\t{\n"
			"\t\t\"Group Name\": \"%s\",\n",
			params.cbp_grp_name.value);
	outbuf += strlen(outbuf);
	sprintf(outbuf, "\t\t\"Members\": [\n");
	for (n = 0; n < clbench_grp.nodes_nr; n++) {
		struct nodeinfo *node = &clbench_grp.grp_nodes[n];
		/* There might be holes in the array */
		if (node->procs_nr == 0)
			continue;

		outbuf += strlen(outbuf);
		sprintf(outbuf, "\t\t\t{\n"
				"\t\t\t\"nodeid\": %d,\n", node->nodeid);
		outbuf += strlen(outbuf);
		sprintf(outbuf, "\t\t\t\"pid(s)\": [");
		maxid = node->procs_nr;
		for (count = 0; count < maxid; count++) {
			outbuf += strlen(outbuf);
			sprintf(outbuf, "%d%s", node->pids[count],
					count == maxid - 1 ? "],\n" : ", ");
		}
		outbuf += strlen(outbuf);
		sprintf(outbuf, "\t\t\t\"IPv6 Address(es)\": [");
		maxid = node->ifs_nr;
		for (count = 0; count < maxid; count++) {
			outbuf += strlen(outbuf);
			sprintf(outbuf, "\"%s\"%s", node->ifs[count],
					count == maxid - 1 ? "]\n" : ", ");
		}
		outbuf += strlen(outbuf);
		sprintf(outbuf, "\t\t\t},\n");
	}
	/* Remove ',' from the last element */
	outbuf[strlen(outbuf) - 2] = '\0';
	outbuf += strlen(outbuf);
	sprintf(outbuf, "\n\t\t]\n\t\t}\n\t]\n");

	res = cpg_iteration_finalize(iter_handle);
	if (res != CS_OK)
		fprintf(stderr, "Unable to finalize group iterator: %s\n",
				clb_strerror(res));

_err:
	res = corosync_cfg_finalize(cfg_handle);

_out:
	if (res != CS_OK)
		fprintf(stderr, "Unable to finalize corosync configuration: "
				"%s\n", clb_strerror(res));

	return;
}

static void
clbench_print_stats(struct timeval *tv, int write_size)
{
	float total_sec;
	float tps;
	float total_data;
	float mbps;
	FILE  *file;
	char *buf;

	total_sec = tv->tv_sec + (tv->tv_usec / 1000000.0);
	tps = ((float)write_count)/total_sec;
	total_data = ((float)write_count) * ((float)write_size)/1000000;
	mbps = total_data/total_sec;

	sprintf(data,	"{\n"
			"\t\"Statistics\": [\n"
			"\t\t{\n"
			"\t\t\"messages\": %d,\n"
			"\t\t\"message size(bytes)\": %d,\n"
			"\t\t\"runtime(sec)\": %7.3f,\n"
			"\t\t\"messages/sec\": %9.3f,\n"
			"\t\t\"MB/sec\": %7.3f\n"
			"\t\t}\n\t],\n", write_count, write_size,
					 total_sec, tps, mbps);

	buf = &data[0] + strlen(data);
	/* Appends node list information to data buffer */
	clbench_print_nodelist(buf);

	printf("%s}\n", data);

	if (is_mask_set(params.cbp_mask, CLBENCH_FLAG_OUT_FILE)) {
		file = fopen(params.cbp_file, "w");
		if (file != NULL) {
			fprintf(file, "%s", data);
			fclose(file);
		} else
			fprintf(stderr, "Cannot open result file %s\n",
				params.cbp_file);
	}
}

static void
cpg_benchmark(cpg_handle_t handle_in, int write_size)
{
	struct timeval tv1, tv2, tv_elapsed;
	struct iovec iov;
	cs_error_t res;
	uint32_t nr = 0;

	clb_stop_run = 0;
	iov.iov_base = data;
	iov.iov_len = write_size;

	write_count = 0;
	/* Check if the timer must be used */
	if (!params.cbp_msg_track)
		alarm(params.cbp_run_time);

	gettimeofday (&tv1, NULL);
	do {
		res = cpg_mcast_joined (handle_in, CPG_TYPE_AGREED, &iov, 1);
		nr++;
		if (params.cbp_msg_track && nr == params.cbp_msg_nr)
			clb_stop_run = 1;
	} while (clb_stop_run == 0 &&
		 (res == CS_OK || res == CS_ERR_TRY_AGAIN));

	if (params.cbp_msg_track) {
		pthread_mutex_lock(&clmutex);
		pthread_cond_wait(&event, &clmutex);
		pthread_mutex_unlock(&clmutex);
	}

	gettimeofday (&tv2, NULL);
	timersub (&tv2, &tv1, &tv_elapsed);

	clbench_print_stats(&tv_elapsed, write_size);
}

static void sigalrm_handler(int num)
{
	clb_stop_run = 1;
}

static void* dispatch_thread(void *arg)
{
	cpg_dispatch(handle, CS_DISPATCH_BLOCKING);
	return NULL;
}

/*
 * usage
 *
 * Display usage and exit.
 */
static void
clbench_usage()
{
	printf("\n"
	       "USAGE:\n"
	       "     %s [-c count] [-g group-name] [-o out-file-name]"
	       " [-s packet-size]  [-t run-time] [-v]\n"
	       "\n"
	       "    -h   Display this help message and exit.\n"
	       "\n"
	       "    -v   Display version number and exit, if no other option\n"
	       "         is used.\n"
	       "\n"
	       "    -c   Specify the number of iterations (message count).\n"
	       "\n"
	       "    -g   Specify the cpg group-name.\n"
	       "         (Defaults to nexenta).\n"
	       "\n"
	       "    -o   Specify the output file.\n"
	       "         (Defaults to stdout).\n"
	       "\n"
	       "    -s   Specify the message size.\n"
	       "         (Defaults to 128. Maximum 1MiB).\n"
	       "\n"
	       "    -t   Specify run time in seconds.\n"
	       "         (Defaults to 10 seconds).\n"
	       "\n"
	       "\n", progname);

	exit(EXIT_SUCCESS);
}

static void
clbench_parse_options(int argc, char *argv[])
{
	int opt;
	size_t len;

	progname = basename(argv[0]);
	while ((opt = getopt(argc, argv, "hvc:g:o:s:t:")) != -1) {
		switch(opt) {

		case 'h':
			clbench_usage();
			break;

		case 'v':
			params.cbp_mask |= CLBENCH_FLAG_VERSION;
			break;

		case 'c':
			params.cbp_mask |= CLBENCH_FLAG_MSG_CNT;
			params.cbp_msg_nr = atoi(optarg);
			if (params.cbp_msg_nr < 1) {
				fprintf(stderr, "Incorrect count value: %d\n",
					params.cbp_msg_nr);
				exit(EXIT_FAILURE);
			}
			break;

		case 'g':
			params.cbp_mask |= CLBENCH_FLAG_GRP_NAME;
			len =
			strlen(optarg) < CPG_MAX_NAME_LENGTH ?
			strlen(optarg) : CPG_MAX_NAME_LENGTH - 1;
			params.cbp_grp_name.length = len;
			strncpy(params.cbp_grp_name.value, optarg, len);
			params.cbp_grp_name.value[len] = '\0';
			break;

		case 'o':
			params.cbp_mask |= CLBENCH_FLAG_OUT_FILE;
			strncpy(params.cbp_file,
				optarg,
				PATH_MAX - 1);
			break;

		case 's':
			params.cbp_mask |= CLBENCH_FLAG_MSG_SZ;
			params.cbp_msg_sz = atoi(optarg);
			if (params.cbp_msg_sz < 1) {
				fprintf(stderr, "Incorrect size value: %d\n",
					params.cbp_msg_sz);
				exit(EXIT_FAILURE);
			}
			break;

		case 't':
			params.cbp_mask |= CLBENCH_FLAG_TIME;
			params.cbp_run_time = atoi(optarg);
			params.cbp_run_time =
			params.cbp_run_time > ONE_MEG ?
			ONE_MEG : params.cbp_run_time;
			break;

		default:
			clbench_usage();
			break;
		}
	}
	if (is_mask_set(params.cbp_mask, CLBENCH_FLAG_MSG_CNT) &&
	    !is_mask_set(params.cbp_mask, CLBENCH_FLAG_TIME))
		params.cbp_msg_track = 1;
}

static void
clbench_set_defaults()
{
	params.cbp_msg_sz = CLBENCH_MSG_SZ;
	params.cbp_run_time = CLBENCH_RUN_TIME;
	params.cbp_grp_name.length = strlen(CLBENCH_GRP_STR);
	assert(params.cbp_grp_name.length < CPG_MAX_NAME_LENGTH);
	strcpy(params.cbp_grp_name.value, CLBENCH_GRP_STR);
}

static int
clbench_initialize()
{
	unsigned int size;
	int rc = 0;
	cs_error_t res;

	if (is_mask_set(params.cbp_mask, CLBENCH_FLAG_VERSION))
		clbench_print_version();

	/* If no other option is used with -v, don't initialize */
	if (is_mask_set(params.cbp_mask, CLBENCH_FLAG_VERSION) &&
	    !is_mask_set(params.cbp_mask, ~CLBENCH_FLAG_VERSION)) {
		rc = -1;
		goto err;
	}

	clbench_grp.grp_nodes = je_calloc(NODES_SLAB, sizeof(struct nodeinfo));
	if (clbench_grp.grp_nodes == NULL) {
		perror("clbench_initialize: Unable to allocate memory");
		rc = -1;
		goto err;
	}

	qb_log_init(progname, LOG_USER, LOG_EMERG);
	qb_log_ctl(QB_LOG_SYSLOG, QB_LOG_CONF_ENABLED, QB_FALSE);
	qb_log_filter_ctl(QB_LOG_STDERR, QB_LOG_FILTER_ADD,
			  QB_LOG_FILTER_FILE, "*", LOG_ERR);
	qb_log_ctl(QB_LOG_STDERR, QB_LOG_CONF_ENABLED, QB_TRUE);

	res = cpg_initialize(&handle, &callbacks);
	if (res != CS_OK) {
		fprintf (stderr, "Unable to initialize cpg group: "
				 "%d :%s\n", res, clb_strerror(res));
		rc = -1;
		goto err;
	}
	/*
	 * If time value set, the run for the set length of time.
	 * If the time value is not set by the user and the count is not set
	 * then set use the default time value. If the count is set (and
	 * time value is not set by the user at the same time) then don't
	 * use the timer.
	 */
	if (is_mask_set(params.cbp_mask, CLBENCH_FLAG_TIME) ||
	    !is_mask_set(params.cbp_mask, CLBENCH_FLAG_MSG_CNT))
		signal (SIGALRM, sigalrm_handler);

	pthread_create(&thread, NULL, dispatch_thread, NULL);
	res = cpg_join(handle, &params.cbp_grp_name);
	if (res != CS_OK) {
		fprintf (stderr, "cpg_join failed with result: %d : %s\n",
				 res, clb_strerror(res));
		rc = -1;
	}

err:
	return rc;
}

static int
clbench_finalize()
{
	int rc = 0;
	cs_error_t res;

	qb_log_fini();
	if (clbench_grp.grp_nodes != NULL)
		je_free(clbench_grp.grp_nodes);

	res = cpg_finalize(handle);
	if (res != CS_OK) {
		fprintf (stderr, "Unable to finalize cpg group: %d : %s\n",
				 res, clb_strerror(res));
		rc = -1;
	}
	return rc;
}

static void
clbench_run()
{
	cpg_benchmark(handle, params.cbp_msg_sz);
}

int main(int argc, char *argv[])
{
	int rc;

	lg = Logger_create("clbench");

	clbench_set_defaults();
	clbench_parse_options(argc, argv);

	rc = clbench_initialize();
	if (rc != 0)
		goto out;

	clbench_run();

	rc = clbench_finalize();
	if (rc != 0)
		goto out;

out:
	return rc;
}
