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
#include <sys/resource.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <net/if.h>
#include <signal.h>
#include <libcgroup.h>
#include <uv.h>
#include <sys/param.h>
#include <openssl/aes.h>

#include "ccowutil.h"
#include "ccowd.h"
#include "auditd.h"
#include "ccow-impl.h"
#include "ccowd-impl.h"
#include "reptrans.h"
#include "reptrans_bg_sched.h"
#include "crypto.h"
#include "clengine.h"
#include "serverid.h"
#include "msgpackalt.h"
#include "flexhash.h"
#include "replicast.h"
#include "trput.h"
#include "gw_cache.h"
#include "gwcache.h"
#include "enc_host.h"

#include <nanomsg/nn.h>
#include <nanomsg/pubsub.h>
#include <nanomsg/pair.h>
#include <nanomsg/reqrep.h>

extern gwcache_stats_t gw_stats;

struct ccowd *ccow_daemon = NULL;

static struct repdev_bg_config rt_cfg;
volatile int ccowd_terminating = 0;

static struct ccowd_ipc_cmd* ccowd_ipc_cmds = NULL;
static uv_rwlock_t ccowd_ipc_lock;
static uint64_t ccowd_ipc_inprog = 0;

int get_isaggregator(struct server_stat *srvr);

#define MAX_AUDITD_MSG 4096

#define DAEMON_CGNAME		"ccowserv"
#define DAEMON_MEM_MIN		(4ULL * 1024ULL * 1024ULL * 1024ULL)
#define CCOWD_MEMLIMIT_EMBEDDED (1ULL * 1024ULL * 1024ULL * 1024ULL)
#define DAEMON_MEM_FREE_PCT	70

#define CCOWD_IF_SPEED_DEFAULT 10000

#define CCOWD_POOL_SIZE 64

#define CCOWD_FH_LOCK_TIMEDWAIT_NS	10000000LL /* 10ms */

int ccow_daemon_init_ipc_listener(struct ccowd *ccow_daemon);

int
ccowd_register_ipc_cmd(const struct ccowd_ipc_cmd* cmd) {
	struct ccowd_ipc_cmd* e = NULL;
	uv_rwlock_wrlock(&ccowd_ipc_lock);
	HASH_FIND(hh,ccowd_ipc_cmds,cmd->key,strlen(cmd->key),e);
	if (e) {
		uv_rwlock_wrunlock(&ccowd_ipc_lock);
		return -EEXIST;
	}
	e = je_malloc(sizeof(*e));
	if (!e) {
		uv_rwlock_wrunlock(&ccowd_ipc_lock);
		return -ENOMEM;
	}
	*e = *cmd;
	e->ctx = NULL;
	HASH_ADD(hh,ccowd_ipc_cmds,key,strlen(e->key),e);
	uv_rwlock_wrunlock(&ccowd_ipc_lock);
	return 0;
}

int
ccowd_unregister_ipc_cmd(const char* key) {
	struct ccowd_ipc_cmd* e = NULL;
	uv_rwlock_wrlock(&ccowd_ipc_lock);
	HASH_FIND(hh,ccowd_ipc_cmds,key,strlen(key),e);
	if (!e) {
		uv_rwlock_wrunlock(&ccowd_ipc_lock);
		return -ENOENT;
	}
	HASH_DELETE(hh,ccowd_ipc_cmds, e);
	uv_rwlock_wrunlock(&ccowd_ipc_lock);
	return 0;
}

static void
ccowd_ipc_cmd_init() {
	ccowd_ipc_cmds = NULL;
	uv_rwlock_init(&ccowd_ipc_lock);
	ccowd_ipc_inprog = 0;
}

static void
ccowd_ipc_cmd_term() {
	uv_rwlock_wrlock(&ccowd_ipc_lock);
	while (!__sync_bool_compare_and_swap(&ccowd_ipc_inprog, 0, 0))
		usleep(100);
	struct ccowd_ipc_cmd* e = NULL, *tmp = NULL;
	HASH_ITER(hh,ccowd_ipc_cmds,e, tmp) {
		HASH_DELETE(hh,ccowd_ipc_cmds, e);
		if (e->ctx)
			je_free(e->ctx);
		je_free(e);
	}
	uv_rwlock_wrunlock(&ccowd_ipc_lock);
	uv_rwlock_destroy(&ccowd_ipc_lock);
}

struct ccowd_ipc_worker_arg {
	struct ccowd_ipc_cmd* e;
	uv_buf_t recv_buf;
	uv_buf_t out_buf;
	int result;
	auditc_link* link;
	void* free_ptr;
};

static void
ccowd_ipc_cmd_exec(void* arg) {
	struct ccowd_ipc_worker_arg* p = arg;
	p->result = p->e->handler(p->e, p->recv_buf, &p->out_buf);
}

static void
ccowd_ipc_cmd_done(void* arg, int status) {
	struct ccowd_ipc_worker_arg* p = arg;
	if (p->result) {
		log_error(lg, "Error while processing an ccowd ipc command %s: %d",
			p->e->key, p->result);
	} else {
		if (p->out_buf.len) {
			assert(p->out_buf.base);
			int rc = nn_send(p->link->sock_in, p->out_buf.base, p->out_buf.len, 0);
			if (p->out_buf.len != (unsigned)rc)
				log_error(lg, "Error while sending ccowd ipc reply: %d", errno);
			je_free(p->out_buf.base);
		}
	}
	if (p->free_ptr)
		je_free(p->free_ptr);
	je_free(arg);
	atomic_dec64(&ccowd_ipc_inprog);
}

static int
ccowd_ipc_process_received_buffer(auditc_link *aclink, char* recv, size_t len) {
	struct ccowd_ipc_cmd* e = NULL, *tmp = NULL;
	int err = 0;
	uv_rwlock_rdlock(&ccowd_ipc_lock);
	int found = 0;
	HASH_ITER(hh,ccowd_ipc_cmds,e, tmp) {
		if (strstr(recv, e->key)) {
			found = 1;
			break;
		}
	}

	if (!found) {
		err = -ENOENT;
		goto _exit;
	}
	assert(e);
	struct ccowd_ipc_worker_arg* arg = je_malloc(sizeof(*arg));
	if (!arg) {
		err = -ENOMEM;
		goto _exit;
	}
	arg->e = e;
	arg->recv_buf.base = recv + strlen(e->key);
	arg->recv_buf.len = len - strlen(e->key);
	arg->out_buf.base = NULL;
	arg->out_buf.len = 0;
	arg->result = 0;
	arg->link = aclink;
	arg->free_ptr = recv;

	atomic_inc64(&ccowd_ipc_inprog);
	if (e->flags & CCOWD_IPC_FLAG_THREADED) {
		assert(ccow_daemon->tp);
		ccowtp_work_queue(ccow_daemon->tp, CCOWD_TP_PRIO_NORMAL,
			ccowd_ipc_cmd_exec, ccowd_ipc_cmd_done, arg);
	} else {
		ccowd_ipc_cmd_exec(arg);
		ccowd_ipc_cmd_done(arg, 0);
	}
_exit:
	uv_rwlock_rdunlock(&ccowd_ipc_lock);
	return err;
}

/* List of local IPC command handlers */
static int
get_server_info_hdl (struct ccowd_ipc_cmd* p, uv_buf_t msg, uv_buf_t* resp) {
	uint128_t serverid = server_get()->id;
	char serveridstr[64];
	int ifcount = ccow_daemon->if_indexes_count;
	auditc_link* aclink = ccow_daemon->aclink;

	if (!aclink) {
		return -EBADF;
	}
	char cmd[] = "GET_SERVERINFO";


	// cmd + _REPLY + IDstr + ifcount(for .) + interfaces + statsite trailers + padding
	int strsz = strlen(cmd) + 6 + 64 + ifcount + (ifcount * 8) + 4 + 1;
	char replystr[strsz];
	uint128_dump(&serverid, serveridstr, 64);
	sprintf(replystr, "%s_REPLY.%s", cmd, serveridstr);
	for (int i = 0; i < ccow_daemon->if_indexes_count; i++) {
		char interface_name[IFNAMSIZ];
		char *ifname = if_indextoname(ccow_daemon->if_indexes[i],
								interface_name);
		strncat(replystr, ".", 1);
		strncat(replystr, ifname, strlen(ifname));
	}
	strncat(replystr, ":0|z", 4);
	log_debug(lg, "<%s>:[%lu]", replystr, strlen(replystr));

	ssize_t len = strlen(replystr);
	if (len != nn_send(aclink->sock_out, replystr, len, 0)) {
		return -errno;
	}

	/*
	 * We know that local Audit server just requested server info.
	 * Possibly that was because of its failure on restart. So, we will
	 * publish all of our ccow.clengine.server.* table now...
	 */
	clengine_notify_auditserv(&g_ceng->me, NULL);
	return 0;
}

static int
fh_cpset_hdl(struct ccowd_ipc_cmd* p, uv_buf_t msg, uv_buf_t* resp) {
	struct nn_msghdr hdr;
	struct nn_iovec iov[1];
	char *genid = msg.base;

	char buf[128];
	snprintf(buf, 128, "FH_CPSET.%s", genid);
	g_ceng->notify(buf, strlen(buf), NULL);

	char* retbuf = je_malloc(16);
	if (!retbuf)
		return -ENOMEM;
	strcpy(retbuf, "OK");
	resp->base = retbuf;
	resp->len = strlen(retbuf)+1;
	return 0;
}

static int
fh_cpupd_hdl(struct ccowd_ipc_cmd* p, uv_buf_t msg, uv_buf_t* resp) {
	struct nn_msghdr hdr;
	struct nn_iovec iov[1];
	char *sig = msg.base;

	char buf[128];
	snprintf(buf, 128, "FH_CPUPD.%s", sig);
	g_ceng->notify(buf, strlen(buf), NULL);

	char* retbuf = je_malloc(16);
	if (!retbuf)
		return -ENOMEM;
	strcpy(retbuf, "OK");
	resp->base = retbuf;
	resp->len = strlen(retbuf)+1;
	return 0;
}

static int
set_mainttime_hdl(struct ccowd_ipc_cmd* p, uv_buf_t msg, uv_buf_t* resp) {
	char value[128] = {0};
	memcpy(value, msg.base, msg.len);
	int minutes = strtol(value, NULL, 10);
	int err = clengine_notify_maintenance(minutes);
	char* reply = je_malloc(32);
	if (err)
		return -ENOMEM;
	sprintf(reply, "SET_MAINT_REPLY%d", err);
	resp->base = reply;
	resp->len = strlen(reply)+1;
	return 0;
}

static struct ccowd_ipc_cmd ipc_cmd_list[] = {
	{.key = "GET_SERVERINFO", .handler = get_server_info_hdl},
	{.key = "FH_CPSET.", .handler = fh_cpset_hdl},
	{.key = "FH_CPUPD.", .handler = fh_cpupd_hdl},
	{.key = "SET_MAINTTIME", .handler = set_mainttime_hdl},
};
/*
 * Read file into allocated rtbuf_t. Returns NULL on error.
 * Syncrhonous operation.
 */
int
ccowd_read_file(const char *filename, rtbuf_t **prb)
{
	struct stat st;
	int err;

	if (stat(filename, &st) != 0) {
		log_debug(lg, "Cannot access configuration file %s: %s",
		    filename, strerror(errno));
		return -errno;
	}

	rtbuf_t *rb = rtbuf_init_alloc_one(st.st_size);
	if (!rb) {
		err = -ENOMEM;
		log_error(lg, "Out of memory while reading %d"
				"%s:", err, filename);
		return -ENOMEM;
	}

	int fd = open(filename, O_RDONLY);
	if (fd == -1) {
		rtbuf_destroy(rb);
		log_error(lg, "Cannot open configuration file %s: %s",
		    filename, strerror(errno));
		return -errno;
	}
	int len = read(fd, rtbuf(rb, 0).base, rtbuf(rb, 0).len);
	if (len == -1) {
		close(fd);
		rtbuf_destroy(rb);
		log_error(lg, "Cannot read configuration file %s: %s",
		    filename, strerror(errno));
		return -errno;
	}
	close(fd);

	*prb = rb;
	return 0;
}

static int
ccowd_parse_config() {
	int err;
	size_t i;
	json_value *opts = ccow_daemon->opts;
	bg_set_default_config(&rt_cfg);

	/* syntax error */
	if (opts->type != json_object) {
		log_error(lg, "Syntax error: not an object: -EINVAL");
		return -EINVAL;
	}
	uint16_t zone = 0;
	uint32_t hb_limit = CCOWD_DEV_HB_LIMIT;
	uint32_t keep_corrupted = 0;
	char *clengine = CCOWD_CLENGINE;
	uint32_t wal_flush_interval = CCOWD_DEV_WAL_FLUSH_INTERVAL;
	json_value *cache = NULL;
	json_value *network = NULL;
	json_value *encryption = NULL;
	json_value *repdev_bg = NULL;
	json_value *transport = NULL;
	for (i = 0; i < opts->u.object.length; i++) {
		if (strncmp(opts->u.object.values[i].name, "network", 7) == 0) {
			network = opts->u.object.values[i].value;
		} else if (strncmp(opts->u.object.values[i].name, "encryption", 10) == 0) {
			encryption = opts->u.object.values[i].value;
		} else if (strncmp(opts->u.object.values[i].name,
						   "cache", 5) == 0) {
			cache = opts->u.object.values[i].value;
		} else if (strncmp(opts->u.object.values[i].name,
						   "clengine", 8) == 0) {
			json_value *v = opts->u.object.values[i].value;
			if (v->type != json_string) {
				log_error(lg, "Syntax error: clengine is not "
						"a string: -EINVAL");
				return -EINVAL;
			}
			clengine = v->u.string.ptr;
		} else if (strncmp(opts->u.object.values[i].name,
						   "zone", 4) == 0) {
			json_value *v = opts->u.object.values[i].value;
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: zone is not "
						"an integer: -EINVAL");
				return -EINVAL;
			}
			zone = v->u.integer;
		} else if (strncmp(opts->u.object.values[i].name,
						   "repdev_bg_config", 16) == 0) {
			repdev_bg = opts->u.object.values[i].value;
		} else if (strncmp(opts->u.object.values[i].name,
						   "transport", 9) == 0) {
			json_value *v = opts->u.object.values[i].value;
			if (v->type != json_array) {
				log_error(lg, "Syntax error: transport is "
						"not an array: -EINVAL");
				return -EINVAL;
			}
			transport = v;
		} else if (strncmp(opts->u.object.values[i].name,
						   "hb_limit", 8) == 0) {
			json_value *v = opts->u.object.values[i].value;
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: hb_limit is "
						"not an integer: -EINVAL");
				log_error(lg, "Using default %d", hb_limit);
			} else {
				hb_limit = v->u.integer;
			}
		} else if (strncmp(opts->u.object.values[i].name,
				   "keep_corrupted", 14) == 0) {
			json_value *v = opts->u.object.values[i].value;
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: keep_corrupted is "
						"not an integer: -EINVAL");
				log_error(lg, "Using default %d", keep_corrupted);
			} else {
				keep_corrupted = v->u.integer;
			}
		}
	}

	/* repdev configuration section */
	if (!repdev_bg) {
		log_warn(lg, "Config warning: replication device configuration "
				"absent, use default");
	} else {
		size_t n_opts = 0;
		err = reptrans_parse_bg_jobs_config(repdev_bg, &rt_cfg, &n_opts);
		if (err) {
			if (err == -EPERM)
				log_error(lg, "Syntax error: repdev bg section is "
						"not an object");
			return err;
		}
	}

	if (cache == NULL) {
		log_info(lg, "Config info: no caching policy selected "
				"using default");
	} else {
		if (cache->type != json_object) {
			log_error(lg, "Syntax error: cache section not "
					"an object: -EINVAL");
			return -EINVAL;
		}
	}

	/* network section not found? */
	if (!network) {
		log_error(lg, "Config error: networking address is not "
				"specified: -EINVAL");
		return -EINVAL;
	}

	/* syntax error */
	if (network->type != json_object) {
		log_error(lg, "Syntax error: network section not an object"
				": -EINVAL");
		return -EINVAL;
	}

	char *server_ip6addr = NULL;
	char *server_ip4addr = NULL;
	char *unix_socket = NULL;
	char *server_interfaces = NULL;
	int server_port = CCOWD_BASE_PORT;
	int mc_ttl = CCOWD_NETWORK_MC_TTL;
	char *mcbase_ip6addr = CCOWD_MCBASE_ADDR;
	char *mcbase_ip4addr = CCOWD_MCBASE4_ADDR;
	int mcbase_port = CCOWD_MCBASE_PORT;

	size_t j;
	for (j = 0; j < network->u.object.length; j++) {
		char *namekey = network->u.object.values[j].name;
		json_value *v = network->u.object.values[j].value;

		/* server_unix_socket */
		if (strncmp(namekey, "server_unix_socket", 18) == 0) {
			if (v->type != json_string) {
				err = -EINVAL;
				log_error(lg, "Syntax error: server_unix_socket is"
						"not a string: %d", err);
				return err;
			}
			unix_socket = v->u.string.ptr;
		/* server_ip6addr */
		} else if (strncmp(namekey, "server_ip6addr", 14) == 0) {
			if (v->type != json_string) {
				err = -EINVAL;
				log_error(lg, "Syntax error: server_ip6addr is"
						"not a string: %d", err);
				return err;
			}
			server_ip6addr = v->u.string.ptr;
		/* server_ip4addr (optional) */
		} else if (strncmp(namekey, "server_ip4addr", 14) == 0) {
			if (v->type != json_string) {
				err = -EINVAL;
				log_error(lg, "Syntax error: server_ip4addr is"
						"not a string: %d", err);
				return err;
			}
			server_ip4addr = v->u.string.ptr;
			/* server_port */
		} else if (strncmp(namekey, "server_port", 11) == 0) {
			if (v->type != json_integer) {
				err = -EINVAL;
				log_error(lg,
						  "Syntax error: server_port is not an "
								  "integer: %d", err);
				return err;
			}
			server_port = v->u.integer;
			/* server_interfaces */
		} else if (strncmp(namekey, "server_interfaces", 14) == 0) {
			if (v->type != json_string) {
				err = -EINVAL;
				log_error(lg, "Syntax error: server_interfaces "
						"is not a string: %d", err);
				return err;
			}
			server_interfaces = v->u.string.ptr;
			/* mcbase_ip6addr */
		} else if (strncmp(namekey, "mcbase_ip6addr", 14) == 0) {
			if (v->type != json_string) {
				err = -EINVAL;
				log_error(lg, "Syntax error: mcbase_ip6addr is"
						"not a string: %d", err);
				return err;
			}
			mcbase_ip6addr = v->u.string.ptr;
			/* mcbase_ip4addr */
		} else if (strncmp(namekey, "mcbase_ip4addr", 14) == 0) {
			if (v->type != json_string) {
				err = -EINVAL;
				log_error(lg, "Syntax error: mcbase_ip4addr is"
						"not a string: %d", err);
				return err;
			}
			mcbase_ip4addr = v->u.string.ptr;
			/* mcbase_port */
		} else if (strncmp(namekey, "mcbase_port", 11) == 0) {
			if (v->type != json_integer) {
				err = -EINVAL;
				log_error(lg,
						  "Syntax error: mcbase_port is not an "
								  "integer: %d", err);
				return err;
			}
			mcbase_port = v->u.integer;
			/* multicast ttl */
		} else if (strncmp(namekey, "mc_ttl", 6) == 0) {
			if (v->type != json_integer) {
				err = -EINVAL;
				log_error(lg,
						  "Syntax error: mc_ttl is not an integer"
								  ": %d", err);
				return err;
			}
			mc_ttl = v->u.integer;
		} else if (strncmp(namekey, "wal_flush_interval", 18) == 0) {
			json_value *v = opts->u.object.values[i].value;
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: wal_flush_interval is not "
						"an integer: -EINVAL");
				return -EINVAL;
			}
			wal_flush_interval = v->u.integer;
		}
	}

	if (!server_ip6addr) {
		server_ip6addr = "::";
		log_warn(lg, "server_ip6addr parameter not specified. Using ::");
	}

	if (server_ip4addr) {
		log_warn(lg, "server_ip4addr parameter specified. Using IPv4 network");
	}

	if (!server_interfaces) {
		err = -EINVAL;
		log_error(lg, "server_interfaces parameter not specified: %d",
				  err);
		return err;
	}

	if (encryption != NULL) {

		/* syntax error */
		if (encryption->type != json_object) {
			log_error(lg, "Syntax error: encryption section not an object"
					": -EINVAL");
			return -EINVAL;
		}

		char *encryption_type = CCOWD_ENCRYPTION_TYPE_HOST_AES_256_GCM;
		char *encryption_host_token = CCOWD_ENCRYPTION_HOST_TOKEN_DEFAULT;
		for (j = 0; j < encryption->u.object.length; j++) {
			char *namekey = encryption->u.object.values[j].name;
			json_value *v = encryption->u.object.values[j].value;

			/* encryption type */
			if (strncmp(namekey, "type", 4) == 0) {
				if (v->type != json_string) {
					err = -EINVAL;
					log_error(lg, "Syntax error: encryption type is"
							"not a string: %d", err);
					return err;
				}
				encryption_type = v->u.string.ptr;
			/* encryption host_token */
			} else if (strncmp(namekey, "host_token", 10) == 0) {
				if (v->type != json_string) {
					err = -EINVAL;
					log_error(lg, "Syntax error: encryption host_token is"
							"not a string: %d", err);
					return err;
				}
				encryption_host_token = v->u.string.ptr;
			}
		}

		/* host based encryption */
		if (strcmp(encryption_type, CCOWD_ENCRYPTION_TYPE_HOST_AES_256_GCM) == 0) {
			/* AES_256_GCM */
			err = ccowd_host_encrypt_init(EVP_aes_256_gcm(),
			    (unsigned char *)&server_get()->id, sizeof(uint128_t),
			    (unsigned char *)encryption_host_token, &ccow_daemon->enc_ctx);
			if (err) {
				log_error(lg, "Host encryption init error: %d", err);
				return err;
			}
			ccow_daemon->enc_ctx->cipher_block_size = AES_BLOCK_SIZE;
			log_notice(lg, "Host Encryption %s now initialized",
			    CCOWD_ENCRYPTION_TYPE_HOST_AES_256_GCM);
		} else if (strcmp(encryption_type, CCOWD_ENCRYPTION_TYPE_HOST_AES_256_CBC) == 0) {
			/* AES_256_CBC */
			err = ccowd_host_encrypt_init(EVP_aes_256_cbc(),
			    (unsigned char *)&server_get()->id, sizeof(uint128_t),
			    (unsigned char *)encryption_host_token, &ccow_daemon->enc_ctx);
			if (err) {
				log_error(lg, "Host encryption init error: %d", err);
				return err;
			}
			ccow_daemon->enc_ctx->cipher_block_size = AES_BLOCK_SIZE;
			log_notice(lg, "Host Encryption %s now initialized",
			    CCOWD_ENCRYPTION_TYPE_HOST_AES_256_CBC);
		} else {
			err = -EINVAL;
			log_error(lg, "Syntax error: encryption host type is"
					" wrong: %d", err);
			return err;
		}

	}

	if (!mcbase_ip6addr) {
		err = -EINVAL;
		log_error(lg, "mcbase_ip6addr parameter not specified: %d",
				  err);
		return err;
	}

	if (server_ip4addr) {
		struct sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(server_port);
		if (inet_pton(AF_INET, server_ip4addr, &addr.sin_addr) != 1) {
			err = -EINVAL;
			log_error(lg, "Incorrect network server_ip4addr/server_port "
					"error: %d", err);
			return err;
		}
		ccow_daemon->server_ip4addr = je_strdup(server_ip4addr);
		ccow_daemon->server_port = server_port;
		ccow_daemon->mcbase_ip4addr = je_strdup(mcbase_ip4addr);
		ccow_daemon->mcbase_port = mcbase_port;

		replicast_ip4_encap(&addr, &ccow_daemon->server_sockaddr);

		static char ifname[IFNAMSIZ];
		err = getifname(server_ip4addr, ifname);
		if (err) {
			log_error(lg, "Cannot get ifname from ip %s "
					"error: %d", server_ip4addr, err);
			return err;
		}
		server_interfaces = ifname;

		char fname[128];
		sprintf(fname, "ip route add %s/8 dev %s 2>/dev/null", mcbase_ip4addr, ifname);
		err = system(fname);
	} else {
		/* check for local server_ip6addr/server_port correctness */
		struct sockaddr_in6 addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin6_family = AF_INET6;
		addr.sin6_port = htons(server_port);
		char *zone_idx = strchr(server_ip6addr, '%');
		if (zone_idx) {
			*zone_idx = '\0';
			ccow_daemon->server_if_index = if_nametoindex(zone_idx + 1);
			if (ccow_daemon->server_if_index == 0) {
				err = -errno;
				log_error(lg, "Incorrect network server_ip6addr interface "
						"index error: %d", err);
				return err;
			}
		}
		if (inet_pton(AF_INET6, server_ip6addr, &addr.sin6_addr) != 1) {
			err = -EINVAL;
			log_error(lg, "Incorrect network server_ip6addr/server_port "
					"error: %d", err);
			return err;
		}
		if (zone_idx)
			*zone_idx = '%';
		ccow_daemon->server_ip6addr = je_strdup(server_ip6addr);
		ccow_daemon->server_port = server_port;
		ccow_daemon->server_sockaddr = addr;
		ccow_daemon->mcbase_ip6addr = je_strdup(mcbase_ip6addr);
		ccow_daemon->mcbase_port = mcbase_port;
	}

	char *sp;
	char *ifname = strtok_r(server_interfaces, ";", &sp);
	int numup = 0;
	i = 0;

	/* walk through all the interface names and fill in if_indexes[] */
	while (ifname != NULL) {

		/* phase one - convert and check availability */
		ccow_daemon->if_indexes[i] = if_nametoindex(ifname);
		if (ccow_daemon->if_indexes[i] == 0) {
			err = -errno;
			log_error(lg, "Non existing network server_interfaces "
					"value at %lu error: %d", i, err);
			return err;
		}
		strcpy(ccow_daemon->if_names[i], ifname);

		/* phase two - verify eligibility */
		uint8_t duplex, link_status;
		int mtu;
		err = ethtool_info(ifname, &ccow_daemon->if_speeds[i], &duplex,
						   &link_status, &mtu);
		if (err) {
			err = -errno;
			log_error(lg, "Not eligibile network server_interfaces "
					"value at %lu error: %d", i, err);
			return err;
		}
		if (duplex < 1) {
			err = -EBADF;
			log_error(lg, "Interface %s in server_interfaces "
					"value at %lu error: Full-Duplex mode is "
					"required", ifname, i);
			return err;
		}
#if 0
		if (mtu < 9000) {
			err = -EBADF;
			log_error(lg, "Interface %s in server_interfaces "
					"value at %lu error: minimally MTU 9000 is "
					"required", ifname, i);
			return err;
		}

		if (ccow_daemon->if_speeds[i] < 9000) {
			log_warn(lg, "Interface %s in server_interfaces "
					"has speed %u less then 9000", ifname,
					 ccow_daemon->if_speeds[i]);
		}
#endif
		if (link_status == 0) {
			log_warn(lg, "Interface %s in server_interfaces "
					"value at %lu error: Link is down", ifname, i);
			/* proceed as long as there are sufficient number
             * of interfaces */
		} else {
			log_info(lg, "Using interface %s, %u Mbps",
					 ifname, ccow_daemon->if_speeds[i]);
			numup++;
		}

		ifname = strtok_r(NULL, ";", &sp);
		i++;
	}

	if (numup == 0) {
		err = -ENODEV;
		log_error(lg,
				  "All configured networking interfaces are down: %d",
				  err);
		return err;
	}

	if (i == 0) {
		err = -ENODEV;
		log_error(lg, "No configured networking interfaces found: %d",
				  err);
		return err;
	}
	ccow_daemon->if_indexes_count = i;

	if (unix_socket) {
		ccow_daemon->unix_socket_addr = je_strdup(unix_socket);
	}

	ccow_daemon->zone = zone;
	ccow_daemon->clengine = clengine;
	ccow_daemon->mc_ttl = mc_ttl;
	ccow_daemon->hb_limit = hb_limit;
	ccow_daemon->wal_flush_interval = wal_flush_interval;

	/* Fill in transport names */
	if (!transport || !transport->u.array.length) {
		log_error(lg, "Config error: no transports specified: "
				"-EINVAL");
		return -EINVAL;
	}
	if (transport->u.array.length > CCOW_MAX_TRANSPORTS) {
		log_error(lg, "Config error: too many transports "
				"specified: -EINVAL");
		return -EINVAL;
	}
	ccow_daemon->transport_count = 0;
	for (j = 0; j < transport->u.array.length; ++j) {
		json_value *v = transport->u.array.values[j];
		if (v->type != json_string) {
			log_error(lg, "Config error: transport name is "
					"not a string: -EINVAL");
			return -EINVAL;
		}
		ccow_daemon->transport_name[j] = je_strdup(v->u.string.ptr);
	}
	ccow_daemon->transport_count = transport->u.array.length;
	ccow_daemon->keep_corrupted = keep_corrupted;

	return 0;
}

static int
ccow_parse_config(json_value *opts)
{
	int err;
	size_t i;

	/* syntax error */
	if (opts->type != json_object) {
		log_error(lg, "Syntax error: not an object: -EINVAL");
		return -EINVAL;
	}

	json_value *tenant = NULL;

	uint64_t trlog_interval_us = TRLOG_INTERVAL_DEFAULT_US;
	uint64_t trlog_quarantine = TRLOG_PROCESSING_QUARANTINE;

	for (i = 0; i < opts->u.object.length; i++) {
		if (strncmp(opts->u.object.values[i].name, "tenant", 6) == 0) {
			tenant = opts->u.object.values[i].value;
		} else if (strncmp(opts->u.object.values[i].name, "trlog", 5) == 0) {
			json_value *trlog = opts->u.object.values[i].value;
			for (size_t j = 0; j < trlog->u.object.length; j++) {
				char *k = trlog->u.object.values[j].name;
				json_value *v = trlog->u.object.values[j].value;
				if (strncmp(k, "interval", 8) == 0) {
					if (v->type != json_integer || v->u.integer < 1) {
						log_error(lg, "Syntax error: trlog "
						    "interval is not an integer or incorrect value");
						return -EINVAL;
					}
					trlog_interval_us = v->u.integer * 1000000UL;
				} else if (strncmp(k, "quarantine", 10) == 0) {
					if (v->type != json_integer || v->u.integer < 1) {
						log_error(lg, "Syntax error: trlog "
						    "quarantine is not an integer or incorrect value");
						return -EINVAL;
					}
					trlog_quarantine = v->u.integer;
				}
			}
		}
	}
	ccow_daemon->trlog_interval_us = trlog_interval_us;
	ccow_daemon->trlog_quarantine = trlog_quarantine;

	/* syntax error */
	if (tenant->type != json_object) {
		log_error(lg, "Syntax error: user section not an object"
		    ": -EINVAL");
		return -EINVAL;
	}

	size_t j;
	int track_statistics = 0;
	int unicastio = REPLICAST_UNICAST_UDP;
	int sync_put_named = RT_SYSVAL_SYNC_PUT_NAMED;
	for (j = 0; j < tenant->u.object.length; j++) {
		char *namekey = tenant->u.object.values[j].name;
		json_value *v = tenant->u.object.values[j].value;

		if (strcmp(namekey, "unicast_io") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: unicast_io "
					"is not an integer: -EINVAL");
				return -EINVAL;
			}
			unicastio = v->u.integer;
			if (unicastio != REPLICAST_UNICAST_UDP &&
			    unicastio != REPLICAST_UNICAST_UDP_MCPROXY &&
			    unicastio != REPLICAST_UNICAST_TCP && unicastio != 0) {
				log_error(lg, "unicast_io: invalid arugment"
					      ": -EINVAL");
				return -EINVAL;
			}
		} else if (strcmp(namekey, "track_statistics") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: track_statistics "
					"is not an integer: -EINVAL");
				return -EINVAL;
			}
			track_statistics = v->u.integer;
		} else if (strcmp(namekey, "sync_put_named") == 0) {
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: "
				    "sync_put_named is not an integer"
				    ": -EINVAL");
				return -EINVAL;
			}
			sync_put_named = v->u.integer;
			if (sync_put_named < 0 ||
			    sync_put_named > REPLICAST_SYNC_PUT_MAX) {
				log_error(lg,
				    "sync_put_named: invalid argument"
				    ": -EINVAL");
				return -EINVAL;
			}
		}
	}

	ccow_daemon->track_statistics = track_statistics;
	ccow_daemon->unicastio = unicastio;
	ccow_daemon->sync_put_named = sync_put_named;

	return 0;
}


int
ccowd_init_interfaces(struct cl_node *node, struct replicast *robj)
{
	int err;

	node->serverid = server_get()->id;
	node->port = ccow_daemon->server_port;
	if (ccow_daemon->if_indexes_count <= 0)
		return -ENOENT;

	memcpy(&node->addr, &robj->msg_origin_udpaddr.sin6_addr, 16);

	// FIXME: temporary.... when "::" is sent to the peer as a
	// reply address, no replies are ever seen.
	memcpy(&robj->recv_addr, &robj->msg_origin_udpaddr,
	    sizeof (struct sockaddr_in6));
	robj->udp_recv_port = node->port;

	ccow_daemon->msg_origin_sockaddr.sin6_addr = robj->msg_origin_udpaddr.sin6_addr;

	// FIXME: set up the zone later
	node->zone = ccow_daemon->zone;

	return 0;
}

static void
ccowd_shutdown()
{
	int rc;

	if (ccow_daemon->opts)
		json_value_free(ccow_daemon->opts);

	clengine_stop();

	/* let device threads finish FSMs */
	usleep(1000000);

	/* gracefully shutdown transports on exit */
	reptrans_destroy();

	/* gracefully shutdown clengine on exit */
	rc = clengine_destroy();
	if (rc != 0)
		log_error(lg, "clengine did not shutdown cleanly %d", rc);

	for (int i = 0; i < ccow_daemon->transport_count; ++i) {
		je_free(ccow_daemon->transport_name[i]);
		ccow_daemon->transport_name[i] = NULL;
	}
}

static void
ccowd_tran_timer(uv_timer_t *req, int status)
{
	/* workaround for threadpool startup bug */
	static int initial_kick = 0;
	/*
	 * We don't want another thread running this function.
	 */
	if (initial_kick++ < 2 || ccow_daemon->tran_running)
		return;
	log_info(lg, "TRLOG: processing transactions started");
	ccow_daemon->tran_running = 1;
	ccowd_tran_start();
}

static void
ccowd_gw_cache_timer(uv_timer_t *req, int status)
{
	/*
	 *
	 */
	log_debug(lg, "GW CACHE: garbage collection astarted");
	ccowd_gw_cache_start();
}

void
ccowd_wait_for_fhrebuild_term(volatile int* term)
{
	volatile int fh_ready;

	uv_mutex_lock(&ccow_daemon->fh_mutex);

	ccowd_fhready_lock(FH_LOCK_READ);
	fh_ready = flexhash_is_pristine(SERVER_FLEXHASH);
	ccowd_fhready_unlock(FH_LOCK_READ);

	while (!fh_ready && !(*term)) {

		uv_cond_timedwait(&ccow_daemon->fh_condv,
		    &ccow_daemon->fh_mutex, CCOWD_FH_LOCK_TIMEDWAIT_NS);

		ccowd_fhready_lock(FH_LOCK_READ);
		fh_ready = flexhash_is_pristine(SERVER_FLEXHASH);
		ccowd_fhready_unlock(FH_LOCK_READ);
	}
	uv_mutex_unlock(&ccow_daemon->fh_mutex);
}

void
ccowd_set_fhrebuild_is_done()
{
	ccowd_fhready_lock(FH_LOCK_READ);
	uv_cond_broadcast(&ccow_daemon->fh_condv);
	ccowd_fhready_unlock(FH_LOCK_READ);
}

static void
ccowd_healthy_timer(uv_timer_t *req, int status) {
	reptrans_fddelta_update(uv_timer_get_repeat(req));
}

static void
ccowd_fhstats_timer(uv_timer_t *req, int status)
{
	/*
	 * Doing the corosync send now for this ccow_daemon
	 * iterate through each vdev and calculate the serverid's capacity
	 */
	char vdevstr[UINT128_BYTES*2+1];
	ccowd_fhready_lock(FH_LOCK_READ);
	struct vdevstore *vd = SERVER_FLEXHASH->vdevstore;
	if (!vd) {
		ccowd_fhready_unlock(FH_LOCK_READ);
		return;
	}
	uint64_t capacity = 0, physical_used = 0;
	char *msg_str = je_calloc(1, vd->lvdevcount*64+128);
	if (!msg_str) {
		ccowd_fhready_unlock(FH_LOCK_READ);
		log_error(lg, "Memory allocation error");
		return;
	}
	char *msg_str_body = msg_str + 30;
	int n_vdevs = 0;
	for (int i = 0; i < vd->lvdevcount; i++) {
		struct lvdev *lv = &vd->lvdevlist[i];
		if (lv && lv->server) {
			if (uint128_cmp(&server_get()->id, &lv->server->id) == 0) {
				physical_used += (lv->size - lv->avail);
				capacity += lv->size;
				uint128_dump(&lv->vdevid, vdevstr, UINT128_BYTES*2+1);
				sprintf(msg_str_body + strlen(msg_str_body), ":%s:%lu",
					vdevstr, (lv->size - lv->avail));
				n_vdevs++;
			}
		}
	}
	ccowd_fhready_unlock(FH_LOCK_READ);
	sprintf(msg_str, "%lu:%d", physical_used, n_vdevs);
	memmove(msg_str + strlen(msg_str), msg_str_body, strlen(msg_str_body) + 1);
	log_debug(lg, "HARD DISK CAPACITY USED: %lu / %lu",
	    physical_used, capacity);

	/*
	 * Now everything is accumulated, we can send it to corosync..
	 */
	clengine_update_others(&server_get()->id, CLENGINE_STAT_PHYSICAL_USED,
		msg_str);
	je_free(msg_str);

	/* Update fh row median value for available storage space */
	if (ccow_daemon->leader) {
		char *msg;
		SERVER_FLEXHASH_SAFE_CALL(
			msg = flexhash_get_row_median_json(ccow_daemon->flexhash),
			FH_LOCK_READ);
		if (msg) {
			clengine_fh_row_update(msg);
			je_free(msg);
		}
	}
}

static void
ccowd_host_stats(uv_timer_t *req, int status)
{
	QUEUE *q, *d;
	struct reptrans *rt;
	struct repdev *dev;
	static int n_stats_called = 0;
	struct server_stat *server = server_get_invalidate();
	if (server->zone != ccow_daemon->zone)
		server->zone = ccow_daemon->zone;
	n_stats_called++;
	n_stats_called %= 10;
	if (n_stats_called == 0) {
		get_isaggregator(server);
	}

	auditc_objid(gauge,  "host.isaggregator", &uint128_null, server->isaggregator);
	auditc_objid(gauge,  "host.zone", &uint128_null, server->zone);
	auditc_low_objid(gauge,  "host.cpuspeed", &uint128_null, server->cpuspeed);
	auditc_low_objid(gauge,  "host.loadavg1", &uint128_null, server->loadavg1 * 1.0);
	auditc_low_objid(gauge,  "host.loadavg5", &uint128_null, server->loadavg5 * 1.0);
	auditc_low_objid(gauge,  "host.loadavg15", &uint128_null, server->loadavg15 * 1.0);
	auditc_low_objid(gauge,  "host.memtotal", &uint128_null, server->memtotal * 1.0);
	auditc_low_objid(gauge,  "host.memused", &uint128_null, server->memused * 1.0);
	auditc_low_objid(gauge,  "host.swapused", &uint128_null, server->swapused * 1.0);
	auditc_low_objid(gauge,  "host.numcpu", &uint128_null, server->numcpu * 1.0);
	auditc_objid_str(gauge,  "host.hostname", &uint128_null, server->name, 0.0);
	auditc_objid_str(gauge,  "host.containerid", &uint128_null, server->containerid, 0.0);
	auditc_low_objid_str(gauge,  "host.installtype", &uint128_null, server->installtype, 0.0);
	auditc_low_objid(gauge, "host.local_timestamp_us", &uint128_null, get_timestamp_us());

	uint64_t genid = SERVER_FLEXHASH->genid;
	auditc_low_objid(gauge,  "host.genid", &uint128_null, genid * 1.0);
	uint64_t cpgenid = SERVER_FLEXHASH->cpgenid;
	auditc_low_objid(gauge,  "host.cpgenid", &uint128_null, cpgenid * 1.0);

	QUEUE_FOREACH(q, &all_rts) {
		rt = QUEUE_DATA(q, struct reptrans, item);
		uv_rwlock_rdlock(&rt->devlock);
		QUEUE_FOREACH(d, &rt->devices) {
			dev = QUEUE_DATA(d, struct repdev, item);

			if (dev->gw_cache) {
				uv_rwlock_rdunlock(&rt->devlock);
				char str[UINT128_BYTES * 2 + 1];
				uint128_dump(&dev->vdevid, str, UINT128_BYTES * 2 + 1);

				auditc_low_objid_str(gauge, "host.gwcache_vdevid", &uint128_null, str, 0.0);
				auditc_low_objid_str(gauge, "host.gwcache_dev_name", &uint128_null, dev->name, 0.0);
				auditc_low_objid(gauge, "host.gwcache_lru_hits", &uint128_null, gw_stats.lru_hits);
				auditc_low_objid(gauge, "host.gwcache_lru_misses", &uint128_null, gw_stats.lru_misses);
				auditc_low_objid(gauge, "host.gwcache_lru_evicts", &uint128_null, gw_stats.lru_evicts);
				auditc_low_objid(gauge, "host.gwcache_populates", &uint128_null, gw_stats.populates);
				auditc_low_objid(gauge, "host.gwcache_evicts", &uint128_null, gw_stats.evicts);
				auditc_low_objid(gauge, "host.gwcache_hits", &uint128_null, gw_stats.hits);
				auditc_low_objid(gauge, "host.gwcache_misses", &uint128_null, gw_stats.misses);

				auditc_low_objid(gauge, "host.gwcache_capacity", &uint128_null, dev->stats.capacity);
				auditc_low_objid(gauge, "host.gwcache_used", &uint128_null, dev->stats.used);
				uv_rwlock_rdlock(&rt->devlock);
			}
		}
		if (rt->ndevs == 0) {
			/* This is a GW, send an ALIVE message */
			char dst[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &ccow_daemon->msg_origin_sockaddr.sin6_addr,
			    dst, INET6_ADDRSTRLEN);
			auditc_servervdev(gauge, "clengine.server", &server->id,
				&uint128_null, dst, 1.0);
		}
		uv_rwlock_rdunlock(&rt->devlock);
	}

	uint32_t total_netspeed = 0;
	for (int i = 0; i < ccow_daemon->if_indexes_count; i++) {
		char *ifname = ccow_daemon->if_names[i];
		uint32_t speed;
		uint8_t duplex, link_status;
		int mtu;

		int err = ethtool_info(ifname, &speed, &duplex, &link_status, &mtu);
		if (err) {
			log_warn(lg, "Interface %s not answering to ETHTOOL requests",
			    ifname);
			continue;
		}
		if (speed != ccow_daemon->if_speeds[i]) {
			log_notice(lg, "Interface %s speed changed from %u to %u Mbps",
			    ifname, ccow_daemon->if_speeds[i], speed);
			replicast_vbuf_link_update(&ccow_daemon->robj[i]->rvbuf, speed);
			ccow_daemon->if_speeds[i] = speed;
		}
		total_netspeed += speed;
	}
	auditc_low_objid(gauge,  "host.netspeed", &uint128_null, total_netspeed * 1.0);
}

static void
ccowd_flush_done(void* arg, int status)
{
	ccow_daemon->flush_progress = 0;
}

static void
ccowd_flush_exec(void* arg)
{
	if (ccowd_terminating)
		return;
	reptrans_flush(RD_FLUSH_TIMEOUT);
}

/*
 * Function executed periodically to flush Write Ahead Log (WAL) to prevent
 * data loss when there is no IO for a period of time. The WAL is flushed
 * by time (5seconds by default) # of objects and size.
 */
static void
ccow_wal_flush_timer(uv_timer_t *req, int status)
{
	if (ccowd_terminating)
		return;
	if (ccow_daemon->flush_progress)
		return;
	if (server_get()->numdisks == 0)
		return;
	ccow_daemon->flush_progress = 1;
	ccowtp_work_queue(ccow_daemon->tp, CCOWD_TP_PRIO_NORMAL, ccowd_flush_exec,
		ccowd_flush_done, ccow_daemon);
}

static void
ccowd__on_exit(uv_async_t *handle, int status)
{
	/* cleanup will be done in startup routine itself */
	if (ccow_daemon->startup_err)
		return;

	ccowd_shutdown();
	uv_close((uv_handle_t *)&ccow_daemon->clengine_rebuild_message, NULL);
	uv_close((uv_handle_t *)&ccow_daemon->clengine_rebuild_message_no_cp, NULL);
	uv_close((uv_handle_t *)&ccow_daemon->auditc_message, NULL);
	uv_close((uv_handle_t *)handle, NULL);
	uv_close((uv_handle_t *)&ccow_daemon->ipc_req, NULL);
	uv_timer_stop(&ccow_daemon->tran_timer);
	uv_close((uv_handle_t *)&ccow_daemon->tran_timer, NULL);
	uv_timer_stop(&ccow_daemon->healthy_timer);
	uv_close((uv_handle_t *)&ccow_daemon->healthy_timer, NULL);
	uv_timer_stop(&ccow_daemon->gw_cache_timer);
	uv_close((uv_handle_t *)&ccow_daemon->gw_cache_timer, NULL);
	uv_timer_stop(&ccow_daemon->host_stats_timer);
	uv_close((uv_handle_t *)&ccow_daemon->host_stats_timer, NULL);
	uv_timer_stop(&ccow_daemon->fhstats_timer);
	uv_close((uv_handle_t *)&ccow_daemon->fhstats_timer, NULL);
	uv_timer_stop(&ccow_daemon->devhb_timer);
	uv_close((uv_handle_t *)&ccow_daemon->devhb_timer, NULL);
	uv_timer_stop(&ccow_daemon->wal_flush_timer);
	uv_close((uv_handle_t *)&ccow_daemon->wal_flush_timer, NULL);
	replicast_destroy(ccow_daemon->robj[0]);
}

static void
ccowd_devhb_done(void* arg, int status)
{
	ccow_daemon->hb_progress = 0;
}

static void
ccowd_devhb_exec(void* arg)
{
	QUEUE *q, *d;
	struct reptrans *rt;

	if (ccowd_terminating)
		return;

	/*
	 * Each device updates the heartbeat by setting hb to 0.
	 * ccow_daemon increments hb on each visit. A device is failed if
	 * ccow_daemon->hb_limit hbs are missed. Upon failure, ccow_daemon
	 * assumes that dev thread is stuck somewhere. It marks the device
	 * faulted and sends FH_VDEV_DEAD message from clengine.
	 */
	QUEUE_FOREACH(q, &all_rts) {
		rt = QUEUE_DATA(q, struct reptrans, item);
		uv_rwlock_rdlock(&rt->devlock);
		QUEUE_FOREACH(d, &rt->devices) {
			struct repdev *dev;
			dev = QUEUE_DATA(d, struct repdev, item);
			uv_rwlock_rdunlock(&rt->devlock);

			repdev_status_t status = reptrans_dev_get_status(dev);
			if (dev->terminating || status == REPDEV_STATUS_UNAVAILABLE ||
			    dev->gw_cache) {
				uv_rwlock_rdlock(&rt->devlock);
				continue;
			}
			if (dev->hb < (unsigned long)ccow_daemon->hb_limit) {
				log_debug(lg, "Dev(%s): hb count %lu",
				    dev->name, dev->hb);
				atomic_inc64(&dev->hb);
			} else {
				struct ccowtp_stat tpstat = {0};
				ccowtp_stat(dev->tp, &tpstat);

				log_error(lg, "Dev(%s): Failing the device as "
				    "heartbeats not received. (hb=%lu hb_limit=%u), tp[HIGHT] pending %lu",
				    dev->name, dev->hb, ccow_daemon->hb_limit,
				    tpstat.pending[REPTRANS_TP_PRIO_HI]);
				reptrans_dev_set_status(dev, REPDEV_STATUS_UNAVAILABLE);
			}

			uv_rwlock_rdlock(&rt->devlock);
		}
		uv_rwlock_rdunlock(&rt->devlock);
	}
}

static void
ccowd_devhb_timer(uv_timer_t *req, int status)
{
	if (ccowd_terminating)
		return;
	if (ccow_daemon->hb_progress)
		return;
	ccow_daemon->hb_progress = 1;
	ccowtp_work_queue(ccow_daemon->tp, CCOWD_TP_PRIO_HI, ccowd_devhb_exec, ccowd_devhb_done,
		ccow_daemon);
}

static void
ccowd__on_clengine_rebuild_message(uv_async_t *handle, int status)
{
	log_info(lg, "rebuild checkpoint.");
	if (!ccowd_terminating)
		clengine_reinit(0);
}

static void
ccowd__on_clengine_rebuild_message_no_cp(uv_async_t *handle, int status)
{
	log_info(lg, "rebuild no checkpoint.");
	if (!ccowd_terminating)
		clengine_reinit(1);
}

void
ccowd_auditc_flush_exec(void *arg)
{
	if (ccowd_terminating)
		return;
	auditc_flush(ccow_daemon->aclink);
}

static void
ccowd__on_auditc_message(uv_async_t *handle, int status)
{
	if (!ccowd_terminating)
		ccowtp_work_queue(ccow_daemon->tp, CCOWD_TP_PRIO_NORMAL, ccowd_auditc_flush_exec,
			NULL, NULL);
}

static void
ccowd_startup(int *err_out)
{
	char msg_origin_addr[INET6_ADDRSTRLEN + IFNAMSIZ];
	char listen_addr[INET6_ADDRSTRLEN + IFNAMSIZ];
	int err = 0;

	/*
	 * CCOW daemon configuration file is ccowd.json
	 */
	char conffile[PATH_MAX];
	snprintf(conffile, sizeof(conffile), CCOWD_CONF_DIR "/" CCOWD_CONF_FILE,
		nedge_path());

	/*
	 * Read configuration file
	 */
	rtbuf_t *rb = NULL;
	err = ccowd_read_file(conffile, &rb);
	if (err != 0)
		goto _exit;

	ccow_daemon->loop = uv_loop_new();
	ccow_daemon->loop_thrid = uv_thread_self();

	/*
	 * Parse configuration file
	 */
	ccow_daemon->opts = json_parse(rtbuf(rb, 0).base, rtbuf(rb, 0).len);
	if (!ccow_daemon->opts) {
		log_error(lg, "Cannot parse configuration file %s -ENOENT",
				  conffile);
		rtbuf_destroy(rb);
		err = -ENOENT;
		goto _exit;
	}
	rtbuf_destroy(rb);

	if (ccowd_parse_config() != 0) {
		json_value_free(ccow_daemon->opts);
		err = -ENOENT;
		goto _exit;
	}

	/*
	 * CCOW library configuration file is ccow.json
	 */
	snprintf(conffile, sizeof(conffile), CCOWD_CONF_DIR "/" CCOW_CONF_FILE,
		nedge_path());

	/*
	 * Read configuration file
	 */
	rb = NULL;
	err = ccowd_read_file(conffile, &rb);
	if (err != 0)
		goto _exit;

	/*
	 * Parse configuration file
	 */
	json_value *ccow_opts = json_parse(rtbuf(rb, 0).base, rtbuf(rb, 0).len);
	if (!ccow_opts) {
		log_error(lg, "Cannot parse configuration file %s -ENOENT",
				  conffile);
		rtbuf_destroy(rb);
		err = -ENOENT;
		goto _exit;
	}
	rtbuf_destroy(rb);

	if (ccow_parse_config(ccow_opts) != 0) {
		json_value_free(ccow_opts);
		err = -ENOENT;
		goto _exit;
	}
	json_value_free(ccow_opts);

	struct ccowtp_job_config ccowd_tp_cfg[] = {
		{
			.sched = SCHED_OTHER,
			.prio = 1,
			.weight = 70,
			.min = 25,
			.resiliency = 1000
		},
		{
			.sched = SCHED_OTHER,
			.prio = 0,
			.weight = 30,
			.min = 20,
			.resiliency = 1000
		},
	};

	ccow_daemon->tp = ccowtp_create(ccow_daemon->loop, ccowd_tp_cfg, 2, CCOWD_POOL_SIZE);
	assert(ccow_daemon->tp);

	uv_mutex_init(&ccow_daemon->fh_mutex);
	uv_rwlock_init(&ccow_daemon->fh_lock);
	uv_cond_init(&ccow_daemon->fh_condv);
	/* now we initialize our flexhash table */
	ccow_daemon->flexhash = flexhash_table_create(FLEXHASH_BOOTUP_VDEVS,
	    FH_SERVER_SIDE);
	if (!ccow_daemon->flexhash) {
		log_error(lg, "Unable to create a flexhash table");
		json_value_free(ccow_daemon->opts);
		err = -ENOMEM;
		goto _exit;
	}
	ccow_daemon->flexhash_version = 1; /* the bootup is always 1 */
	/* we mark this one stale immediately so we don't reply from this one */
	flexhash_mark_stale(ccow_daemon->flexhash);

	if (ccow_daemon->mcbase_ip4addr) {
		struct sockaddr_in addr4;
		inet_pton(AF_INET, ccow_daemon->mcbase_ip4addr, &addr4.sin_addr);
		replicast_ip4_encap(&addr4, &ccow_daemon->mcbase_sockaddr);
	} else {
		inet_pton(AF_INET6, ccow_daemon->mcbase_ip6addr,
		    &ccow_daemon->mcbase_sockaddr.sin6_addr);
	}
	flexhash_assign_mcbase(ccow_daemon->flexhash,
	    (uint128_t *) &ccow_daemon->mcbase_sockaddr.sin6_addr,
	    ccow_daemon->mcbase_port);

	if (ccow_daemon->server_ip4addr) {
		strcpy(msg_origin_addr, ccow_daemon->server_ip4addr);
		strcpy(listen_addr, ccow_daemon->server_ip4addr);

		ccow_daemon->msg_origin_addr = je_strdup(msg_origin_addr);
		if (!ccow_daemon->msg_origin_addr) {
			err = -ENOMEM;
			goto _exit;
		}
	} else {
		/* If listening on anycast address, let other side know an IP */
		if (strncmp(ccow_daemon->server_ip6addr, "::", strlen("::")) == 0) {
			err = find_ipv6local(ccow_daemon->if_names[0], msg_origin_addr);
			if (err != 0)
				goto _exit;
		} else
			strcpy(msg_origin_addr, ccow_daemon->server_ip6addr);

		ccow_daemon->msg_origin_addr = je_strdup(msg_origin_addr);
		if (!ccow_daemon->msg_origin_addr) {
			err = -ENOMEM;
			goto _exit;
		}
		char *zone_idx = strchr(ccow_daemon->msg_origin_addr, '%');
		if (zone_idx)
			*zone_idx = '\0';

		if (strchr(ccow_daemon->server_ip6addr, '%'))
			strcpy(listen_addr, ccow_daemon->server_ip6addr);
		else
			snprintf(listen_addr, INET6_ADDRSTRLEN + IFNAMSIZ,
				"%s%%%s", ccow_daemon->server_ip6addr,
				ccow_daemon->if_names[0]);
	}

	ccow_daemon->robj[0] = replicast_init("daemon_main", ccow_daemon->loop,
	    listen_addr, ccow_daemon->server_port, ccow_daemon->unix_socket_addr,
	    msg_origin_addr, NULL, 0, ccow_daemon->mc_ttl, NULL);
	if (!ccow_daemon->robj[0]) {
		json_value_free(ccow_daemon->opts);
		err = -ENOENT;
		goto _exit;
	}
	replicast_vbuf_init(&ccow_daemon->robj[0]->rvbuf,
	    ccow_daemon->if_speeds[0]);
	// tell replicast that we are the server, and assign a pointer to us
	ccow_daemon->robj[0]->server_ctx = ccow_daemon;
	ccow_daemon->robj[0]->loop_thrid = ccow_daemon->loop_thrid;
	replicast_state_init(ccow_daemon->robj[0], RT_PINGPONG, pingpong_init);
	replicast_mcproxy_init(ccow_daemon->robj[0], reptrans_robj_mcproxy);

	/* initialize selected cluster engine on start */
	struct cl_node myself;
	memset(&myself, 0, sizeof(struct cl_node));

	err = ccowd_init_interfaces(&myself, ccow_daemon->robj[0]);
	if (err) {
		log_error(lg, "FATAL: ccowd interface init failed %d", err);
		json_value_free(ccow_daemon->opts);
		replicast_destroy(ccow_daemon->robj[0]);
		goto _exit;
	}

	uv_timer_init(ccow_daemon->loop, &ccow_daemon->host_stats_timer);
	ccow_daemon->host_stats_timer.data = NULL;
	uv_timer_start(&ccow_daemon->host_stats_timer, ccowd_host_stats,
				   CCOW_HOST_STATS_START_TIMER_MS, CCOW_HOST_STATS_TIMER_MS);

	uv_timer_init(ccow_daemon->loop, &ccow_daemon->gw_cache_timer);
	trlog_init(&ccow_daemon->trhdl);
	uv_timer_start(&ccow_daemon->gw_cache_timer, ccowd_gw_cache_timer,
				   CCOW_TRAN_START_TIMER_MS, CCOW_GW_CACHE_TIMER_MS);

	uv_async_init(ccow_daemon->loop, &ccow_daemon->exit_handle,
				  ccowd__on_exit);
	uv_async_init(ccow_daemon->loop, &ccow_daemon->auditc_message,
				  ccowd__on_auditc_message);
	uv_async_init(ccow_daemon->loop, &ccow_daemon->clengine_rebuild_message,
				  ccowd__on_clengine_rebuild_message);
	uv_async_init(ccow_daemon->loop, &ccow_daemon->clengine_rebuild_message_no_cp,
				  ccowd__on_clengine_rebuild_message_no_cp);

	/* Start device heart-beat timer */
	uv_timer_init(ccow_daemon->loop, &ccow_daemon->devhb_timer);
	uv_timer_start(&ccow_daemon->devhb_timer, ccowd_devhb_timer,
				   CCOW_DEV_HB_TIMER_MS, CCOW_DEV_HB_TIMER_MS);

	/* Initialize IPC commands demux */
	ccowd_ipc_cmd_init();

	/* initialize transports and devices, no timeout for now */
	err = reptrans_init(0, &myself, &rt_cfg, RT_FLAG_CREATE,
	    ccow_daemon->transport_count, ccow_daemon->transport_name, ccow_daemon->params);
	if (err < 0) {
		if (err != -ENODEV)
			log_error(lg, "FATAL: reptrans failed to init %d", err);
		json_value_free(ccow_daemon->opts);
		replicast_destroy(ccow_daemon->robj[0]);
		if (myself.vdevs)
			je_free(myself.vdevs);
		goto _exit;
	}

	if (server_get()->numdisks == 0) {
		myself.gateway = 1;
	}

	for (uint32_t j=0; j < myself.nr_vdevs; j++) {
		struct cl_vdev *vdevptr = &myself.vdevs[j];
		vdevptr->state = VDEV_STATE_ALIVE;
	}

	uv_timer_init(ccow_daemon->loop, &ccow_daemon->wal_flush_timer);
	uv_timer_start(&ccow_daemon->wal_flush_timer, ccow_wal_flush_timer,
				   CCOW_DEV_WAL_FLUSH_TIMEOUT,
				   ccow_daemon->wal_flush_interval);

	uv_timer_init(ccow_daemon->loop, &ccow_daemon->fhstats_timer);
	uv_timer_start(&ccow_daemon->fhstats_timer, ccowd_fhstats_timer,
				   CCOW_FLEXHASH_STATS_START_TIMER_MS,
				   CCOW_FLEXHASH_STATS_TIMER_MS);

	uv_timer_init(ccow_daemon->loop, &ccow_daemon->tran_timer);
	uv_timer_start(&ccow_daemon->tran_timer, ccowd_tran_timer,
			   CCOW_TRAN_START_TIMER_MS, ccow_daemon->trlog_interval_us/1000UL);

	uv_timer_init(ccow_daemon->loop, &ccow_daemon->healthy_timer);
	uv_timer_start(&ccow_daemon->healthy_timer, ccowd_healthy_timer,
		CCOW_HEALTHY_UPDATE_TIMER_MS, CCOW_HEALTHY_UPDATE_TIMER_MS);


	/* create a default hashcount if necessary */
	flexhash_hashcount_init(&myself);

	err = flexhash_add_server(SERVER_FLEXHASH, &myself, FH_TABLE_JOIN,
	    FH_GOOD_HC, FH_REBUILD_NEXT);
	if (err) {
		log_error(lg, "FATAL: flexhash unable to add myself to"
				"flexhash");
		reptrans_destroy();
		json_value_free(ccow_daemon->opts);
		if (myself.vdevs)
			je_free(myself.vdevs);
		goto _exit;
	}

	/* handle clengine failure to init, fatal */
	err = clengine_init(ccow_daemon->clengine, &myself);
	if (err) {
		log_error(lg, "FATAL: clengine failed to init %d", err);
		reptrans_destroy();
		json_value_free(ccow_daemon->opts);
		if (myself.vdevs)
			je_free(myself.vdevs);
		goto _exit;
	}
	/* Registering IPC handlers */
	for (size_t i = 0; i < sizeof(ipc_cmd_list)/sizeof(ipc_cmd_list[0]); i++) {
		int err = ccowd_register_ipc_cmd(ipc_cmd_list + i);
		if (err) {
			log_error(lg, "The IPC command <%s> already registered",
				ipc_cmd_list[i].key);
		}
	}
	/* now that we have the serverid , setup the audit server listener */
	err = ccow_daemon_init_ipc_listener(ccow_daemon);
	if (err != 0) {
		log_error(lg, "Error initializing audit server listener: %d", err);
		clengine_destroy();
		reptrans_destroy();
		json_value_free(ccow_daemon->opts);
		if (myself.vdevs)
			je_free(myself.vdevs);
		goto _exit;
	}

	if (myself.vdevs)
		je_free(myself.vdevs);

_exit:
	*err_out = err;
}

static void
ccowd_main_loop(void *UNUSED(arg))
{
	log_info(lg, "CCOW daemon main loop started");
	ccow_daemon->startup_err = -1;
	ccowd_startup(&ccow_daemon->startup_err);

	/*
	 * wait till ccow_daemon_init(), wq() and main_loop() all
	 * syncrhonized.
	 */
	uv_barrier_wait(&ccow_daemon->main_barrier);

	if (!ccow_daemon->startup_err) {
		pthread_setschedprio(uv_thread_self(), 15);
		uv_run(ccow_daemon->loop, UV_RUN_DEFAULT);

		while (!uv_workers_empty(ccow_daemon->loop)
			   || !uv_wq_empty(ccow_daemon->loop)) {
			usleep(10000);
			uv_run(ccow_daemon->loop, UV_RUN_ONCE);
		}

		/* Free memory allocated by uv_loop_new() in an unusual way.
		 * See a note for NED-1049 for explanation
		 **/

		/* Workaround made in NED-1049 has open filedescriptor leakage
		 * The problem why uv_loop_delete made seg faults, was because not all handles where "uv_close"-ed.
		 * Every handle should be closed before call uv_loop_delete.
		 * uv_timer_stop or similar functions are not mandatory to call prior uv_close.
		 * uv_close itself calls corresponding stop depending on the handle type.
		 * for more info see NED-3835
		*/
		uv_loop_delete(ccow_daemon->loop);
		ccow_daemon->loop = NULL;
		reptrans_close_all_rt();
		ccowtp_free(ccow_daemon->tp);
	}
	if (ccow_daemon->robj[0])
		replicast_finish_destroy(ccow_daemon->robj[0]);
	log_info(lg, "CCOW daemon main loop terminated");
}

static void
ccow_daemon_ipc_cb(uv_poll_t* handle, int status, int events)
{
	auditc_link *aclink = handle->data;

	if (status != 0) {
		log_error(lg, "Error receiving message from audit server ");
		return;
	}

	struct nn_iovec iov[2];
	struct nn_msghdr hdr;
	char* incmd = je_calloc(1, MAX_AUDITD_MSG);
	if (!incmd)
		return;

	iov[0].iov_base = incmd;
	iov[0].iov_len = MAX_AUDITD_MSG;

	memset(&hdr, 0, sizeof (hdr));
	hdr.msg_iov = iov;
	hdr.msg_iovlen = 2;

	ssize_t read_bytes = nn_recvmsg(aclink->sock_in, &hdr, NN_DONTWAIT);
	if (read_bytes == 0) {
		log_warn(lg, "audit server closed connection ");
		return;
	}

	if (read_bytes == -1) {
		if (errno == EAGAIN || errno == EINTR)
			read_bytes = nn_recvmsg(aclink->sock_in, &hdr,
						NN_DONTWAIT);
	}

	if (read_bytes <= 0)
		return;

	int err = ccowd_ipc_process_received_buffer(aclink, incmd, read_bytes);
	if (err == -ENOENT) {
		log_error(lg, "Couldn't find any handlers for ccowd ipc <%s>", incmd);
	} else if (err)
		log_error(lg, "Error processing ccowd ipc: <%s>", incmd);
}

int
ccow_daemon_init_ipc_listener(struct ccowd *ccow_daemon)
{
	auditc_link *aclink = ccow_daemon->aclink;

	aclink->sock_in = nn_socket(AF_SP, NN_REP);
	if (aclink->sock_in == -1) {
		log_error(lg, "ccow_daemon audit listener: create error: %s [%d]",
		    strerror(errno), (int)errno);
		return -errno;
	}
	char ipc_addr[PATH_MAX];
	snprintf(ipc_addr, sizeof(ipc_addr), CCOWD_IPC_ADDRESS, nedge_path());
	aclink->eid_in = nn_bind(aclink->sock_in, ipc_addr);
	if (aclink->eid_in < 0) {
		log_error(lg, "Failed to bind to \"%s\": %s [%d]",
				ipc_addr, strerror(errno), errno);
		nn_close(aclink->sock_in);
		aclink->sock_in = -1;
		return -errno;
	}
	log_info(lg, "Listening on \"%s\" for internal messages",
			ipc_addr);
	int ipc_fd;
	size_t fdsz = sizeof (ipc_fd);
	int err = nn_getsockopt (aclink->sock_in, NN_SOL_SOCKET, NN_RCVFD,
	    (char *)&ipc_fd, &fdsz);
	if (err < 0) {
		nn_close(aclink->sock_in);
		log_error(lg, "setsockopt rcv_fd error: %s [%d]",
			strerror(errno), (int)errno);
		aclink->sock_in = -1;
		return -errno;
	}

	ccow_daemon->ipc_req.data = aclink;
	uv_poll_init(ccow_daemon->loop, &ccow_daemon->ipc_req, ipc_fd);
	uv_poll_start(&ccow_daemon->ipc_req, UV_READABLE, ccow_daemon_ipc_cb);

	return 0;
}

static void
signal_handler(int signum)
{
	static int terminating = 0;
	static int flushing = 0;

	if (terminating) {
		if (!lg)
			return;
		log_warn(lg, "Received signal [%s] while exiting! Ignoring..",
		    strsignal(signum));
		return;
	}

	if (signum == SIGWINCH) {
		if (!lg)
			return;
		reptrans_start_scrub();
		return;
	}

	if (signum == SIGHUP) {
		if (!lg)
			return;
		Logger_hup(lg);
		char local_path[PATH_MAX];
		snprintf(local_path, sizeof(local_path), "%s/.local", nedge_path());
		FILE* fh = fopen(local_path, "r");
		if (fh == NULL)
			return;
		char line[128];
		while (fgets(line, 128, fh) != NULL) {
			char* p = strstr(line, "CCOWD_COREDUMP");
			if (p) {
				p = strchr(p, '0');
				if (p)
					ccow_daemon->do_core_dump = 0;
				else
					ccow_daemon->do_core_dump = 1;
				continue;
			}
		}
		fclose(fh);

		if (flushing) {
			log_warn(lg,
			    "Received signal [%s] while flushing! Ignoring..",
			    strsignal(signum));
			return;
		}
		flushing = 1;
		log_notice(lg, "Received signal [%s]! Flushing reptrans..",
			strsignal(signum));
		log_flush(lg);
		reptrans_flush(RD_FLUSH_FORCE);
		flushing = 0;
		return;
	}

	if (signum == SIGUSR2) {
		log_notice(lg, "Received signal [%s]! Sending message "
		    "to main thread to rebuild FH.. without CP", strsignal(signum));
		uv_async_send(&ccow_daemon->clengine_rebuild_message_no_cp);
		return;
	}

	if (signum == SIGUSR1) {
		if (!lg)
			return;
		char *str = getenv("UNAVAILABLE");
		if (str) {
			QUEUE *q, *d;
			struct reptrans *rt;

			QUEUE_FOREACH(q, &all_rts) {
				rt = QUEUE_DATA(q, struct reptrans, item);
				uv_rwlock_rdlock(&rt->devlock);
				QUEUE_FOREACH(d, &rt->devices) {
					struct repdev *dev;
					dev = QUEUE_DATA(d, struct repdev, item);
					uv_rwlock_rdunlock(&rt->devlock);

					repdev_status_t status = reptrans_dev_get_status(dev);
					if (dev->terminating ||
						status == REPDEV_STATUS_UNAVAILABLE) {
						uv_rwlock_rdlock(&rt->devlock);
						continue;
					}
					if (strcmp(dev->name, str)) {
						uv_rwlock_rdlock(&rt->devlock);
						continue;
					}
					log_notice(lg, "Device %s forced to "
						"DEAD", str);
					reptrans_dev_set_status(dev,
						REPDEV_STATUS_UNAVAILABLE);

					uv_rwlock_rdlock(&rt->devlock);
				}
				uv_rwlock_rdunlock(&rt->devlock);
			}
		} else {
			ccow_daemon->bg_restart = 1;
			log_notice(lg, "Received signal [%s]! Sending message "
			    "to main thread to rebuild FH..", strsignal(signum));
			uv_async_send(&ccow_daemon->clengine_rebuild_message);
		}
		return;
	}

	if (signum == SIGABRT || signum == SIGSEGV || signum == SIGBUS) {
		/* core dumps may be disallowed */
		struct rlimit core_limits;
		if (ccow_daemon->do_core_dump)
			core_limits.rlim_cur = core_limits.rlim_max = RLIM_INFINITY;
		else
			core_limits.rlim_cur = core_limits.rlim_max = 0;
		setrlimit(RLIMIT_CORE, &core_limits);

		if (lg) {
			int err = 0;
			char msg[256] = {0};
			const char* signame = strsignal(signum);
			struct repdev* dev = rt_get_thread_vdev_context();

			strcat(msg, "Received signal [");
			strcat(msg, signame);
			if (dev) {
				strcat(msg, "], VDEV context: ");
				strcat(msg, dev->name);
				strcat(msg, " , backtrace:");
			} else
				strcat(msg, "], backtrace:");
			log_backtrace(lg, 2, msg);
			log_flush(lg);
		}
		if (ccow_daemon->do_core_dump) {
			signal(signum, SIG_DFL);
			raise(signum);
			return;
		} else
			_exit(signum);
	}

	terminating = 1;

	if (lg)
		log_error(lg, "Received signal [%s]! Terminating..", strsignal(signum));

	/** @warning this function calls uv_thread_join() for our thread. It is
	 *           not a problem, but the correct solution is to avoid senceless
	 *           multithreading here */
	ccow_daemon_term();

	if (signum == SIGINT) {
		/*
		 * exit cleanly on SIGINT.  this will enable ASAN reporting.
		 */
		exit(0);
	}

	signal(signum, SIG_DFL);
	raise(signum);
}

static int
estimate_memlim(uint64_t *mem_out)
{
	char *env_memlim = getenv("CCOWD_CGROUP_MEMLIM");
	if (env_memlim) {
		*mem_out = atoll(env_memlim);
		return 0;
	} else if (is_embedded()) {
		*mem_out = CCOWD_MEMLIMIT_EMBEDDED;
		return 0;
	}

	/*
	 * read and parse /proc/meminfo.
	 */
	FILE * fp = 0;
	fp = fopen("/proc/meminfo", "r");
	if (fp == 0) {
		log_error(lg, "fopen returned error : %s", strerror(errno));
		return -errno;
	}

	char buf[128];
	size_t rv, free = 0, buffered = 0, cached = 0, swapcached = 0;
	int cached_read = 0;
	while (fgets(buf, sizeof(buf), fp)) {
		if (sscanf(buf, "MemFree: %zu kB", &rv) == 1) {
			free = rv * 1024UL;
			continue;
		}

		if (sscanf(buf, "Buffers: %zu kB", &rv) == 1) {
			buffered = rv * 1024UL;
			continue;
		}

		if (sscanf(buf, "Cached: %zu kB", &rv) == 1) {
			if (!cached_read) {
				cached = rv * 1024UL;
				cached_read = 1;
				continue;
			}
		}

		if (sscanf(buf, "SwapCached: %zu kB", &rv) == 1) {
			swapcached = rv * 1024UL;
			break;
		}
	}

	fclose(fp);

	if (free == 0) {
		log_error(lg, "cannot parse /proc/meminfo");
		return -ENOENT;
	}

	size_t free_ram  = free + buffered + cached;
	if (free_ram > swapcached + 1)
		free_ram -= swapcached;

	if (free_ram < DAEMON_MEM_MIN)
		*mem_out = DAEMON_MEM_MIN;
	else
		*mem_out = free_ram * DAEMON_MEM_FREE_PCT / 100;

	return 0;
}

static int
cgroup_setup(char *cgname, uint64_t memlim)
{
	int err;
	struct cgroup *cgroup = NULL;

	err = cgroup_init();
	if (err) {
		log_error(lg, "libcgroup init failed: %s",
		    cgroup_strerror(err));
		goto _exit;
	}

	void *handle;
	struct cgroup_file_info info;
	int lvl, count = 0, found = 0;

	err = cgroup_walk_tree_begin("memory", "/", 0, &handle, &info, &lvl);
	if (err != 0) {
		log_error(lg, "failed to enumerate existing cgroups");
		goto _exit;
	}
	while (cgroup_walk_tree_next(0, &handle, &info, lvl) != ECGEOF) {
		if (info.type == CGROUP_FILE_TYPE_DIR) {
			if (!strcmp(cgname, info.path))
				found = 1;
			count++;
		}
	}
	cgroup_walk_tree_end(&handle);

	cgroup = cgroup_new_cgroup(cgname);
	if (!cgroup) {
		err = ECGFAIL;
		log_error(lg, "failed to construct cgroup: %s",
		    cgroup_strerror(err));
		goto _exit;
	}

	struct cgroup_controller *cgc = NULL;
	if (found) {
		err = cgroup_get_cgroup(cgroup);
		if (err) {
			log_error(lg, "failed to get cgroup: %s",
			    cgroup_strerror(err));
			goto _exit;
		}
		cgc = cgroup_get_controller(cgroup, "memory");
		if (cgc) {
			err = cgroup_set_value_uint64(cgc, "memory.limit_in_bytes", memlim);
			if (err) {
				log_error(lg, "failed to set memory limit for cgroup");
				goto _exit;
			}
			err = cgroup_modify_cgroup(cgroup);
			if (err) {
				log_warn(lg, "failed to modify cgroup %s: %s", cgname,
				    cgroup_strerror(err));
				goto _exit;
			}
			goto _exit_attach;
		}
	}

	if (!cgc) {
		cgc = cgroup_add_controller(cgroup, "memory");
		if (!cgc) {
			err = ECGINVAL;
			log_error(lg, "failed to add memory controller");
			goto _exit;
		}
	}

	err = cgroup_add_value_uint64(cgc, "memory.limit_in_bytes", memlim);
	if (err) {
		log_error(lg, "failed to set memory limit for cgroup");
		goto _exit;
	}

	err = cgroup_add_value_uint64(cgc, "memory.swappiness", 0);
	if (err) {
		log_error(lg, "failed to set swappiness limit for cgroup");
		goto _exit;
	}

	err = cgroup_create_cgroup(cgroup, 1);
	if (err) {
		log_warn(lg, "failed to create cgroup %s: %s", cgname,
		    cgroup_strerror(err));
		goto _exit;
	}

_exit_attach:
	err = cgroup_attach_task(cgroup);
	if (err) {
		log_error(lg, "failed to assign new task to cgroup: %s",
		    cgroup_strerror(err));
		goto _exit;
	}

	log_info(lg, "cgroup memlimit set to %ldMB", memlim / 1024 / 1024);

_exit:
	if (cgroup)
		cgroup_free(&cgroup);
	return err;
}

static void
process_term(void *arg)
{
	/* sending signal from the thread so that TPs would not hang */
	raise(SIGTERM);
}

void
ccow_daemon_process_shutdown()
{
	static pthread_t process_term_thread;
	pthread_attr_t attr;
	int err;

	err = pthread_attr_init(&attr);
	if (!err)
		err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (!err)
		err = pthread_create(&process_term_thread, &attr,
		    (void *)&process_term, NULL);
	if (err) {
		log_error(lg, "process_term create : (%d) %s", err, strerror(err));
	}
	pthread_attr_destroy(&attr);

	/* we will give 90s to the process to terminate gracefully */
	sleep(90);

	/* if we still here - get out non-gracefully */
	raise(SIGKILL);
}

/**
 * Initialize CCOW library.
 *
 * Scope: PUBLIC
 */
int
ccow_daemon_init(struct ccowd_params *params)
{
	int err = 0;

	lg = Logger_create("ccowd");
	if (!lg)
		return -ENOMEM;

	load_crypto_lib();
	err = setpriority(PRIO_PROCESS, getpid(), -10);
	if (err) {
		log_warn(lg, "Unable to set process highest priority");
	}

#ifdef CCOW_VALGRIND
	if (!RUNNING_ON_VALGRIND) {
#endif
		struct rlimit limit;
		limit.rlim_cur = CCOWD_RLIMIT_NOFILE;
		limit.rlim_max = CCOWD_RLIMIT_NOFILE;
		if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
			log_warn(lg, "setrlimit() failed with err=%d\n", -errno);
		}
#ifdef CCOW_VALGRIND
	}
#endif

	const rlim_t stack_size = 32L * 1024L * 1024L;
	struct rlimit stack_limits;
	int res = getrlimit(RLIMIT_STACK, &stack_limits);

	if (res == 0) {
		if (stack_limits.rlim_cur < stack_size) {
			log_info(lg, "stack size was %d", (int) stack_limits.rlim_cur);
			log_info(lg, "setting stack size to %d", (int) stack_size);
			stack_limits.rlim_cur = stack_size;
			res = setrlimit(RLIMIT_STACK, &stack_limits);
			if (res != 0) {
				log_warn(lg, "setrlimit returned result = %d\n", res);
			}
		}
	}

	uint64_t memlim = 0;
	err = estimate_memlim(&memlim);
	if (err)
		return 1;

	if (memlim) {
		err = cgroup_setup(DAEMON_CGNAME, memlim);
	}

	ccow_daemon = je_calloc(1, sizeof (*ccow_daemon));
	if (!ccow_daemon) {
		log_error(lg, "Out of memory: -ENOMEM");
		return -ENOMEM;
	}
	ccow_daemon->do_core_dump = getenv("CCOWD_COREDUMP") != NULL;

	signal(SIGPIPE, SIG_IGN);       // Ignore SIG_IGN
	signal(SIGHUP, signal_handler);
	signal(SIGUSR1, signal_handler);
	signal(SIGUSR2, signal_handler);
	signal(SIGABRT, signal_handler);
	signal(SIGSEGV, signal_handler);
	signal(SIGBUS, signal_handler);

	// Ignore SIGINT till initialization is complete
	signal(SIGINT, SIG_IGN);

	crc32c_init();

	char ipc_addr[PATH_MAX];
	sprintf(ipc_addr, AUDITD_IPC_ADDRESS, nedge_path());
	ccow_daemon->params = params;
	ccow_daemon->aclink = auditc_init_with_namespace(ipc_addr, 0,
	    CCOW_AUDITC_NS);
	if (!ccow_daemon->aclink) {
		log_error(lg, "Error initializing audit client");
		je_free(ccow_daemon);
		ccow_daemon = NULL;
		return err;
	}

	err = server_init();
	if (err != 0) {
		log_error(lg, "Error initializing server statistics: %d", err);
		je_free(ccow_daemon);
		ccow_daemon = NULL;
		return err;
	}
	char srvbuf[MAX_SERVER_STR_LEN];
	server_dump(srvbuf, MAX_SERVER_STR_LEN);
	if (!params)
		log_notice(lg, "%s", srvbuf);

	/*
	 * FIXME: comment why we use 3 threads at startup
	 *
	 * @todo We really need only one single thread, because other threads
	 *       don't have any load.
	 */
	uv_barrier_init(&ccow_daemon->main_barrier, STARTUP_THREAD_SYNC_NUM);
	uv_thread_create(&ccow_daemon->main_thread, ccowd_main_loop, NULL);
	uv_barrier_wait(&ccow_daemon->main_barrier);

	signal(SIGINT, signal_handler);

	err = ccow_daemon->startup_err;
	if (err)
		ccow_daemon_term();

	return err;
}

/**
 * Terminate CCOW library.
 *
 * Scope: PUBLIC
 *
 * @warning this function calls uv_thread_join(). It is not a problem, but it
 *          is good idea to don't call it from main_watcher or main_thread.
 */
void
ccow_daemon_term()
{
	if (!ccow_daemon || ccowd_terminating)
		return;
	ccowd_terminating = 1;
	if (!ccow_daemon->startup_err)
		uv_async_send(&ccow_daemon->exit_handle);
	usleep(500000);
	if (ccow_daemon->tp)
		ccowtp_stop(ccow_daemon->tp, ccow_daemon->startup_err == 0 ? 1 : 0);
	uv_thread_join(&ccow_daemon->main_thread);
	uv_barrier_destroy(&ccow_daemon->main_barrier);
	if (ccow_daemon->server_ip6addr)
		je_free(ccow_daemon->server_ip6addr);
	if (ccow_daemon->server_ip4addr)
		je_free(ccow_daemon->server_ip4addr);
	if (ccow_daemon->unix_socket_addr)
		je_free(ccow_daemon->unix_socket_addr);
	if (ccow_daemon->msg_origin_addr)
		je_free(ccow_daemon->msg_origin_addr);
	if (ccow_daemon->mcbase_ip6addr)
		je_free(ccow_daemon->mcbase_ip6addr);
	if (ccow_daemon->mcbase_ip4addr)
		je_free(ccow_daemon->mcbase_ip4addr);
	if (SERVER_FLEXHASH) {
		flexhash_table_destroy(SERVER_FLEXHASH);
// FIXME: need to serialize vs. polling for FH rebuild here
//		uv_mutex_destroy(&ccow_daemon->fh_lock);
	}
	uv_cond_destroy(&ccow_daemon->fh_condv);
	auditc_finalize(ccow_daemon->aclink);
	trlog_destroy(&ccow_daemon->trhdl);
	if (ccow_daemon->enc_ctx)
		ccowd_host_encrypt_cleanup(ccow_daemon->enc_ctx);
	je_free(ccow_daemon);
	unload_crypto_lib();
	ccowd_ipc_cmd_term();
	Logger_destroy(lg);
	lg = NULL;
	ccow_daemon = NULL;
	ccowd_terminating = 0;
}
