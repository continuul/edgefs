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
#include <getopt.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <openssl/rand.h>

#include <nanomsg/nn.h>
#include <nanomsg/reqrep.h>

#include "ccowutil.h"
#include "msgpackalt.h"
#include "logger.h"
#include "ccow.h"
#include "h2o.h"
#include "h2o/serverutil.h"
#include "libauth/auth.h"
#include "ccowobj.h"
#include "session_cache.h"
#include "list_cache.h"
#include "picotls.h"
#include "picotls/minicrypto.h"
#include "picotls/openssl.h"

#define LISTCACHE_IPC			"ipc:///opt/nedge/var/run/listcache.ipc"
#define PROXY_KEEPALIVE_TIMEOUT		5000
#define PROXY_CONFIG_IO_TIMEOUT		600000
#define PROXY_SOCKET_PULL		8

static h2o_globalconf_t gconfig;
static ccowobj_handler_t *ccowobj_handle;
static int daemonize = 0;
char pidfile[PATH_MAX];
static pthread_t listcache_tid;


struct listener_ctx_t {
	h2o_accept_ctx_t accept_ctx;
	h2o_socket_t *sock;
};

struct listener_ssl_config_t {
	H2O_VECTOR(h2o_iovec_t) hostnames;
	char *certificate_file;
	SSL_CTX *ctx;
	struct {
		uint64_t interval;
		unsigned max_failures;
		char *cmd;
		pthread_t updater_tid; /* should be valid when and only when interval != 0 */
		struct {
			pthread_mutex_t mutex;
			h2o_buffer_t *data;
		} response;
	} ocsp_stapling;
};
#define H2O_DEFAULT_OCSP_UPDATER_MAX_THREADS 10

struct listener_config_t {
	int fd;
	struct sockaddr_storage addr;
	socklen_t addrlen;
	h2o_hostconf_t **hosts;
	H2O_VECTOR(struct listener_ssl_config_t *) ssl;
	int proxy_protocol;
};

struct st_session_ticket_generating_updater_conf_t {
    const EVP_CIPHER *cipher;
    const EVP_MD *md;
};

static struct {
    struct {
        void (*setup)(SSL_CTX **contexts, size_t num_contexts);
        union {
            struct {
                char *prefix;
                size_t num_threads;
            } memcached;
        } vars;
    } cache;
    struct {
        void *(*update_thread)(void *conf);
        union {
            struct st_session_ticket_generating_updater_conf_t generating;
        } vars;
    } ticket;
    unsigned lifetime;
} ssl_conf;

struct st_session_ticket_t {
    unsigned char name[16];
    struct {
        const EVP_CIPHER *cipher;
        unsigned char *key;
    } cipher;
    struct {
        const EVP_MD *md;
        unsigned char *key;
    } hmac;
    uint64_t not_before;
    uint64_t not_after;
};

typedef H2O_VECTOR(struct st_session_ticket_t *) session_ticket_vector_t;

static struct {
    pthread_rwlock_t rwlock;
    session_ticket_vector_t tickets; /* sorted from newer to older */
} session_tickets = {
/* we need writer-preferred lock, but on linux PTHREAD_RWLOCK_INITIALIZER is reader-preferred */
#ifdef PTHREAD_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP
    PTHREAD_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP
#else
    PTHREAD_RWLOCK_INITIALIZER
#endif
    ,
    {NULL} /* tickets */
};

static struct listener_config_t **listeners_config;
static int tfo_queues = 4096;
static size_t num_threads = 1;
static size_t num_listeners = 0;
static int max_connections = 1024;
static h2o_barrier_t startup_sync_barrier;

#define NUM_THREADS_EMBEDDED 4

struct {
	pthread_t tid;
	h2o_context_t ctx;
	h2o_multithread_receiver_t server_notifications;
} * threads;

struct {
	/* unused buffers exist to avoid false sharing of the cache line */
	char _unused1_avoir_false_sharing[32];
	int _num_connections; /* number of currently handled incoming connections,
				 should use atomic functions to update the value */
	char _unused2_avoir_false_sharing[32];
	unsigned long
		_num_sessions; /* total number of opened incoming connections,
				  should use atomic functions to update the value */
	char _unused3_avoir_false_sharing[32];
} srv_state;

volatile sig_atomic_t shutdown_requested;

struct ccow_send_generator_t {
	h2o_generator_t super;
};

static int
num_connections(int delta)
{
	return __sync_fetch_and_add(&srv_state._num_connections, delta);
}

static unsigned long
num_sessions(int delta)
{
	return __sync_fetch_and_add(&srv_state._num_sessions, delta);
}

static void
notify_all_threads(void)
{
	unsigned i;
	for (i = 0; i != num_threads; ++i)
		h2o_multithread_send_message(&threads[i].server_notifications, NULL);
}

static void
on_socketclose(void *data)
{
	int prev_num_connections = num_connections(-1);

	if (prev_num_connections == max_connections) {
		/* ready to accept new connections. wake up all the threads! */
		notify_all_threads();
	}
}

static void
on_accept(h2o_socket_t *listener, const char *err)
{
	struct listener_ctx_t *ctx = listener->data;
	size_t num_accepts = max_connections / 16 / num_threads;
	if (num_accepts < 8)
		num_accepts = 8;

	if (err != NULL) {
		return;
	}

	do {
		h2o_socket_t *sock;
		if (num_connections(0) >= max_connections) {
			/* The accepting socket is disactivated before entering the next in `run_loop`.
			 * Note: it is possible that the server would accept at most `max_connections + num_threads` connections, since the
			 * server does not check if the number of connections has exceeded _after_ epoll notifies of a new connection _but_
			 * _before_ calling `accept`.  In other words t/40max-connections.t may fail.
			 */
			break;
		}
		if ((sock = h2o_evloop_socket_accept(listener)) == NULL) {
			break;
		}
		num_connections(1);
		num_sessions(1);

		sock->on_close.cb = on_socketclose;
		sock->on_close.data = ctx->accept_ctx.ctx;

		h2o_accept(&ctx->accept_ctx, sock);

	} while (--num_accepts != 0);
}

static void
update_listener_state(struct listener_ctx_t *listeners)
{
	size_t i;

	if (num_connections(0) < max_connections) {
		for (i = 0; i != num_listeners; ++i) {
			if (!h2o_socket_is_reading(listeners[i].sock))
				h2o_socket_read_start(listeners[i].sock, on_accept);
		}
	} else {
		for (i = 0; i != num_listeners; ++i) {
			if (h2o_socket_is_reading(listeners[i].sock))
				h2o_socket_read_stop(listeners[i].sock);
		}
	}
}

static int
set_cloexec(int fd)
{
	return fcntl(fd, F_SETFD, FD_CLOEXEC) != -1 ? 0 : -1;
}

static void
on_server_notification(h2o_multithread_receiver_t *receiver, h2o_linklist_t *messages)
{
	/* the notification is used only for exitting h2o_evloop_run; actual changes are done in the main loop of run_loop */
	while (!h2o_linklist_is_empty(messages)) {
		h2o_multithread_message_t *message = H2O_STRUCT_FROM_MEMBER(h2o_multithread_message_t, link, messages->next);
		h2o_linklist_unlink(&message->link);
		je_free(message);
	}
}

static void*
listcache_loop(void *arg)
{
	int fd;

	fd = nn_socket(AF_SP, NN_REP);
	if (fd < 0) {
		log_error(lg, "nn_socket: %s\n", nn_strerror (nn_errno ()));
		return NULL;
	}

	if (nn_bind(fd, LISTCACHE_IPC) < 0) {
		log_error(lg, "nn_bind: %s\n", nn_strerror (nn_errno ()));
		nn_close (fd);
		return NULL;
	}

	/*  Its important to note that we must not issue two receives in a
	    row without replying first, or the following receive(s) will
	    cancel any unreplied requests. */
	while (1) {
		char cmdval[8192];
		int rc;

		if (shutdown_requested)
			break;

		rc = nn_recv(fd, cmdval, sizeof (cmdval), NN_DONTWAIT);
		if (rc < 0) {
			if (errno == EAGAIN) {
				usleep(1000);
				continue;
			}
			/*  Any error here is unexpected. */
			log_error(lg, "nn_recv: %s\n", nn_strerror (nn_errno ()));
			break;
		}

		/*  Ensure zero terminated string. */
		if ((unsigned)rc < sizeof (cmdval)) {
			cmdval[rc] = '\0';
		}

		/* Single char command */
		uint8_t cmd = cmdval[0];

		/* Value is in UTF8 */
		char *value = &cmdval[1];

		switch (cmd) {
		case 'L':
			// FIXME: implement list
			break;
		case 'P':
			// FIXME: implement put
			break;
		case 'D':
			// FIXME: implement delete
			break;
		default:
			log_error(lg, "Received malformed '%c' command", cmd);
			rc = nn_send(fd, "error", 6, 0);
			continue;
		}

		printf("recvd cmd=%c value len=%ld\n", cmd, strlen(value));

		/* pack example array of objects, so it will be available as
		 * JSON on Javascript side:
		 *
		 * [
		 *   { key1: '7', key2: 'long-value-xxxxxxxxxxxxxxxxxxxxxxxxxx\u0000' },
		 *   { key3: 'value3\u0000' }
		 * ]
		 */
		msgpack_p *p = msgpack_pack_init();
		msgpack_pack_array(p, 2);

		/* array element 0, 2 key-value */
		msgpack_pack_map(p, 2);
		msgpack_pack_raw(p, "key1", 4);
		msgpack_pack_int32(p, 7);
		msgpack_pack_raw(p, "key2", 4);
		msgpack_pack_str(p, "long-value-xxxxxxxxxxxxxxxxxxxxxxxxxx");

		/* array element 1, 1 key-value */
		msgpack_pack_map(p, 1);
		msgpack_pack_raw(p, "key3", 4);
		msgpack_pack_str(p, "value3");

		uv_buf_t buf;
		msgpack_get_buffer(p, &buf);

		rc = nn_send(fd, buf.base, buf.len, 0);
		if (rc < 0) {
			log_error(lg, "nn_send: %s (ignoring)\n",
			    nn_strerror (nn_errno ()));
		}
		msgpack_pack_free(p);
	}

	nn_close (fd);
	return NULL;
}

static void *
run_loop(void *_thread_index)
{
	size_t thread_index = (size_t)_thread_index;
	struct listener_ctx_t *listeners = alloca(sizeof(*listeners) * num_listeners);
	size_t i;
	int err;

	h2o_context_init(&threads[thread_index].ctx, h2o_evloop_create(), &gconfig);
	h2o_multithread_register_receiver(threads[thread_index].ctx.queue,
	    &threads[thread_index].server_notifications, on_server_notification);
	threads[thread_index].tid = pthread_self();

	/* setup listeners */
	for (i = 0; i != num_listeners; ++i) {
		struct listener_config_t *listener_config = listeners_config[i];
		int fd;

		/* dup the listener fd for other threads than the main thread */
		if (thread_index == 0) {
			fd = listener_config->fd;
		} else {
			if ((fd = dup(listener_config->fd)) == -1) {
				perror("failed to dup listening socket");
				abort();
			}
			set_cloexec(fd);
		}
		memset(listeners + i, 0, sizeof(listeners[i]));
		listeners[i].accept_ctx.ctx = &threads[thread_index].ctx;
		listeners[i].accept_ctx.hosts = listener_config->hosts;
		if (listener_config->ssl.size != 0)
			listeners[i].accept_ctx.ssl_ctx = listener_config->ssl.entries[0]->ctx;
		listeners[i].accept_ctx.expect_proxy_line = listener_config->proxy_protocol;
		listeners[i].sock = h2o_evloop_socket_create(threads[thread_index].ctx.loop, fd, H2O_SOCKET_FLAG_DONT_READ);
		listeners[i].sock->data = listeners + i;
	}

	/* and start listening */
	update_listener_state(listeners);

	/* make sure all threads are initialized before starting to serve requests */
	h2o_barrier_wait(&startup_sync_barrier);

	if (thread_index == 0) {
		err = strsess_cache_ini(&sess_cache, STRSESS_CACHE_NUM, on_strsess_evict);
		if (err) {
			log_error(lg, "Terminating due to sess_cache ini error %d", err);
			shutdown_requested = 1;
		} else {
			/* 1 seconds timer for strsess */
			strsess_timeout.super.cb = on_strsess_timeout;
			strsess_timeout.ctx = &threads[0].ctx;
			strsess_timeout.cache = sess_cache;
			h2o_timeout_link(threads[0].ctx.loop, &threads[0].ctx.one_sec_timeout,
			    &strsess_timeout.super);
		}

		char cluster[MAX_ITEM_SIZE];
		memcpy(cluster, ccowobj_handle->tenant_path.base, ccowobj_handle->tenant_path.len);
		cluster[ccowobj_handle->tenant_path.len] = '\0';
		char *p = strstr(cluster,"/");
		if (p == NULL) {
			log_error(lg, "Terminating due to cluster name parse error");
			shutdown_requested = 1;
		} else {
			*p = '\0';
		}

		err = list_cache_ini(&list_cache, cluster);
		if (err) {
			log_error(lg, "Terminating due to list_cache ini error %d", err);
			shutdown_requested = 1;
		} else {
			/* 1 seconds timer for list cache */
			list_timeout.super.cb = on_list_timeout;
			list_timeout.ctx = &threads[0].ctx;
			list_timeout.cache = list_cache;
			h2o_timeout_link(threads[0].ctx.loop, &threads[0].ctx.one_sec_timeout,
			    &list_timeout.super);
		}

	}

	/* the main loop */
	while (1) {
		if (shutdown_requested)
			break;
		update_listener_state(listeners);
		/* run the loop once */
		h2o_evloop_run(threads[thread_index].ctx.loop, INT32_MAX);
	}

	if (thread_index == 0) {
		log_info(lg, "received SIGTERM, gracefully shutting down");
		pthread_join(listcache_tid, NULL);
	}

	/* shutdown requested, unregister, close the listeners and notify the protocol handlers */
	for (i = 0; i != num_listeners; ++i)
		h2o_socket_read_stop(listeners[i].sock);
	h2o_evloop_run(threads[thread_index].ctx.loop, 0);
	for (i = 0; i != num_listeners; ++i) {
		h2o_socket_close(listeners[i].sock);
		listeners[i].sock = NULL;
	}
	h2o_context_request_shutdown(&threads[thread_index].ctx);

	/* wait until all the connection gets closed */
	while (num_connections(0) != 0)
		h2o_evloop_run(threads[thread_index].ctx.loop, INT32_MAX);

	ccowobj_deregister_ctx(ccowobj_handle, &threads[thread_index].ctx);

	/* closing caches at the very end */
	if (thread_index == 0) {
		strsess_cache_fini(sess_cache);
		list_cache_fini(list_cache);
		unlink(pidfile);
	}

	return NULL;
}

static void
setup_ecc_key(SSL_CTX *ssl_ctx)
{
#ifdef SSL_CTX_set_ecdh_auto
	SSL_CTX_set_ecdh_auto(ssl_ctx, 1);
#else
	int nid = NID_X9_62_prime256v1;
	EC_KEY *key = EC_KEY_new_by_curve_name(nid);
	if (key == NULL) {
		log_error(lg, "Failed to create curve \"%s\"", OBJ_nid2sn(nid));
		return;
	}
	SSL_CTX_set_tmp_ecdh(ssl_ctx, key);
	EC_KEY_free(key);
#endif
}

static void
update_ocsp_stapling(struct listener_ssl_config_t *ssl_conf, h2o_buffer_t *resp)
{
	pthread_mutex_lock(&ssl_conf->ocsp_stapling.response.mutex);
	if (ssl_conf->ocsp_stapling.response.data != NULL)
		h2o_buffer_dispose(&ssl_conf->ocsp_stapling.response.data);
	ssl_conf->ocsp_stapling.response.data = resp;
	pthread_mutex_unlock(&ssl_conf->ocsp_stapling.response.mutex);
}

static int
get_ocsp_response(const char *cert_fn, char *cmd_fullpath, h2o_buffer_t **resp)
{
	char *argv[] = {cmd_fullpath, (char *)cert_fn, NULL};
	int child_status, ret;

	if (h2o_read_command(cmd_fullpath, argv, resp, &child_status) != 0) {
		log_error(lg, "[OCSP Stapling] failed to execute %s:%s",
		    cmd_fullpath, strerror(errno));
		switch (errno) {
		case EACCES:
		case ENOENT:
		case ENOEXEC:
			/* permanent errors */
			ret = EX_CONFIG;
			goto Exit;
		default:
			ret = EX_TEMPFAIL;
			goto Exit;
		}
	}

	if (!(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0))
		h2o_buffer_dispose(resp);
	if (!WIFEXITED(child_status)) {
		log_error(lg, "[OCSP Stapling] command %s was killed by signal %d",
		    cmd_fullpath, WTERMSIG(child_status));
		ret = EX_TEMPFAIL;
		goto Exit;
	}
	ret = WEXITSTATUS(child_status);

Exit:
	return ret;
}

static h2o_sem_t ocsp_updater_semaphore;

static void *
ocsp_updater_thread(void *_ssl_conf)
{
	struct listener_ssl_config_t *ssl_conf = _ssl_conf;
	time_t next_at = 0, now;
	unsigned fail_cnt = 0;
	int status;
	h2o_buffer_t *resp;

	assert(ssl_conf->ocsp_stapling.interval != 0);

	log_info(lg, "[OCSP Stapling] thread started");

	while (1) {
		/* sleep until next_at */
		if ((now = time(NULL)) < next_at) {
			time_t sleep_secs = next_at - now;
			sleep(sleep_secs < UINT_MAX ? (unsigned)sleep_secs : UINT_MAX);
			continue;
		}
		/* fetch the response */
		h2o_sem_wait(&ocsp_updater_semaphore);
		status = get_ocsp_response(ssl_conf->certificate_file, ssl_conf->ocsp_stapling.cmd, &resp);
		h2o_sem_post(&ocsp_updater_semaphore);
		switch (status) {
		case 0: /* success */
			fail_cnt = 0;
			update_ocsp_stapling(ssl_conf, resp);
			log_error(lg, "[OCSP Stapling] successfully updated the response for certificate file:%s",
			    ssl_conf->certificate_file);
			break;
		case EX_TEMPFAIL: /* temporary failure */
			if (fail_cnt == ssl_conf->ocsp_stapling.max_failures) {
				log_error(lg,
				    "[OCSP Stapling] OCSP stapling is temporary disabled due to repeated errors for certificate file:%s",
				    ssl_conf->certificate_file);
				update_ocsp_stapling(ssl_conf, NULL);
			} else {
				log_error(lg, "[OCSP Stapling] reusing old response due to a temporary error occurred while fetching OCSP "
				    "response for certificate file:%s",
				    ssl_conf->certificate_file);
				++fail_cnt;
			}
			break;
		default: /* permanent failure */
			update_ocsp_stapling(ssl_conf, NULL);
			log_warn(lg, "[OCSP Stapling] disabled for certificate file:%s",
			    ssl_conf->certificate_file);
			goto Exit;
		}
		/* update next_at */
		next_at = time(NULL) + ssl_conf->ocsp_stapling.interval;
	}

Exit:
	return NULL;
}

static int
on_staple_ocsp_ossl(SSL *ssl, void *_ssl_conf)
{
	struct listener_ssl_config_t *ssl_conf = _ssl_conf;
	void *resp = NULL;
	size_t len = 0;

	/* fetch ocsp response */
	pthread_mutex_lock(&ssl_conf->ocsp_stapling.response.mutex);
	if (ssl_conf->ocsp_stapling.response.data != NULL) {
		resp = CRYPTO_malloc((int)ssl_conf->ocsp_stapling.response.data->size, __FILE__, __LINE__);
		if (resp != NULL) {
			len = ssl_conf->ocsp_stapling.response.data->size;
			memcpy(resp, ssl_conf->ocsp_stapling.response.data->bytes, len);
		}
	}
	pthread_mutex_unlock(&ssl_conf->ocsp_stapling.response.mutex);

	if (resp != NULL) {
		SSL_set_tlsext_status_ocsp_resp(ssl, resp, len);
		return SSL_TLSEXT_ERR_OK;
	} else {
		return SSL_TLSEXT_ERR_NOACK;
	}
}

static struct listener_ssl_config_t *
resolve_sni(struct listener_config_t *listener, const char *name, size_t name_len)
{
	size_t i, j;

	for (i = 0; i != listener->ssl.size; ++i) {
		struct listener_ssl_config_t *ssl_config = listener->ssl.entries[i];
		for (j = 0; j != ssl_config->hostnames.size; ++j) {
			if (ssl_config->hostnames.entries[j].base[0] == '*') {
				/* matching against "*.foo.bar" */
				size_t cmplen = ssl_config->hostnames.entries[j].len - 1;
				if (!(cmplen < name_len && h2o_lcstris(name + name_len - cmplen, cmplen, ssl_config->hostnames.entries[j].base + 1,
						    ssl_config->hostnames.entries[j].len - 1)))
					continue;
			} else {
				if (!h2o_lcstris(name, name_len, ssl_config->hostnames.entries[j].base, ssl_config->hostnames.entries[j].len))
					continue;
			}
			/* found */
			return listener->ssl.entries[i];
		}
	}
	return listener->ssl.entries[0];
}

static int
on_sni_callback(SSL *ssl, int *ad, void *arg)
{
	struct listener_config_t *listener = arg;
	const char *server_name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

	if (server_name != NULL) {
		struct listener_ssl_config_t *resolved = resolve_sni(listener, server_name, strlen(server_name));
		if (resolved->ctx != SSL_get_SSL_CTX(ssl))
			SSL_set_SSL_CTX(ssl, resolved->ctx);
	}

	return SSL_TLSEXT_ERR_OK;
}

struct st_staple_ocsp_ptls_t {
	ptls_staple_ocsp_t super;
	struct listener_ssl_config_t *conf;
};

static int
on_staple_ocsp_ptls(ptls_staple_ocsp_t *_self, ptls_t *tls, ptls_buffer_t *output, size_t cert_index)
{
	struct st_staple_ocsp_ptls_t *self = (struct st_staple_ocsp_ptls_t *)_self;
	int locked = 0, ret;

	if (cert_index != 0) {
		ret = PTLS_ERROR_LIBRARY;
		goto Exit;
	}

	pthread_mutex_lock(&self->conf->ocsp_stapling.response.mutex);
	locked = 1;

	if (self->conf->ocsp_stapling.response.data == NULL) {
		ret = PTLS_ERROR_LIBRARY;
		goto Exit;
	}
	ptls_buffer_pushv(output, self->conf->ocsp_stapling.response.data->bytes, self->conf->ocsp_stapling.response.data->size);
	ret = 0;

Exit:
	if (locked)
		pthread_mutex_unlock(&self->conf->ocsp_stapling.response.mutex);
	return ret;
}

struct st_on_client_hello_ptls_t {
	ptls_on_client_hello_t super;
	struct listener_config_t *listener;
};

static int
on_client_hello_ptls(ptls_on_client_hello_t *_self, ptls_t *tls, ptls_iovec_t server_name,
    const ptls_iovec_t *negotiated_protocols, size_t num_negotiated_protocols,
    const uint16_t *signature_algorithms, size_t num_signature_algorithms)
{
	struct st_on_client_hello_ptls_t *self = (struct st_on_client_hello_ptls_t *)_self;
	int ret = 0;

	/* handle SNI */
	if (server_name.base != NULL) {
		struct listener_ssl_config_t *resolved = resolve_sni(self->listener, (const char *)server_name.base, server_name.len);
		ptls_context_t *newctx = h2o_socket_ssl_get_picotls_context(resolved->ctx);
		ptls_set_context(tls, newctx);
		ptls_set_server_name(tls, (const char *)server_name.base, server_name.len);
	}

	/* handle ALPN */
	if (num_negotiated_protocols != 0) {
		const h2o_iovec_t *server_pref;
		for (server_pref = h2o_alpn_protocols; server_pref->len != 0; ++server_pref) {
			size_t i;
			for (i = 0; i != num_negotiated_protocols; ++i)
				if (h2o_memis(server_pref->base, server_pref->len, negotiated_protocols[i].base, negotiated_protocols[i].len))
					goto ALPN_Found;
		}
		return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
ALPN_Found:
		if ((ret = ptls_set_negotiated_protocol(tls, server_pref->base, server_pref->len)) != 0)
			return ret;
	}

	return ret;
}

static const char *
listener_setup_ssl_picotls(struct listener_config_t *listener, struct listener_ssl_config_t *ssl_config,
    SSL_CTX *ssl_ctx)
{
	static const ptls_key_exchange_algorithm_t *key_exchanges[] = {&ptls_minicrypto_x25519, &ptls_openssl_secp256r1, NULL};
	struct st_fat_context_t {
		ptls_context_t ctx;
		struct st_on_client_hello_ptls_t ch;
		struct st_staple_ocsp_ptls_t so;
		ptls_openssl_sign_certificate_t sc;
	} *pctx = h2o_mem_alloc(sizeof(*pctx));
	EVP_PKEY *key;
	X509 *cert;
	STACK_OF(X509) * cert_chain;
	int ret;

	*pctx = (struct st_fat_context_t){{ptls_openssl_random_bytes,
		key_exchanges,
		ptls_openssl_cipher_suites,
		{NULL, 0},
		&pctx->ch.super,
		&pctx->so.super,
		&pctx->sc.super,
		NULL,
		0,
		8192,
		1},
		{{on_client_hello_ptls}, listener},
		{{on_staple_ocsp_ptls}, ssl_config}};

	{ /* obtain key and cert (via fake connection for libressl compatibility) */
		SSL *fakeconn = SSL_new(ssl_ctx);
		assert(fakeconn != NULL);
		key = SSL_get_privatekey(fakeconn);
		assert(key != NULL);
		cert = SSL_get_certificate(fakeconn);
		assert(cert != NULL);
		SSL_free(fakeconn);
	}

	if (ptls_openssl_init_sign_certificate(&pctx->sc, key) != 0) {
		je_free(pctx);
		return "failed to setup private key";
	}

	SSL_CTX_get_extra_chain_certs(ssl_ctx, &cert_chain);
	ret = ptls_openssl_load_certificates(&pctx->ctx, cert, cert_chain);
	assert(ret == 0);

	h2o_socket_ssl_set_picotls_context(ssl_ctx, &pctx->ctx);

	return NULL;
}

static int
listener_setup_ssl(const char *cert_file, const char *key_file,
    struct listener_config_t *listener, char *host)
{
	SSL_CTX *ssl_ctx = NULL;
	long ssl_options = SSL_OP_ALL;

        /* default is >= TLSv1 */
        ssl_options |= SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;

/* disable tls compression to avoid "CRIME" attacks (see http://en.wikipedia.org/wiki/CRIME) */
#ifdef SSL_OP_NO_COMPRESSION
	ssl_options |= SSL_OP_NO_COMPRESSION;
#endif

	ssl_ctx = SSL_CTX_new(SSLv23_server_method());
	SSL_CTX_set_options(ssl_ctx, ssl_options);
	setup_ecc_key(ssl_ctx);

	/* load certificate and private key */
	if (SSL_CTX_use_certificate_file(ssl_ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
		log_error(lg, "an error occurred while trying to load server certificate file:%s", cert_file);
		return -1;
	}
	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
		log_error(lg, "an error occurred while trying to load private key file:%s", key_file);
		return -1;
	}

	char *cipher_suite = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256";
	if (SSL_CTX_set_cipher_list(ssl_ctx, cipher_suite) != 1) {
		log_error(lg, "failed to setup SSL cipher suite");
		return -1;
	}

	/* setup protocol negotiation methods */
#if H2O_USE_NPN
	h2o_ssl_register_npn_protocols(ssl_ctx, h2o_npn_protocols);
#endif
#if H2O_USE_ALPN
	h2o_ssl_register_alpn_protocols(ssl_ctx, h2o_alpn_protocols);
#endif

	/* set SNI callback to the first SSL context, when and only when it should be used */
	if (listener->ssl.size == 1) {
		SSL_CTX_set_tlsext_servername_callback(listener->ssl.entries[0]->ctx, on_sni_callback);
		SSL_CTX_set_tlsext_servername_arg(listener->ssl.entries[0]->ctx, listener);
	}

	/* create a new entry in the SSL context list */
	struct listener_ssl_config_t *ssl_config = h2o_mem_alloc(sizeof(*ssl_config));
	memset(ssl_config, 0, sizeof(*ssl_config));

	h2o_vector_reserve(NULL, &listener->ssl, listener->ssl.size + 1);
	listener->ssl.entries[listener->ssl.size++] = ssl_config;

	h2o_vector_reserve(NULL, &ssl_config->hostnames, ssl_config->hostnames.size + 1);
	ssl_config->hostnames.entries[ssl_config->hostnames.size++] = h2o_iovec_init(host, strlen(host));

	ssl_config->ctx = ssl_ctx;
	ssl_config->certificate_file = je_strdup(cert_file);

	SSL_CTX_set_tlsext_status_cb(ssl_ctx, on_staple_ocsp_ossl);
	SSL_CTX_set_tlsext_status_arg(ssl_ctx, ssl_config);

	pthread_mutex_init(&ssl_config->ocsp_stapling.response.mutex, NULL);
	ssl_config->ocsp_stapling.cmd = "/opt/nedge/sbin/fetch-ocsp-response";
	ssl_config->ocsp_stapling.interval = 4 * 60 * 60; /* defaults to 4 hours */
	ssl_config->ocsp_stapling.max_failures = 3; /* defaults to 3; permit 3 failures before temporary disabling OCSP stapling */
	h2o_multithread_create_thread(&ssl_config->ocsp_stapling.updater_tid, NULL, ocsp_updater_thread, ssl_config);

        const char *errstr = listener_setup_ssl_picotls(listener, ssl_config, ssl_ctx);
        if (errstr != NULL)
		log_error(lg, "%s; TLS 1.3 will be disabled", errstr);

	return 0;
}

static struct listener_config_t *
add_listener(int fd, struct sockaddr *addr, socklen_t addrlen, int is_global, int proxy_protocol)
{
	struct listener_config_t *listener = h2o_mem_alloc(sizeof(*listener));

	memcpy(&listener->addr, addr, addrlen);
	listener->fd = fd;
	listener->addrlen = addrlen;
	if (is_global) {
		listener->hosts = NULL;
	} else {
		listener->hosts = h2o_mem_alloc(sizeof(listener->hosts[0]));
		listener->hosts[0] = NULL;
	}
	memset(&listener->ssl, 0, sizeof(listener->ssl));
	listener->proxy_protocol = proxy_protocol;

	listeners_config = h2o_mem_realloc(listeners_config, sizeof(*listeners_config) * (num_listeners + 1));
	listeners_config[num_listeners++] = listener;

	return listener;
}

static int
open_tcp_listener(const char *hostname, const char *port, int domain,
    int type, int protocol, struct sockaddr *addr, socklen_t addrlen)
{
	int fd;

	if ((fd = socket(domain, type, protocol)) == -1)
		goto Error;
	set_cloexec(fd);

	{ /* set reuseaddr */
		int flag = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) != 0)
			goto Error;
	}

	{ /* set TCP_DEFER_ACCEPT */
		int flag = 1;
		if (setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &flag, sizeof(flag)) != 0)
			goto Error;
	}

	if (bind(fd, addr, addrlen) != 0)
		goto Error;

	if (listen(fd, H2O_SOMAXCONN) != 0)
		goto Error;

	/* set TCP_FASTOPEN; when tfo_queues is zero TFO is always disabled */
	if (tfo_queues > 0) {
		int tfo_q = tfo_queues;
		if (setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, (const void *)&tfo_q, sizeof(tfo_q)) != 0)
			log_error(lg, "[warning] failed to set TCP_FASTOPEN:%s", strerror(errno));
	}

	log_info(lg, "Listening on %s:%s", hostname, port);

	return fd;

Error:
	if (fd != -1)
		close(fd);
	log_error(lg, "failed to listen to port %s:%s: %s", hostname != NULL ? hostname : "ANY", port,
	    strerror(errno));
	return -1;
}

static struct st_session_ticket_t *
new_ticket(const EVP_CIPHER *cipher, const EVP_MD *md, uint64_t not_before,
    uint64_t not_after, int fill_in)
{
	int key_len = EVP_CIPHER_key_length(cipher), block_size = EVP_MD_block_size(md);
	struct st_session_ticket_t *ticket = h2o_mem_alloc(sizeof(*ticket) + key_len + block_size);

	ticket->cipher.cipher = cipher;
	ticket->cipher.key = (unsigned char *)ticket + sizeof(*ticket);
	ticket->hmac.md = md;
	ticket->hmac.key = ticket->cipher.key + key_len;
	ticket->not_before = not_before;
	ticket->not_after = not_after;
	if (fill_in) {
		RAND_bytes(ticket->name, sizeof(ticket->name));
		RAND_bytes(ticket->cipher.key, key_len);
		RAND_bytes(ticket->hmac.key, block_size);
	}

	return ticket;
}

static void
free_ticket(struct st_session_ticket_t *ticket)
{
	int key_len = EVP_CIPHER_key_length(ticket->cipher.cipher), block_size = EVP_MD_block_size(ticket->hmac.md);
	h2o_mem_set_secure(ticket, 0, sizeof(*ticket) + key_len + block_size);
	je_free(ticket);
}

static int
ticket_sort_compare(const void *_x, const void *_y)
{
	struct st_session_ticket_t *x = *(void **)_x, *y = *(void **)_y;

	if (x->not_before != y->not_before)
		return x->not_before > y->not_before ? -1 : 1;
	return memcmp(x->name, y->name, sizeof(x->name));
}

static void
free_tickets(session_ticket_vector_t *tickets)
{
	size_t i;
	for (i = 0; i != tickets->size; ++i)
		free_ticket(tickets->entries[i]);
	je_free(tickets->entries);
	memset(tickets, 0, sizeof(*tickets));
}

static struct
st_session_ticket_t *find_ticket_for_encryption(session_ticket_vector_t *tickets, uint64_t now)
{
	size_t i;

	for (i = 0; i != tickets->size; ++i) {
		struct st_session_ticket_t *ticket = tickets->entries[i];
		if (ticket->not_before <= now) {
			if (now <= ticket->not_after) {
				return ticket;
			} else {
				return NULL;
			}
		}
	}
	return NULL;
}

static int
ticket_key_callback(unsigned char *key_name, unsigned char *iv, EVP_CIPHER_CTX *ctx, HMAC_CTX *hctx, int enc)
{
	int ret;
	pthread_rwlock_rdlock(&session_tickets.rwlock);

	if (enc) {
		RAND_bytes(iv, EVP_MAX_IV_LENGTH);
		struct st_session_ticket_t *ticket = find_ticket_for_encryption(&session_tickets.tickets, time(NULL)), *temp_ticket = NULL;
		if (ticket != NULL) {
		} else {
			/* create a dummy ticket and use (this is the only way to continue the handshake; contrary to the man pages, OpenSSL
			 * crashes if we return zero */
			ticket = temp_ticket = new_ticket(EVP_aes_256_cbc(), EVP_sha256(), 0, UINT64_MAX, 1);
		}
		memcpy(key_name, ticket->name, sizeof(ticket->name));
		EVP_EncryptInit_ex(ctx, ticket->cipher.cipher, NULL, ticket->cipher.key, iv);
		HMAC_Init_ex(hctx, ticket->hmac.key, EVP_MD_block_size(ticket->hmac.md), ticket->hmac.md, NULL);
		if (temp_ticket != NULL)
			free_ticket(ticket);
		ret = 1;
	} else {
		struct st_session_ticket_t *ticket;
		size_t i;
		for (i = 0; i != session_tickets.tickets.size; ++i) {
			ticket = session_tickets.tickets.entries[i];
			if (memcmp(ticket->name, key_name, sizeof(ticket->name)) == 0)
				goto Found;
		}
		/* not found */
		ret = 0;
		goto Exit;
Found:
		EVP_DecryptInit_ex(ctx, ticket->cipher.cipher, NULL, ticket->cipher.key, iv);
		HMAC_Init_ex(hctx, ticket->hmac.key, EVP_MD_block_size(ticket->hmac.md), ticket->hmac.md, NULL);
		/* Request renewal if the youngest key is active */
		if (i != 0 && session_tickets.tickets.entries[i - 1]->not_before <= (uint64_t)time(NULL))
			ret = 2;
		else
			ret = 1;
	}

Exit:
	pthread_rwlock_unlock(&session_tickets.rwlock);
	return ret;
}

static int
ticket_key_callback_ossl(SSL *ssl, unsigned char *key_name, unsigned char *iv,
    EVP_CIPHER_CTX *ctx, HMAC_CTX *hctx, int enc)
{
	return ticket_key_callback(key_name, iv, ctx, hctx, enc);
}

static int
encrypt_ticket_key_ptls(ptls_encrypt_ticket_t *self, ptls_t *tls, int is_encrypt, ptls_buffer_t *dst, ptls_iovec_t src)
{
	return (is_encrypt ? ptls_openssl_encrypt_ticket : ptls_openssl_decrypt_ticket)(dst, src, ticket_key_callback);
}

static void
ssl_setup_session_resumption(SSL_CTX **contexts, size_t num_contexts)
{
	if (ssl_conf.cache.setup != NULL)
		ssl_conf.cache.setup(contexts, num_contexts);

	if (num_contexts == 0)
		return;

	/* start session ticket updater thread */
	pthread_t tid;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, 1);
	h2o_multithread_create_thread(&tid, &attr, ssl_conf.ticket.update_thread, NULL);
	size_t i;
	for (i = 0; i != num_contexts; ++i) {
		SSL_CTX *ctx = contexts[i];
		SSL_CTX_set_tlsext_ticket_key_cb(ctx, ticket_key_callback_ossl);
		ptls_context_t *pctx = h2o_socket_ssl_get_picotls_context(ctx);
		if (pctx != NULL) {
			static ptls_encrypt_ticket_t encryptor = {encrypt_ticket_key_ptls};
			pctx->ticket_lifetime = 86400 * 7; // FIXME conf.lifetime;
			pctx->encrypt_ticket = &encryptor;
		}
	}
}

static int
setup_listener(h2o_hostconf_t *hostconf, char *host, char *port, int is_ssl)
{
	/* TCP socket */
	struct addrinfo hints, *res, *ai;
	int error;
	struct stat st;
	char httpsKey[256];
	char httpsCert[256];

	/* call getaddrinfo */
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;
	if ((error = getaddrinfo(host, port, &hints, &res)) != 0) {
		log_error(lg, "failed to resolve the listening address");
		return -1;
	} else if (res == NULL) {
		log_error(lg, "failed to resolve the listening address: getaddrinfo returned an empty list");
		return -1;
	}

	for (ai = res; ai != NULL; ai = ai->ai_next) {
		int fd = open_tcp_listener(host, port, ai->ai_family,
		    ai->ai_socktype, ai->ai_protocol, ai->ai_addr, ai->ai_addrlen);
		if (fd == -1) {
			freeaddrinfo(res);
			return -1;
		}
		struct listener_config_t *listener =
			add_listener(fd, ai->ai_addr, ai->ai_addrlen, 0, 0);


		if (stat("/opt/nedge/nmf/etc", &st) == 0) {
			if (stat("/opt/nedge/nmf/etc/h2o.key", &st) == 0 &&
				stat("/opt/nedge/nmf/etc/h2o.crt", &st) == 0) {
				log_info(lg, "Loading user s3 https key/cert from prod location");
				strcpy(httpsKey, "/opt/nedge/nmf/etc/h2o.key");
				strcpy(httpsCert, "/opt/nedge/nmf/etc/h2o.crt");
			} else {
				log_info(lg, "Loading default s3 https key/cert from prod location");
				strcpy(httpsKey, "/opt/nedge/nmf/etc/ccowgws3.key");
				strcpy(httpsCert, "/opt/nedge/nmf/etc/ccowgws3.crt");
			}
		} else {
			if (stat("/opt/nedge/src/nmf/etc/h2o.key", &st) == 0 &&
				stat("/opt/nedge/src/nmf/etc/h2o.crt", &st) == 0) {
				log_info(lg, "Loading user s3 https key/cert from dev location");
				strcpy(httpsKey, "/opt/nedge/src/nmf/etc/h2o.key");
				strcpy(httpsCert, "/opt/nedge/src/nmf/etc/h2o.crt");
			} else if (stat("/opt/nedge/src/nmf/etc/ccowgws3.key", &st) == 0 &&
			           stat("/opt/nedge/src/nmf/etc/ccowgws3.crt", &st) == 0) {
				log_info(lg, "Loading default s3 https key/cert from dev location");
				strcpy(httpsKey, "/opt/nedge/src/nmf/etc/ccowgws3.key");
				strcpy(httpsCert, "/opt/nedge/src/nmf/etc/ccowgws3.crt");
			} else {
				log_info(lg, "Loading user s3 https key/cert from etc/ssl location");
				strcpy(httpsKey, "/opt/nedge/etc/ssl/ssl.key");
				strcpy(httpsCert, "/opt/nedge/etc/ssl/ssl.crt");
			}
		}

		if (is_ssl && listener_setup_ssl(httpsCert, httpsKey, listener, host) != 0) {
			freeaddrinfo(res);
			return -1;
		}
		h2o_append_to_null_terminated_list((void *)&listener->hosts, hostconf);
	}

	/* release res */
	freeaddrinfo(res);
	return 0;
}

static void on_sigterm(int signo)
{
	if (shutdown_requested)
		return;
	log_error(lg, "terminating...");
	auth_destroy();
	shutdown_requested = 1;
	if (!h2o_barrier_done(&startup_sync_barrier)) {
		/* initialization hasn't completed yet, exit right away */
		exit(0);
	}
	notify_all_threads();
}

static void
setup_signal_handlers(void)
{
	h2o_set_signal_handler(SIGTERM, on_sigterm);
	h2o_set_signal_handler(SIGINT, on_sigterm);
	h2o_set_signal_handler(SIGPIPE, SIG_IGN);
}

static void
usage(const char *cmd)
{
	fprintf(stderr, "Usage: %s <-c name> <-t name> [opts] [<host>:]<port>\n"
	    "Options (required):\n"
	    "     -c, --cluster=name             cluster name space\n"
	    "     -t, --tenant=name              tenant within cluster name space\n"
	    "\n"
	    "Options (optional):\n"
	    "     -p, --proxy                    proxy server(e.g. http://127.0.0.1:9982)\n"
	    "     -S, --ssl_port=port            use specific SSL port\n"
	    "     -s, --subdomains               enable use of S3 subdomains\n"
	    "     -a, --auth                     S3 authentication on\n"
	    "     -l, --acl                      S3 acls on\n"
	    "     -r, --region=name              S3 region name\n",
	    cmd);
	exit(1);
}

static int
write_pidfile(char *pid_file, pid_t pid)
{
	FILE *file = fopen(pid_file, "w");
	if (!file) {
		fprintf(stderr, "Failed to open pid file! (%s)", pid_file);
		return 1;
	}

	fprintf(file, "%d", pid);
	fclose(file);

	return 0;
}

static pthread_mutex_t *crypto_mutexes;

static void
lock_callback(int mode, int n, const char *file, int line)
{
	if ((mode & CRYPTO_LOCK) != 0) {
		pthread_mutex_lock(crypto_mutexes + n);
	} else if ((mode & CRYPTO_UNLOCK) != 0) {
		pthread_mutex_unlock(crypto_mutexes + n);
	} else {
		assert(!"unexpected mode");
	}
}

static unsigned long
thread_id_callback(void)
{
	return (unsigned long)pthread_self();
}

static int
add_lock_callback(int *num, int amount, int type, const char *file, int line)
{
	(void)type;
	(void)file;
	(void)line;

	return __sync_add_and_fetch(num, amount);
}

H2O_NORETURN static void *
cache_cleanup_thread(void *_contexts)
{
	SSL_CTX **contexts = _contexts;

	while (1) {
		size_t i;
		for (i = 0; contexts[i] != NULL; ++i)
			SSL_CTX_flush_sessions(contexts[i], time(NULL));
		sleep(ssl_conf.lifetime / 4);
	}
}

static void
spawn_cache_cleanup_thread(SSL_CTX **_contexts, size_t num_contexts)
{
	/* copy the list of contexts */
	SSL_CTX **contexts = je_malloc(sizeof(*contexts) * (num_contexts + 1));
	h2o_memcpy(contexts, _contexts, sizeof(*contexts) * num_contexts);
	contexts[num_contexts] = NULL;

	/* launch the thread */
	pthread_t tid;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, 1);
	h2o_multithread_create_thread(&tid, &attr, cache_cleanup_thread, contexts);
}

static void
setup_cache_enable(SSL_CTX **contexts, size_t num_contexts, int async_resumption)
{
	size_t i;
	for (i = 0; i != num_contexts; ++i) {
		SSL_CTX_set_session_cache_mode(contexts[i], SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_AUTO_CLEAR);
		SSL_CTX_set_timeout(contexts[i], ssl_conf.lifetime);
		if (async_resumption)
			h2o_socket_ssl_async_resumption_setup_ctx(contexts[i]);
	}
	spawn_cache_cleanup_thread(contexts, num_contexts);
}

static void
setup_cache_internal(SSL_CTX **contexts, size_t num_contexts)
{
	setup_cache_enable(contexts, num_contexts, 0);
}

static int
update_tickets(session_ticket_vector_t *tickets, uint64_t now)
{
	int altered = 0, has_valid_ticket;

	/* remove old entries */
	while (tickets->size != 0) {
		struct st_session_ticket_t *oldest = tickets->entries[tickets->size - 1];
		if (now <= oldest->not_after)
			break;
		tickets->entries[--tickets->size] = NULL;
		free_ticket(oldest);
		altered = 1;
	}

	/* create new entry if necessary */
	has_valid_ticket = find_ticket_for_encryption(tickets, now) != NULL;
	if (!has_valid_ticket || (tickets->entries[0]->not_before + ssl_conf.lifetime / 4 < now)) {
		uint64_t not_before = has_valid_ticket ? now + 60 : now;
		struct st_session_ticket_t *ticket = new_ticket(ssl_conf.ticket.vars.generating.cipher, ssl_conf.ticket.vars.generating.md,
		    not_before, not_before + ssl_conf.lifetime - 1, 1);
		h2o_vector_reserve(NULL, tickets, tickets->size + 1);
		memmove(tickets->entries + 1, tickets->entries, sizeof(tickets->entries[0]) * tickets->size);
		++tickets->size;
		tickets->entries[0] = ticket;
		altered = 1;
	}

	return altered;
}

H2O_NORETURN static void *
ticket_internal_updater(void *unused)
{
	while (1) {
		pthread_rwlock_wrlock(&session_tickets.rwlock);
		update_tickets(&session_tickets.tickets, time(NULL));
		pthread_rwlock_unlock(&session_tickets.rwlock);
		/* sleep for certain amount of time */
		sleep(120 - (h2o_rand() >> 16) % 7);
	}
}

static void
init_openssl(void)
{
	int nlocks = CRYPTO_num_locks(), i;
	crypto_mutexes = h2o_mem_alloc(sizeof(*crypto_mutexes) * nlocks);
	for (i = 0; i != nlocks; ++i)
		pthread_mutex_init(crypto_mutexes + i, NULL);
	CRYPTO_set_locking_callback(lock_callback);
	CRYPTO_set_id_callback(thread_id_callback);
	CRYPTO_set_add_lock_callback(add_lock_callback);

	/* Dynamic locks are only used by the CHIL engine at this time */

	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	ssl_conf.cache.setup = setup_cache_internal;
	ssl_conf.ticket.update_thread = ticket_internal_updater;
	/* to protect the secret >>>2030 we need AES-256 (http://www.keylength.com/en/4/) */
	ssl_conf.ticket.vars.generating.cipher = EVP_aes_256_cbc();
	/* integrity checks are only necessary at the time of handshake, and sha256 (recommended by RFC 5077) is sufficient */
	ssl_conf.ticket.vars.generating.md = EVP_sha256();
	ssl_conf.lifetime = 3600; /* default value for session timeout is 1 hour */
}

int
main(int argc, char **argv)
{
	char *ccowlog = getenv("CCOW_LOG_STDOUT");
	static const struct option longopts[] = {
		{"ssl_port", required_argument, NULL, 'S'},
		{"cluster", required_argument, NULL, 'c'},
		{"tenant", required_argument, NULL, 't'},
		{"proxy", optional_argument, NULL, 'p'},
		{"subdomains", optional_argument, NULL, 's'},
		{"auth", optional_argument, NULL, 'a'},
		{"acl", optional_argument, NULL, 'l'},
		{"region", optional_argument, NULL, 'r'},
		{}
	};
	int opt_ch;
	h2o_hostconf_t *hostconf;
	int err;
	size_t i, j;
	struct addrinfo *hostport_ai = NULL;
	char *host, *port = NULL;
	char ssl_port[10] = { 0 };
	h2o_context_t ctx;
	char cluster[2048];
	char tenant[2048];
	char region[256];
	char proxy[256] = "http://127.0.0.1:9982";
	int subdomains = 0;
	int authOn = 0;
	int aclOn = 0;
	region[0] = 0;

	daemonize = (ccowlog && *ccowlog == '1') ? 0 : 1;


	cluster[0] = tenant[0] = 0;
	while ((opt_ch = getopt_long(argc, argv, "S:c:t:p:r:sal", longopts, NULL)) != -1) {
		switch (opt_ch) {
		case 'c':
			strcpy(cluster, optarg);
			break;
		case 't':
			strcpy(tenant, optarg);
			break;
		case 'p':
			strncpy(proxy, optarg, 255);
			break;
		case 'r':
			strncpy(region, optarg, 255);
			break;
		case 's':
			subdomains = 1;
			break;
		case 'a':
			authOn = 1;
			break;
		case 'l':
			aclOn = 1;
			break;
		case 'S':
			{
				int _ssl_port;
				if (sscanf(optarg, "%u", &_ssl_port) != 1 || _ssl_port > 65535) {
					fprintf(stderr, "SSL port (-S) must be a non-negative number in the range 0..65535\n");
					exit(1);
				}
				strcpy(ssl_port, optarg);
				break;
			}
		default:
			usage(argv[0]);
			break;
		}
	}

	if (argc == optind || !cluster[0] || !tenant[0]) {
		usage(argv[0]);
	} else {
		if (region[0] == 0) {
			strncpy(region, cluster, 255);
		}
		char *hostport = argv[optind], *colon;
		if ((colon = strchr(hostport, ':')) != NULL) {
			hostport = argv[optind];
			host = je_strdup(hostport);
			host[colon - hostport] = '\0';
			port = colon + 1;
		} else {
			host = "0.0.0.0";
			port = argv[optind];
		}
		if (!ssl_port[0]) {
			snprintf(ssl_port, 6, "%u", atoi(port) + 1);
		}
	}

	char *nedge_home = getenv("NEDGE_HOME");
	if (nedge_home)
		snprintf(pidfile, PATH_MAX, "%s/var/run/ccowhttpd.pid",
		    nedge_home);
	else
		snprintf(pidfile, PATH_MAX, "%s/var/run/ccowhttpd.pid",
		    QUOTE(INSTALL_PREFIX));

	struct stat st;
	if (stat(pidfile, &st) == 0) {
		FILE *fp = fopen(pidfile, "r");
		if (fp == NULL) {
			fprintf(stderr, "Daemon already running!\n");
			return 1;
		} else {
			int pid;
			int nread;
			char buf[PATH_MAX];

			nread = fscanf(fp, "%d", &pid);
			fclose(fp);
			sprintf(buf, "/proc/%d", pid);
			if (nread == 1 && stat(buf, &st) == 0) {
				fprintf(stderr, "Daemon already running!\n");
				return 1;
			}
		}
	}

	if (daemonize && daemon(1, 1)) {
		fprintf(stderr, "Failed to daemonize\n");
		return 1;
	}

	if (daemonize) {
		int write_pidfile_res = write_pidfile(pidfile, getpid());
		if (write_pidfile_res) {
			fprintf(stderr, "Failed to write pidfile\n");
			return 1;
		}
	}

	h2o_sem_init(&ocsp_updater_semaphore, H2O_DEFAULT_OCSP_UPDATER_MAX_THREADS);
	init_openssl();

	/* re-open logger after all forks are done */
	lg = Logger_create("ccowhttpd");
	auth_init();

	setpriority(PRIO_PROCESS, getpid(), -15);

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
				log_error(lg, "setrlimit returned result = %d errno = %d\n",
				    res, errno);
				exit(1);
			}
		}
	}

	log_info(lg, "proxy: %s", proxy);

	if (num_threads < h2o_numproc())
		num_threads = h2o_numproc();
	if (getenv("CCOW_EMBEDDED") && num_threads > NUM_THREADS_EMBEDDED)
		num_threads = NUM_THREADS_EMBEDDED;
	log_info(lg, "num_threads: %lu", num_threads);

	h2o_config_init(&gconfig);
	gconfig.http2.idle_timeout = 10 * 1000;
	gconfig.http1.req_timeout = 300 * 1000;
	gconfig.proxy.connect_timeout = 10 * 1000;
	gconfig.proxy.first_byte_timeout = 10 * 1000;
	gconfig.proxy.io_timeout = 300 * 1000;
	hostconf = h2o_config_register_host(&gconfig, h2o_iovec_init(H2O_STRLIT("default")), 65535);

	/* main handler */
	char pathconf_namespace[sizeof(cluster) + sizeof(tenant) + 1];
	sprintf(pathconf_namespace, "%s/%s", cluster, tenant);
	h2o_pathconf_t *pathconf = h2o_config_register_path(hostconf, "/", 0);
	ccowobj_handle = ccowobj_register(pathconf, pathconf_namespace, NULL,
			authOn, aclOn, region, subdomains, 0);

	/* what's not handled by main hander goes to slow-path proxy */
	h2o_url_t upstream;
	h2o_proxy_config_vars_t proxy_config = {};
	proxy_config.io_timeout = PROXY_CONFIG_IO_TIMEOUT;
	proxy_config.connect_timeout = PROXY_CONFIG_IO_TIMEOUT;
	proxy_config.first_byte_timeout = PROXY_CONFIG_IO_TIMEOUT;
	h2o_url_parse(proxy, strlen(proxy), &upstream);

	h2o_socketpool_target_t *targets[PROXY_SOCKET_PULL];
	for (int i = 0; i < PROXY_SOCKET_PULL; i++)
		targets[i] = h2o_socketpool_create_target(&upstream, NULL);
	h2o_socketpool_t *sockpool = je_malloc(sizeof(*sockpool));
	memset(sockpool, 0, sizeof(*sockpool));
	h2o_socketpool_init_specific(sockpool, SIZE_MAX, &targets[0], PROXY_SOCKET_PULL, NULL);
	h2o_socketpool_set_timeout(sockpool, PROXY_KEEPALIVE_TIMEOUT);
	h2o_socketpool_set_ssl_ctx(sockpool, NULL);
	h2o_proxy_register_reverse_proxy(pathconf, &proxy_config, sockpool);

	// h2o_access_log_register(&config.default_host, "/dev/stdout", NULL);

	setup_listener(hostconf, host, port, 0);
	setup_listener(hostconf, host, ssl_port, 1);

	/* initialize SSL_CTXs for session resumption and ticket-based resumption
	 * (also starts memcached client threads for the purpose) */
        H2O_VECTOR(SSL_CTX *) ssl_contexts = {NULL};
        for (i = 0; i != num_listeners; ++i) {
            for (j = 0; j != listeners_config[i]->ssl.size; ++j) {
                h2o_vector_reserve(NULL, &ssl_contexts, ssl_contexts.size + 1);
                ssl_contexts.entries[ssl_contexts.size++] = listeners_config[i]->ssl.entries[j]->ctx;
            }
        }
        ssl_setup_session_resumption(ssl_contexts.entries, ssl_contexts.size);
        je_free(ssl_contexts.entries);

	setup_signal_handlers();

	//pthread_create(&listcache_tid, NULL, listcache_loop, NULL);

	/* start the threads */
	threads = alloca(sizeof(threads[0]) * num_threads);
	h2o_barrier_init(&startup_sync_barrier, num_threads);
	pthread_t tids[num_threads];
	for (i = 1; i != num_threads; ++i) {
		h2o_multithread_create_thread(&tids[i], NULL, run_loop, (void *)i);
	}

	/* this thread becomes the first thread */
	run_loop((void *)0);

	for (i = 1; i != num_threads; ++i) {
		pthread_join(tids[i], NULL);
	}

	return 0;
}
