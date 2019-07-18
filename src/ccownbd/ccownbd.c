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
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <netinet/in.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <libgen.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <linux/nbd.h>
#include <limits.h>
#include <time.h>

#include "ccowutil.h"
#include "ccow.h"
#include "logger.h"
#include "queue.h"

Logger lg;
static struct ccownbd_info *g_ci = NULL;
static int nbd = 0;
static char *g_pidfile = NULL;
static int daemonize = 0;
static int ccownbd_op_cnt = 0;

#define CCOWNBD_BLKSIZE		4096
#define CCOWNBD_OP_CNT		512
#define CCOWNBD_CHUNK_SIZE_MAX	(8 * 1024 * 1024)

#define TIMER_INTERVAL		15

pthread_mutex_t timer_lck = PTHREAD_MUTEX_INITIALIZER;
pthread_t timer_thread;
pthread_cond_t timer_cv = PTHREAD_COND_INITIALIZER;

struct ccownbd_info {
	ccow_t tctx;
	uint32_t chunk_size;
	size_t size;
	char cid[2048], tid[2048], bid[2048], oid[2048];
	size_t cid_size, tid_size, bid_size, oid_size;
	ccow_completion_t c;
	int io_count;
	uint64_t genid;
	int writes;
};

struct ccownbd_chunk_context {
	char ma_bufs[2 * CCOWNBD_CHUNK_SIZE_MAX];
	uint64_t s0;
	uint64_t s1;
	uint64_t s2;
	size_t l0;
	size_t l1;
	size_t l2;
	char *buf;
};

#ifdef WORDS_BIGENDIAN
#define ntohll(a) (a)
#else
static inline uint64_t
ntohll(uint64_t a) {
	u_int32_t lo = a & 0xffffffff;
	u_int32_t hi = a >> 32U;
	lo = ntohl(lo);
	hi = ntohl(hi);
	return ((u_int64_t) lo) << 32U | hi;
}
#endif
#define htonll ntohll

static int ccownbd_finalize(struct ccownbd_info *, int flush);

void *
timer_func(void * arg)
{
	int err;
	struct timespec to;
	struct ccownbd_info * ci = arg;

	do {
		if (!ci) {
			pthread_exit(NULL);
			return NULL;
		}
		err = pthread_mutex_lock(&timer_lck);
		assert(err == 0);

		to.tv_sec = time(NULL) + TIMER_INTERVAL;
		to.tv_nsec = 0;

		err = pthread_cond_timedwait(&timer_cv, &timer_lck, &to);
		if (err == ETIMEDOUT) {
			/* only flush new version if LUN was trully idle */
			int need_flush = ci->writes > 0;
			if (need_flush)
				log_debug(lg, "Timer finalize flush");
			err = ccownbd_finalize(ci, need_flush);
			if (err != 0) {
				/* ccownbd should have logged errors. */
				break;
			}
			if (need_flush)
				ci->writes = 0;
		} else {
			break;
		}

		err = pthread_mutex_unlock(&timer_lck);
		assert(err == 0);
	} while (1);

	err = pthread_mutex_unlock(&timer_lck);
	assert(err == 0);

	pthread_exit(NULL);
}

int
nbd_check_conn(char* devname) {
	char buf[256];
	char* p;
	int fd, i;

	if (!strncmp(devname, "/dev/", 5))
		devname += 5;

	if ((p=strchr(devname, 'p')))
		*p='\0';

	snprintf(buf, 256, "/sys/block/%s/pid", devname);

	if ((fd = open(buf, O_RDONLY)) < 0) {
		if (errno == ENOENT) {
			return 1;
		} else {
			return 2;
		}
	}
	i = read(fd, buf, 256);
	assert(i != -1);
	close(fd);
	return 0;
}

static int
nbd_read(int fd, char* buf, size_t total)
{
	int bytes;
	size_t cnt = total;

	while (cnt > 0) {
		bytes = read(fd, buf, cnt);
		if (bytes < 1)
			return -errno;
		buf += bytes;
		cnt -= bytes;
	}
	assert(cnt == 0);

	return 0;
}

static int
nbd_write(int fd, char* buf, size_t total)
{
	int written;
	size_t cnt = total;

	while (cnt > 0) {
		written = write(fd, buf, cnt);
		if (written < 1)
			return -errno;
		buf += written;
		cnt -= written;
	}
	assert(cnt == 0);

	return 0;
}

static int
ccownbd_chunk(struct ccownbd_info *ci, uint64_t offset,  char *buf,
    size_t length, struct iovec **iov, size_t *iovcnt, int write,
    struct ccownbd_chunk_context *ch_ctx)
{
	int err = 0;
	uint64_t s0 = 0, s1 = 0, s2 = 0;
	size_t l0 = 0, l1 = 0, l2 = 0;
	size_t t = 0;
	size_t cnt = 0;
	size_t iov_idx = 0;

	uint64_t mask = ci->chunk_size;
	mask--;

	/*
	 * start and length of region 0. this is the unaligned region at the
	 * beginning of the request.  length may be zero if the offset is
	 * page aligned.
	 */

	log_debug(lg, "offset = %"PRIx64" : mask = %"PRIx64" : chunk_size = %d",
	    offset, mask, ci->chunk_size);

	s0 = offset & mask;

	if (s0 == 0) {
		l0 = 0;
	} else {
		if (ci->chunk_size - s0 < length) {
			l0 = ci->chunk_size - s0;
		} else {
			l0 = length;
		}

		t += l0;
	}

	/*
	 * start and length of region 1. this is the aligned region in the
	 * middle of the request. length may be zero.
	 */
	s1 = s0 + l0;
	if (t < length) {
		l1 = (length - l0) & ~(mask);
		t += l1;
	}

	/*
	 * start and length of region 2. this is the sub-page sized region at
	 * the end of the request.
	 */
	s2 = s1 + l1;
	if (t < length) {
		l2 = length - t;
	}

	ch_ctx->s0 = s0;
	ch_ctx->s1 = s1;
	ch_ctx->s2 = s2;
	ch_ctx->l0 = l0;
	ch_ctx->l1 = l1;
	ch_ctx->l2 = l2;
	ch_ctx->buf = buf;

	log_debug(lg, "s0 : 0x%"PRIx64, s0);
	log_debug(lg, "s1 : 0x%"PRIx64, s1);
	log_debug(lg, "s2 : 0x%"PRIx64, s2);
	log_debug(lg, "l0 : 0x%"PRIx64, l0);
	log_debug(lg, "l1 : 0x%"PRIx64, l1);
	log_debug(lg, "l2 : 0x%"PRIx64, l2);

	if (write) {
		/*
		 * initialize io vector
		 */
		cnt = l1 / ci->chunk_size;
		if (l0 > 0) cnt++;
		if (l2 > 0) cnt++;

		struct iovec *v = je_calloc(cnt, sizeof (struct iovec));
		if (v == NULL) {
			*iovcnt = 0;
			return -ENOMEM;
		}

		/*
		 * writes may require read/modify/write on unaligned pages
		 */
		if (l0 > 0) {
			struct iovec iov = {
				.iov_base = &ch_ctx->ma_bufs[0],
				.iov_len  = ci->chunk_size
			};

			err = ccow_get_cont(ci->c, &iov, 1,
			    offset & ~(mask), 1, &ci->io_count);
			if (err != 0) {
				log_error(lg, "failed to create CCOW get: %d",
				    err);
				return err;
			}

			err = ccow_wait(ci->c, ci->io_count);
			if (err != 0) {
				log_error(lg, "failed to create CCOW get wait:"
				    " %d", err);
				return err;
			}

			memcpy(&ch_ctx->ma_bufs[0] + s0, buf, l0);

			v[iov_idx].iov_base = &ch_ctx->ma_bufs[0];
			v[iov_idx++].iov_len = ci->chunk_size;
		}

		if (l2 > 0) {
			struct iovec iov = {
				.iov_base = &ch_ctx->ma_bufs[ci->chunk_size],
				.iov_len  = ci->chunk_size
			};

			err = ccow_get_cont(ci->c, &iov, 1, offset + l0 + l1,
			    1, &ci->io_count);
			if (err != 0) {
				log_error(lg, "failed to create CCOW get2: %d",
				    err);
				return err;
			}

			err = ccow_wait(ci->c, ci->io_count);
			if (err != 0) {
				log_error(lg, "failed to create CCOW get wait2:"
				    " %d", err);
				return err;
			}

			memcpy(&ch_ctx->ma_bufs[ci->chunk_size],
			    buf + l0 + l1, l2);

			v[iov_idx + l1/ci->chunk_size].iov_base =
				&ch_ctx->ma_bufs[ci->chunk_size];
			v[iov_idx + l1/ci->chunk_size].iov_len = ci->chunk_size;
		}

		char *base = buf + l0;

		while (l1 > 0) {
			v[iov_idx].iov_base = base;
			v[iov_idx].iov_len = ci->chunk_size;

			base += ci->chunk_size;
			iov_idx++;
			l1 -= ci->chunk_size;
		}

		*iov = v;
		*iovcnt = cnt;
	} else {

		cnt = l1 / ci->chunk_size;
		if (l0 > 0) cnt++;
		if (l2 > 0) cnt++;

		/*
		 * reads may require alignnent adjustment for unaligned pages
		 */
		struct iovec *v = je_calloc(cnt, sizeof (struct iovec));
		if (l0 > 0) {
			v[iov_idx].iov_base = &ch_ctx->ma_bufs[0];
			v[iov_idx++].iov_len = ci->chunk_size;
		}

		if (l2 > 0) {
			v[iov_idx + l1/ci->chunk_size].iov_base =
				&ch_ctx->ma_bufs[ci->chunk_size];
			v[iov_idx + l1/ci->chunk_size].iov_len = ci->chunk_size;
		}

		char *base = buf + l0;

		while (l1 > 0) {
			v[iov_idx].iov_base = base;
			v[iov_idx].iov_len = ci->chunk_size;

			base += ci->chunk_size;
			iov_idx++;
			l1 -= ci->chunk_size;
		}

		*iov = v;
		*iovcnt = cnt;
	}

	return err;
}

static int
ccownbd_finalize(struct ccownbd_info *ci, int flush)
{
	int err;
	int flags;

	/* not ready yet, can be called from timer */
	if (!ci->c)
		return 0;

	if (flush) {
		/* reset ephemeral flag */
		flags = 0;
		ccow_stream_flags(ci->c, &flags);
		flags &= ~CCOW_CONT_F_EPHEMERAL;
		ccow_stream_flags(ci->c, &flags);
	}
	err = ccow_finalize(ci->c, NULL);
	if (err) {
		log_error(lg, "cannot cleanly finalize stream: %d", err);
		return err;
	}

	ci->io_count = 0;

	flags = CCOW_CONT_F_EPHEMERAL;
	err = ccow_create_stream_completion(ci->tctx, NULL,
	    NULL, ccownbd_op_cnt, &ci->c, ci->bid,
	    ci->bid_size, ci->oid, ci->oid_size, &ci->genid, &flags, NULL);
	if (err) {
		log_error(lg, "cannot cleanly create new stream: %d", err);
		return err;
	}

	return 0;
}

static int
ccownbd_open(struct ccownbd_info *ci, const char *uri, const char *devfile,
    uint64_t *size)
{
	int err;

	if (sscanf(uri, "%2047[^/]/%2047[^/]/%2047[^/]/%2047[^\n]",
		    ci->cid, ci->tid, ci->bid, ci->oid) < 4) {
		log_error(lg, "open error: wrong ccowbd backing store format");
		return -1;
	}
	ci->cid_size = strlen(ci->cid) + 1;
	ci->tid_size = strlen(ci->tid) + 1;
	ci->bid_size = strlen(ci->bid) + 1;
	ci->oid_size = strlen(ci->oid) + 1;

	int ccow_fd = open("/opt/nedge/etc/ccow/ccow.json", O_RDONLY);
	if (ccow_fd < 0) {
		log_error(lg, "ccow.json open error [%d]: %s", -errno,
		    strerror(errno));
		return -errno;
	}

	char buf[16384];
	err = read(ccow_fd, buf, 16383);
	if (err < 0) {
		log_error(lg, "ccow.json read error [%d]: %s", -errno,
		    strerror(errno));
		close(ccow_fd);
		return -errno;
	}
	close(ccow_fd);
	buf[err] = 0;

	err = ccow_tenant_init(buf, ci->cid, ci->cid_size, ci->tid,
	    ci->tid_size, &ci->tctx);
	if (err) {
		log_error(lg, "ccow_tenant_init error: %d", err);
		return err;
	}

	ccow_completion_t c;
	err = ccow_create_completion(ci->tctx, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "ccow_create_completion error on init: %d", err);
		return err;
	}

	ccow_lookup_t iter;
	err = ccow_get(ci->bid, ci->bid_size, ci->oid, ci->oid_size, c, NULL,
	    0, 0, &iter);
	if (err) {
		ccow_release(c);
		log_error(lg, "ccow_get error on init: %d", err);
		return err;
	}

	err = ccow_wait(c, -1);
	if (err) {
		if (iter)
			ccow_lookup_release(iter);
		log_error(lg, "ccow_wait error on init: %d", err);
		return err;
	}

	*size = 0;
	ci->chunk_size = 0;
	struct ccow_metadata_kv *kv = NULL;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_CUSTOM |
			    CCOW_MDTYPE_METADATA, -1))) {
		if (strcmp(kv->key, "X-volsize") == 0) {
			ccow_iterator_kvcast(CCOW_KVTYPE_UINT64, kv, size);
		} else if (strcmp(kv->key, RT_SYSKEY_CHUNKMAP_CHUNK_SIZE) == 0) {
			ccow_iterator_kvcast(CCOW_KVTYPE_UINT32, kv,
			    &ci->chunk_size);
		}
	}
	ccow_lookup_release(iter);

	char setbuf[128];
	sprintf(setbuf, "echo %d > /sys/block/%s/queue/max_sectors_kb",
	    512, basename((char *)devfile));
	err = system(setbuf);
	if (err) {
		log_error(lg, "error while executing: %s", setbuf);
		return -EBADF;
	}

	if (!*size) {
		log_error(lg, "attribute X-volsize not found on init");
		return -EBADF;
	}

	if (!ci->chunk_size || (ci->chunk_size % 512 != 0) ||
	    ci->chunk_size > CCOWNBD_CHUNK_SIZE_MAX) {
		log_error(lg, "attribute %s not found or incorrect (%d) on init",
		    RT_SYSKEY_CHUNKMAP_CHUNK_SIZE, ci->chunk_size);
		return -EBADF;
	}

	ci->size = *size;
	ci->io_count = 0;
	ci->genid = 0;

	uint16_t tracker = 1;
	err = ccow_attr_modify_default(c, CCOW_ATTR_TRACK_STATISTICS,
	    (uint16_t *)&tracker, NULL);
	if (err) {
		log_error(lg, "error while setting md for tracking");
		return -EBADF;
	}

	int flags = CCOW_CONT_F_EPHEMERAL;
	err = ccow_create_stream_completion(ci->tctx, NULL, NULL,
	    ccownbd_op_cnt, &ci->c, ci->bid, ci->bid_size, ci->oid,
	    ci->oid_size, &ci->genid, &flags, NULL);
	if (err) {
		log_error(lg, "cannot initialize stream on init: %d", err);
		return err;
	}

	return 0;
}

static void
ccownbd_close(struct ccownbd_info *ci)
{
	int err = -EBADF;

	if (!nbd || !ci->c)
		return;

	ioctl(nbd, NBD_CLEAR_QUE);
	ioctl(nbd, NBD_CLEAR_SOCK);

	if (ci == NULL || ci->c == NULL) {
		log_error(lg, "Invalid ccownbd descriptors: %d", err);
		return;
	}

	err = ccow_finalize(ci->c, NULL);
	if (err) {
		log_warn(lg, "cannot finalize stream on close: %d", err);
	}

	ccow_tenant_term(ci->tctx);
	ci->tctx = NULL;
}

static int
ccownbd_read(struct ccownbd_info *ci, void *buf, uint32_t length,
    uint64_t offset)
{
	int err;
	struct ccownbd_chunk_context ch_ctx;
	struct iovec *iov = NULL;
	size_t iovcnt;

	err = pthread_mutex_lock(&timer_lck);
	assert(err == 0);

	uint64_t mask = ci->chunk_size;
	mask--;

	err = ccownbd_chunk(ci, offset, buf, length, &iov, &iovcnt, 0, &ch_ctx);
	if (err) {
		log_error(lg, "read bs_ccowbd_chunk returned error: %d", err);
		goto _finalize;
	}

	err = ccow_get_cont(ci->c, iov, iovcnt, offset & (~mask), 1,
	    &ci->io_count);
	if (err) {
		log_error(lg, "get error on I/O submit: %d", err);
		goto _finalize;
	}

	err = ccow_wait(ci->c, ci->io_count);
	if (err != 0) {
		log_error(lg, "get error on CCOW wait: %d", err);
		goto _finalize;
	}

	if (ch_ctx.l0 > 0) {
		char *base = iov[0].iov_base + ch_ctx.s0;
		memcpy(ch_ctx.buf, base, ch_ctx.l0);
	}

	if (ch_ctx.l2 > 0) {
		char *base = iov[iovcnt - 1].iov_base;
		memcpy(ch_ctx.buf + ch_ctx.l0 + ch_ctx.l1,
		    base, ch_ctx.l2);
	}

	je_free(iov);
	iov = NULL;

	pthread_mutex_unlock(&timer_lck);

	return 0;

_finalize:;
	if (iov != NULL) {
		je_free(iov);
		iov = NULL;
	}

	int ferr = ccownbd_finalize(ci, 0);
	pthread_mutex_unlock(&timer_lck);

	if (ferr)
		return ferr;
	return err;
}

static int
ccownbd_write(struct ccownbd_info *ci, void *buf, uint32_t length,
    uint64_t offset)
{
	int err;
	struct ccownbd_chunk_context ch_ctx;
	struct iovec *iov = NULL;
	size_t iovcnt;

	uint64_t mask = ci->chunk_size;
	mask--;

	err = pthread_mutex_lock(&timer_lck);
	assert(err == 0);

	err = ccownbd_chunk(ci, offset, buf, length, &iov, &iovcnt, 1, &ch_ctx);
	if (err) {
		log_error(lg, "write bs_ccowbd_chunk returned error: %d", err);
		goto _finalize;
	}

	err = ccow_put_cont(ci->c, iov, iovcnt, offset & ~(mask), 1,
	    &ci->io_count);
	if (err) {
		log_error(lg, "put error on I/O submit: %d", err);
		goto _finalize;
	}

	err = ccow_wait(ci->c, ci->io_count);
	if (err != 0) {
		log_error(lg, "put error on CCOW wait: %d", err);
		goto _finalize;
	}

	je_free(iov);
	iov = NULL;

	pthread_mutex_unlock(&timer_lck);

	return 0;

_finalize:;
	if (iov != NULL) {
		je_free(iov);
		iov = NULL;
	}

	int ferr = ccownbd_finalize(ci, 0);
	pthread_mutex_unlock(&timer_lck);
	if (ferr)
		return ferr;
	return err;
}

static void
signal_handler(int signum)
{
	static int terminating = 0;

	if (terminating) {
		log_warn(lg, "Received signal [%s] while exiting! Ignoring..",
		    strsignal(signum));
		return;
	}


	if (signum == SIGHUP) {
		Logger_hup(lg);

		if (g_ci != NULL) {
			ccow_stats_t stats;
			int rv = ccow_get_stats(g_ci->tctx, &stats);

			if (rv == 0) {
				ccow_print_stats(stats);
			}
		}

		return;
	}

	if (signum == SIGABRT || signum == SIGSEGV) {
		log_flush(lg);
		signal(signum, SIG_DFL);
		raise(signum);
		return;
	}

	terminating = 1;
	log_error(lg, "Received signal [%s]! Terminating..", strsignal(signum));

	void * rv;
	pthread_cond_signal(&timer_cv);
	pthread_join(timer_thread, &rv);

	if (g_ci && g_ci->tctx) {
		ccownbd_close(g_ci);
		if (g_pidfile)
			unlink(g_pidfile);
	}

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
nbd_start(struct ccownbd_info *ci, const char *objpath, const char *devfile,
    long int devnum)
{
	int sv[2];
	int sk, err;
	struct nbd_request request;
	struct nbd_reply reply;
	ssize_t bytes;

	err = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	if (err) {
		fprintf(stderr, "socketpair failed [%d]: %s", -errno,
		    strerror(errno));
		return -errno;
	}

	nbd = open(devfile, O_RDWR);
	if (nbd == -1) {
		fprintf(stderr, "%s: open failed [%d]: %s", devfile, -errno,
		    strerror(errno));
		return -errno;
	}

	if (ioctl(nbd, NBD_CLEAR_SOCK) == -1) {
		fprintf(stderr, "ioctl NBD_CLEAR_SOCK failed [%d]: %s", -errno,
		    strerror(errno));
		close(nbd);
		return -errno;
	}

	/* kernel bug: need to open/close on start to refresh part table */
	int refresh_pid;
	if (!(refresh_pid = fork())) {
		/* child */
		close(nbd);
		if (fork() > 0)
			exit(0);
		/* grandchild */
		usleep(250000);
		while (nbd_check_conn((char *)devfile))
			usleep(250000);
		open(devfile, O_RDONLY);
		exit(0);
	} else if (refresh_pid != -1) {
		int status;
		wait(&status);
	} else {
		fprintf(stderr, "ioctl NBD_CLEAR_SOCK failed [%d]: %s", -errno,
		    strerror(errno));
		close(nbd);
		return -errno;
	}

	if (!fork()) {
		/* child */
		close(sv[0]);
		sk = sv[1];

		if (ioctl(nbd, NBD_SET_SOCK, sk) == -1) {
			fprintf(stderr, "ioctl NBD_SET_SOCK failed [%d]: %s",
			    -errno, strerror(errno));
		} else if (ioctl(nbd, NBD_SET_FLAGS, NBD_FLAG_SEND_TRIM) == -1) {
			fprintf(stderr, "ioctl NBD_SET_FLAGS failed [%d]: %s",
			    -errno, strerror(errno));
		} else if (ioctl(nbd, NBD_SET_FLAGS, NBD_FLAG_SEND_FLUSH) == -1) {
			fprintf(stderr, "ioctl NBD_SET_FLAGS failed [%d]: %s",
			    -errno, strerror(errno));
		} else {
			err = ioctl(nbd, NBD_DO_IT);
			if (err != -1)
				fprintf(stderr, "nbd device %s terminated with "
				    "code %d", devfile, err);
		}

		ioctl(nbd, NBD_CLEAR_QUE);
		ioctl(nbd, NBD_CLEAR_SOCK);

		exit(0);
	}

	if (daemonize) {
		int std_fd;
		if ((std_fd = open("/dev/null", O_RDWR, 0)) != -1) {
			dup2(std_fd, STDIN_FILENO);
			dup2(std_fd, STDOUT_FILENO);
			dup2(std_fd, STDERR_FILENO);
			if (std_fd > STDERR_FILENO)
				close(std_fd);
		}
	}

	/* re-open logger after all forks are done */
	char logname[32];
	sprintf(logname, "ccownbd%ld", devnum);
	lg = Logger_create(logname);

	signal(SIGPIPE, SIG_IGN);       // Ignore SIG_IGN
	signal(SIGHUP, signal_handler);
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	uint64_t size;
	err = ccownbd_open(ci, objpath, devfile, &size);
	if (err) {
		close(nbd);
		return err;
	}

	if (ioctl(nbd, NBD_SET_BLKSIZE, CCOWNBD_BLKSIZE) == -1) {
		log_error(lg, "ioctl NBD_SET_BLKSIZE failed [%d]: %s", -errno,
		    strerror(errno));
		close(nbd);
		return -errno;
	}

	if (ioctl(nbd, NBD_SET_SIZE_BLOCKS, ci->size / CCOWNBD_BLKSIZE) == -1) {
		log_error(lg, "ioctl NBD_SET_SIZE_BLOCKS failed [%d]: %s",
		    -errno, strerror(errno));
		close(nbd);
		return -errno;
	}

	close(sv[1]);
	sk = sv[0];

	reply.magic = htonl(NBD_REPLY_MAGIC);
	reply.error = htonl(0);

	while ((bytes = read(sk, &request, sizeof (request))) > 0) {
		void *chunk;

		assert(bytes == sizeof (request));
		memcpy(reply.handle, request.handle, sizeof (reply.handle));

		uint32_t len = ntohl(request.len);
		uint64_t from = ntohll(request.from);
		assert(request.magic == htonl(NBD_REQUEST_MAGIC));

		/*
		 * We account for chunking generated I/O, which can be up to 3
		 */
		if (ci->io_count >= ccownbd_op_cnt - 6) {
			log_debug(lg, "FINALIZING on SUBMIT");
			pthread_mutex_lock(&timer_lck);
			err = ccownbd_finalize(ci, 0);
			pthread_mutex_unlock(&timer_lck);
			if (err)
				return err;
		}

		log_debug(lg, "chunk_size = 0x%x : blk_size = 0x%x",
		    ci->chunk_size, CCOWNBD_BLKSIZE);

		switch(ntohl(request.type)) {
		case NBD_CMD_READ:
			log_debug(lg, "Request for read of size %d", len);
			chunk = je_malloc(len);
			reply.error = ccownbd_read(ci, chunk, len, from);
			nbd_write(sk, (char*)&reply, sizeof (struct nbd_reply));
			if(reply.error == 0)
				nbd_write(sk, (char*)chunk, len);
			je_free(chunk);
			break;
		case NBD_CMD_WRITE:
			log_debug(lg, "Request for write of size %d", len);
			chunk = je_malloc(len);
			nbd_read(sk, chunk, len);
			reply.error = ccownbd_write(ci, chunk, len, from);
			ci->writes++;
			je_free(chunk);
			nbd_write(sk, (char*)&reply, sizeof (struct nbd_reply));
			break;
		case NBD_CMD_DISC:
			log_debug(lg, "Disconnect request");
			return 0;
		case NBD_CMD_FLUSH:
			log_debug(lg, "NBD flush request");
			pthread_mutex_lock(&timer_lck);
			reply.error = ccownbd_finalize(ci, 1);
			ci->writes = 0;
			pthread_mutex_unlock(&timer_lck);
			if (reply.error)
				return reply.error;
			nbd_write(sk, (char*)&reply, sizeof (struct nbd_reply));
			break;
		case NBD_CMD_TRIM:
			log_debug(lg, "Trim request");
			reply.error = 0; /* nothing to do */
			nbd_write(sk, (char*)&reply, sizeof (struct nbd_reply));
			break;
		default:
			assert(0);
		}
	}
	if (bytes == -1)
		log_error(lg, "Read failed [%d]: %s", -errno, strerror(errno));

	return 0;
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

int
main(int argc, char *argv[])
{
	int err;
	char *ccowlog = getenv("CCOW_LOG_STDOUT");
	char *ccownbd_op_cnt_env = getenv("CCOWNBD_OP_CNT");
	char pidfile[PATH_MAX];
	char devfile[PATH_MAX];
	char *objpath = argv[1];
	char *pdevnum = argv[2];

	daemonize = (ccowlog && *ccowlog == '1') ? 0 : 1;
	ccownbd_op_cnt = ccownbd_op_cnt_env ?
		strtol(ccownbd_op_cnt_env, NULL, 10) : CCOWNBD_OP_CNT;

	if (argc != 3) {
		printf("Usage: ccownbd <objpath> <devnum>\n");
		return -1;
	}

	long int devnum = strtol(pdevnum, NULL, 10);
	if ((errno == ERANGE && (devnum == LONG_MAX || devnum == LONG_MIN))
	    || (errno != 0 && devnum == 0) || devnum < 0 || devnum >= 4096) {
		fprintf(stderr, "Wrong devnum '%s' argument!\n", pdevnum);
		return 1;
	}
	sprintf(devfile, "/dev/nbd%ld", devnum);

	char *nedge_home = getenv("NEDGE_HOME");
	if (nedge_home)
		snprintf(pidfile, PATH_MAX, "%s/var/run/ccownbd%ld.pid",
		    nedge_home, devnum);
	else
		snprintf(pidfile, PATH_MAX, "%s/var/run/ccownbd%ld.pid",
		    QUOTE(INSTALL_PREFIX), devnum);

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

	int write_pidfile_res = write_pidfile(pidfile, getpid());
	if (write_pidfile_res) {
		fprintf(stderr, "Failed to write pidfile\n");
		return 1;
	}

	setpriority(PRIO_PROCESS, getpid(), -15);

	struct ccownbd_info ci;
	g_ci = &ci;
	g_pidfile = pidfile;

	err = pthread_create(&timer_thread, NULL, timer_func, g_ci);
	if (err != 0) {
		int e = errno;
		printf("pthread_create returned error %d.\n", e);
		printf("\"%s\".\n", strerror(e));
		return -1;
	}

	/* temporarily close logger */
	err = nbd_start(&ci, objpath, devfile, (int)devnum);

	/* ci.tctx will be set in nbd_start() on succcessful ccownbd init */
	if (ci.tctx) {
		/* Normally we exit on SIGTERM. This is error case.
		 * Stop timer thread on error */
		void * rv;
		pthread_cond_signal(&timer_cv);
		pthread_join(timer_thread, &rv);

		ccownbd_close(&ci);
	}

	if (daemonize)
		unlink(pidfile);
	return err;
}
