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
#include <uv.h>
#include "ccow.h"
#include "ccow-impl.h"

void chid_cb(rtbuf_t *rb, void *cb_data)
{
	struct ccow_io *get_io = (struct ccow_io *)cb_data;
	get_io->cm_reflist = rb;
}

static void
ccow_namedget_done(struct getcommon_client_req *r)
{
	int err;
	struct ccow_io *get_io = (struct ccow_io *)r->io;
	struct ccow_op *op = get_io->op;
	struct ccow_lookup *iter = op->iter;
	struct ccow_completion *c = get_io->comp;
	struct ccow_op *cont_op = get_io->op;

	log_trace(lg, "r %p: %s, status %d iovcnt_in %ld",
		r, ccow_op2str(op->optype),
	    op->status, op->iovcnt_in);

	/* get out on error */
	if (op->status != 0) {
		ccow_release(c);
		return;
	}

	/* no need to traverse chunks */
	if (!op->iovcnt_in)
		return;

	/* EC recovery might require VM chid */
	op->vmchid = r->chid;

	op->chm = chunkmap_find(op->metadata.chunkmap_type);
	if (!op->chm) {
		log_error(lg, "Cannot find metadata chunkmap_type %s",
		    op->metadata.chunkmap_type);
		ccow_fail_io(get_io, -EBADF);
		ccow_release(c);
		return;
	}

	assert(!op->chm_handle);
	err = op->chm->create(op, NULL, NULL, &op->chm_handle);
	if (err) {
		log_error(lg, "Cannot create CHM handle of type %s",
		    op->metadata.chunkmap_type);
		ccow_fail_io(get_io, err);
		ccow_release(c);
		return;
	}

	err = op->chm->traverse(op->chm_handle, cont_op, op->traverse_cb, get_io);
	if (err) {
		/*
		 * Libchunk may return -ENOENT as an indication of not-found
		 * case, so we do not log it as an error here and let upper
		 * layer decide
		 */
		if (err != -ENOENT)
			log_error(lg, "Error (%d) while traversing CHM of type %s",
			    err, op->metadata.chunkmap_type);
		ccow_fail_io(get_io, err);
		op->chm->destroy(op->chm_handle);
		op->chm_handle = NULL;
		ccow_release(c);
		return;
	}

	/*
	 * At this point I/O pipe line can execute chunkmap created
	 * I/Os if any... See ccow_compete_io() for details.
	 */
}

struct unnamedget_cont_req {
	struct ccow *tc;
	struct ccow_io *io;
};

CCOW_EI_TAG_DEFINE(unnamedget_cont__init, 5);

static void
unnamedget_cont__init(struct state *st)
{
	int err;
	struct unnamedget_cont_req *r = st->data;
	struct ccow_io *io = r->io;
	struct ccow_completion *c = io->comp;
	struct ccow_op *op = c->init_op;

	log_trace(lg, "st %p", st);

#if CCOW_EI
	CCOW_EI_TAG_INC(unnamedget_cont__init, err, 912);

	if (err != 0) {
		log_debug(lg, "Inserting error %d in unnamedget_cont__init", err);
		state_next(st, EV_ERR);
		return;
	}
#endif

	err = op->chm->traverse(op->chm_handle, io->cont_op, op->traverse_cb, io);
	if (err) {
		state_next(st, EV_ERR);
		return;
	}

	ccow_io_lock(io);
	if (QUEUE_EMPTY(&io->p_queue)) {
		state_override(st, ST_READY);
	} else {
		while (!QUEUE_EMPTY(&io->p_queue)) {
			QUEUE *q = QUEUE_HEAD(&io->p_queue);
			struct ccow_io *cio = QUEUE_DATA(q, struct ccow_io, p_item);

			err = ccow_start_io(cio);
			if (err) {
				ccow_io_unlock(io);
				state_next(st, EV_ERR);
				return;
			}

			QUEUE_REMOVE(q);
			QUEUE_INIT(q);
			QUEUE_INSERT_TAIL(&io->p_busy_queue, &cio->p_item);
		}
	}
	ccow_io_unlock(io);

	state_next(st, EV_DONE);
}

static void
unnamedget_cont__term(struct state *st)
{
	struct unnamedget_cont_req *r = st->data;

	log_trace(lg, "st %p", st);

	ccow_complete_io((struct ccow_io *)st);
}

/*
 * Initiate CCOW_GET_CONT
 *
 * Scope: PUBLIC
 */
int
ccow_get_cont_helper(struct ccow_completion *c, struct iovec *iov,
    size_t iovcnt, uint64_t off, int need_wait, int *index,
    struct iovec * seq_iov_in, size_t seq_iovcnt_in)
{
	int err;

	if (!c->init_op) {
		log_error(lg, "ccow_get_cont called on uninitialized ccow_completion, "
		    "c->init_op = NULL");
		return -EINVAL;
	}

	struct ccow_op *op = c->init_op;
	struct ccow *tc = c->tc;
	int is_btree_map = memcmp_quick(op->metadata.chunkmap_type, strlen(op->metadata.chunkmap_type),
	    RT_SYSVAL_CHUNKMAP_BTREE, strlen(RT_SYSVAL_CHUNKMAP_BTREE)) == 0;

	if (is_btree_map && (off % (uint64_t)op->metadata.chunkmap_chunk_size) != 0) {
		log_error(lg, "Chunks start offset %lu isn't chunk size %u aligned (ignored)",
		    off, op->metadata.chunkmap_chunk_size);
	}

	for (size_t i = 0; i < iovcnt; i++) {
		/* check against object's current chunk size, except the last one */
		if (is_btree_map && i + 1 < iovcnt && iov[i].iov_len != op->metadata.chunkmap_chunk_size) {
			log_error(lg, "Chunk idx=%ld buffer length %lu isn't chunk size %u aligned (ignored)",
			    i, iov[i].iov_len, op->metadata.chunkmap_chunk_size);
		}
		if (iov[i].iov_len > REPLICAST_CHUNK_SIZE_MAX) {
			log_error(lg, "Chunk size %lu too big, idx=%ld",
			    iov[i].iov_len, i);
			return -E2BIG;
		}
	}

	tc->stats.ccow.get_conts++;

	/* cannot be called from tenant's event loop context! */
	nassert(tc->loop_thrid != uv_thread_self());

	if (c->status != 0) {
		log_error(lg, "ccow_get_cont called on invalid ccow_completion, "
		    "c->status = %d", c->status);
		return -EINVAL;
	}

	uv_mutex_lock(&c->operations_mutex);
	if (op->completed || op->finalizing) {
		log_error(lg, "ccow_get_cont gets called after init operation "
		    "completed (%d) or finalizing (%d)",
		    op->completed, op->finalizing);
		uv_mutex_unlock(&c->operations_mutex);
		return -EINVAL;
	}
	uv_mutex_unlock(&c->operations_mutex);

	log_debug(lg, "===> GetCont %lu vector(s) at 0x%" PRIx64  " index %i",
	    iovcnt, off, index ? *index : -1);
	log_hexdump(lg, "CID:", (char *)op->cid, op->cid_size);
	log_hexdump(lg, "TID:", (char *)op->tid, op->tid_size);
	log_hexdump(lg, "BID:", (char *)op->bid, op->bid_size);
	log_hexdump(lg, "OID:", (char *)op->oid, op->oid_size);

	struct ccow_op *cont_op;
	err = ccow_operation_create_cont(c, CCOW_GET_CONT, &cont_op, index);
	if (err) {
		log_error(lg, "GET Unnamed request operation alloc error: %d",
		    err);
		return err;
	}

	cont_op->seq_iov_in = seq_iov_in;
	cont_op->seq_iovcnt_in = seq_iovcnt_in;

	cont_op->need_wait = need_wait;

	static const struct transition trans_tbl[] = {
		// FROM, EVENT, ACTION, TO, GUARD
		// -----------------------------------------------------------
		{ ST_INIT, EV_CALL, &unnamedget_cont__init, ST_WAIT, NULL },
		{ ST_WAIT, EV_DONE, NULL, ST_READY, NULL },
		{ ST_READY, EV_DONE, NULL, ST_TERM, NULL },
		{ ST_ANY, EV_ANY, NULL, ST_TERM, NULL }
	};

	struct unnamedget_cont_req *r = je_calloc(1, sizeof (*r));
	if (!r) {
		err = -ENOMEM;
		ccow_operation_destroy(cont_op, 1);
		log_error(lg, "UNNAMED GET CONT request alloc error: %d", err);
		return err;
	}

	r->tc = c->tc;

	err = ccow_create_io(c, op, CCOW_GET_CONT, trans_tbl,
			sizeof (trans_tbl) / sizeof (*trans_tbl), r,
			unnamedget_cont__term, &r->io);
	if (err) {
		log_error(lg, "ccow_create_io returned err = %d", err);
		ccow_operation_destroy(cont_op, 1);
		je_free(r);
		return err;
	}

	/* used by hashuncomp, see named-get.c */
	r->io->cont_op = cont_op;

	/*
	 * Prepare outputs for comphash
	 *
	 * NOTICE: we allocate actual output (chunk->base) in comphash.
	 */
	cont_op->chunks = rtbuf_init_mapped((uv_buf_t *)iov, iovcnt);
	if (!cont_op->chunks) {
		log_error(lg, "memory allocation failure");
		ccow_operation_destroy(cont_op, 1);
		je_free(r);
		return -ENOMEM;
	}

	/*
	 * Remember request arguments
	 */
	cont_op->iov_in = iov;
	cont_op->iovcnt_in = iovcnt;
	cont_op->offset = off;

	cont_op->namedget_io = r->io;
	atomic_inc(&cont_op->busy_cnt);

	/*
	 * Chain continuation I/O into CCOW_CONT (e.g. init_op)
	 */
	ccow_io_lock(r->io);

	ccow_chain_io(op, r->io);

	if (op->busy_cnt == 0 || r->io->parallel_io) {
		err = ccow_start_io(r->io);
		if (err != 0 && err != -EEXIST) {
			ccow_io_unlock(r->io);
			log_error(lg, "ccow_start_io returned err = %d", err);
			ccow_operation_destroy(cont_op, 1);
			je_free(r);
			return err;
		}
	}
	ccow_io_unlock(r->io);

	return 0;
}

static void
ccow_get_cont_ra_cb(ccow_completion_t comp, void *arg, int index, int status)
{
	assert(comp != NULL);
	assert(comp->operations != NULL);

	log_debug(lg, "ccow_get_cont_ra_cb : index = %d : "
	    "comp = %p : comp->status = %d \n",
	    index, comp, comp->status);

	if (comp->operations[index] == NULL) {
		return;
	}

	struct ccow_op * op = comp->operations[index];

	if (op->seq_iov_in != NULL && op->iovcnt_in > op->seq_iovcnt_in) {
		je_free(op->iov_in[op->seq_iovcnt_in].iov_base);
		je_free(op->iov_in);
		op->iov_in = op->seq_iov_in;
		op->iovcnt_in = op->seq_iovcnt_in;
	}

	if (comp->seq_cb != NULL) {
		comp->seq_cb(comp, arg, index, status);
	} else {
		/* assert(0); */
	}
}

int
ccow_get_cont(struct ccow_completion *c, struct iovec *iov,
    size_t iovcnt, uint64_t off, int need_wait, int *index)
{
	size_t i;
	size_t ra_size  = 0;
	uint64_t ra_off = 0;
	uint64_t ra_end = 0;

	struct ccow *tc = c->tc;
	assert(tc != NULL);

	do {
		if (tc->disable_read_ahead) {
			tc->stats.read_ahead.disabled++;
			break;
		}
		tc->stats.read_ahead.enabled++;

		if (c->comp_cb != ccow_get_cont_ra_cb) {
			c->seq_cb = c->comp_cb;
			c->comp_cb = ccow_get_cont_ra_cb;
		}

		if (c->seq_len + c->seq_off == off) {
			tc->stats.read_ahead.sequential++;
			c->seq_cnt++;
		} else {
			tc->stats.read_ahead.non_sequential++;
			c->seq_cnt = 0;
		}

		c->seq_off = off;
		c->seq_len = 0;

		for (i = 0; i < iovcnt; i++) {
			c->seq_len += iov[0].iov_len;
		}

		if (c->seq_cnt < tc->read_ahead_detect) {
			tc->stats.read_ahead.not_detected++;
			break;
		}
		tc->stats.read_ahead.detected++;

		if (iovcnt + tc->read_ahead_factor >= (uint32_t)(tc->io_rate_max*2) ||
		    (c->seq_cnt - tc->read_ahead_detect) % tc->read_ahead_factor != 0) {
			tc->stats.read_ahead.not_factored++;
			break;
		}
		tc->stats.read_ahead.factored++;

		ra_size = c->seq_len * (tc->read_ahead_factor - 1);
		ra_off = off + c->seq_len;
		/* Note: metadata.logical_size is updated only after finalize/create,
		 * so it is always one finalize late for a new object
		 */
		ra_end = c->operations[0]->metadata.logical_size;

		if (ra_end == 0) {
			break;
		}

		if (ra_off + ra_size >= ra_end) {
			if (ra_end >= ra_off) {
				ra_size = ra_end - ra_off;
			} else {
				log_debug(lg, "read ahead offset %lu is greater then object logical size %lu"
						" probably logical_size is outdated", ra_off, ra_end);
				ra_size = 0;
			}
		}

		if (ra_size == 0) {
			break;
		}
	} while (0);

	struct iovec * seq_iov_in = NULL;
	size_t seq_iovcnt_in = 0;

	do {
		if (ra_size == 0) {
			break;
		}

		uint8_t * buf = je_malloc(ra_size);
		if (buf == NULL) {
			break;
		}

		/*
		 * there is a requirement and corresponding assumption that
		 * each iovec entry is one and only one chunk.
		 */
		size_t n_chnks = ra_size / iov[0].iov_len;
		size_t s_chnks = iov[0].iov_len;
		size_t new_iovcnt = iovcnt + n_chnks;

		struct iovec * new_iov = je_malloc(new_iovcnt * sizeof(struct iovec));
		if (new_iov == NULL) {
			assert(buf != NULL);
			je_free(buf);
			buf = NULL;
			break;
		}

		/*
		 * save the original iov
		 */
		seq_iov_in    = iov;
		seq_iovcnt_in = iovcnt;

		/*
		 * copy the orginal iov into the new iov
		 */
		for (i = 0; i < seq_iovcnt_in; i++) {
			new_iov[i].iov_base = seq_iov_in[i].iov_base;
			new_iov[i].iov_len  = seq_iov_in[i].iov_len;
		}

		/*
		 * add the new buffers into the last iov entries
		 */
		for (i = seq_iovcnt_in; i < new_iovcnt; i++) {
			new_iov[i].iov_base = buf + ((i - seq_iovcnt_in) * s_chnks);
			new_iov[i].iov_len  = s_chnks;
		}

		/*
		 *
		 */
		iov    = new_iov;
		iovcnt = new_iovcnt;
	} while(0);

	int rv = ccow_get_cont_helper(c, iov, iovcnt, off, need_wait,
	    index, seq_iov_in, seq_iovcnt_in);

	return rv;
}

/*
 * Lists chids of VM or CM.
 * Chunk manifest is fetched for a given version.
 */
int
ccow_get_chids(const char *cid, size_t cid_size, const char *tid,
    size_t tid_size, const char *bid, size_t bid_size, const char *oid,
    size_t oid_size, const uint512_t *vmchid, uint64_t attr,
    struct ccow_completion *c, struct iovec *iov,
    size_t iovcnt, rtbuf_t **rb, ccow_lookup_t *iter)
{
	int err;

	assert(iter != NULL);

	/*
	 * Construct Named Get to retrieve Version Manifest
	 */
	struct ccow_io *get_io;
	struct ccow_op *get_op;

	err = ccow_namedget_create(cid, cid_size, tid, tid_size, bid, bid_size,
	    oid, oid_size, c, ccow_namedget_done, CCOW_GET_LIST, &get_op, &get_io);
	if (err)
		return err;
	struct ccow_lookup *lp;
	lp = ccow_lookup_create(c, CCOW_LOOKUP_CLASS_OBJECT);
	if (iter != NULL) {
		if (!lp) {
			ccow_destroy_io(get_io);
			return -ENOMEM;
		}
		assert(get_op->iter == NULL);
		get_op->iter = *iter = lp;
	}

	/*
	 * Remember request arguments
	 */
	get_op->iov_in = iov;
	get_op->iovcnt_in = iovcnt;
	get_op->offset = 0;

	get_io->attributes = attr;
	struct getcommon_client_req *req = CCOW_IO_REQ(get_io);
	if (vmchid)
		req->chid = *vmchid;

	/*
	 * Prepare outputs for hashuncomp
	 */
	get_op->chunks = rtbuf_init_mapped((uv_buf_t *)iov, iovcnt);
	if (!get_op->chunks) {
		ccow_lookup_release(get_op->iter);
		*iter = NULL;
		ccow_destroy_io(get_io);
		return -ENOMEM;
	}
	get_op->traverse_cb = chid_cb;

	/* async start the io */
	err = ccow_start_io(get_io);
	if (err)
		return err;
	err = ccow_wait(c, -1);
	if (!err) {
		*rb = rtbuf_clone_bufs(get_io->cm_reflist);
	}
	return err;
}

/*
 * Initiate CCOW GET
 *
 * Scope: PRIVATE
 */
int ccow_tenant_get(const char *cid, size_t cid_size, const char *tid,
    size_t tid_size, const char *bid, size_t bid_size, const char *oid,
    size_t oid_size, struct ccow_completion *c, struct iovec *iov,
    size_t iovcnt, uint64_t off, ccow_op_t optype, ccow_lookup_t *iter)
{
	int err;

	assert(optype);
	assert(cid && cid_size > 0);
	assert(tid && tid_size > 0);
	assert(bid && bid_size > 0);
	assert(oid && oid_size > 0);

	if (*cid == 0 && strncmp(tid, RT_SYSVAL_TENANT_ADMIN,
	          sizeof (RT_SYSVAL_TENANT_ADMIN)) == 0) {
		tid = RT_SYSVAL_TENANT_SVCS;
		tid_size = sizeof (RT_SYSVAL_TENANT_SVCS);
	}

	if (memcmp_quick(tid, tid_size, RT_SYSVAL_TENANT_ADMIN,
		    strlen(RT_SYSVAL_TENANT_ADMIN) + 1) == 0) {
		tid = "";
		tid_size = 1;
	}

	log_debug(lg, "===> %s %lu vector(s) at 0x%" PRIx64,
		ccow_op2str(optype), iovcnt, off);
	log_escdump(lg, "CID:", (char *)cid, cid_size);
	log_escdump(lg, "TID:", (char *)tid, tid_size);
	log_escdump(lg, "BID:", (char *)bid, bid_size);
	log_escdump(lg, "OID:", (char *)oid, oid_size);

	/*
	 * If application asks us to initialize iterator, set its pointer
	 * to NULL initially. Further, we will allocate iterator and will fill
	 * it in on NamedGet completion.
	 *
	 * It is responsibility of an application to release initialized
	 * iterator.
	 *
	 * Common pattern looks like this:
	 *
	 * ccow_lookup_t iter;
	 * err = ccow_tenant_get(..., &iter);
	 * if (err)
	 *	return;
	 * err = ccow_wait();
	 * if (iter)
	 *      ccow_lookup_release(iter);
	 * if (err)
	 *      return;
	 */
	if (iter)
		*iter = NULL;

	/*
	 * Construct Named Get to retrieve Version Manifest
	 */
	struct ccow_io *get_io;
	struct ccow_op *get_op;
	err = ccow_namedget_create(cid, cid_size, tid, tid_size, bid, bid_size,
	    oid, oid_size, c, ccow_namedget_done, optype, &get_op, &get_io);
	if (err)
		return err;
	struct ccow_lookup *lp;
	if (iter != NULL) {
		if (*bid == 0 && *oid == 0)
			lp = ccow_lookup_create(c, CCOW_LOOKUP_CLASS_TENANT);
		else if (*bid && *oid == 0)
			lp = ccow_lookup_create(c, CCOW_LOOKUP_CLASS_BUCKET);
		else
			lp = ccow_lookup_create(c, CCOW_LOOKUP_CLASS_OBJECT);
		if (!lp) {
			ccow_destroy_io(get_io);
			return -ENOMEM;
		}
		assert(get_op->iter == NULL);
		get_op->iter = *iter = lp;
	}

	/*
	 * Remember request arguments
	 */
	get_op->iov_in = iov;
	get_op->iovcnt_in = iovcnt;
	get_op->offset = off;

	/*
	 * Prepare outputs for hashuncomp
	 */
	get_op->chunks = rtbuf_init_mapped((uv_buf_t *)iov, iovcnt);
	if (!get_op->chunks) {
		if (iter) {
			ccow_lookup_release(get_op->iter);
			*iter = NULL;
		}
		ccow_destroy_io(get_io);
		return -ENOMEM;
	}

	/* async start the io */
	err = ccow_start_io(get_io);
	return err;
}

/*
 * Initiate CCOW GET
 *
 * Each IO vector represents preallocated buffer for exactly one chunk.
 * This function expects logically contiguous vectors from specified offest
 * to be provided by an application.
 *
 * Scope: PUBLIC
 */
int ccow_get(const char *bid, size_t bid_size, const char *oid, size_t oid_size,
    ccow_completion_t comp, struct iovec *iov, size_t iovcnt, uint64_t off,
    ccow_lookup_t *iter)
{
	struct ccow_completion *c = comp;
	struct ccow *tc = c->tc;
	int err;

	tc->stats.ccow.gets++;

	err = ccow_tenant_get(tc->cid, tc->cid_size, tc->tid, tc->tid_size,
	    bid, bid_size, oid, oid_size, comp, iov, iovcnt, off,
	    CCOW_GET, iter);
	return err;
}


/*
 * Initiate CCOW GET VERSIONS
 *
 * Scope: PUBLIC
 */
int ccow_get_versions(const char *bid, size_t bid_size, const char *oid, size_t oid_size,
    ccow_completion_t comp, ccow_lookup_t *iter)
{
    struct ccow_completion *c = comp;
    struct ccow *tc = c->tc;
    int err;
    struct iovec *iov = NULL;
    size_t iovcnt = 0;
    uint64_t off = 0;

    tc->stats.ccow.gets++;

    err = ccow_tenant_get(tc->cid, tc->cid_size, tc->tid, tc->tid_size,
        bid, bid_size, oid, oid_size, comp, iov, iovcnt, off,
        CCOW_GET_VERSIONS, iter);
    return err;
}

/*
 * Initiate CCOW GET TEST
 *
 * Scope: PUBLIC
 */
int ccow_get_test(const char *bid, size_t bid_size, const char *oid, size_t oid_size,
    ccow_completion_t comp)
{
	struct ccow_completion *c = comp;
	struct ccow *tc = c->tc;
	int err;

	tc->stats.ccow.gets++;

	err = ccow_tenant_get(tc->cid, tc->cid_size, tc->tid, tc->tid_size,
	    bid, bid_size, oid, oid_size, comp, NULL, 0, 0,
	    CCOW_GET, NULL);
	return err;
}


/*
 * Initiate CCOW GET LIST
 *
 * Scope: PUBLIC
 */
int ccow_get_list(const char *bid, size_t bid_size, const char *oid,
    size_t oid_size, ccow_completion_t comp, struct iovec *iov, size_t iovcnt,
    size_t count, ccow_lookup_t *iter)
{
	struct ccow_completion *c = comp;
	struct ccow *tc = c->tc;
	int err;

	err = ccow_tenant_get(tc->cid, tc->cid_size, tc->tid,
	    tc->tid_size, bid, bid_size, oid, oid_size, comp, iov, iovcnt,
	    count, CCOW_GET_LIST, iter);
	return err;
}

/*
 * Initiate CCOW GET by NHID string
 *
 * Scope: PRIVATE
 */
int
ccow_tenant_getobj(const char *nhid_str, struct ccow_completion *c,
    struct iovec *iov, size_t iovcnt, uint64_t off, ccow_op_t optype,
    ccow_lookup_t *iter)
{
	int err;

	if (strlen(nhid_str) != UINT512_BYTES * 2) {
		log_error(lg, "Wrong oid length. Expecting %lu bytes \
		    oid_size: %lu oid: %s", UINT512_BYTES * 2,
		    strlen(nhid_str), nhid_str);
		return -EBADF;
	}

	err = ccow_tenant_get("", 1, "", 1, "", 1, nhid_str,
	    UINT512_BYTES * 2 + 1, c, iov, iovcnt, off, optype, iter);
	return err;
}

int
ccow_fetch_lock(ccow_t tc, const char *bid, size_t bid_size,
		const char *oid, size_t oid_size,
		struct ccow_obj_lock *query_lock,
		uint8_t mode, uint64_t off, uint64_t len)
{
	struct ccow_obj_lock lk;
	char ino_str[22];
	msgpack_p *inp = NULL;
	msgpack_u *u;
	struct iovec in_iov, query_iov;
	ccow_completion_t c;
	int err;

	memset(&lk, 0, sizeof(lk));
	lk.lk_mode = mode;
	lk.lk_region.off = off;
	lk.lk_region.len = len;

	inp = msgpack_pack_init();
	err = ccow_pack_lock(inp, &lk);
	if (err) {
		log_error(lg, "Failed to pack lock. err: %d", err);
		goto _out;
	}

	msgpack_get_buffer(inp, (uv_buf_t *)&in_iov);
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "Failed to create comp. err: %d", err);
		goto _out;
	}

	memset(&query_iov, 0, sizeof(query_iov));
	err = ccow_get_res(tc->cid, tc->cid_size, tc->tid, tc->tid_size,
				bid, bid_size, oid, oid_size,
				c, CCOW_SR_MAJ_LOCK, CCOW_SR_MINOR_ANY,
				&query_iov, 1, &in_iov, 1);
	err = ccow_wait(c, -1);
	if (err) {
		log_debug(lg, "Failed to fetch lock. err: %d", err);
		goto _out;
	}

	u = msgpack_unpack_init(query_iov.iov_base, query_iov.iov_len, 0);
	if (u) {
		ccow_unpack_lock(u, query_lock);
		msgpack_unpack_free(u);
	}

_out:
	msgpack_pack_free(inp);
	return err;
}

int
ccow_get_posix_lock(ccow_t tc, const char *bid, size_t bid_size,
		const char *oid, size_t oid_size,
		struct flock *query_lock,
		struct flock *result_lock)
{
	struct ccow_obj_lock obj_lock;
	/* 0 length means entire file */
	uint64_t req_len = query_lock->l_len ? query_lock->l_len : ~0;
	int mode;
	int err;

	if (query_lock->l_type & LOCK_NB)
		mode = CCOW_LOCK_NON_BLOCK;

	switch (query_lock->l_type) {
	case LOCK_SH:
		mode |= CCOW_LOCK_SHARED;
		break;
	case LOCK_EX:
		mode |= CCOW_LOCK_EXCL;
		break;
	case LOCK_UN:
		mode |= CCOW_LOCK_UNLOCK;
		break;
	default:
		break;
	}

	err = ccow_fetch_lock(tc, bid, bid_size, oid, oid_size,
				&obj_lock, mode, query_lock->l_start, req_len);
	if (err) {
		log_debug(lg, "Failed to fetch lock. err: %d", err);
		if (err == -ENOENT) {
			result_lock->l_type = F_UNLCK;
			/* No lock means no error */
			err = 0;
		}
	} else {
		result_lock->l_type = obj_lock.lk_mode == CCOW_LOCK_EXCL ? F_WRLCK :
									   F_RDLCK;
	}
	result_lock->l_start = obj_lock.lk_region.off;
	result_lock->l_len = obj_lock.lk_region.len;

	return err;
}

static void
ccow_resget_done(struct getres_client_req *r)
{
}

int
ccow_get_res(const char *cid, size_t cid_size, const char *tid,
    size_t tid_size, const char *bid, size_t bid_size, const char *oid,
    size_t oid_size, ccow_completion_t c,
    ccow_sr_mj_opcode_t mjr_res, ccow_sr_mn_opcode_t mnr_res,
    struct iovec *in_iov, size_t in_iovcnt,
    struct iovec *out_iov, size_t out_iovcnt)
{
	struct ccow_io *get_io;
	struct ccow_op *get_op;
	int err;

	assert(in_iovcnt == 1);
	assert(out_iovcnt == 1);

	log_escdump(lg, "CID:", (char *)cid, cid_size);
	log_escdump(lg, "TID:", (char *)tid, tid_size);
	log_escdump(lg, "BID:", (char *)bid, bid_size);
	log_escdump(lg, "OID:", (char *)oid, oid_size);

	err = ccow_resget_create(cid, cid_size, tid, tid_size, bid, bid_size,
				 oid, oid_size, c, ccow_resget_done,
				 CCOW_GET_RES, &get_op, &get_io);
	if (err)
		return err;

	get_op->iov_in = in_iov;
	get_op->iovcnt_in = in_iovcnt;
	struct getres_client_req *r = CCOW_IO_REQ(get_io);

	/*
	 * Set payload to be sent to the server.
	 */
	r->out_payload.bufs = (uv_buf_t *)out_iov;
	r->out_payload.nbufs = 1;

	r->in_payload.bufs = (uv_buf_t *)in_iov;
	r->in_payload.nbufs = 1;

	r->maj_res = mjr_res;
	r->minor_res = mnr_res;

	err = ccow_start_io(get_io);

	if (err) {
		ccow_destroy_io(get_io);
	}
	return err;
}

