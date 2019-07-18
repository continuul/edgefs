/*
 * rowevac.c
 *
 *  Created on: Jul 5, 2018
 *      Author: root
 */

#include "ccow-impl.h"
#include "rowevac.h"
#include "state.h"

struct rowevac_req {
	CCOW_CLASS_FIELDS
	struct ccow_network *netobj;
	struct rowevac_cmd* cmd;
};

/*
 * ACTION: unblock caller and report error
 */
static void
rowevac__error(struct state *st) {
	struct rowevac_req *r = st->data;
	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}
}

/*
 * ACTION: process response
 */
static void
rowevac__response(struct state *st)
{
	struct rowevac_req *r = st->data;
	struct repctx *ctx = r->ctx;
	struct ccow_network *netobj = r->netobj;
	struct ccow *tc = netobj->tc;
	struct repwqe *wqe = ctx->wqe_in;
	assert(wqe);
	int err;

	struct repmsg_rowevac *msg =
		(struct repmsg_rowevac *)wqe->msg;

	r->cmd->status = msg->status;
}

static void
rowevac_timeout(uv_timer_t *req, int status)
{
	struct state *st = req->data;
	struct rowevac_req *r = st->data;
	if (r->timer_req->data) {
		uv_timer_stop(r->timer_req);
		r->timer_req->data = NULL;
	}
	log_warn(lg, "ROW EVAC request timeout after %d attempts "
	    "seqid:%d.%d", r->retry + 1, r->ctx->sequence_cnt,
	    r->ctx->sub_sequence_cnt - 1);
	state_event(st, EV_TIMEOUT);
}

/*
 * ACTION: Prepare and send OPPS_STATUS request
 */
static void
rowevac__send(struct state *st)
{
	int err;
	struct rowevac_req *r = st->data;
	struct ccow_network *netobj = r->netobj;
	struct ccow *tc = netobj->tc;

	struct repmsg_rowevac msg;
	memset(&msg, 0, sizeof (msg));
	msg.dest_vdev = r->cmd->dest_vdev;
	msg.src_vdev = r->cmd->src_vdev;
	msg.row = r->cmd->row;
	msg.opcode = r->cmd->opcode;
	msg.flags = r->cmd->flags;
	msg.amount = r->cmd->amount;
	msg.status = -1;
	msg.id = r->cmd->id;

	if (tc->unicastio == REPLICAST_UNICAST_UDP_MCPROXY) {
		r->ctx->attributes = RD_ATTR_UNICAST_UDP_MCPROXY;
		msg.hdr.attributes |= RD_ATTR_UNICAST_UDP_MCPROXY;
	}

	struct sockaddr_in6 send_addr;
	flexhash_get_rowaddr(tc->flexhash, msg.row, &send_addr);
	send_addr.sin6_scope_id = netobj->if_indexes[0];
	r->inexec++;
	err = replicast_send(netobj->robj[0], r->ctx, RT_ROWEVAC,
		(struct repmsg_generic *)&msg, NULL, NULL, 0,
		&send_addr, replicast_send_done_generic, st, NULL);
	if (err) {
		r->inexec--;
		ccow_fail_io(st->io, err);
		state_next(st, EV_ERR);
		return;
	}

	if (r->timer_req->data)
		uv_timer_stop(r->timer_req);
	/*
	 * Timeout in OPP_STATUS_TIMEOUT_MS mss..
	 */
	r->timer_req->data = st;
	uv_timer_start(r->timer_req, rowevac_timeout, 10000, 0);
}

/*
 * GUARD: check for retry < MAX_RETRY
 */
static int
rowevac__retry(struct state *st)
{
	struct rowevac_req *r = st->data;

	if (++r->retry < 100)
		return 1; // ok

	log_error(lg, "ROW EVAC request timeout after %d attempts "
	    "seqid:%d.%d", r->retry, r->ctx->sequence_cnt,
	    r->ctx->sub_sequence_cnt - 1);

	ccow_fail_io(st->io, -EIO);
	state_next(st, EV_ERR);
	return 0; // fail
}

static void
rowevac__init(struct state *st)
{
	struct rowevac_req *r = st->data;
	struct ccow_network *netobj = r->netobj;
	struct ccow *tc = netobj->tc;

	r->ctx = repctx_init(netobj->robj[0]);
	if (!r->ctx) {
		log_error(lg, "repctx alloc: out of memory: -ENOMEM");
		ccow_fail_io(st->io, -ENOMEM);
		state_next(st, EV_ERR);
		return;
	}
	r->ctx->state = st;

	r->timer_req = je_malloc(sizeof (*r->timer_req));
	if (!r->timer_req) {
		repctx_destroy(r->ctx);
		ccow_fail_io(st->io, -ENOMEM);
		state_next(st, EV_ERR);
		return;
	}
	r->timer_req->data = NULL;
	uv_timer_init(tc->loop, r->timer_req);

	state_next(st, EV_SEND);
}

static void
blr_timer_close_cb(uv_handle_t* handle)
{
	je_free(handle);
}

static void
rowevac__term(struct state *st)
{
	struct rowevac_req *r = st->data;
	struct ccow_io *io = (struct ccow_io *)st;

	assert(r->inexec >= 0);

	if (r->inexec) {
		log_debug(lg, "req %p request inexec %d, cannot terminate",
		    r, r->inexec);
		return;
	}

	if (r->timer_req->data)
		uv_timer_stop(r->timer_req);
	uv_close((uv_handle_t *)r->timer_req, blr_timer_close_cb);
	repctx_destroy(r->ctx);
	ccow_complete_io(io);
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
// ---------------------------------------------------------------------
{ ST_INIT, EV_CALL, &rowevac__init, ST_INIT, NULL },
{ ST_INIT, EV_SEND, &rowevac__send, ST_WAIT, NULL },
{ ST_WAIT, EV_TIMEOUT, &rowevac__send, ST_WAIT, &rowevac__retry },
{ ST_WAIT, RT_ROWEVAC_ACK, &rowevac__response, ST_TERM, NULL },
{ ST_ANY, EV_ANY, &rowevac__error, ST_TERM, NULL }
};

/*
 * Initiate RT_OPP_STATUS
 *
 */
int ccow_rowevac_request(struct ccow *tc, struct ccow_completion *c,
	struct rowevac_cmd* cmd)
{
	int err;
	struct ccow_network *netobj = tc->netobj;

	struct rowevac_req *r = je_calloc(1, sizeof (*r));
	if (!r) {
		log_error(lg, "blob_lookup_request: out of memory: -ENOMEM");
		return -ENOMEM;
	}
	r->netobj = netobj;
	r->cmd = cmd;

	struct ccow_op *op;
	err = ccow_operation_create(c, CCOW_ROWEVAC, &op);
	if (err) {
		ccow_release(c);
		je_free(r);
		return err;
	}

	struct ccow_io *io;
	err = ccow_create_io(c, op, CCOW_OPP_STATUS, trans_tbl,
	    sizeof (trans_tbl) / sizeof (*trans_tbl), r, rowevac__term, &io);
	if (err) {
		ccow_operation_destroy(op, 1);
		ccow_release(c);
		je_free(r);
		return err;
	}
	err = ccow_start_io(io);
	return err;
}



