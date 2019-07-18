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
#include "ccowd-impl.h"
#include "state.h"

extern struct ccowd *ccow_daemon;

static void
pingpong__error(struct state *st)
{
	struct repctx *ctx = st->data;
}

/*
 * ACTION: process RT_PINGPONG request
 *
 * Return same message back to a caller
 */
static void
pingpong__req(struct state *st)
{
	struct repctx *ctx = st->data;
	struct repwqe *wqe = ctx->wqe_in;
	assert(wqe);

	struct repmsg_pingpong *msg =
		(struct repmsg_pingpong *)wqe->msg;
	struct repmsg_pingpong rsp;

	memset(&rsp, 0, sizeof (rsp));
	rsp.message = msg->message;
	rsp.message_size = msg->message_size;

	int err = replicast_send(ccow_daemon->robj[0], NULL,
	    RT_PINGPONG_ACK, (struct repmsg_generic *)&rsp,
	    (struct repmsg_generic *)wqe->msg, NULL, 0, NULL, NULL, NULL, NULL);
	if (err)
		state_next(ctx->state, EV_ERR);
}

static void
pingpong__term(struct state *st)
{
	struct repctx *ctx = st->data;
	repctx_destroy(ctx);
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
//---------------------------------------------------------------------
{ ST_INIT, RT_PINGPONG, &pingpong__req, ST_TERM, NULL },
{ ST_ANY, EV_ANY, &pingpong__error, ST_TERM, NULL }
};

int
pingpong_init(struct replicast *robj, struct repctx *ctx, struct state *state)
{
	state->table = trans_tbl;
	state->cur = ST_INIT;
	state->max = sizeof(trans_tbl)/sizeof(*trans_tbl);
	state->data = ctx;
	state->term_cb = pingpong__term;
	return 0;
}
