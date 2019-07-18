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

#include "ccow-impl.h"
#include "state.h"
#include "replicast.h"

static void
client_notification_term(struct state *st)
{
	log_trace(lg, "Terminating st %p", st);
}

static void
client_notify(struct state *st)
{
	struct repmsg_notification *notice = st->data;
	struct ccow_io *io = (struct ccow_io *)notice->io_cookie;

	log_trace(lg, "st %p", st);
	
	state_override(&io->state, ST_TERM);
	ccow_complete_io(io);
}

static const struct transition trans_tbl[] = {
	{ ST_INIT, RT_CLIENT_NOTIFICATION, &client_notify, ST_TERM }
};

int
client_notification_init(struct replicast *robj, struct repctx *ctx,
			 struct state *state)
{
	int err;
	struct repmsg_notification *notice;

	log_trace(lg, "robj %p, ctx %p, state %p", robj, ctx, state);

	/* TODO: check if client is terminating */
	notice = (struct repmsg_notification *)ctx->wqe_in->msg;
	log_debug(lg, "Recevied Notification for ioptr %" PRIx64 "!!!",
		  notice->io_cookie);

	state_init(state, trans_tbl, sizeof(trans_tbl)/sizeof(*trans_tbl),
		   notice, client_notification_term);

	return 0;
}
