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
#include <inttypes.h>
#include <string.h>
#include <nanomsg/nn.h>
#include <nanomsg/pubsub.h>

#include "ccowhttpd.h"
#include "putpub.h"

static int putpub_fd;

#define PUTPUB_ADDRESS	"ipc:///opt/nedge/var/run/ccowhttpd_putpub.ipc"

void
putpub_init()
{
	putpub_fd = nn_socket(AF_SP, NN_PUB);
	if (putpub_fd < 0) {
		log_error(lg, "Failed create socket: %s [%d]", strerror(errno),
		    (int)errno);
		return;
	}

	int linger = -1;
	nn_setsockopt(putpub_fd, NN_SOL_SOCKET, NN_LINGER, &linger, sizeof (linger));

	/* set the option so we can use ipv6 address */
	int flag = 0;
	int rc = nn_setsockopt(putpub_fd, NN_SOL_SOCKET , NN_IPV4ONLY, &flag,
	    sizeof(int));
	if (rc < 0) {
		nn_close(putpub_fd);
		log_error(lg, "setsockopt error: %s [%d]",
		    strerror(errno), errno);
		return;
	}

	rc = nn_bind(putpub_fd, PUTPUB_ADDRESS);
	if(rc < 0) {
		nn_close(putpub_fd);
		log_error(lg, "Failed bind to \"%s\": %s [%d]", PUTPUB_ADDRESS,
		    strerror(errno), (int)errno);
		return;
	}

	log_info(lg, "Publishing PUT events on '%s'", PUTPUB_ADDRESS);
}

int
putpub_send(char *bk, char *obj)
{
	char buf[2048];
	snprintf(buf, 2048, "%s/%s", bk, obj);
	return nn_send(putpub_fd, buf, strlen(buf), 0);
}

void
putpub_destroy()
{
	nn_close(putpub_fd);
}
