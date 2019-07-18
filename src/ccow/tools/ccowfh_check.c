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
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include "ccowutil.h"
#include "ccow.h"
#include "ccow-impl.h"
#include "ccowd.h"
#include "server-list.h"

ccow_t cl = NULL;
FILE *fd;

static int
libccow_setup()
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return -ENOMEM;
	char *buf = je_calloc(1, 16384);
	if (!buf)
		return -ENOMEM;
	if (read(fd, buf, 16383) == -1)
		goto _err;
	if (close(fd))
		goto _err;
	if (ccow_admin_init(buf, "", 1, &cl))
		goto _err;
	if (buf)
		je_free(buf);
	return 0;
_err:
	if (buf)
		je_free(buf);
	return -EINVAL;
}

static void
libccow_teardown()
{
	if (cl)
		ccow_tenant_term(cl);
}



static int
libccow_check_checkpoint(int get_file)
{
	int err=0;
	printf("check checkpoint\n");

	struct ccow *tc = cl;
	struct ccow_completion *c;
	err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err) {
		return err;
	}
	uint32_t flags = 0;
	if (get_file)
		flags |= SERVER_LIST_GET_CHECKPOINT;
	err = server_list_get_init(tc->netobj, c, uint128_null, 0, flags);
	if (err) {
		ccow_tenant_term(tc);
		return err;
	}
	err = ccow_wait(c, -1);

	return err;
}


static void
usage()
{
	printf("Usage:\t ccowfh_check -c\n");
}

int
main(int argc, char **argv)
{
	int get_file = 0;
	if (argc > 1) {
		if (strcmp(argv[1], "-h") == 0)
			usage();
		if (strcmp(argv[1], "-c") == 0)
			get_file = 1;
	}
	int err = libccow_setup();
	if (err) {
		fprintf(stderr, "Error init system context %d\n", err);
		return err;
	}
	err = libccow_check_checkpoint(get_file);
	if (err) {
		fprintf(stderr, "Error when running a check checkpoint\n");
		return err;
	}
	libccow_teardown();
	return err;
}


