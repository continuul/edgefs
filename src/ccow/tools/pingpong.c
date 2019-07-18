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
 * usage
 *
 * Display usage and exit.
 */
#include "ccowutil.h"
#include "ccow-impl.h"
#include "ccowd.h"

#define JSON_BUF_SZ 16*1024

static char *progname;
static char *clust_name;
static char *tc_name;

static ccow_t cl = NULL;
char buf[JSON_BUF_SZ];
static int dmon = 0;

static int
ccowd_init()
{
  	int rc = 0;

	if(dmon) {
		rc = ccow_daemon_init(NULL);
		usleep(2 * 1000000L);
	}
	return rc;
}

static int
ccow_init()
{
	int fd;
	int rc = -1;
	size_t cl_len;
	size_t tc_len;

	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
	fd  = open(path, O_RDONLY);
	if (fd != -1) {
		rc = read(fd, buf, JSON_BUF_SZ - 1);	
		if (rc >= 0) {
			cl_len = strlen(clust_name) + 1;
			tc_len = strlen(tc_name) + 1;
			rc = ccow_tenant_init(buf, clust_name, cl_len,
					      tc_name, tc_len, &cl);
		}
		close(fd);
	}
	return rc;
}

static int
pingpong_run()
{
	return ccow_pingpong(cl, 1);
}

static void
pingpong_usage()
{
	printf("\n"
	       "USAGE:\n"
	       "     %s <-c cluster-name> <-t tenant-name> [-dh]\n"
	       "\n"
	       "    -h   Display this help message and exit.\n"
	       "\n"
	       "    -c   Name of the cluster\n"
	       "\n"
	       "    -d   Run '%s' with a single node\n"
	       "\n"
	       "    -t   Name of the tenant\n"
	       "\n", progname, progname);

	exit(EXIT_SUCCESS);
}

static void
pingpong_parse_options(int argc, char *argv[])
{
	int opt;
	size_t len;

	progname = basename(argv[0]);
	while ((opt = getopt(argc, argv, "hdc:t:")) != -1) {
		switch(opt) {

		case 'h':
			pingpong_usage();
			break;

		case 'c':
			clust_name = optarg;
			break;

		case 'd':
			dmon = 1;
			break;

		case 't':
			tc_name = optarg;
			break;

		default:
			pingpong_usage();
			break;
		}
	}
	if (clust_name == NULL && tc_name == NULL)
		pingpong_usage();
}

static int
pingpong_init()
{
	int rc;

	rc = ccowd_init();
	if (rc == 0) {
		rc = ccow_init();
		if (rc != 0)
			ccow_daemon_term();
	}
	return rc;
}

static void
pingpong_term()
{
	ccow_tenant_term(cl);
	if(dmon)
		ccow_daemon_term();
}

int
main(int argc, char *argv[])
{
	int rc;

	pingpong_parse_options(argc, argv);
	rc = pingpong_init();
	if (rc != 0)
		fprintf(stderr, "Failed not initialize\n");
	else {
		rc = pingpong_run();
		pingpong_term();
	}
	return rc;
}
