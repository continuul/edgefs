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
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <linux/limits.h>

#include "ccowutil.h"
#include "reptrans.h"

static int daemonize;
static char pidfile[PATH_MAX];

#define MAX_DEV 256
Logger lg;
struct enum_dev_arg {
	int n_dev;
	struct repdev **dev;
};

static void
enum_dev__done_cb(struct repdev *dev, void *arg, int status)
{
	struct enum_dev_arg *da = (struct enum_dev_arg *)arg;
	if (status == 0)
		da->dev[da->n_dev++] = dev;
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

static void
signal_handler(int signum)
{
	static int terminating = 0;

	if (terminating) {
		return;
	}

	if (signum == SIGHUP)
		return;

	terminating = 1;

	log_error(lg, "Received signal [%s]! Terminating..", strsignal(signum));
	reptrans_destroy();
	reptrans_close_all_rt();

	if (daemonize)
		unlink(pidfile);

	signal(signum, SIG_DFL);
	raise(signum);
}

int
main(int argc, char* argv[]) {
	int err;
	struct repdev *devices[MAX_DEV];
	struct enum_dev_arg enum_arg = {0, devices};
	const char *transport[] = { "rtrd" };

	char *rdhold_fg = getenv("CCOW_RDHOLD_FG");
	daemonize = (rdhold_fg && *rdhold_fg == '1') ? 0 : 1;

	signal(SIGTERM, signal_handler);

	lg = Logger_create("rdhold");

	char *nedge_home = getenv("NEDGE_HOME");
	if (nedge_home)
		snprintf(pidfile, PATH_MAX, "%s/var/run/rdhold.pid",
		    nedge_home);
	else
		snprintf(pidfile, PATH_MAX, "%s/var/run/rdhold.pid",
		    QUOTE(INSTALL_PREFIX));

	if (pidfile_verify(pidfile, "rdhold") != 0)
		return 1;

	if (daemonize) {
		pid_t pid, sid;
		int fd;

		pid = fork();
		if (pid < 0) {
			fprintf(stderr, "Failed to fork() daemon!\n");
			return 1;
		}

		/* Parent process returns */
		if (pid)
			return 0;

		/* Create a new session, so to daemonize... */
		sid = setsid();
		if (sid < 0) {
			fprintf(stderr, "Failed to set daemon SID!");
			return 1;
		}

		int write_pidfile_res = write_pidfile(pidfile, sid);
		if (write_pidfile_res) {
			fprintf(stderr, "Failed to write pidfile. Terminating.\n");
			return 1;
		}

		if ((fd = open("/dev/null", O_RDWR, 0)) != -1) {
			dup2(fd, STDIN_FILENO);
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
			if (fd > STDERR_FILENO)
				close(fd);
		}
	}

	err =  reptrans_init(0, NULL, NULL,
		RT_FLAG_STANDALONE | RT_FLAG_RDONLY | RT_FLAG_RDHOLD,
		1, (char**)transport, NULL);
	if (err <= 0) {
		fprintf(stderr, "Cannot initiailze reptrans: %d\n", err);
		if (daemonize)
			unlink(pidfile);
		return -1;
	}

	err = reptrans_enum(NULL, &enum_arg, enum_dev__done_cb, 0);
	if (err) {
		fprintf(stderr, "Cannot enumerate reptrans: %d\n", err);
		goto _exit;
	}

	int i;
	for (i = 0; i < enum_arg.n_dev; i++) {
		log_notice(lg, "Dev(%s): hold set successfully",
		    devices[i]->name);
	}

	while (1)
		sleep(1);
_exit:
	if (daemonize)
		unlink(pidfile);
	reptrans_destroy();
	reptrans_close_all_rt();
	return -1;
}
