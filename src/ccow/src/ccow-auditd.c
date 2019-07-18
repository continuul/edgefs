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
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>

#include "ccowutil.h"
#include "auditd.h"

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
main(int argc, char **argv)
{
	char *ccowlog = getenv("CCOW_LOG_STDOUT");
	auditd_daemonize = (ccowlog && *ccowlog == '1') ? 0 : 1;

	auditd_setup_pidfile_var();

	if (pidfile_verify(auditd_pidfile, "ccow-auditd") != 0)
		return 1;

	if (auditd_daemonize) {
		pid_t pid, sid;
		int fd;

		pid = fork();
		if (pid < 0) {
			fprintf(stderr, "Failed to fork() daemon\n");
			return 1;
		}

		/* Parent process returns */
		if (pid)
			return 0;

		/* Create a new session, so to daemonize... */
		sid = setsid();
		if (sid < 0) {
			fprintf(stderr, "Failed to set daemon SID\n");
			return 1;
		}

		int write_pidfile_res = write_pidfile(auditd_pidfile, sid);
		if (write_pidfile_res) {
			fprintf(stderr, "Failed to write pidfile\n");
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

	int err = auditd_init();
	if (!err)
		auditd_term(1 /* wait for signals */);

	if (auditd_daemonize)
		unlink(auditd_pidfile);
	return err;
}
