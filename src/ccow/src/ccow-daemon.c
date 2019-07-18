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
#include <unistd.h>
#include <limits.h>
#include <getopt.h>
#include "reptrans-data.h"

#include "ccowutil.h"
#include "ccowd.h"

extern void *ccow_daemon;
static int daemonize;
static char pidfile[PATH_MAX];

volatile int initialized;

static void
signal_handler(int signum)
{
	static int terminating = 0;

	if(!initialized) {
		log_warn(lg, "Received signal [%s] while not initialized! Ignoring..",
			strsignal(signum));
		return;
	}

	if (terminating) {
		log_warn(lg, "Received signal [%s] while exiting! Ignoring..",
		    strsignal(signum));
		return;
	}

	if (signum == SIGHUP)
		return;

	terminating = 1;

	log_error(lg, "Received signal [%s]! Terminating..", strsignal(signum));
	ccow_daemon_term();

	if (daemonize)
		unlink(pidfile);

	signal(signum, SIG_DFL);
	raise(signum);
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
usage(void) {
	printf("\n"
	"USAGE:\n"
	"	./ccow-daemon [-h] [--log-flush NAME]"
	"\n"
	"	-h Display this help message and exit.\n"
	"\n"
	"	--log-flush NAME return non-zero result in case of any error or flush journal on success."
	"\n"
	"	--log-recovery NAME removes log on secified device and returns result of removal operation"
	"\n"
	"	--mdreloc TTAG moves data off MD offload to HDD for specified TTAG"
	"\n");
	exit(EXIT_SUCCESS);

}

int
main(int argc, char **argv)
{
	struct ccowd_params params;
	int err, c;

	char *ccowlog = getenv("CCOW_LOG_STDOUT");
	daemonize = (ccowlog && *ccowlog == '1') ? 0 : 1;

	initialized = 0;

	memset(&params, 0, sizeof (params));
	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"help",	0,		0,  'h' },
			{"log-flush", required_argument, 0,  0 },
			{"log-recovery", required_argument, 0,  1 },
			{"mdreloc", required_argument, 0,  2 },
			{0,         0,	                 0,  0 }
		};

		c = getopt_long(argc, argv, "h",
				long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
			case 0:
				params.log_flush = 1;
				params.name = optarg;
				daemonize = 0;
				break;
			case 1:
				params.log_recovery = 1;
				params.name = optarg;
				daemonize = 0;
				break;
			case 2:
				params.relocate_ttag = -1;
				for (size_t i = 0; i < TT_LAST; i++) {
					if (!strcmp(optarg, type_tag_name[i])) {
						params.relocate_ttag = i;
						break;
					}
				}
				if (params.relocate_ttag != TT_VERSION_MANIFEST &&
					params.relocate_ttag != TT_CHUNK_MANIFEST &&
					params.relocate_ttag != TT_PARITY_MANIFEST)
				{
					fprintf(stderr, "Unsupported type tag %s\n", optarg);
					exit(-1);
				}

				if (params.relocate_ttag >= 0)
					params.relocate_mdoffload = 1;
				else {
					fprintf(stderr, "Unknown type tag %s", optarg);
					exit(-1);
				}
				break;
			case '?':
			case 'h':
				usage();
				break;
			default:
				fprintf(stderr, "cmdline parse error\n");
				exit(-1);
		}
	}

	signal(SIGTERM, signal_handler);

	char *nedge_home = getenv("NEDGE_HOME");
	if (nedge_home)
		snprintf(pidfile, PATH_MAX, "%s/var/run/ccowd.pid",
		    nedge_home);
	else
		snprintf(pidfile, PATH_MAX, "%s/var/run/ccowd.pid",
		    QUOTE(INSTALL_PREFIX));

	if (pidfile_verify(pidfile, "ccow-daemon") != 0)
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

	err = ccow_daemon_init(&params);
	initialized = 1;

	while (!err && ccow_daemon)
		usleep(100000);

	if (daemonize)
		unlink(pidfile);

	if (params.log_flush || params.log_recovery)
		return params.log_err;
	return err;
}
