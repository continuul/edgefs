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

#include <linux/limits.h>
#include <errno.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <net/if.h>
#include <signal.h>
#include <uv.h>

#include <isgw-api.h>
#include <logger.h>

#include <engine/engine-api.h>
#include <server/server-api.h>
#include <nn_ipc/nn_ipc-api.h>

#include "provider/provider.h"

static struct isgw_config g_config;
static struct isgw_server g_server;
static struct isgw_engine g_engine;
static struct isgw_nn_ipc g_nn_ipc;

static int daemonize;
static char pidfile[PATH_MAX];

static void
isgw_daemon_term()
{
	isgw_nn_ipc_join(&g_nn_ipc);
	isgw_engine_join(&g_engine);

	isgw_nn_ipc_destroy(&g_nn_ipc);
	isgw_engine_destroy(&g_engine);
	log_info(lg, "ISGW engine destroyed");

	isgw_server_destroy(&g_server);
	log_info(lg, "ISGW server destroyed");

	isgw_config_destroy(&g_config);
	log_info(lg, "ISGW config destroyed");
}

static void
isgw_logs_init()
{
	lg = Logger_create("isgwd");

	if (!lg) {
		fprintf(stderr, "Failed to create logger\n");
		exit(ENOMEM);
	}

	char *env_level = getenv(CCOW_LOG_LEVEL);
	if (env_level)
		lg->level = atoi(env_level);
	else
		lg->level = LOG_LEVEL_INFO;
}


static int
isgw_daemon_init()
{
	int err;

	err = isgw_config_init(&g_config);
	if (err)
		return err;

	memset(&g_engine, 0, sizeof(g_engine));
	err = isgw_engine_init(&g_engine, &g_config);
	if (err)
		return err;

	memset(&g_server, 0, sizeof(g_server));
	err = isgw_server_init(&g_server, &g_engine, &g_config);
	if (err)
		return err;

	memset(&g_nn_ipc, 0, sizeof(g_nn_ipc));
	err = isgw_nn_ipc_init(&g_nn_ipc, &g_engine, &g_config);
	if (err)
		return err;

	log_notice(lg, "Inter-Segment Gateway service now initialized");

	return 0;
}

/** Dumb async-signal-safe dprintf() replacement.
 *
 *  According to man 7 signal-safety strcat() and write() are signal-safe,
 *  so our function also is signal-safe. */
static void write_signal_msg(int out_fd, const char *init_str, int signum, const char *end_str)
{
	char msg[LOG_MAX_MSG_LEN] = "";
	/** Preserve errno for consistency of interupted context */
	int err_no = errno;

	strcat(msg, init_str);
	strcat(msg, strsignal(signum));
	strcat(msg,	end_str);

	if (write(out_fd, msg, strlen(msg))) { }

	errno = err_no;
}

/** @warning Please do no use here any log_*() and *printf() functions,
 *           because it will result in heap corruption and other really
 *           challenging bugs */
static void
signal_handler(int signum)
{
	static int isgw_terminating;
	if (isgw_terminating) {
		/** SIGABRT, SIGQUIT, SIGSEGV */
		if (signum == SIGABRT || signum == SIGQUIT || signum == SIGSEGV) {
			/** Currently there are no ways to output msg in daemon mode */
			if(!daemonize) {
				write_signal_msg(STDOUT_FILENO,
						">>> Received signal [", signum,
						"]while exiting! Immediately exit.. <<<\n");
			}

			signal(signum, SIG_DFL);
			raise(signum);

			/** This return will be never executed in our application,
			 *  because raise() will not exit. */
			return;
		}


		/** Currently there are no ways to output msg in daemon mode */
		if(!daemonize) {
			write_signal_msg(STDOUT_FILENO,
					">>> Received signal [", signum,
					"]while exiting! Ignored.. <<<\n");
		}
		return;
	}

	if (signum == SIGHUP)
		return;

	if (signum == SIGUSR1) {
		/* log_notice(lg, "Received SIGUSR1, request engine refresh"); */
		g_engine.refresh = 1;
		return;
	}

	if (signum == SIGINT || signum == SIGTERM) {
		/** Currently there are no ways to output msg in daemon mode */
		if(!daemonize) {
			write_signal_msg(STDOUT_FILENO,
					">>> Received signal [", signum, "]! Terminating process started.. <<<\n");
		}

		isgw_terminating = 1;
		g_engine.terminating = 1;
		g_server.terminating = 1;
		g_nn_ipc.terminating = 1;

		return;
	}

	/** SIGABRT, SIGQUIT, SIGSEGV, ... */

	/** Currently there are no ways to output msg in daemon mode */
	if(!daemonize) {
		write_signal_msg(STDOUT_FILENO,
				">>> Received signal [", signum, "]! Immediately exit.. <<<\n");
	}

	signal(signum, SIG_DFL);
	raise(signum);

	/** This return will be never executed in our application,
	 *  because raise() will not exit. */
	return;
}

static void
fprint_usage(FILE*o, const char *name)
{
	fprintf(o, "Usage: %s [ -h ] [ -r <replication_mode> ] [ -f <service>,<service>,... ]\n", name);
	fprintf(o, "\t[ -s <service> ] [ -c <service> ] ...\n");

	fflush(o);
}

static void
fprint_help(FILE*o, const char *name)
{
	fprint_usage(o, name);

	fprintf(o, "\n");
	fprintf(o, " -r Override replication mode\n");
	fprintf(o, "\tValues: initial=1, continuous=2, full(init+cont)=3\n");
	fprintf(o, "\tValues: comma-separated list of services\n");
	fprintf(o, " -c run 'Client' service\n");
	fprintf(o, " -s run 'Server' service\n");
	fprintf(o, " -h print this help message to stdout and exit\n");

	fflush(o);
}

static int
parse_options(int argc, char **argv, int daemonize, struct isgw_config *config)
{
	int opt, err = 0;

	if (argc == 1) {
		fprint_usage(stderr, argv[0]);
		return -EINVAL;
	}

	while ((opt = getopt(argc, argv, "f:r:s:c:h")) != -1) {
		switch (opt) {
		case 's':
			err = isgw_config_add_server(config, daemonize, optarg);
			break;
		case 'c':
			err = isgw_config_add_client(config, daemonize, optarg);
			break;
		case 'r':
			isgw_config_replication_mode(config, optarg);
			break;
		case 'h':
			fprint_help(stdout, argv[0]);
			exit(EXIT_SUCCESS);

		default:
			fprint_usage(stderr, argv[0]);
			err = -EINVAL;
			break;
		}
		if (err)
			return err;
	}

	return 0;
}

static void isgwd_daemonize() {
	pid_t pid, sid;
	int fd;

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "Failed to fork() daemon!\n");
		exit(EXIT_FAILURE);
	}

	/* Parent process returns */
	if (pid)
		exit(EXIT_SUCCESS);

	/* Create a new session */
	sid = setsid();
	if (sid < 0) {
		fprintf(stderr, "Failed to set daemon SID!\n");
		exit(EXIT_FAILURE);
	}

	/* Currenly we still should set container-wide pid if we run in container */
	if (isgw_get_docker_service_name()) {
		if (isgw_write_pidfile(pidfile, sid)) {
			fprintf(stderr, "Failed to write pidfile. Terminating.\n");
			exit(EXIT_FAILURE);
		}
	}

	if ((fd = open("/dev/null", O_RDWR, 0)) != -1) {
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		if (fd > STDERR_FILENO)
			close(fd);
	}
}

int
main(int argc, char **argv)
{
	char *ccowlog = getenv("CCOW_LOG_STDOUT");
	daemonize = (ccowlog && *ccowlog == '1') ? 0 : 1;

	/* Currenly we still should check container-wide pid if we run in container */
	if (isgw_get_docker_service_name()
			&& -1 != isgw_service_readpid(pidfile, '\0', NULL)) {
		fprintf(stderr, "Daemon already running!\n");
		return 1;
	}

	if (daemonize)
		isgwd_daemonize();

	isgw_logs_init();

	int err = parse_options(argc, argv, daemonize, &g_config);
	if (err)
		return err;

	struct rlimit core_limits;
	core_limits.rlim_cur = core_limits.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_CORE, &core_limits);

	sigset_t set;
	sigemptyset(&set);
	/** Postponing SIGINT processing until end of initialization */
	sigaddset(&set, SIGINT);
	int s = sigprocmask(SIG_BLOCK, &set, NULL);
	if (s != 0) {
		fprintf(stderr,
				"sigprocmask(): [%s]! Something really bad happenend. Terminating.\n",
				strerror(errno));
		return 1;
	}

	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, signal_handler);
	signal(SIGHUP, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGABRT, signal_handler);
	/** @todo Set alternate stack using sigaltstack() to handle StackOverflow.
	 *        Description: 'man 7 sigaltstack', chapter 'NOTES' */
	signal(SIGSEGV, signal_handler);
	signal(SIGQUIT, signal_handler);
	signal(SIGUSR1, signal_handler);

	err = isgw_daemon_init();
	if (err) {
		isgw_daemon_term();
		return err;
	}

	/** Allow processing of SIGINT in this thread only */
	s = pthread_sigmask(SIG_UNBLOCK, &set, NULL);
	if (s != 0) {
		log_error(lg,
				"pthread_sigmask(): [%s]! Please check the systems settings.",
				strerror(s));
	}
	isgw_daemon_term();

	return 0;
}
