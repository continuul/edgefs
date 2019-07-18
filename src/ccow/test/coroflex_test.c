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
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <signal.h>

#include "ccowutil.h"
#include "ccow.h"
#include "cmocka.h"

Logger lg;

static void
signal_servers(int numservers, pid_t *pid, int signal)
{
	for (int i = 0; i < numservers; i++)
		kill(pid[i], signal);
}

static void
spawn_servers(int numservers, int numdevices, pid_t *pid, int logsuffix)
{
	char nd[32];
	char logfile[64];

	for (int i = 0; i < numservers; i++) {
		snprintf(logfile, 64, "/tmp/coroflex-%d.%d", logsuffix, i);
		snprintf(nd, 32, "%d", numdevices);
		fprintf(stdout, "Server %d numdevices %d: Redirecting output to %s\n",
			i, numdevices, logfile);

		pid[i] = fork();
		if (pid[i] < 0) {
			fprintf(stderr, "Error forking a child\n");
			return;
		}

		if (pid[i] == 0) {
			char *argv[] = { "coroflex", "-d", nd, "-f", logfile, NULL };
			execvp("coroflex", argv);
			fprintf(stderr, "Error executing program\n");
			return;
		}
	}
}

// 10 servers with 5 devices each.
static void
coroflex_test_1()
{
	int numservers = 10, numdevices = 5;
	pid_t pids[10];

	spawn_servers(numservers, numdevices, pids, 1);
	sleep(5);
	signal_servers(numservers, pids, SIGINT);
}

// 10 servers with 5 devices each.
// 5 servers leave and join again.
static void
coroflex_test_2()
{
	int numservers = 10, numdevices = 5;
	pid_t pids[10];

	spawn_servers(numservers, numdevices, pids, 2);
	sleep(5);
	for (int i = 0; i < 2; i++) {
		signal_servers(5, pids, SIGUSR1);
		sleep(5);
	}
	signal_servers(numservers, pids, SIGINT);
}

// 5 servers with 20 devices each.
// 2 servers leave and join again 2 times
static void
coroflex_test_3()
{
	int numservers = 5, numdevices = 20;
	pid_t pids[10];

	spawn_servers(numservers, numdevices, pids, 3);
	sleep(5);
	for (int i = 0; i < 4; i++) {
		signal_servers(2, pids, SIGUSR1);
		sleep(8);
	}
	signal_servers(numservers, pids, SIGINT);
}

int
main(int argc, char **argv)
{
	lg = Logger_create("coroflex_test");

	const UnitTest tests[] = {
		unit_test(coroflex_test_1),
		unit_test(coroflex_test_2),
		unit_test(coroflex_test_3),
	};

	return run_tests(tests);
}

