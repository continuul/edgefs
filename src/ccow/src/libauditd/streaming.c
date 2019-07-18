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
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <errno.h>

#include "ccowutil.h"
#include "logger.h"
#include "streaming.h"

// Struct to hold the callback info
struct callback_info {
    FILE *f;
    void *data;
    stream_callback cb;
};

/**
 * Local callback that invokes the user specified callback with the pip
 */
static int stream_cb(void *data, metric_type type, char *name, void *val) {
    struct callback_info *info = data;
    return info->cb(info->f, info->data, type, name, val);
}

/**
 * Streams the metrics stored in a metrics object to an external command
 * @arg m The metrics object to stream
 * @arg data An opaque handle passed to the callback
 * @arg cb The callback to invoke
 * @arg cmd The command to invoke, invoked with a shell.
 * @return 0 on success, or the value of stream callback.
 */
int stream_to_command(metrics *m, void *data, stream_callback cb, char *cmd)
{
    int i = 0;
    char *argv[32];

    if (!cmd || *cmd == '\0')
        return 0;

    log_trace(lg, "cmd: %s", cmd);
    char *sp;
    char *token = strtok_r(cmd, " ", &sp);
    while (token != NULL) {
        argv[i++] = token;
        token = strtok_r(NULL, " ", &sp);
    }
    argv[i++] = NULL;

    log_trace(lg, "argv[0]:%s: args[1]: %s:", argv[0], argv[1]);
    struct stat sb;
    int rc;
    if ((rc = stat(argv[0], &sb)) == -1) {
        log_error(lg, "stat failed!: %d:%s", rc, strerror(errno));
        return -1;
    }

    // Create a pipe to the child
    int filedes[2] = {0, 0};
    int res = pipe(filedes);
    if (res < 0) return res;


    // Fork and exec
    int status = 0;
    pid_t pid = fork();
    if (pid < 0) return res;

    // Check if we are the child
    if (pid == 0) {
        // Set stdin to the pipe
        if (dup2(filedes[0], STDIN_FILENO)){
            log_error(lg, "Failed to initialize stdin!: %s", strerror(errno));
            perror("Failed to initialize stdin!");
            exit(250);
        }
        close(filedes[1]);

        // Try to run the command
        res = execve(argv[0], argv, environ);
        if (res != 0) {
            log_error(lg, "Failed to execute command!");
            perror("Failed to execute command!");
        }

        // Always exit
        exit (255);
    } else {
        // Close the read end
        close(filedes[0]);
        if (waitpid(pid, &status, WNOHANG) != 0)
            return -1;
    }

    // Create a file wrapper
    FILE *f = fdopen(filedes[1], "w");

    // Wrap the relevant pointers
    struct callback_info info = {f, data, cb};

    // Start iterating
    metrics_iter(m, &info, stream_cb);

    // Close everything out
    fclose(f);
    close(filedes[1]);

    // Wait for termination
    do {
        if (waitpid(pid, &status, 0) < 0) break;
        usleep(100000);
    } while (!WIFEXITED(status));

    log_trace(lg, "stream terminated");
    // Return the result of the process
    return WEXITSTATUS(status);
}

