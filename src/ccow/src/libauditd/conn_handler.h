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
#ifndef CONN_HANDLER_H
#define CONN_HANDLER_H
#include "config.h"
#include "networking.h"

typedef struct {
	char address[INET6_ADDRSTRLEN];
	statsite_conn_info *conn;
	int ipc_fd;
} auditd_client_handle;

/**
 * This structure is used to communicate
 * between the connection handlers and the
 * networking layer.
 */
typedef struct {
    statsite_config *config;     // Global configuration
    statsite_conn_info *conn;    // Opaque handle into the networking stack
} statsite_conn_handler;

/**
 * Invoked to initialize the conn handler layer.
 */
void init_conn_handler(statsite_config *config);

/**
 * Invoked to when we've reached the flush interval timeout
 */
void flush_interval_trigger();

/**
 * Called when statsite is terminating to flush the
 * final set of metrics
 */
void final_flush();

/**
 * Invoked by the networking layer when there is new
 * data to be handled. The connection handler should
 * consume all the input possible, and generate responses
 * to all requests.
 * @arg handle The connection related information
 * @return 0 on success.
 */
int handle_client_connect(statsite_conn_handler *handle);
int handle_ccowd_message(char *buffer, int buffer_length);
int auditserver_subscriber(statsite_config *config, char *auditserver_id,
					char *auditserver_addr, char *topic);
int parse_auditd_client(statsite_conn_handler *handle);

#endif
