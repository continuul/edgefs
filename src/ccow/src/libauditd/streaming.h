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
#ifndef STREAMING_H
#define STREAMING_H
#include <stdio.h>
#include "metrics.h"

/**
 * This callback is used to stream data to the external command.
 * It is provided with all the metrics and a pipe. The command should
 * return 1 to terminate. See metric_callback for more info.
 */
typedef int(*stream_callback)(FILE *pipe, void *data, metric_type type, char *name, void *value);

/**
 * Streams the metrics stored in a metrics object to an external command
 * @arg m The metrics object to stream
 * @arg data An opaque handle passed to the callback
 * @arg cb The callback to invoke
 * @arg cmd The command to invoke, invoked with a shell.
 * @return 0 on success, or the value of stream callback.
 */
int stream_to_command(metrics *m, void *data, stream_callback cb, char *cmd);

#endif

