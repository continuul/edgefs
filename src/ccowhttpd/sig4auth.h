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
#ifndef sig4auth_h
#define sig4auth_h

#ifdef __cplusplus
extern "C" {
#endif

#include "param.h"
#include "request_util.h"

int sig4auth_sign_request(h2o_mem_pool_t *pool, param_vector *query_params, param_vector *headers, char *method, char *path,
		char *credential_scope, char *signedHeaders, char *secret, char *region,
		char *signature, int signature_max_size);

#ifdef __cplusplus
}
#endif

#endif
