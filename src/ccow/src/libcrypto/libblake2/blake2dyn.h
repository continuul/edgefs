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
#ifndef BLAKE2DYN_H
#define BLAKE2DYN_H

#include "blake2.h"
extern int (*blake2b_init_dyn)(blake2b_state*, size_t);
extern int (*blake2b_update_dyn)(blake2b_state *S, const void *in, size_t inlen);
extern int (*blake2b_final_dyn)(blake2b_state *S, void *out, size_t outlen);
extern int (*blake2b_dyn)(void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen);
extern int (*blake2bp_init_dyn)(blake2bp_state *S, size_t outlen);
extern int (*blake2bp_update_dyn)(blake2bp_state *S, const void *in, size_t inlen);
extern int (*blake2bp_final_dyn)(blake2bp_state *S, void *out, size_t outlen);
extern int (*blake2bp_dyn)(void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen);

#endif
