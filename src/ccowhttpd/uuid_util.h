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
#ifndef uuid_util_h
#define uuid_util_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <uuid/uuid.h>

#define UUID_BUFFER 64

static inline void
uuid_util_generate(uuid_t uuid)
{
	uuid_generate_time_safe(uuid);
}

static inline void
uuid_util_str(uuid_t uuid, char *buffer)
{
	uuid_unparse_lower(uuid, buffer);
}

static inline int
uuid_util_parse(char *buffer, uuid_t uuid)
{
	return uuid_parse(buffer, uuid);
}

static inline int
uuid_util_compare(uuid_t uuid1, uuid_t uuid2)
{
	return uuid_compare(uuid1, uuid2);
}

#ifdef __cplusplus
}
#endif

#endif
