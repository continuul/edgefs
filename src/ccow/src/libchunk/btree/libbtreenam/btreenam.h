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
#ifndef __BTREENAM_H__
#define __BTREENAM_H__

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct _btn_key_
{
	uint32_t   len;
	uint32_t   val_len;
	uint8_t  key[];

} btn_key_t;

typedef struct _btn_data_
{
	struct refentry re;

} btn_data_t;

#define BTN_CHUNKMAP_FINALIZE	0x02

#ifdef	__cplusplus
}
#endif

#endif
