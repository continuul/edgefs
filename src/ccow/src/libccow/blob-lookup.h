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
#ifndef __BLOB_LOOKUP_H__
#define __BLOB_LOOKUP_H__

#ifdef	__cplusplus
extern "C" {
#endif

#define BLOB_LOOKUP_MAX_RETRY		40
#define BLOB_LOOKUP_TIMEOUT_MS		2000
#define BLOB_LOOKUP_ERROR_RETRY_TIMEOUT_MS	250

int ccow_blob_lookup_request(struct ccow_network *netobj, const uint512_t* chid,
	uint8_t ttag, uint8_t hash_type, struct ccow_completion *c,
	uint128_t* vdevs_out, size_t* n_vdev_max);

#ifdef	__cplusplus
}
#endif

#endif
