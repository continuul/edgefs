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

#ifndef NEDGE_PAYLOAD_S3_H
#define NEDGE_PAYLOAD_S3_H

#include <curl/curl.h>

#define EDGE_USER_AGENT "EdgeRTLFS/1.0"

struct payload_s3 {
	int ssl_en;
	char host[1024];
	char path[2048];
	int port;
	char *bucket_url;
	char *access_key;
	char *secret_key;
	char *aws_region;
	CURLSH *share;
	uv_mutex_t conn_lock;
};

int payload_s3_init(char *url, char *region, char *keyfile, struct payload_s3 **ctx_out);
void payload_s3_destroy(struct payload_s3 *ctx);
int payload_s3_put(struct payload_s3 *ctx, const uint512_t *chid, uv_buf_t *data);
int payload_s3_get(struct payload_s3 *ctx, const uint512_t *chid, uv_buf_t *outbuf);
int payload_s3_delete(struct payload_s3 *ctx, const uint512_t *chid);

#endif
