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
#ifndef ccowobj_h
#define ccowobj_h

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>

#include "objio.h"
#include "ccowobj_generator.h"

enum {
    CCOWOBJ_FLAG_NO_ETAG	= 0x1,
    CCOWOBJ_FLAG_DIR_LISTING	= 0x2
};

typedef struct ccowobj_handler {
	h2o_handler_t super;
	h2o_iovec_t conf_path; /* has "/" appended at last */
	h2o_iovec_t tenant_path; /* has "/" appended at last */
	h2o_mimemap_t *mimemap;
	int flags;
	int authOn;
	int aclOn;
	int subdomains;
	char tid[MAX_ITEM_SIZE];
	char cid[MAX_ITEM_SIZE];
	size_t cid_size, tid_size;
	char region[256];
} ccowobj_handler_t;


/**
 * registers a handler that serves bucket
 * @param pathconf
 * @param real_path
 * @param mimemap the mimemap (h2o_mimemap_create is called internally if the argument is NULL)
 */
ccowobj_handler_t *ccowobj_register(h2o_pathconf_t *pathconf, const char *real_path,
           h2o_mimemap_t *mimemap, int authOn, int aclOn, char *region, int subdomains, int flags);

void ccowobj_deregister_ctx(ccowobj_handler_t *h, h2o_context_t *ctx);

/**
 * returns the associated mimemap
 */
h2o_mimemap_t *ccowobj_get_mimemap(ccowobj_handler_t *handler);


#ifdef __cplusplus
}
#endif

#endif
