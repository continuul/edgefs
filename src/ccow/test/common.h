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
#ifndef __TEST_COMMON_H__
#define __TEST_COMMON_H__

#include <stdio.h>
#include <stdlib.h>
#include <uv.h>

#include "ccow.h"
#include <openssl/md5.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct cminfo {
	ccow_lookup_t iter;
	ccow_completion_t comp;
	char oid[256];
	char chunkmap_type[256];
	uint8_t fixed_depth;
	uint16_t fixed_width;
	uint32_t fixed_bs;
	uint16_t btree_order;
};

unsigned char* getMd5sum(char *input_buf, size_t size);

int test_send_multicast(char *addr, int port, char *buf, int len);

void put_simple(ccow_completion_t c, char *bid, char *oid, struct iovec *iov,
    size_t iovcnt, uint64_t off);

void put(ccow_t cl, char *bid, char *oid, struct iovec *iov, size_t iovcnt,
    uint64_t off, ccow_callback_t cb_async, void *arg);

void get_simple(ccow_completion_t c, char *bid, char *oid, struct iovec *iov,
    size_t iovcnt, uint64_t off, ccow_lookup_t *iter);

void get(ccow_t cl, char *bid, char *oid, struct iovec *iov, size_t iovcnt,
    uint64_t off, ccow_callback_t cb_async, void *arg, ccow_lookup_t *iter);

void delete(ccow_t cl, char *bid, char *oid, ccow_callback_t cb_async,
    void *arg);

/* Timer for auditserver sleep. */
void asleep();
/* mdtype is defined as :
 * #define CCOW_MDTYPE_METADATA	0x1
 * #define CCOW_MDTYPE_CUSTOM	0x2
 * #define CCOW_MDTYPE_ACL	0x4
 * #define CCOW_MDTYPE_NAME_INDEX 0x8
 * #define CCOW_MDTYPE_ALL	0xFF
 */
void dump_iter_to_stdout(ccow_lookup_t iter, int mdtype);

void get_offsets(ccow_t cl, char *bid, char *oid, size_t bs, int *offsets,
    int num_items);

void put_offsets(ccow_t cl, char *bid, char *oid, size_t bs, int *offsets,
    int num_items);

uint64_t sst_convert_bytes(const char * in_string);
#ifdef	__cplusplus
}
#endif

#endif
