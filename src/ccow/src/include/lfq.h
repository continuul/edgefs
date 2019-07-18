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

#ifndef _LFQ_H
#define _LFQ_H

#include "ccowutil.h"
#include "uv.h"
#include "utringbuffer.h"

struct _lfqueue_t {
	UT_ringbuffer *ring;
	int popped_count;
	pthread_spinlock_t ring_lock;
};
typedef struct _lfqueue_t *lfqueue_t;

lfqueue_t lfqueue_create(size_t);
void lfqueue_destroy(lfqueue_t q);
void *lfqueue_dequeue(lfqueue_t);
int lfqueue_enqueue(lfqueue_t, void *);
int lfqueue_length(lfqueue_t q);
int lfqueue_cap(lfqueue_t q);

#endif /* _LFQ_H  */
