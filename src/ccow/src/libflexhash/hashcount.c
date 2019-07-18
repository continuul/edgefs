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
#include <pthread.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "ccowutil.h"
#include "logger.h"
#include "hashcount.h"

struct hashcount *g_hashcount = NULL;

struct hashcount *
hashcount_create(int numrows)
{
	struct hashcount *hc = NULL;
	int i;

	if (numrows < 1) {
		log_error(lg, "Invalid value for table initialization: "
		    "numrows = %d\n", numrows);
		return NULL;
	}
	hc = (struct hashcount *)
		je_calloc(1, sizeof (struct hashcount));
	if (hc == NULL) {
		return NULL;
	}

	hc->entry = (uint16_t *)
		je_calloc(numrows, sizeof (uint16_t));
	if (hc->entry == NULL) {
		je_free(hc);
		return NULL;
	}
	for (i = 0; i < numrows; i++) {
		hc->entry[i] = 0;
	}
	hc->numrows = numrows;

	return hc;
}

void
hashcount_destroy(struct hashcount *hc)
{
	if (hc == NULL) {
		log_error(lg, "Unable to destroy a NULL ");
		assert(0);
	}

	je_free(hc->entry);
	je_free(hc);
}

uint16_t
hashcount_incr(struct hashcount *hc, hcrow_t rowid)
{
	uint16_t count = hc->entry[rowid];
	return count++;
}

uint16_t
hashcount_decr(struct hashcount *hc, hcrow_t rowid)
{
	uint16_t count = hc->entry[rowid];
	return count--;
}

uint16_t
hashcount_entry(struct hashcount *hc, hcrow_t rowid)
{
	uint16_t count = hc->entry[rowid];
	return count;
}

struct hashcount *
hashcount_default()
{
	if (g_hashcount == NULL) {
		log_error(lg, "Attept to access unitialized hashcount table");
		assert(0);
	}
	return g_hashcount;
}
