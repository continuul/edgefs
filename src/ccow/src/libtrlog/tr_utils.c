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

#include <errno.h>
#include <stdlib.h>

/* NEdge ccow headers */
#include <logger.h>

#include "trlog.h"


/** @return 0     - SUCCESS
 *          errno - otherwise
 */
static inline int
trlog_strtoull(const char *nptr, uint64_t *batch_seq_ts)
{
	errno = 0;

	*batch_seq_ts = strtoull(nptr, NULL, 10);

	return errno;
}

/** @return 0     - SUCCESS
 *          errno - otherwise
 */
int
trlog_parse_marker(const char *errmsg_prefix, const char *marker_name,
		char **marker_arr, int marker_arr_len,
		uint64_t *batch_seq_ts, uint64_t *batch_seq_prev_ts)
{
	int res;

	res = trlog_strtoull((char*)marker_arr[0], batch_seq_ts);

	if (NULL == errmsg_prefix)
		errmsg_prefix = "";

	if (res == EINVAL || res == ERANGE) {
		log_error(lg, "%sCannot convert %s TRLOG marker: %s %lu",
			errmsg_prefix, marker_name, (char*)marker_arr[0], *batch_seq_ts);
	}

	if (marker_arr_len < 2)
		return res;

	res = trlog_strtoull((char*)marker_arr[1], batch_seq_prev_ts);

	if (res == EINVAL || res == ERANGE) {
		log_error(lg, "%sCannot convert %s prev TRLOG marker: %s %lu",
			errmsg_prefix, marker_name,
			(char*)marker_arr[1], *batch_seq_prev_ts);
	}

	return res;
}

/** @return 0     - SUCCESS
 *          errno - otherwise
 */
int
trlog_read_marker_seq_tss(ccow_t tc, const char *errmsg_prefix, char *marker_name,
		uint64_t *batch_seq_ts, uint64_t *batch_seq_prev_ts)
{
	int err;
	int marker_arr_len;
	char *marker_arr[2];

	marker_arr[0] = (char *) je_calloc(1, MARKER_RECORD_MAXSIZE);
	marker_arr[1] = (char *) je_calloc(1, MARKER_RECORD_MAXSIZE);

	if (!marker_arr[0] || !marker_arr[1]) {
		return -ENOMEM;
	}


	*batch_seq_ts = 0;
	*batch_seq_prev_ts = 0;

	err = trlog_read_marker(tc, marker_name, marker_arr, &marker_arr_len);

	if (err) {
		je_free(marker_arr[0]);
		je_free(marker_arr[1]);
		return (err == -ENOENT) ? 0 : err;
	}

	assert(marker_arr_len >= 1);

	trlog_parse_marker(errmsg_prefix, marker_name, marker_arr, marker_arr_len,
		batch_seq_ts, batch_seq_prev_ts);

	if (NULL == errmsg_prefix)
		errmsg_prefix = "";

	log_debug(lg, "%sRead %s TRLOG marker_arr[0] %s, marker_arr[1] %s, seq_ts %lu seq_prev_ts %lu",
		errmsg_prefix, marker_name, marker_arr[0], marker_arr[1],
		*batch_seq_ts, *batch_seq_prev_ts);

	je_free(marker_arr[0]);
	je_free(marker_arr[1]);

	return 0;
}


int trlog_write_marker_seq_tss(ccow_t tc, char *marker_name,
		uint64_t batch_seq_ts, uint64_t batch_seq_prev_ts)
{
	char buf[24];
	char buf2[24];
	char *marker_arr[2];

	snprintf(buf, 24, "%023lu", batch_seq_ts);
	marker_arr[0] = buf;
	snprintf(buf2, 24, "%023lu", batch_seq_prev_ts);
	marker_arr[1] = buf2;

	log_debug(lg, "Write %s TRLOG marker_arr[0] %s, marker_arr[1] %s, seq_ts %lu seq_prev_ts %lu",
		marker_name, marker_arr[0], marker_arr[1],
		batch_seq_ts, batch_seq_prev_ts);

	return trlog_write_marker(tc, marker_name, marker_arr, 2);
}
