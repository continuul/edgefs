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
#ifndef __BUFCURSOR_H__
#define __BUFCURSOR_H__

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct buf_cursor {
	char *buf;		/* Original buffer pointer */
	char *curptr;		/* Current pointer */
	size_t curpos;		/* Current position in the buffer */
	size_t len;		/* Total buffer length */
	size_t avail_len;	/* Current available for writing */
} buf_cursor_t;

static inline void
buf_cursor_init(buf_cursor_t *cursor, char *str, size_t len)
{
	if (cursor) {
		cursor->buf = cursor->curptr = str;
		cursor->len = cursor->avail_len = len;
		cursor->curpos = 0;
	}
}

static inline void
buf_cursor_write(buf_cursor_t *cursor, const char *format, ...)
{
	if (cursor) {
		va_list ap;
		va_start(ap, format);
		cursor->curpos += vsnprintf(cursor->curptr, cursor->avail_len,
					format, ap);
		cursor->curptr = cursor->buf + cursor->curpos;
		cursor->avail_len = cursor->curpos < cursor->len ?
				    cursor->len - cursor->curpos : 0;
		va_end(ap);
	}
}

#ifdef	__cplusplus
}
#endif

#endif
