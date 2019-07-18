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
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <unistd.h>
#include <limits.h>
#include <stdbool.h>


#ifndef _LOGGER_H_
#define _LOGGER_H_

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef unlikely
#ifdef __GNUC__
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif
#endif

#define CCOW_STRINGIFY(s)   CCOW_STRINGIFY_X (s)
#define CCOW_STRINGIFY_X(s) #s

#define LOG_LEVEL_DUMP  0
#define LOG_LEVEL_TRACE 1
#define LOG_LEVEL_DEBUG 2
#define LOG_LEVEL_INFO  3
#define LOG_LEVEL_WARN  4
#define LOG_LEVEL_ERROR 5
#define LOG_LEVEL_NOTICE 6
#define LOG_LEVEL_ALERT 7

#define LOG_COLOR_DEFAULT "\033[39m"
#define LOG_COLOR_MAGENTA "\x1b[35m"
#define LOG_COLOR_BLUE   "\x1b[34m"
#define LOG_COLOR_RED    "\x1b[31m"
#define LOG_COLOR_YELLOW "\x1b[33m"
#define LOG_COLOR_GREEN  "\x1b[32m"
#define LOG_COLOR_CYAN   "\x1b[36m"
#define LOG_COLOR_RESET  "\x1b[0m"

#define LOG_LEVEL_CHARS "HTDIWEN"
/* @warning This size should be larger than flexhash-checkpoint.json.
 * 1024 is too small. 4096 looks good enough. */
#define LOG_MAX_MSG_LEN 4096
#define LOG_DEFAULT_BUFSIZE (256*1024)

#define	LOG_FLAGS_AUTOFLUSH	(1 << 0)	/* Auto flush output. */

#define CCOW_LOG_BUFSIZE "CCOW_LOG_BUFSIZE"
#define CCOW_LOG_COLORS	"CCOW_LOG_COLORS"
#define CCOW_LOG_LEVEL	"CCOW_LOG_LEVEL"
#define CCOW_LOG_SYSLOG	"CCOW_LOG_SYSLOG"
#define CCOW_LOG_MODULES	"CCOW_LOG_MODULES"
#define CCOW_LOG_STDOUT "CCOW_LOG_STDOUT"
#define CCOW_LOG_AUTOFLUSH "CCOW_LOG_AUTOFLUSH"
#define CCOW_LOG_ROTATE_LINES "CCOW_LOG_ROTATE_LINES"
#define CCOW_LOG_ROTATE_MODE "CCOW_LOG_ROTATE_MODE"
#define CCOW_LOG_MAX_LINES 10000000
#define CCOW_LOG_ROTATE_OVERWRITE 1
#define CCOW_LOG_ROTATE_RENAME 2

#define ___FILE___ (strrchr(__FILE__, '/') ? \
    strrchr(__FILE__, '/') + 1 : __FILE__)

#if 0
#define is_dbg_flexhash ( \
    strcmp(___FILE___, "flexhash.c") == 0 || \
    strcmp(___FILE___, "server-list.c") == 0 || \
    strcmp(___FILE___, "clengine.c") == 0 || \
    strcmp(___FILE___, "corosync.c") == 0 || \
    strcmp(___FILE___, "cltopo.c") == 0 || \
    strcmp(___FILE___, "cltopo-server-list.c") == 0)
#define is_dbg_ccowio ( \
    strcmp(___FILE___, "ccow.c") == 0)
#define is_dbg_get ( \
    strcmp(___FILE___, "getcommon_client.c") == 0 || \
    strcmp(___FILE___, "getcommon_server.c") == 0)
#define is_dbg_put ( \
    strcmp(___FILE___, "putcommon_client.c") == 0 || \
    strcmp(___FILE___, "putcommon_server.c") == 0)
#define is_dbg_namedget ( \
    strcmp(___FILE___, "named-get.c") == 0)
#define is_dbg_unnamedget ( \
    strcmp(___FILE___, "unnamed-get.c") == 0)
#define is_dbg_unnamedput ( \
    strcmp(___FILE___, "unnamed-put.c") == 0)
#define is_dbg_namedput ( \
    strcmp(___FILE___, "named-put.c") == 0)
#define is_dbg_reptrans ( \
    strcmp(___FILE___, "reptrans.c") == 0)
#define is_dbg_verify ( \
    strcmp(___FILE___, "verify.c") == 0)
#define is_dbg_ngrequest ( \
    strcmp(___FILE___, "ngrequest.c") == 0 || \
    strcmp(___FILE___, "ngrequest-send.c") == 0 || \
    strcmp(___FILE___, "ngrequest-count-srv.c") == 0 || \
    strcmp(___FILE___, "ngrequest-count.c") == 0)
#define is_dbg_comp (is_dbg_flexhash)
#else
#define is_dbg_comp (0)
#endif

typedef struct LOGGER {
	int level;
	int colors;
	int flags;
	unsigned int max_lines;
	volatile unsigned long lines_count;
	volatile unsigned long logsync;
	volatile unsigned long logsync1;
	int mode;
	FILE *file;
	FILE *file_bt;
	char logname[64];
	char file_name[PATH_MAX];
	char host_buf[256];
	char *modules;
} LOGGER;

typedef LOGGER* Logger;

/* Convenient common place for declaration */
extern Logger lg;

Logger Logger_create(const char *logname);
Logger Logger_init(LOGGER *lg, const char *logname);
void Logger_destroy(LOGGER *lg);
void Logger_hup(LOGGER *lg);

int log_module(Logger l, const char *module);

void log_flush(Logger l);
/** @param flush    - true  - log should be flushed just after adding the message
 *                  - false - log should be flushed according to autoflush policy */
void log_add_v(Logger l, int level, bool flush, const char *format, va_list args);

/* Urgent important messages */
static inline void
log_add_flush_f(Logger l, int loglevel, const char *fmt, ...)
		__attribute__((format(printf, 3, 4)));
/* Casual messages */
static inline void
log_add_autoflush_f(Logger l, int loglevel, const char *fmt, ...)
		__attribute__((format(printf, 3, 4)));

static inline void
log_add_flush_f(Logger l, int loglevel, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_add_v(l, loglevel, true, fmt, ap);
	va_end(ap);
}

static inline void
log_add_autoflush_f(Logger l, int loglevel, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_add_v(l, loglevel, false, fmt, ap);
	va_end(ap);
}


#define log_alert(l, fmt, ...) do { \
		if (likely(LOG_LEVEL_DEBUG < l->level)) \
			log_add_flush_f(l, LOG_LEVEL_ALERT, \
				"%14s:%-4d : " fmt, ___FILE___, __LINE__, \
				##__VA_ARGS__); \
		else \
			log_add_flush_f(l, LOG_LEVEL_ALERT, \
				"%14s:%-4d : %s(): " fmt, ___FILE___, __LINE__, \
				__func__, ##__VA_ARGS__); \
} while (0)

#define log_notice(l, fmt, ...) do { \
		if (likely(LOG_LEVEL_DEBUG < l->level)) \
			log_add_flush_f(l, LOG_LEVEL_NOTICE, \
				"%14s:%-4d : " fmt, ___FILE___, __LINE__, \
				##__VA_ARGS__); \
		else \
			log_add_flush_f(l, LOG_LEVEL_NOTICE, \
				"%14s:%-4d : %s(): " fmt, ___FILE___, __LINE__, \
				__func__, ##__VA_ARGS__); \
} while (0)

#define do_log_info(l)  (LOG_LEVEL_INFO >= l->level || (l->modules && log_module(l, ___FILE___)))

#define log_info(l, fmt, ...) do { \
	if (likely(LOG_LEVEL_INFO >= l->level) || \
		(l->modules && log_module(l, ___FILE___))) { \
		if (likely(LOG_LEVEL_DEBUG < l->level)) \
			log_add_autoflush_f(l, LOG_LEVEL_INFO, \
				"%14s:%-4d : " fmt, ___FILE___, __LINE__, \
				##__VA_ARGS__); \
		else \
			log_add_autoflush_f(l, LOG_LEVEL_INFO, \
				"%14s:%-4d : %s(): " fmt, ___FILE___, __LINE__, \
				__func__, ##__VA_ARGS__); \
	} \
} while (0)

#define do_log_warn(l)  (LOG_LEVEL_WARN >= l->level || (l->modules && log_module(l, ___FILE___)))

#define log_warn(l, fmt, ...) do { \
	if (unlikely(LOG_LEVEL_WARN >= l->level) || \
		(l->modules && log_module(l, ___FILE___))) { \
		if (likely(LOG_LEVEL_DEBUG < l->level)) \
			log_add_autoflush_f(l, LOG_LEVEL_WARN, \
					"%14s:%-4d : " fmt, ___FILE___, __LINE__, \
				##__VA_ARGS__); \
		else \
			log_add_autoflush_f(l, LOG_LEVEL_WARN, \
				"%14s:%-4d : %s(): " fmt, ___FILE___, __LINE__, \
				__func__, ##__VA_ARGS__); \
	} \
} while (0)

#define log_error(l, fmt, ...) do { \
		if (likely(LOG_LEVEL_DEBUG < l->level)) \
			log_add_flush_f(l, LOG_LEVEL_ERROR, \
				"%14s:%-4d : " fmt, ___FILE___, __LINE__, \
				##__VA_ARGS__); \
		else \
			log_add_flush_f(l, LOG_LEVEL_ERROR, \
				"%14s:%-4d : %s(): " fmt, ___FILE___, __LINE__, \
				__func__, ##__VA_ARGS__); \
} while (0)

#define log_softerror(l, err, fmt, ...) do { \
	if (err == ENOENT || err == -ENOENT || err == EEXIST || \
	    err == -EEXIST || err == EPERM || err == -EPERM || err == ENOTEMPTY) { \
		log_warn(l, "error: %d, " fmt, err, ##__VA_ARGS__); \
	} else { \
		log_error(l, "error: %d, " fmt, err, ##__VA_ARGS__); \
	} \
} while (0)

#define do_log_debug(l)  (LOG_LEVEL_DEBUG >= l->level || (l->modules && log_module(l, ___FILE___)))

#define log_debug(l, fmt, ...) do { \
	if (unlikely(LOG_LEVEL_DEBUG >= l->level) || \
		(l->modules && log_module(l, ___FILE___)) || \
			is_dbg_comp) { \
		log_add_autoflush_f(l, LOG_LEVEL_DEBUG, \
			"%14s:%-4d : %s(): " fmt, ___FILE___, __LINE__, \
			__func__, ##__VA_ARGS__); \
	} \
} while (0)

#define do_log_trace(l)  (LOG_LEVEL_TRACE >= l->level || (l->modules && log_module(l, ___FILE___)))

#define log_trace(l, fmt, ...) do { \
	if (unlikely(LOG_LEVEL_TRACE >= l->level) || \
		(l->modules && log_module(l, ___FILE___)) || \
			is_dbg_comp) { \
		log_add_autoflush_f(l, LOG_LEVEL_TRACE, \
			"%14s:%-4d : %s(): " fmt, ___FILE___, __LINE__, \
			__func__, ##__VA_ARGS__); \
	} \
} while (0)

void log_hexdump_bin(Logger l, const char *desc, char *src, int src_len);
/* More convenient for ascii-like strings */
void log_escdump_bin(Logger l, const char *desc, char *src, int src_len);

#define log_hexdump(l, desc, src, src_len) do { \
	if (unlikely(LOG_LEVEL_DUMP >= l->level) || \
		(l->modules && log_module(l, ___FILE___)) || \
			is_dbg_comp) { \
		log_hexdump_bin(l, desc, src, src_len); \
	} \
} while (0)

#define log_escdump(l, desc, src, src_len) do { \
	if (unlikely(LOG_LEVEL_DUMP >= l->level) || \
		(l->modules && log_module(l, ___FILE___)) || \
			is_dbg_comp) { \
		log_escdump_bin(l, __FILE__ ":" CCOW_STRINGIFY(__LINE__) " : "  desc, src, src_len); \
	} \
} while (0)


void log_set_autoflush(LOGGER *lg, int set);
void log_set_level(LOGGER *lg, int level);
void log_set_modules(LOGGER *lg, char* modules);
void log_set_max_lines(LOGGER *lg, int max_lines);
void log_set_rotate_mode(LOGGER *lg, int mode);
void log_backtrace(Logger l, size_t n_skip, const char* msg);

#ifdef	__cplusplus
}
#endif
#endif
