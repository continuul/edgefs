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
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/time.h>
#include <uv.h>
#include <syslog.h>
#include <pthread.h>

#include "ccowutil.h"
#include "logger.h"
#include "ccowutil.h"
#include <backtrace.h>
#include <backtrace-supported.h>


#define QUOTE(name) #name

static char *LOG_LEVEL_COLORS[] = {
	LOG_COLOR_DEFAULT,
	LOG_COLOR_BLUE,
	LOG_COLOR_DEFAULT,
	LOG_COLOR_GREEN,
	LOG_COLOR_YELLOW,
	LOG_COLOR_RED,
	LOG_COLOR_CYAN,
	LOG_COLOR_CYAN
};

/* mapping to syslog severities */
static char *LOG_LEVEL_SEV[] = {
	"debug  ",
	"debug  ",
	"debug  ",
	"info   ",
	"warning",
	"error  ",
	"notice ",
	"alert  "
};

static int LOG_LEVEL_SYSLOG_PRIO[] = {
	LOG_DEBUG,
	LOG_DEBUG,
	LOG_DEBUG,
	LOG_INFO,
	LOG_WARNING,
	LOG_ERR,
	LOG_NOTICE,
	LOG_ALERT
};

Logger lg = NULL;

Logger
Logger_init(LOGGER *lgp, const char *logname)
{
	Logger l;

	l = (Logger) lgp;
	l->level = LOG_LEVEL_ERROR;
	l->colors = 0;
	l->flags = 0;
	l->lines_count = 0;
	l->logsync = 0;
	l->logsync1 = 0;
	l->max_lines = CCOW_LOG_MAX_LINES;
	l->mode = CCOW_LOG_ROTATE_RENAME;
	l->modules = NULL;
	l->file = NULL;
	l->file_bt = NULL;

	if (gethostname(l->host_buf, sizeof(l->host_buf)) != 0)
		strcpy(l->host_buf, "localhost");

	strncpy(l->logname, logname, 64);

	char *env_level = getenv(CCOW_LOG_LEVEL);
	if (env_level)
		l->level = atoi(env_level);

	char *env_modules = getenv(CCOW_LOG_MODULES);
	if (env_modules) {
		log_set_modules(lgp, env_modules);
	}

	char *env_colors = getenv(CCOW_LOG_COLORS);
	if (env_colors)
		l->colors = atoi(env_colors);

	char *env_stdout = getenv(CCOW_LOG_STDOUT);

	if (getenv(CCOW_LOG_AUTOFLUSH))
		l->flags |= LOG_FLAGS_AUTOFLUSH;

	char *env_rotate_mode = getenv(CCOW_LOG_ROTATE_MODE);
	if (env_rotate_mode)
		l->mode = atoi(env_rotate_mode);

	char *env_rotate_lines = getenv(CCOW_LOG_ROTATE_LINES);
	if (env_rotate_lines)
		l->max_lines = atoi(env_rotate_lines);

	char *env_syslog = getenv(CCOW_LOG_SYSLOG);
	if (!env_syslog)
		env_syslog = "1";

	if (env_stdout != 0 && atoi(env_stdout) != 0) {
		l->file = stdout;

		/*
		 * Console output is unbuffered to ensure proper thread
		 * ordering.
		 */
		setvbuf(stdout, NULL, _IOLBF, BUFSIZ);
	} else if (!lg && env_syslog != 0 && atoi(env_syslog) != 0) {
		l->file = NULL;
		openlog (logname, LOG_PID, LOG_USER);
		char *env_file_name = getenv("NEDGE_HOME");

		if (env_file_name) {
			snprintf(l->file_name, PATH_MAX, "%s/var/log/%s.log",
			    env_file_name, l->logname);
		}
		else {
			snprintf(l->file_name, PATH_MAX, "%s/var/log/%s.log",
			    QUOTE(INSTALL_PREFIX), l->logname);
		}

		l->file_bt = fopen(l->file_name, "a+");
	} else {

		/*
		 * No colors by default if we logging to a file
		 */
		if (!env_colors)
			l->colors = 0;

		char *env_file_name = getenv("NEDGE_HOME");

		if (env_file_name) {
			snprintf(l->file_name, PATH_MAX, "%s/var/log/%s.log",
			    env_file_name, logname);
		}
		else {
			snprintf(l->file_name, PATH_MAX, "%s/var/log/%s.log",
			    QUOTE(INSTALL_PREFIX), logname);
		}

		l->file = fopen(l->file_name, "a+");

		if (l->file == NULL) {
			int error = errno;

			openlog ("ccow",
			    (LOG_PERROR | LOG_CONS | LOG_PID), LOG_USER);
			syslog (LOG_ERR, "Failed to open log file, error %d (%s)",
			    error, strerror(error));
			closelog();

			exit(EXIT_FAILURE);
		}

		char *env_log_bufsize = getenv(CCOW_LOG_BUFSIZE);
		int log_bufsize = env_log_bufsize ?
		    atoi(env_log_bufsize) : LOG_DEFAULT_BUFSIZE;
		/** @warning Too small bufsize will break log consistency */
		if (log_bufsize < LOG_MAX_MSG_LEN)
			log_bufsize = LOG_MAX_MSG_LEN;
		/** @warning Strange value of limit. 64M buffer often is practical with debug logs */
		if (log_bufsize > 16*1024*1024) {
			fclose(l->file);
			printf("Failed to set size of log file buffer\n");
			return NULL;
		}

		/*
		 * If the 8 bytes are not added, it will cause poor
		 * performance as per Henry Newman "SysAdmin" book.
		 */
		if (setvbuf(l->file, NULL, _IOFBF, log_bufsize + 8) != 0) {
			fclose(l->file);
			printf("Failed to allocate log file buffer\n");
			return NULL;
		}
	}

	return l;
}

Logger
Logger_create(const char *logname)
{
	if (lg && strcmp(lg->logname, logname) == 0)
		return lg;
	LOGGER *l = je_malloc(sizeof (struct LOGGER));
	if (!l)
		return NULL;
	return Logger_init(l, logname);
}

void
Logger_destroy(LOGGER *l)
{
	if (l == NULL)
		return;

	log_flush(l);
	if (l->file)
		fclose(l->file);
	else {
		fclose(l->file_bt);
		closelog();
	}
	if (l->modules)
		je_free(l->modules);
	je_free(l);
	l = NULL;
}

void
Logger_hup(LOGGER *lgp) {
	log_flush(lgp);
	char local_path[PATH_MAX];
	snprintf(local_path, sizeof(local_path), "%s/.local", nedge_path());
	FILE* fh = fopen(local_path, "r");
	if (fh == NULL)
		return;
	char line[256];
	char *p;
	while (fgets(line, 256, fh) != NULL) {
		p = strstr(line, CCOW_LOG_LEVEL);
		if (p) {
			p = strrchr(p, '=');
			if (!p)
				continue;
			*(p + 2) = 0;
			lgp->level = atoi(p + 1);
			log_notice(lgp, "Log level now set to %d", lgp->level);
			continue;
		}
		p = strstr(line, CCOW_LOG_MODULES);
		if (p) {
			p = strrchr(p, '=');
			if (!p)
				continue;
			if (p[strlen(p) - 1] == '\n')
				p[strlen(p) - 1] = 0;
			log_set_modules(lgp, p + 1);
			log_notice(lgp, "Log modules now set to %s", lgp->modules);
			continue;
		}
	}
	fclose(fh);
}



void
log_set_autoflush(LOGGER *lgp, int set)
{
	Logger l;
	l = (Logger) lgp;

	if (l == NULL)
		return;

	if (set)
		l->flags |= LOG_FLAGS_AUTOFLUSH;
	else
		l->flags &= ~LOG_FLAGS_AUTOFLUSH;
}

void
log_set_level(LOGGER *lgp, int level)
{
	Logger l;
	l = (Logger) lgp;

	if (l == NULL)
		return;

	l->level = level;
	return;
}

void
log_set_modules(LOGGER *lgp, char* modules)
{
	Logger l;
	l = (Logger) lgp;

	if (l == NULL || !modules)
		return;

	if (l->modules)
		je_free(l->modules);

	l->modules = je_malloc(strlen(modules) + 3);
	strcpy(l->modules,",");
	strcat(l->modules, modules);
	strcat(l->modules,",");

	return;
}


void
log_set_max_lines(LOGGER *lgp, int max_lines)
{
	Logger l;
	l = (Logger) lgp;

	if (l == NULL)
		return;

	l->max_lines = max_lines;
	return;
}

void
log_set_rotate_mode(LOGGER *lgp, int mode)
{
	Logger l;
	l = (Logger) lgp;

	if (l == NULL)
		return;

	l->mode = mode;
	return;
}

static void
log_check_and_rotate(Logger l)
{
	char new_file_name[PATH_MAX];
	if (l->file == stdout || l->file == NULL)
		return;
	if (atomic_inc(&l->lines_count) >= l->max_lines && CAS(&l->logsync1, 0, 1)) {
		if (l->lines_count >= l->max_lines) {
			l->lines_count = 0;
			FILE *file = l->file;
			if (l->mode == CCOW_LOG_ROTATE_RENAME) {
				snprintf(new_file_name, PATH_MAX, "%s.old", l->file_name);
				if (access(new_file_name, F_OK) != -1)
					unlink(new_file_name);
				rename(l->file_name, new_file_name);
			}
			l->file = fopen(l->file_name, "w+");
			if (l->file == NULL) {
				int error = errno;

				openlog ("ccow",
				    (LOG_PERROR | LOG_CONS | LOG_PID), LOG_USER);
				syslog (LOG_ERR, "logrotate: Failed to open log file, error %d (%s)",
				    error, strerror(error));
				closelog();

				exit(EXIT_FAILURE);
			}
			while(!CAS(&l->logsync, 0, 0))
				usleep(1);
			fclose(file);
			l->logsync1 = 0;
		}
	}
}


void
log_add_v(Logger l, int level, bool flush, const char *format, va_list args)
{
	char line[LOG_MAX_MSG_LEN] = "";
	unsigned long thrid = ccow_gettid();

	if (l->file == NULL) {
		int l_size = snprintf(line, sizeof(line), "[%lu] %s", thrid, format);

		/* WA: Improve readability of messages from old code */
		if ('\n' == line[l_size-1])
			line[l_size-1] = '\0';

		vsyslog(LOG_LEVEL_SYSLOG_PRIO[level], line, args);
		return;
	}

	struct timespec tp;
	clock_gettime(CLOCK_REALTIME_COARSE, &tp);

	unsigned long pid = getpid();
	char buf[128];
	struct tm tm;
	unsigned line_idx;

	strftime(buf, sizeof (buf), "%b %d %H:%M:%S", localtime_r(&tp.tv_sec, &tm));

	if (l->colors)
		strcpy (line, LOG_LEVEL_COLORS[level]);

	line_idx = strlen(line);

	line_idx += snprintf(line + line_idx, sizeof(line) - line_idx,
		"%s.%03d %s %s[%lu] %s [%lu] ",
		    buf,
		    (int)(tp.tv_nsec/1000000),
		    l->host_buf,
		    l->logname,
		    pid,
		    LOG_LEVEL_SEV[level],
		    thrid);

	/** @warning Using fprintf() will be a bottle-neck in multi-threaded environment */
	line_idx += vsnprintf(line + line_idx, sizeof(line) - line_idx,
			format, args);

	/* WA: Improve readability of messages from old code */
	if ('\n' == line[line_idx-1]) {
		line[line_idx-1] = '\0';
		line_idx --;
	}

	strcpy(line + line_idx, l->colors ? LOG_COLOR_RESET "\n" : "\n");

	log_check_and_rotate(l);

	atomic_inc(&l->logsync);

	fwrite(line, strlen(line), 1, l->file);

	atomic_dec(&l->logsync);

	if (flush || l->flags & LOG_FLAGS_AUTOFLUSH)
		log_flush(l);
}

void
log_hexdump_bin(Logger l, const char *desc, char *src, int src_len)
{
	char *sp; /* pointer to walk through the src */
	char *dp; /* pointer to walk through the dest */
	int i = 0; /* keep count of where we are */
	char *bufptr; /* where we are writing the ascii to */
	int bufidx = 0; /* how far through the current line? */
	char *dest;

	if (src_len == 0) {
		log_add_autoflush_f(l, LOG_LEVEL_DUMP, "%s: Empty buffer", desc);
		return;
	}

	/* a buffer of hex characters */
	static const char hexchars[] = "0123456789ABCDEF";

	/*
	 * converted length is ...
	 *
	 * 77 bytes per line
	 * (
	 *   11 for the address display
	 *   16 * 3 for the hex chars
	 *    1 for the extra whitespace mid line
	 *   16 for the ascii display
	 *    1 for the line ending
	 * )
	 * multiplied by the number of lines to display
	 * +1 at the very end for NULL termination
	 */

	int line_len = 78;
	int hex_display_len = (16 * 3) + 11 + 2;

	/* how long should the destination string be? */
	int dest_len = (src_len / 16) * line_len;
	if (src_len % 16 > 0)
	{
		dest_len += line_len;
	}
	dest_len++;

	/* allocate the memory where the hexdump will go */
	dp = dest = je_calloc(1, (size_t) dest_len + strlen(desc) + 1);
	if (!dest)
		return;
	dp += sprintf(dest, "%s\n", desc);

	/* we need to know where to start writing ascii output */
	bufptr = dp + hex_display_len;

	/* line by line conversion */
	sp = src;
	for(i = 0; i < src_len; i++, sp++, bufptr++)
	{
		bufidx = i & 0xF;

		/* step 1:
		 *
		 * are we at the start of the line?
		 */
		if (0 == bufidx)
		{
			sprintf(dp, "[%08x] ", i);
			dp += 11;
		}

		/* step 2:
		 *
		 * work out the ASCII to show
		 */
		if (*sp < 32 || *sp > 126)
		{
			*bufptr = '.';
		}
		else
		{
			*bufptr = *sp;
		}

		/* step 3:
		 *
		 * we need the hex, next
		 */
		*dp = hexchars[(*sp >> 4) & 0xF];
		dp++;
		*dp = hexchars[*sp & 0xF];
		dp++;
		*dp = ' ';
		dp++;

		/* step 4:
		 *
		 * are we in the middle of a line?
		 */
		if (7 == bufidx)
		{
			*dp = ' ';
			dp++;
		}

		/* step 5:
		 *
		 * are we at the end of a line?
		 */
		if (15 == bufidx)
		{
			/* yes ... append the ascii buffer! */
			*dp = ' ';
			dp = bufptr + 1;
			*dp = '\n';
			dp++;

			/* move to the next asciiBuffer */
			bufptr = dp + hex_display_len - 1;
		}
	}

	/* finally ... deal with any partial line */
	if (15 != bufidx)
	{
		for (; bufidx < 15; bufidx++)
		{
			if (bufidx == 7)
			{
				*dp = ' ';
				dp++;
			}
			*dp = ' ';
			dp++;
			*dp = ' ';
			dp++;
			*dp = ' ';
			dp++;
		}

		/* add the final line ending */
		*dp = ' ';
		dp  = bufptr;
		*dp = '\n';
		dp++;
		*dp = 0;
	}

	/* the final length of the buffer is (dp - dest); */
	log_add_autoflush_f(l, LOG_LEVEL_DUMP, "%s", dest);

	je_free(dest);
}

void
log_escdump_bin(Logger l, const char *desc, char *src, int src_len)
{
	unsigned msg_idx = 0;
	char msg[LOG_MAX_MSG_LEN];

	if (src_len == 0) {
		log_add_autoflush_f(l, LOG_LEVEL_DUMP, "%s: Empty buffer", desc);
		return;
	}

	msg_idx += snprintf(msg, sizeof(msg), "%s: \"", desc);

	static const char simple[] = "\\\'\"";
	static const char complex_tmpl[] = "\a\b\f\n\r\t\v";
	static const char complexMap[] = "abfnrtv";

	for (ssize_t i = 0; i < src_len; i++)
	{
		char *p;
		if ('\0' == src[i])
		{
			msg_idx += sprintf(msg + msg_idx, "\\x00");
		}
		else if (strchr(simple, src[i]))
		{
			msg[msg_idx] = '\\'; msg_idx ++;
			msg[msg_idx] = src[i]; msg_idx ++;
		}
		else if ((p = strchr(complex_tmpl, src[i])))
		{
			size_t idx = p - complex_tmpl;
			msg[msg_idx] = '\\'; msg_idx ++;
			msg[msg_idx] = complexMap[idx]; msg_idx ++;
		}
		else if (isprint(src[i]))
		{
			msg[msg_idx] = src[i]; msg_idx ++;
		}
		else
		{
			msg_idx += sprintf(msg + msg_idx, "\\x%02x", src[i]);
		}
	}

	msg[msg_idx] = '"'; msg_idx ++;
	msg[msg_idx] = '\0'; msg_idx ++;

	log_add_autoflush_f(l, LOG_LEVEL_DUMP, "%s", msg);
}

void
log_flush(Logger l)
{
	if (l->file)
		fflush(l->file);
	if (l->file_bt)
		fflush(l->file_bt);
}

int
log_module(Logger l, const char *module) {
	if (!l || !l->modules || !module)
		return 0;

	char search[256];
	strcpy(search,",");
	strncat(search, module, 253);
	strcat(search, ",");

	return strstr(l->modules, search) != NULL;
}

static int
uint64_to_str(uint64_t n, uint16_t radix, int use_padding, char *s)
{
	const char hex_lookup[] = "0123456789ABCDEF";
	register int len = 0;
	uint64_t tmp = n;
	int rc = 0;

	if (radix > 16)
		radix = 16;

	if (!tmp)
		len = 1;
	else {
		for (; tmp; tmp /= radix)
			++len;
	}
	s[len] ='\0';

	int off = 0;
	if (use_padding) {
		int maxlen = 0;
		switch(radix) {
			case 8:
				maxlen = 22;
				break;
			case 10:
				maxlen = 20;
				break;
			case 16:
				maxlen = 16;
				break;
			default:
				break;
		}
		/* padding */
		off = maxlen - len;
		s[maxlen] = '\0';
		for (int i = 0; i < off; i++)
			s[i] = '0';
	}
	rc = off + len;
	for (--len; len >= 0; n /= radix, --len)
		s[off + len] = hex_lookup[n % radix];
	return rc;
}

struct bt_ctx {
	struct backtrace_state *state;
	int error;
	char* str;
	Logger lg;
	size_t fno;
	size_t buf_size;
	size_t skip;
};

static void
bt_append_buf(Logger l, int level, const char *msg, char* buf)
{
	struct timespec tp;
	clock_gettime(CLOCK_REALTIME_COARSE, &tp);

	unsigned long pid = getpid();
	unsigned long thrid = ccow_gettid();
	struct tm tm;
	char str[128];

	if (l->colors) {
		strcat(buf,LOG_LEVEL_COLORS[level]);
		strcat(buf,"[");
		int rc = uint64_to_str(pid, 10, 0, str);
		strcat(buf,str);
		strcat(buf,".");
		rc = uint64_to_str(thrid, 10, 0, str);
		strcat(buf,str);
		strcat(buf,"] ");
		rc = strlen(buf);
		buf[rc] = LOG_LEVEL_CHARS[level];
		strcat(buf,", ");
		rc = uint64_to_str(tp.tv_sec, 10, 0, str);
		strcat(buf,str);
		strcat(buf," : ");
		strcat(buf, msg);
		strcat(buf, LOG_COLOR_RESET);
		strcat(buf, "\n");
	} else {
		strcat(buf,"[");
		uint64_to_str(pid, 10, 0, str);
		strcat(buf,str);
		strcat(buf,".");
		uint64_to_str(thrid, 10, 0, str);
		strcat(buf,str);
		strcat(buf,"] ");
		int rc = strlen(buf);
		buf[rc] = LOG_LEVEL_CHARS[level];
		strcat(buf,", ");
		uint64_to_str(tp.tv_sec, 10, 0, str);
		strcat(buf,str);
		strcat(buf," : ");
		strcat(buf, msg);
		strcat(buf, "\n");
	}
}

static void
bt_error_callback(void *data, const char *msg, int errnum)
{
	struct bt_ctx *ctx = data;
	char* str = ctx->str;
	strcat(str, "ERROR: ");
	strcat(str, msg);
	ctx->error = errnum;
}

static int
bt_full_callback(void *data, uintptr_t pc, const char *filename, int lineno,
	const char *function)
{
	struct bt_ctx *ctx = data;
	if (function) {
		char buff[256] = {0};
		char str[64] = {0};
		if (ctx->skip) {
			ctx->skip--;
			return 0;
		}
		buff[0] = '#';
		uint64_to_str(ctx->fno++, 10, 0, str);
		strcat(buff, str);
		strcat(buff,": 0x");
		uint64_to_str(pc, 16, 1, str);
		strcat(buff, str);
		strcat(buff, " ");
		strcat(buff, function);
		strcat(buff, "() at ");
		if (filename) {
			strcat(buff, filename);
		} else {
			strcat(buff, "??");
		}
		strcat(buff, ":");
		uint64_to_str(lineno, 10, 0, str);
		strcat(buff, str);
		size_t len = strlen(buff);
		if (len + strlen(ctx->str) + 1 > ctx->buf_size)
			return -ENOSPC;
		bt_append_buf(ctx->lg, LOG_LEVEL_ERROR , buff, ctx->str);
	}
	return 0;
}

void
log_backtrace(Logger l, size_t n_skip, const char* msg)
{
	char buf[8192] = {0};
	int err = 0;
	int fd =l->file ? fileno(l->file) : fileno(l->file_bt);

	if (msg && (strlen(msg) + 1 > sizeof(buf))) {
		err = write(fd, "backtrace buffer overflow!\n", 26);
		return;
	}

	bt_append_buf(l, LOG_LEVEL_ERROR , msg, buf);

	struct backtrace_state *state = backtrace_create_state(
		NULL, BACKTRACE_SUPPORTS_THREADS,
		bt_error_callback, NULL);

	struct bt_ctx ctx = { .state = state, .error = 0, .str = buf,
		.fno = 0, .buf_size = sizeof(buf), .skip = n_skip, .lg = l};

	err = backtrace_full(state, 0, bt_full_callback, bt_error_callback,
		&ctx);

	if (err || !strlen(buf)) {
		bt_append_buf(l, LOG_LEVEL_ERROR , "Failed to get a backtrace", buf);
	}
	err = write(fd, buf, strlen(buf));
}
