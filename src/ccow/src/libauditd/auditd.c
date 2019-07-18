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
/**
 * This is the main entry point into statsite.
 * We are responsible for parsing any commmand line
 * flags, reading the configuration, starting
 * the filter manager, and finally starting the
 * front ends.
 */
#include <sys/resource.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/file.h>
#include <signal.h>
#include <linux/limits.h>

#include "ccowutil.h"
#include "queue.h"
#include "logger.h"
#include "auditd.h"
#include "auditd-impl.h"
#include "hashtable.h"
#include "config.h"
#include "conn_handler.h"
#include "networking.h"

#define QUOTE(name) #name
#define AUDITD_EVAC_TIMEOUT	30

/**
 * By default we should run. Our signal
 * handler updates this variable to allow the
 * program to gracefully terminate.
 */
static volatile int SHOULD_RUN = 1;

int auditd_daemonize = 0;
char auditd_pidfile[PATH_MAX] = "";

#define REINIT_COALESCE_TIMEOUT_US	(10*1000000UL)

const char *auditd_setup_pidfile_var(void)
{
	char *nedge_home = getenv("NEDGE_HOME");
	if (nedge_home)
		snprintf(auditd_pidfile, PATH_MAX, "%s/var/run/auditd.pid",
		    nedge_home);
	else
		snprintf(auditd_pidfile, PATH_MAX, "%s/var/run/auditd.pid",
		    QUOTE(INSTALL_PREFIX));

	return auditd_pidfile;
}

statsite_networking *netconf = NULL;
statsite_config *config = NULL;
pthread_t main_thread;
QUEUE clstat_engines = QUEUE_INIT_STATIC(clstat_engines);
static struct clstat_engine *g_ceng = NULL;
uv_poll_t *clstat_poll;
uv_async_t clstat_reinit_handle;

static int clstat_init(const char *name);
static int clstat_destroy(int reinit);

#define CLSTAT_FILE		"stats"
#define CLSTAT_EXTN		"db"
#define CLSTAT_TABLE_SIZE	10000
hashtable_t *clstat_table = NULL;
/** @todo Subject to remove */
static pthread_mutex_t clstat_lock = PTHREAD_MUTEX_INITIALIZER;

#define CHECKPOINT_FILE_NAME	"%s/var/run/flexhash-checkpoint.json"
#define CANDIDATE_CHECKPOINT_FILE "%s/var/run/flexhash-checkpoint-candidate.json"
#define MSG_SIZE_MAX		(4 * 1024 * 1024UL)
#define STAT_SIZE_MAX		(8 * 1024)
time_t last_checkpoint_mtime = 0;

static char *
clstat_statsdb_filename(void)
{
	char *env_prefix = getenv("NEDGE_HOME");
	static char file_name[1024];

	if (env_prefix) {
		sprintf(file_name, "%s/var/run/%s.%s",
		    env_prefix, CLSTAT_FILE, CLSTAT_EXTN);
	} else {
		sprintf(file_name, "%s/var/run/%s.%s",
		    QUOTE(INSTALL_PREFIX), CLSTAT_FILE,
		    CLSTAT_EXTN);
	}

	return file_name;
}

/** SIGHUP && SIGUSR1 signals call-back for libuv */
static void signal_handler_uv(uv_signal_t* handle, int signum)
{
	if (signum != SIGHUP && signum != SIGUSR1)
		return;

	if (!SHOULD_RUN) {
		log_warn(lg, "Received signal [%s] while exiting! Immediately terminating",
		    strsignal(signum));

		unlink(auditd_pidfile);
		/** @warning In theory we should wait here graceful exit, but for unknown reason the exit is forced */
		exit(1);
	}

	if (signum == SIGHUP) {
		if (!lg)
			return;

		log_info(lg, "Received signal [%s]: GET_SERVERINFO",
			strsignal(signum));

		char *env_level = getenv(CCOW_LOG_LEVEL);
		if (env_level)
			lg->level = atoi(env_level);

		char request[] = "GET_SERVERINFO";
		int res = auditd_send_ccowd_message(netconf, request);
		if (res != 0) {
			log_error(lg, "Failed sending GET_SERVERINFO on SIGHUP: [%d]", res);
		}
		log_flush(lg);
		return;
	}

	if (signum == SIGUSR1) {
		if (!lg)
			return;

		log_info(lg, "Received signal [%s]: refreshing stats.db",
			strsignal(signum));

		char *file_name = clstat_statsdb_filename();
		pthread_mutex_lock(&clstat_lock);
		FILE *save_file = NULL, *probe = NULL;
		/* Open file. Create one if doesn't exist, don't truncate */
		probe = fopen(file_name, "a+");
		if (!probe) {
			pthread_mutex_unlock(&clstat_lock);
			return;
		}
		/* Take an exclusive ownership*/
		int err = flock(fileno(probe), LOCK_EX);
		if (err) {
			fclose(probe);
			pthread_mutex_unlock(&clstat_lock);
			return;
		}
		/* Truncate */
		save_file = fopen(file_name, "w+");
		if (save_file)
			fclose(save_file);
		fclose(probe);
		pthread_mutex_unlock(&clstat_lock);
		clstat_reinit();
		return;
	}
}

int
auditd_stats_sharedlock(void** handle) {
	char *file_name = clstat_statsdb_filename();
	FILE *file = NULL;
	char buff[8*1024];
	int err = 0;
	/* Open file. Create one if doesn't exist, don't truncate */
	file = fopen(file_name, "a+");
	if (!file)
		return -ENOENT;
	/* Take a shared lock*/
	err = flock(fileno(file), LOCK_SH);
	if (err) {
		fclose(file);
		return err;
	}
	*handle = file;
	return 0;
}

int
auditd_stats_sharedunlock(void* handle) {
	char *file_name = clstat_statsdb_filename();
	FILE *file = handle;
	if (!handle)
		return -EINVAL;
	fclose(file);
	return 0;
}

int
auditd_stats_query(const char* query, QUEUE* response) {
	char *file_name = clstat_statsdb_filename();
	FILE *file = NULL;
	char buff[8*1024];
	int err = 0;
	/* Open file. Create one if doesn't exist, don't truncate */
	file = fopen(file_name, "a+");
	if (!file)
		return -ENOENT;
	/* Take a shared lock*/
	err = flock(fileno(file), LOCK_SH);
	if (err) {
		fclose(file);
		return err;
	}
	char* line = NULL;
	while ((line = fgets(buff, sizeof(buff), file)) != NULL) {
		if (!strstr(line, query))
			continue;
		struct auditd_query_resp* e = je_malloc(sizeof(*e));
		if (!e) {
			err = -ENOMEM;
			goto _exit;
		}
		QUEUE_INIT(&e->item);
		e->entry = je_strdup(line);
		if (!e->entry) {
			err = -ENOMEM;
			goto _exit;
		}
		QUEUE_INSERT_TAIL(response, &e->item);
	}
_exit:
	fclose(file);
	if (err) {
		QUEUE* q = NULL;
		while(!QUEUE_EMPTY(response)) {
			q = QUEUE_HEAD(response);
			struct auditd_query_resp* e = QUEUE_DATA(q, struct auditd_query_resp, item);
			QUEUE_REMOVE(q);
			QUEUE_INIT(q);
			je_free(e->entry);
			je_free(e);
		}
	}
	return err;
}

/** Dumb async-signal-safe dprintf() replacement.
 *
 *  According to man 7 signal-safety strcat() and write() are signal-safe,
 *  so our function also is signal-safe. */
static void write_signal_msg(int out_fd, const char *init_str, int signum, const char *end_str)
{
	char msg[LOG_MAX_MSG_LEN] = "";
	/** Preserve errno for consistency of interupted context */
	int err_no = errno;

	strcat(msg, init_str);
	strcat(msg, strsignal(signum));
	strcat(msg,	end_str);

	if (write(out_fd, msg, strlen(msg))) {}

	errno = err_no;
}

/**
 * Our registered signal handler, invoked
 * when we get signals such as SIGINT, SIGTERM.
 */
static void
signal_handler(int signum) {
	if (!SHOULD_RUN) {
		/** Currently there are no ways to output msg in daemon mode */
		if (!auditd_daemonize) {
			write_signal_msg(STDOUT_FILENO,
					">>> Received signal [", signum,
					"] while exiting! Immediately terminating. <<<\n");
		}
		unlink(auditd_pidfile);
		/** @warning In theory we should wait here graceful exit, but for unknown reason the exit is forced */
		_exit(1);
	}

	if (SIGINT != signum && SIGTERM != signum)
		return;

	/** Currently there are no ways to output msg in daemon mode */
	if (!auditd_daemonize) {
		write_signal_msg(STDOUT_FILENO,
				">>> Received signal [", signum, "]! Immediately exiting... <<<\n");
	}

	SHOULD_RUN = 0;  // Stop running now
	unlink(auditd_pidfile);
	if (SIGTERM == signum) {
		/** @warning In theory we should have here graceful exit,
		 * but for unknown reason the exit is forced */
		_exit(1);
	}
}

static int
need_update_checkpoint()
{

	if (!config || !config->is_aggregator) {
		return 0;
	}
	struct stat filestat;
	char cp_path[PATH_MAX];
	snprintf(cp_path, sizeof(cp_path), CHECKPOINT_FILE_NAME, nedge_path());
	if (stat(cp_path, &filestat) != 0) {
		log_trace(lg, "Checkpoint file not found");
		return 0;
	}
	if (last_checkpoint_mtime == 0) {
		last_checkpoint_mtime = filestat.st_mtime;
		return 1;
	} else if (last_checkpoint_mtime == filestat.st_mtime) {
		return 0;
	}
	return 1;

}

int
clstat_reinit()
{
	uv_async_send(&clstat_reinit_handle);
	return 0;
}

void
clstat_reinit_call(uv_async_t *handle, int status)
{
	static uint64_t last_call_ts = 0;
	if (last_call_ts + REINIT_COALESCE_TIMEOUT_US > get_timestamp_us())
		return;
	clstat_destroy(1);
	clstat_init("corosync");
	last_call_ts = get_timestamp_us();
}

static void *
auditd_main(void *arg)
{
	uv_signal_t sighup, sigusr1;

	int err = clstat_init("corosync");
	if (err) {
		log_error(lg, "Failed to initialize Cluster Stat Engine: %d", err);
		return NULL;
	}

	uv_signal_init(uv_default_loop(), &sighup);
	uv_signal_init(uv_default_loop(), &sigusr1);

	uv_signal_start(&sighup, signal_handler_uv, SIGHUP);
	uv_signal_start(&sigusr1, signal_handler_uv, SIGUSR1);

	uv_async_init(uv_default_loop(), &clstat_reinit_handle, clstat_reinit_call);

	// Join the networking loop, blocks until exit
	enter_networking_loop(netconf, &SHOULD_RUN);

	uv_close((uv_handle_t *)&sighup, NULL);
	uv_close((uv_handle_t *)&sigusr1, NULL);

	// Begin the shutdown/cleanup
	shutdown_networking(netconf);

	// Do the final flush
	final_flush();

	clstat_destroy(0);

	// Free the event loop
	uv_loop_delete(uv_default_loop());

	return NULL;
}

struct clstat_engine *
clstat_find(const char *name)
{
	int len;
	QUEUE *q;

	QUEUE_FOREACH(q, &clstat_engines) {
		struct clstat_engine *ceng =
			QUEUE_DATA(q, struct clstat_engine, item);
		len = strlen(ceng->name);

		if (strncmp(ceng->name, name, len) == 0 &&
		    (name[len] == ':' || name[len] == '\0'))
			return ceng;
	}

	return NULL;
}


static void
send_checkpoint_update()
{
	// READ in the new checkpoint file, then notify
	char buf[MSG_SIZE_MAX] = "CONF_UPDATE|CHPT|";
	size_t c_len = strlen(buf);
	char cp_path[PATH_MAX];
	snprintf(cp_path, sizeof(cp_path), CHECKPOINT_FILE_NAME, nedge_path());
	FILE *fd = fopen(cp_path, "r");
	if (!fd) {
		log_error(lg, "Unable to open checkpoint file! %d", errno);
		return;
	}
	size_t msg_len = fread(buf + c_len, 1, MSG_SIZE_MAX - c_len, fd);
	fclose(fd);
	pthread_mutex_lock(&clstat_lock);
	int err = g_ceng->notify(buf, msg_len + c_len + 1, NULL);
	pthread_mutex_unlock(&clstat_lock);
	if (err) {
		log_error(lg, "Unable to send new checkpoint file! %d", err);
	}
	return;
}

static void
clstat_join_cb(struct cpg_node *joined, struct cpg_node *members,
	size_t nr_members, int result, void *opaque,
	int opaque_len)
{
	if (need_update_checkpoint())
		send_checkpoint_update();
	log_trace(lg, "joined nodeid=%u\n", joined->nodeid);
}

static void
clstat_leave_cb(struct cpg_node *left, struct cpg_node *members,
	size_t nr_members)
{
	if (need_update_checkpoint())
		send_checkpoint_update();
	log_trace(lg, "left nodeid=%u\n", left->nodeid);
}

static void
clstat_notify_cb(struct cpg_node *sender, void *msg, size_t msg_len)
{
	/* Incoming formats (string buffer):
	 *
	 *  1)   STAT_UDPATE|KEY|VALUE|TS
	 *
	 *  2)   CONF_UPDATE|KEY|VALUE
	 */

	if (!msg) {
		log_error(lg, "Unable to process a NULL message ");
		return;
	}
	log_trace(lg, "notify nodeid=%u msg_len=%lu", sender->nodeid, msg_len);

	if (msg_len >= MSG_SIZE_MAX)
		return;

	*((char *)msg + msg_len - 1) = 0;

        int i = 0;
        char *cmdargv[32];
	char * sp;
        char *token = strtok_r(msg, "|", &sp);
        while (token != NULL) {
            cmdargv[i++] = token;
            token = strtok_r(NULL, "|", &sp);
        }

	if (i < 2)
		return;

	char *opcode = cmdargv[0];
	char *key = cmdargv[1];
	char *value = cmdargv[2];

	char *ts = NULL;
	if (i > 3)
		ts = cmdargv[3];

	if (strcmp(opcode, "STAT_UPDATE") == 0) {
		/* skip non-ccow stat updates */
		if (strstr(key, ".ccow.") == NULL)
			return;
		char val[MSG_SIZE_MAX];
		int err = snprintf(val, MSG_SIZE_MAX, "%s|%s", value, ts);
		if (err < 0)
			return;
		pthread_mutex_lock(&clstat_lock);
		if (strstr(key, "reptrans.rowusagecounters")) {
			/* We want to remove previous entries. They won't be
			 * replaced because the key pattern isn't fixed, only
			 * first 91 bytes remains the same. So we looking for
			 * server/vdevID pattern and removing whole entry,
			 * then placing a new one.
			 */
			char full_str[512];
			memcpy(full_str, key, 91);
			full_str[91] = 0;
			unsigned int num;
			void **keys = hashtable_keys(clstat_table, &num);
			for (size_t i = 0; i < num; i++) {
				if (strstr(keys[i], full_str))
					hashtable_remove(clstat_table, keys[i], strlen(keys[i]) + 1);
			}
			if (keys)
				je_free(keys);
		} else if (strstr(key, "clengine.server")) {
			/* Cleanup old "clengine.server" messages for current serverID
			 * Because server's IP is a part of the key and IP can be changed
			 * after POD restart. Find all messages with current serverID, but different IP and remove them
			 * Message format: gauges.ccow.clengine.server.253930251D6C278A17BC8F739FEC0D90.__ffff_ffff_cc27_fd0a
			 */
			char substr[64];
			char ip[64] = {0};
			memcpy(substr, key, 60);
			substr[60] = 0;
			char* dot = strchr(key+61, '.');
			if (dot) {
				strncpy(ip, key+61, dot - key - 61);
				unsigned int num;
				void **keys = hashtable_keys(clstat_table, &num);
				for (size_t i = 0; i < num; i++) {
					if (strstr(keys[i], substr) && !strstr(keys[i], ip)) {
						hashtable_remove(clstat_table, keys[i], strlen(keys[i]) + 1);
						log_debug(lg, "Removed an outdated entry with key %s", keys[i]);
					}
				}
				if (keys)
					je_free(keys);
			} else {
				log_error(lg, "Couldn't find IP in a message %s", key);
			}
		}
		err = hashtable_put(clstat_table, key, strlen(key) + 1,
		    val, strlen(val) + 1);
		pthread_mutex_unlock(&clstat_lock);
		if (err) {
			log_warn(lg, "Cannot insert new stat %s: %d", key, err);
		}
	} else if (strcmp(opcode, "CONF_UPDATE") == 0) {
		// write to <nedge_home>/var/run/flexhash-checkpoint-candidate.json
		char cp_path[PATH_MAX];
		snprintf(cp_path, sizeof(cp_path), CANDIDATE_CHECKPOINT_FILE, cp_path);
		FILE *fd = fopen(cp_path, "w");
		if (!fd) {
			log_error(lg, "Cannot process new checkpoint %s", key);
			return;
		}
		size_t bytes = fwrite(value, 1, strlen(value), fd);
		if (bytes != strlen(value))
			log_error(lg, "Cannot write new checkpoint candidate %s", key);
		fclose(fd);
		return;
	} else {
		log_warn(lg, "Received unsupported clstat opcode %s", opcode);
	}
}

static int
check_join_cb(struct cpg_node *joining,
	void *opaque, int opaque_len)
{
	// FIXME: check join criteria
	return 1; /* allow */
}

static void
clstat_handle_new_ev(uv_poll_t *watcher, int status, int ready_events)
{
	g_ceng->dispatch();
}

static int
clstat_init(const char *name)
{
	g_ceng = clstat_find(name);
	if (!g_ceng) {
		log_error(lg, "Cluster stat engine %s not found", name);
		return -1;
	}

	clstat_table = hashtable_create(CLSTAT_TABLE_SIZE, 0, 0.05);
	if (!clstat_table) {
		log_error(lg, "clstat_table: out of memory");
		return -1;
	}

	struct clstat_handlers handlers;
	handlers.join_handler = clstat_join_cb;
	handlers.leave_handler = clstat_leave_cb;
	handlers.notify_handler = clstat_notify_cb;

	g_ceng->group_fd = g_ceng->init(&handlers);
	if (g_ceng->group_fd < 0) {
		raise(SIGTERM);
		return -1;
	}
	// Create the libuv objects
	clstat_poll = je_malloc(sizeof(uv_poll_t));
	uv_poll_init(uv_default_loop(), clstat_poll, g_ceng->group_fd);
	uv_poll_start(clstat_poll, UV_READABLE, clstat_handle_new_ev);

	int err = g_ceng->join(check_join_cb, NULL, 0);
	if (err) {
		log_error(lg, "Error while joining, err: %d", err);
		return err;
	}

	log_info(lg, "Cluster Stat Engine %s now initialized", name);

	return 0;
}

static void
deferred_close_cb(uv_handle_t* handle)
{
	je_free(handle);
}

static int
clstat_destroy(int reinit)
{
	int err = 0;

	if (uv_is_active((const uv_handle_t *)clstat_poll)) {
		uv_close((uv_handle_t *)clstat_poll, deferred_close_cb);
	}

	if (clstat_table) {
		hashtable_destroy(clstat_table);
		clstat_table = NULL;
	}

	if (g_ceng)
		err = clstat_cleanup();

	return err;
}

int
clstat_notify(void *msg, size_t msg_len)
{
	char buf[STAT_SIZE_MAX];
	int err;

	strcpy(buf, "STAT_UPDATE|");
	strncat(buf, msg, msg_len);

	pthread_mutex_lock(&clstat_lock);
	err = g_ceng->notify(buf, strlen(buf), NULL);
	pthread_mutex_unlock(&clstat_lock);
	return err;
}

int
clstat_dump(void)
{
	char *file_name = clstat_statsdb_filename();
	FILE *save_file = NULL, *probe = NULL;
	/* Open file. Create one if doesn't exist, don't truncate */
	probe = fopen(file_name, "a+");
	if (!probe)
		return -ENOENT;
	/* Take an exclusive ownership */
	int err = flock(fileno(probe), LOCK_EX);
	if (err) {
		fclose(probe);
		return err;
	}
	save_file = fopen(file_name, "w+");
	if (!save_file) {
		fclose(probe);
		return -ENOENT;
	}

	pthread_mutex_lock(&clstat_lock);
	unsigned int num;
	void **keys = hashtable_keys(clstat_table, &num);
	if (!keys) {
		pthread_mutex_unlock(&clstat_lock);
		fclose(save_file);
		fclose(probe);
		return -ENOMEM;
	}

	for (unsigned int i = 0; i < num; i++) {
		char *key = (char *) keys[i];
		size_t value_size;
		char *value = hashtable_get(clstat_table, key, strlen(key) + 1,
			&value_size);
		/* Remove outdated rowevac entries */
		if (strstr(key, "rowevac_job")) {
			char* p = strchr(value, '|');
			assert(p);
			uint64_t ts = strtoll(p + 1, NULL, 10);
			struct timeval now;
			gettimeofday(&now, NULL);
			if (ts + AUDITD_EVAC_TIMEOUT < (uint64_t)now.tv_sec) {
				hashtable_remove(clstat_table, key, strlen(key) + 1);
				continue;
			}
		}
		fprintf(save_file, "%s|%s\n", key, value);
		if (strstr(key, "namedput.obj_latency_update"))
			hashtable_remove(clstat_table, key, strlen(key) + 1);
	}
	pthread_mutex_unlock(&clstat_lock);
	fclose(save_file);
	fclose(probe);

	if (keys)
		je_free(keys);
	return 0;
}

int
auditd_init()
{
	lg = Logger_create("auditd");

#ifdef CCOW_VALGRIND
	if (!RUNNING_ON_VALGRIND) {
#endif
		struct rlimit limit;
		limit.rlim_cur = AUDITD_RLIMIT_NOFILE;
		limit.rlim_max = AUDITD_RLIMIT_NOFILE;
		if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
			log_error(lg, "setrlimit() failed with err=%d\n", -errno);
			return 1;
		}
#ifdef CCOW_VALGRIND
	}
#endif

	/* core dumps may be disallowed by parent of our process; change that */
	struct rlimit core_limits;
	core_limits.rlim_cur = core_limits.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_CORE, &core_limits);

	// Parse the config file
	config = je_calloc(1, sizeof(statsite_config));
	char conf_pref[PATH_MAX];
	snprintf(conf_pref, sizeof(conf_pref), AUDITD_CONF_DIR "/%s",
		nedge_path(), AUDITD_CONF_FILE);
	int config_res = config_from_filename(conf_pref, config);
	if (config_res != 0) {
		log_error(lg, "Failed to read the configuration file!");
		return 1;
	}

	// Validate the config file
	if (validate_config(config)) {
		log_error(lg, "Invalid configuration!");
		return 1;
	}

	// Build the prefix tree
	if (build_prefix_tree(config)) {
		log_error(lg, "Failed to build prefix tree!");
		return 1;
	}

	// Log that we are starting up
	log_info(lg, "Starting Audit service...");

	// Initialize the networking
	/** @bug Timeout is too long or does not exist and signal handlers still are not acivated */
	int net_res = init_networking(config, &netconf);
	if (net_res != 0) {
		log_error(lg, "Failed to initialize networking!");
		return 1;
	}

	// Setup signal handlers
	signal(SIGPIPE, SIG_IGN);       // Ignore SIG_IGN
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGABRT, signal_handler);
	signal(SIGSEGV, signal_handler);
	signal(SIGQUIT, signal_handler);
	// SIGHUP & SIGUSR1 will be intercepted later, during initialization of event-loop

	if (pthread_create(&main_thread, NULL, auditd_main, NULL)) {
		log_error(lg, "Error creating main thread");
		return 1;

	}

	return 0;
}

void
auditd_term(int sigwait)
{
	SHOULD_RUN = sigwait;  // Stop running now

	/* wait for the second thread to finish */
	if(pthread_join(main_thread, NULL)) {
		log_error(lg, "Error joining with main thread");
		return;
	}

	// Free our memory
	je_free(config);
}
