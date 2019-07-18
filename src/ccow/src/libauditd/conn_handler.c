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
#include <string.h>
#include <regex.h>
#include <assert.h>
#include <pthread.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <math.h>
#include <inttypes.h>
#include <nanomsg/nn.h>
#include <nanomsg/pubsub.h>

#include "ccowutil.h"
#include "logger.h"
#include "auditd-impl.h"
#include "metrics.h"
#include "streaming.h"
#include "conn_handler.h"

/*
 * Binary defines
 */
#define BIN_TYPE_KV             0x1
#define BIN_TYPE_COUNTER        0x2
#define BIN_TYPE_TIMER          0x3
#define BIN_TYPE_SET            0x4
#define BIN_TYPE_GAUGE          0x5
#define BIN_TYPE_GAUGE_DELTA    0x6

#define BIN_OUT_NO_TYPE 0x0
#define BIN_OUT_SUM     0x1
#define BIN_OUT_SUM_SQ  0x2
#define BIN_OUT_MEAN    0x3
#define BIN_OUT_COUNT   0x4
#define BIN_OUT_STDDEV  0x5
#define BIN_OUT_MIN     0x6
#define BIN_OUT_MAX     0x7
#define BIN_OUT_HIST_FLOOR    0x8
#define BIN_OUT_HIST_BIN      0x9
#define BIN_OUT_HIST_CEIL     0xa
#define BIN_OUT_PCT     0x80

/* Key, value index literals */
#define KEY_INDEX 0
#define VALUE_INDEX 1
#define TS_INDEX 2

/* Static method declarations */
static int handle_binary_client_connect(statsite_conn_handler *handle);
static int handle_ascii_client_connect(statsite_conn_handler *handle);
static int buffer_after_terminator(char *buf, int buf_len, char terminator, char **after_term, int *after_len);

/* These are the quantiles we track */
static const double QUANTILES[] = {0.5, 0.95, 0.99};
static const int NUM_QUANTILES = 3;


// This is the magic byte that indicates we are handling
// a binary command, instead of an ASCII command. We use
// 170 (0xaa) value.
static const unsigned char BINARY_MAGIC_BYTE = 0xaa;
static const int MAX_BINARY_HEADER_SIZE = 12;
static const int MIN_BINARY_HEADER_SIZE = 6;

/**
 * This is the current metrics object we are using
 */
static metrics *GLOBAL_METRICS;
static statsite_config *GLOBAL_CONFIG;

static int GLOBAL_PUB_FD;

/**
 * Invoked to initialize the conn handler layer.
 */
void init_conn_handler(statsite_config *config)
{
	// Make the initial metrics object
	metrics *m = je_malloc(sizeof(metrics));
	int res = init_metrics(config->timer_eps, (double*)&QUANTILES,
	    NUM_QUANTILES, config->histograms, config->set_precision, m);
	assert(res == 0);
	GLOBAL_METRICS = m;

	// Store the config
	GLOBAL_CONFIG = config;

	if (!config->pub_endpoint) {
		log_info(lg, "Publishing TCP endpoint is disabled");
		return;
	}

	GLOBAL_PUB_FD = nn_socket(AF_SP, NN_PUB);
	if (GLOBAL_PUB_FD < 0) {
		log_error(lg, "Failed create socket: %s [%d]", strerror(errno),
		    (int)errno);
		return;
	}

	int linger = -1;
	nn_setsockopt(GLOBAL_PUB_FD, NN_SOL_SOCKET, NN_LINGER, &linger, sizeof (linger));

	/* set the option so we can use ipv6 address */
	int flag = 0;
	int rc = nn_setsockopt(GLOBAL_PUB_FD, NN_SOL_SOCKET , NN_IPV4ONLY, &flag,
	    sizeof(int));
	if (rc < 0) {
		nn_close(GLOBAL_PUB_FD);
		log_error(lg, "setsockopt error: %s [%d]",
		    strerror(errno), errno);
		return;
	}

	char *address = config->pub_endpoint;
	rc = nn_bind(GLOBAL_PUB_FD, address);
	if(rc < 0) {
		nn_close(GLOBAL_PUB_FD);
		log_error(lg, "Failed bind to \"%s\": %s [%d]", address,
		    strerror(errno), (int)errno);
		return;
	}

	log_info(lg, "Publishing events on TCP '%s'", address);
}

/**
 * Streaming callback to format our output
 */
static int stream_formatter(FILE *pipe, void *data, metric_type type, char *name, void *value) {
    #define STREAM(...) if (fprintf(pipe, __VA_ARGS__, (long long)tv->tv_sec) < 0) return 1;
    struct timeval *tv = data;
    timer_hist *t;
    int i;

    log_trace(lg, "Stream formatter feeding data");
    switch (type) {
        case KEY_VAL:
            STREAM("kv.%s|%f|%lld\n", name, *(double*)value);
            break;

        case GAUGE:
            STREAM("gauges.%s|%f|%lld\n", name, ((gauge_t*)value)->value);
            break;

        case COUNTER:
            STREAM("counts.%s|%f|%lld\n", name, counter_sum(value));
            break;

        case SET:
            STREAM("sets.%s|%"PRIu64"|%lld\n", name, set_size(value));
            break;

        case TIMER:
            t = (timer_hist*)value;
            STREAM("timers.%s.sum|%f|%lld\n", name, timer_sum(&t->tm));
            STREAM("timers.%s.sum_sq|%f|%lld\n", name, timer_squared_sum(&t->tm));
            STREAM("timers.%s.mean|%f|%lld\n", name, timer_mean(&t->tm));
            STREAM("timers.%s.lower|%f|%lld\n", name, timer_min(&t->tm));
            STREAM("timers.%s.upper|%f|%lld\n", name, timer_max(&t->tm));
            STREAM("timers.%s.count|%"PRIu64"|%lld\n", name, timer_count(&t->tm));
            STREAM("timers.%s.stdev|%f|%lld\n", name, timer_stddev(&t->tm));
            STREAM("timers.%s.median|%f|%lld\n", name, timer_query(&t->tm, 0.5));
            STREAM("timers.%s.p95|%f|%lld\n", name, timer_query(&t->tm, 0.95));
            STREAM("timers.%s.p99|%f|%lld\n", name, timer_query(&t->tm, 0.99));

            // Stream the histogram values
            if (t->conf) {
                STREAM("timers.%s.histogram.bin_<%0.2f|%u|%lld\n", name, t->conf->min_val, t->counts[0]);
                for (i=0; i < t->conf->num_bins-2; i++) {
                    STREAM("timers.%s.histogram.bin_%0.2f|%u|%lld\n", name, t->conf->min_val+(t->conf->bin_width*i), t->counts[i+1]);
                }
                STREAM("timers.%s.histogram.bin_>%0.2f|%u|%lld\n", name, t->conf->max_val, t->counts[i+1]);
            }
            break;

        default:
            log_error(lg, "Unknown metric type: %d", type);
            break;
    }
    return 0;
}

/* Helps to write out a single binary result */
#pragma pack(push,1)
struct binary_out_prefix {
    uint64_t timestamp;
    uint8_t  type;
    uint8_t  value_type;
    uint16_t key_len;
    double   val;
};
#pragma pack(pop)

static int stream_bin_writer(FILE *pipe, uint64_t timestamp, unsigned char type,
        unsigned char val_type, double val, char *name) {
        uint16_t key_len = strlen(name) + 1;
        struct binary_out_prefix out = {timestamp, type, val_type, key_len, val};
        if (!fwrite(&out, sizeof(struct binary_out_prefix), 1, pipe)) return 1;
        if (!fwrite(name, key_len, 1, pipe)) return 1;
        return 0;
}

static int stream_formatter_bin(FILE *pipe, void *data, metric_type type, char *name, void *value) {
    #define STREAM_BIN(...) if (stream_bin_writer(pipe, ((struct timeval *)data)->tv_sec, __VA_ARGS__, name)) return 1;
    #define STREAM_UINT(val) if (!fwrite(&val, sizeof(unsigned int), 1, pipe)) return 1;
    timer_hist *t;
    int i;
    switch (type) {
        case KEY_VAL:
            STREAM_BIN(BIN_TYPE_KV, BIN_OUT_NO_TYPE, *(double*)value);
            break;

        case GAUGE:
            STREAM_BIN(BIN_TYPE_GAUGE, BIN_OUT_NO_TYPE, ((gauge_t*)value)->value);
            break;

        case COUNTER:
            STREAM_BIN(BIN_TYPE_COUNTER, BIN_OUT_SUM, counter_sum(value));
            STREAM_BIN(BIN_TYPE_COUNTER, BIN_OUT_SUM_SQ, counter_squared_sum(value));
            STREAM_BIN(BIN_TYPE_COUNTER, BIN_OUT_MEAN, counter_mean(value));
            STREAM_BIN(BIN_TYPE_COUNTER, BIN_OUT_COUNT, counter_count(value));
            STREAM_BIN(BIN_TYPE_COUNTER, BIN_OUT_STDDEV, counter_stddev(value));
            STREAM_BIN(BIN_TYPE_COUNTER, BIN_OUT_MIN, counter_min(value));
            STREAM_BIN(BIN_TYPE_COUNTER, BIN_OUT_MAX, counter_max(value));
            break;

        case SET:
            STREAM_BIN(BIN_TYPE_SET, BIN_OUT_SUM, set_size(value));
            break;

        case TIMER:
            t = (timer_hist*)value;
            STREAM_BIN(BIN_TYPE_TIMER, BIN_OUT_SUM, timer_sum(&t->tm));
            STREAM_BIN(BIN_TYPE_TIMER, BIN_OUT_SUM_SQ, timer_squared_sum(&t->tm));
            STREAM_BIN(BIN_TYPE_TIMER, BIN_OUT_MEAN, timer_mean(&t->tm));
            STREAM_BIN(BIN_TYPE_TIMER, BIN_OUT_COUNT, timer_count(&t->tm));
            STREAM_BIN(BIN_TYPE_TIMER, BIN_OUT_STDDEV, timer_stddev(&t->tm));
            STREAM_BIN(BIN_TYPE_TIMER, BIN_OUT_MIN, timer_min(&t->tm));
            STREAM_BIN(BIN_TYPE_TIMER, BIN_OUT_MAX, timer_max(&t->tm));
            STREAM_BIN(BIN_TYPE_TIMER, BIN_OUT_PCT | 50, timer_query(&t->tm, 0.5));
            STREAM_BIN(BIN_TYPE_TIMER, BIN_OUT_PCT | 95, timer_query(&t->tm, 0.95));
            STREAM_BIN(BIN_TYPE_TIMER, BIN_OUT_PCT | 99, timer_query(&t->tm, 0.99));

            // Binary streaming for histograms
            if (t->conf) {
                STREAM_BIN(BIN_TYPE_TIMER, BIN_OUT_HIST_FLOOR, t->conf->min_val);
                STREAM_UINT(t->counts[0]);
                for (i=0; i < t->conf->num_bins-2; i++) {
                    STREAM_BIN(BIN_TYPE_TIMER, BIN_OUT_HIST_BIN, t->conf->min_val+(t->conf->bin_width*i));
                    STREAM_UINT(t->counts[i+1]);
                }
                STREAM_BIN(BIN_TYPE_TIMER, BIN_OUT_HIST_CEIL, t->conf->max_val);
                STREAM_UINT(t->counts[i+1]);
            }
            break;

        default:
            log_error(lg, "Unknown metric type: %d", type);
            break;
    }
    return 0;
}

void
aggregator_client(char *name)
{
    char buf[2048];
    char serveridstr[UINT128_BYTES * 2 + 2];
    char serveraddrstr[INET6_ADDRSTRLEN];
    char vdevidstr[UINT128_BYTES * 2 + 2];

    if (!GLOBAL_CONFIG->is_aggregator)
        return;

    if (!name)
        return;

    // we create a local copy and parse the local buffer
    memset(buf, 0, 2048);
    int len = strlen(name);
    strncpy(buf, name, len);
    buf[len] = '\0';

    int j = 0;
    char *token;

    /*
     * Filter by ccow.clengine.server.<serverid>.<ipv6addr>.<vdevid>.
     *
     * If this metric isn't matching, skip it...
     * Use the "." as delimiters and parse out the serverid and the address
     */
    char *cmdargv[32];
    char *sp;
    token = strtok_r(buf, ".", &sp);
    while (token != NULL) {
        cmdargv[j++] = token;
        token = strtok_r(NULL, ".", &sp);
    }
    if (j != 6) {
        return;
    }
    if ((strcmp(cmdargv[0],"ccow") != 0)
        || (strcmp(cmdargv[1], "clengine") != 0)
        || (strcmp(cmdargv[2], "server") != 0)) {
        return;
    }

    strcpy(serveridstr, cmdargv[3]);
    strcpy(serveraddrstr, cmdargv[4]);
    strcpy(vdevidstr, cmdargv[5]);

    /*
     * CCOWD sends encoded IPv6 address where ":" substitued with "_".
     *
     * Now replace the "_" in the address with the ":" to make it
     * a normal ipv6 address
     */
    for (j = 0; j < INET6_ADDRSTRLEN; j++)
        serveraddrstr[j] = (serveraddrstr[j] == '_') ? ':' : serveraddrstr[j];
    log_debug(lg, "serverid:<%s> addr:<%s> vdevid:<%s>", serveridstr, serveraddrstr, vdevidstr);

    /*
     * If the serverid is ours, skip it. Could happen since it comes from
     * corosync engine. While skipping, it doesn't mean we will not get
     * notifications from the local CCOWD. We will, via local IPC handler...
     */
    if (strcmp(serveridstr, GLOBAL_CONFIG->serveridstr) == 0) {
        // don't subscribe to ourselves
        log_debug(lg, "Self-subscribe skipped on serverid: %s", serveridstr);
        return;
    }

    char *topic = "";
    int res = auditserver_subscriber(GLOBAL_CONFIG, serveridstr,
        serveraddrstr, topic);
    if (res && res != -EEXIST) {
        log_error(lg, "Unable to subscribe. topic: %s server: %s"
            "addr: %s", topic, serveridstr, serveraddrstr);
    } else if (res != -EEXIST) {
        log_debug(lg, "Successfully subscribed to topic: <%s>", topic);
    }
}

static int publish_cb(void *data, metric_type type, char *name, void *value) {
    #define STREAM_NN(...) \
	if (sprintf(buf, __VA_ARGS__, (long long)tv->tv_sec) < 0 || \
	    nn_send(GLOBAL_PUB_FD, buf, strlen(buf), 0) < 0 || \
	    clstat_notify(buf, strlen(buf)) < 0) { \
		return 1; \
	}
    char buf[8192];
    struct timeval *tv = data;
    timer_hist *t;
    int i;
    switch (type) {
        case KEY_VAL:
            STREAM_NN("kv.%s|%f|%lld\n", name, *(double*)value);
            break;

        case GAUGE:
            STREAM_NN("gauges.%s|%f|%lld\n", name, ((gauge_t*)value)->value);
            aggregator_client(name);
            break;

        case COUNTER:
            STREAM_NN("counts.%s|%f|%lld\n", name, counter_sum(value));
            break;

        case SET:
            STREAM_NN("sets.%s|%"PRIu64"|%lld\n", name, set_size(value));
            break;

        case TIMER:
            t = (timer_hist*)value;
            STREAM_NN("timers.%s.sum|%f|%lld\n", name, timer_sum(&t->tm));
            STREAM_NN("timers.%s.sum_sq|%f|%lld\n", name, timer_squared_sum(&t->tm));
            STREAM_NN("timers.%s.mean|%f|%lld\n", name, timer_mean(&t->tm));
            STREAM_NN("timers.%s.lower|%f|%lld\n", name, timer_min(&t->tm));
            STREAM_NN("timers.%s.upper|%f|%lld\n", name, timer_max(&t->tm));
            STREAM_NN("timers.%s.count|%"PRIu64"|%lld\n", name, timer_count(&t->tm));
            STREAM_NN("timers.%s.stdev|%f|%lld\n", name, timer_stddev(&t->tm));
            STREAM_NN("timers.%s.median|%f|%lld\n", name, timer_query(&t->tm, 0.5));
            STREAM_NN("timers.%s.p95|%f|%lld\n", name, timer_query(&t->tm, 0.95));
            STREAM_NN("timers.%s.p99|%f|%lld\n", name, timer_query(&t->tm, 0.99));

            // Stream the histogram values
            if (t->conf) {
                STREAM_NN("timers.%s.histogram.bin_<%0.2f|%u|%lld\n", name, t->conf->min_val, t->counts[0]);
                for (i=0; i < t->conf->num_bins-2; i++) {
                    STREAM_NN("timers.%s.histogram.bin_%0.2f|%u|%lld\n", name, t->conf->min_val+(t->conf->bin_width*i), t->counts[i+1]);
                }
                STREAM_NN("timers.%s.histogram.bin_>%0.2f|%u|%lld\n", name, t->conf->max_val, t->counts[i+1]);
            }
            break;

        default:
            log_error(lg, "Unknown metric type: %d", type);
            break;
    }
    return 0;
}

/**
 * This is the thread that is invoked to handle flushing metrics
 */
static void* flush_thread(void *arg) {
    char *cmd;

    // Cast the args
    metrics *m = arg;

    // Get the current time
    struct timeval tv;
    gettimeofday(&tv, NULL);

    metrics_iter(m, &tv, publish_cb);

    // Determine which callback to use
    stream_callback cb = (GLOBAL_CONFIG->binary_stream)? stream_formatter_bin: stream_formatter;

    // Stream the records
    cmd = strdup(GLOBAL_CONFIG->stream_cmd);
    if (cmd != NULL) {
	    int res = stream_to_command(m, &tv, cb, cmd);
	    if (res != 0) {
		log_warn(lg, "Streaming command '%s' exited with status %d",
		    GLOBAL_CONFIG->stream_cmd, res);
	    }
	    free(cmd);
    }

    // Flush our log..
    log_flush(lg);

    // Cleanup
    destroy_metrics(m);
    je_free(m);
    return NULL;
}

/**
 * Invoked to when we've reached the flush interval timeout
 */
void flush_interval_trigger() {
    // Make a new metrics object
    metrics *m = je_malloc(sizeof(metrics));
    init_metrics(GLOBAL_CONFIG->timer_eps, (double*)&QUANTILES, NUM_QUANTILES,
            GLOBAL_CONFIG->histograms, GLOBAL_CONFIG->set_precision, m);

    // Swap with the new one
    metrics *old = GLOBAL_METRICS;
    GLOBAL_METRICS = m;

    // Start a flush thread
    pthread_t thread;
    int err = pthread_create(&thread, NULL, flush_thread, old);
    if (err == 0) {
        pthread_detach(thread);
        return;
    }

    log_warn(lg, "Failed to spawn flush thread: %s", strerror(err));
    GLOBAL_METRICS = old;
    destroy_metrics(m);
    je_free(m);
}

/**
 * Called when statsite is terminating to flush the
 * final set of metrics
 */
void final_flush() {
    // Get the last set of metrics
    metrics *old = GLOBAL_METRICS;
    GLOBAL_METRICS = NULL;
    flush_thread(old);
}


/**
 * Invoked by the networking layer when there is new
 * data to be handled. The connection handler should
 * consume all the input possible, and generate responses
 * to all requests.
 * @arg handle The connection related information
 * @return 0 on success.
 */
int handle_client_connect(statsite_conn_handler *handle) {
    // Try to read the magic character, bail if no data
    unsigned char magic;
    if (unlikely(peek_client_byte(handle->conn, &magic) == -1)) return 0;

    // Check the magic byte
    if (magic == BINARY_MAGIC_BYTE)
        return handle_binary_client_connect(handle);
    else
        return handle_ascii_client_connect(handle);
}

int process_serverinfo_reply(char **argv, int argc)
{
	int ret, i;

	if (argc <= 2) {
		// must have at least one interface or this is no good
		return -1;
	}
	statsite_config *config = GLOBAL_CONFIG;
	config->if_count = argc - 2;
	strcpy(config->serveridstr, argv[1]);
	for (i = 0; i < config->if_count; i++) {
		config->if_name[i] = je_strdup(argv[i+2]);
	}
	return 0;
}

/**
 * Invoked by the networking layer when a message is received
 * from ccowd in response to a request send from the audit server
 */
int handle_ccowd_message(char *buffer, int buffer_length)
{
	char *token = NULL;
	char serveridstr[64];

	if (!buffer) {
		return -EINVAL;
	}

	if (buffer && buffer_length > 0)
		log_info(lg, "<%s>", buffer);

        int i = 0;
        char *cmdargv[32];
	char *sp;
        token = strtok_r(buffer, ".", &sp);
        while (token != NULL) {
            cmdargv[i++] = token;
            token = strtok_r(NULL, ".", &sp);
        }

	if (strncmp(cmdargv[0], "GET_SERVERINFO_REPLY", 20) == 0) {
		int err = process_serverinfo_reply(cmdargv, i);
		if (err)
			log_error(lg, "parser error : [%d]", err);
	} else {
		log_error(lg, "Unknown command reply: <%s>", cmdargv[0]);
	}
	return 0;
}


/**
 * Simple string to double conversion
 */
static double str2double(const char *s, char **end) {
    double val = 0.0;
    char neg = 0;
    if (*s == '-') {
        neg = 1;
        s++;
    }
    for (; *s >= '0' && *s <= '9'; s++) {
        val = (val * 10.0) + (*s - '0');
    }
    if (*s == '.') {
        s++;
        double frac = 0.0;
        int digits = 0;
        for (; *s >= '0' && *s <= '9'; s++) {
            frac = (frac * 10.0) + (*s - '0');
            digits++;
        }
        val += frac / pow(10.0, digits);
    }
    if (neg) val *= -1.0;
    if (end) *end = (char*)s;
    return val;
}

/*
 * We are an aggregator.
 *
 * Auditd "clients" will send us already formatted string. We'll intercept it
 * and pass it down as is (or minimal changes)
 */
int parse_auditd_client(statsite_conn_handler *handle)
{
    // Look for the next command line
    char *buf, *key, *val_str, *type_str, *sample_str, *endptr;
    metric_type type;
    int buf_len, should_free, status, i, after_len;
    double val, sample_rate;
    while (1) {
        status = extract_to_terminator(handle->conn, '\n', &buf, &buf_len, &should_free);
        if ((status == -1) || ((buf == NULL) && (buf_len == 0)))
	    return 0; // Return if no command is available

        char *token;
        int i = 0;
        char *statargv[TS_INDEX + 1];
	char *sp = NULL;
        token = strtok_r(buf, "|", &sp);
        while (token != NULL) {
            if (i > TS_INDEX) {
                log_warn(lg, "Unexpected audit string: %s", buf);
                break;
            }
            statargv[i++] = token;
            token = strtok_r(NULL, "|", &sp);
        }

	if (i < TS_INDEX + 1) {
            log_warn(lg, "Failed auditd client metric and value! Input: %s", buf);
            goto ERR_RET;
	}
	char full_statname[4096];
	strcpy(full_statname, statargv[0]);
        val_str = statargv[1];

        char *statname[32];
        i = 0;
	char *spp;
        token = strtok_r(statargv[0], ".", &spp);
        while (token != NULL) {
            statname[i++] = token;
            token = strtok_r(NULL, ".", &spp);
        }

        /*
         * Skip non-CCOW and CCOWD_PRIVATE
         */
        if (i >= 4) {
            if (strcmp(statname[1], "ccow") != 0 ||
                (strcmp(statname[2], "clengine") == 0 &&
                 strcmp(statname[3], "server") == 0)) {
                goto END_LOOP;
            }
        }

        if (strcmp(statname[0], "timers") == 0)
            type = TIMER;
        else if (strcmp(statname[0], "gauges") == 0)
            type = GAUGE;
        else if (strcmp(statname[0], "counts") == 0)
            type = COUNTER;
        else if (strcmp(statname[0], "kv") == 0)
            type = KEY_VAL;
        else if (strcmp(statname[0], "sets") == 0)
            type = SET;
        else {
            log_warn(lg, "Failed auditd client metric type! Input: %s", buf);
            goto ERR_RET;
        }

	strcpy(buf, full_statname + strlen(statname[0]) + 1);

        // Increment the number of inputs received
        if (GLOBAL_CONFIG->input_counter)
            metrics_add_sample(GLOBAL_METRICS, COUNTER, GLOBAL_CONFIG->input_counter, 1);

        // Fast track the set-updates
        if (type == SET) {
            metrics_set_update(GLOBAL_METRICS, buf, val_str);
            goto END_LOOP;
        }

        // Convert the value to a double
        val = str2double(val_str, &endptr);
        if (unlikely(endptr == val_str)) {
            log_warn(lg, "Failed value conversion! Input: %s: %s",
                buf, val_str);
            goto ERR_RET;
        }

        // Store the sample
        metrics_add_sample(GLOBAL_METRICS, type, buf, val);

END_LOOP:
        // Make sure to free the command buffer if we need to
        if (should_free) je_free(buf);
    }

    return 0;
ERR_RET:
    if (should_free) je_free(buf);
    return -1;
}


/**
 * Invoked to handle ASCII commands. This is the default
 * mode for statsite, to be backwards compatible with statsd
 * @arg handle The connection related information
 * @return 0 on success.
 */
static int handle_ascii_client_connect(statsite_conn_handler *handle) {
    // Look for the next command line
    char *buf, *key, *val_str, *type_str, *sample_str, *endptr;
    metric_type type;
    int buf_len, should_free, status, i, after_len;
    double val, sample_rate;
    while (1) {
        status = extract_to_terminator(handle->conn, '\n', &buf, &buf_len, &should_free);
        if (status == -1) return 0; // Return if no command is available

        // Check for a valid metric
        // Scan for the colon
        status = buffer_after_terminator(buf, buf_len, ':', &val_str, &after_len);
        if (likely(!status)) status |= buffer_after_terminator(val_str, after_len, '|', &type_str, &after_len);
        if (unlikely(status)) {
            log_warn(lg, "Failed parse metric! Input: %s", buf);
            goto ERR_RET;
        }

        // Convert the type
        switch (*type_str) {
            case 'c':
                type = COUNTER;
                break;
            case 'm':
                type = TIMER;
                break;
            case 'k':
                type = KEY_VAL;
                break;
            case 'g':
                type = GAUGE;

                // Check if this is a delta update
                switch (*val_str) {
                    case '+':
                        // Advance past the + to avoid breaking str2double
                        val_str++;
                    case '-':
                        type = GAUGE_DELTA;
                }
                break;
            case 's':
                type = SET;
                break;
            case 'z':
		type = CCOWD_PRIVATE;
		break;
            default:
                type = UNKNOWN;
                log_warn(lg, "Received unknown metric type! Input: %c", *type_str);
                goto ERR_RET;
        }

	if (type == CCOWD_PRIVATE) {
            handle_ccowd_message(buf, buf_len);
            goto END_LOOP;
	}
        // Increment the number of inputs received
        if (GLOBAL_CONFIG->input_counter)
            metrics_add_sample(GLOBAL_METRICS, COUNTER, GLOBAL_CONFIG->input_counter, 1);

        // Fast track the set-updates
        if (type == SET) {
            metrics_set_update(GLOBAL_METRICS, buf, val_str);
            goto END_LOOP;
        }

        // Convert the value to a double
        val = str2double(val_str, &endptr);
        if (unlikely(endptr == val_str)) {
            log_warn(lg, "Failed value conversion! Input: %s", val_str);
            goto ERR_RET;
        }

        // Handle counter sampling if applicable
        if (type == COUNTER && !buffer_after_terminator(type_str, after_len, '@', &sample_str, &after_len)) {
            sample_rate = str2double(sample_str, &endptr);
            if (unlikely(endptr == sample_str)) {
                log_warn(lg, "Failed sample rate conversion! Input: %s", sample_str);
                goto ERR_RET;
            }
            if (sample_rate > 0 && sample_rate <= 1) {
                // Magnify the value
                val = val * (1.0 / sample_rate);
            }
        }

        // Store the sample
        metrics_add_sample(GLOBAL_METRICS, type, buf, val);

END_LOOP:
        // Make sure to free the command buffer if we need to
        if (should_free) je_free(buf);
    }

    return 0;
ERR_RET:
    if (should_free) je_free(buf);
    return -1;
}

// Handles the binary set command
// Return 0 on success, -1 on error, -2 if missing data
static int handle_binary_set(statsite_conn_handler *handle, uint16_t *header, int should_free) {
    /*
     * Abort if we haven't received the command
     * header[1] is the key length
     * header[2] is the set length
     */
    char *key;
    int val_bytes = header[1] + header[2];

    // Read the full command if available
    if (unlikely(should_free)) je_free(header);
    if (read_client_bytes(handle->conn, MIN_BINARY_HEADER_SIZE + val_bytes, (char**)&header, &should_free))
        return -2;
    key = ((char*)header) + MIN_BINARY_HEADER_SIZE;

    // Verify the null terminators
    if (unlikely(*(key + header[1] - 1))) {
        log_warn(lg, "Received command from binary stream with non-null terminated key: %.*s!", header[1], key);
        goto ERR_RET;
    }
    if (unlikely(*(key + val_bytes - 1))) {
        log_warn(lg, "Received command from binary stream with non-null terminated set key: %.*s!", header[2], key+header[1]);
        goto ERR_RET;
    }

    // Increment the input counter
    if (GLOBAL_CONFIG->input_counter)
        metrics_add_sample(GLOBAL_METRICS, COUNTER, GLOBAL_CONFIG->input_counter, 1);

    // Update the set
    metrics_set_update(GLOBAL_METRICS, key, key+header[1]);

    // Make sure to free the command buffer if we need to
    if (unlikely(should_free)) je_free(header);
    return 0;

ERR_RET:
    if (unlikely(should_free)) je_free(header);
    return -1;
}

/**
 * Invoked to handle binary commands.
 * @arg handle The connection related information
 * @return 0 on success.
 */
static int handle_binary_client_connect(statsite_conn_handler *handle) {
    metric_type type;
    uint16_t key_len;
    int should_free;
    unsigned char *cmd, *key;
    while (1) {
        // Peek and check for the header. This is up to 12 bytes.
        // Magic byte - 1 byte
        // Metric type - 1 byte
        // Key length - 2 bytes
        // Metric value - 8 bytes OR Set Length 2 bytes
        if (peek_client_bytes(handle->conn, MIN_BINARY_HEADER_SIZE, (char**)&cmd, &should_free))
            return 0;  // Return if no command is available

        // Check for the magic byte
        if (unlikely(cmd[0] != BINARY_MAGIC_BYTE)) {
            log_warn(lg, "Received command from binary stream without magic byte! Byte: %u", cmd[0]);
            goto ERR_RET;
        }

        // Get the metric type
        switch (cmd[1]) {
            case BIN_TYPE_KV:
                type = KEY_VAL;
                break;
            case BIN_TYPE_COUNTER:
                type = COUNTER;
                break;
            case BIN_TYPE_TIMER:
                type = TIMER;
                break;
            case BIN_TYPE_GAUGE:
                type = GAUGE;
                break;
            case BIN_TYPE_GAUGE_DELTA:
                type = GAUGE_DELTA;
                break;

            // Special case set handling
            case BIN_TYPE_SET:
                switch (handle_binary_set(handle, (uint16_t*)cmd, should_free)) {
                    case -1:
                        return -1;
                    case -2:
                        return 0;
                    default:
                        continue;
                }

            default:
                log_warn(lg, "Received command from binary stream with unknown type: %u!", cmd[1]);
                goto ERR_RET;
        }

        // Abort if we haven't received the full key, wait for the data
        key_len = *(uint16_t*)(cmd+2);

        // Read the full command if available
        if (unlikely(should_free)) je_free(cmd);
        if (read_client_bytes(handle->conn, MAX_BINARY_HEADER_SIZE + key_len, (char**)&cmd, &should_free))
            return 0;
        key = cmd + MAX_BINARY_HEADER_SIZE;

        // Verify the key contains a null terminator
        if (unlikely(*(key + key_len - 1))) {
            log_warn(lg, "Received command from binary stream with non-null terminated key: %.*s!", key_len, key);
            goto ERR_RET;
        }

        // Increment the input counter
        if (GLOBAL_CONFIG->input_counter)
            metrics_add_sample(GLOBAL_METRICS, COUNTER, GLOBAL_CONFIG->input_counter, 1);

        // Add the sample
        metrics_add_sample(GLOBAL_METRICS, type, (char *)key, *(double*)(cmd+4));

        // Make sure to free the command buffer if we need to
        if (unlikely(should_free)) je_free(cmd);
    }
    return 0;
ERR_RET:
    if (unlikely(should_free)) je_free(cmd);
    return -1;
}


/**
 * Scans the input buffer of a given length up to a terminator.
 * Then sets the start of the buffer after the terminator including
 * the length of the after buffer.
 * @arg buf The input buffer
 * @arg buf_len The length of the input buffer
 * @arg terminator The terminator to scan to. Replaced with the null terminator.
 * @arg after_term Output. Set to the byte after the terminator.
 * @arg after_len Output. Set to the length of the output buffer.
 * @return 0 if terminator found. -1 otherwise.
 */
static int buffer_after_terminator(char *buf, int buf_len, char terminator, char **after_term, int *after_len) {
    // Scan for a space
    char *term_addr = memchr(buf, terminator, buf_len);
    if (!term_addr) {
        *after_term = NULL;
        return -1;
    }

    // Convert the space to a null-seperator
    *term_addr = '\0';

    // Provide the arg buffer, and arg_len
    *after_term = term_addr+1;
    *after_len = buf_len - (term_addr - buf + 1);
    return 0;
}
