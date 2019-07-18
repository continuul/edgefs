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

#define MAX_RPDEV 255

#include <getopt.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#include "lfq.h"
#include "reptrans.h"
#include "rtrd/reptrans-rd.h"
#include "ccowutil.h"

#define CHIDS_RANDOM (1 << 0)
#define CHIDS_STORE (1 << 1)
#define CHIDS_FROM_CACHE (1 << 2)

Logger lg; // without a logger libreptrans crashes
struct repdev *rpdev[MAX_RPDEV];
char *transport[1] = {"rtrd"};

#define DEV_RD_PARTS 64

struct enum_dev_arg {
    int n_dev;
    struct repdev **dev;
};

/* structure per device */
typedef struct job_thread {
    pthread_t *t;
    struct repdev *dev;
    int blob_count;
    int prev_count;
} job_thread_t;

/* structure per thread per device */
typedef struct dev_thread {
    uint32_t start;
    uint32_t stop;
    job_thread_t *job;
} dev_thread_t;

typedef struct lmdb_stat_cb {
    uint32_t data[DEV_RD_PARTS];
    uint32_t log_data[DEV_RD_PARTS];
    uint32_t tt_mask;
} lmdb_stat_cb_t;

job_thread_t *job_list;

struct avg_ring bps_avg_ring;
uint32_t global_progress;

struct sigaction action;
struct timeval g_start;
uint32_t n_blobs = 0; // # op blobs we write per vdev
uint32_t shut_down = 0;

struct enum_dev_arg devices = {0, rpdev};

uint512_t *g_chid; // array containing our pre calculated hashes

struct opt {
    int32_t blob_size;   // size of the blog to be written
    int32_t utilization; // percentage of devices to fill
    int32_t threads;     // threads per device
    int32_t grafana;
    char *header; // metric name for grafana server
    int info;     // print device info
} opt = {.blob_size = 32 * 1024,
         .utilization = 10,
         .threads = 4,
         .grafana = 0,
         .info = 0,
         .header = NULL};

void log_devices(struct enum_dev_arg *devices, int verbose);

uint32_t get_blob_count(struct enum_dev_arg *devices);

static void
enum_cb(struct repdev *dev, void *arg, int status) {

    struct enum_dev_arg *da = (struct enum_dev_arg *) arg;

    if (status == 0)
        da->dev[da->n_dev++] = dev;
}

/* intialize reptrans and partition devices when invalid config is found */

int
init(void) {

    if (reptrans_init(0, NULL, NULL, RT_FLAG_STANDALONE | RT_FLAG_CREATE, 1,
                      (char **) transport, NULL) <= 0) {
        log_error(lg, "Failed reptrans_init()\n");
        return 1;
    }

    if (reptrans_enum(NULL, &devices, enum_cb, 0) != 0) {
        log_error(lg, "Failed to enumerate devices\n");
        return 1;
    }

    log_devices(&devices, 0);
    n_blobs = get_blob_count(&devices);

    log_info(lg, "number of per-device blobs based on smallest device: %d",
             n_blobs);

    return 0;
}

int
fini(void) {
	reptrans_destroy();
	reptrans_close_all_rt();
    return 0;
}

/*
 * get usage info from directly from the DB's
 * we only collect TT_CHUCK_PAYLOAD for now
 */
part_walk_action_t
get_lmdb_stat(struct repdev_db *db, void *arg) {

    MDB_txn *txn;
    MDB_stat mst;

    lmdb_stat_cb_t *cb = (lmdb_stat_cb_t *) arg;
    struct repdev *dev = db->dev;
    struct repdev_log *log = &db->log[0];

    int err;

    if ((err = mdb_txn_begin(DEV_ENV(db, TT_CHUNK_PAYLOAD), NULL, MDB_RDONLY,
                             &txn)) != 0)
        return PART_WALK_TERMINATE;

    for (int i = 0; i < DEV_SHARDS_MAX; i++) {
        if ((err = mdb_stat(txn, DEV_SHARD(db, TT_CHUNK_PAYLOAD, i), &mst)) !=
            0)
            return PART_WALK_TERMINATE;
        cb->data[db->part] =
            (mst.ms_psize *
             (mst.ms_branch_pages + mst.ms_leaf_pages + mst.ms_overflow_pages) /
             (1024 * 1024));
    }

    mdb_txn_abort(txn);

    if (dev->wal_disabled == 0) {

        /*
         * add the info from the log
         */

        if ((err = mdb_txn_begin(log->env, NULL, MDB_RDONLY, &txn)) != 0)
            return PART_WALK_TERMINATE;

        if ((err = mdb_stat(txn, log->dbi[TT_CHUNK_PAYLOAD], &mst)) != 0)
            return PART_WALK_TERMINATE;

        cb->log_data[db->part] =
            (mst.ms_psize *
             (mst.ms_branch_pages + mst.ms_leaf_pages + mst.ms_overflow_pages) /
             (1024 * 1024));
    }

    mdb_txn_abort(txn);

    if (err != 0)
        return PART_WALK_TERMINATE;

    return PART_WALK_CONTINUE;
}

void
log_devices(struct enum_dev_arg *devices, int verbose) {

    if (verbose == 0) {
        for (int i = 0; i < devices->n_dev; i++) {
            log_info(
                lg, "device: %s, path: %s, journal: %s, bcache: %d size: %ld"
                    "used: %ld, free %ld",
                devices->dev[i]->name, devices->dev[i]->path,
                devices->dev[i]->journal, devices->dev[i]->bcache,
                devices->dev[i]->stats.capacity, devices->dev[i]->stats.used,
                devices->dev[i]->stats.capacity - devices->dev[i]->stats.used);
        }
    }
}

uint32_t
get_blob_count(struct enum_dev_arg *devices) {

    uint64_t min =
        devices->dev[0]->stats.capacity - devices->dev[0]->stats.used;

    if (devices->n_dev == 1)
        goto _out;

    for (int i = 1; i < devices->n_dev; i++) {
        if ((devices->dev[i]->stats.capacity - devices->dev[i]->stats.used) <
            min)
            min = devices->dev[i]->stats.capacity - devices->dev[i]->stats.used;
    }

_out:
    log_info(lg, "smallest amount of free space %ld", min);
    float u = (float) opt.utilization / 100;
    return ((uint32_t)((u * min) / opt.blob_size));
}

int
generate_chids(uint32_t n_bolbs, uint32_t flags) {

    rtbuf_t *rb;
    g_chid = je_calloc(n_bolbs, sizeof(uint512_t));

    if (!g_chid) {
        log_error(lg, "No memory\n");
        exit(-ENOMEM);
    }

    /*
     * if you nezap a lot this can speed things up
     * its purpose how ever is to run r/w test using
     * previously inserted k/v
     */
    if (flags & CHIDS_FROM_CACHE) {
        FILE *f;

        if ((f = fopen("chids_cache", "r")) != NULL) {

            uint32_t c = fread(g_chid, sizeof(uint512_t), n_bolbs, f);
            fclose(f);

            if (c != n_bolbs) {
                log_info(lg, "c is: %d n = %d\n", c, n_bolbs);
                log_info(lg, "cache is garbage; regenerating and overwriting "
                             "cache file\n");
                remove("chids_cache");
            } else {
                log_info(
                    lg,
                    "%d blobs loaded from cache -- make sure you nezapped!\n",
                    c);
                return 0;
            }
        } else {
            flags |= CHIDS_STORE;
        }
    }

    if (flags & CHIDS_RANDOM) {
        gettimeofday(&g_start, NULL);
    } else {
        g_start.tv_usec = 10000;
        g_start.tv_sec = 34545;
    }

    if ((rb = rtbuf_init_alloc_one(opt.blob_size)) == NULL) {
        log_error(lg, "No memory\n");
        exit(-ENOMEM);
    }

    log_info(lg, "Starting generation of %d CHIDs", n_bolbs);
    uint64_t start = uv_hrtime();

    for (uint32_t i = 0; i < n_bolbs; i++) {
        ((uint32_t *) rtbuf(rb, 0).base)[0] = g_start.tv_usec + i;
        ((uint32_t *) rtbuf(rb, 0).base)[1] = g_start.tv_sec;

        if (rtbuf_hash(rb, HASH_TYPE_XXHASH_256, &g_chid[i]) != 0) {
            log_info(lg, "Error during hash calculation");
            rtbuf_destroy(rb);
            return 1;
        }
    }

    if (flags & CHIDS_STORE) {
        FILE *f;
        if ((f = fopen("chids_cache", "w+")) == NULL) {
            log_info(lg, "failed to create chid chache file");
            return 1;
        }

        uint32_t c = fwrite(g_chid, sizeof(uint512_t), n_bolbs, f);
        if (c != n_bolbs) {
            log_info(lg, "failed to store cached chids");
            fclose(f);
            unlink("chids_cache");
        } else {
            fclose(f);
        }
    }

    rtbuf_destroy(rb);
    log_info(lg, "took %lus", (uint64_t)((uv_hrtime() - start) / 1e9));
    return 0;
}

void
usage() {

    printf("\n-s\t blob_size in bytes\n");
    printf("-u\t utlization in perecent of the device\n");
    printf("-t\t number of threads per device\n");
    printf(
        "-g\t send data to graphite, requires GRAFANA_SERVER env to be set\n");
    printf("-h\t requirerd with -g, to name the metric send to grafana\n");

    printf("\nexamples:\n\n");

    printf("write up to 80 percent of blobs of default size (32k):\n");
    printf("\t rtbench -u 80\n\n");

    printf("write up to 80 percent of blobs size 64k:\n");
    printf("\t rtbench -u 80 -s 655536\n\n");

    printf("same but send to grafana:\n\n");

    printf("\t rtbench -u 80 -s 655536 -g -h myexperimentname\n\n");

}

/*
 * each device will have opt.thread writers
 */

void *
put_blob_thread(void *arg) {

    dev_thread_t *data = (dev_thread_t *) arg;

    int32_t err = 0;
    rtbuf_t *rb = rtbuf_init_alloc_one(opt.blob_size);
    memset(rtbuf(rb, 0).base, 0, opt.blob_size);

    log_info(lg, "[tid: %lu] %d --> %d", pthread_self(), data->start,
               data->stop);

    for (uint32_t i = data->start; err == 0 && shut_down == 0 && i < data->stop;
         i++) {

        ((uint32_t *) rtbuf(rb, 0).base)[0] = g_start.tv_usec + i;
        ((uint32_t *) rtbuf(rb, 0).base)[1] = g_start.tv_sec;

        err = reptrans_put_blob_with_attr(data->job->dev, TT_CHUNK_PAYLOAD,
                                          HASH_TYPE_XXHASH_256, rb, &g_chid[i],
                                          0, -1);
        if (err) {
            log_error(lg, "error putting blob %d", err);
            fini();
			shut_down = 1;
		}
        data->job->blob_count++;
        global_progress++;
    }
    return NULL;
}

/*
 * each device will have one start thread
 */

void *
start_per_dev_threads(void *arg) {

    job_thread_t *job = (job_thread_t *) arg;
    struct repdev *dev = job->dev;

    uint32_t bpt = n_blobs / opt.threads;

    dev_thread_t *dp = (dev_thread_t *) je_malloc(opt.threads * sizeof(*dp));
    pthread_t *thread_list =
        (pthread_t *) je_malloc(opt.threads * sizeof(*thread_list));

    for (int32_t c = 0; c < opt.threads; c++) {
        dp[c].start = c * bpt;
        dp[c].stop = (c + 1) * bpt;
        dp[c].job = job;
    }

    dp[opt.threads - 1].stop = n_blobs;

    for (int32_t c = 0; c < opt.threads; c++)
        pthread_create(&thread_list[c], NULL, &put_blob_thread,
                       (void *) &dp[c]);

    for (int c = 0; c < opt.threads; c++)
        pthread_join(thread_list[c], NULL);

    printf("\n"); // avoid clobber of progress
    log_info(lg, "all threads joined for device %s", dev->name);

    return NULL;
}

void
sighandler(int sig, siginfo_t *siginfo, void *context) {

    shut_down = 1;
    exit(1);
}

void *
put_blob_progress() {

    int prev = 0;
    lmdb_stat_cb_t cb = {{0}};

    do {
        uint64_t bps_avg = avg_ring_update(&bps_avg_ring,
                                   (uint64_t)(global_progress - prev));
        log_notice(lg, "n_blobs: %d (for all devices), written blobs: %d, bps: "
                     "%ld, MB/s: %ld",
                 n_blobs * devices.n_dev, global_progress, bps_avg,
                 bps_avg * opt.blob_size / 1024 / 1024);
        prev = global_progress;

        for (int i = 0; i < devices.n_dev; i++) {
            log_info(lg, "%s bps : %d", job_list[i].dev->name,
                       job_list[i].blob_count - job_list[i].prev_count);
            job_list[i].prev_count = job_list[i].blob_count;
        }

        for (int d = 0; d < devices.n_dev; d++) {
            rd_partition_walk(devices.dev[d], get_lmdb_stat, &cb);

            log_info(lg, "%s %7s %7s %7s", devices.dev[d]->name, "Part",
                       "Main used", "Log used");

            for (int i = 0; i < DEV_RD_PARTS; i++) {
                log_info(lg, "%39s %7d  %7u  %7u", "", i, cb.data[i],
                           cb.log_data[i]);
            }
        }

        sleep(1);
    } while (shut_down == 0);

    return NULL;
}

char *
join_strings(lfqueue_t q, int count) {
    char *item;

    char *str = (char *) malloc(count);
    str[0] = '\0';

    while ((item = lfqueue_dequeue(q)) != NULL) {
        strcat(str, item);
        free(item);
    }

    return str;
}

void *
put_blob_progress_grafana() {

    int sfd;
    const char *server;
    struct sockaddr_in remoteaddr;
    char hostname[1024] = {0};
    lmdb_stat_cb_t cb = {{0}, {0}, 0};

    int prev = 0;
    gethostname(&hostname[0], 1024);

    /*
     * we queue the metrics and send them in one batch vs. send each
     * metric as it comes. This works better for graphite
     */

    char *grafana_metric = (char *) malloc(8096);

    if ((server = getenv("GRAFANA_SERVER")) == NULL) {
        printf("please set GRAFANA_SERVER environment variable\n");
        exit(0);
    }

    if ((sfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        log_info(lg, "failed to create socket");
        exit(0);
    }

    remoteaddr.sin_family = AF_INET;
    remoteaddr.sin_addr.s_addr = inet_addr(server);
    remoteaddr.sin_port = htons(2003);

    if (connect(sfd, (struct sockaddr *) &remoteaddr, sizeof(remoteaddr)) !=
        0) {
        log_info(
            lg,
            "error connecting, perhaps try fusion? its the same... mostly\n");
        return NULL;
    }

    /* enable NODELAY */
    int flag = 1;
    setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));

    log_info(lg, "starting grafana feed");

    size_t len;
    uint32_t t;
    char *msg;
    char *metric = NULL;
    do {

        t = time(NULL);
        len = 0;

        // TODO use snprint()
        for (int d = 0; d < devices.n_dev; d++) {

            len += sprintf(grafana_metric + len, "%s.%s.%s.bps %d %d\n",
                           hostname, opt.header, devices.dev[d]->name,
                           job_list[d].blob_count - job_list[d].prev_count, t);
            job_list[d].prev_count = job_list[d].blob_count;

            rd_partition_walk(devices.dev[d], get_lmdb_stat, &cb);

            for (int i = 0; i < DEV_RD_PARTS; i++) {
                len += sprintf(grafana_metric + len, "%s.%s.%s.data.%d %d %d\n",
                               hostname, opt.header, devices.dev[d]->name, i,
                               cb.data[i], t);

                len += sprintf(grafana_metric + len, "%s.%s.%s.WAL.%d %d %d\n",
                               hostname, opt.header, devices.dev[d]->name, i,
                               cb.log_data[i], t);
            }
        }

        send(sfd, grafana_metric, len, 0);
        printf("%s", &grafana_metric[0]);
        fflush(stdout);
        sleep(1);
    } while (shut_down == 0);

    return NULL;
}

int
main(int argc, char *argv[]) {

    lg = Logger_create("rtbench");

    while (1) {
        int opt_index;
        int c;
        static struct option long_options[] = {
            {"help", 0, 0, 'h'},    {"utilization", 0, 0, 'u'},
            {"size", 0, 0, 's'},    {"threads", 0, 0, 't'},
            {"grafana", 0, 0, 'g'}, {"header", 0, 0, 'h'},
            {"info", 0, 0, 'i'},    {NULL}};

        c = getopt_long(argc, argv, "gh:u:s:t:i", long_options, &opt_index);

        if (c == -1)
            break;

        switch (c) {

            case 's':
                opt.blob_size = atol(optarg);
                break;
            case 'u':
                opt.utilization = atol(optarg);
                break;
            case 'g': // use existing blobs and load cache
                opt.grafana = 1;
                break;
            case 't':
                opt.threads = atol(optarg);
                break;
            case 'h':
                opt.header = optarg;
                break;
            case 'i':
                opt.info = 1;
                break;
            default:
                log_error(lg, "invalid options");
                usage();
                exit(1);
        }
    }

    action.sa_sigaction = sighandler;
    action.sa_flags = SA_SIGINFO;
    sigaction(SIGINT, &action, NULL);

    if (opt.grafana &&
        (opt.header == NULL || (getenv("GRAFANA_SERVER") == NULL))) {
        printf("grafana requires a header for its metric name and "
               "GRAFANA_SERVER environment");
        return 0;
    }

    log_info(lg, "blob size %d, utilization %d", opt.blob_size,
             opt.utilization);

    if (init() != 0)
        exit(1);

    if (generate_chids(n_blobs, CHIDS_RANDOM | CHIDS_STORE) != 0)
        exit(1);

    if (opt.info == 1) {
        lmdb_stat_cb_t cb = {{0}, {0}, 0};
        rd_partition_walk(devices.dev[0], get_lmdb_stat, &cb);
        for (int i = 0; i < DEV_RD_PARTS; i++) {
            log_info(lg, "part used %d\n", cb.data[i]);
        }

        return 0;
    }

    job_list = (job_thread_t *) je_malloc(devices.n_dev * sizeof(job_thread_t));

    for (int i = 0; i < devices.n_dev; i++) {
        log_info(lg, "starting worker threads for %s", devices.dev[i]->name);

        job_list[i].dev = devices.dev[i];
        job_list[i].blob_count = 0;
        job_list[i].prev_count = 0;

        pthread_create((pthread_t *) &job_list[i].t, NULL,
                       &start_per_dev_threads, (void *) &job_list[i]);
    }

    pthread_t progress;
    sleep(1);
    if (opt.grafana == 0)
        pthread_create(&progress, NULL, &put_blob_progress, NULL);
    else
        pthread_create(&progress, NULL, &put_blob_progress_grafana, NULL);

    for (int i = 0; i < devices.n_dev; i++)
        pthread_join(*job_list[i].t, NULL);

    shut_down = 1;

    pthread_join(progress, NULL);

    fini();
}
