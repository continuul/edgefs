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
#ifndef _FH_PRIVATE_H__
#define _FH_PRIVATE_H__


/* 10 PB cluster at  4 TB per drive would result in 2500 devices
 * we pad that upto 3000 devices
 * If we choose 3 vdevs per server, we take the max as 1000
 * servers
 *
 * */
#define FLEXHASH_MAX_VDEVS		3000
#define FLEXHASH_MAX_SERVERS		1000
#define FLEXHASH_MAX_ZONES		30


/* use this on selecting the vdevs on rebalance. this is per row so
 * is pretty high
 */
#define FH_MAX_VDEVS_PER_SERVER		64
#define FH_MIN_VDEVS_PER_SERVER		3

/* must have this many servers at least for min server-domain-policy */
#define FH_MIN_SERVER_COUNT		3
#define FH_MIN_ZONE_COUNT		3

#define FH_REP_COUNT_SUPPORTED		8
#define FH_MIN_SERVER_PER_ROW		4
#define FH_MIN_ZONES_PER_ROW		4
#define FH_MIN_RCOUNT			6

#define FLEXHASH_MAX_TAB_LENGTH		FLEXCOUNT_TAB_LENGTH

struct flexhash;

/* compute the number of devices per row */
int flexhash_devs_perrow(volatile struct flexhash *fhtable, int numdevices);

/* stats per negotiation group */
struct ngstat {
	/* Store last N rtt times for unsolicited messages */
	struct avg_ring avg_unsol_ring;
	/* Store last N rtt times for put select messages */
	struct avg_ring avg_put_select_ring;
	/* Store last N rtt times for get select messages */
	struct avg_ring avg_namedget_select_ring;
	/* Store last N rtt times for get select messages */
	struct avg_ring avg_unnamedget_select_ring;
	/* Store last N rtt times for GET solicited messages */
	struct avg_ring	avg_get_sol_ring;
	/* Store last N rtt times for PUT solicited messages */
	struct avg_ring	avg_put_sol_ring;
	/* Average unsolicited message RTT */
	uint64_t	    avg_unsol_rtt;
	/* Average unsolicited select message RTT put */
	uint64_t	    avg_put_select_rtt;
	/* Average unsolicited named get select RTT */
	uint64_t	    avg_namedget_select_rtt;
	/* Average unsolicited unnamed get select RTT */
	uint64_t	    avg_unnamedget_select_rtt;
	/* Average GET solicited message RTT */
	uint64_t	    avg_get_sol_rtt;
	/* Average PUT solicited message RTT */
	uint64_t	    avg_put_sol_rtt;

	/* % free for capacity for the row */
	double		    avg_avail;

	/* number of alive servers for this row */
	int		    alive_servercount;
	/* number of distinct servers for this row */
	int		    servercount;
	/* number of distinct zones for this row */
	int		    zonecount;
	/* number of alive zones for this row */
	int		    alive_zonecount;
	/* list of zones for this row */
	uint8_t		    zonelist[FLEXHASH_MAX_ZONES];
};


/* linked list of pointers to vdevs */
struct dlist {
	volatile int	numdevs;	/* number of devices in this row */
	struct fhdev	*devlist;	/* list of devices in this row */
	struct ngstat	ngstat;		/* stats for this row */
	int		deltadevs;	/* are we under-served over-served? */
	uint64_t	avail_median;	/* Median available storage space */
};
int dlist_find_id(struct dlist *dlist, uint128_t *id);


/* linked list element. Each element should point to a vdev */
struct fhdev {
	struct lvdev	*vdev;		/* pointer to the main in-memory sdev */
	struct fhdev	*next;		/* pointer to the next element */
};

int dlist_add(struct dlist *dlist, struct fhdev *fhdev);
int dlist_delete(struct dlist *dlist, uint128_t *vdevid);
int dlist_member(struct dlist *dlist, uint128_t *id);
int dlist_append(struct dlist *head, struct dlist *tail);
void dlist_free(struct dlist *dlist);

struct rowcount {
	int count;		/* how many rows this one is in */
	int mean_count;		/* median numrows participation on all devices */
	int deltarows;		/* delta of rows per device and the actual rows */
	int numrows;		/* number of rows in the flexhash, for hashcount */
	float rowusage;		/* active rows as a pct of numrows */
	float spaceusage;		/* pct of space usage */
	uint8_t hashcount[FLEXHASH_MAX_TAB_LENGTH]; /* hashcount  */
};

struct rebuild_ctx {
	int rebuild;
	int expected_nr_nodes;
	int rcvd_nr_nodes;
	struct flexhash *fhtable;
};

typedef uint16_t			fhrow_t;

void set_unique_servercount(struct dlist *dl);

/* use this on selecting the vdevs on rebalance. this is per row so
 * is pretty high
 */
#define FH_MAX_VDEVS_PER_SERVER		64
#define FH_MIN_VDEVS_PER_SERVER		3

#define FH_ALLOW_SHRINKAGE		0

// forward declaration
struct repdev;

typedef enum vdev_types {
	FH_TYPE_GENERIC			= 0x000,
	FH_TYPE_7K_HDD			= 0x001,
	FH_TYPE_10K_HDD			= 0x002,
	FH_TYPE_15K_HDD			= 0x004,
	FH_TYPE_SMR_HDD			= 0x008,
	FH_TYPE_MLC_SSD			= 0x010,
	FH_TYPE_SLC_SSD			= 0x020,
	FH_TYPE_PCIE_SSD		= 0x040,
	FH_TYPE_DRAM_SSD		= 0x080,
	FH_TYPE_MRAM_SSD		= 0x100
} vdev_types_t;

typedef enum server_types {
	FH_ROLE_DESIGNATED_SERVER	= 0x001,
	FH_ROLE_VACHE_SERVER		= 0x002,
	FH_ROLE_GATEWAY_SERVER		= 0x004,
	FH_ROLE_ARCHIVE_SERVER		= 0x008,
	FH_ROLE_NOTIFICATION_SERVER	= 0x010,
	FH_ROLE_AUDIT_SERVER		= 0x020
} server_types_t;


typedef enum weight_factors {
	FH_WEIGHT_CPU_SPEED,		/* 1.5 GHz = 1 */
	FH_WEIGHT_BUS_WIDTH,		/* 32-bit = 1 */
	FH_WEIGHT_MEM_CAPACITY,		/* 2 GB = 1 */
	FH_WEIGHT_STORAGE_CAPACITY,	/* 500GB = 1 */
	FH_WEIGHT_NETWORK_CAPACITY,	/* 1GbE = 1 */
	FH_WEIGHT_STORAGE_THROUGHPUT,	/* 10K IOP = 1 */
	FH_WEIGHT_MAX_WEIGHT_FACTORS	/* placeholder */
} weight_factors_t;

#define FH_CAPACITY_STORAGE_WF		(2^16)
#define FH_LATENCY_STORAGE_WF		(2^16)

typedef uint128_t		sdevid_t;
#define COMPARE_SDEVID(x, y)	uint128_cmp(x, y)
#define MAX_SDEVID_STR		UINT128_BYTES * 2 + 2
#define SDEVID_DUMP(v, o)	uint128_dump(v, o, MAX_SDEVID_STR);

#define DEFAULT_TIMESLICE_MS	25		/* 25 ms */
#define DEFAULT90_TIMESLICE_MS	1500		/* 1.5 seconds for 90th percentile */
#define FH_DEFAULT_NG_RTT	20		/* default value for RTT, us */

#define FH_BYTES_TO_MIB(sz)	((sz) >> 20)	/* Convert bytes to MiB (MB) */
#define FH_MIBS_TO_BYTES(sz)	((sz) << 20)	/* Convert MiB (MB) to bytes */


void set_unique_zonecount(struct dlist *dl);


void fhrebalance_setdevice_hashcount(struct flexhash *fhtable);
void fhrebalance_free_rcount(struct flexhash *fhtable);

#define FH_CLIENT_SIDE 1
#define FH_SERVER_SIDE 2

#endif /* _FH_PRIVATE_H__ */
