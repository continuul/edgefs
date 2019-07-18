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
#ifndef __FLEXHASH_H__
#define __FLEXHASH_H__

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This particular typedef should be included at a ccow level.
 */
typedef uuint128_t server_id_t ;

/*
 * These are the entry points to the flexhash routines that are
 * available to other programs in the CCOW system.
 */
struct flexhash_table util_flexhash = {
	.name		= "flexhash",
	.version	= "1.0",

	.init		= flexhash_init,	/* Initialize */
	.join		= flexhash_join,	/* A server joins */
	.leave		= flexhash_leave,	/* A server leaves */
	.rorow		= flexhash_rorow,	/* a server goes RO for a */
						/* row */
	.lvrow		= flexhash_lvrow,	/* a server leaves a row */
	.jnrow		= flexhash_jnrow,	/* a server joins a row */
	.getrows	= flexhash_notify,	/* get the list of rows */
						/* that server belongs to */
	.getonerow	= flexhash_row,		/* retrieve a single row */
						/* from the flexhash_table */
	.dispatch	= flexhash_dispatch,	/* Forgot why we have this */
};

/*
 * A server that is a designated_server may enter READ_ONLY mode
 * for particular hash rows in which it resides.  This means that
 * all assets on that server which are held in that row will be
 * replicated to other designated servers.  Note that this can
 * be used for a lazy migration of rows to other servers. When
 * the replication process has confirmed that an asset in a
 * READ_ONLY role has been replicated to a sufficient count of
 * other designated copies, then the READ_ONLY copy can be placed
 * on the "to be deleted" queue.  This does not mean that the
 * asset is immediately deleted, just that it will be deleted at
 * a convenient time.
 */
typedef enum {
	FH_ROLE_DESIGNATED_SERVER	= 0X001,
	FH_ROLE_VACHE_SERVER		= 0X002,
	FH_ROLE_GATEWAY_SERVER		= 0X004,
	FH_ROLE_ARCHIVE_SERVER		= 0X008,
	FH_ROLE_NOTIFICATION_SERVER	= 0X010,
	FH_ROLE_AUDIT_SERVER		= 0X020
} server_roles_t;

typedef enum {
	FH_TYPE_7K_HDD			= 0X001,
	FH_TYPE_10K_HDD			= 0X082,
	FH_TYPE_15K_HDD			= 0X004,
	FH_TYPE_SMR_HDD			= 0X008,
	FH_TYPE_MLC_SSD			= 0X010,
	FH_TYPE_SLC_SSD			= 0X020,
	FH_TYPE_PCIE_SSD		= 0X040,
	FH_TYPE_DRAM_SSD		= 0X080,
	FH_TYPE_MRAM_SSD		= 0X100
} vdev_types_t;

/*
 * These are the weighting factors used to score the number of hash
 * rows in which a server or device will appear.
 */
typedef enum {
	FH_WEIGHT_CPU_SPEED,		/* 1.5 GHz = 1 */
	FH_WEIGHT_BUS_WIDTH,		/* 32-bit = 1 */
	FH_WEIGHT_MEM_CAPACITY,		/* 2 GB = 1 */
	FH_WEIGHT_STORAGE_CAPACITY,	/* 500GB = 1 */
	FH_WEIGHT_NETWORK_CAPACITY,	/* 1GbE = 1 */
	FH_WEIGHT_STORAGE_THROUGHPUT,	/* 10K IOP = 1 */
	FH_WEIGHT_MAX_WEIGHT_FACTORS	/* placeholder */
} weight_factors_t;

/*
 * Failure Domains are the distinct domains which can lead to particular
 * typed of failures.  Some of the more prominent domains:
 *
 * Postal Code		This may seem like overkill, but it is highly desirable
 *			to place assets in distinct postal codes if that level
 *			of distribution is available.
 *
 * Power Grid		There are multiple power zones within a data center.
 *			in additon to the commercial power feed, there may be
 *			one or more UPS zones.
 *
 * Building		The building number can separate groups of servers into
 *			separate failure domains which may or may not map to
 *			power grids.
 *
 * Cooling		There may be multiple cooling/HVAC domains within a
 *			building
 *
 * Floor		A basement may be prone to flood damage
 *
 * Room			A specific room may be shut down for reasons of
 *			HVAC/power unrelated to the grid or HVAC zone
 *
 * Rack			A rack may need to be decommissioned to retire it from
 *			its lease and be replaced
 *
 * Network/Subnet	The network can be partitioned due to switch and/or
 *			router failures.  For the moment, the subnet serves as
 *			as a proxy for all other failure domains
 */
typedef struct {
	int postal_code;
	int power_grid;
	int building;
	int hvac;
	int floor;
	int room;
	int rack;
	int subnet;
} failure_domains_t;

/*
 * There are functions that will compute a server's weight (number of
 * rows in which the processor/device appears in flexhash) as a function
 * of the weight_factors above).  If a device's hash algorithm designated
 * count plus, the rows for which the device holds assets exceeds the
 * weight count, then the device can unsubscribe from rows that are
 * designated, but for which the device holds no (or few assets).  Step
 * one of unsubscribing is to place the device into READ_ONLY mode for
 * a row and then when all assets are in the "to be deleted" queue, the
 * server can unsubscribe from the row.
 */
struct ccow_servers {
	server_id_t serverid;
	int weight;
	server_roles_t primary_role;
	failure_domains_t failure_zones;
	int num_devices;
	server_id_t *device_list;
	struct ccow_servers *next_server;
};

struct flexhash {
	int			num hashrows;
	struct ccow_servers	*flexhash_table;
};

/*
 * flexhash_init()
 *
 * Loads any cached context for the rows that this server will
 * join.  I.E., The server will search its assigned/attached storage devices
 * for the keys to the assets that it manages and build a list of the rows
 * that those assets belong to in the current flexhash_table.  This will
 * be "put" into an object that is unique to this server.  This way we
 * can perform orderly storage and retrieval of "global" information.  There
 * may be a memory cache of these "global" objects that are MRU/MFU in
 * order to manage the process of optimizing the speed of access to these
 * objects and to manage the notification of new versions or the checking
 * for new versions of these objects.
 */
int flexhash_init();

/*
 * flexhash_join()
 *
 * Receives a data structure which describes the servers
 * that have joined the ring.  It also receives a pointer to the current
 * flexhash_table and will return the updated flexhash_table
 */
struct flexhash *flexhash_join(
			struct ccow_servers	*server_list,
			int			num_servers,
			struct flexhash		*flexhash_table);

/*
 * flexhash_leave()
 *
 * Receives a copy of the flexhash table (array of
 * flexhash rows) and the serverid of a server that is leaving the
 * cluster -- affectionately referred to as the walking dead
 */
struct flexhash *flexhash_leave(
			struct ccow_servers	*server_list,
			server_id_t		walking_dead);


#ifdef	__cplusplus
}
#endif

#endif
