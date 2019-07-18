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
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <limits.h>

#include "ccowutil.h"
#include "logger.h"
#include "reptrans.h"
#include "serverid.h"
#include "flexhash.h"
#include "clengine.h"
#include "fhprivate.h"
#include "rebalance.h"

/* Forward declaration */
void fhrebalance_zone_row(struct flexhash *fhtable);

/* compute the servers per row */
int
flexhash_spr(volatile struct flexhash *fhtable)
{
	int numservers = fhtable->servercount;

	int spr = FH_REP_COUNT_SUPPORTED;
	if (numservers < FH_REP_COUNT_SUPPORTED)
		spr = numservers;

	return spr;
}

int
flexhash_zpr(int numdevices, int numzones)
{
	int zpr = FH_REP_COUNT_SUPPORTED;
	if (numzones < FH_REP_COUNT_SUPPORTED)
		zpr = numzones;

	return zpr;
}


void
flexhash_lvdev_hashcount(struct flexhash *fhtable, struct lvdev *lvdev)
{
	char vdevstr[64];
	uint128_dump(&lvdev->vdevid, vdevstr, 64);

	// go through the flexhash rows looking for this vdev
	// if found, mark that particular row in the vdev's hashcount
	for (fhrow_t row = 0; row < fhtable->numrows; row++) {
		if (dlist_member(&fhtable->dl[row], &lvdev->vdevid)) {
			// log_debug(lg, "row: %d vdev: %s", row, vdevstr);
			lvdev->hashcount[row]=1;
		} else {
			lvdev->hashcount[row]=0;
		}
	}
}

void fhrebalance_zone_overserved(struct flexhash *fhtable, fhrow_t row, int diff_zones);
void fhrebalance_zone_underserved(struct flexhash *fhtable, fhrow_t row, int diff_zones);

void
fhrebalance_server_row(struct flexhash *fhtable)
{
	int numrows = flexhash_numrows(fhtable);
	int spr = flexhash_spr(fhtable);
	int diff_servers = 0;
	for (int row = 0; row < fhtable->numrows; row++) {
		struct dlist *dl = &fhtable->dl[row];
		if (dl->ngstat.servercount > spr) {
			diff_servers = spr - dl->ngstat.servercount;
			fhrebalance_server_overserved(fhtable, row, diff_servers);
		}
	}
	for (int row = 0; row < fhtable->numrows; row++) {
		struct dlist *dl = &fhtable->dl[row];
		if (dl->ngstat.servercount < FH_MIN_RCOUNT) {
			diff_servers = FH_MIN_RCOUNT - dl->ngstat.servercount;
			fhrebalance_server_underserved(fhtable, row, diff_servers);
		}
	}
}


int
flexhash_addlist_candidates(struct dlist *dl, struct lvdev *lvdev)
{
	struct fhdev *fhdev = je_calloc(1, sizeof (struct fhdev));
	if (!fhdev) {
		log_error(lg, "Unable to allocate memory for dhdev");
		return -1;
	}
	fhdev->vdev = lvdev;
	int err = dlist_add(dl, fhdev);
	if (err == -EEXIST) {
		je_free(fhdev);
		fhdev = NULL;
	}

	return 0;
}


int
flexhash_swap(struct flexhash *fhtable, int row, struct lvdev *lvdevdel, struct lvdev *lvdevadd)
{
	char delstr[64];
	char addstr[64];
	uint128_dump(&lvdevdel->vdevid, delstr, 64);
	uint128_dump(&lvdevadd->vdevid, addstr, 64);

	struct fhserver *del_server = lvdevdel->server;
	struct fhserver *add_server = lvdevadd->server;
	int err = 0;
	struct dlist *rowl = flexhash_devicelist(fhtable, row);

	// check swap possibility
	if (fhtable->fdmode == FD_ZONE) { // zone case
		if (del_server->zone != add_server->zone) {
			log_debug(lg, "swap wrong zone exit");
			return -EINVAL;
		}
	}

	err = fhrebalance_addvdev_row(row, rowl, lvdevadd);
	if (err) {
		log_debug(lg, "swap add %s error %d", addstr, err);
		return err;
	}

	err = fhrebalance_rmvdev_row(row, rowl, lvdevdel);
	if (err) {
		log_debug(lg, "swap rm %s error %d", delstr, err);
		return err;
	}
	log_debug(lg, "Swapped vdev: %s (%d) with vdev: %s (%d)", delstr, lvdevdel->rcount->hashcount[row], addstr, lvdevadd->rcount->hashcount[row]);

	return 0;
}

static int
rowusage_eval(const void *ka, const size_t ka_len, const void *kb, const size_t kb_len)
{
	struct lvdev *lvdev_a = (struct lvdev *) ka;
	struct lvdev *lvdev_b = (struct lvdev *) kb;
	int curr_a = lvdev_a->rcount->count;
	int curr_b = lvdev_b->rcount->count;
	int mean = lvdev_a->rcount->mean_count;
	int numrows = lvdev_a->rcount->numrows;

	if (curr_a > mean) {
		if (curr_a < curr_b)
			return 1;
		else
			return -1;
	}
	if (curr_a < mean) {
		int dval_a = mean - curr_a;
		int dval_b = mean - curr_b;
		if ( dval_a < dval_b )
			return 1;
		else
			return -1;
	}

	return 0;
}

int
fhrebalance_zone_participation(struct flexhash *fhtable)
{
	int numrows = fhtable->numrows;
	int err = 0;
	uint128_t serverid;
	int total_swaps = 0;
	for (int zone = 1; zone <= fhtable->zonecount; zone++) {
		log_debug(lg,"zone participation zone: %d", zone);
		while (1) {
			int nswap = 0;

			struct lvdev *lvdevdel = NULL;
			struct lvdev *lvdevadd = NULL;
			int max = 0;
			int min = INT_MAX;
			for (int i = 0; i < fhtable->vdevstore->lvdevcount; i++) {
				struct lvdev *lvdev = &fhtable->vdevstore->lvdevlist[i];
				if (lvdev->activerows != 0)
					continue;
				if ((int)lvdev->server->zone != zone)
					continue;
				if (lvdev->rcount->count > max) {
					max = lvdev->rcount->count;
					lvdevdel = lvdev;
				}
				if (lvdev->rcount->count < min) {
					min = lvdev->rcount->count;
					lvdevadd = lvdev;
				}
			}

			if (lvdevdel == lvdevadd) { // next zone
				log_notice(lg, "zone participation hi equal low exit");
				break;
			}

			int delta = (max - min);
			log_debug(lg, "zone participation max: %d, min: %d, delta: %d", max, min, delta);
			if (delta < 2) {
				log_debug(lg, "zone participation delta exit: %d", delta);
				break;
			}

			// Find row
			int row = -1;
			for (int r = 0; r < fhtable->numrows; r++) {
				if (lvdevdel->rcount->hashcount[r] && !lvdevadd->rcount->hashcount[r]) {
					row = r;
					log_debug(lg, "zone participation row: %d del hashcount: %d add hashcount %d",
					    row, lvdevdel->rcount->hashcount[r], lvdevadd->rcount->hashcount[r]);
					break;
				}
			}


			if (row >= 0) {
				char delstr[64];
				char addstr[64];
				uint128_dump(&lvdevdel->vdevid, delstr, 64);
				uint128_dump(&lvdevadd->vdevid, addstr, 64);
				if (flexhash_swap(fhtable, row, lvdevdel, lvdevadd) == 0) {
					nswap++;
					total_swaps++;
				}
			}

			if (nswap == 0) {
				log_debug(lg, "zone participation nswap exit");
				break;
			}
		}
	}

	log_debug(lg, "zone participation total swaps: %d", total_swaps);
	return 0;
}

int
fhrebalance_server_participation(struct flexhash *fhtable)
{
	int numrows = fhtable->numrows;
	int err = 0;
	uint128_t serverid;
	int total_swaps = 0;

	struct fhserver *fhserver = fhtable->serverlist;
	char strid[UINT128_STR_BYTES];
	for (; fhserver; fhserver = fhserver->next) {
		uint128_dump(&fhserver->id, strid, UINT128_STR_BYTES);
		log_debug(lg, "server participation serverID: %s", strid);
		while (1) {
			int nswap = 0;

			struct lvdev *lvdevdel = NULL;
			struct lvdev *lvdevadd = NULL;
			int max = 0;
			int min = INT_MAX;
			for (int i = 0; i < fhtable->vdevstore->lvdevcount; i++) {
				struct lvdev *lvdev = &fhtable->vdevstore->lvdevlist[i];
				if (lvdev->activerows != 0)
					continue;
				if (uint128_cmp(&fhserver->id, &lvdev->server->id) != 0)
					continue;

				if (lvdev->rcount->count > max) {
					max = lvdev->rcount->count;
					lvdevdel = lvdev;
				}
				if (lvdev->rcount->count < min) {
					min = lvdev->rcount->count;
					lvdevadd = lvdev;
				}
			}

			if (lvdevdel == lvdevadd) { // next server
				log_debug(lg, "server participation hi equal low exit");
				break;
			}

			int delta = (max - min);
			log_debug(lg, "server participation max: %d, min: %d, delta: %d", max, min, delta);
			if (delta < 2) {
				log_debug(lg, "server participation delta exit: %d", delta);
				break;
			}

			// Find row
			int row = -1;
			for (int r = 0; r < fhtable->numrows; r++) {
				if (lvdevdel->rcount->hashcount[r] && !lvdevadd->rcount->hashcount[r]) {
					row = r;
					break;
				}
			}


			if (row >= 0) {
				char delstr[64];
				char addstr[64];
				uint128_dump(&lvdevdel->vdevid, delstr, 64);
				uint128_dump(&lvdevadd->vdevid, addstr, 64);
				if (flexhash_swap(fhtable, row, lvdevdel, lvdevadd) == 0) {
					nswap++;
					total_swaps++;
				}
			}

			if (nswap == 0) {
				log_debug(lg, "server participation nswap exit");
				break;
			}
		}
	}

	log_debug(lg, "zone participation total swaps: %d", total_swaps);
	return 0;
}


int
fhrebalance_final_check(struct flexhash *fhtable, int devperrow)
{
	int numrows = fhtable->numrows;
	struct vdevstore *vdevstore = fhtable->vdevstore;
	for (int i = 0; i < vdevstore->lvdevcount; i++) {
		struct lvdev *lvdev = &vdevstore->lvdevlist[i];
		flexhash_lvdev_hashcount(fhtable, lvdev);
	}
	int zcount_check;
	if (fhtable->zonecount >= FH_REP_COUNT_SUPPORTED)
		zcount_check = FH_REP_COUNT_SUPPORTED;
	else
		zcount_check = FH_MIN_ZONE_COUNT;

	struct dlist *dl;
	for (int i = 0; i < numrows; i++) {
		dl = &fhtable->dl[i];
		if ((dl->ngstat.zonecount > zcount_check) || (dl->ngstat.zonecount < zcount_check)) {
			log_warn(lg, "Zonecount row: %d desired: %d available: %d",
			    i, zcount_check, dl->ngstat.zonecount);
		}
		if ((dl->numdevs > devperrow) || (dl->numdevs < devperrow)) {
			log_warn(lg, "Devicecount row: %d desired: %d available: %d ",
			    i, devperrow, dl->numdevs);
		}
	}
	return 0;
}

void
set_unique_zonecount(struct dlist *dl)
{
	uint8_t zoneidlist[FLEXHASH_MAX_ZONES];
	int zonecount=0;
	struct fhdev *fhdev = dl->devlist;
	while (fhdev != NULL) {
		struct lvdev *lvdev = fhdev->vdev;
		struct fhserver *fhserver = lvdev->server;
		int j =0, found = 0;
		if (fhserver) {
			for (j=0; j < zonecount; j++) {
				if (fhserver->zone == zoneidlist[j]) {
					found = 1;
					break;
				}
			}
			if (!found && fhserver->zone != 0) {
				zoneidlist[zonecount++] = fhserver->zone;
			}
		}
		found = 0;
		fhdev = fhdev->next;
	}
	assert(zonecount < FLEXHASH_MAX_ZONES);
	dl->ngstat.zonecount = zonecount;
	memcpy(&dl->ngstat.zonelist[0],&zoneidlist[0], zonecount * sizeof(uint8_t));

	zonecount=0;
	fhdev = dl->devlist;
	while (fhdev != NULL) {
		struct lvdev *lvdev = fhdev->vdev;

		if (lvdev->state != VDEV_STATE_ALIVE) {
			fhdev = fhdev->next;
			continue;
		}

		struct fhserver *fhserver = lvdev->server;
		int j =0, found = 0;
		if (fhserver) {
			for (j=0; j < zonecount; j++) {
				if (fhserver->zone == zoneidlist[j]) {
					found = 1;
					break;
				}
			}
			if (!found && fhserver->zone != 0) {
				zoneidlist[zonecount++] = fhserver->zone;
			}
		}
		found = 0;
		fhdev = fhdev->next;
	}
	dl->ngstat.alive_zonecount = zonecount;
}

#define	FH_MAX_VDEVS_PER_ROW	1024
#define FH_VDEV_ROWUSAGE_LIMIT	0.55
#define FH_VDEV_SPACE_LIMIT	0.80

void
shuffle_vdevs(uint128_t *vdevlist, int n)
{
	if (n > 1) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		unsigned long tmm = 1000000 * tv.tv_sec + tv.tv_usec;
		srand(tmm);
		for (int i = 0; i < n - 1; i++) {
			int j = i + rand() / (RAND_MAX / (n - i) + 1);
			uint128_t temp = vdevlist[j];
			vdevlist[j] = vdevlist[i];
			vdevlist[i] = temp;
		}
	}
}

void
shuffle_rows(int *rows, int n)
{
	if (n > 1) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		unsigned long tmm = 1000000 * tv.tv_sec + tv.tv_usec;
		srand(tmm);
		for (int i = 0; i < n - 1; i++) {
			int j = i + rand() / (RAND_MAX / (n - i) + 1);
			int temp = rows[j];
			rows[j] = rows[i];
			rows[i] = temp;
		}
	}
}

void
shuffle_srvs(struct fhserver **srvs, int n)
{
	if (n > 1) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		unsigned long tmm = 1000000 * tv.tv_sec + tv.tv_usec;
		srand(tmm);
		for (int i = 0; i < n - 1; i++) {
			int j = i + rand() / (RAND_MAX / (n - i) + 1);
			struct fhserver *temp = srvs[j];
			srvs[j] = srvs[i];
			srvs[i] = temp;
		}
	}


}


int
fhrebalance_addvdev_row(int row, struct dlist *dl, struct lvdev *lvdev)
{
	struct fhdev *fhdev = je_calloc(1, sizeof (struct fhdev));
	if (!fhdev)
		return -ENOMEM;

	fhdev->vdev = lvdev;

	int err = dlist_add(dl, fhdev);
	if (err) {
		je_free(fhdev);
		return err;
	}
	// now update stats to reflect this
	dl->deltadevs++;
	if (lvdev->rcount) {
		lvdev->rcount->count++;
		lvdev->rcount->deltarows++;
		lvdev->rcount->rowusage
			= (float) lvdev->rcount->count/(float) lvdev->rcount->numrows;
		lvdev->rcount->hashcount[row]++;
	}

	struct fhserver *fhserver = lvdev->server;
	if (fhserver->rcount) {
		if (fhserver->rcount->hashcount[row]++ == 0) {
			fhserver->rcount->count++;
			fhserver->rcount->rowusage
				= (float) fhserver->rcount->count/(float) fhserver->rcount->numrows;
		}
	}
	return 0;
}

int
fhrebalance_limit_underserved_row(struct flexhash *fhtable, int row,
    int rowsperdev)
{
	int ret = 0;
	struct vdevstore *vdevstore = fhtable->vdevstore;
	uint128_t vdev_candidates[vdevstore->lvdevcount];
	struct dlist *rowdl = &fhtable->dl[row];
	int needed = abs(rowdl->deltadevs);

	// we need vdevs, so go through the vdevlist
	// get oversubscribed ones
	for (int i = 0; i < vdevstore->lvdevcount; i++) {
		struct lvdev *lvdev = &vdevstore->lvdevlist[i];
		vdev_candidates[i] = lvdev->vdevid;
	}
	shuffle_vdevs(&vdev_candidates[0], vdevstore->lvdevcount);
	for (int i = 0; i < vdevstore->lvdevcount; i++) {
		struct lvdev *lvdev = vdevstore_get_lvdev(fhtable->vdevstore, &vdev_candidates[i]);
		if (lvdev) {
			struct fhserver *fhserver = lvdev->server;
			if (lvdev->rcount) {
				if (rowdl->deltadevs == 0)
					break;;
				if (lvdev->rcount->count > rowsperdev)
					continue;
				int err = fhrebalance_addvdev_row(row, rowdl, lvdev);
				if (err) {
					char vdevstr[64];
					uint128_dump(&lvdev->vdevid, vdevstr, 64);
					log_debug(lg, "Unable to add vdev: %s"
					    "to row: %d err: %d", vdevstr, row,
					    err);
				}
			}
		}
	}
	// update the unique server count for this row
	set_unique_servercount(rowdl);
	set_unique_zonecount(rowdl);
	return 0;
}


int
fhrebalance_limit_overserved_row(struct flexhash *fhtable, int row,
	int rowsperdev)
{
	int ret = 0;
	struct dlist *rowdl = &fhtable->dl[row];
	int needed = abs(rowdl->deltadevs);
	uint128_t vdev_candidates[FH_MAX_VDEVS_PER_ROW];

	// go through the row collecting vdev candidates
	// for removal
	struct fhdev *fhdevptr = rowdl->devlist;
	int j = 0;
	while (fhdevptr && (j < FH_MAX_VDEVS_PER_ROW)) {
		struct lvdev *lvdev = fhdevptr->vdev;

		// this vdev has reached its count skip it
		if (lvdev->rcount->deltarows <= 0) {
			fhdevptr = fhdevptr->next;
			continue;
		}

		// if this was a persistent hashcount
		// and says the row has data, don't remove it
		if ((lvdev->activerows > 0)
		    && (lvdev->hashcount[row] > 0)) {
			fhdevptr = fhdevptr->next;
			continue;
		}
		if ((lvdev->rcount->rowusage > FH_VDEV_ROWUSAGE_LIMIT)
		    || (lvdev->activerows == 0)) {
			vdev_candidates[j] = lvdev->vdevid;
			j++;
		}
		fhdevptr = fhdevptr->next;
	}
	if (j > 0) {
		shuffle_vdevs(&vdev_candidates[0], j);
		int count = 0; int i = 0;
		while (( i < j) && (count < needed)) {
			struct lvdev *lvdev = vdevstore_get_lvdev(fhtable->vdevstore, &vdev_candidates[i]);
			if (lvdev) {
				struct fhserver *fhserver = lvdev->server;
				char serverstr[64];
				uint128_dump(&fhserver->id, serverstr, 64);

				/* FIXME: large cases has broken DPR if not using 1 ! */
				if (fhserver->rcount->hashcount[row] < 1 /*FH_MIN_VDEVS_PER_SERVER*/) {
					log_warn(lg, "Cannot remove vdev %d server: "
					    "%s from row: %d as count %d drops below %d",
					    lvdev->idx, serverstr, row, fhserver->rcount->hashcount[row],
					    FH_MIN_VDEVS_PER_SERVER);
					i++;
					continue;
				}
				int err = fhrebalance_rmvdev_row(row, rowdl, lvdev);
				if (!err)
					count++;
			}
			i++;
		}
	}

	// update the unique server count for this row
	set_unique_servercount(rowdl);
	set_unique_zonecount(rowdl);
	return ret;
}



void
fhrebalance_vdev_row(struct flexhash *fhtable, int rowsperdev, int devsperrow)
{
	int numrows = flexhash_numrows(fhtable);
	int rowlist[numrows];
	for (int i = 0; i < numrows; i++) {
		rowlist[i] = i;
	}
	shuffle_rows(&rowlist[0], numrows);
	for (int i = 0; i < numrows; i++) {
		int rowi = rowlist[i];
		struct dlist *rowdl = &fhtable->dl[rowi];
		if (rowdl->deltadevs > 0) {
			fhrebalance_limit_overserved_row(fhtable, rowi, rowsperdev);
		}
	}
	// shuffle_rows(&rowlist[0], numrows);
	for (int i = 0; i < numrows; i++) {
		int rowi = rowlist[i];
		struct dlist *rowdl = &fhtable->dl[rowi];
		if (rowdl->deltadevs < 0) {
			fhrebalance_limit_underserved_row(fhtable, rowi, rowsperdev);
		}
	}
}

int
fhrebalance_rmvdev_row(int row, struct dlist *dl, struct lvdev *lvdev)
{

	struct fhserver *fhserver = lvdev->server;

	if (lvdev->rcount) {
		if (lvdev->rcount->deltarows <= 0)
			return -1;
	}
	if (fhserver->rcount) {
		if (lvdev->rcount->hashcount[row] == 0)
			return -1;
	}
	// remove from the list
	int err = dlist_delete(dl, &lvdev->vdevid);
	if (err)
		return err;

	// update the statistics that needs to reflect this removal
	dl->deltadevs--;

	// because in case of serverdomain lvdev->rcount is not used
	if (lvdev->rcount) {
		assert(lvdev->rcount->count > 0);
		lvdev->rcount->count--;
		lvdev->rcount->deltarows--;
		lvdev->rcount->rowusage
			= (float) lvdev->rcount->count/(float) lvdev->rcount->numrows;
		lvdev->rcount->hashcount[row]--;
	}
	if (fhserver->rcount) {
		fhserver->rcount->hashcount[row]--;
		if (fhserver->rcount->hashcount[row] == 0) {
			fhserver->rcount->count--;
			fhserver->rcount->rowusage
				= (float) fhserver->rcount->count/(float) fhserver->rcount->numrows;
		}
	}
	return 0;
}

int
fhrebalance_add_vdevs_server(struct flexhash *fhtable, int row,
    struct fhserver *fhserver, int dcount, int force)
{
	struct dlist *vdevlist = &fhserver->vdevlist;
	struct fhdev *fhdevptr = vdevlist->devlist;
	struct dlist *rowdl = &fhtable->dl[row];
	uint128_t vdev_candidates[FH_MAX_VDEVS_PER_SERVER];
	float rowusage_server_goal = (float) fhtable->servercount/ (float) fhtable->numrows;

        int numdev = fhtable->vdevstore->lvdevcount;
        int numrows = flexhash_numrows(fhtable);
        int devsperrow = fhtable->devsperrow;
        int rowsperdev = (devsperrow * numrows) / numdev;

	int j = 0;
	while (fhdevptr && (j < FH_MAX_VDEVS_PER_SERVER)) {
		struct lvdev *lvdev  = fhdevptr->vdev;
		if (lvdev->rcount->hashcount[row] > 0) {
			fhdevptr = fhdevptr->next;
			continue;
		}
		if ((lvdev->rcount->count >= rowsperdev)
		    && (!force)) {
			fhdevptr = fhdevptr->next;
			continue;
		}
		vdev_candidates[j++] = lvdev->vdevid;
		fhdevptr = fhdevptr->next;
	}
	int count = 0;
	if (j > 0) {
		shuffle_vdevs(&vdev_candidates[0], j);
		int i = 0;
		while ((count < dcount) && ( i < j)) {
			struct lvdev *lvdev = vdevstore_get_lvdev(fhtable->vdevstore, &vdev_candidates[i]);
			struct fhserver *server = lvdev->server;
			int err = fhrebalance_addvdev_row(row, rowdl, lvdev);
			if (!err)
				count++;
			i++;
		}
	}
	// update the unique server count for this row
	set_unique_servercount(rowdl);
	set_unique_zonecount(rowdl);
	return count;
}

int
fhrebalance_rm_server(struct flexhash *fhtable, int row, struct fhserver *fhserver, int force)
{
	struct dlist *vdevlist = &fhserver->vdevlist;
	struct fhdev *fhdevptr = vdevlist->devlist;
	struct dlist *rowdl = &fhtable->dl[row];

	int count = 0;
	while (fhdevptr) {
		struct lvdev *lvdev = fhdevptr->vdev;
		if ((lvdev) && (lvdev->rcount->rowusage < FH_VDEV_ROWUSAGE_LIMIT) && !force) {
			fhdevptr = fhdevptr->next;
			continue;
		}
		if (lvdev->rcount->hashcount[row]) {
			fhdevptr = fhdevptr->next;
			continue;
		}
		int err = fhrebalance_rmvdev_row(row, rowdl, lvdev);
		if (!err)
			count++;
		fhdevptr = fhdevptr->next;
	}
	// update the unique server count for this row
	set_unique_servercount(rowdl);
	set_unique_zonecount(rowdl);

	return count;
}


void
fhrebalance_server_underserved(struct flexhash *fhtable, fhrow_t row, int diff_servers)
{
	int i = 0;
	struct dlist *dl = &fhtable->dl[row];
	int spr = flexhash_spr(fhtable);
	struct fhserver *srvs[fhtable->servercount];

	struct fhserver *fhserver = fhtable->serverlist;
	for (i = 0; fhserver; fhserver = fhserver->next) {
		srvs[i++] = fhserver;
	}
	bool spr_done;
	bool servervdevcount;
	shuffle_srvs(srvs, fhtable->servercount);
	for (i = 0; i < fhtable->servercount; i++) {
		fhserver = srvs[i];
		if ((dl->ngstat.servercount >= spr) ||
		    (dl->ngstat.servercount >= FH_MIN_RCOUNT))
			spr_done = true;
		if (fhserver->rcount->hashcount[row] >= FH_MIN_VDEVS_PER_SERVER)
			servervdevcount = true;
		if (spr_done && servervdevcount)
			break;
		else
			fhrebalance_add_vdevs_server(fhtable, row, fhserver,
				FH_MIN_VDEVS_PER_SERVER, 0);
	}
}

void
fhrebalance_server_overserved(struct flexhash *fhtable, fhrow_t row, int diff_servers)
{
	int numdevices = fhtable->vdevstore->lvdevcount;
	int numservers = fhtable->servercount;
	int spr = flexhash_spr(fhtable);
	float rowusage_server_goal = (float) numservers/ (float) fhtable->numrows;
	struct dlist *dl = &fhtable->dl[row];
	int j=0;
	struct fhserver *fhserver = fhtable->serverlist;
	for (; fhserver; fhserver=fhserver->next) {
		if (dl->ngstat.servercount <= spr)
			break;
		if (fhserver->rcount) {
			if ((fhserver->rcount->hashcount[row] > 0)
			    && (fhserver->rcount->rowusage > rowusage_server_goal)) {
				fhrebalance_rm_server(fhtable, row, fhserver, 0);
				j++;
			}
		}
	}
	log_debug(lg, "Rebalance removed %d servers from row %d, desired: %d", j, row, diff_servers);
}

/* add the servers back into the row regardless of the server's row usage
 * we do this to satisfy the replication count criterion
 */
void
fhrebalance_server_add(struct flexhash *fhtable, fhrow_t row, int scount)
{
	int i=0;
	int count = 0; int passcount = 0;
	struct dlist *dl = &fhtable->dl[row];
	int spr = flexhash_spr(fhtable);

	struct fhserver *srvs[fhtable->servercount];
	struct fhserver *fhserver = fhtable->serverlist;
	for (; fhserver; fhserver=fhserver->next) {
		srvs[i++] = fhserver;
	}

	while ((count < scount) && (passcount < 2)) {
		shuffle_srvs(srvs, fhtable->servercount);
		for (i = 0; i < fhtable->servercount; i++) {
			if (dl->ngstat.servercount >= spr)
				break;
			struct fhserver *fhserver = srvs[i];
			if (fhserver->rcount) {
				if (fhserver->rcount->hashcount[row] > 0)
					continue;
				int devs = fhrebalance_add_vdevs_server(fhtable, row, fhserver, 1, 1);
				if (devs > 0)
					count++;
			} else {
				log_debug(lg, "fhserver->rcount empty");
			}
		}
		passcount++;
	}
	set_unique_servercount(dl);
	set_unique_zonecount(dl);
}

void
fhrebalance_server_del(struct flexhash *fhtable, fhrow_t row, int scount)
{
	int i = 0, count = 0;
	int passcount = 0;
	struct dlist *dl = &fhtable->dl[row];
	int spr = flexhash_spr(fhtable);
	struct fhserver *srvs[fhtable->servercount];
	struct fhserver *fhserver = fhtable->serverlist;
	for (; fhserver; fhserver=fhserver->next) {
		srvs[i++] = fhserver;
	}

	while ((count < abs(scount)) && (passcount < 2)) {
		struct fhserver *fhserver = fhtable->serverlist;
		shuffle_srvs(srvs, fhtable->servercount);
		for (i = 0; i < fhtable->servercount; i++) {
			if (dl->ngstat.servercount <= spr)
				break;
			if (dl->numdevs <= fhtable->devsperrow)
				break;
			struct fhserver *fhserver = srvs[i];
			char serverstr[64];
			uint128_dump(&fhserver->id, serverstr, 64);
			int sc = fhrebalance_rm_server(fhtable, row, fhserver, 1);
			if (sc)
				count++;
		}
		passcount++;
	}
}


struct dlist *get_zonevdevlist(struct flexhash *fhtable, uint8_t zone)
{
	struct dlist *retlist = je_calloc(1, sizeof (struct dlist));
	if (!retlist) {
		log_error(lg, "Unable to allocate memeory");
		return NULL;
	}

	struct fhserver *fhserver = fhtable->serverlist;
	for(; fhserver; fhserver = fhserver->next) {
		if (fhserver->zone == zone) {
			int err = dlist_append(retlist, &fhserver->vdevlist);
			if (err)
				log_error(lg, "Unable to append vdevlist for "
				    "zone: %d", zone);
		}
	}
	return retlist;
}
void
free_zonevdevlist(struct dlist *vdevlist)
{
	dlist_free(vdevlist);
	je_free(vdevlist);
}

int
fhrebalance_add_vdevs_zone(struct flexhash *fhtable, int row,
    struct dlist *vdevlist, int dcount)
{
	struct fhdev *fhdevptr = vdevlist->devlist;
	struct dlist *rowdl = &fhtable->dl[row];
	uint128_t vdev_candidates[FH_MAX_VDEVS_PER_SERVER];
	uint128_t nullid;
	int j = 0;

	memset(&nullid, 0, sizeof (uint128_t));
	while (fhdevptr && (j < FH_MAX_VDEVS_PER_SERVER)) {
		struct lvdev *lvdev  = fhdevptr->vdev;
		if (lvdev->rcount) {
			if (lvdev->rcount->hashcount[row] > 0) {
				fhdevptr = fhdevptr->next;
				continue;
			}
		} else {
			log_debug(lg, "lvdev->rcount is empty");
		}
		if (uint128_cmp(&lvdev->vdevid, &nullid) != 0)
			vdev_candidates[j++] = lvdev->vdevid;
		fhdevptr = fhdevptr->next;
	}
	if (j > 0) {
		shuffle_vdevs(&vdev_candidates[0], j);
		int count = 0; int i = 0;
		while ((count < dcount) && ( i < j)) {
			struct lvdev *lvdev = vdevstore_get_lvdev(fhtable->vdevstore, &vdev_candidates[i]);
			int err = fhrebalance_addvdev_row(row, rowdl, lvdev);
			if (!err)
				count++;
			i++;
		}
	}

	// update the unique server count for this row
	set_unique_zonecount(rowdl);
	return j;
}



int
fhrebalance_rm_vdevs_zone(struct flexhash *fhtable, int row,
	struct dlist *vdevlist, int dcount)
{

	struct fhdev *fhdevptr = vdevlist->devlist;
	struct dlist *rowdl = &fhtable->dl[row];
	uint128_t vdev_candidates[FH_MAX_VDEVS_PER_SERVER];

	int j = 0;
	while (fhdevptr && (j < FH_MAX_VDEVS_PER_SERVER)) {
		struct lvdev *lvdev = fhdevptr->vdev;

		if ((lvdev->activerows > 0)
		    && (lvdev->hashcount[row] > 0)) {
			fhdevptr = fhdevptr->next;
			continue;
		}
		if (lvdev->activerows == 0) {
			vdev_candidates[j] = lvdev->vdevid;
			j++;
		}
		fhdevptr = fhdevptr->next;
	}
	if (j > 0) {
		shuffle_vdevs(&vdev_candidates[0], j);
		int count = 0; int i = 0;
		while (( i < j) && (count < dcount)) {
			struct lvdev *lvdev = vdevstore_get_lvdev(fhtable->vdevstore, &vdev_candidates[i++]);
			if (lvdev) {
				int err = fhrebalance_rmvdev_row(row, rowdl, lvdev);
				if (!err)
					count++;
			}
			i++;
		}
	}
	// update the unique server count for this row
	set_unique_zonecount(rowdl);
	return j;
}

void
fhrebalance_zone_overserved(struct flexhash *fhtable, fhrow_t row, int diff_zones)
{
	assert(diff_zones > 0);

	for (int i = 0; i < fhtable->zonecount; i++) {
		uint8_t zone = fhtable->zonelist[i];
		// row is over and server is over
		struct dlist *vdevlist = get_zonevdevlist(fhtable, zone);
		if (!vdevlist) {
			log_error(lg, "Unable to retrieve vdevs for "
			    "row: %d zone: %d", row, zone);
			continue;
		}
		int rcount = fhrebalance_rm_vdevs_zone(fhtable, row,
		    vdevlist, diff_zones);
		free_zonevdevlist(vdevlist);
	}
}


void
fhrebalance_zone_underserved(struct flexhash *fhtable, fhrow_t row, int diff_zones)
{
	assert (diff_zones < 0);
	for (int i = 0; i < fhtable->zonecount; i++) {
		uint8_t zone = fhtable->zonelist[i];
		// row is under, zone is under
		// vdevs may be over elsewhere so they can be added
		struct dlist *vdevlist = get_zonevdevlist(fhtable, zone);
		if (!vdevlist) {
			log_error(lg, "Unable to retrieve vdevs for "
			    "row: %d zone: %d", row, zone);
			continue;
		}
		int acount = fhrebalance_add_vdevs_zone(fhtable, row,
		    vdevlist, abs(diff_zones));
		free_zonevdevlist(vdevlist);
	}
}

void
fhrebalance_zone_row(struct flexhash *fhtable)
{
	int zpr = flexhash_zpr(fhtable->vdevstore->lvdevcount, fhtable->zonecount);
	int diff_zones = 0;

	for (int row = 0; row < fhtable->numrows; row++) {
		struct dlist *dl = &fhtable->dl[row];
		diff_zones = dl->ngstat.zonecount - zpr;
		if (diff_zones > 0) {
			fhrebalance_zone_overserved(fhtable, row, diff_zones);
		} else if (diff_zones < 0) {
			fhrebalance_zone_underserved(fhtable, row, diff_zones);
		}
	}
}


/* remove the fictitious elements and keep only
 * the ones that say they have the real data
 */
void
fhrebalance_activerows_only(struct flexhash *fhtable)
{
	fhtable->total_activerows = 0;
	struct vdevstore *vdevstore = fhtable->vdevstore;
	for (int row = 0; row < fhtable->numrows; row++) {
		struct dlist *rowdl = &fhtable->dl[row];
		// now go through the lvdevlist and remove the candidates
		for (int i = 0; i < vdevstore->lvdevcount; i++) {
			struct lvdev *lvdev = &vdevstore->lvdevlist[i];
			if (lvdev->activerows > 0)
				fhtable->total_activerows += lvdev->activerows;
			if ((lvdev->activerows > 0) ||
			    !lvdev->rcount ||
			    !lvdev->rcount->hashcount[row]) {
				continue;
			}
			dlist_delete(rowdl, &lvdev->vdevid);
			rowdl->deltadevs--;
			if (lvdev->rcount) {
				if (lvdev->rcount->count > 0)
					lvdev->rcount->count--;
				lvdev->rcount->deltarows--;
				lvdev->rcount->rowusage
					= (float) lvdev->rcount->count/(float) lvdev->rcount->numrows;
				lvdev->rcount->hashcount[row] = 0;
			}
			struct fhserver *fhserver = lvdev->server;
			if (fhserver->rcount) {
				fhserver->rcount->hashcount[row]--;
				if (fhserver->rcount->hashcount[row] == 0) {
					fhserver->rcount->count--;
					fhserver->rcount->rowusage
						= (float) fhserver->rcount->count/(float) fhserver->rcount->numrows;
				}
			}
		}
		set_unique_servercount(rowdl);
		set_unique_zonecount(rowdl);
	}
}

void
fhrebalance_update_zonerowcount(struct flexhash *fhtable, uint32_t zone, int row)
{
	if (fhtable->zonerowusage) {

		size_t sz;
		struct rowcount *rcount = (struct rowcount *) hashtable_get(fhtable->zonerowusage, &zone, sizeof (uint32_t), &sz);
		if (!rcount) {
			rcount = je_calloc(1, sizeof(struct rowcount));
			int err = hashtable_put(fhtable->zonerowusage, &zone, sizeof(uint32_t), rcount, sizeof(struct rowcount));
			if (err < 0) {
				log_error(lg, "Unable to put zone %d into the zonerowusage hashtable", zone);
				return;
			}
		} else {
			rcount->hashcount[row] = 1;
			rcount->count++;
			rcount->numrows = flexhash_numrows(fhtable);
			rcount->rowusage = ( (float) rcount->count)/( (float) rcount->numrows);
		}
	}
}

void
fhrebalance_setdevice_hashcount(struct flexhash *fhtable)
{
	int devsperrow = fhtable->devsperrow;
	int rowsperdev = (fhtable->devsperrow * flexhash_numrows(fhtable))/fhtable->vdevstore->lvdevcount;

	for (fhrow_t row = 0; row < fhtable->numrows; row++) {
		struct dlist *rowdl = &fhtable->dl[row];
		struct fhdev *fhdevptr = rowdl->devlist;
		rowdl->deltadevs = rowdl->numdevs - devsperrow;

		while(fhdevptr) {
			struct lvdev *lvdev = fhdevptr->vdev;
			if (!lvdev->rcount) {
				lvdev->rcount = je_calloc(1, sizeof (struct rowcount));
				if (!lvdev->rcount) {
					log_error(lg, "Unable to allocate memory");
					return;
				}
			}
			// keep track of how many rows this vdev is part of
			// and the rows it belongs to
			lvdev->rcount->count++;
			lvdev->rcount->numrows = flexhash_numrows(fhtable);
			lvdev->rcount->deltarows
				= lvdev->rcount->count - rowsperdev;
			// in case of lvdev , hashcount represents if this is
			// present or not
			lvdev->rcount->hashcount[row] = 1;
			lvdev->numrows = flexhash_numrows(fhtable);
			lvdev->rcount->rowusage
				= (float)lvdev->rcount->count/(float)lvdev->numrows;
			if (lvdev->size > 0) {
				lvdev->rcount->spaceusage
					= ((float) lvdev->size - (float) lvdev->avail)/(float) lvdev->size;
			}
			struct fhserver *server = lvdev->server;
			if (!server->rcount) {
				server->rcount = je_calloc(1, sizeof (struct rowcount));
				if (!server->rcount) {
					log_error(lg, "Unable to allocate memory");
					if (lvdev->rcount)
						je_free(lvdev->rcount);
					return;
				}
			}

			// in case of server, the hashcount also gives
			// a count of how many vdevs for this server are
			// at this row

			// we don't count the server for every vdev
			// count it only one per vdev in a row. we want to
			// count the number of perticipating rows
			if (server->rcount->hashcount[row]++ == 0)
				server->rcount->count++;
			server->rcount->numrows = flexhash_numrows(fhtable);
			server->rcount->rowusage
				= (float) server->rcount->count/(float)server->rcount->numrows;

			// update the rcount for every zone
			fhrebalance_update_zonerowcount(fhtable, server->zone, row);

			fhdevptr = fhdevptr->next;
		}
		set_unique_servercount(rowdl);
		set_unique_zonecount(rowdl);
	}

	// non-participating structs must have a rcount as well
	// because we may need to add them
	for (int i = 0; i < fhtable->vdevstore->lvdevcount; i++) {
		struct lvdev *lvdevptr = &fhtable->vdevstore->lvdevlist[i];
		if (!lvdevptr->rcount) {
			lvdevptr->rcount = je_calloc(1, sizeof (struct rowcount));
			if (!lvdevptr->rcount) {
				log_error(lg, "Unable to allocate memory");
				return;
			}
		}
		lvdevptr->rcount->numrows = flexhash_numrows(fhtable);

	}

	// non -participating servers need rcounts as well
	struct fhserver *fhserver = fhtable->serverlist;
	while (fhserver) {
		if (!fhserver->rcount) {
			fhserver->rcount = je_calloc(1, sizeof (struct rowcount));
			if (!fhserver->rcount) {
				log_error(lg, "Unable to allocate memory");
				return;
			}
		}
		fhserver->rcount->numrows = flexhash_numrows(fhtable);
		fhserver = fhserver->next;
	}
}

void
fhrebalance_free_rcount(struct flexhash *fhtable)
{
	// go through the vdev list and free the rcount struct
	for (int i = 0; i < fhtable->vdevstore->lvdevcount; i++) {
		struct lvdev *lvdevptr = &fhtable->vdevstore->lvdevlist[i];
		if (lvdevptr->rcount) {
			je_free(lvdevptr->rcount);
			lvdevptr->rcount = NULL;
		}
	}

	// go through the server list and free their rcount structs
	struct fhserver *fhserver = fhtable->serverlist;
	while (fhserver) {
		if (fhserver->rcount) {
			je_free(fhserver->rcount);
			fhserver->rcount = NULL;
		}
		fhserver = fhserver->next;
	}
	if (fhtable->zonerowusage)
		hashtable_destroy(fhtable->zonerowusage);
}

void
fhrebalance_server_revise(struct flexhash *fhtable)
{
	int numdevices = fhtable->vdevstore->lvdevcount;
	int numservers = fhtable->servercount;
	int spr = flexhash_spr(fhtable);
	for (int row =0; row < fhtable->numrows; row++) {
		struct dlist *rowdl = &fhtable->dl[row];
		if (rowdl->ngstat.servercount < spr) {
			fhrebalance_server_add(fhtable, row, (spr - rowdl->ngstat.servercount));
		}
		if (rowdl->ngstat.servercount > spr) {
			fhrebalance_server_del(fhtable, row, (spr - rowdl->ngstat.servercount));
		}
	}
}

void
fhrebalance_show_rcount(struct flexhash *fhtable)
{
	// go through the vdev list and print the rcount struct
	for (int i = 0; i < fhtable->vdevstore->lvdevcount; i++) {
		struct lvdev *lvdevptr = &fhtable->vdevstore->lvdevlist[i];
		if (lvdevptr->rcount) {
			char vdevstr[64];
			uint128_dump(&lvdevptr->vdevid, vdevstr, 64);
			log_info(lg, "vdev: %s count: %d deltarows: %d rowusage: %f activerows: %d",
			    vdevstr, lvdevptr->rcount->count,
			    lvdevptr->rcount->deltarows,
			    lvdevptr->rcount->rowusage, lvdevptr->activerows );
		}
	}

	// go through the server list and print their rcount structs
	struct fhserver *fhserver = fhtable->serverlist;
	while (fhserver) {
		if (fhserver->rcount) {
			char sdevstr[64];
			uint128_dump(&fhserver->id, sdevstr, 64);
			log_info(lg, "server: %s count: %d numvdevs: %d rowusage: %f",
			    sdevstr, fhserver->rcount->count,
			    fhserver->vdevlist.numdevs,
			    fhserver->rcount->rowusage);

		}
		fhserver = fhserver->next;
	}
}


typedef enum fhrebalance_ {
	FHREBALANCE_ANY = 0,
	FHREBALANCE_SERVER = 1,
	FHREBALANCE_ZONE = 2
} fhrebalance_t;

void
flexhash_rebalance(struct flexhash *fhtable)
{
	int numdev = fhtable->vdevstore->lvdevcount;

	if (numdev == 0) {
		log_warn(lg, "Skip re-balancing when numdevices: %d", numdev);
		return;
	}
	fhtable->devsperrow = flexhash_devs_perrow(fhtable, numdev);
	int numrows = flexhash_numrows(fhtable);
	int rowsperdev = (fhtable->devsperrow * numrows)/numdev;

	// make sure the vdev and server representation is the
	// same as the one in the table, here we allocate
	// and setup the rcount structure
	fhrebalance_setdevice_hashcount(fhtable);

	// eliminate the vdevs that have activerows=0
	// we give preference to the ones who already had
	// data written to it
	fhrebalance_activerows_only(fhtable);

	fhrebalance_t rbtype;

	if (fhtable->zonecount >= FH_MIN_ZONE_COUNT) {
		rbtype = FHREBALANCE_ZONE;
		fhtable->fdmode = FD_ZONE;
		log_notice(lg, "zonecount: %d flexhash rebalance:  zoning", fhtable->zonecount);
		fhrebalance_zone_row(fhtable);
	} else if (fhtable->servercount >= FH_MIN_SERVER_COUNT) {
		rbtype = FHREBALANCE_SERVER;
		fhtable->fdmode = FD_SERVER;
		log_notice(lg, "servercount: %d flexhash rebalance: server",
		    fhtable->servercount);
		fhrebalance_server_row(fhtable);
	} else {
		rbtype = FHREBALANCE_ANY;
		fhtable->fdmode = FD_ANY_FIRST;
	}

	// now look at vdev under and over. we need to make sure that
	// we have the right number of devices.
	fhrebalance_vdev_row(fhtable, rowsperdev, fhtable->devsperrow);

	// go back and revise the server balancing if necessary
	if (rbtype == FHREBALANCE_SERVER)
		fhrebalance_server_revise(fhtable);

	if (fhtable->fdmode == FD_ZONE) {
		fhrebalance_zone_participation(fhtable);
	} else {
		fhrebalance_server_participation(fhtable);
	}

	// log distribution
	flexhash_distribution(fhtable);


	// the on disk log for flexhash should indicate that this
	// was done in a rebalance/rebuild
	flexhash_set_leader(fhtable);

	log_debug(lg, "Rebalance additional changes in final check ");
	int err = fhrebalance_final_check(fhtable, fhtable->devsperrow);
	if (err) {
		log_error(lg, "Flexhash rebalance check failed"
		    " numdevs: %d devices_per_row: %d numrows: %d "
		    "rows_per_dev: %d", numdev, fhtable->devsperrow, numrows, rowsperdev);
	} else {
		log_notice(lg, "Flexhash rebalance completed"
		    " numdevs: %d devices_per_row: %d numrows: %d rows_per_dev: %d",
		    numdev, fhtable->devsperrow, numrows, rowsperdev);
	}


	flexhash_table_dump(fhtable, "rebuilt");

	// free the rcounts
	fhrebalance_free_rcount(fhtable);

}
