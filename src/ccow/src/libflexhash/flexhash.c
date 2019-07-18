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
#include <sys/utsname.h>
#include <limits.h>

#include "ccowutil.h"
#include "logger.h"
#include "replicast.h"
#include "reptrans.h"
#include "serverid.h"
#include "flexhash.h"
#include "clengine.h"
#include "ccow-impl.h"
#include "ccowd-impl.h"

#include "hashtable.h"
#include "json.h"
#include "fhprivate.h"
#include "probes.h"

#define QUOTE(name) #name
#define HASH_REPLICATION_COUNT 100

#define CKP_NODEVICES	-1

/* Forward declaration */
static void
flexhash_rowevac_list(struct flexhash *fhtable, int rowsperdev,
			revac_candidate_cb_t revac);

static evac_policy_func_t evac_policies [] = {
	NULL,			/* Must be NULL */
	flexhash_rowevac_list,	/* Row participation */
	NULL,			/* Row available storage space */
	NULL,			/* Row available server space */
	NULL			/* Row available zone space */
};

void
flexhash_update_zonecount(volatile struct flexhash *fhtable, struct fhserver *fhserver);

uint64_t
flexhash_total_capacity(volatile struct flexhash *fhtable)
{
	return fhtable->total_capacity;
}

uint64_t
flexhash_total_logical_used(volatile struct flexhash *fhtable,
    uint64_t *new_total_logical_used)
{
	if (new_total_logical_used)
		fhtable->total_logical_used = *new_total_logical_used;
	return fhtable->total_logical_used;
}

static void
flexhash_dump_fhserver(struct fhserver *fhserver)
{
	char idstr[UINT128_STR_BYTES];
	uint128_dump(&fhserver->id, idstr, UINT128_STR_BYTES);
	log_info(lg, "fhserver: id: %s vdevs: %d", idstr, fhserver->nr_vdevs);
}

static int
flexhash_setup_hashmask(struct flexhash *fhtable)
{
	int numrows = fhtable->numrows;

	if (numrows % 2) {
		log_error(lg, "numrows must be a multiple of 2");
		return -EBADF;
	}
	fhtable->hashmask = numrows - 1;

	return 0;
}


static void
flexhash_dump_serverlist(volatile struct flexhash *fhtable)
{
	struct fhserver *sptr = fhtable->serverlist;
	int i = 0;
	for (; sptr; sptr=sptr->next) {
		flexhash_dump_fhserver(sptr);
		i++;
	}
	log_info(lg, "Total Servers: counted: %d tablecount: %d", i, fhtable->servercount);
}

static void
vdevstore_dump(volatile struct flexhash *fhtable)
{
	int i = 0, *idx = NULL;
	struct lvdev *lvdevptr = NULL;
	size_t n;

	struct vdevstore *vdevstore = fhtable->vdevstore;
	char out[33];

	log_debug(lg, "vdevstore vdevcount: %d", vdevstore->lvdevcount);
	for (i = 0; i < vdevstore->lvdevcount; i++) {
		lvdevptr = &vdevstore->lvdevlist[i];
		uint128_dump(&lvdevptr->vdevid, out, 33);
		idx = hashtable_get(vdevstore->hashtable, &lvdevptr->vdevid,
					sizeof (uint128_t), &n);
		if (idx != NULL)
			log_debug(lg, "vdevid: %s hashget index: %d arrindex: %d, n=%ld state: %d",
					out, (*idx), (*idx) - 1, n, lvdevptr->state);
		else
			log_debug(lg, "vdevid: %s hashget index: NULL", out);
	}
}


static uint64_t hash64(uint64_t x) {
	x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
	x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
	x = x ^ (x >> 31);
	return x;
}


static int cmp_server(const void *a, const void *b) {
	struct server_rec *server1 = (struct server_rec *)a;
	struct server_rec *server2 = (struct server_rec *)b;
	if (server1->hash < server2->hash)
		return -1;
	if (server1->hash > server2->hash)
		return 1;
	return 0;
}


static uint128_t find_server(struct server_rec *srv, int scnt, struct server_rec *key) {
	int result, middle, x, y;
	int start = 0, end = scnt - 1;

	x = cmp_server(key, &srv[0]);
	y = cmp_server(key, &srv[scnt - 1]);

	if (x < 0) {
		return srv[0].sptr->id;
	}
	if (y >= 0) {
		return srv[0].sptr->id;
	}

	/* Now do binary search */
	while (end - start > 1) {
		middle = (end + start) / 2;
		x = cmp_server(key, &srv[middle]);

		if (x < 0)
			end = middle;
		else
			start = middle;
	}

	return srv[end].sptr->id;
}

/* Find nearest fhserver by 128-bit key (simple DHT implementation) */
int
flexhash_serverid_by_key(volatile struct flexhash *fhtable, uint128_t *key128,
    uint128_t *id_out)
{
	struct server_rec *servers;
	int scnt = 0;

	/* Sort servers if not yet */
	if (!fhtable->sorted_servers) {

		servers = je_malloc(fhtable->servercount*HASH_REPLICATION_COUNT * sizeof(struct server_rec));
		if (!servers)
			return 0;

		struct fhserver *sptr = fhtable->serverlist;
		for (; sptr; sptr=sptr->next) {
			if (!sptr->nr_vdevs)
				continue;
			for (int r = 0; r < HASH_REPLICATION_COUNT; r++) {
				servers[scnt].sptr = sptr;
				servers[scnt].hash = hash64(sptr->id.u ^ r*73);
				scnt++;
			}
		}
		if (!scnt) {
			je_free(servers);
			return 0;
		}

		qsort(servers, scnt, sizeof(struct server_rec), cmp_server);

		fhtable->sorted_servers = servers;
		fhtable->sorted_servers_cnt = scnt;
	} else {
		servers = fhtable->sorted_servers;
		scnt = fhtable->sorted_servers_cnt;
	}

	if (scnt == 0)
		return 0;

	struct server_rec key;
	key.hash = hash64(key128->u);

	*id_out = find_server(servers, scnt, &key);
	return 1;
}

/* this function returns the number of devices flexhash was initialized with
 * not necessarily what it currently has.
 * use the function flexhash_current_devicecount() for the most current
 * count of vdevs
 */
static int
flexhash_numdevices(volatile struct flexhash *fhtable)
{
	return fhtable->numdevices;
}

int
flexhash_current_devicecount(volatile struct flexhash *fhtable)
{
	struct vdevstore *vdevstore = fhtable->vdevstore;
	assert(vdevstore);
	return (vdevstore->lvdevcount);
}

/*
 * returns
 *	1 - if this is a valid server ( it has vdevs that have valid ids )
 *	0 - if the server does not have valid id vdev
 */
int
flexhash_vdev_servercount(struct dlist *vdevlist)
{
	struct fhdev *iter;
	uint128_t nullid;
	memset(&nullid, 0, sizeof (uint128_t));
	if (!vdevlist)
		return 0;

	int vdevcount = 0;
	iter = vdevlist->devlist;
	while(iter) {
		if (uint128_cmp(&iter->vdev->vdevid, &nullid) != 0)
			vdevcount++;
		iter = iter->next;
	}
	int retval = (vdevcount > 0) ? 1 : 0;
	return retval;
}

#define FLEXHASH_LOGFILE "flexhash"
#define FLEXHASH_LOGFILE_EXTN "json"
#define FLEXHASH_CHECKPOINT "checkpoint"
#define FH_LOGFILE_LIM_NR 8
#define FLEXHASH_GENID_FILE "fhgenid"

char *
flexhash_checkpoint_filepath(volatile struct flexhash *fhtable, char *filepath, int backup)
{
	char *env_prefix = getenv("NEDGE_HOME");
	if (!fhtable)
		return NULL;

	if (env_prefix && filepath) {
		if (backup) {
			snprintf(filepath, PATH_MAX, "%s/var/run/%s-%s-bak.%s",
			    env_prefix, FLEXHASH_LOGFILE, FLEXHASH_CHECKPOINT,
			    FLEXHASH_LOGFILE_EXTN);
		} else {
			snprintf(filepath, PATH_MAX, "%s/var/run/%s-%s.%s",
			    env_prefix, FLEXHASH_LOGFILE, FLEXHASH_CHECKPOINT,
			    FLEXHASH_LOGFILE_EXTN);
		}
	} else {
		if (backup) {
			snprintf(filepath, PATH_MAX, "%s/var/run/%s-%s-bak.%s",
			    QUOTE(INSTALL_PREFIX), FLEXHASH_LOGFILE, FLEXHASH_CHECKPOINT,
			    FLEXHASH_LOGFILE_EXTN);
		} else {
			snprintf(filepath, PATH_MAX, "%s/var/run/%s-%s.%s",
			    QUOTE(INSTALL_PREFIX), FLEXHASH_LOGFILE, FLEXHASH_CHECKPOINT,
			    FLEXHASH_LOGFILE_EXTN);
		}
	}
	return filepath;
}

int
flexhash_checkpoint_numdevices()
{
	int numdevices=-1;

	char *env_prefix = getenv("NEDGE_HOME");
	char filepath[PATH_MAX];
	struct stat st;

	if (env_prefix) {
		snprintf(filepath, PATH_MAX, "%s/var/run/%s-%s.%s",
		    env_prefix, FLEXHASH_LOGFILE, FLEXHASH_CHECKPOINT,
		    FLEXHASH_LOGFILE_EXTN);
	} else {
		snprintf(filepath, PATH_MAX, "%s/var/run/%s-%s.%s",
		    QUOTE(INSTALL_PREFIX), FLEXHASH_LOGFILE, FLEXHASH_CHECKPOINT,
		    FLEXHASH_LOGFILE_EXTN);
	}

	int rc = stat(filepath, &st);
	if (rc != 0) {
		log_warn(lg, "File: %s not found", filepath);
		return numdevices;
	}

	if (st.st_size == 0) {
		log_error(lg, "Unknown size checkpoint: %s file %d bytes long", filepath, (int) st.st_size);
		return numdevices;
	}
	rtbuf_t *rb = rtbuf_init_alloc_one(st.st_size);
	if (!rb) {
		log_error(lg, "Out of memory while reading " "%s:", filepath);
		return numdevices;
	}

	int fd = open(filepath, O_RDONLY);
	if (fd == -1) {
		rtbuf_destroy(rb);
		log_error(lg, "Cannot open configuration file %s: %s",
		    filepath, strerror(errno));
		return numdevices;
	}
	int len = read(fd, rtbuf(rb, 0).base, rtbuf(rb, 0).len);
	if (len == -1) {
		close(fd);
		rtbuf_destroy(rb);
		log_error(lg, "Cannot read configuration file %s: %s",
		    filepath, strerror(errno));
		return numdevices;
	}
	close(fd);
	json_value *fh_json = json_parse(rtbuf(rb, 0).base, rtbuf(rb, 0).len);
	if (!fh_json) {
		log_error(lg, "Cannot parse flexhash-checkpoint.json file %s ",
				filepath);
		rtbuf_destroy(rb);
		json_value_free(fh_json);
		return numdevices;
	}
	int found = 0;
	for (uint32_t i = 0; i < fh_json->u.object.length; i++) {
		if (strncmp(fh_json->u.object.values[i].name, "vdevcount", 9) == 0) {
			json_value *v = fh_json->u.object.values[i].value;
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: servercount is not "
				    "an integer: -EINVAL");
				json_value_free(fh_json);
				return numdevices;
			}
			numdevices = v->u.integer;
			found++;
		}
	}

	if (!found)
		log_error(lg, "Valid number of devices not found");

	rtbuf_destroy(rb);
	json_value_free(fh_json);

	return numdevices;

}


int
flexhash_update_checkpoint(volatile struct flexhash *fhtable, char *desc)
{
	struct stat st;
	char filepath[PATH_MAX], *fp;
	char bakfilepath[PATH_MAX], *bfp;
	int err = 0;
	uint64_t start = uv_hrtime();

	fp = flexhash_checkpoint_filepath(fhtable, filepath, 0);
	if (!fp) {
		err = -ENOENT;
		goto _exit;
	}
	bfp = flexhash_checkpoint_filepath(fhtable, bakfilepath, 1);
	if (!bfp) {
		err = -ENOENT;
		goto _exit;
	}
	int rc = stat(bfp, &st);
	if (rc == 0) {
		log_debug(lg, "File %s found, removing ", bakfilepath);
		err = remove(bakfilepath);
		if (err != 0) {
			log_error(lg, "Unable to remove the file %s err: %d",
			    bakfilepath, err);
			goto _exit;
		}
	}
	rc = stat(fp, &st);
	if (rc == 0) {
		if ((st.st_mode & S_IFMT) == S_IFREG) {
			err = rename(filepath, bakfilepath);
			if (err != 0) {
				log_error(lg, "Unable to rename the file %s to %s err: %d",
				    filepath, bakfilepath, err);
				goto _exit;
			}
		}
	}
	FILE *save_file = fopen(fp, "w+");
	if (!save_file) {
		log_error(lg, "Cannot open configuration file %s: %s",
		    fp, strerror(errno));
		err = -errno;
		goto _exit;
	}
	flexhash_json_dump(save_file, fhtable, fhtable->leader, desc);
	fclose(save_file);
	err = 0;
_exit:
	return err;
}



typedef struct iddelta_
{
	int				idx;
	int				count;
	enum replicast_failure_domain	fd;
	uint128_t			id;
	uint8_t				zone;
	int				delta;
	struct iddelta_			*next;
} iddelta_t;
typedef iddelta_t idlist_t;

iddelta_t *
allocate_iddelta(int fd, int delta)
{
	iddelta_t *idd = je_calloc(1, sizeof(iddelta_t));
	if (!idd) {
		log_error(lg, "Unable to allocate memory");
		return NULL;
	}
	idd->fd = fd;
	idd->delta = delta;
	idd->count++;
	idd->idx = idd->count - 1;

	return idd;
}


int
update_idlist_id(hashtable_t *idtable, uint128_t *id, int fd, int delta)
{
	idlist_t *idl=NULL;
	if (id == NULL) {
		log_error(lg, "Unable to update NULL id");
		return -1;
	}
	size_t sz;
	iddelta_t *idd = (iddelta_t *) hashtable_get(idtable, id, sizeof (uint128_t), &sz);
	if (!idd) {
		idd = allocate_iddelta(fd, delta);
		int err = hashtable_put(idtable, id, sizeof(uint128_t), idd, sizeof(iddelta_t));
		if (err < 0) {
			log_error(lg, "Unable to put into the hashtable");
			return -1;
		}
	} else {
		idd->delta += delta;
	}
	return 0;
}

int
update_idlist_zone(hashtable_t *zone_table, uint8_t zone, int fd, int delta)
{
	if (!zone_table)
		return -1;
	if (zone == 0)
		return -1;
	size_t sz;
	iddelta_t *idd = (iddelta_t *) hashtable_get(zone_table, &zone, sizeof(uint8_t), &sz);
	if (!idd) {
		idd = allocate_iddelta(fd, delta);
		int err = hashtable_put(zone_table, &zone, sizeof(uint8_t), idd, sizeof(iddelta_t));
		if (err < 0) {
			log_error(lg, "Unable to put into the hashtable");
			return -1;
		}
	} else {
		idd->delta += delta;
	}
	return 0;
}

int
vdevstore_getvdev_index_nl(struct vdevstore *vdevstore, uint128_t *vdevid)
{
	int *vdevindex = NULL;
	size_t n;

	// if the hashtable has no members return -ENOENT
	if (hashtable_isempty(vdevstore->hashtable))
		return -ENOENT;

	vdevindex = hashtable_get(vdevstore->hashtable, vdevid,
				sizeof (uint128_t), &n);

	if ((!vdevindex) || (n != sizeof (int)))
		return -ENOENT;

	/* when we added the entry into the hashtable we did a +1
	 * now e -1 on a get
	 */
	return (*vdevindex - 1);
}

int
flexhash_split(volatile struct flexhash *fhtable)
{
	char *env_prefix = getenv("NEDGE_HOME");
	char filepath[PATH_MAX];

	if (env_prefix) {
		snprintf(filepath, PATH_MAX, "%s/var/run/%s-%s.%s",
		    env_prefix, FLEXHASH_LOGFILE, FLEXHASH_CHECKPOINT,
		    FLEXHASH_LOGFILE_EXTN);
	} else {
		snprintf(filepath, PATH_MAX, "%s/var/run/%s-%s.%s",
		    QUOTE(INSTALL_PREFIX), FLEXHASH_LOGFILE, FLEXHASH_CHECKPOINT,
		    FLEXHASH_LOGFILE_EXTN);
	}

	struct flexhash *ckpfhtable = flexhash_read_checkpoint(filepath, 1);
	if (!ckpfhtable) {
		log_warn(lg,"Unable to get the checkpoint flexhash ");
		// if checkpoint is not found,this is a new cluster
		// so we do not mark it split. It must be good.
		return 0;
	}

	// go through the checkpoint devicelist and make sure they are in-memory
	struct lvdev *lvdev = NULL;
	int nodevice = 0, wrong_state = 0;
	for (int i = 0; i < ckpfhtable->vdevstore->lvdevcount; i++) {
		lvdev = &fhtable->vdevstore->lvdevlist[i];
		vdevstate_t st;

		int found = vdevstore_get_state(fhtable->vdevstore, &lvdev->vdevid, &st);
		if (found == -ENODEV)
			nodevice++;
		if (st != VDEV_STATE_ALIVE)
			wrong_state++;
	}

	// if some device were missing and some devices were not alive
	// we consider this split case.
	if ((nodevice != 0) || (wrong_state != 0))
		return 1;

	return 0;
}



int
flexhash_fddelta(volatile struct flexhash *fhtable, char *fhtable2, struct fddelta *fddelta)
{
	// retrieve the existing checkpoint file if it exists
	struct flexhash *ckpfhtable = flexhash_read_checkpoint(fhtable2, 1);
	if (!ckpfhtable) {
		log_warn(lg,"Unable to get the checkpoint flexhash ");
		return -ENOENT;
	}

	// store cp genid for neadm
	fhtable->cpgenid = ckpfhtable->genid;

	// now compare the checkpoint flexhash with the one that is passed in

	// now we compare the vdevcount and generate the delta
	int maxcount = ( fhtable->vdevstore->lvdevcount > ckpfhtable->vdevstore->lvdevcount)
		? fhtable->vdevstore->lvdevcount : ckpfhtable->vdevstore->lvdevcount;
	hashtable_t *vdev_hlist = hashtable_create(maxcount, 0, 0.05);
	maxcount = ( fhtable->servercount > ckpfhtable->servercount)
		? fhtable->servercount : ckpfhtable->servercount;
	hashtable_t *server_hlist = hashtable_create(maxcount, 0, 0.05);
	maxcount = ( fhtable->zonecount > ckpfhtable->zonecount )
		? fhtable->zonecount : ckpfhtable->zonecount;
	hashtable_t *zone_hlist = hashtable_create(maxcount, 0, 0.05);

	int fh_servercount = 0;
	struct fhserver *srvptr = fhtable->serverlist;
	for (; srvptr != NULL; srvptr = srvptr->next) {
		if (srvptr->gateway || (srvptr->nr_vdevs <= 0))
			continue;
		fh_servercount++;
	}

	struct lvdev *lvdev = NULL;
	for (int i = 0; i < fhtable->vdevstore->lvdevcount; i++) {
		lvdev = &fhtable->vdevstore->lvdevlist[i];
		struct fhserver *srv = lvdev->server;
		int idx = vdevstore_getvdev_index_nl(ckpfhtable->vdevstore, &lvdev->vdevid);
		if (idx == -ENOENT && lvdev->state != VDEV_STATE_NONE) {
			int err = update_idlist_id(vdev_hlist, &lvdev->vdevid, FD_ANY_FIRST, 1);
			if (err != 0) {
				log_error(lg, "Unable to update the vdev delta count");
				continue;
			}
			struct fhserver *server = flexhash_get_fhserver(ckpfhtable, &srv->id);
			err = update_idlist_id(server_hlist, &srv->id, FD_SERVER, 1);
			if (err != 0) {
				log_error(lg, "Unable to update the server vdev count");
				continue;
			}
			if (srv->zone > 0) {
				// zone of value zero (0) is illegal.
				// hashtable chokes on redhat sometimes when 0 is used
				// as an index.
				err = update_idlist_zone(zone_hlist, srv->zone, FD_ZONE, 1);
				if (err != 0) {
					log_error(lg, "Unable to update the zone %d", srv->zone);
					continue;
				}
			}
		}
	}

	for (int i = 0; i < ckpfhtable->vdevstore->lvdevcount; i++) {
		lvdev = &ckpfhtable->vdevstore->lvdevlist[i];
		struct fhserver *srv = lvdev->server;
		int idx = vdevstore_getvdev_index_nl(fhtable->vdevstore, &lvdev->vdevid);
		if (idx == -ENOENT && lvdev->state != VDEV_STATE_NONE) {
			int err = update_idlist_id(vdev_hlist, &lvdev->vdevid, FD_ANY_FIRST, -1);
			if (err != 0) {
				log_error(lg, "Unable to update the vdev delta count");
				continue;
			}
			struct fhserver *server = flexhash_get_fhserver(fhtable, &srv->id);
			err = update_idlist_id(server_hlist, &srv->id, FD_SERVER, -1);
			if (err != 0) {
				log_error(lg, "Unable to update the server vdev count");
				continue;
			}
			if (srv->zone > 0) {
				err = update_idlist_zone(zone_hlist, srv->zone, FD_ZONE, -1);
				if (err != 0) {
					log_error(lg, "Unable to update the zone %d", srv->zone);
				}
			}
		}
	}
	unsigned int vsz, ssz, zsz;
	uint128_t **vidl = (uint128_t **) hashtable_keys(vdev_hlist, &vsz);
	uint128_t **sidl = (uint128_t **) hashtable_keys(server_hlist, &ssz);
	uint128_t **zidl = (uint128_t **) hashtable_keys(zone_hlist, &zsz);

	fddelta->vdev_delta = fhtable->vdevstore->lvdevcount - ckpfhtable->vdevstore->lvdevcount;
	fddelta->server_delta = fh_servercount - ckpfhtable->servercount;
	fddelta->zone_delta = fhtable->zonecount - ckpfhtable->zonecount;

	fddelta->affected_vdevs = vsz;
	fddelta->affected_servers = ssz;
	fddelta->affected_zones = zsz;

	fddelta->prev_numrows = ckpfhtable->numrows;
	fddelta->prev_numdevices = ckpfhtable->vdevstore->lvdevcount;

	hashtable_destroy(vdev_hlist);
	hashtable_destroy(server_hlist);
	hashtable_destroy(zone_hlist);

	log_notice(lg, "affected_vdevs: %d affected_servers: %d affected_zones: %d", vsz, ssz, zsz);
	flexhash_table_destroy(ckpfhtable);
	return 0;
}


int
flexhash_fddelta_checkpoint(volatile struct flexhash *fhtable, int *fd_delta_value,
				struct fddelta *fddelta)
{
	char *env_prefix = getenv("NEDGE_HOME");
	char filepath[PATH_MAX];

	if (env_prefix) {
		snprintf(filepath, PATH_MAX, "%s/var/run/%s-%s.%s",
		    env_prefix, FLEXHASH_LOGFILE, FLEXHASH_CHECKPOINT,
		    FLEXHASH_LOGFILE_EXTN);
	} else {
		snprintf(filepath, PATH_MAX, "%s/var/run/%s-%s.%s",
		    QUOTE(INSTALL_PREFIX), FLEXHASH_LOGFILE, FLEXHASH_CHECKPOINT,
		    FLEXHASH_LOGFILE_EXTN);
	}
	int err = flexhash_fddelta(fhtable, filepath, fddelta);
	if (err != 0) {
		log_warn(lg, "Unable to calculate fddelta ");
		return err;
	}

	if (fhtable->fdmode == FD_ANY_FIRST) {
		if ((fddelta->vdev_delta == 0)
		    && (fddelta->affected_vdevs == 0)) {
			*fd_delta_value = 0;
			return 0;
		}
		if (fddelta->vdev_delta != 0) {
			*fd_delta_value = fddelta->vdev_delta;
			return 0;
		}
		*fd_delta_value = fddelta->affected_vdevs;
		return 0;
	}

	if (fhtable->fdmode == FD_SERVER) {
		if ((fddelta->server_delta == 0)
		    && (fddelta->affected_servers == 0)) {
			*fd_delta_value = 0;
			return 0;
		}
		if (fddelta->vdev_delta < 0)
			*fd_delta_value = -fddelta->affected_servers;
		else
			*fd_delta_value = fddelta->affected_servers;
		return 0;
	}

	if (fhtable->fdmode == FD_ZONE) {
		if ((fddelta->zone_delta == 0)
		    && (fddelta->affected_zones == 0)) {
			*fd_delta_value = 0;
			return 0;
		}
		if ((fddelta->vdev_delta < 0) || (fddelta->server_delta < 0))
			*fd_delta_value = -fddelta->affected_zones;
		else
			*fd_delta_value = fddelta->affected_zones;
		return 0;
	}
	log_error(lg, "Flexhash Unknown failure domain: %d", fhtable->fdmode);
	return -1;
}


/*
 * Determine if the leader needs to rebalance or not based on
 * the server that joined in
 * If it is a gateway that joined without any disks we do not need to rebalance
 * If it is a server that joined with disks, we need to rebalance
 * Return value:
 *	0	- if the rebalance need not happen
 *	1	- if we need to rebalance
 */

int
flexhash_delta_rebalance(volatile struct flexhash *fhtable)
{
	char *env_prefix = getenv("NEDGE_HOME");
	char filepath[PATH_MAX];

	if (env_prefix) {
		snprintf(filepath, PATH_MAX, "%s/var/run/%s-%s.%s",
		    env_prefix, FLEXHASH_LOGFILE, FLEXHASH_CHECKPOINT,
		    FLEXHASH_LOGFILE_EXTN);
	} else {
		snprintf(filepath, PATH_MAX, "%s/var/run/%s-%s.%s",
		    QUOTE(INSTALL_PREFIX), FLEXHASH_LOGFILE, FLEXHASH_CHECKPOINT,
		    FLEXHASH_LOGFILE_EXTN);
	}

	if (fhtable->genid == 1)
		return 1;

	/* FIXME: need a way to skip gateways */

	return 1;
}

void
flexhash_set_fdmode(volatile struct flexhash *fhtable)
{
	if (fhtable->zonecount >= FH_MIN_ZONE_COUNT) {
		if (fhtable->fdmode != FH_MIN_ZONE_COUNT)
			log_notice(lg, "Changing failure domain mode to zoning");
		fhtable->fdmode = FD_ZONE;
	} else if (fhtable->servercount >= FH_MIN_SERVER_COUNT) {
		if (fhtable->fdmode != FD_SERVER)
			log_notice(lg, "Changing failure domain mode to server");
		fhtable->fdmode = FD_SERVER;
	} else {
		if (fhtable->fdmode != FD_ANY_FIRST)
			log_notice(lg, "Changing failure domain mode to devices");
		fhtable->fdmode = FD_ANY_FIRST;
	}
}

void
fh_get_logfile_path(char *file, uint8_t fileid)
{
	char *env_prefix = getenv("NEDGE_HOME");

	if (env_prefix) {
		snprintf(file, PATH_MAX, "%s/var/run/%s.%d.%s",
		    env_prefix, FLEXHASH_LOGFILE, fileid,
		    FLEXHASH_LOGFILE_EXTN);
	} else {
		snprintf(file, PATH_MAX, "%s/var/run/%s.%d.%s",
		    QUOTE(INSTALL_PREFIX), FLEXHASH_LOGFILE, fileid,
		    FLEXHASH_LOGFILE_EXTN);
	}
}

void
fh_get_sym_logfile_path(char *file)
{
	char *env_prefix = getenv("NEDGE_HOME");

	if (env_prefix) {
		snprintf(file, PATH_MAX, "%s/var/run/%s.%s",
		    env_prefix, FLEXHASH_LOGFILE, FLEXHASH_LOGFILE_EXTN);
	} else {
		snprintf(file, PATH_MAX, "%s/var/run/%s.%s",
		    QUOTE(INSTALL_PREFIX), FLEXHASH_LOGFILE,
		    FLEXHASH_LOGFILE_EXTN);
	}
}

void
fh_get_genid_filepath(char *file)
{
	char *env_prefix = getenv("NEDGE_HOME");

	if (env_prefix) {
		snprintf(file, PATH_MAX, "%s/var/run/%s",
		    env_prefix, FLEXHASH_GENID_FILE);
	} else {
		snprintf(file, PATH_MAX, "%s/var/run/%s",
		    QUOTE(INSTALL_PREFIX), FLEXHASH_GENID_FILE);
	}
}

void
fh_set_logfileid(struct flexhash *fhtable)
{
	char	    file_name[PATH_MAX];
	uint8_t     id;
	uint8_t     last_fid = 0;
	time_t	    last_time = 0;
	struct stat st;

	/*
	 * Determine logfile id from the existing files.
	 * Check if it's wrap around
	 */
	fh_get_logfile_path(file_name, FH_LOGFILE_LIM_NR - 1);
	if (stat(file_name, &st) != 0) {
		for (id = 0; id < FH_LOGFILE_LIM_NR; id++) {
			fh_get_logfile_path(file_name, id);
			if (stat(file_name, &st) != 0)
				break;
			fhtable->fhlogid++;
		}
	} else { /* else it's wrap around */
		/* Determine last index from the time stamp */
		for (id = 0; id < FH_LOGFILE_LIM_NR; id++) {
			fh_get_logfile_path(file_name, id);
			if (stat(file_name, &st) == 0 &&
			    last_time < st.st_mtime) {
				last_time = st.st_mtime;
				last_fid = id;
			}
		}
		fhtable->fhlogid = (last_fid + 1) % FH_LOGFILE_LIM_NR;
	}

	assert(fhtable->fhlogid < FH_LOGFILE_LIM_NR);
}

static struct vdevstore *
vdevstore_create(int vdevcount, struct flexhash *fhtable)
{
	struct vdevstore *vdevstore;

	vdevstore = (struct vdevstore *)je_calloc(1,
					sizeof (struct vdevstore));
	if (!vdevstore)
		return NULL;

	vdevstore->lvdevlist = (struct lvdev *)je_calloc(vdevcount,
					sizeof (struct lvdev));
	vdevstore->lvdevcount = 0;

	vdevstore->hashtable = hashtable_create(vdevcount, 0, 0.05);

	if (!vdevstore->hashtable) {
		je_free(vdevstore->lvdevlist);
		vdevstore->lvdevlist = NULL;
		je_free(vdevstore);
		vdevstore = NULL;
		return NULL;
	}
	vdevstore->vdevusage = hashtable_create(vdevcount, 0, 0.05);
	if (!vdevstore->vdevusage) {
		je_free(vdevstore->hashtable);
		vdevstore->hashtable = NULL;
		je_free(vdevstore->lvdevlist);
		vdevstore->lvdevlist = NULL;
		je_free(vdevstore);
		vdevstore = NULL;
		return NULL;
	}

	vdevstore->fhtable = fhtable;
	pthread_mutex_init(&vdevstore->mutex, NULL);

	return vdevstore;
}


struct flexhash *
flexhash_table_create(int numdevices, int fh_clientserver)
{
	struct flexhash *fhtable;
	int i;

	if ((numdevices < 1) || (numdevices > FLEXHASH_MAX_VDEVS)) {
		log_error(lg, "Invalid value for table initialization: "
				"numdevices=%d", numdevices);
		return NULL;
	}

	/* compute the number of rows for the number of devices */
	int numrows = flexhash_hashrowcount(numdevices);

	fhtable = (struct flexhash *) je_calloc(1, sizeof (struct flexhash));
	if (fhtable == NULL) {
		return NULL;
	}
	/* default is always 1 indicative of the fact this is not a
	 * cluster syncronized value
	 */
	fhtable->genid = 1;
	fhtable->total_capacity = 0;
	fhtable->numdevices = numdevices;
	fhtable->dl = (struct dlist *) je_calloc(numrows, sizeof (struct dlist));
	if (fhtable->dl == NULL) {
		je_free(fhtable);
		fhtable = NULL;
		return NULL;
	}

	fhtable->numrows = numrows;
	int err = flexhash_setup_hashmask(fhtable);
	if (err) {
		je_free(fhtable->dl);
		fhtable->dl = NULL;
		je_free(fhtable);
		fhtable = NULL;
		return NULL;
	}
	log_info(lg, "Flexhash created. genid: %ld numdevices: %d  numrows: %d "
			"hashmask: 0x%x", fhtable->genid, fhtable->numdevices,
			fhtable->numrows, fhtable->hashmask);

	int vdevstore_size = numdevices*2+10;
	if (vdevstore_size > FLEXHASH_MAX_VDEVS)
		vdevstore_size = FLEXHASH_MAX_VDEVS;
	fhtable->vdevstore = vdevstore_create(vdevstore_size, fhtable);
	if (fhtable->vdevstore == NULL) {
		je_free(fhtable->dl);
		fhtable->dl = NULL;
		je_free(fhtable);
		fhtable = NULL;
		return NULL;
	}

	uv_mutex_init(&fhtable->mutex);
	fhtable->serverlist = NULL;
	fhtable->servercount = 0;
	fhtable->ckpread = 0;
	fhtable->stale = 0;
	fhtable->is_ready = FH_PRISTINE;
	fhtable->fh_ready = 0;
	fhtable->sorted_servers = NULL;
	/* file logging is not required on the client side
	 * with lots of tenant contexts, file logging on the
	 * client side could have conflicts
	 * do this only on the server side
	 */
	if (fh_clientserver == FH_SERVER_SIDE)
		fh_set_logfileid(fhtable);

	return fhtable;
}


/* PRIVATE */
static void
fhdev_dump(struct fhdev *fhdev)
{
	assert(fhdev);

	struct lvdev *lvdev = fhdev->vdev;
	char out[MAX_SDEVID_STR], server_out[MAX_SDEVID_STR];
	uint128_dump(&lvdev->vdevid, out, MAX_SDEVID_STR);
	uint128_dump(&lvdev->server->id, server_out, MAX_SDEVID_STR);
	log_debug(lg, "fhdev %p vdevid: %s state: %d server: %p"
	    " fhdev->next: %p", fhdev, out, lvdev->state, lvdev->server,
	    fhdev->next);
}


/* PRIVATE */
static void
dlist_dump(int i, struct dlist *dl)
{
	struct fhdev *head = NULL;
	struct fhdev *fhdev = NULL;

	if (dl == NULL) {
		return;
	}
	log_debug(lg, "flexhash row: %d numdevs: %d servercount: %d "
	    "zonecount: %d", i, dl->numdevs, dl->ngstat.servercount,
	    dl->ngstat.zonecount);
	head = dl->devlist;
	while (head != NULL) {
		fhdev_dump(head);
		head = head->next;
	}
}

#define FH_LVDEV_IDX_SZ sizeof(int) + 2 /*
					 * Pad with two chars - One for
					 * separator, another for NULL char
					 */

static inline void log_str_dump(int mode, char *str)
{
	if (mode == 2)
		log_notice(lg, "%s", str);
	else
		log_debug(lg, "%s", str);
}

static void
row_dump(int i, struct dlist *dl, int mode)
{
	struct fhdev *head = NULL;
	char   rowbuf[JSON_BUF_PAGE_SZ];
	size_t cursor;
	if (dl == NULL)
		return;

	set_unique_servercount(dl);
	set_unique_zonecount(dl);
	int servercount = dl->ngstat.servercount;
	int zonecount = dl->ngstat.zonecount;

	sprintf(rowbuf, "%d : row: ", i);
	head = dl->devlist;
	while (head != NULL) {
		struct lvdev *lvdev = head->vdev;

		cursor = strlen(rowbuf);
		if (cursor + FH_LVDEV_IDX_SZ < JSON_BUF_PAGE_SZ)
			sprintf(rowbuf + cursor, "%d ", lvdev->idx);
		else {
			log_str_dump(mode, rowbuf);
			rowbuf[0] = '\0'; /* reset buffer after dumping */
			sprintf(rowbuf, "%d ", lvdev->idx);
		}
		head = head->next;
	}
	cursor = strlen(rowbuf);
	if (cursor > 0)
		log_str_dump(mode, rowbuf);
	sprintf(rowbuf, " #devs: %d #servers: %d #zones: %d", dl->numdevs, servercount, zonecount);
	log_str_dump(mode, rowbuf);
}


static void
flexhash_row_dump(int i, struct dlist *dl, int mode)
{
	row_dump(i, dl, mode);
}

void
flexhash_dump(volatile struct flexhash *fhtable, int mode)
{
	int i;
	struct dlist *dl = NULL;
	char   buf[JSON_BUF_PAGE_SZ];

	if (fhtable == NULL) {
		log_error(lg, "Invalid Flexhash table");
		return;
	}

	sprintf(buf, "Flexhash Table numrows = %d {", fhtable->numrows);
	log_str_dump(mode, buf);
	if (mode == 0) {
		for (i = 0; i < fhtable->numrows; i++) {
			dl = &fhtable->dl[i];
			if (dl)
				dlist_dump(i, dl);
		}
	} else if (mode == 1 || mode == 2) {
		for (i = 0; i < fhtable->numrows; i++) {
			dl = &fhtable->dl[i];
			if (dl)
				row_dump(i, dl, mode);
		}
	}
	sprintf(buf, "} Flexhash Table numrows = %d", fhtable->numrows);
	log_str_dump(mode, buf);
	vdevstore_dump(fhtable);
}

void
flexhash_summary(volatile struct flexhash *fhtable)
{
	log_info(lg, "Flexhash table: %p genid: %ld numrows: %d hashmask: 0x%x"
	    "servercount: %d vdevcount: %d", fhtable, fhtable->genid,
	    fhtable->numrows, fhtable->hashmask, fhtable->servercount,
	    fhtable->vdevstore->lvdevcount);
}

int
cmp_vdevids(const void *id1, const void* id2)
{
	return strncmp ((char *)id1, (char *)id2, 6*sizeof(char));
}

int
flexhash_valid_servercount(volatile struct flexhash *fhtable)
{
	struct fhserver *sptr = fhtable->serverlist;
	int i = 0;
	int valid_servercount = 0;

	for (; sptr; sptr=sptr->next) {
		int fh_srvcount = flexhash_vdev_servercount(&sptr->vdevlist);
		valid_servercount += fh_srvcount;
	}

	return valid_servercount;
}

int
flexhash_zcount(volatile struct flexhash *fhtable)
{
	int zcount=0;
	for (int i=0; i < fhtable->zonecount; i++) {
		if (fhtable->zonelist[i] == 0)
			continue;
		zcount++;
	}
	return zcount;
}


#define FH_JSON_SMALL_BUF_SZ 1024 /* must be less than JSON_BUF_PAGE_SZ */
static char json_rowstr[8*FLEXHASH_MAX_VDEVS+1];
static unsigned json_rowstr_idx;

void
flexhash_json_dump(FILE *fd, volatile struct flexhash *fhtable,
			int leader, const char *desc)
{
	struct utsname utsn;
	struct lvdev *lvdev;
	char json_buf[FH_JSON_SMALL_BUF_SZ];
	uint128_t nullid;
	int valid_servercount = 0;
	memset(&nullid, 0, sizeof (uint128_t));

	uname(&utsn);
	valid_servercount = flexhash_valid_servercount(fhtable);

	int valid_vdevcount = 0;
	for (int i = 0; i < fhtable->vdevstore->lvdevcount; i++) {
		lvdev = &fhtable->vdevstore->lvdevlist[i];
		if ( (!lvdev) || (lvdev->state == VDEV_STATE_DEAD))
			continue;
		valid_vdevcount++;
	}

	int zcount = flexhash_zcount(fhtable);
	json_file_buf_prepare();
	sprintf(json_buf, "{\n"
			  "\t\"hostname\": \"%s\",\n"
			  "\t\"pid\": %d,\n"
			  "\t\"leader\": %d,\n"
			  "\t\"desc\": \"%s\", \n"
			  "\t\"genid\": %ld,\n"
			  "\t\"failure_domain\": %d,\n"
			  "\t\"from_checkpoint\": %d,\n"
			  "\t\"numrows\": %d,\n"
			  "\t\"hashmask\": \"0x%x\",\n"
			  "\t\"servercount\": %d,\n"
			  "\t\"zonecount\": %d,\n"
			  "\t\"vdevcount\": %d,\n",
			  utsn.nodename, getpid(), leader, desc, fhtable->genid,
			  fhtable->fdmode, fhtable->ckpread, fhtable->numrows, fhtable->hashmask,
			  ( valid_servercount >= 1 ) ? valid_servercount : 0,
			  zcount, valid_vdevcount);
	json_buf_put(fd, json_buf);

	/* Print out Server section */
	sprintf(json_buf,"\t\"servers\": [\n");
	json_buf_put(fd, json_buf);
	for (struct fhserver* srv = fhtable->serverlist; srv; srv = srv->next) {
		char serveridstr[MAX_SDEVID_STR];
		char ipstr[INET6_ADDRSTRLEN];

		inet_ntop(AF_INET6, &srv->ipaddr, ipstr, INET6_ADDRSTRLEN);
		uint128_dump(&srv->id, serveridstr, MAX_SDEVID_STR);
		sprintf(json_buf,"\t\t{\n"
				 "\t\t\t\"serverid\": \"%s\",\n"
				 "\t\t\t\"ip\": \"%s\",\n"
				 "\t\t\t\"port\": %d\n"
				 "\t\t}%s",
				 serveridstr, ipstr, srv->port,
				 srv->next == NULL ? "\n" : ",\n");
		json_buf_put(fd, json_buf);
	}
	sprintf(json_buf,"\t],\n\t\"vdevlist\": [\n");
	json_buf_put(fd, json_buf);

	/* Print out the list of vdevs and their known idx */
	for (int i = 0; i < fhtable->vdevstore->lvdevcount; i++) {
		size_t n;
		char vdevstr[MAX_SDEVID_STR];
		char serveridstr[MAX_SDEVID_STR];

		lvdev = &fhtable->vdevstore->lvdevlist[i];
		if ( (!lvdev) || (lvdev->state == VDEV_STATE_DEAD))
			continue;

		if (i > 0) {
			sprintf(json_buf, ",\n");
			json_buf_put(fd, json_buf);
		}

		uint128_dump(&lvdev->vdevid, vdevstr, MAX_SDEVID_STR);
		uint128_dump(&lvdev->server->id, serveridstr, MAX_SDEVID_STR);
		int *idx = hashtable_get(fhtable->vdevstore->hashtable,
				&lvdev->vdevid, sizeof (uint128_t), &n);

		sprintf(json_buf, "\t\t{\n"
				  "\t\t\t\"vdevid\": \"%s\",\n"
				  "\t\t\t\"serverid\": \"%s\",\n"
				  "\t\t\t\"zone\": %d, \n"
				  "\t\t\t\"array idx\": %d,\n"
				  "\t\t\t\"short id\": \"%c%c%c%c\",\n"
				  "\t\t\t\"state\": %d,\n"
				  "\t\t\t\"capacity\": \"%u MiB\",\n"
				  "\t\t\t\"free space\": \"%u MiB\",\n"
				  "\t\t\t\"unicast port\": \"%u\",\n"
				  "\t\t\t\"hashcount\": [ ",
				  vdevstr, serveridstr, lvdev->server->zone,
				  (*idx) - 1, vdevstr[4],vdevstr[5],
				  vdevstr[6], vdevstr[7], lvdev->state,
				  (unsigned int)FH_BYTES_TO_MIB(lvdev->size),
				  (unsigned int)FH_BYTES_TO_MIB(lvdev->avail),
				  lvdev->port);
		json_buf_put(fd, json_buf);
		json_rowstr[0] = '\0';
		json_rowstr_idx = 0;
		for (int j = 0; j < fhtable->numrows; j++) {
			if (j < (fhtable->numrows - 1))
				json_rowstr_idx += snprintf(
						json_rowstr + json_rowstr_idx,
						sizeof(json_rowstr) - json_rowstr_idx,
					   	"%d,", lvdev->hashcount[j]);
			else
				json_rowstr_idx += snprintf(
						json_rowstr + json_rowstr_idx,
						sizeof(json_rowstr) - json_rowstr_idx,
						"%d", lvdev->hashcount[j]);
		}
		json_buf_put(fd, json_rowstr);
		sprintf(json_buf, " ]\n\t\t}");

		json_buf_put(fd, json_buf);
	}

	sprintf(json_buf, "\n\t],\n\t\"rows\": [\n");
	json_buf_put(fd, json_buf);
	/* now we print out the table of rows and device idx */

	uint32_t vdevs_per_row;
	for (int i = 0; i < fhtable->numrows; i++) {
		struct dlist *dl = &fhtable->dl[i];
		set_unique_zonecount(dl);
		set_unique_servercount(dl);
		sprintf(json_buf, "\t\t{\n"
				  "\t\t\t\"rownum\": %d,\n"
				  "\t\t\t\"servercount\": %d,\n"
				  "\t\t\t\"zonecount\": %d,\n"
				  "\t\t\t\"numdevices\": %d,\n"
				  "\t\t\t\"rowmembers\": [ ",
				  i, dl->ngstat.servercount,
				  dl->ngstat.zonecount, dl->numdevs);
		json_buf_put(fd, json_buf);
		struct fhdev *head = dl->devlist;
		vdevs_per_row = 0;
		json_rowstr[0] = '\0';
		json_rowstr_idx = 0;
		while (head != NULL) {
			struct lvdev *lvdev = head->vdev;
			char vdevstr[MAX_SDEVID_STR];

			uint128_dump(&lvdev->vdevid, vdevstr, MAX_SDEVID_STR);
			json_rowstr_idx += snprintf(
					json_rowstr + json_rowstr_idx,
					sizeof(json_rowstr) - json_rowstr_idx,
					"\"%c%c%c%c\", ",
					     vdevstr[0],
					     vdevstr[1], vdevstr[2],
					     vdevstr[3]);
			head = head->next;
			vdevs_per_row++;
		}
		if (vdevs_per_row) {
			/* Sort the ids before printing */
			qsort(json_rowstr, vdevs_per_row, 8*sizeof(char),
			      cmp_vdevids);
			/* Remove the last comma */
			json_rowstr[strlen(json_rowstr) - 2] = '\0';
		}

		json_buf_put(fd, json_rowstr);
		if (i < (fhtable->numrows - 1))
			sprintf(json_buf, " ]\n\t\t},\n");
		else
			sprintf(json_buf, " ]\n\t\t}\n");
		json_buf_put(fd, json_buf);
	}
	sprintf(json_buf, "\t],\n\t\"zonelist\": [ ");
	json_buf_put(fd, json_buf);
	int add_comma = 0;
	for (int i=0; i < fhtable->zonecount; i++) {
		if (fhtable->zonelist[i] == 0)
			continue;
		add_comma = ( (i+1) == fhtable->zonecount ) ? 0 : 1;
		if (add_comma)
			sprintf(json_buf, " \"%d\",", fhtable->zonelist[i]);
		else
			sprintf(json_buf, " \"%d\" ", fhtable->zonelist[i]);
		json_buf_put(fd, json_buf);
	}
	sprintf(json_buf, "]\n}\n");
	json_buf_put(fd, json_buf);
	json_buf_flush(fd);
}

static void
flexhash_genid_dump(uint64_t genid)
{
	char filepath[PATH_MAX];

	fh_get_genid_filepath(filepath);
	unlink(filepath);

	FILE *fp = fopen(filepath, "w");
	if (fp == NULL) {
		log_error(lg, "Failed to open file %s", filepath);
		return;
	}

	int ret = fprintf(fp, "%lu", genid);
	fclose(fp);

	if (ret <= 0)
		log_error(lg, "Failed to dump flexhash genid");
}

void
flexhash_disk_dump(volatile struct flexhash *fhtable, char *jsonfile, int leader, const char *desc)
{
	char file_name[PATH_MAX];
	log_notice(lg, "Dumping the file to disk");
	if (!jsonfile)
		fh_get_logfile_path(file_name, fhtable->fhlogid);
	else
		strcpy(file_name, jsonfile);

	FILE *save_file = fopen(file_name, "w+");
	if (save_file) {
		flexhash_json_dump(save_file, fhtable, leader, desc);
		fclose(save_file);
		char sym_file_name[PATH_MAX];
		fh_get_sym_logfile_path(sym_file_name);
		unlink(sym_file_name);
		if (symlink(file_name, sym_file_name)) {
			log_error(lg, "Unable to create symlink: %s err: %d",
					sym_file_name, errno);
		}
		fhtable->fhlogid = (fhtable->fhlogid + 1) % FH_LOGFILE_LIM_NR;
	} else {
		log_error(lg, "Unable to open file for writing: %s err: %d",
				file_name, errno);
	}

	flexhash_genid_dump(flexhash_genid(fhtable));
}

void
flexhash_mem_dump(volatile struct flexhash *fhtable, int leader, const char *desc,
    char **bp, size_t *bsize)
{
	FILE *memfile = open_memstream(bp, bsize);
	if (memfile) {
		flexhash_json_dump(memfile, fhtable, leader, desc);
		fclose(memfile);
	} else {
		log_error(lg, "Unable to open memfile for writing, err: %d", errno);
	}
}

void
flexhash_table_dump(volatile struct flexhash *fhtable, const char *desc)
{
	flexhash_disk_dump(fhtable, NULL, fhtable->leader, desc);
}

/* PRIVATE function */
void
dlist_free(struct dlist *dl)
{
	struct fhdev *tmp, *head;
	if (dl == NULL) {
		return;
	}
	head = dl->devlist;
	while (head != NULL) {
		tmp = head;
		head = head->next;
		je_free(tmp);
		tmp = NULL;
		dl->numdevs--;
	}
}

/* return true if there exists a member with this id in the list */
/* 0 - false -- does not exist or not found
 * 1 - true - found, exists
 */
int
dlist_member(struct dlist *dlist, uint128_t *id)
{
	struct fhdev *iter;
	if (!dlist)
		return 0;

	iter = dlist->devlist;
	while(iter) {
		if (uint128_cmp(&iter->vdev->vdevid, id) == 0)
			return 1;
		iter = iter->next;
	}

	return 0;
}

static int
dlist_find(struct dlist *dlist, struct fhdev *fhdev)
{
	struct fhdev *fhdevptr = dlist ? dlist->devlist : NULL;

	while (fhdevptr != NULL) {
		 struct lvdev *list_vdev = fhdevptr->vdev;
		 struct lvdev *needle_vdev = fhdev->vdev;

		if (COMPARE_SDEVID(&list_vdev->vdevid, &needle_vdev->vdevid) == 0) {
			return 1;
		}
		fhdevptr = fhdevptr->next;
	}
	return 0;
}

int
dlist_add(struct dlist *dlist, struct fhdev *fhdev)
{
	assert(dlist);
	assert(fhdev);

	char vdevstr[MAX_SDEVID_STR];
	struct fhdev *fhdevptr = dlist->devlist;
	struct dlist *head;
	struct lvdev *lvdev = fhdev->vdev;;


	if (fhdevptr == NULL) {
		dlist->devlist = fhdev;
		fhdev->next = NULL;
	} else {
		int found = dlist_find(dlist, fhdev);
		if (found)
			return -EEXIST;

		fhdev->next = fhdevptr;
		dlist->devlist = fhdev;
	}
	dlist->numdevs++;
	return 0;
}

int
dlist_append(struct dlist *headlist, struct dlist *taillist)
{
	if (!headlist || !taillist)
		return -EINVAL;
	struct fhdev *fhdevptr = taillist->devlist;
	for (; fhdevptr; fhdevptr = fhdevptr->next) {
		struct fhdev *fhdev = je_calloc(1, sizeof(struct fhdev));
		if (!fhdev)
			return -ENOMEM;
		fhdev->vdev = fhdevptr->vdev;
		int err = dlist_add(headlist, fhdev);
	}
	return 0;
}


/* delete only the fhdev element from the list
 * used when a vdev is marked dead
 * if desired to remove only one element from
 * a flexhash row
 * or a single vdev from a fhserver
 */

int
dlist_delete(struct dlist *dlist, uint128_t *vdevid)
{
	struct fhdev *iter, *tmp, *nxt;

	assert(dlist);
	assert(vdevid);

	iter = dlist->devlist;
	if ((!iter) && (dlist->numdevs == 0))
		return -ENOENT;

	if (COMPARE_SDEVID(vdevid, &iter->vdev->vdevid) == 0) {
		dlist->devlist = iter->next;
		je_free(iter);
		iter = NULL;
		dlist->numdevs--;
		return 0;
	}
	if (dlist->numdevs == 1)
		return -ENOENT;
	while ( iter->next != NULL) {
		nxt = iter->next;
		if (COMPARE_SDEVID(vdevid, &nxt->vdev->vdevid) == 0) {
			iter->next = nxt->next;
			je_free(nxt);
			nxt = NULL;
			if (dlist->numdevs > 0)
				dlist->numdevs--;
			return 0;
		}
		iter = iter->next;
	}
	return -ENOENT;



}

uint64_t
flexhash_genid(volatile struct flexhash *fhtable)
{
	return fhtable->genid;
}

uint64_t
flexhash_get_genid(int mode, void *ctx)
{
	uint64_t retval = 0;
	switch (mode) {
	case FH_GENID_CLIENT:
		{
			struct ccow *tc = (struct ccow *) ctx;
			retval = flexhash_genid(tc->flexhash);
			break;
		}
	case FH_GENID_SERVER:
		{
			struct ccowd *ccow_daemon = (struct ccowd *) ctx;
			retval = flexhash_genid(ccow_daemon->flexhash);
			break;
		}
	default:
		break;
	}
	return retval;
}

void
flexhash_set_genid(volatile struct flexhash *fhtable, uint64_t genid)
{
	fhtable->genid = genid;
}

void
flexhash_reset_genid(int mode, void *ctx)
{
	switch (mode) {
	case FH_GENID_CLIENT:
		{
			struct ccow *tc = (struct ccow *) ctx;
			flexhash_set_genid(tc->flexhash, 1);
			break;
		}
	case FH_GENID_SERVER:
		{
			struct ccowd *ccow_daemon = (struct ccowd *) ctx;
			flexhash_set_genid(ccow_daemon->flexhash, 1);
			break;
		}
	default:
		break;
	}
}

static void
flexhash_free_fhserver(struct fhserver *fhserver)
{
	assert(fhserver);
	dlist_free(&fhserver->vdevlist);
}


static void
flexhash_serverlist_free(volatile struct flexhash *fhtable)
{
	struct fhserver *head, *tmp;

	head = fhtable->serverlist;
	while (head != NULL) {
		tmp = head;
		head = head->next;
		flexhash_free_fhserver(tmp);
		je_free(tmp);
		tmp = NULL;
		fhtable->servercount--;
	}
}

static void
vdevstore_destroy(struct vdevstore *vdevstore)
{
	assert(vdevstore);
	assert(vdevstore->hashtable);
	assert(vdevstore->lvdevlist);

	if (vdevstore->hashtable)
		hashtable_destroy(vdevstore->hashtable);
	if (vdevstore->vdevusage)
		hashtable_destroy(vdevstore->vdevusage);

	je_free(vdevstore->lvdevlist);
	vdevstore->lvdevlist = NULL;
	je_free(vdevstore);
	vdevstore = NULL;
}


void
flexhash_table_destroy(volatile struct flexhash *fhtable)
{
	int i;
	struct dlist *dl = NULL;

	if (fhtable == NULL) {
		log_error(lg, "Unable to delete a NULL table ");
		assert(0);
	}

	for (i = 0; i < fhtable->numrows; i++) {
		dl = &fhtable->dl[i];
		dlist_free(dl);
	}

	if (fhtable->sorted_servers)
		je_free(fhtable->sorted_servers);

	vdevstore_destroy(fhtable->vdevstore);
	flexhash_serverlist_free(fhtable);
	je_free(fhtable->dl);
	fhtable->dl = NULL;
	je_free((void *) fhtable);
	fhtable = NULL;
}

inline struct dlist *
flexhash_devicelist(volatile struct flexhash *fhtable, fhrow_t rowid)
{
	return fhtable && rowid < fhtable->numrows ? &fhtable->dl[rowid] : NULL;
}

struct lvdev *
flexhash_get_lvdev(volatile struct flexhash *fhtable, fhrow_t rowid, uint128_t *vdevid)
{
	struct dlist *dl = flexhash_devicelist(fhtable, rowid);
	struct fhdev *fdevptr = NULL;
	struct lvdev *lvdev = NULL;

	if (dl == NULL) {
		return NULL;
	}

	fdevptr = dl->devlist;
	for (; fdevptr != NULL; fdevptr = fdevptr->next) {
		lvdev = fdevptr->vdev;
		if (COMPARE_SDEVID(vdevid, &lvdev->vdevid) == 0) {
			if (lvdev->state != VDEV_STATE_DEAD)
				return lvdev;
		}
	}
	return NULL;
}

/* PRIVATE */
struct fhserver *
flexhash_get_fhserver(volatile struct flexhash *fhtable, uint128_t *sdevid)
{
	struct fhserver *sdevptr = NULL;

	int i = 0;

	assert(fhtable != NULL);
	assert(sdevid);

	sdevptr = fhtable->serverlist;
	for (; sdevptr != NULL; sdevptr = sdevptr->next) {
		if (COMPARE_SDEVID(sdevid, &sdevptr->id) == 0) {
			return sdevptr;
		}
	}
	return NULL;
}

int
dlist_find_id(struct dlist *dlist, uint128_t *id)
{
	if ((!dlist)  || (!id))
		return 0;

	struct fhdev *fhdevptr = dlist->devlist;

	while (fhdevptr != NULL) {
		 struct lvdev *list_vdev = fhdevptr->vdev;
		if (COMPARE_SDEVID(&list_vdev->vdevid, id) == 0) {
			return 1;
		}
		fhdevptr = fhdevptr->next;
	}
	return 0;
}


volatile struct flexhash *
flexhash_join(volatile struct flexhash *fhtable, fhrow_t rowid, uint128_t *sdevid)
{
	struct dlist *dl = NULL;
	struct fhdev *fhdev = NULL;
	struct lvdev *lvdev = NULL;
	int err;

	char vdevstr[MAX_SDEVID_STR];
	if (fhtable == NULL)
		return NULL;

	assert(sdevid);
	assert(fhtable->vdevstore);

	uint128_dump(sdevid, vdevstr, MAX_SDEVID_STR);
	pthread_mutex_lock(&fhtable->vdevstore->mutex);
	int idx = vdevstore_getvdev_index_nl(fhtable->vdevstore, sdevid);
	if (idx == -ENOENT) {
		log_error(lg, "Unable to find vdev: %s", vdevstr);
		pthread_mutex_unlock(&fhtable->vdevstore->mutex);
		return fhtable;
	}
	dl = &fhtable->dl[rowid];
	lvdev = &fhtable->vdevstore->lvdevlist[idx];
	fhdev = je_calloc(1, sizeof (struct fhdev));
	if (!fhdev) {
		log_error(lg, "Unable to allocate memory for dhdev");
		pthread_mutex_unlock(&fhtable->vdevstore->mutex);
		return NULL;
	}
	fhdev->vdev = lvdev;
	err = dlist_add(dl, fhdev);
	if (err == -EEXIST) {
		pthread_mutex_unlock(&fhtable->vdevstore->mutex);
		je_free(fhdev);
		fhdev = NULL;
	}
	lvdev->hashcount[rowid] = 1;
	pthread_mutex_unlock(&fhtable->vdevstore->mutex);
	return fhtable;
}

int
flexhash_vdev_leave(volatile struct flexhash *fhtable, fhrow_t rowid, int index)
{
	int err;
	struct dlist *dl = NULL;
	struct fhdev *fhdev = NULL;
	struct lvdev *lvdev = NULL;
	char vdevstr[MAX_SDEVID_STR];

	if (fhtable == NULL)
		return -EBADF;
	assert(fhtable->vdevstore);

	pthread_mutex_lock(&fhtable->vdevstore->mutex);

	if (index > fhtable->vdevstore->lvdevcount) {
		pthread_mutex_unlock(&fhtable->vdevstore->mutex);
		return -ENOENT;
	}

	lvdev = &fhtable->vdevstore->lvdevlist[index];
	if (lvdev == NULL) {
		pthread_mutex_unlock(&fhtable->vdevstore->mutex);
		return -EBADF;
	}

	sdevid_t *sdevid = &lvdev->vdevid;

	assert(sdevid);
	uint128_dump(sdevid, vdevstr, MAX_SDEVID_STR);

	dl = flexhash_devicelist(fhtable, rowid);
	err = dlist_delete(dl, sdevid);
	lvdev->hashcount[rowid] = 0;
	pthread_mutex_unlock(&fhtable->vdevstore->mutex);

	return err;
}

int
flexhash_assign_mcbase(volatile struct flexhash *fhtable, uint128_t *addr,
			uint16_t port)
{
	if (fhtable->mcbase_port != 0 &&
	    memcmp((void *) &fhtable->mcbase_in6_addr.sin6_addr, addr, 16) != 0)
		return -EINVAL;

	memcpy((void *) &fhtable->mcbase_in6_addr.sin6_addr, addr, 16);
	fhtable->mcbase_port = port;
	return 0;
}

void
flexhash_copy_mcbase(volatile struct flexhash *dst_fhtable, volatile struct flexhash *src_fhtable)
{
	if ((dst_fhtable) && (src_fhtable)) {
		memcpy((void *) &dst_fhtable->mcbase_in6_addr, (void *) &src_fhtable->mcbase_in6_addr,
		    sizeof (struct sockaddr_in6));
		dst_fhtable->mcbase_port = src_fhtable->mcbase_port;
	}
}


/*
 * compute the weight for the vdev based on the stat
 */
uint64_t
flexhash_compute_vdev_weight(struct reptrans_devinfo_req *stat)
{
	uint64_t weight = 0;
	uint64_t capacity = atomic_get_uint64(&stat->capacity);
	uint64_t used = atomic_get_uint64(&stat->used);
	double tw = 0.0;
	tw = (FH_CAPACITY_STORAGE_WF/(1 + capacity + stat->used))
		+ (FH_LATENCY_STORAGE_WF/(1 + stat->put4k_latency));
	weight = (uint64_t)tw;
	return weight;
}

/*
 * compute the weight for the server based on the stat
 */
uint64_t
flexhash_compute_server_weight(struct server_stat *server)
{
	uint64_t weight = 0;
	weight = server->numcpu + (uint64_t)server->cpuspeed + server->memtotal;
	return weight;
}

int
flexhash_add_fhserver(volatile struct flexhash *fhtable, struct fhserver *fhserver)
{
	struct fhserver *serverptr = NULL;
	char serveridstr[MAX_SDEVID_STR];

	/* FIXME: if update, update the whole server with newer info, like
	 *        CPU speed, memory, zone, etc..
	 */

	assert((fhtable != NULL) && (fhserver != NULL));

	serverptr = fhtable->serverlist;
	if (serverptr == NULL) { /* empty list adding the first element */
		fhserver->next = NULL;
		fhtable->serverlist = fhserver;
		fhtable->servercount = 1;
		return 0;
	}
	while (serverptr->next != NULL) {
		if (COMPARE_SDEVID(&fhserver->id, &serverptr->id) == 0) {
			SDEVID_DUMP(&fhserver->id, serveridstr);
			/*
			 * If server already exists, free input server and set input
			 * server to this one, as the calling func doesnt know how
			 * to handle memory in this case.
			 */
			log_warn(lg, "Server %s already exists", serveridstr);
			return -EEXIST;
		}
		serverptr = serverptr->next;
	}

	fhserver->next = NULL;
	serverptr->next = fhserver;
	fhtable->servercount++;

	return 0;
}


/* Called by the client (libccow) when it received
 * the list of servers on a server list get
 */
void
flexhash_add_serverlist(volatile struct flexhash *fhtable,
	struct cl_node *nodelist, int numnodes, int rebuild_next)
{
	int err;
	struct cl_node *nodeptr = nodelist;
	int i;
	struct fhserver *fhserver = NULL;

	fhtable->fdmode = nodeptr->fdmode;
	fhtable->ckpread = nodeptr->ckpread;

	char out[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
	for (i = 0; i < numnodes; i++) {
		uint128_dump(&nodeptr->serverid, out, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &nodeptr->addr, dst, INET6_ADDRSTRLEN);
		log_debug(lg, "Flexhash add server: %s, %s.%d nr_vdevs: %d zone: %d",
		    out, dst, nodeptr->port,  nodeptr->nr_vdevs, nodeptr->zone);
		fhserver  = flexhash_add_server_only(fhtable, nodeptr);
		if (!fhserver) {
			log_error(lg, "Unable to add server: %s", out);
			nodeptr++;
			continue;
		}
		err = flexhash_add_vdevs(fhtable, nodeptr, fhserver,
			FH_TABLE_JOIN, FH_GOOD_HC, rebuild_next);
		if (err) {
			log_error(lg, "Unable to add vdevs to server: %s", out);
		}
		nodeptr++;
		flexhash_update_zonecount(fhtable, fhserver);
	}
	/* Update row server count */
	for (int row = 0; row < fhtable->numrows; row++) {
		set_unique_servercount(&fhtable->dl[row]);
		set_unique_zonecount(&fhtable->dl[row]);
	}

}
int
flexhash_addto_server(volatile struct flexhash *fhtable, struct fhserver *fhserver,
			struct lvdev *lvdev)
{
	int err;
	assert(fhtable);
	assert(fhserver);
	assert(lvdev);

	struct fhdev *fhdev = je_calloc(1, sizeof (struct fhdev));
	if (!fhdev)
		return -ENOMEM;
	fhdev->vdev = lvdev;
	err = dlist_add(&fhserver->vdevlist, fhdev);
	if (err == -EEXIST) {
		je_free(fhdev);
		return err;
	}
	fhserver->nr_vdevs++;

	return 0;
}

struct fhserver *
flexhash_add_server_only(volatile struct flexhash *fhtable, struct cl_node *node)
{
	int err, arridx;
	struct fhserver *fhserver;
	fhrow_t rowid;
	uint128_t nullid;

	if (flexhash_is_stale(fhtable)
	    && flexhash_rebuild_inprogress(fhtable)) {
		log_warn(lg, "Unable to add server while rebuild is in-progress");
		return NULL;
	}

	memset(&nullid, 0, sizeof (uint128_t));
	char serverstr[UINT128_BYTES * 2 + 1];
	uint128_dump(&node->serverid, serverstr, UINT128_BYTES * 2 + 1);
	if (uint128_cmp(&nullid, &node->serverid) == 0) {
		log_error(lg, "Unable to add serverid: %s", serverstr);
		return NULL;
	}
	// log_debug(lg, "Flexhash add serverid: %s", serverstr);
	fhserver = flexhash_get_fhserver(fhtable, &node->serverid);
	if (!fhserver) {
		fhserver = je_calloc(1, sizeof (struct fhserver));
		if (!fhserver)
			return NULL;
		fhserver->id = node->serverid;
		fhserver->ipaddr = node->addr;
		fhserver->port = node->port;
		fhserver->zone = node->zone;
		fhserver->gateway = node->gateway;
		err = flexhash_add_fhserver(fhtable, fhserver);
		if (err == -EEXIST) {
			je_free(fhserver);
			fhserver = flexhash_get_fhserver(fhtable, &node->serverid);
		}
	}
	assert(fhserver);
	return fhserver;
}

static struct lvdev *
vdevstore_add_new(struct vdevstore *vdevstore, uint128_t *vdevid,
    struct fhserver *fhserver, int *arrindex)
{
	struct lvdev *lvdev;
	int hindex = 0, currindex = 0;
	int err;

	if ((!vdevstore) || (!vdevid))
		return NULL;

	// the count value will always be the
	// array index to where the next element
	// goes.
	currindex = vdevstore->lvdevcount;

	/* the hashtable treats 0 in the value as NULL
	 * we add a one on insert , and subtract 1 when we get
	 * the value back. Hash index value is always 1 greater than
	 * the array index
	 */
	hindex = vdevstore->lvdevcount + 1;
	err = hashtable_put(vdevstore->hashtable, vdevid, sizeof (uint128_t),
		&hindex, sizeof (int));
	if (err < 0) {
		char vdevstr[UINT128_BYTES * 2 + 1];
		uint128_dump(vdevid, vdevstr, UINT128_BYTES * 2 + 1);
		log_error(lg, "Unable to insert vdev %s into hashtable", vdevstr);
		*arrindex = -1;
		return NULL;
	}

	/* Note: the following is just a verification step to check if
	 * what was inserted into the hashtable is consistent.
	 * remove once the hashtable bug is fixed
	 * bug is that the hashtable_get sometimes returns incorrect values
	 */
	size_t n;
	int *idx = hashtable_get(vdevstore->hashtable, vdevid,
						sizeof (uint128_t), &n);
	assert((*idx) == hindex);
	assert(currindex < FLEXHASH_MAX_VDEVS);

	lvdev = &vdevstore->lvdevlist[currindex];
	memset(lvdev, 0, sizeof (struct lvdev));
	memcpy(&lvdev->vdevid, vdevid, sizeof (uint128_t));

	lvdev->state = VDEV_STATE_ALIVE;
	lvdev->server = fhserver;
	vdevstore->lvdevcount++;

	*arrindex = currindex;
	return lvdev;
}


int
flexhash_add_vdevs(volatile struct flexhash *fhtable, struct cl_node *node,
	struct fhserver *fhserver, int join, int validhc, int rebuild_next)
{
	int err, arridx;
	uint32_t i;
	struct cl_vdev *vdevptr = NULL;
	char vdevstr[UINT128_BYTES * 2 + 1];
	uint128_t nullid;
	struct lvdev *lvdev = NULL;

	if (flexhash_is_stale(fhtable)
	    && flexhash_rebuild_inprogress(fhtable)) {
		log_error(lg, "Unable to add server while rebuild is in-progress");
		return -EBUSY;
	}

	pthread_mutex_lock(&fhtable->vdevstore->mutex);

	memset(&nullid, 0, sizeof (uint128_t));
	char serverstr[UINT128_BYTES * 2 + 1];
	uint128_dump(&node->serverid, serverstr, UINT128_BYTES * 2 + 1);
	vdevptr = node->vdevs;
	for (i = 0; i < node->nr_vdevs; i++) {
		uint128_dump(&vdevptr->vdevid, vdevstr, UINT128_BYTES * 2 + 1);
		if (uint128_cmp(&nullid, &vdevptr->vdevid) == 0) {
			// gateway can send zeroes, so we won't log it as error
			// rather as debug only
			log_debug(lg, "Unable to add vdevid: %s", vdevstr);
			vdevptr++;
			continue;
		}
		// do a hashtable lookup to see if this is already there
		int idx = vdevstore_getvdev_index_nl(fhtable->vdevstore, &vdevptr->vdevid);
		if (idx == -ENOENT) {
			lvdev = vdevstore_add_new(fhtable->vdevstore,
			    &vdevptr->vdevid, fhserver, &arridx);
			if (!lvdev) {
				log_error(lg, "Unable to get lvdev: %s"
				    " index: %d", vdevstr, arridx);
				vdevptr++;
				continue;
			}
			lvdev->idx = arridx;
			// copy the data we want
			lvdev->size = vdevptr->size;
			lvdev->avail = vdevptr->avail;
			lvdev->state = vdevptr->state;
			lvdev->port = vdevptr->port;

			fhtable->total_capacity += vdevptr->size;
		} else {
			lvdev = &fhtable->vdevstore->lvdevlist[idx];
			lvdev->state = vdevptr->state;
			lvdev->port = vdevptr->port;
			assert(lvdev);
		}
		if (validhc) {
			// do the necessary conversion as the numrows may
			// be different between what we received , and the
			// table we are working with.
			lvdev->numrows = fhtable->numrows;
			memset(&lvdev->hashcount[0], 0, sizeof (lvdev->hashcount));
			for (int j = 0; j < vdevptr->numrows; j++) {
				int row = j % lvdev->numrows;
				if (vdevptr->hashcount[j] > 0)
					lvdev->hashcount[row]++;
			}
			lvdev->activerows = 0;
			if (vdevptr->activerows > 0) {
				for (uint32_t j = 0; j < lvdev->numrows; j++) {
					if (lvdev->hashcount[j] > 0)
						lvdev->activerows++;
				}
			}
			log_debug(lg, "vdev: %s total: %ld free: %ld arr index: %d"
			    " in activerows: %d converted-activerows: %d",
			    vdevstr, lvdev->size, lvdev->avail, lvdev->idx,
			    vdevptr->activerows, lvdev->activerows);
		}

		if (vdevptr->state == VDEV_STATE_DEAD) {
			// No need to add if it is marked DEAD
			vdevptr++;
			continue;
		}

		// now make sure the server knows about this vdev
		err = flexhash_addto_server(fhtable, fhserver, lvdev);
		if (err == -EEXIST) {
			log_debug(lg, "serverlist server: %s vdev: %s already exists",
							serverstr, vdevstr);
		}

		if (lvdev->activerows == 0 && rebuild_next == FH_REBUILD_NEXT) {
			// No need to join the flexhash.
			// Rebalance will select the device if required.
			vdevptr++;
			continue;
		}

		if (join) {
			if (vdevptr->numrows > FLEXHASH_MAX_TAB_LENGTH) {
				log_error(lg, "vdev: %s numrows: %d exceeds"
				    " max allowable %d", vdevstr,
				    vdevptr->numrows, FLEXHASH_MAX_TAB_LENGTH);
				vdevptr++;
				continue;
			}
			// now go through the hashcount table and join the
			// rows, even if we knew about the vdev, we should
			// still join in case we get new rows
			for (fhrow_t vrow = 0; vrow < vdevptr->numrows; vrow++) {
				if (vdevptr->hashcount[vrow] > 0) {
					fhrow_t rowid = vrow % fhtable->numrows;
					if (vdevptr->state != VDEV_STATE_DEAD) {
						pthread_mutex_unlock(&fhtable->vdevstore->mutex);
						fhtable = flexhash_join(fhtable, rowid,
								(sdevid_t *)&vdevptr->vdevid);
						pthread_mutex_lock(&fhtable->vdevstore->mutex);
					}
				}
			}
		}
		vdevptr++;
	}
	pthread_mutex_unlock(&fhtable->vdevstore->mutex);
	return 0;
}

void
flexhash_update_zonecount(volatile struct flexhash *fhtable, struct fhserver *fhserver)
{
	int zc = 0;
	int found = 0;

	if (fhserver->zone == 0)
		return;

	for (zc = 0; zc < fhtable->zonecount; zc++) {
		if (fhtable->zonelist[zc] == fhserver->zone)
			found = 1;
	}
	if (!found)
		fhtable->zonelist[fhtable->zonecount++] = fhserver->zone;

	assert(fhtable->zonecount < FLEXHASH_MAX_ZONES);
}

void
flexhash_recalc_zonecount(volatile struct flexhash *fhtable)
{
	struct fhserver *msptr;

	fhtable->zonecount=0;
	for (msptr = fhtable->serverlist; msptr; msptr = msptr->next)
		flexhash_update_zonecount(fhtable, msptr);
}

static void
flexhash_dump_repvdev(struct cl_vdev *vdev, int log_hashcount)
{
	int i;
	char out[UINT128_STR_BYTES];
	uint128_dump(&vdev->vdevid, out, UINT128_STR_BYTES);
	log_debug(lg, "VDEVID: %s port: %d", out, vdev->port);

	if (log_hashcount) {
		// print hashcount only when debugging
		for (i = 0; i < vdev->numrows; i++) {
			log_debug(lg, "\t%d = %d", i, vdev->hashcount[i]);
		}
	}
}


void
flexhash_dump_repnode(struct cl_node *node, uint32_t numnodes)
{
	uint32_t i;
	uint32_t j;
	struct cl_node *nodeptr = node;
	struct cl_vdev *vdevptr;
	char out[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
	for (i = 0; i < numnodes; i++) {
		uint128_dump(&nodeptr->serverid, out, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &nodeptr->addr, dst, INET6_ADDRSTRLEN);
		log_debug(lg, "Server ID: %s, %s.%d nr_vdevs: %d",
		    out, dst, nodeptr->port,  nodeptr->nr_vdevs);
		vdevptr = nodeptr->vdevs;
		for (j = 0; j < nodeptr->nr_vdevs; j++) {
			flexhash_dump_repvdev(vdevptr, 0);
			vdevptr++;
		}
		nodeptr++;
	}

}

void
flexhash_get_rowaddr(volatile struct flexhash *fhtable, uint16_t row,
			struct sockaddr_in6 *addr)
{
	if (REP_IS_4OVER6(&fhtable->mcbase_in6_addr)) {
		struct sockaddr_in addr4;
		replicast_ip4_decap((struct sockaddr_in6 *)&fhtable->mcbase_in6_addr, &addr4);
		addr4.sin_addr.s_addr |= ((uint32_t)row + 1) << 24;
		replicast_ip4_encap(&addr4, addr);
		addr->sin6_port = htons(fhtable->mcbase_port);
		return;
	}
	struct in6_addr b_addr = fhtable->mcbase_in6_addr.sin6_addr;
	b_addr.__in6_u.__u6_addr16[5] = row + 1;
	memcpy(&addr->sin6_addr, &b_addr, 16);
	addr->sin6_family = AF_INET6;
	addr->sin6_port = htons(fhtable->mcbase_port);

	/*
	 * Control traffic is always higher priority then RT.
	 *
	 * This corresponds to DSCP EF class (Expedited Forwarding,
	 * IP TOS value 184).
	 */
	addr->sin6_flowinfo = htonl((46 << 4) | IPV6_FLOWINFO_PRIORITY);

	if (unlikely(lg->level <= LOG_LEVEL_DUMP)) {
		char dst[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &addr->sin6_addr, dst, INET6_ADDRSTRLEN);
		log_debug(lg, "Selected Flexhash Row Addr: %s, row=%d",
		    dst, row);
	}
}

void
flexhash_get_hashaddr(volatile struct flexhash *fhtable, uint512_t *hashid,
				struct sockaddr_in6 *addr)
{
	fhrow_t row = HASHROWID(hashid, fhtable);
	flexhash_get_rowaddr(fhtable, row, addr);
}

fhrow_t
flexhash_get_addr_fhrow(struct sockaddr_in6 *addr)
{
	fhrow_t fhrow;

	if (REP_IS_4OVER6(addr)) {
		struct sockaddr_in addr4;
		replicast_ip4_decap(addr, &addr4);
		fhrow = (addr4.sin_addr.s_addr >> 24) - 1;
	} else
		fhrow = addr->sin6_addr.__in6_u.__u6_addr16[5] - 1;
	return fhrow;
}

void
flexhash_get_tenant_rcvaddr(volatile struct flexhash *fhtable, uint512_t *hashid,
	struct in6_addr inaddr, uint16_t port, struct sockaddr_in6 *outaddr)
{
	fhrow_t row = HASHCALC(hashid, 0x7F);

	inaddr.__in6_u.__u6_addr16[5] = row + 1;
	row = hashid->l.u.l & 0x7F;
	inaddr.__in6_u.__u6_addr16[6] = row + 1;
	row = hashid->l.u.u & 0x7F;
	inaddr.__in6_u.__u6_addr16[7] = row + 1;

	outaddr->sin6_addr = inaddr;
	outaddr->sin6_family = AF_INET6;
	outaddr->sin6_flowinfo = 0;
	outaddr->sin6_port = htons(port);
}


int
flexhash_numrows(volatile struct flexhash *fhtable)
{
	return fhtable->numrows;
}


int
flexhash_client_rthash_exists(volatile struct flexhash *fhtable, uint64_t rtid)
{
	int err;
	if (!fhtable) return 0;
	if (!fhtable->vdevstore) return 0;
	if (!fhtable->vdevstore->vdevusage) return 0;

	pthread_mutex_lock(&fhtable->vdevstore->mutex);
	err = hashtable_contains(fhtable->vdevstore->vdevusage, &rtid,
					sizeof (uint64_t));
	pthread_mutex_unlock(&fhtable->vdevstore->mutex);

	return err;
}

int
flexhash_client_rthash_add(volatile struct flexhash *fhtable, uint64_t rtid)
{
	int err;
	uint32_t rtusage = 1;
	assert(fhtable);
	assert(fhtable->vdevstore);

	pthread_mutex_lock(&fhtable->vdevstore->mutex);
	err = hashtable_put(fhtable->vdevstore->vdevusage, &rtid,
			sizeof (uint64_t), &rtusage, sizeof (uint32_t));
	pthread_mutex_unlock(&fhtable->vdevstore->mutex);

	return err;

}


static void
fix_row_lvdevs(volatile struct flexhash *fh, uint128_t *vdevid, struct lvdev *lnew)
{
	for (fhrow_t row = 0; row < fh->numrows; row++) {
		struct dlist *rowdl = &fh->dl[row];
		struct fhdev *fhdevptr = rowdl->devlist;
		struct fhdev *fhprev = NULL;

		while (fhdevptr) {
			if (uint128_cmp(&fhdevptr->vdev->vdevid, vdevid) == 0) {
				if (lnew)
					fhdevptr->vdev = lnew;
				else {
					if (fhprev)
						fhprev->next = fhdevptr->next;
					else
						rowdl->devlist = fhdevptr->next;
				}
				break;
			}
			fhdevptr = fhdevptr->next;
		}
	}
}

void
fix_server_lvdevs(volatile struct flexhash *fh, uint128_t *vdevid, struct lvdev *lnew)
{
	struct fhserver *sptr = fh->serverlist;
	for (; sptr; sptr=sptr->next) {
		struct dlist *srvdl = &sptr->vdevlist;
		struct fhdev *fhdevptr = srvdl->devlist;
		struct fhdev *fhprev = NULL;

		while (fhdevptr) {
			if (uint128_cmp(&fhdevptr->vdev->vdevid, vdevid) == 0) {
				if (lnew)
					fhdevptr->vdev = lnew;
				else {
					if (fhprev)
						fhprev->next = fhdevptr->next;
					else
						srvdl->devlist = fhdevptr->next;
				}
				break;
			}
			fhprev = fhdevptr;
			fhdevptr = fhdevptr->next;
		}
	}

}

int
vdevstore_remove_vdev(volatile struct flexhash *fh, uint128_t *vdevid)
{
	uint128_t nullid;
	int err;
	memset(&nullid, 0, sizeof (uint128_t));
	if (uint128_cmp(&nullid, vdevid) == 0) {
		return -EINVAL;
	}

	pthread_mutex_lock(&fh->vdevstore->mutex);

	if (hashtable_isempty(fh->vdevstore->hashtable)) {
		pthread_mutex_unlock(&fh->vdevstore->mutex);
		return -EINVAL;
	}


	int idx = vdevstore_getvdev_index_nl(fh->vdevstore, vdevid);
	if (idx == -ENOENT) {
		pthread_mutex_unlock(&fh->vdevstore->mutex);
		return idx;
	}

	if (hashtable_contains(fh->vdevstore->hashtable, vdevid, sizeof (uint128_t))) {
		hashtable_remove(fh->vdevstore->hashtable, vdevid, sizeof (uint128_t));
		fix_row_lvdevs(fh, vdevid, NULL);
		fix_server_lvdevs(fh, vdevid, NULL);
	} else {
		pthread_mutex_unlock(&fh->vdevstore->mutex);
		return -ENOENT;
	}

	unsigned int sz;
	uint128_t **vdev_keys = (uint128_t **) hashtable_keys(fh->vdevstore->hashtable, &sz);

	size_t allocount = fh->checkpoint_numdevices > (uint32_t) fh->vdevstore->lvdevcount ?
		fh->checkpoint_numdevices : (uint32_t) fh->vdevstore->lvdevcount;
	struct lvdev *lvdevlist =
		(struct lvdev *)je_calloc(allocount, sizeof (*lvdevlist));

	for (unsigned int i=0; i < sz; i++) {
		char vdevstr[64];
		uint128_dump(vdev_keys[i], vdevstr, 64);
		int index = vdevstore_getvdev_index_nl(fh->vdevstore, vdev_keys[i]);
		memcpy(&lvdevlist[i],&fh->vdevstore->lvdevlist[index], sizeof(struct lvdev));
		fix_row_lvdevs(fh, vdev_keys[i], &lvdevlist[i]);
		fix_server_lvdevs(fh, vdev_keys[i], &lvdevlist[i]);
		int hindex = i + 1;
		err = hashtable_put(fh->vdevstore->hashtable,
				vdev_keys[i],
				sizeof (uint128_t),
				&hindex, sizeof (int));
		if (err) {
			pthread_mutex_unlock(&fh->vdevstore->mutex);
			log_error(lg, "Unable to update vdev at index: %d", hindex);
			je_free(lvdevlist);
			return -ENOMEM;
		}
	}
	je_free(fh->vdevstore->lvdevlist);
	fh->vdevstore->lvdevlist = lvdevlist;
	fh->vdevstore->lvdevcount = sz;
	pthread_mutex_unlock(&fh->vdevstore->mutex);
	fh->numdevices--;
	return 0;
}



/* returns the index into the array for the vdevid requested
 */
int
flexhash_getvdev_index(volatile struct flexhash *fhtable, uint128_t *vdevid)
{
	int *vdevindex = NULL;
	size_t n;
	struct vdevstore *vdevstore = fhtable->vdevstore;

	pthread_mutex_lock(&vdevstore->mutex);
	// if the hashtable has no members return -ENOENT
	if (hashtable_isempty(vdevstore->hashtable)) {
		pthread_mutex_unlock(&vdevstore->mutex);
		return -ENOENT;
	}
	vdevindex = hashtable_get(vdevstore->hashtable, vdevid,
				sizeof (uint128_t), &n);
	if ((!vdevindex) || (n != sizeof (int))) {
		pthread_mutex_unlock(&vdevstore->mutex);
		return -ENOENT;
	}

	pthread_mutex_unlock(&vdevstore->mutex);
	/* when we added the entry into the hashtable we did a +1
	 * now e -1 on a get
	 */
	return (*vdevindex - 1);
}

/* Used by unit tests only */
uint128_t
vdevstore_getvdev_id(struct vdevstore *vdevstore, int index)
{
	uint128_t vdevid;
	struct lvdev *lvdev = NULL;

	memset(&vdevid, 0, sizeof (uint128_t));
	if (index >= vdevstore->lvdevcount)
		return vdevid;

	lvdev = &vdevstore->lvdevlist[index];
	return lvdev->vdevid;
}


int
vdevstore_mark_dead(struct vdevstore *vdevstore, uint128_t *vdevid)
{
	int vdevindex;
	struct lvdev *lvdev = NULL;
	char vdevstr[UINT128_STR_BYTES];

	uint128_dump(vdevid, vdevstr, UINT128_STR_BYTES);
	pthread_mutex_lock(&vdevstore->mutex);
	vdevindex = vdevstore_getvdev_index_nl(vdevstore, vdevid);

	/* error case, errors are all negative */
	if (vdevindex < 0) {
		log_error(lg, "vdev: %s not found", vdevstr);
		pthread_mutex_unlock(&vdevstore->mutex);
		return vdevindex;
	}

	lvdev = &vdevstore->lvdevlist[vdevindex];
	log_notice(lg, "Marking vdev: %s as DEAD", vdevstr);
	lvdev->state = VDEV_STATE_DEAD;

	pthread_mutex_unlock(&vdevstore->mutex);

	return vdevindex;
}

int
vdevstore_mark_ro(struct vdevstore *vdevstore, uint128_t *vdevid)
{
	int vdevindex;
	struct lvdev *lvdev = NULL;
	char vdevstr[UINT128_STR_BYTES];

	uint128_dump(vdevid, vdevstr, UINT128_STR_BYTES);
	pthread_mutex_lock(&vdevstore->mutex);
	vdevindex = vdevstore_getvdev_index_nl(vdevstore, vdevid);

	/* error case, errors are all negative */
	if (vdevindex < 0) {
		log_error(lg, "vdev: %s not found", vdevstr);
		pthread_mutex_unlock(&vdevstore->mutex);
		return vdevindex;
	}
	lvdev = &vdevstore->lvdevlist[vdevindex];
	log_notice(lg, "Marking vdev: %s as READ-ONLY", vdevstr);
	lvdev->state = VDEV_STATE_READ_ONLY;

	pthread_mutex_unlock(&vdevstore->mutex);

	return vdevindex;
}

int
vdevstore_get_state(struct vdevstore *vdevstore, uint128_t *vdevid,
	vdevstate_t* state)
{
	int vdevindex = 0;
	struct lvdev *lvdev = NULL;

	pthread_mutex_lock(&vdevstore->mutex);
	vdevindex = vdevstore_getvdev_index_nl(vdevstore, vdevid);

	if (vdevindex < 0) {
		pthread_mutex_unlock(&vdevstore->mutex);
		return -ENODEV;
	}
	*state = vdevstore->lvdevlist[vdevindex].state;
	pthread_mutex_unlock(&vdevstore->mutex);
	return 0;
}

int
vdevstore_mark_alive(struct vdevstore *vdevstore, uint128_t *vdevid)
{
	int vdevindex;
	struct lvdev *lvdev = NULL;
	char vdevstr[UINT128_STR_BYTES];

	uint128_dump(vdevid, vdevstr, UINT128_STR_BYTES);
	pthread_mutex_lock(&vdevstore->mutex);
	vdevindex = vdevstore_getvdev_index_nl(vdevstore, vdevid);

	/* error case, errors are all negative */
	if (vdevindex < 0) {
		log_error(lg, "vdev: %s not found", vdevstr);
		pthread_mutex_unlock(&vdevstore->mutex);
		return vdevindex;
	}
	lvdev = &vdevstore->lvdevlist[vdevindex];
	log_notice(lg, "Marking vdev: %s as ALIVE", vdevstr);
	lvdev->state = VDEV_STATE_ALIVE;
	pthread_mutex_unlock(&vdevstore->mutex);

	return vdevindex;
}

static
void flexhash_rtvdev_hashvalue(uint128_t *vdevs, int numvdevs, uint32_t *hvalue)
{
	/* first we sort the array of vdevs */
	qsort(vdevs, numvdevs, sizeof (uint128_t),
	    (int (*) (const void *,const void *))uint128_cmp);

	/* skip empty vdevs (already stored case) */
	int i;
	for (i = 0; i < numvdevs; i++) {
		if (uint128_cmp(vdevs + i, &uint128_null) != 0)
			break;
	}

	/* now we compute the hashvalue over the entire non-empty list of ids */
	tiny_hash(vdevs + i, sizeof (uint128_t) * (numvdevs - i), hvalue);
}

void
flexhash_set_rtaddr(volatile struct flexhash *fhtable, uint128_t *vdevs,
			 int numvdevs, struct sockaddr_in6 *rtaddr)
{
	uint32_t	hvalue;

	flexhash_rtvdev_hashvalue(vdevs, numvdevs, &hvalue);

	rtaddr->sin6_addr.__in6_u.__u6_addr32[3] = hvalue;

	char dst[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &rtaddr->sin6_addr, dst, INET6_ADDRSTRLEN);
}


/* returns 1 if valid
 * returns 0 if invalid
 */
int
flexhash_validate_vdev(volatile struct flexhash *fhtable, uint128_t *vdevid)
{
	struct vdevstore *vdevstore = fhtable->vdevstore;
	struct lvdev *lvdev;
	int idx;
	int err;

	pthread_mutex_lock(&fhtable->vdevstore->mutex);
	idx = vdevstore_getvdev_index_nl(fhtable->vdevstore, vdevid);
	if (idx < 0) {
		pthread_mutex_unlock(&fhtable->vdevstore->mutex);
		return 0;
	}

	lvdev = &vdevstore->lvdevlist[idx];
	if (uint128_cmp(&lvdev->vdevid, vdevid) == 0) {
		/* id matches at the index found
		 * return true, if this is a live entry
		 */
		if (lvdev->state != VDEV_STATE_DEAD) {
			pthread_mutex_unlock(&fhtable->vdevstore->mutex);
			return 1;
		} else {
			pthread_mutex_unlock(&fhtable->vdevstore->mutex);
			return 0; /* marked dead */
		}
	}
	pthread_mutex_unlock(&fhtable->vdevstore->mutex);
	/* This is a stale entry in the hash table so
	 * remove it from the hash and return false
	 */
	vdevstore_remove_vdev(fhtable, vdevid);
	return 0;
}

// XXX: Revise . It returns the pointer to lvdev if available
// there is a tiny tiny window when the pointer may be invalid
struct lvdev *vdevstore_get_lvdev(struct vdevstore *vdevstore, uint128_t *vdevid)
{
	struct lvdev *lvdev;

	pthread_mutex_lock(&vdevstore->mutex);
	int idx = vdevstore_getvdev_index_nl(vdevstore, vdevid);
	if (idx < 0) {
		pthread_mutex_unlock(&vdevstore->mutex);
		return NULL;
	}

	lvdev = &vdevstore->lvdevlist[idx];
	if (uint128_cmp(&lvdev->vdevid, vdevid) != 0) {
		pthread_mutex_unlock(&vdevstore->mutex);
		return NULL;
	}

	if (lvdev->state != VDEV_STATE_DEAD) {
		pthread_mutex_unlock(&vdevstore->mutex);
		return lvdev;
	}

	pthread_mutex_unlock(&vdevstore->mutex);
	return NULL;
}

/* Do a estimated sum of squares over a random distribution
 * to obtain an initial count for hashcount
 * It uses the vdevid's tiny hash value as a seed for
 * random number generation, after which it does a sum of squares
 * estimation over the numbers generated.
 *
 */
#define		FH_SSQ_COUNT_LIMIT	50

void
flexhash_sumsquares_seeded(uint128_t *id, uint16_t *hashcount,
				uint32_t numhashrows)
{
	uint32_t	masked_bits, hash_mask, shiftcount;
	uint32_t	hvalue, sum, oldv, i;
	uint16_t	mean;


	hash_mask = 0;
	shiftcount = 0;
	while (numhashrows > hash_mask + 1) {
		shiftcount++;
		hash_mask = pow(2, shiftcount) - 1;
	}

	tiny_hash(id, sizeof (uint128_t), &hvalue);
	srand(hvalue);

	sum = 0;
	for (i = 0; i < numhashrows; i++) {
		hashcount[i] = rand() % FH_SSQ_COUNT_LIMIT;
		sum += hashcount[i];
	}

	mean = sum/numhashrows;

	for (i = 0; i < numhashrows; i++) {
		oldv = (hashcount[i] - mean)^2;
		if (oldv && (hash_mask != 0))
			hashcount[i] = oldv % hash_mask;
#if 0
		else
			hashcount[i] = 1;
		/* hashcount value is never zero, i is 1 in the worst case */
		hashcount[i] = (hashcount[i]) ? hashcount[i] : 1;
#endif
		hashcount[i] = (hashcount[i] > 0) ? 1 : 0;
	}
}

/*
 * given the number of vdevs, find the total
 * number of hashrows that are optimal.
 * Based on Robert's formula.
 *
 * 2^( log2( n / (2 * log10(n)) ) )
 *
 *
 * hashsize below 8 ( for upto 9 servers) is not very interesting in "reality".
 * for now we make sure the minimum is MIN_FLEXHASH_ROWSIZE. this number can be
 * tunable based on experiments and the practicality.
 *
 */

#define MIN_FLEXHASH_ROWSIZE	8
int
flexhash_hashrowcount(int numdevs)
{
	int ret;
	if (numdevs < 32)
		ret = exp2f( ceilf( log2f( (float) numdevs / ceilf( log10f( (float) numdevs * 2.0 )))));
	else if (numdevs < 256)
		ret = 128;
	else if (numdevs < 2048)
		ret = 256;
	else if (numdevs < 4098)
		ret = 512;
	else
		ret = 1024;
	if (ret < MIN_FLEXHASH_ROWSIZE)
		ret = MIN_FLEXHASH_ROWSIZE;
	return ret;
}

#define MIN_DEVS_PERROW 4
/* 3.0 here is the minimum required number of replicas */
int
flexhash_devs_perrow(volatile struct flexhash *fhtable, int numdevices)
{
	int ret;
	int min_rcount = numdevices >= 128 ? FH_MIN_RCOUNT - 1 : FH_MIN_RCOUNT;
	if (numdevices >= FLEXHASH_BOOTUP_VDEVS) {
		ret = ceilf(log10f( (float) numdevices)) * (float) min_rcount;
	} else {
		ret = MIN_DEVS_PERROW;
	}

	int newdevs = 0;
	for (int i = 0; i < fhtable->vdevstore->lvdevcount; i++) {
		struct lvdev *lvdev = &fhtable->vdevstore->lvdevlist[i];
		if (lvdev->activerows == 0)
			newdevs++;
	}

    uint32_t vdevs_per_row;
    int total_vdevs_per_row = 0;
    for (int i = 0; i < fhtable->numrows; i++) {
        struct dlist *dl = &fhtable->dl[i];
        struct fhdev *head = dl->devlist;
        vdevs_per_row = 0;
        while (head != NULL) {
            struct lvdev *lvdev = head->vdev;
            if (lvdev && lvdev->hashcount[i] > 0)
                 vdevs_per_row++;
            head = head->next;
        }
        total_vdevs_per_row += vdevs_per_row;
    }
    int mean_vdevs_per_row = total_vdevs_per_row / fhtable->numrows;
    if (total_vdevs_per_row % fhtable->numrows != 0)
    	mean_vdevs_per_row++;

    if (ret < mean_vdevs_per_row) {
    	ret = mean_vdevs_per_row;
    }

	log_notice(lg, "flexhash_devs_perrow corrected ret: %d, mean: %d", ret, mean_vdevs_per_row);

	/* do not increment for new table */
    int delta = 0;
	if (newdevs != fhtable->vdevstore->lvdevcount && newdevs > 0) {
		delta = ceilf( (float) newdevs * 2.0 / (float) fhtable->numrows );
		if (delta < 2)
			delta = 2;
	}

	ret += delta;
    log_notice(lg, "flexhash_devs_perrow res: %d, delta: %d, rows: %d,  newdevs: %d, lvdevcount: %d",
    		ret, delta, fhtable->numrows, newdevs, fhtable->vdevstore->lvdevcount);

	return ret;
}

/*
 * Given the id, the weight and the maximum vdevs determine the
 * hashcount distribution. Taken from Robert's algorithm.
 *
 * caller has to free the returned  memory
 */

void
flexhash_sumsquares(uint128_t *id, uint16_t *hashcount, uint32_t numhashrows)
{
	uint32_t		masked_bits, hash_mask, shiftcount;
	uint32_t		oldv;
	uint32_t		i;

	hash_mask = 0;
	shiftcount = 0;

	while (numhashrows > hash_mask + 1) {
		shiftcount++;
		hash_mask = pow(2, shiftcount) - 1;
	}

	for (i=0; i < numhashrows; i++) {
		hashcount[i] = i;
	}

	while (1) {
		/* we do the while(1) and the following if condition
		 * because we cannot use the <= operator with 128 bit
		 * numbers yet
		 */
		if (uint128_cmp(id, &uint128_null) == 0) break;

		uint128_t hmask, mb;
		hmask.l = (uint64_t) hash_mask;
		hmask.u = 0;

		mb.l = id->l & hmask.l;
		mb.u = id->u & hmask.u;

		masked_bits = (uint32_t) mb.l;

		for (i = 0; i < numhashrows; i++) {
			oldv = hashcount[i];
			hashcount += (oldv * oldv) + masked_bits;
		}
		*id = uint128_shiftr(id, shiftcount);
	}

	for (i = 0; i < numhashrows; i++) {
		oldv = hashcount[i];
		hashcount[i] = oldv % hash_mask;
	}
}

int
flexhash_leave(volatile struct flexhash *fhtable, uint128_t *vdevid)
{
	char vdevstr[UINT128_BYTES * 2 + 1];
	uint128_dump(vdevid, vdevstr, UINT128_BYTES*2 + 1);
	log_notice(lg, "VDEV %s is leaving the Flexhash", vdevstr);

	int index = vdevstore_mark_dead(fhtable->vdevstore, vdevid);

	if (index < 0) {
		log_error(lg, "VDEV %s not found in Flexhash", vdevstr);
		return -1;
	}
	int err;
	// remove it from the flexhash on every row that it is in
	for (int i = 0; i < fhtable->numrows; i++) {
		err = flexhash_vdev_leave(fhtable, i, index);
		if (err != 0) {
			// vdev not found in the row could be valid
			continue;
		}
		log_debug(lg, "Removed VDEV %s from row: %d, now numdevs %d",
		    vdevstr, i, fhtable->dl[i].numdevs);
	}
	return 0;
}

/* do the estimate for 90th percentile for the latency
 * so we take out the outliers
 */

uint64_t flexhash_estimate_90th(volatile struct flexhash *fhtable,
			uint128_t *vdevid, uint64_t required_len,
			uint64_t lat90th_4k_current,
			uint64_t lat90th_64k_current, uint64_t lat90th_512k_current)
{
	struct vdevstore *vdevstore = fhtable->vdevstore;
	struct lvdev *lvdev;
	int idx;
	int err;
	uint64_t ret_est = 0;

	idx = vdevstore_getvdev_index_nl(fhtable->vdevstore, vdevid);
	if (idx < 0 || !required_len) {
		char vdevstr[UINT128_BYTES * 2 + 1];
		uint128_dump(vdevid, vdevstr, UINT128_BYTES*2 + 1);
		log_warn(lg, "Not estimating for missing vdev %s", vdevstr);
		return (uint64_t)-1;
	}

	lvdev = &vdevstore->lvdevlist[idx];
	if (lvdev->state == VDEV_STATE_DEAD) {
		char vdevstr[UINT128_BYTES * 2 + 1];
		uint128_dump(vdevid, vdevstr, UINT128_BYTES*2 + 1);
		log_warn(lg, "Not estimating for dead vdev %s", vdevstr);
		return (uint64_t)-1;
	}
	uint64_t num, lat;
	if (required_len < 65536) {
		lat = lat90th_4k_current;
		if (lat > 0)
			ret_est = lat;
		else
			ret_est = DEFAULT90_TIMESLICE_MS * 1000;
	} else if (required_len < 524288) {
		lat = lat90th_64k_current;
		if (lat > 0)
			ret_est = lat;
		else
			ret_est = DEFAULT90_TIMESLICE_MS * 1000;
	} else {
		lat = lat90th_512k_current;
		if (lat > 0)
			ret_est = lat;
		else
			ret_est = DEFAULT90_TIMESLICE_MS * 1000;
	}
	if (unlikely(LOG_LEVEL_DEBUG >= lg->level)) {
		char vdevstr[UINT128_BYTES * 2 + 1];
		memset(vdevstr, 0, UINT128_BYTES*2 + 1);
		uint128_dump(vdevid, vdevstr, UINT128_BYTES*2 + 1);

		log_debug(lg, "%p flexhash 90th estimate: vdevid: %s req_len: %ld "
		    "time: %ld", fhtable, vdevstr, required_len, ret_est);
	}
	return ret_est;
}


/* Given the buffer size required, estimate the time slot required for
 * transfer
 * returns 0 - on error
 * returns time_estimate  in microseconds on success
 */


uint64_t
flexhash_estimate_delta_time(volatile struct flexhash *fhtable, uint128_t *vdevid,
    uint64_t required_len, fh_io_type_t io_type, uint64_t lat4k_current,
    uint64_t lat64k_current, uint64_t lat512k_current)
{
	struct vdevstore *vdevstore = fhtable->vdevstore;
	struct lvdev *lvdev;
	int idx;
	int err;
	uint64_t ret_est = 0;

	assert(required_len);

	idx = vdevstore_getvdev_index_nl(fhtable->vdevstore, vdevid);
	if (idx < 0) {
		char vdevstr[UINT128_BYTES * 2 + 1];
		uint128_dump(vdevid, vdevstr, UINT128_BYTES*2 + 1);
		log_warn(lg, "Not estimating for missing vdev %s", vdevstr);
		return (uint64_t)-1;
	}

	lvdev = &vdevstore->lvdevlist[idx];
	if (lvdev->state == VDEV_STATE_DEAD) {
		char vdevstr[UINT128_BYTES * 2 + 1];
		uint128_dump(vdevid, vdevstr, UINT128_BYTES*2 + 1);
		log_warn(lg, "Not estimating for dead vdev %s", vdevstr);
		return (uint64_t)-1;
	}

	uint64_t num, lat;
	if (required_len < 65536) {
		num = (required_len/4096);
		if (required_len % 4096) num++;
		if (lat4k_current > 0)
			ret_est = lat4k_current * num;
		else
			ret_est = DEFAULT_TIMESLICE_MS * 1000;
	} else if (required_len < 524288) {
		num = (required_len/65536);
		if (required_len % 65536) num++;
		if (lat64k_current > 0)
			ret_est = lat64k_current * num;
		else
			ret_est = 2 * DEFAULT_TIMESLICE_MS * 1000;
	} else {
		num = (required_len/524288);
		if (required_len % 524288) num++;
		if (lat512k_current > 0)
			ret_est = lat512k_current * num;
		else
			ret_est = 4 * DEFAULT_TIMESLICE_MS * 1000;
	}

	if (io_type != FH_IOTYPE_PUT_DEV) {
		ret_est += SERVER_ALPHA_FACTOR;
	}

	if (unlikely(LOG_LEVEL_DEBUG >= lg->level)) {
		char vdevstr[UINT128_BYTES * 2 + 1];
		memset(vdevstr, 0, UINT128_BYTES*2 + 1);
		uint128_dump(vdevid, vdevstr, UINT128_BYTES*2 + 1);

		log_debug(lg, "%p flexhash estimate: vdevid: %s req_len: %ld "
		    "time: %ld", fhtable, vdevstr, required_len, ret_est);
	}

	return ret_est;
}


/*
 * Update the local in memory flexhash table with the current available raw disk
 * capacity left on each device.
 * This will be a short lived operation that is called ~ 1-2x a day
 */
void
local_flexhash_update_vdev_seqid(volatile struct flexhash *fhtable,
    char *vdevidstr, uint64_t seqid)
{
	struct vdevstore *vdevstore = fhtable->vdevstore;
	int idx;

	uint128_t vdevid;
	uint128_fromhex(vdevidstr, UINT128_STR_BYTES, &vdevid);

	pthread_mutex_lock(&vdevstore->mutex);
	idx = vdevstore_getvdev_index_nl(vdevstore, &vdevid);
	if (idx < 0) {
		pthread_mutex_unlock(&vdevstore->mutex);
		return;
	}
	vdevstore->lvdevlist[idx].seqid = seqid;
	pthread_mutex_unlock(&vdevstore->mutex);
}

int
local_flexhash_update_serverid_seqid(volatile struct flexhash *fhtable,
    char *serveridstr, uint64_t inprog_seqid)
{
	uint128_t serverid;
	uint128_fromhex(serveridstr, UINT128_STR_BYTES, &serverid);

	struct fhserver *fhserver;
	fhserver = flexhash_get_fhserver(fhtable, &serverid);
	if (!fhserver) {
		return -ENOENT;
	}
	fhserver->inprog_seqid = inprog_seqid;

	return 0;
}

/*
 * Update the local in memory flexhash table with the result of TRLOG flush.
 * Called on every VDEVID flush, which is ~ 5s interval
 */
void
flexhash_update_vdev_physical_used(volatile struct flexhash *fhtable,
    uint128_t *vdevid, uint64_t physical_used)
{
	struct vdevstore *vdevstore = fhtable->vdevstore;
	int idx;

	pthread_mutex_lock(&vdevstore->mutex);
	idx = vdevstore_getvdev_index_nl(vdevstore, vdevid);
	if (idx < 0) {
		pthread_mutex_unlock(&vdevstore->mutex);
		return;
	}
	vdevstore->lvdevlist[idx].avail = vdevstore->lvdevlist[idx].size - physical_used;
	pthread_mutex_unlock(&vdevstore->mutex);
	return;
}

int
flexhash_get_ngcount(volatile struct flexhash *fhtable, const uint512_t *hashid,
    fhrow_t *row_out, int *ngcount)
{
	int count = 0;
	struct dlist *dl = NULL;

	if (hashid)
		*row_out = HASHROWID(hashid, fhtable);

	dl = flexhash_devicelist(fhtable, *row_out);
	if (!dl) {
		log_warn(lg, "Empty list. returning row: %d", *row_out);
		return -ENOENT;
	}
	*ngcount = dl->numdevs;

	if (!flexhash_is_pristine(fhtable))
		return -EAGAIN;
	return 0;
}

int flexhash_is_rowmember_fhrow(volatile struct flexhash *fhtable, uint128_t *vdevid,
					fhrow_t row)
{
	int count = 0;
	struct dlist *dl = NULL;

	dl = flexhash_devicelist(fhtable, row);
	if (!dl) {
		log_warn(lg, "Empty list. returning %d", count);
		return 0;
	}
	return dlist_find_id(dl, vdevid) ? 1 : 0;
}

static int
vdev_compare (const void * a, const void * b)
{
	struct lvdev **vdeva = (struct lvdev **)a;
	struct lvdev **vdevb = (struct lvdev **)b;
	return COMPARE_SDEVID(&(*vdeva)->vdevid, &(*vdevb)->vdevid);
}

int flexhash_get_row_server_addrs(int is_client, void *ctx,
    uint16_t row, struct sockaddr_in6 *addrs_out, int *addrs_len)
{
	struct dlist *dl = NULL;
	volatile struct flexhash *fhtable;

	if (is_client) {
		struct ccow *tc = (struct ccow *) ctx;
		fhtable = tc->flexhash;
	} else {
		struct ccowd *ccow_daemon = (struct ccowd *) ctx;
		fhtable = ccow_daemon->flexhash;
	}

	dl = flexhash_devicelist(fhtable, row);
	if (!dl) {
		log_warn(lg, "Empty dl list");
		return -ENOEXEC;
	}

	uint128_t sids[REPLICAST_DEVROW_MAX] = { {0} };
	struct fhdev *fhdevptr = dl->devlist;
	int count = 0;
	while (fhdevptr != NULL) {
		struct lvdev *list_vdev = fhdevptr->vdev;
		if (list_vdev->state == VDEV_STATE_DEAD)
			continue;
		struct fhserver *server = list_vdev->server;
		int slot = -1;
		for (int i = 0; i < REPLICAST_DEVROW_MAX; i++) {
			if (uint128_cmp(&sids[i], &server->id) == 0)
				break;
			if (uint128_cmp(&sids[i], &uint128_null) == 0) {
				slot = i;
				break;
			}
		}
		if (slot != -1) {
			sids[slot] = server->id;
			memcpy((void *) &addrs_out[count].sin6_addr, &server->ipaddr, 16);
			addrs_out[count].sin6_family = AF_INET6;
			addrs_out[count].sin6_port = htons(server->port);
			count++;
		}
		fhdevptr = fhdevptr->next;
	}

	*addrs_len = count;

	return 0;
}

int flexhash_find_master(volatile struct flexhash *fhtable,
    const uint512_t *hashid, int shard_index, uint128_t *vdevid_out)
{
	int count = 0;
	struct dlist *dl = NULL;
	fhrow_t row = HASHROWID(hashid, fhtable);

	dl = flexhash_devicelist(fhtable, row);
	if (!dl) {
		log_warn(lg, "Empty list. returning %d", count);
		return -ENOEXEC;
	}

	struct fhdev *fhdevptr = dl->devlist;
	struct lvdev *min_vdev = NULL;

	/* select "MIN" vdev */
	if (shard_index <= 0) {
		while (fhdevptr != NULL) {
			struct lvdev *list_vdev = fhdevptr->vdev;
			if (list_vdev->state == VDEV_STATE_DEAD)
				continue;
			if (!min_vdev) {
				min_vdev = list_vdev;
			} else {
				if (COMPARE_SDEVID(&list_vdev->vdevid, &min_vdev->vdevid) < 0)
					min_vdev = list_vdev;
			}
			fhdevptr = fhdevptr->next;
		}
		if (!min_vdev) {
			log_warn(lg, "Empty vdev list. Min vdev not defined.");
			return -ENOENT;
		}
		*vdevid_out = min_vdev->vdevid;
		return 0;
	}


	// Find sharding master based on shard index
	int num_vdev = 0;
	struct lvdev *values[FLEXHASH_MAX_VDEVS];
	while (fhdevptr != NULL) {
		struct lvdev *list_vdev = fhdevptr->vdev;
		if (list_vdev->state == VDEV_STATE_DEAD)
			continue;
		values[num_vdev++] = list_vdev;
		fhdevptr = fhdevptr->next;
	}

	if (num_vdev == 0) {
		log_warn(lg, "Empty vdev list");
		return -ENOENT;
	}

	qsort (values, num_vdev, sizeof(struct lvdev *), vdev_compare);

	*vdevid_out = values[shard_index % num_vdev]->vdevid;
	return 0;
}

int flexhash_is_rowmember(volatile struct flexhash *fhtable, uint128_t *vdevid,
						const uint512_t *hashid)
{
	fhrow_t row = HASHROWID(hashid, fhtable);

	return flexhash_is_rowmember_fhrow(fhtable, vdevid, row);
}

int
flexhash_check_inprog_seqid(volatile struct flexhash *fhtable, uint64_t inprog_seqid)
{
	struct fhserver *iter;

	assert(fhtable);

	iter = fhtable->serverlist;
	if ((!iter) && (fhtable->servercount == 0))
		return -ENOENT;

	int total = 0;
	int bad = 0;
	int i;

	if (fhtable->fdmode == FD_ANY_FIRST) {
		while (iter != NULL) {
			if (iter->inprog_seqid < inprog_seqid) {
				return -ENODEV;
			}
			iter = iter->next;
		}
		return 0;
	} else if (fhtable->fdmode == FD_SERVER) {
		while (iter != NULL) {
			total++;
			if (iter->inprog_seqid < inprog_seqid) {
				bad++;
			}
			iter = iter->next;
		}
	} else if (fhtable->fdmode == FD_ZONE) {
		total = flexhash_zcount(fhtable);
		if (total == 0)
			return -ENODEV;

		uint8_t badzones[FLEXHASH_MAX_ZONES];
		while (iter != NULL) {
			if (iter->zone > 0 && iter->inprog_seqid < inprog_seqid) {
				int found = 0;
				for (i=0; i<bad; i++) {
				   if (badzones[i] == iter->zone) {
					   found = 1;
					   break;
				   }
				}
				if (!found) {
					badzones[bad++] = iter->zone;
				}
			}
			iter = iter->next;
		}
	} else {
		return -EINVAL;
	}

	if (total == 0 || bad > 1 || bad == total) {
		return -ENODEV;
	}

	return 0;
}

int
flexhash_check_seqid(volatile struct flexhash *fhtable, uint64_t seqid)
{
	struct fhserver *iter;

	assert(fhtable);

	iter = fhtable->serverlist;
	if ((!iter) && (fhtable->servercount == 0))
		return -ENOENT;

	int total = 0;
	int bad = 0;
	int i;

	if (fhtable->fdmode == FD_ANY_FIRST) {
		while (iter != NULL) {
			struct fhdev *fhdev = iter->vdevlist.devlist;

			while (fhdev != NULL) {
				struct lvdev *lvdev = fhdev->vdev;

				/*
				 * Read-only VDEVs still can process TS batches.
				 *
				 * The case is a boundary condition when device
				 * accumulated batches and switched to RO.
				 *
				 * As we do not exclude RO devices from FH table
				 * we had to expect them to be part of TRLOG logic
				 */
				if (lvdev->state != VDEV_STATE_ALIVE &&
				    lvdev->state != VDEV_STATE_READ_ONLY) {
					fhdev = fhdev->next;
					continue;
				}
				total++;

				if (lvdev->seqid < seqid) {
					bad++;
				}

				fhdev = fhdev->next;
			}
			iter = iter->next;
		}
	} else if (fhtable->fdmode == FD_SERVER) {
		while (iter != NULL) {
			struct fhdev *fhdev = iter->vdevlist.devlist;

			total++;

			int slow_disk = 0;
			while (fhdev != NULL) {
				struct lvdev *lvdev = fhdev->vdev;

				if (lvdev->state != VDEV_STATE_ALIVE &&
					lvdev->state != VDEV_STATE_READ_ONLY) {
					fhdev = fhdev->next;
					continue;
				}

				if (lvdev->seqid < seqid) {
					slow_disk = 1;
					break;
				}

				fhdev = fhdev->next;
			}
			iter = iter->next;
			if (slow_disk) {
				bad++;
			}
		}
	} else if (fhtable->fdmode == FD_ZONE) {
		total = flexhash_zcount(fhtable);
		if (total == 0)
			return -ENODEV;

		uint8_t badzones[FLEXHASH_MAX_ZONES];
		while (iter != NULL) {
			struct fhdev *fhdev = iter->vdevlist.devlist;

			int slow_disk = 0;
			while (fhdev != NULL) {
				struct lvdev *lvdev = fhdev->vdev;

				if (lvdev->state != VDEV_STATE_ALIVE &&
					lvdev->state != VDEV_STATE_READ_ONLY) {
					fhdev = fhdev->next;
					continue;
				}

				if (lvdev->seqid < seqid) {
					slow_disk = 1;
					break;
				}

				fhdev = fhdev->next;
			}

			if (iter->zone > 0 && slow_disk) {
				int found = 0;
				for (i=0; i<bad; i++) {
				   if (badzones[i] == iter->zone) {
					   found = 1;
					   break;
				   }
				}
				if (!found) {
					badzones[bad++] = iter->zone;
				}
			}
			iter = iter->next;
		}
	} else {
		return -EINVAL;
	}

	if (total == 0 || bad > 1 || bad == total) {
		return -ENODEV;
	}


	return 0;
}

int
flexhash_remove_fhserver(volatile struct flexhash *fhtable, uint128_t *vdevid)
{
	struct fhserver *iter, *tmp;

	assert(fhtable);
	assert(vdevid);

	iter = fhtable->serverlist;
	if ((!iter) && (fhtable->servercount == 0))
		return -ENOENT;

	if (COMPARE_SDEVID(vdevid, &iter->id) == 0) {
		fhtable->serverlist = iter->next;
		flexhash_free_fhserver(iter);
		fhtable->servercount--;
		return 0;
	}
	if (fhtable->servercount == 1)
		return -ENOENT;

	while (iter->next != NULL) {
		if (COMPARE_SDEVID(vdevid, &iter->next->id) == 0) {
			tmp = iter->next;
			iter->next = iter->next->next;
			flexhash_free_fhserver(tmp);
			fhtable->servercount--;
			return 0;
		}

		iter = iter->next;
	}
	return -ENOENT;
}

int
flexhash_remove_server(volatile struct flexhash *fhtable, struct cl_node *node)
{
	int err;
	char vdevstr[MAX_SDEVID_STR];

	struct fhserver *fhserver;
	fhserver = flexhash_get_fhserver(fhtable, &node->serverid);
	if (!fhserver) {
		return -ENOENT;
	}
	// go through the list of vdevs and mark them dead
	struct fhdev *fhdev = fhserver->vdevlist.devlist;
	while (fhdev != NULL) {
		struct lvdev *lvdev = fhdev->vdev;
		int err = flexhash_leave(fhtable, &lvdev->vdevid);
		fhdev = fhdev->next;
	}
	// remove the server from the list
	err = flexhash_remove_fhserver(fhtable, &node->serverid);
	if (err)
		return err;

	flexhash_recalc_zonecount(fhtable);
	return 0;
}


struct cl_vdev *
flexhash_fhserver_vdevs(volatile struct flexhash *fhtable, struct fhserver *fhserver,
				int *vdevcount, int hflags)
{
	struct cl_vdev *retvdev;

	assert(fhserver);

	if (fhserver->nr_vdevs <= 0) {
		*vdevcount = 0;
		return NULL;
	}
	retvdev = (struct cl_vdev *) je_calloc(fhserver->nr_vdevs,
						sizeof (struct cl_vdev));
	if (!retvdev) {
		*vdevcount = 0;
		return NULL;
	}
	struct fhdev *fhdev = fhserver->vdevlist.devlist;
	if ((!fhdev) && (fhserver->nr_vdevs <= 0)) {
		*vdevcount = 0;
		je_free(retvdev);
		return NULL;
	}
	int i = 0;
	while (fhdev != NULL) {
		struct lvdev *lvdev = fhdev->vdev;
		memcpy(&retvdev[i].vdevid,&lvdev->vdevid,
		    sizeof (uint128_t));
		retvdev[i].size = lvdev->size;
		retvdev[i].avail = lvdev->avail;
		retvdev[i].activerows = lvdev->activerows;
		retvdev[i].state = lvdev->state;
		retvdev[i].port = lvdev->port;
		// Revisit: done this way while debugging memory corruption
		if (hflags) {
			retvdev[i].numrows = lvdev->numrows;
			for (uint32_t j = 0; j < lvdev->numrows; j++) {
				retvdev[i].hashcount[j] = lvdev->hashcount[j];
			}
		} else {
			retvdev[i].numrows = 0;
			memset(&retvdev[i].hashcount[0],
						0, FLEXHASH_MAX_TAB_LENGTH);
		}
		fhdev = fhdev->next;
		i++;
	}

	*vdevcount = i;
	return retvdev;
}

int
flexhash_get_nodecopy(volatile struct flexhash *fhtable, uint128_t *serverid,
						struct cl_node **node, int hcflags)
{
	struct fhserver *fhserver = flexhash_get_fhserver(fhtable, serverid);
	if (!fhserver)
		return -ENOENT;
	struct cl_node *retnode = je_calloc(1, sizeof (struct cl_node));

	retnode->serverid = fhserver->id;
	retnode->addr = fhserver->ipaddr;
	retnode->port = fhserver->port;
	retnode->zone = fhserver->zone;
	int vdevcount;
	retnode->vdevs = flexhash_fhserver_vdevs(fhtable, fhserver, &vdevcount, hcflags);
	retnode->nr_vdevs = vdevcount;
	*node = retnode;
	return 0;
}

inline int
flexhash_is_stale(volatile struct flexhash *fhtable)
{
	return fhtable->stale;
}

inline void
flexhash_mark_stale(volatile struct flexhash *fhtable)
{
	fhtable->stale = 1;
}

inline void
flexhash_clear_stale(volatile struct flexhash *fhtable)
{
	fhtable->stale = 0;
}

inline static void
flexhash_set_rebuild_in_progress(volatile struct flexhash *fhtable)
{
	fhtable->is_ready = FH_REBUILD;
}

struct fhserver *
flexhash_find_fhserver(struct flexhash *fhtable, uint128_t *id)
{

	struct fhserver *sptr = fhtable->serverlist;
	for (int i = 0; i != fhtable->servercount; i++) {
		if (uint128_cmp(&sptr->id, id) == 0) {
			return sptr;
		}
		sptr = sptr->next;
	}

	return NULL;
}


int
flexhash_add_temp_servlist(struct flexhash *fhtable, json_value *vl)
{
	struct fhserver *serverptr = NULL;
	struct fhserver *fhserver = NULL;
	char serveridstr[MAX_SDEVID_STR];

	if (!vl) {
		log_error(lg, "Incorrect json");
		return -EINVAL;
	}

	if (vl->type != json_string) {
		log_error(lg,"Syntax error: when reading the json file for flexhash");
		return -EINVAL;
	}
	strncpy(serveridstr, vl->u.string.ptr, vl->u.string.length);

	uint128_t serverid;
	uint128_fromhex(serveridstr, UINT128_STR_BYTES, &serverid);
	fhserver = je_calloc(1, sizeof(struct fhserver));
	if (fhserver == 0) {
		log_error(lg, "Not enough memory");
		return -ENOMEM;
	}
	memcpy(&fhserver->id, &serverid, sizeof(uint128_t));

	SDEVID_DUMP(&serverid, serveridstr);
	serverptr = fhtable->serverlist;
	if (serverptr == NULL) { /* empty list adding the first element */
		fhserver->next = NULL;
		fhtable->serverlist = fhserver;
		fhtable->servercount = 1;
		return 0;
	}
	if (COMPARE_SDEVID(&serverid, &serverptr->id) == 0) {
		log_warn(lg, "Server %s already exists", serveridstr);
		je_free(fhserver);
		return -EEXIST;
	}
	while (serverptr->next != NULL) {
		if (uint128_cmp(&serverid, &serverptr->next->id) == 0) {
			log_warn(lg, "Server %s already exists", serveridstr);
			je_free(fhserver);
			return -EEXIST;
		}
		serverptr = serverptr->next;
	}

	fhserver->next = NULL;
	serverptr->next = fhserver;
	fhtable->servercount++;
	return 0;
}

void
flexhash_file_hashcount(struct flexhash *fhtable, struct lvdev *lvdev, json_value *vl)
{
	lvdev->numrows = fhtable->numrows;
	for (int r=0; r < fhtable->numrows; r++) {
		json_value *vll = vl->u.array.values[r];
		if (!vll)
			continue;
		if (vll->u.integer) {
			lvdev->hashcount[r] = 1;
			flexhash_join(fhtable, r, (sdevid_t *)&lvdev->vdevid);
		}
	}
}

/* Arguments:
 *	- json buffer to be parsed
 *	- either use this checkpoint numdevices or the one in the buffer
 *	  if this is -1, then use the rowmount calculated based on the numdevices
 *	  in the buffer, if this is a positive number use this
 */

static struct flexhash *
flexhash_read_json_buf(json_value *fh_json, int ckp_numdevices)
{
	int numdevices = 0;
	int found = 0;
	for (uint32_t i = 0; i < fh_json->u.object.length; i++) {
		if (strncmp(fh_json->u.object.values[i].name, "vdevcount", 9) == 0) {
			json_value *v = fh_json->u.object.values[i].value;
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: servercount is not "
				    "an integer: -EINVAL");
				json_value_free(fh_json);
				return NULL;
			}
			numdevices = v->u.integer;
			found++;
		}
	}

	if (numdevices == 0 && found == 0) {
		log_error(lg, "Error numdevices: %d", numdevices);
		json_value_free(fh_json);
		return NULL;
	}

	if (ckp_numdevices == CKP_NODEVICES )
		ckp_numdevices = numdevices;
	struct flexhash *fhtable = flexhash_table_create(ckp_numdevices, FH_SERVER_SIDE);
	if (fhtable == NULL) {
		log_error(lg, "Error creating flexhash table ");
		json_value_free(fh_json);
		return NULL;
	}

	json_value *vdlist = NULL;
	for (uint32_t i = 0; i < fh_json->u.object.length; i++) {
		if (strncmp(fh_json->u.object.values[i].name, "genid", 5) == 0) {
			json_value *v = fh_json->u.object.values[i].value;
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: genid is not "
				    "an integer: -EINVAL");
				json_value_free(fh_json);
				return NULL;
			}
			fhtable->genid = v->u.integer;
		} else if (strncmp(fh_json->u.object.values[i].name, "failure_domain", 14) == 0) {
			json_value *v = fh_json->u.object.values[i].value;
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: failure_domain is not "
				    "an integer: -EINVAL");
				json_value_free(fh_json);
				return NULL;
			}
			fhtable->fdmode = v->u.integer;
		} else if (strncmp(fh_json->u.object.values[i].name, "zonecount", 9) == 0) {
			json_value *v = fh_json->u.object.values[i].value;
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: zonecount is not "
				    "an integer: -EINVAL");
				json_value_free(fh_json);
				return NULL;
			}
			fhtable->zonecount = v->u.integer;
		} else if (strncmp(fh_json->u.object.values[i].name, "servercount", 11) == 0) {
			json_value *v = fh_json->u.object.values[i].value;
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: servercount is not "
				    "an integer: -EINVAL");
				json_value_free(fh_json);
				return NULL;
			}
			fhtable->servercount = v->u.integer;
		} else if (strncmp(fh_json->u.object.values[i].name, "vdevcount", 9) == 0) {
			json_value *v = fh_json->u.object.values[i].value;
			if (v->type != json_integer) {
				log_error(lg, "Syntax error: vdevcount is not "
				    "an integer: -EINVAL");
				json_value_free(fh_json);
				return NULL;
			}
			int vdevcount = v->u.integer;
			if (vdevcount != numdevices) {
				log_debug(lg, " vdevcount: %d does not match numdevices: %d", vdevcount, numdevices);
				json_value_free(fh_json);
				return NULL;
			}
			fhtable->numdevices = v->u.integer;
		}
	}

	int scount = 0;
	// create a list of servers first
	for (uint32_t i = 0; i < fh_json->u.object.length; i++) {
		if (strncmp(fh_json->u.object.values[i].name, "vdevlist", 8) == 0) {
			vdlist = fh_json->u.object.values[i].value;
			for (uint32_t j = 0; j < vdlist->u.array.length; j++) {
				json_value *vl = vdlist->u.array.values[j];
				for (uint32_t k = 0; k < vl->u.object.length; k++) {
					if (strncmp(vl->u.object.values[k].name, "serverid", 8) == 0) {
						json_value *vll = vl->u.object.values[k].value;
						int err = flexhash_add_temp_servlist(fhtable, vll);
						if (!err)
							scount++;
					}
				}
			}
		}
		if (strncmp(fh_json->u.object.values[i].name, "zonelist", 8) == 0) {
			vdlist = fh_json->u.object.values[i].value;
			for (uint32_t j = 0; j < vdlist->u.array.length; j++) {
				json_value *vll = vdlist->u.array.values[j];
				char *eptr;
				fhtable->zonelist[j] = strtoul(vll->u.string.ptr, &eptr, 10);
			}
		}
	}
	int arridx;
	struct lvdev *lvdev;
	uint128_t vdevid, serverid;
	struct fhserver *fhserver;
	int sid_found = 0;
	int vid_found = 0;
	for (uint32_t m = 0; m < fh_json->u.object.length; m++) {
		if (strncmp(fh_json->u.object.values[m].name, "vdevlist", 8) == 0) {
			vdlist = fh_json->u.object.values[m].value;
			for (uint32_t k = 0; k < vdlist->u.array.length; k++) {
				json_value *vl = vdlist->u.array.values[k];
				for (uint32_t i = 0; i < vl->u.object.length; i++) {
					if (strncmp(vl->u.object.values[i].name, "vdevid", 6) == 0) {
						json_value *vll = vl->u.object.values[i].value;
						uint128_fromhex(vll->u.string.ptr, UINT128_STR_BYTES, &vdevid);
						continue;
					}
					if (strncmp(vl->u.object.values[i].name, "serverid", 8) == 0) {
						json_value *vll = vl->u.object.values[i].value;
						uint128_fromhex(vll->u.string.ptr, UINT128_STR_BYTES, &serverid);
						sid_found = 1;
						continue;
					}
					if (!sid_found && !vid_found)
						continue;

					fhserver = flexhash_find_fhserver(fhtable, &serverid);
					if (!fhserver)
						continue;

					int idx = vdevstore_getvdev_index_nl(fhtable->vdevstore, &vdevid);
					if (idx == -ENOENT) {
						lvdev = vdevstore_add_new(fhtable->vdevstore,
						    &vdevid, fhserver, &arridx);
						if (!lvdev) {
							log_error(lg, "Unable to get lvdev: "
							    " index: %d", arridx);
							continue;
						}
					} else {
						lvdev = &fhtable->vdevstore->lvdevlist[idx];
					}
					if (strncmp(vl->u.object.values[i].name, "zone", 4) == 0) {
						json_value *vll = vl->u.object.values[i].value;
						if (vll->type == json_integer) {
							fhserver->zone = vll->u.integer;
						}
						continue;
					}
					if (strncmp(vl->u.object.values[i].name, "name", 4) == 0) {
						json_value *vll = vl->u.object.values[i].value;
						if (vll->type != json_string) {
							log_error(lg, "Invalid device name!");
							continue;
						}
					}
					if (strncmp(vl->u.object.values[i].name, "state", 5) == 0) {
						json_value *vll = vl->u.object.values[i].value;
						if (vll->type == json_integer) {
							lvdev->state = vll->u.integer;
						}
						continue;
					}
					if (strncmp(vl->u.object.values[i].name, "capacity", 8) == 0) {
						json_value *vll = vl->u.object.values[i].value;
						char *token = strtok(vll->u.string.ptr, " ");
						char *eptr;
						lvdev->size = FH_MIBS_TO_BYTES(strtoul(token, &eptr, 10));
						continue;
					}
					fhtable->total_capacity += lvdev->size;

					if (strncmp(vl->u.object.values[i].name, "free space", 10) == 0) {
						json_value *vll = vl->u.object.values[i].value;
						char *token = strtok(vll->u.string.ptr, " ");
						char *eptr;
						lvdev->avail = FH_MIBS_TO_BYTES(strtoul(token, &eptr, 10));
						continue;
					}

					if (strncmp(vl->u.object.values[i].name, "unicast port", 12) == 0) {
						json_value *vll = vl->u.object.values[i].value;
						char *token = strtok(vll->u.string.ptr, " ");
						char *eptr;
						lvdev->port = strtoul(token, &eptr, 10);
						continue;
					}

					if (strncmp(vl->u.object.values[i].name, "hashcount", 8) == 0) {
						json_value *vll = vl->u.object.values[i].value;
						flexhash_file_hashcount(fhtable, lvdev, vll);
						continue;
					}
					int err = flexhash_addto_server(fhtable, fhserver, lvdev);
					if (err && err != -EEXIST) {
						char vdevstr[UINT128_STR_BYTES], serverstr[UINT128_STR_BYTES];
						uint128_dump(&lvdev->vdevid, vdevstr, UINT128_STR_BYTES);
						uint128_dump(&fhserver->id, serverstr, UINT128_STR_BYTES);
						log_error(lg, "Unable to add vdev: %s to server: %s",
						    vdevstr, serverstr);
					}

				}
			}
		}
	}
	/* Fetch servers IP */
	for (uint32_t m = 0; m < fh_json->u.object.length; m++) {
		if (strncmp(fh_json->u.object.values[m].name, "servers", 7) == 0) {
			vdlist = fh_json->u.object.values[m].value;
			for (uint32_t k = 0; k < vdlist->u.array.length; k++) {
				json_value *vl = vdlist->u.array.values[k];
				struct fhserver* srv = NULL;
				uint128_t ip = uint128_null;
				uint16_t port = CCOWD_BASE_PORT;
				for (uint32_t i = 0; i < vl->u.object.length; i++) {
					json_value *vll = vl->u.object.values[i].value;
					if (strncmp(vl->u.object.values[i].name, "serverid", 8) == 0) {
						uint128_t srvid;
						char *token = strtok(vll->u.string.ptr, " ");
						uint128_fromhex(token, UINT128_STR_BYTES, &srvid);
						srv = flexhash_find_fhserver(fhtable, &srvid);
						continue;
					} else if (strncmp(vl->u.object.values[i].name, "ip", 2) == 0) {
						char *token = strtok(vll->u.string.ptr, " ");
						inet_pton(AF_INET6, token, &ip);
						continue;
					} else if (strncmp(vl->u.object.values[i].name, "port", 4) == 0) {
						port = vll->u.integer;
						continue;
					}
				}
				if (srv && uint128_cmp(&ip, &uint128_null)) {
					srv->ipaddr = ip;
					srv->port = port;
				}
			}
		}
	}
	json_value_free(fh_json);
	fhtable->ckpread = 1;
	return fhtable;
}

struct flexhash *
flexhash_read_buf(int ckp_numdevices, char *buf, int len)
{
	json_value *fh_json = json_parse(buf, len);
	if (fh_json == NULL) {
		log_error(lg, "Unable to read buf: %p len: %d", buf, len);
		return NULL;
	}
	return flexhash_read_json_buf(fh_json, ckp_numdevices);
}

/* returns
 *
 * 1 - (true) if file checkpoint exists and was found
 * 0 - (false) if the checkpoint file was not found
 *
 */
int
flexhash_checkpoint_exists()
{
	char *env_prefix = getenv("NEDGE_HOME");
	char filepath[PATH_MAX];
	struct stat st;

	if (env_prefix) {
		snprintf(filepath, PATH_MAX, "%s/var/run/%s-%s.%s",
		    env_prefix, FLEXHASH_LOGFILE, FLEXHASH_CHECKPOINT,
		    FLEXHASH_LOGFILE_EXTN);
	} else {
		snprintf(filepath, PATH_MAX, "%s/var/run/%s-%s.%s",
		    QUOTE(INSTALL_PREFIX), FLEXHASH_LOGFILE, FLEXHASH_CHECKPOINT,
		    FLEXHASH_LOGFILE_EXTN);
	}
	int rc = stat(filepath, &st);
	if (rc != 0) {
		log_warn(lg, "File: %s not found", filepath);
		return 0;
	}

	return 1;
}

int
flexhash_cpset(volatile struct flexhash *fhtable, uint64_t recv_genid)
{
	struct stat st;
	char *env_prefix = getenv("NEDGE_HOME");
	char filepath[PATH_MAX];
	char filepath2[PATH_MAX];
	char filepath3[PATH_MAX];
	int inputFd, outputFd, openFlags;
	mode_t filePerms;
	ssize_t numRead;
	char buf[4096];
	int rc;

	/* check if current genid still same as requested */
	if (fhtable->genid != recv_genid)
		return -EBADF;

	/* check if flexhash.json exists */
	snprintf(filepath, PATH_MAX, "%s/var/run/%s.%s",
	    env_prefix, FLEXHASH_LOGFILE, FLEXHASH_LOGFILE_EXTN);
	rc = stat(filepath, &st);
	if (rc != 0)
		return rc;

	/* check if "old" flexhash-checkpoint-bak.json exists and if so delete it */
	snprintf(filepath3, PATH_MAX, "%s/var/run/%s-%s-bak.%s",
	    env_prefix, FLEXHASH_LOGFILE, FLEXHASH_CHECKPOINT,
	    FLEXHASH_LOGFILE_EXTN);
	rc = stat(filepath3, &st);
	if (rc == 0) {
		log_debug(lg, "File %s found, removing ", filepath3);
		rc = remove(filepath3);
		if (rc != 0) {
			log_error(lg, "Unable to remove old bak file %s err: %d",
			    filepath3, rc);
			return rc;
		}
	}
	/* check if "old" flexhash-checkpoint.json exists and if so rename as bak */
	snprintf(filepath2, PATH_MAX, "%s/var/run/%s-%s.%s",
	    env_prefix, FLEXHASH_LOGFILE, FLEXHASH_CHECKPOINT,
	    FLEXHASH_LOGFILE_EXTN);
	rc = stat(filepath2, &st);
	if (rc == 0) {
		if ((st.st_mode & S_IFMT) == S_IFREG) {
			rc = rename(filepath2, filepath3);
			if (rc != 0) {
				log_error(lg, "Unable to rename the file %s to %s err: %d",
				    filepath2, filepath3, rc);
				return rc;
			}
		}
	}

	inputFd = open(filepath, O_RDONLY);
	if (inputFd == -1) {
		rc = -errno;
		log_debug(lg, "Unable to open %s, err %d", filepath, rc);
		return -errno;
	}

	openFlags = O_CREAT | O_WRONLY | O_TRUNC;
	filePerms = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP |
		S_IROTH | S_IWOTH;      /* rw-rw-rw- */
	outputFd = open(filepath2, openFlags, filePerms);
	if (outputFd == -1) {
		rc = -errno;
		close(inputFd);
		log_debug(lg, "Unable to open %s, err %d", filepath2, rc);
		return rc;
	}

	/* Transfer data until we encounter end of input or an error */
	while ((numRead = read(inputFd, buf, 4096)) > 0) {
		if (write(outputFd, buf, numRead) != numRead) {
			numRead = -1;
			break;
		}
	}
	if (numRead == -1) {
		log_debug(lg, "Read/Write error from %s to %s",
		    filepath, filepath2);
	}

	close(inputFd);
	close(outputFd);
	return 0;
}

/* returns the servercount from the checkpoint
 * if file not found or other error cases
 * it returns a -1
 */
int
flexhash_checkpoint_servercount()
{
	int scount=-1;

	char *env_prefix = getenv("NEDGE_HOME");
	char filepath[PATH_MAX];

	if (env_prefix) {
		snprintf(filepath, PATH_MAX, "%s/var/run/%s-%s.%s",
		    env_prefix, FLEXHASH_LOGFILE, FLEXHASH_CHECKPOINT,
		    FLEXHASH_LOGFILE_EXTN);
	} else {
		snprintf(filepath, PATH_MAX, "%s/var/run/%s-%s.%s",
		    QUOTE(INSTALL_PREFIX), FLEXHASH_LOGFILE, FLEXHASH_CHECKPOINT,
		    FLEXHASH_LOGFILE_EXTN);
	}

	struct flexhash *ckpfhtable = flexhash_read_checkpoint(filepath, 1);
	if (!ckpfhtable) {
		log_warn(lg,"Unable to get the checkpoint flexhash ");
		// if checkpoint is not found,this is a new cluster
		// so we do not mark it split. It must be good.
		return scount;
	}

	scount = ckpfhtable->servercount;
	return scount;

}

/* read the checkpoint from a file. is asis_mode ==1, use the filename as is.
 * if the asis_mode ==0, it will pick up the file from <edgefs_home>/var/run
 */
struct flexhash *
flexhash_read_checkpoint(char *filename, int asis_mode)
{
	char *env_prefix = getenv("NEDGE_HOME");
	char filepath[PATH_MAX];
	struct stat st;

	if (filename) {
		if (asis_mode == 0)
			snprintf(filepath, PATH_MAX, "%s/var/run/%s",
				env_prefix, filename);
		else
			sprintf(filepath, "%s", filename);
	} else {
		if (env_prefix) {
			snprintf(filepath, PATH_MAX, "%s/var/run/%s-%s.%s",
			    env_prefix, FLEXHASH_LOGFILE, FLEXHASH_CHECKPOINT,
			    FLEXHASH_LOGFILE_EXTN);
		} else {
			snprintf(filepath, PATH_MAX, "%s/var/run/%s-%s.%s",
			    QUOTE(INSTALL_PREFIX), FLEXHASH_LOGFILE, FLEXHASH_CHECKPOINT,
			    FLEXHASH_LOGFILE_EXTN);
		}
	}
	int rc = stat(filepath, &st);
	if (rc != 0) {
		log_warn(lg, "File: %s not found", filepath);
		return NULL;
	}

	if (st.st_size == 0) {
		log_error(lg, "Removing the Checkpoint: %s file %d bytes long", filepath, (int) st.st_size);
		unlink(filepath);
		return NULL;
	}

	rtbuf_t *rb = rtbuf_init_alloc_one(st.st_size);
	if (!rb) {
		log_error(lg, "Out of memory while reading " "%s:", filepath);
		return NULL;
	}

	int fd = open(filepath, O_RDONLY);
	if (fd == -1) {
		rtbuf_destroy(rb);
		log_error(lg, "Cannot open configuration file %s: %s",
		    filepath, strerror(errno));
		return NULL;
	}
	int len = read(fd, rtbuf(rb, 0).base, rtbuf(rb, 0).len);
	if (len == -1) {
		close(fd);
		rtbuf_destroy(rb);
		log_error(lg, "Cannot read configuration file %s: %s",
		    filepath, strerror(errno));
		return NULL;
	}
	close(fd);

	json_value *fh_json = json_parse(rtbuf(rb, 0).base, rtbuf(rb, 0).len);
	rtbuf_destroy(rb);
	if (!fh_json) {
		log_error(lg, "Cannot parse flexhash-checkpoint.json file %s ",
				filepath);
		return NULL;
	}

	return flexhash_read_json_buf(fh_json, CKP_NODEVICES);
}

int
flexhash_save_checkpoint(char *savebuf)
{
	struct stat st;
	char *env_prefix = getenv("NEDGE_HOME");
	char filepath[PATH_MAX];
	char bakfilepath[PATH_MAX];
	int err = 0;
	uint64_t start = uv_hrtime();

	if (env_prefix) {
		snprintf(filepath, PATH_MAX, "%s/var/run/%s-%s.%s",
		    env_prefix, FLEXHASH_LOGFILE, FLEXHASH_CHECKPOINT,
		    FLEXHASH_LOGFILE_EXTN);
		snprintf(bakfilepath, PATH_MAX, "%s/var/run/%s-%s-bak.%s",
		    env_prefix, FLEXHASH_LOGFILE, FLEXHASH_CHECKPOINT,
		    FLEXHASH_LOGFILE_EXTN);
	} else {
		snprintf(filepath, PATH_MAX, "%s/var/run/%s-%s.%s",
		    QUOTE(INSTALL_PREFIX), FLEXHASH_LOGFILE, FLEXHASH_CHECKPOINT,
		    FLEXHASH_LOGFILE_EXTN);
		snprintf(bakfilepath, PATH_MAX, "%s/var/run/%s-%s-bak.%s",
		    QUOTE(INSTALL_PREFIX), FLEXHASH_LOGFILE, FLEXHASH_CHECKPOINT,
		    FLEXHASH_LOGFILE_EXTN);
	}

	int rc = stat(bakfilepath, &st);
	if (rc == 0) {
		log_debug(lg, "File %s found, removing ", bakfilepath);
		err = remove(bakfilepath);
		if (err != 0) {
			log_error(lg, "Unable to remove the file %s err: %d",
			    bakfilepath, err);
			goto _exit;
		}
	}
	rc = stat(filepath, &st);
	if (rc == 0) {
		if ((st.st_mode & S_IFMT) == S_IFREG) {
			err = rename(filepath, bakfilepath);
			if (err != 0) {
				log_error(lg, "Unable to rename the file %s to %s err: %d",
				    filepath, bakfilepath, err);
				goto _exit;
			}
		}
	}
	int fd = open(filepath, O_RDWR | O_CREAT, S_IRUSR | S_IRGRP | S_IROTH);
	if (fd == -1) {
		log_error(lg, "Cannot open configuration file %s: %s",
		    filepath, strerror(errno));
		err = -errno;
		goto _exit;
	}

	ssize_t bytes_wrote = 0;
	ssize_t len = strlen(savebuf);
	ssize_t bytes_remaining = len;
	char *tmp_savebuf = savebuf;
	while(bytes_wrote < len) {
		bytes_wrote = write(fd, tmp_savebuf, bytes_remaining);
		if (bytes_wrote < 0) {
			close(fd);
			log_error(lg, "Could not complete the write for %s error: %s",
			    filepath, strerror(errno));
			err = -errno;
			goto _exit;
		}
		tmp_savebuf += bytes_wrote;
		bytes_remaining -= bytes_wrote;
	}
	close(fd);

_exit:
	if (FLEXHASH_FLEXHASH_SAVE_CHECKPOINT_ENABLED()) {
		FLEXHASH_FLEXHASH_SAVE_CHECKPOINT(savebuf, err,
			uv_hrtime() - start);
	}
	return err;
}


int
flexhash_get_checkpoint(rtbuf_t **retbuf)
{
	struct stat st;
	char *env_prefix = getenv("NEDGE_HOME");
	char filepath[PATH_MAX];

	*retbuf = NULL;

	if (env_prefix) {
		snprintf(filepath, PATH_MAX, "%s/var/run/%s-%s.%s",
		    env_prefix, FLEXHASH_LOGFILE, FLEXHASH_CHECKPOINT,
		    FLEXHASH_LOGFILE_EXTN);
	} else {
		snprintf(filepath, PATH_MAX, "%s/var/run/%s-%s.%s",
		    QUOTE(INSTALL_PREFIX), FLEXHASH_LOGFILE, FLEXHASH_CHECKPOINT,
		    FLEXHASH_LOGFILE_EXTN);
	}
	int rc = stat(filepath, &st);
	if (rc != 0) {
		log_warn(lg, "Unable to find file: %s", filepath);
		return -errno;
	}

	rtbuf_t *rb = rtbuf_init_alloc_one(st.st_size + 1);
	if (!rb) {
		log_error(lg, "Out of memory while reading "
		    "%s:", filepath);
		return -ENOMEM;
	}

	int fd = open(filepath, O_RDONLY);
	if (fd == -1) {
		rtbuf_destroy(rb);
		log_error(lg, "Cannot open configuration file %s: %s",
		    filepath, strerror(errno));
		return -errno;
	}

	int len = read(fd, rtbuf(rb, 0).base, st.st_size);
	if (len == -1) {
		close(fd);
		rtbuf_destroy(rb);
		log_error(lg, "Cannot read configuration file %s: %s",
		    filepath, strerror(errno));
		return -errno;
	}
	close(fd);

	/* make it NULL terminated */
	*((char*)rtbuf(rb, 0).base + st.st_size) = 0;

	*retbuf = rb;

	return 0;
}

int
flexhash_get_nodes(volatile struct flexhash *fhtable, struct cl_node **nodes,
    int *numnodes, int hflags)
{
	int i = 0;
	struct cl_node *retnode;
	struct fhserver *fhserver;

	assert(fhtable);

	if (fhtable->stale) {
		log_warn(lg, "Flexhash currently marked stale, try again ");
		return -EAGAIN;
	}
	if (fhtable->servercount <= 0) {
		log_warn(lg, "Flexhash servercount: %d", fhtable->servercount);
		return -ENOENT;
	}
	retnode = je_calloc(fhtable->servercount, sizeof (struct cl_node));
	if (!retnode)
		return -ENOMEM;
	fhserver = fhtable->serverlist;
	while (fhserver != NULL) {
		memcpy(&retnode[i].serverid, &fhserver->id, sizeof (uint128_t));
		memcpy(&retnode[i].addr, &fhserver->ipaddr, sizeof (uint128_t));
		retnode[i].port = fhserver->port;
		retnode[i].zone = fhserver->zone;
		retnode[i].fdmode = fhtable->fdmode;
		retnode[i].ckpread = fhtable->ckpread;
		int vdevcount;
		retnode[i].vdevs = flexhash_fhserver_vdevs(fhtable, fhserver, &vdevcount, hflags);
		retnode[i].nr_vdevs = vdevcount;
		fhserver = fhserver->next;
		i++;
	}
	assert(i == fhtable->servercount);
	*nodes = retnode;
	*numnodes = i;
	return 0;
}

int
flexhash_add_server(volatile struct flexhash *fhtable, struct cl_node *node,
    int join, int validhc, int rebuild_next)
{
	flexhash_lock(fhtable);
	struct fhserver *fhserver
		= flexhash_add_server_only(fhtable, node);
	if (!fhserver) {
		flexhash_unlock(fhtable);
		return -EBADF;
	}
	flexhash_unlock(fhtable);

	int err = flexhash_add_vdevs(fhtable, node, fhserver, join, validhc,
		rebuild_next);
	if (err)
		return err;

	flexhash_update_zonecount(fhtable, fhserver);

	return 0;
}

uint64_t
flexhash_estimate_client_start(uint64_t genid, uint64_t genid_delta,
						uint64_t now, uint64_t pp_rcvd)
{
	uint64_t ret_time = 0;
	/*
	 * genid - original uvid_timestamp -- when the first request started
	 *		Note: this gets reset on a retry
	 * genid_delta - the time delta between the genid and the time this request was generated
	 *               client pads this with rtt/2 so we don't add that at the server side
	 * now - the time when we are taking the estimate
	 * pp_rcvd - when the server received this request
	 * (genid + genid_delta) - the time this request started
	 * (now - pp_rcvd) - the time delta on the server side
	 * SERVER_ALPHA_FACTOR - arbitrary constant
	 */
	ret_time = genid + genid_delta + (now - pp_rcvd) + SERVER_ALPHA_FACTOR;
	return ret_time;
}


static void
flexhash_getvdev_hashcount(struct flexhash *fhtable, struct cl_vdev *vdev)
{
	// go through the flexhash rows looking for this vdev
	// if found, mark that particular row in the vdev's hashcount
	for (fhrow_t row = 0; row < fhtable->numrows; row++) {
		if (dlist_member(&fhtable->dl[row], &vdev->vdevid)) {
			vdev->hashcount[row]++;
		} else {
			vdev->hashcount[row]=0;
		}
	}
}

/* generate the fibonacci series */
int fib(int n)
{
	int f[n+1];
	int i;

	f[0] = 0;
	f[1] = 1;

	for (i = 2; i <= n; i++) {
		f[i] = f[i-1] + f[i-2];
	}
	return f[n];
}

/* Keep the fibinacci numbers in this range */
#define FH_HC_FIB_START 15
#define FH_HC_FIB_MAX 65

/* generate a hashcount distribution based on number of devices
 * DEPRECATED: review before removal.
 */

static void
flexhash_generate_hashcount_distribution(uint128_t *id, int idx, int numdev,
			uint16_t *hashcount, int numrows, int rc)
{
	assert(numdev);
	assert(hashcount);
	assert(numrows >= numdev);

	int wt = ceil(log10(numdev)) * rc;
	int estrowcount = flexhash_hashrowcount(numdev);
	int estslots = numrows/estrowcount;
	int fibcurr = FH_HC_FIB_START;

	for (int i = 0; i < estslots; i++) {
		uint32_t snum = (id->u >> 32) & 0xFFFFFFFF;
		fibcurr = (fibcurr > FH_HC_FIB_MAX) ? FH_HC_FIB_START : fibcurr;
		snum += fib(wt + fibcurr++);
		fhrow_t row = snum % numrows;
		hashcount[row]++;
	}
}

static void
fhrebalance_dlist_free(int row, struct fhdev *dl)
{
	struct fhdev *tmp, *head;

	head = dl;
	while (head != NULL) {
		tmp = head;
		head = head->next;
		struct lvdev *lvdev = tmp->vdev;
		lvdev->rcount->numrows--;
		je_free(tmp);
		tmp = NULL;
	}
}

struct fhdev *
fhrebalance_copy_dlist(struct dlist *dl, int count)
{
	assert(dl);
	int i = 0;
	struct fhdev *retdevlist = NULL, *prev = NULL;
	struct fhdev *fhdevptr = dl->devlist;

	while (fhdevptr && i < count) {
		struct fhdev *tempdev = je_calloc(1, sizeof (struct fhdev));
		tempdev->vdev = fhdevptr->vdev;
		tempdev->next = NULL;

		if (retdevlist == NULL) {
			retdevlist = tempdev;
			prev = tempdev;
		} else {
			prev->next = tempdev;
			prev = tempdev;
		}
		fhdevptr = fhdevptr->next;
		i++;
	}
	return retdevlist;
}

void
flexhash_update_rtt(volatile struct flexhash *fhtable, uint512_t *chid,
			fh_msg_t msg_type, uint64_t start, uint64_t end,
			uint64_t req_len)
{
	fhrow_t row = HASHROWID(chid, fhtable);
	struct ngstat *ngstat = &fhtable->dl[row].ngstat;
	struct avg_ring *ring;
	uint64_t avg_rtt;

	if (end < start)
		return;

	uint64_t delta = end - start;

	if (msg_type == FH_MSG_GET_SOLICITED || msg_type == FH_MSG_PUT_SOLICITED) {
		uint64_t num_4k = (req_len/4096);
		if (req_len % 4096)
			num_4k++;

		delta = (delta/num_4k);
	}

	if (delta >= AVG_RING_MAX_VAL)
		return;

	if (msg_type == FH_MSG_UNSOLICITED)
		ring = &ngstat->avg_unsol_ring;
	else if (msg_type == FH_MSG_PUT_SELECT)
		ring = &ngstat->avg_put_select_ring;
	else if (msg_type == FH_MSG_NAMEDGET_SELECT)
		ring = &ngstat->avg_namedget_select_ring;
	else if (msg_type == FH_MSG_UNNAMEDGET_SELECT)
		ring = &ngstat->avg_unnamedget_select_ring;
	else if (msg_type == FH_MSG_GET_SOLICITED)
		ring = &ngstat->avg_get_sol_ring;
	else
		ring = &ngstat->avg_put_sol_ring;

	avg_rtt = avg_ring_update(ring, delta);

	if (msg_type == FH_MSG_UNSOLICITED)
		ngstat->avg_unsol_rtt = avg_rtt;
	else if (msg_type == FH_MSG_PUT_SELECT)
		ngstat->avg_put_select_rtt = avg_rtt;
	else if (msg_type == FH_MSG_NAMEDGET_SELECT)
		ngstat->avg_namedget_select_rtt = avg_rtt;
	else if (msg_type == FH_MSG_UNNAMEDGET_SELECT)
		ngstat->avg_unnamedget_select_rtt = avg_rtt;
	else if (msg_type == FH_MSG_GET_SOLICITED)
		ngstat->avg_get_sol_rtt = avg_rtt;
	else
		ngstat->avg_put_sol_rtt = avg_rtt;
}

uint64_t
flexhash_get_rtt(volatile struct flexhash *fhtable, uint512_t *chid, fh_msg_t msg_type,
    uint64_t req_len)
{
	if (!fhtable)
		return FH_DEFAULT_NG_RTT;

	fhrow_t row = HASHROWID(chid, fhtable);

	struct ngstat *ngstat = &fhtable->dl[row].ngstat;
	uint64_t avg_rtt = 0;

	if (msg_type == FH_MSG_GET_SOLICITED || msg_type == FH_MSG_PUT_SOLICITED) {
		uint64_t num_4k = (req_len/4096);
		if (req_len % 4096)
			num_4k++;
		if (msg_type == FH_MSG_GET_SOLICITED) {
			avg_rtt = ngstat->avg_get_sol_rtt * num_4k;
		} else
			avg_rtt = ngstat->avg_put_sol_rtt * num_4k;
	} else if (msg_type == FH_MSG_UNSOLICITED) {
		avg_rtt = ngstat->avg_unsol_rtt;
	} else if (msg_type == FH_MSG_PUT_SELECT) {
		avg_rtt = ngstat->avg_put_select_rtt;
	} else if (msg_type == FH_MSG_NAMEDGET_SELECT) {
		avg_rtt = ngstat->avg_namedget_select_rtt;
	} else if (msg_type == FH_MSG_UNNAMEDGET_SELECT) {
		avg_rtt = ngstat->avg_unnamedget_select_rtt;
	}
	return avg_rtt > 0 ? avg_rtt : FH_DEFAULT_NG_RTT;
}

/* returns 0 - if not found
 * returns 1 - if found
 */
int
flexhash_exists(volatile struct flexhash *fhtable, fhrow_t row, uint128_t *vdevid)
{
	struct dlist *dlist = flexhash_devicelist(fhtable, row);
	return dlist_find_id(dlist, vdevid);
}

int
flexhash_get_vdev_row(volatile struct flexhash *fhtable, uint128_t *vdevid, fhrow_t* row)
{
	for (fhrow_t i = 0; i < fhtable->numrows; i++) {
		struct dlist *dlist = flexhash_devicelist(fhtable, i);
		if (dlist_find_id(dlist, vdevid)) {
			*row = i;
			return 0;
		}
	}
	return -1;
}


static void
flexhash_free_clnodes(struct cl_node *node, int nr_nodes)
{
	if (node && nr_nodes > 0) {
		struct cl_node *nodeptr = node;
		for (int i = 0; i < nr_nodes; i++) {
			je_free(nodeptr->vdevs);
			nodeptr->vdevs = NULL;
			nodeptr++;
		}
		je_free(node);
		node = NULL;
	}
}

int
flexhash_add_node(struct flexhash *fhtable, struct cl_node *node)
{
	struct fhserver *fhserver;
	char out[UINT128_STR_BYTES];

	uint128_dump(&node->serverid, out, UINT128_STR_BYTES);
	fhserver = flexhash_get_fhserver(fhtable, &node->serverid);
	if (fhserver) {
		log_warn(lg, "rebuild : server %s already exists", out);
		return -1;
	}
	int err = flexhash_add_server(fhtable, node, FH_TABLE_JOIN,
	    FH_GOOD_HC, FH_REBUILD_NEXT);
	if (err) {
		log_error(lg, "Unable to update new "
			"flexhash for %s err=%d", out, err);
		return err;
	}
	return 0;
}

int
flexhash_init_from_table(struct flexhash *dtable, struct flexhash *stable)
{
	struct cl_node *node;
	int nr_nodes;

	int err = flexhash_get_nodes(stable, &node, &nr_nodes, FH_GOOD_HC);
	if (err) {
		log_error(lg, "Unable to initialize a new flexhash. get_nodes failed");
		return err;
	}

	struct cl_node *nodeptr;
	for (int i = 0; i < nr_nodes; i++) {
		nodeptr = &node[i];
		char serverstr[UINT128_STR_BYTES];
		uint128_dump(&nodeptr->serverid, serverstr, UINT128_STR_BYTES);
		err = flexhash_add_node(dtable, nodeptr);
		if (err < 0) {
			log_notice(lg, "Failed to add node : %s", serverstr);
			return err;
		}
	}

	replicast_free_repnodelist(node, nr_nodes);
	flexhash_copy_mcbase(dtable, stable);
	flexhash_set_genid(dtable, get_timestamp_us());
	return 0;
}

int
flexhash_checkpoint_file_stat()
{
	char *env_prefix = getenv("NEDGE_HOME");
	char filepath[PATH_MAX];
	struct stat st;

	if (env_prefix) {
		snprintf(filepath, PATH_MAX, "%s/var/run/%s-%s.%s",
		    env_prefix, FLEXHASH_LOGFILE, FLEXHASH_CHECKPOINT,
		    FLEXHASH_LOGFILE_EXTN);
	} else {
		snprintf(filepath, PATH_MAX, "%s/var/run/%s-%s.%s",
		    QUOTE(INSTALL_PREFIX), FLEXHASH_LOGFILE, FLEXHASH_CHECKPOINT,
		    FLEXHASH_LOGFILE_EXTN);
	}

	return stat(filepath, &st);
}

static int
flexhash_rm_fhserver(struct flexhash *fhtable, uint128_t *sid)
{
	struct fhserver *sptr = fhtable->serverlist;
	struct fhserver *psptr=NULL;
	for(; sptr; sptr=sptr->next) {
		if (uint128_cmp(&sptr->id, sid) == 0) {
			if (psptr == NULL) {
				fhtable->serverlist = sptr->next;
			} else {
				psptr->next = sptr->next;
			}
			dlist_free(&sptr->vdevlist);
			je_free(sptr);
			fhtable->servercount--;
			return 0;
		}
		psptr=sptr;
	}
	return -ENOENT;
}


void
set_unique_servercount(struct dlist *dl)
{
	uint128_t serveridlist[FLEXHASH_MAX_SERVERS];
	int servercount = 0;
	struct fhdev *fhdev = dl->devlist;
	while (fhdev != NULL) {
		struct lvdev *lvdev = fhdev->vdev;

		// count the distinct servers
		struct fhserver *fhserver = lvdev->server;
		int j = 0, found = 0;
		if (fhserver) {
			for (j = 0; j < servercount; j++) {
				if (uint128_cmp(&fhserver->id, &serveridlist[j]) == 0) {
					found = 1;
					break;
				}
			}
			if (!found) {
				serveridlist[servercount++] = fhserver->id;
			}
		}
		fhdev = fhdev->next;
	}
	dl->ngstat.servercount = servercount;

	servercount = 0;
	fhdev = dl->devlist;
	while (fhdev != NULL) {
		struct lvdev *lvdev = fhdev->vdev;
		if (lvdev->state != VDEV_STATE_ALIVE) {
			fhdev = fhdev->next;
			continue;
		}

		// count the alive servers
		struct fhserver *fhserver = lvdev->server;
		int j = 0, found = 0;
		if (fhserver) {
			for (j = 0; j < servercount; j++) {
				if (uint128_cmp(&fhserver->id, &serveridlist[j]) == 0) {
					found = 1;
					break;
				}
			}
			if (!found) {
				serveridlist[servercount++] = fhserver->id;
			}
		}
		fhdev = fhdev->next;
	}
	dl->ngstat.alive_servercount = servercount;
}

void
flexhash_init_rowstat(struct flexhash *fhtable)
{
	struct vdevstore *vds = fhtable->vdevstore;
	for (int i = 0; i < vds->lvdevcount; i++) {
		struct lvdev *vdev = &vds->lvdevlist[i];
		vdev->numrows = fhtable->numrows;
		vdev->activerows = 0;
		for (int row = 0; row < fhtable->numrows; row++) {
			if (flexhash_exists(fhtable, row, &vdev->vdevid)) {
				vdev->activerows++;
			}
		}
	}
	/* Update row server count */
	for (int row = 0; row < fhtable->numrows; row++) {
		set_unique_servercount(&fhtable->dl[row]);
		set_unique_zonecount(&fhtable->dl[row]);
	}
}

static void
flexhash_adjust_checkpoint(struct flexhash *nfhtable, struct flexhash *mnfhtable, int rmvdev)
{
	char vdevstr[UINT128_BYTES * 2 + 1];
	/* 1. remove devices from mnfh if not present anymore */
	struct vdevstore *mvds = mnfhtable->vdevstore;
	struct vdevstore *nvds = nfhtable->vdevstore;
_vdevloop:
	for (int i = 0; i < mvds->lvdevcount; i++) {
		struct lvdev *vdev = &mvds->lvdevlist[i];
		int found = vdevstore_getvdev_index_nl(nvds, &vdev->vdevid);
		if (found == -ENOENT) {
			uint128_dump(&vdev->vdevid, vdevstr, UINT128_BYTES * 2 + 1);
			int lvv = flexhash_leave(mnfhtable, &vdev->vdevid);
			if (lvv == 0) {
				int rmm = vdevstore_remove_vdev(mnfhtable, &vdev->vdevid);
				if (rmm == 0) {
					log_debug(lg, "Adjustment Removing %s ", vdevstr);
					goto _vdevloop;
				}
			}
		} else {
			/* adjust lvdev from discovered values */
			struct lvdev *nvdev = &nvds->lvdevlist[found];
			vdev->state = nvdev->state;
			vdev->size = nvdev->size;
			vdev->avail = nvdev->avail;
			vdev->activerows = nvdev->activerows;
			vdev->port = nvdev->port;
		}
	}
_iterate:;
	/* 2. adjust server count if not found in nfhtable remove it from mnfhtable */
	struct fhserver *msptr = mnfhtable->serverlist;
	struct fhserver *nsptr = nfhtable->serverlist;
	for (; msptr; msptr = msptr->next) {
		struct fhserver *itserver = flexhash_get_fhserver(nfhtable, &msptr->id);
		if (itserver == NULL) {
			flexhash_rm_fhserver(mnfhtable, &msptr->id);
			goto _iterate;
		}
		/* else, update vital server info */
		msptr->ipaddr = itserver->ipaddr;
		msptr->port = itserver->port;
		msptr->zone = itserver->zone;
		msptr->gateway = itserver->gateway;
	}

	/* 3. Recalculate zone count */
	flexhash_recalc_zonecount(mnfhtable);

	/* 4. update the row statistics */
	flexhash_init_rowstat(mnfhtable);
}

void
flexhash_rebuild_done(volatile struct flexhash **fhtable, int checkpoint_mode,
    int rmvdev, int skip_cp)
{
	struct flexhash *oldfh = (struct flexhash *) *fhtable;
	struct rebuild_ctx *rb_ctx = &(oldfh->rebuild_ctx);
	int err;
	log_info(lg, "FHRB: cp mode:%d skip_cp:%d", checkpoint_mode, skip_cp);
	int numdevices = flexhash_current_devicecount(rb_ctx->fhtable);

	int checkpoint_numdevices = numdevices;
	int fddelta_val;
	struct fddelta fddelta;

	err = flexhash_fddelta_checkpoint(oldfh, &fddelta_val, &fddelta);
	if (!err)
		checkpoint_numdevices = fddelta.prev_numdevices;

	struct flexhash *nfhtable = flexhash_table_create(checkpoint_numdevices,
	    FH_SERVER_SIDE);
	if (!nfhtable) {
		log_error(lg, "Unable to create a flexhash table ");
		return;
	}
	nfhtable->numdevices = numdevices;
	nfhtable->checkpoint_numdevices = checkpoint_numdevices;

	err = flexhash_init_from_table(nfhtable, rb_ctx->fhtable);
	if (err) {
		log_error(lg, "Failed to create a flexhash from a discovered table");
		flexhash_table_destroy(nfhtable);
		flexhash_table_destroy(rb_ctx->fhtable);
		return;
	}
	int skip_cp_fh = rb_ctx->fhtable->skip_cp;
	flexhash_table_destroy(rb_ctx->fhtable);
	nfhtable->skip_cp = 0;
	if (checkpoint_mode && !skip_cp_fh && !skip_cp) {
		log_info(lg, "Checkpoint file found , using it for rebuild");
		struct flexhash *mnfhtable = flexhash_read_checkpoint(NULL, 0);
		if (mnfhtable) {
			mnfhtable->checkpoint_numdevices =
				nfhtable->checkpoint_numdevices;
			flexhash_copy_mcbase(mnfhtable, nfhtable);
			flexhash_set_genid(mnfhtable, nfhtable->genid);

			// check servers and devices on the checkpoint vs ones discovered
			flexhash_adjust_checkpoint(nfhtable, mnfhtable, rmvdev);
			rb_ctx->fhtable = mnfhtable;
			flexhash_clear_stale(rb_ctx->fhtable);
		}
	} else {
		if (skip_cp_fh || skip_cp)
			log_info(lg, "Skipping checkpoint, rebuilding");
		else
			log_info(lg, "Checkpoint file not found, rebuilding");
		rb_ctx->fhtable = nfhtable;

		flexhash_mark_stale(rb_ctx->fhtable);
		/* rebalance the leader selected table */
		flexhash_rebalance(rb_ctx->fhtable);
		flexhash_clear_stale(rb_ctx->fhtable);
	}
	oldfh->rebuild_ctx.rebuild = 0;

	flexhash_set_fdmode(rb_ctx->fhtable);

	/* this is where the flexhash table is swapped */
	*fhtable = rb_ctx->fhtable;
	(*fhtable)->rebuild_ctx.rebuild = 0;

	log_info(lg, "Flexhash rebuild completed. genid: %ld numrows: %d",
	    flexhash_genid(*fhtable), rb_ctx->fhtable->numrows);

	if (checkpoint_mode && !skip_cp) {
		log_warn(lg, "discovered numdevices: %d checkpoint numdevices: %d",
		    flexhash_current_devicecount(nfhtable),
		    flexhash_current_devicecount(rb_ctx->fhtable));
		flexhash_table_destroy(nfhtable);
	}
	flexhash_dump(rb_ctx->fhtable, 0);
	if (oldfh)
		flexhash_table_destroy(oldfh);
}

int
flexhash_rebuild_start(volatile struct flexhash *fhtable, int nr_nodes, int known_vdevs)
{
	int err = 0;
	log_info(lg, "Flexhash rebuild started nr_nodes: %d known_vdevs: %d",
	    nr_nodes, known_vdevs);
	flexhash_set_rebuild_in_progress(fhtable);

	fhtable->rebuild_ctx.rebuild = 1;
	fhtable->rebuild_ctx.expected_nr_nodes = nr_nodes;

	/* new temp device only flexhash */
	int numdevices = flexhash_current_devicecount(fhtable);
	if (known_vdevs > numdevices)
		numdevices = known_vdevs;
	/* for the case when rt-lfs is empty in the gateway */
	if (numdevices == 0)
		numdevices = FLEXHASH_BOOTUP_VDEVS;

	fhtable->rebuild_ctx.fhtable = flexhash_table_create(numdevices, FH_SERVER_SIDE);
	if (!fhtable->rebuild_ctx.fhtable) {
		log_error(lg, "Unable to create flexhash");
		flexhash_clear_stale(fhtable);
		return -ENOMEM;
	}
	flexhash_copy_mcbase(fhtable->rebuild_ctx.fhtable, fhtable);

	/* set a proper genid here */
	flexhash_set_genid(fhtable->rebuild_ctx.fhtable, get_timestamp_us());

	return err;
}

int
flexhash_rebuild_inprogress(volatile struct flexhash *fhtable)
{
	return fhtable->rebuild_ctx.rebuild;
}

void
flexhash_hashcount_init(struct cl_node *node)
{
	for (int i=0; i < (int) node->nr_vdevs; i++) {
		struct cl_vdev *vdevptr = &node->vdevs[i];
		char vdevstr[UINT128_STR_BYTES];
		uint128_dump(&vdevptr->vdevid, vdevstr, UINT128_STR_BYTES);
		log_debug(lg, "vdev: %s activerows: %d", vdevstr,
					vdevptr->activerows);
		if (vdevptr->activerows == 0) {
			flexhash_sumsquares_seeded(&vdevptr->vdevid,
				&vdevptr->hashcount[0], FLEXHASH_MAX_TAB_LENGTH);
			vdevptr->numrows = FLEXHASH_MAX_TAB_LENGTH;
		}
	}
}

void
flexhash_set_fhready(volatile struct flexhash *fhtable)
{
	fhtable->fh_ready = 1;
}

int
flexhash_is_fhready(int mode, void *ctx)
{
	switch (mode) {
		case FH_GENID_CLIENT:
		{
			struct ccow *tc = (struct ccow *) ctx;
			return tc->flexhash->fh_ready;
			break;
		}
		case FH_GENID_SERVER:
		{
			struct ccowd *ccow_daemon = (struct ccowd *) ctx;
			return ccow_daemon->flexhash->fh_ready;
			break;
		}
		default:
			assert(0);
			break;
	}
}

void
flexhash_distribution(volatile struct flexhash *fhtable)
{
	struct flexhash *fh = (struct flexhash *)fhtable;
	int numdev = fhtable->vdevstore->lvdevcount;
	int numrows = fhtable->numrows;

	log_debug(lg, "Flexhash distribution genid: %lu devices: %d rows: %d"
	    " servers: %d zones: %d devsperrow: %d", fhtable->genid, numdev,
	    numrows, fhtable->servercount, fhtable->zonecount, fhtable->devsperrow);

	log_debug(lg, "Server distribution spr: %d", flexhash_spr(fh));
	struct fhserver *fhserver = fhtable->serverlist;
	char str[UINT128_STR_BYTES];
	for (; fhserver; fhserver = fhserver->next) {
		uint128_dump(&fhserver->id, str, UINT128_STR_BYTES);
		log_debug(lg, "ServerID: %s rows: %d rowusage: %.2f",
		    str, fhserver->rcount->count, fhserver->rcount->rowusage);
		for (int row = 0; row < fhtable->numrows; row++) {
			struct dlist *dl = &fhtable->dl[row];
			int n = fhserver->rcount->hashcount[row];
			if (!n)
				continue;
			int contrib = (n * 100 ) / dl->numdevs;
			log_debug(lg, "row: %d devices: %d total: %d "
			    "contribution: %d %%", row, n, dl->numdevs,
			    contrib);
		}
	}

	log_debug(lg, "Device distribution");
	for (int i = 0; i < fhtable->vdevstore->lvdevcount; i++) {
		struct lvdev *lvdev = &fhtable->vdevstore->lvdevlist[i];
		uint128_dump(&lvdev->vdevid, str, UINT128_STR_BYTES);
		log_debug(lg, "DeviceID: %s rows %d active: %d rowusage: %.2f deltarows: %d "
		    "spaceusage: %.2f", str, lvdev->rcount->count, lvdev->activerows,
		    lvdev->rcount->rowusage, lvdev->rcount->deltarows,
		    lvdev->rcount->spaceusage);

		char present[2048], rowstr[10];
		present[0] = 0;
		for (int row = 0; row < fhtable->numrows; row++) {
			if (lvdev->rcount->hashcount[row]) {
				snprintf(rowstr, sizeof(rowstr), "%d ", row);
				strcat(present, rowstr);
			}
		}

		log_debug(lg, "rows served: %s", present);
	}

    if (fhtable->fdmode == FD_ZONE) {
        log_info(lg, "Device per zone distribution");
        for (int z = 1; z <= fhtable->zonecount; z++) {
            log_info(lg, "Zone: %d", z);
            int dev_index = 0;
            for (int i = 0; i < fhtable->vdevstore->lvdevcount; i++) {
                struct lvdev *lvdev = &fhtable->vdevstore->lvdevlist[i];
                if ((int)lvdev->server->zone != z)
                    continue;
                uint128_dump(&lvdev->vdevid, str, UINT128_STR_BYTES);
                log_info(lg, "    %s ", str);

                char present[2048], rowstr[10];
                present[0] = 0;
                int nrow = 0;
                for (int row = 0; row < fhtable->numrows; row++) {
                    if (lvdev->rcount->hashcount[row]) {
                        snprintf(rowstr, sizeof(rowstr), "%d ", row);
                        strcat(present, rowstr);
                        nrow++;
                        dev_index++;
                    }
                }
                log_info(lg, "    %d rows: %s", nrow, present);
            }
            log_info(lg, "    index: %d", dev_index);
        }
    } else {
        struct fhserver *fhserver = fhtable->serverlist;
        char strid[UINT128_STR_BYTES];
        for (; fhserver; fhserver = fhserver->next) {
            uint128_dump(&fhserver->id, strid, UINT128_STR_BYTES);
            log_info(lg, "serverID: %s", strid);
            int dev_index = 0;
            for (int i = 0; i < fhtable->vdevstore->lvdevcount; i++) {
                struct lvdev *lvdev = &fhtable->vdevstore->lvdevlist[i];
                if (uint128_cmp(&fhserver->id, &lvdev->server->id) != 0)
                    continue;
                uint128_dump(&lvdev->vdevid, str, UINT128_STR_BYTES);
                log_info(lg, "    %s ", str);

                char present[2048], rowstr[10];
                present[0] = 0;
                int nrow = 0;
                for (int row = 0; row < fhtable->numrows; row++) {
                    if (lvdev->rcount->hashcount[row]) {
                        snprintf(rowstr, sizeof(rowstr), "%d ", row);
                        strcat(present, rowstr);
                        nrow++;
                        dev_index++;
                    }
                }
                log_info(lg, "    %d rows: %s", nrow, present);
            }
            log_info(lg, "    index: %d", dev_index);
        }
    }


	log_debug(lg, "Row distribution");
	for (int row = 0; row < fhtable->numrows; row++) {
		struct dlist *dl = &fhtable->dl[row];
		log_debug(lg, "row: %d servers: %d zones: %d devices: %d "
		    "deltadevs: %d", row, dl->ngstat.servercount,
		    dl->ngstat.zonecount, dl->numdevs, dl->deltadevs);
	}
}

int
compare_avail (const void *val1, const void *val2)
{
	uint64_t a = *(uint64_t *)val1;
	uint64_t b = *(uint64_t *)val2;

	return a < b ? -1 : a > b ? 1 : 0;
}

static void
flexhash_calc_row_median(struct dlist *dl)
{
	uint64_t data_set[dl->numdevs];
	struct fhdev *dev = dl->devlist;
	int count = 0;

	/* Get the available space for each disk */
	while (dev != NULL) {
		data_set[count++] = dev->vdev->avail;
		dev = dev->next;
		assert(count <= dl->numdevs);
	}

	/* Sort the available space */
	qsort(data_set, dl->numdevs, sizeof(uint64_t), compare_avail);

	/* Return the median */
	count = dl->numdevs / 2;
	dl->avail_median =  dl->numdevs % 2 ? data_set[count] :
			    (data_set[count] + data_set[count - 1])/2;
}

uint128_t *
get_hilo_median_candidate(struct dlist *dl, int hi)
{
	struct fhdev *dev = dl->devlist;
	struct lvdev *selected = NULL;

	uint64_t limit = dl->avail_median;

	while (dev != NULL) {
		if (hi) {
			/* Highest usage device */
			if (dev->vdev->avail < limit) {
				limit = dev->vdev->avail;
				selected = dev->vdev;
			}
		} else {
			/* Lowest usage device */
			if (dev->vdev->avail > limit) {
				limit = dev->vdev->avail;
				selected = dev->vdev;
			}
		}
		dev = dev->next;
	}
	return selected ? &selected->vdevid : NULL;
}

/* Caller should free the buffer */
char*
flexhash_get_median_candidates_json(volatile struct flexhash *fhtable)
{
	char *buf;
	unsigned buf_idx = 0;
	uint128_t *hid = NULL, *lod = NULL;
	struct dlist *dl = NULL;

	buf = je_calloc(1, MAX_EVAC_MSG);
	if (!buf)
		return buf;

	buf_idx += snprintf(buf, MAX_EVAC_MSG, "[\n");
	for (int i = 0; i < fhtable->numrows; i++) {
		buf_idx += snprintf(buf + buf_idx, MAX_EVAC_MSG - buf_idx,
				"\t{\n\t\t\"row\": %d,\n", i);
		dl = &fhtable->dl[i];
		flexhash_calc_row_median(dl);
		if (dl->avail_median) {
			buf_idx += snprintf(buf + buf_idx, MAX_EVAC_MSG - buf_idx,
					"\t\t\"median\": %"PRIu64",\n",
					dl->avail_median);
			hid = get_hilo_median_candidate(dl, 1);
			lod = get_hilo_median_candidate(dl, 0);
			char svdevstr[64];
			char dvdevstr[64];
			if (hid) {
				uint128_dump(hid, svdevstr, 64);
			} else {
				sprintf(svdevstr, "None,");
			}
			if (lod) {
				uint128_dump(lod, dvdevstr, 64);
			} else {
				sprintf(dvdevstr, "None");
			}
			buf_idx += snprintf(buf + buf_idx, MAX_EVAC_MSG - buf_idx,
					"\t\t\"sdev\": \"%s\",\n", svdevstr);
			buf_idx += snprintf(buf + buf_idx, MAX_EVAC_MSG - buf_idx,
					"\t\t\"tdev\": \"%s\"\n", dvdevstr);
		} else {
			buf_idx += snprintf(buf + buf_idx, MAX_EVAC_MSG - buf_idx,
					"\t\t\"median\": %"PRIu64",\n",
					dl->avail_median);
			buf_idx += snprintf(buf + buf_idx, MAX_EVAC_MSG - buf_idx,
					"\t\t\"sdev\": \"None\",\n");
			buf_idx += snprintf(buf + buf_idx, MAX_EVAC_MSG - buf_idx,
					"\t\t\"tdev\": \"None\"\n");
		}
		if (i != fhtable->numrows - 1)
			buf_idx += snprintf(buf + buf_idx, MAX_EVAC_MSG - buf_idx,
					"\t},\n");
		else
			buf_idx += snprintf(buf + buf_idx, MAX_EVAC_MSG - buf_idx,
					"\t}\n");
	}
	buf_idx += snprintf(buf + buf_idx, MAX_EVAC_MSG - buf_idx,
			"]\n");
	return buf;
}

/* Caller should free the buffer */
char *
flexhash_get_row_median_json(volatile struct flexhash *fhtable)
{
	char *buf;
	unsigned buf_idx = 0;
	unsigned const buf_size = 64 * (fhtable->numrows + 1);

	/*
	 * Each row will have approximately 40 - 50 characters
	 * We take additional row to add the message and top JSON name.
	 */
	buf = je_calloc(1, buf_size);
	if (!buf)
		return buf;

	buf_idx += snprintf(buf, buf_size, "FH_ROW_UPDATE:{\n\t\"row_medians\": [\n");
	for (int i = 0; i < fhtable->numrows; i++) {
		flexhash_calc_row_median(&fhtable->dl[i]);
		if (i != fhtable->numrows - 1)
			buf_idx += snprintf(buf + buf_idx, buf_size - buf_idx,
					"\t{ \"median_avail\" : %" PRIu64 " },\n",
					fhtable->dl[i].avail_median);
		else
			buf_idx += snprintf(buf + buf_idx, buf_size - buf_idx,
					"\t{ \"median_avail\" : %" PRIu64 " }\n",
					fhtable->dl[i].avail_median);
	}
	buf_idx += snprintf(buf + buf_idx, buf_size - buf_idx, "\t]\n}\n");
	return buf;
}

void
local_flexhash_row_update(volatile struct flexhash *fhtable, char *json_str)
{
	json_value *opts, *medians = NULL;
	size_t i, j;
	int rows;

	opts = json_parse(json_str, strlen(json_str));
	if (!opts || opts->type != json_object) {
		if (opts)
			json_value_free(opts);
		log_notice(lg, "Invalid row update message");
		return;
	}

	for (i = 0; i < opts->u.object.length; i++) {
		if (strcmp(opts->u.object.values[i].name, "row_medians") == 0)
			medians = opts->u.object.values[i].value;
		else
			assert(0);
	}

	rows = (int)medians->u.array.length;
	if ( rows != fhtable->numrows )
		goto end_median_update;

	assert(rows == fhtable->numrows);

	for (j = 0; j < medians->u.array.length; j++) {

		json_value *med = medians->u.array.values[j];
		if (med->type != json_object) {
			log_debug(lg, "Invalid json entry");
			continue;
		}

		/* We expect only a single value */
		char *namekey = med->u.object.values[0].name;
		json_value *v = med->u.object.values[0].value;

		if (strcmp(namekey, "median_avail") == 0) {
			if (v->type != json_integer)
				log_warn(lg, "Invalid row median value");
			else
				fhtable->dl[j].avail_median = v->u.integer;
		} else
			log_warn(lg, "Invalid row attribute");
	}
end_median_update:
	json_value_free(opts);
}

void
flexhash_lock(volatile struct flexhash *fhtable)
{
	uv_mutex_lock((uv_mutex_t *) &fhtable->mutex);
}

void
flexhash_unlock(volatile struct flexhash *fhtable)
{
	uv_mutex_unlock((uv_mutex_t *) &fhtable->mutex);
}


void flexhash_set_leader(volatile struct flexhash *fhtable)
{
	fhtable->leader=1;
}

id_rowdata_t *
allocate_idrowdata(int rowcount, int idx, int idx_val)
{
	id_rowdata_t *idd = je_calloc(1, sizeof(id_rowdata_t));
	if (!idd) {
		log_error(lg, "Unable to allocate memory");
		return NULL;
	}
	idd->rowcount = rowcount;
	idd->rows = je_calloc(rowcount, sizeof(int));
	idd->rows[idx] = idx_val;
	return idd;
}

void
free_idrowdata(id_rowdata_t *idd)
{
	je_free(idd->rows);
	je_free(idd);
}

static void
flexhash_assign_list(struct flexhash *fhtable, hashtable_t *assign_list,
			struct lvdev *lvdev, fhrow_t row, int is_src)
{
#if 0
	struct fhdev *fhdev = je_calloc(1, sizeof(struct fhdev));
	fhdev->vdev = lvdev;
#endif

	int err;
	size_t sz;

	id_rowdata_t *idd = (id_rowdata_t *) hashtable_get(assign_list,
							   &lvdev->vdevid,
							   sizeof (uint128_t), &sz);
	if (!idd) {
		idd = allocate_idrowdata(fhtable->numrows, row, 1);
		idd->fdmode = fhtable->fdmode;
		idd->zone = lvdev->server->zone;
		idd->srvid = lvdev->server->id;
		err = hashtable_put(assign_list, &lvdev->vdevid, sizeof(uint128_t),
					idd, sizeof(id_rowdata_t));
		if (err < 0) {
			char vdevstr[64];
			uint128_dump(&lvdev->vdevid, vdevstr, 64);
			je_free(idd);
			log_error(lg, "Unable to put VDEV: %s into the hashtable",
					vdevstr);
			return;
		}
	} else {
		if (is_src)
			idd->rows[row] += 1;
		else
			idd->rows[row] -= 1;
	}
}

void
flexhash_free_list(hashtable_t *hlist)
{
	unsigned int kcount;
	uint128_t **vidl = (uint128_t **) hashtable_keys(hlist, &kcount);

	for (unsigned int i = 0; i < kcount; i++) {
		uint128_t *vdevid = vidl[i];
		size_t sz;
		id_rowdata_t *idd = (id_rowdata_t *) hashtable_get(hlist, vdevid,
								   sizeof (uint128_t),
								   &sz);
		if (idd)
			free_idrowdata(idd);
	}
}

void
flexhash_evac(enum evac_policy policy, struct flexhash *fh,
		int rowsperdev, revac_candidate_cb_t evac_cb)
{
	if (policy < EVAC_ROW_PARTICIPATION || policy >= EVAC_END) {
		log_error(lg, "Invalid evacuation policy %d", policy);
		return;
	}
	if (evac_policies[policy])
		evac_policies[policy](fh, rowsperdev, evac_cb);
	else
		log_error(lg, "Policy for (%d) not implemented", policy);
}

static void
flexhash_rowevac_list(struct flexhash *fhtable, int rowsperdev,
			revac_candidate_cb_t revac)
{
	uint16_t src_devs = 0, tgt_devs = 0;
	fhrebalance_setdevice_hashcount(fhtable);

	int maxcount = fhtable->vdevstore->lvdevcount;
	hashtable_t *vdev_src_list = hashtable_create(maxcount, 0, 0.05);
	hashtable_t *vdev_tgt_list = hashtable_create(maxcount, 0, 0.05);

	if (!vdev_src_list || !vdev_tgt_list) {
		log_debug(lg, "Unable to allocate memory");
		if (vdev_src_list)
			hashtable_destroy(vdev_src_list);
		if (vdev_tgt_list)
			hashtable_destroy(vdev_tgt_list);
		return;
	}

	for (fhrow_t row = 0; row < fhtable->numrows; row++) {

		struct dlist *rowdl = &fhtable->dl[row];
		struct fhdev *fhdevptr = rowdl->devlist;

		while (fhdevptr) {
			struct lvdev *lvdev = fhdevptr->vdev;
			if (lvdev->rcount) {
				if (lvdev->rcount->count > rowsperdev &&
					lvdev->rcount->hashcount[row] == 1) {
				/* This device is overcommited. Choose it as source */
					flexhash_assign_list(fhtable, vdev_src_list,
								lvdev, row, 1);
					src_devs++;
					lvdev->rcount->count--;
				} else if (lvdev->rcount->count < rowsperdev &&
					lvdev->rcount->hashcount[row] == 1) {
				/* This device is undercommited. Choose it as target */
					flexhash_assign_list(fhtable, vdev_tgt_list,
								lvdev, row, 0);
					lvdev->rcount->count++;
					tgt_devs++;
				}
			}
			fhdevptr = fhdevptr->next;
		}
	}

	/* Call the callback */
	if (src_devs && tgt_devs)
		revac(rowsperdev, vdev_src_list, vdev_tgt_list);
	else
		log_warn(lg, "rows_per_device: %d  devices_greater: %d"
				" devices_less: %d", rowsperdev, src_devs, tgt_devs);


	flexhash_free_list(vdev_src_list);
	flexhash_free_list(vdev_tgt_list);

	fhrebalance_free_rcount(fhtable);
}

int
flexhash_row_zonecount(volatile struct flexhash *fhtable, fhrow_t row)
{
	if (row > fhtable->numrows)
		return -1;

	struct ngstat *ngstat = &fhtable->dl[row].ngstat;
	if (!ngstat)
		return -1;

	return ngstat->alive_zonecount;
}

int
flexhash_row_servercount(volatile struct flexhash *fhtable, fhrow_t row)
{
	if (row > fhtable->numrows)
		return -1;

	struct ngstat *ngstat = &fhtable->dl[row].ngstat;
	if (!ngstat)
		return -1;

	return ngstat->alive_servercount;
}
