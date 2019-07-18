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
/*
 * kvslmdb-backend.c
 *
 *  Created on: May 28, 2018
 *      Author: root
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <assert.h>
#include <fcntl.h>
#include <kvs-backend.h>
#include <lmdb.h>

struct kvslmdb_handle {
	int term;
	const char* path;
	MDB_env* env;
	MDB_dbi dbi;
	json_value *opts;
	size_t capacity;
};

#define LMDB_FS_RESERVED_BLOCKS 5
#define LMDB_MAXREADERS         512

typedef struct kvslmdb_handle* kvslmdb_handle_t;

static int
kvslmdb_lmdb_oomfunc(MDB_env *env, int pid, void* thread_id, size_t txn, unsigned gap,
    int retry)
{
	log_notice(lg, "Detected laggard reader PID=%d TID=%p TXN=%lu GAP=%u retry=%d",
	    pid, thread_id, txn, gap, retry);
	return 0;
}

static int
kvslmdb_init_internal(kvslmdb_handle_t h) {
	json_value* o = h->opts;
	int sync = 1;
	int readahead = 128;
	int direct = 0;
	int err = 0;
	char fname[PATH_MAX];
	MDB_txn* main_txn = NULL;
	if (o) {
		for (size_t i = 0; i < o->u.object.length; i++) {
			char *namekey = o->u.object.values[i].name;
			json_value *v = o->u.object.values[i].value;
			if (strcmp(namekey, "sync") == 0) {
				if (v->type != json_integer) {
					log_error(lg, "rt-kvs.json error: \"sync\" option must be integer");
					continue;
				}
				sync = v->u.integer;
			} else if (strcmp(namekey, "readahead") == 0) {
				if (v->type != json_integer) {
					log_error(lg, "rt-kvs.json error: \"readahead\" option must be integer");
					continue;
				}
				readahead = v->u.integer;
			} else if (strcmp(namekey, "direct") == 0) {
				if (v->type != json_integer) {
					log_error(lg, "rt-kvs.json error: \"direct\" option must be integer");
					continue;
				}
				direct = v->u.integer;
			}
		}
	}
	/*
	 *  key/value data store init
	 */
	err = mdb_env_create(&h->env);
	if (err) {
		log_error(lg, "Dev(%s): cannot create mdb env: (%d) %s",
			h->path, err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	mdb_env_set_mapsize(h->env, h->capacity);

	mdb_env_set_maxreaders(h->env, LMDB_MAXREADERS);

	err = mdb_env_set_maxdbs(h->env, 1);
	if (err) {
		log_error(lg, "Dev(%s): cannot set maxdbs: (%d) %s",
			h->path, err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	mdb_env_set_oomfunc(h->env, kvslmdb_lmdb_oomfunc);

	int sync_flag = sync == 0 ? MDB_NOSYNC :
		(sync == 1 ? (direct ? MDB_NOSYNC : MDB_NOMETASYNC) :
		 (sync == 2 ? MDB_NOMETASYNC : 0));
	int rdahead_flag = readahead ? 0 : MDB_NORDAHEAD;
	int direct_flag = direct ? MDB_DIRECT : 0;
	int env_opt = MDB_COALESCE | MDB_LIFORECLAIM | MDB_NOTLS | sync_flag \
		      | MDB_NOSUBDIR | rdahead_flag | direct_flag;

	sprintf(fname, "rm -f %s/parts/%02x/main.mdb-lock", h->path, 0);
	err = system(fname);
	sprintf(fname, "mkdir -p %s/parts/%02x/", h->path, 0);
	err = system(fname);
	sprintf(fname, "%s/parts/%02x/main.mdb", h->path, 0);
	err = mdb_env_open(h->env, fname, env_opt, 0664);
	if (err) {
		log_error(lg, "Dev(%s): cannot open, path=%s "
		    "mdb env: (%d) %s", h->path, fname,
		    err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	/*
	 * Initialize/Open main data store now
	 */
	err = mdb_txn_begin(h->env, NULL, 0, &main_txn);
	if (err) {
		log_error(lg, "Dev(%s): cannot begin mdb txn: (%d) %s",
			h->path, err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	err = mdb_dbi_open(main_txn, "main", MDB_CREATE, &h->dbi);
	if (err) {
		log_error(lg, "Dev(%s): cannot open mdb: (%d) %s",
		    h->path, err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	err = mdb_txn_commit(main_txn);
	if (err) {
		log_error(lg, "Dev(%s): cannot commit to mdb: (%d) %s",
		    h->path, err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}
	main_txn = NULL;
	mdb_env_sync(h->env, 1);
	err = 0;

_exit:
	if (main_txn)
		mdb_txn_abort(main_txn);
	if (err && h->env)
		mdb_env_close(h->env);
	return err;
}


static int
kvslmdb_init(const char* path, json_value *o, kvs_backend_handle_t* handle) {
	struct stat st;
	struct statvfs vstat;
	char fname[1024];

	if (!path || !strlen(path)) {
		log_error(lg, "Directory path is void");
		return -ENOENT;
	}

	int err = stat(path, &st);
	if (err && err != ENOENT)
		return -err;
	if (!err) {
		if (!S_ISDIR(st.st_mode)) {
			log_error(lg, "Specified path %s isn't a directory", path);
			return -EINVAL;
		}
	} else {
		/* Folder doesn't exist, trying to create */
		err = mkdir(path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
		if (err) {
			log_error(lg, "Cannot create storage folder: %s(%d)", strerror(err), err);
			return -err;
		}
	}

	err = statvfs(path, &vstat);
	if (err) {
		log_error(lg, "statvfs error: %s(%d)", strerror(err), err);
		return -err;
	}

	kvslmdb_handle_t h = calloc(1, sizeof(*h));
	if (!h)
		return -ENOMEM;
	h->path = strdup(path);
	size_t capacity =  vstat.f_bsize * vstat.f_blocks;
	h->capacity = capacity - LMDB_FS_RESERVED_BLOCKS*capacity/100;
	h->term = 0;
	h->env = NULL;
	h->opts = o;
	err = kvslmdb_init_internal(h);
	if (!err)
		*handle = h;
	return err;
}

static int
kvslmdb_compose_key(int8_t ttag, iobuf_t key, iobuf_t* key_out) {
	uint8_t hdr[2] = {0};
	hdr[0] = ttag;
	char* new_key = malloc(key.len+2);
	if (!new_key)
		return -ENOMEM;
	new_key[0] = hdr[0];
	new_key[1] = hdr[1];
	memcpy(new_key+sizeof(hdr), key.base, key.len);
	key_out->base = new_key;
	key_out->len = key.len + sizeof(hdr);
	return 0;
}

static int
kvslmdb_get(kvs_backend_handle_t handle, int8_t ttag, iobuf_t key,
	iobuf_t* value) {
	kvslmdb_handle_t h = handle;
	if (h->term)
		return -ENODEV;
	iobuf_t full_key;
	MDB_txn* txn;

	int err = kvslmdb_compose_key(ttag, key, &full_key);
	assert(err == 0);
	err = mdb_txn_begin(h->env, NULL, MDB_RDONLY, &txn);
	if (err) {
		log_error(lg, "Dev(%s): cannot begin mdb txn: (%d) %s",
			h->path, err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}
	MDB_val k = {.mv_data = full_key.base, .mv_size = full_key.len };
	MDB_val v = { .mv_data = NULL, .mv_size = 0 };
	err = mdb_get(txn, h->dbi, &k, &v);
	if (err) {
		log_error(lg, "Dev(%s): cannot mdb_get: (%d) %s",
			h->path, err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}
	assert(v.mv_size);
	assert(v.mv_size <= value->len);
	memcpy(value->base, v.mv_data, v.mv_size);
	err = 0;

_exit:
	mdb_txn_abort(txn);
	return err;
}

static int
kvslmdb_put(kvs_backend_handle_t handle, int8_t ttag, iobuf_t* keys,
	iobuf_t* values, size_t n_entries) {

	kvslmdb_handle_t h = handle;
	if (h->term)
		return -ENODEV;
	iobuf_t full_key;
	MDB_txn* txn;

	int err = mdb_txn_begin(h->env, NULL, 0, &txn);
	if (err) {
		log_error(lg, "Dev(%s): cannot begin mdb txn: (%d) %s",
			h->path, err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	for (size_t i = 0; i < n_entries; i++) {
		int err = kvslmdb_compose_key(ttag, keys[i], &full_key);
		assert(err == 0);
		MDB_val k = {.mv_data = full_key.base, .mv_size = full_key.len };
		MDB_val v = { .mv_data = NULL, .mv_size = values[i].len };
		err = mdb_put(txn, h->dbi, &k, &v, MDB_RESERVE);
		if (err) {
			log_error(lg, "Dev(%s): cannot begin mdb_put txn: (%d) %s",
				h->path, err, mdb_strerror(err));
			err = -EIO;
			break;
		} else
			memcpy(v.mv_data, values[i].base, values[i].len);
	}

_exit:
	if (!err) {
		err = mdb_txn_commit(txn);
		if (err) {
			log_error(lg, "Dev(%s): cannot mdb_txn_commit: (%d) %s",
				h->path, err, mdb_strerror(err));
			err = -EIO;
		}
	} else {
		mdb_txn_abort(txn);
	}
	return err;
}

static int
kvslmdb_delete(kvs_backend_handle_t handle, int8_t ttag, iobuf_t* keys, size_t n_entries) {
	kvslmdb_handle_t h = handle;
	if (h->term)
		return -ENODEV;
	iobuf_t full_key;
	MDB_txn* txn;

	int err = mdb_txn_begin(h->env, NULL, 0, &txn);
	if (err) {
		log_error(lg, "Dev(%s): cannot begin mdb txn: (%d) %s",
			h->path, err, mdb_strerror(err));
		err = -EIO;
		goto _exit;
	}

	for (size_t i = 0; i < n_entries; i++) {
		int err = kvslmdb_compose_key(ttag, keys[i], &full_key);
		assert(err == 0);
		MDB_val k = {.mv_data = full_key.base, .mv_size = full_key.len };
		err = mdb_del(txn, h->dbi, &k, NULL);
		if (err) {
			log_error(lg, "Dev(%s): cannot begin mdb_del txn: (%d) %s",
				h->path, err, mdb_strerror(err));
			err = -EIO;
			break;
		}
	}

_exit:
	if (!err) {
		err = mdb_txn_commit(txn);
		if (err) {
			log_error(lg, "Dev(%s): cannot mdb_txn_commit: (%d) %s",
				h->path, err, mdb_strerror(err));
			err = -EIO;
		}
	} else {
		mdb_txn_abort(txn);
	}
	return err;
}

static void
kvslmdb_exit(kvs_backend_handle_t handle) {
	kvslmdb_handle_t h = handle;
	if (h->term)
		return;
	h->term = 1;
	if (h->env) {
		mdb_dbi_close(h->env, h->dbi);
		mdb_env_close(h->env);
	}
	free(h);
}

static int
kvslmdb_info(kvs_backend_handle_t handle, kvs_backend_info_t* info) {
	kvslmdb_handle_t h = handle;
	if (h->term)
		return -ENODEV;
	MDB_envinfo env_stat;
	int err = mdb_env_info(h->env, &env_stat);
	if (err) {
		log_error(lg, "Dev(%s): cannot mdb_env_info: (%d) %s",
			h->path, err, mdb_strerror(err));
		return -EIO;
	}
	info->capacity = env_stat.me_mapsize;
	info->min_value_size = 1;
	info->del_bulk_size = 1024;
	info->put_bulk_size = 1024;
	return 0;
}

static int
kvslmdb_erase(kvs_backend_handle_t handle) {
	kvslmdb_handle_t h = handle;
	char cmd[PATH_MAX];
	if (h->term)
		return -ENODEV;
	mdb_dbi_close(h->env, h->dbi);
	mdb_env_close(h->env);
	h->env = NULL;
	sprintf(cmd, "find %s -name \"*\" -exec sh -c 'rm -rf $1 > /dev/null 2>&1' -- {} \\;", h->path);
	int err = system(cmd);
	return err;
}

kvs_backend_t kvslmdb_vtbl = {
	.name = "kvslmdb",
	.init = kvslmdb_init,
	.info = kvslmdb_info,
	.exit = kvslmdb_exit,
	.get = kvslmdb_get,
	.put = kvslmdb_put,
	.remove = kvslmdb_delete,
	.erase = kvslmdb_erase
};

