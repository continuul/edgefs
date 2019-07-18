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
 * dbi_delete.c
 *
 *  Created on: Jun 15, 2018
 *      Author: root
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lmdb.h>
#include <errno.h>

int main (int argc, char** argv) {
	if (argc != 4) {
		printf("Usage: dbi_delete <env_path> <DBI name> <num_entries_to_delete>");
		exit(0);
	}
	const char* env_path = argv[1];
	const char* dbi_name = argv[2];
	int num_del = strtol(argv[3], NULL, 10);
	if (num_del < 0 && errno) {
		fprintf(stderr, "Number of entries has a wrong fromat\n");
		exit(-1);
	}

	MDB_env* env = NULL;
	MDB_txn* txn = NULL;
	MDB_dbi dbi = 0;
	MDB_cursor* cur = NULL;

	/*
	 * Main key/value data store
	 */
	int err = mdb_env_create(&env);
	if (err) {
		fprintf(stderr, "Cannot create an MDB env: %d (%s)\n", err,
			mdb_strerror(err));
		exit(-1);
	}

	mdb_env_set_maxreaders(env, 512);

	err = mdb_env_set_maxdbs(env, 256);
	if (err) {
		fprintf(stderr, "Cannot mdb_env_set_maxdbs: %d (%s)\n", err, mdb_strerror(err));
		exit(-1);
	}
	unsigned int env_opt = MDB_COALESCE | MDB_LIFORECLAIM | MDB_RAW | MDB_NOTLS \
		| MDB_NOSUBDIR;

	err = mdb_env_open(env, env_path, env_opt, 0664);
	if (err) {
		fprintf(stderr, "Cannot mdb_env_open: %d (%s)\n", err, mdb_strerror(err));
		exit(-1);
	}

	err = mdb_txn_begin(env, NULL, 0, &txn);
	if (err) {
		fprintf(stderr, "Cannot mdb_txn_begin: %d (%s)\n", err, mdb_strerror(err));
		mdb_env_close(env);
		exit(-1);
	}

	err = mdb_dbi_open(txn, dbi_name, 0, &dbi);
	if (err) {
		mdb_txn_abort(txn);
		mdb_env_close(env);
		fprintf(stderr, "Cannot mdb_dbi_open for DBI %s: %d (%s)\n", dbi_name, err, mdb_strerror(err));
		exit(-1);
	}

	if (num_del == 0) {
		err = mdb_drop(txn, dbi, 1);
		if (err) {
			mdb_txn_abort(txn);
			fprintf(stderr, "Cannot dbi_drop for DBI %s: %d (%s)\n", dbi_name, err, mdb_strerror(err));
		} else {
			err = mdb_txn_commit(txn);
			if (err)
				fprintf(stderr, "Cannot mdb_txn_commit on dbi_drop for DBI %s: %d (%s)\n", dbi_name, err, mdb_strerror(err));
		}
		mdb_dbi_close(env, dbi);
		mdb_env_close(env);
		exit(err);
	}
	err = mdb_cursor_open(txn, dbi, &cur);
	if (err) {
		mdb_txn_abort(txn);
		mdb_dbi_close(env, dbi);
		mdb_env_close(env);
		fprintf(stderr, "Cannot mdb_cursor_open for DBI %s: %d (%s)\n", dbi_name, err, mdb_strerror(err));
		exit(-1);
	}

	int op = MDB_FIRST;
	MDB_val key, data, pdata;
	size_t n_puts = 0;
	while ((err = mdb_cursor_get(cur, &key, &data, op)) == 0 && --num_del >= 0) {
		op = MDB_NEXT;
		err = mdb_cursor_del(cur, 0);
		if (err) {
			fprintf(stderr, "Error deleting cursor entry: %d (%s)",
				err, mdb_strerror(err));
			mdb_txn_abort(txn);
			mdb_dbi_close(env, dbi);
			mdb_env_close(env);
			exit(-1);
		}
	}
	if (err && err != MDB_NOTFOUND) {
		fprintf(stderr, "mdb_cursor_get returned %d (%s)\n", err, mdb_strerror(err));
		mdb_txn_abort(txn);
		mdb_dbi_close(env, dbi);
		mdb_env_close(env);
		exit(-1);
	}

	err = mdb_txn_commit(txn);
	if (err) {
		fprintf(stderr, "mdb_txn_commit returned %d (%s)\n", err, mdb_strerror(err));
	}
	mdb_dbi_close(env, dbi);
	mdb_env_close(env);
	exit(err);
}



