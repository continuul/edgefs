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
#ifndef __FSIO_SNAPSHOT_H__
#define __FSIO_SNAPSHOT_H__

/**
 * We support only File snapshot.
 * Snapshot creation for Directory will fail.
 */

/**
 * Create the snapview object for the export if not already created.
 * Initialize the in memory structure with the snapview object details.
 */
int fsio_snapshot_init(ci_t *ci);

/**
 * Clean out the in memory structures.
 * It does NOT delete the on disk snapview object.
 */
int fsio_snapshot_term(ci_t *ci);

/**
 * Create snapshot for specified file.
 * If the snapshot_name is already used for this file then return error.
 */
int fsio_snapshot_create(ci_t *ci, char *path, char *snapshot_name);

/**
 * Delete snapshot for specified file.
 */
int fsio_snapshot_delete(ci_t *ci, char *path, char *snapshot_name);

/**
 * Return list of names for all snapshots available for a file.
 * The caller must free up the memory.
 * snap_list is array of strings with snap_count elements.
 */
int fsio_snapshot_list(ci_t *ci, char *path, uint64_t *snap_count,
    char ***snap_list);

/**
 * Rollback specific snapshot for a file
 */
int fsio_snapshot_rollback(ci_t *ci, char *path, char *snapshot_name);

#endif /* __FSIO_SNAPSHOT_H__ */
