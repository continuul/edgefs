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
#ifndef __TC_POOL_H__
#define __TC_POOL_H__

/**
 * Initialize tc pool module
 */
int
tc_pool_init(void);

/**
 * Createpool of tenant context.
 * Create max_tc_count tenant contexts and maintain them in the pool.
 */
int
tc_pool_create(char *ccow_config, char *cluster, char *tenant,
		uint64_t max_tc_count, void **tc_pool_handle);

/**
 * Return next TC from the pool.
 */
int
tc_pool_get_tc(void *tc_pool_handle, inode_t ino, ccow_t *tc);

/**
 * Find already created TC pool handle
 */
int
tc_pool_find_handle(char *cluster, char *tenant, void **tc_pool_handle);

/**
 *	Release all TCs
 */
int
tc_pool_term(void);

#endif /* __TC_POOL_H__ */
