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
#ifndef __LOCKS_H__
#define __LOCKS_H__

#include "ccow-impl.h"
#include "reptrans.h"
#include "skiplist.h"

typedef void (*free_lock_t)(void *lk);

/*
 * Advisory lock API
 */
int rt_locks_init(struct repdev *dev);
void rt_locks_destroy(struct repdev *dev);

int rt_is_locked(struct repdev *dev, struct ccow_obj_lock *lk_req);
int rt_add_lock(struct repdev *dev, struct ccow_obj_lock *lk_req,
		 free_lock_t free_lk);
void rt_remove_lock(struct repdev *dev, struct ccow_obj_lock *lk_req);
int rt_sh_ex_conflicts(struct skiplist *list, struct ccow_obj_lock *lk_req);
int rt_lock_conflicts(struct repdev *dev, struct ccow_obj_lock *lk);
struct ccow_obj_lock *
rt_get_lock(struct repdev *dev, struct ccow_obj_lock *lk_req);

static inline int
rt_locks_overlap(struct ccow_obj_lock *lk1, struct ccow_obj_lock *lk2)
{
	return ccow_region_intersects(&lk1->lk_region, &lk2->lk_region);
}

/* Debug functions */
void rt_locks_dump_regions(struct skiplist *lk_list);
void rt_locks_obj_dump_regions(struct repdev *dev, uint512_t *nhid);
void rt_locks_dump(struct repdev *dev);

#endif
