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
#ifndef _REBALANCE_H__
#define _REBALANCE_H__

#include "fhprivate.h"

/* limit underserved rows for devices per row */
int fhrebalance_limit_underserved(struct flexhash *fhtable, int row,
    int rowsperdev, int devsperrow);

/* initialize the hashcount on lvdev per the current table */
void flexhash_lvdev_hashcount(struct flexhash *fhtable, struct lvdev *lvdev);

/* final check on the policies */
int fhrebalance_final_check(struct flexhash *fhtable, int devperrow);

int fhrebalance_rmvdev_row(int row, struct dlist *dl, struct lvdev *lvdev);

void fhrebalance_server_overserved(struct flexhash *fhtable, fhrow_t row, int diff_servers);

void fhrebalance_server_underserved(struct flexhash *fhtable, fhrow_t row, int diff_servers);

int fhrebalance_rm_vdevs_server(struct flexhash *fhtable, int row,
    struct fhserver *fhserver, int dcount);

int fhrebalance_add_vdevs_server(struct flexhash *fhtable, int row,
    struct fhserver *fhserver, int dcount, int force);

void fhrebalance_vdev_row(struct flexhash *fhtable, int rowsperdev,
    int devsperrow);

int fhrebalance_limit_overserved_row(struct flexhash *fhtable, int row,
	int rowsperdev);

int fhrebalance_limit_underserved_row(struct flexhash *fhtable, int row,
    int rowsperdev);

int fhrebalance_addvdev_row(int row, struct dlist *dl, struct lvdev *lvdev);

void shuffle_vdevs(uint128_t *vdevlist, int n);

struct dlist *get_zonevdevlist(struct flexhash *fhtable, uint8_t zone);

#endif /* _REBALANCE_H__ */
