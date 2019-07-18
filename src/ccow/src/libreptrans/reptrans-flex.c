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
#include "replicast.h"
#include "reptrans.h"
#include "reptrans-flex.h"

/* never return zero. return default if zero computed
 * otherwise return whatever is calculated
 */
uint64_t flexhash_estimate_vdev_weight(volatile struct flexhash *fhtable,
			struct repdev *dev, fh_io_type_t iotype)
{
	uint64_t ret_weight;

	if (iotype == FH_IOTYPE_GET) {
		ret_weight = dev->get_disk_qdepth + 1;
	} else if (iotype == FH_IOTYPE_PUT) {
		ret_weight = dev->put_disk_qdepth + 1;
	} else
		assert(0);

	if (unlikely(lg->level <= LOG_LEVEL_DUMP)) {
		char vdevstr[UINT128_STR_BYTES];
		uint128_dump(&dev->vdevid, vdevstr, UINT128_STR_BYTES);
		log_debug(lg, "vdev: %s current weight iotype=%d: %ld", vdevstr,
		    iotype, ret_weight);
	}
	return ret_weight;
}

uint128_t *
flexhash_get_serverid(volatile struct flexhash *fhtable, struct repdev *dev)
{
	struct lvdev *lvdev;

	assert(fhtable != NULL && dev != NULL);
	lvdev = vdevstore_get_lvdev(fhtable->vdevstore, &dev->vdevid);

	return lvdev ? &lvdev->server->id : NULL;
}

/* return value of zero indicates an unusable device
 */
uint64_t flexhash_estimate_vdev_avail_pct(volatile struct flexhash *fhtable,
			struct repdev *dev)
{
	struct vdevstore *vdevstore = fhtable->vdevstore;
	int idx;

	idx = flexhash_getvdev_index(fhtable, &dev->vdevid);
	if (idx < 0)
		return 0;
	double avail = (double)vdevstore->lvdevlist[idx].avail;
	double size = (double)vdevstore->lvdevlist[idx].size;
	return (uint64_t)(1000000.0 * avail/size);
}
