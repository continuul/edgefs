//
// Copyright (c) 2015-2018 Nexenta Systems, inc.
//
// This file is part of EdgeFS Project
// (see https://github.com/Nexenta/edgefs).
//
// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
//


#include <errno.h>

#include "ccowutil.h"
#include "pmu.h"
#include "pmu_vdev.h"
#include "pmu_private.h"


struct pmu_vdevlist *allvdevs = NULL;

int
pmu_vdev_register(struct pmu_vdev *pmu_vdev)
{
	if (!pmu_vdev) {
		return -EACCES;
	}
	if (allvdevs == NULL) {
		allvdevs = je_malloc(sizeof(struct pmu_vdevlist));
		if (!allvdevs)
			return -ENOMEM;

		allvdevs->vdevcount = 0;
		allvdevs->vdevlist = NULL;
	}
	struct pmu_vdev *pvdevptr = allvdevs->vdevlist;
	if (pvdevptr == NULL) {
		allvdevs->vdevlist = pmu_vdev;
		allvdevs->vdevcount++;
		return 0;
	}
	while (pvdevptr->next != NULL) {
		pvdevptr = pvdevptr->next;
	}
	pvdevptr->next = pmu_vdev;
	return 0;
}

int
pmu_vdev_unregister(struct pmu_vdev *pmu_vdev)
{
	if (allvdevs->vdevcount == 0 && allvdevs->vdevlist == NULL) {
		je_free(allvdevs);
		return 0;
	}

	assert(allvdevs->vdevlist != NULL);

	struct pmu_vdev *pvdevptr = allvdevs->vdevlist;
	struct pmu_vdev *pptr = allvdevs->vdevlist;
	while (pvdevptr != NULL) {
		if (uint128_cmp(&pmu_vdev->id, &pvdevptr->id) == 0) {
			if ( pvdevptr == pptr ) {
				/* first element */
				allvdevs->vdevlist = pptr->next;
				allvdevs->vdevcount--;
				return 0;
			}
			pptr->next = pvdevptr->next;
			allvdevs->vdevcount--;
			return 0;
		}
		pptr = pvdevptr;
		pvdevptr = pvdevptr->next;
	}
	return -ENOENT;
}

struct pmu_vdev *
select_vdev(unsigned chunk_num)
{
	struct pmu_vdev *vdevptr = NULL;
	int selected_vdev = chunk_num % (unsigned) allvdevs->vdevcount;

	vdevptr = allvdevs->vdevlist;
	int count=0;
	while (vdevptr != NULL) {
		if (selected_vdev == count)
			break;
		count++;
		vdevptr = vdevptr->next;
	}
	return vdevptr;
}


void
pmu_vdev_notify_all(pmu_if_t *pi)
{

	if (!allvdevs)
		return;

	if (allvdevs->vdevcount == 0)
		return;

	struct pmu_vdev *pvdevptr = allvdevs->vdevlist;

	while (pvdevptr != NULL) {
		void *p;
		int err;

		err = uv_async_send(&pvdevptr->lfq_kick);
		assert(err == 0);
		while ((p = pmu_lfq_consume(pvdevptr->rtn)) != NULL)
			transaction_complete(p);
		pmu_tx_kick(pi);

		pvdevptr = pvdevptr->next;
	}
}



const frame_header_t *first_frame(const chunk_track_t *t)
{
	unsigned i;

	for (i = 0; i != PMU_TEST_MAX_DATAGRAMS;++i) {
		if (t->frame[i])
			return t->frame[i];
	}
	return (const frame_header_t *)NULL;
}

