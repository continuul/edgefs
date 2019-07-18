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
#ifndef _REPTRANS_FLEX_H
#define _REPTRANS_FLEX_H

#include "flexhash.h"

/* review */
uint64_t flexhash_estimate_vdev_weight(volatile struct flexhash *fhtable,
					struct repdev *dev,
					fh_io_type_t iotype);

uint128_t *flexhash_get_serverid(volatile struct flexhash *fhtable, struct repdev *dev);
uint64_t flexhash_estimate_vdev_avail_pct(volatile struct flexhash *fhtable,
			struct repdev *dev);

#endif /* _REPTRANS_FLEX_H */
