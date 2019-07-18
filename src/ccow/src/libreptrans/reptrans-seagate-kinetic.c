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
#include <stdio.h>
#include <unistd.h>
#include <uv.h>

#include "ccowutil.h"
#include "reptrans.h"

static int
seagate_kinetic_init(json_value *opts, reptrans_init_cb_t cb)
{
	return 0;
}

static int
seagate_kinetic_destroy()
{
	return 0;
}

static void
seagate_kinetic_dev_destroy(struct repdev *dev)
{
}

static int
seagate_kinetic_dev_cancel(struct repdev *dev)
{
	return 0;
}

struct reptrans rt_seagate_kinetic = {
	.name		= "rt-seagate-kinetic",
	.probe		= seagate_kinetic_init,
	.destroy	= seagate_kinetic_destroy,
	.dev_free	= seagate_kinetic_dev_destroy,
	.dev_close	= seagate_kinetic_dev_cancel
};

reptrans_register(rt_seagate_kinetic);
