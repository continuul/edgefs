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

#ifndef __CLBENCH_H__
#define __CLBENCH_H__

#define CLBENCH_VER		1

#define CLBENCH_MSG_SZ		128
#define CLBENCH_RUN_TIME	10
#define CLBENCH_GRP_STR		"nexenta_test_group" /* Max 127 chars */

#define CLBENCH_FLAG_MSG_CNT	0x1
#define CLBENCH_FLAG_MSG_SZ	(0x1 << 1)
#define CLBENCH_FLAG_GRP_NAME	(0x1 << 2)
#define CLBENCH_FLAG_TIME	(0x1 << 3)
#define CLBENCH_FLAG_OUT_FILE	(0x1 << 4)
#define CLBENCH_FLAG_VERSION	(0x1 << 5)

struct clbench_params {
	uint16_t	cbp_mask;	/* Bit mask of options */
	uint32_t	cbp_msg_sz;	/* Message size */
	uint32_t	cbp_msg_nr;	/* Number of messages */
	uint16_t	cbp_msg_track;	/*
					 * Flag to track messages when timer
					 * is not used
					 */
	time_t		cbp_run_time;	/* Benchmark run time in seconds */
	struct cpg_name cbp_grp_name;	/* Name of the cluster */
					/* Output file name */
	char		cbp_file[PATH_MAX];
};

#endif /* __CLBENCH_H__ */
