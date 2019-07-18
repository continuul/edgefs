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


/*
 * pmu_test.h - defines the test message and pig reply for pmu_test applications in the current directory
 *
 *  Created on: Oct 27, 2017
 *      Author: caitlin.bestler@nexenta.com
 */

#ifndef PMU_TEST_H_
#define PMU_TEST_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#define N_SEEDS			100
#define PMU_TEST_MAX_DATAGRAMS	1024

typedef struct pmu_test_fixed_msg
{				// fixed header present in each datagram of a message.
	unsigned must_be_89abcdef;
	unsigned n_datagrams;
	unsigned chunk_num;
	unsigned seed;			// drives vdev selection on target.
	unsigned total_fill;
	unsigned reply_required;	// boolean, unsigned is for allignment
	uint64_t  originated_ts;	// from hpet_cycles() on initiator, in originator byte order
					// value is opague to target node
} pmu_test_fixed_msg_t;

typedef struct pmu_test_msg_datagram
{						// Each UDP payload of a test message
	pmu_test_fixed_msg_t fixed;
	unsigned datagram_num;
	unsigned fill[8000/sizeof(unsigned)];	// 0,1,2,3,.... from start of entire message.
						// Size is maximum, udp_length gives actual datagram size
} pmu_test_msg_datagram_t;

typedef struct pmu_test_reply_msg
{
	unsigned must_be_01234567;
	unsigned chunk_num;		// echoed
	unsigned n_missing;		// # of datagrams for this chunk that were not received.
	uint64_t originated_ts;		// echoed value from the original message
	uint64_t reply_ts;		// when reply was processed on target, in network order
} pmu_test_reply_msg_t;

#endif /* PMU_TEST_H_ */
