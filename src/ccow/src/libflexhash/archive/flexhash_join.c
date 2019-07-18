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
#include "flexhash.h"
#include "build_weighted.h"

flexhash_join(
	struct ccow_servers *	server_list,
	int			num_servers,
	struct flexhash *	flexhash_table )
{
    struct server_weights ** weighted_table ;
	/*
     * First we need to build the default weighted table based on the list
     * of server ids.  We need to know the number of hashrows for the 
     * range of rows that the weighted entries will build.
     */
    weighted_table = build_weighted (
                            num_servers,
                            server_list,
                            flexhash_table->num_hashrows) ;


