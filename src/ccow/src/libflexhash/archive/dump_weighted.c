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
#include <time.h>
#include <stdlib.h>
#include "FlexHash_decls.h"
#include "FH_Debug.h"

/* BEGIN DECLARATION --> Do Not Delete used to create Headers */
/*
 * This routine produces an intelligent and human readable dump of the
 * weighted table which reflects the generation of hash codes for the
 * servers to reflect how many times a server should appear in the
 * FlexHash table as a function of its capabilities/capacity.
 */
int dump_weighted(
	struct server_weights ** weighted,
	long num_servers)
/* END DECLARATION --> Do Not Delete used to create Headers */
{
	long	server_num ;
	int	hash_num ;
	
	W_Enter(dump_weighted) ;
	for (server_num=0; server_num < num_servers; server_num++)
	{
		fprintf(stderr, "Server #: %ld; Weight %d; server_id %llX\n\t",
			server_num, weighted[server_num]->weight,
			weighted[server_num]->server_id) ;
		for (hash_num=0; hash_num< weighted[server_num]->weight; hash_num++)
		{
			fprintf(stderr, "%03d | ",
				weighted[server_num]->server_hashes[hash_num]) ;
		}
		fprintf(stderr, "\n") ;
	}
	W_Exit(dump_weighted) ;
	return(0) ;
}
