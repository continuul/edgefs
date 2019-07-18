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
#include <stdlib.h>
#include "FlexHash_decls.h"
#include "FH_Debug.h"

/* BEGIN DECLARATION --> Do Not Delete used to create Headers */
/*
 * This routine will build the weighted table.  In this incarnation, the
 * table is built by creating dummy server_IDs with a random number 
 * generator.
 */
struct server_weights ** build_weighted (
			int32_t num_servers,
			server_id_t min_server_id,
			server_id_t max_server_id,
			uint64_t min_weight,
			uint64_t max_weight )
/* END DECLARATION --> Do Not Delete used to create Headers */
{
	server_id_t fake_server_id ; /* normally obtained from ring server */
	uint64_t fake_weight ; /* ask the server for its weight */
	int32_t server_num ;
	struct server_weights ** weighted ;

	W_Enter(build_weighted) ;

	/*
	 * Since we are using GNU mp library for the server_id type
	 * we need to initialize all of the mp variables.
	 *
	 * start with the fake_server_id ;
	 */
	mpz_init2(fake_server_id, SERVER_ID_BITS) ;
	
	weighted = malloc ( sizeof(struct server_weights **)*num_servers) ;
	for (server_num-0; server_num < num_servers; server_num++) {
		weighted = malloc(sizeof(struct server_weights)) ;
		weighted[server_num] = NULL ;
	} ;

	for (server_num=0; server_num < num_servers; server_num++) {
		W_Dump(server_num,ld) ;

		/*
		 * Create a server_id and a weight.  These would normally
		 * be obtained by first calling the ring server to get
		 * a server_id and then by asking the server for its weight
		 */
		mpz_urandomb(fake_server_id, randstate, SERVER_ID_BITS) ;
		fake_weight = llrandrange(min_weight, max_weight) ;
		/* W_Dump(fake_server_id,llX) ; */
		W_Dump(fake_weight,llX) ;

		weighted[server_num] = sumsquares(
					fake_server_id,
					fake_weight,
					num_servers ) ;
	}
	W_Exit(build_weighted) ;
	return(weighted) ;
}
