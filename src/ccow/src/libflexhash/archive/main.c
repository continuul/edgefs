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
#include "FlexHash_decls.h"

/* BEGIN DECLARATION --> Do Not Delete used to create Headers */
/*
 * In intial versions of the program this will be a test harness
 */
int main(int argc, char ** argv)
/* END DECLARATION --> Do Not Delete used to create Headers */
{
	int32_t num_servers ;
	server_id_t max_server_id ;
	server_id_t min_server_id ;
	uint64_t min_weight ;
	uint64_t max_weight ;
	int stdrandom ; /* file handle for /dev/urandom */
	const char * DEVRANDOM = "/dev/urandom" ;
	/* mpz_t randomseed ; */
	unsigned long int randomseed ;
	unsigned long int urandomseed ;
	int readcount ;

	struct FlexHash ** FlexHash_tab ;

	struct server_weights **  weighted ;

	W_Enter_main(main) ;

	/*
	 * At this point we should be processing the getopt arguments
	 * to handle things like the locale for the functions.
	 */

	/*
	 * Set the locale to the operating system default
	 */
	/* set_locale(LC_ALL, "") ; */

	/* initialize and seed the random number generator */
	/*
	 * The following looks a bit complex, and it is much more
	 * complex than the simplistic "seed(time(NULL))"
	 * This seeding will use the Linux /dev/urandom device
	 * to fetch a pseudo-random seed. Since this has been
	 * around for a long time under all flavors of Linux since 
	 * 1.3.30, this is portable on Linux, but not Windows
	 */
	/* mpz_init(randomseed) ; */
	/* gmp_randinit_default(randstate) ; */
	/* stdrandom = open (DEVRANDOM, O_RDONLY) ; */
	readcount = read(stdrandom, &urandomseed, sizeof(urandomseed)) ;
	if (readcount<0) {
		ERR_EXIT(ERROR_READING_DEV_URANDOM) ;
	} else if (readcount<sizeof(urandomseed)) {
		ERR_EXIT(ERROR_DEV_URANDOM_READ_TOO_SMALL) ;
	}
	close(stdrandom) ;
	
	/* gmp_randseed_ui(randstate, urandomseed) ; */

	/* srand (time(NULL)) ; */
	srand(urandomseed) ;

	min_weight = 3 ;
	max_weight = 8 ;

	/* Start with max_Servers servers and see what is generated */
	num_servers = MAX_Servers ;
	W_Dump(num_servers,d) ;

	/* Initialize the max_server_id */
	uint128_set64(&max_server_id, UINT64_MAX, UINT64_MAX) ;
	uint128_set64(&min_server_id, INT64_MAX, UINT64_MAX) ;
	/*
	 * max_server_id= UINT64_MAX ;
	 * min_server_id= INT64_MAX ;
	 */
	/*
	 * W_Dump(max_server_id,llX) ;
	 * W_Dump(min_server_id,llX) ;
	 */

	weighted = build_weighted(num_servers, max_server_id, min_server_id, min_weight, max_weight) ;

	/* weighted = build_weighted(num_servers, min_weight, max_weight) ; */

	/* At this point we have built a weighting table for the list 
	 * of servers.  Now we have to organize this into a hash table
	 * with linked lists that for a give hash will give the server_id
	 * of the servers that will service that hash row
	 * Before we do this, the diagnostic version of the code will 
	 * generate a dump of this initial Hash Table
	 */
#if DEBUG > 4
	dump_weighted(weighted, num_servers) ;
#endif
	FlexHash_tab = build_FlexHash(weighted, num_servers) ;
	dump_FlexHash(FlexHash_tab, num_servers) ;
	W_Exit(main) ;
	exit(0) ;
}
