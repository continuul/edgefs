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
 * The function which takes the server_id and generates a hash of it with
 * different weightings by performing a sum of the squares of the bytes
 * within the server_id.  A seed is added to the different weights that
 * helps to distribute this widely across the total number of hash rows.
 * The assumption here is that the number of hash rows will be a binary
 * power of two in order to make the shift operations work in consuming
 * the server_id.
 *
 * This function computes the row of hash values for a single server_id and
 * returns a structure that will go into an array of structures in the 
 * parent function.
 */
struct server_weights * sumsquares (
			server_id_t server_id,
			int weight,
			int64_t hashtablerows )
/* END DECLARATION --> Do Not Delete used to create Headers */
/*
 * The row that is computed with the hashweights for this server_id
 * should probably be passed in as a parameter rather than returning
 * a pointer to an array allocated within the function or performing
 * a malloc of the array.  For the moment, this is the lazy
 * implementation that ignores all of the niceties of how it should
 * be done.
 */
{
	uint32_t masked_bits ;
	int i ;
	int old ;
	int shiftcount ;
	int hash_mask ;
	int64_t num_hash_rows ;
	struct server_weights * new_weights ;

	W_Enter(sumsquares) ;
	/* W_Dump(server_id,llX) ; */
	W_Dump(weight,d) ;
	W_Dump(total_servers,ld) ;

	/*
	 * Verify that the weight is legal.
	 */

	if (legal_weight(weight) != TRUE) { 
		/*
		 * The following is a place holder for an I18N Function
		 * that will look up the correct localization string,
		 * emit that message with diagnostic information including
		 * the function name, source file and line number and then
		 * exit the program.
		 */
		ERR_EXIT(INVALID_WEIGHT_SPECIFIED) ;
	}
	/*
	 * Determine the size of the hash_mask and shiftcount as a function
	 * of the next power of 2 larger than the number of total_servers.
	 *
	 * This will also be the default size of the hash table based on
	 * the number of servers.  Rather than burying this simple
	 * calculation in this function and reproducing it elsewhere, we
	 * will invoke a function to perform the calculation.
	 * Note that this might wind up as a Macro.
	 */

	W_Dump("About to call hashrow count",s) ;
	num_hash_rows = hashrowcount ( total_servers ) ; 
	W_Dump(num_hash_rows,ld) ;
	hash_mask=0 ;
	shiftcount=0 ;
	while (num_hash_rows > hash_mask +1) {
		shiftcount++ ;
		hash_mask = pow(2,shiftcount) -1 ;
	}
	W_Dump(shiftcount,d) ;
	W_Dump(hash_mask,d) ;

	new_weights = malloc ( sizeof (struct server_weights) ) ;
	mpz_init2(new_weights->min_server_id, SERVER_ID_BITS) ;
	mpz_init2(new_weights->min_server_id, SERVER_ID_BITS) ;

	new_weights->server_id = server_id ;
	new_weights->weight = weight ;

	W_Dump(new_weights->server_id,llX) ;
	W_Dump(new_weights->weight,d) ;


	for (i=0; i< weight; i++)
	{
		new_weights->server_hashes[i] = i ;
		W_Dump(i,d) ;
		W_Dump(new_weights->server_hashes[i],d) ;
	}
	while ( server_id > 0 )
	{
		W_Dump(server_id,llX) ;

		masked_bits = server_id % hash_mask ; 
		W_Dump(masked_bits,X) ;

		for (i=0; i<weight; i++)
		{
			old=new_weights->server_hashes[i] ;
			new_weights->server_hashes[i] += abs((old * old) + masked_bits) ;
			W_Dump(i,d) ;
			W_Dump(new_weights->server_hashes[i],d) ;
		}
		server_id = server_id >> shiftcount ;
		W_Dump(server_id,llX) ;
	}
	W_Dump(server_id,llX) ;

	/* This final pass is to make sure that the hash #s fit in */
	/* a single masked_bits with the mod function */

	for (i=0; i < weight; i++)
	{
		old=new_weights->server_hashes[i] ;
		new_weights->server_hashes[i] = abs(old) % hash_mask ;
		W_Dump(i,d) ;
		W_Dump(new_weights->server_hashes[i],d) ;
	}
	W_Exit(sumsquares) ;
	return(new_weights) ;
}
