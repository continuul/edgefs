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
 * This routine produces an intelligent and human readable dump of the
 * FlexHash table.
 */
int dump_FlexHash (
	struct FlexHash ** FlexHash_tab,
	int rows )
/* END DECLARATION --> Do Not Delete used to create Headers */
{
	int i ;
	struct FlexHash * chaser ;
	int server_count ;

	W_Enter(dump_FlexHash) ;
	for (i=0; i < rows; i++) {
		W_Dump(i,d) ;
		fprintf(stdout, "Row Number: %d\n", i) ;
		chaser = FlexHash_table[i] ;
		server_count = 0 ;
		while (chaser != NULL) {
			fprintf (stdout, "\t%d:\t%llX\n",
				server_count, chaser->server_id ) ;
			W_Dump(chaser->server_id,llX) ;
			chaser=chaser->next_server ;
			server_count++ ;
		}
	}
	W_Exit(dump_FlexHash) ;
}
