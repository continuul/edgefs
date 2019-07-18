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
#include <math.h>
#include "FlexHash_decls.h"
#include "FH_Debug.h"

/* BEGIN DECLARATION --> Do Not Delete used to create Headers */
/*
 * Based on the total number of servers, this simple function will
 * calculate the number of rows in the hash table based on the number
 * of total servers in the ring.  For the moment this is the next
 * integer power of 2 greater than the number of servers.  Before
 * changing this calculation you should consult build_FlexHash to
 * consider the impact and underlying asumptions that routine makes
 * based on this power of 2 assumption.  Fibonacci numbers may be
 * considered as an alternative, but beware.
 */
int32_t hashrowcount ( int32_t num_servers ) 
/* END DECLARATION --> Do Not Delete used to create Headers */
{
	int i ;
	int32_t rows ;

	W_Enter(hashrowcount) ;
	W_Dump(num_servers,ld) ;
	i=0;
	rows = pow(2,i) ;
	W_Dump(rows,ld) ;
	while (rows < num_servers) {
		i++ ;
		rows = pow(2,i) ;
		W_Dump(rows,ld) ;
	}
	W_Dump(rows,ld) ;
	W_Exit(hashrowcount) ;
	return(rows) ;
}

