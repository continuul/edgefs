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
 * This routine copies a row of the FlexHash table from one row to
 * another.  It might be argued that all of the duplicate rows could
 * actually point to the same row instance rather than being a full
 * copy.  I have taken the more conservative approach to actually
 * copy the row.  Changing to many pointers to the same row is a 
 * decision that can be deferred.  If we make that decision, we 
 * will have to verify that if a row is modified, that only a copy
 * of the row is modified or that you really intended that all
 * copies of the row should stay the same.
 */
int copy_FlexHashrow (
	struct FlexHash ** FlexHash_tab,
	int old_row,
	int row_num )
/* END DECLARATION --> Do Not Delete used to create Headers */
{
	struct FlexHash * chaser ;
	struct FlexHash * fox ;

	W_Enter(copy_FlexHashrow) ;
	
	chaser=FlexHash_table[old_row] ;
	FlexHash_table[new_row] = malloc(sizeof(struct FlexHash )) ;
	fox = FlexHash_table[new_row] ;

	while (chaser != NULL) {
		fox->server_id = chaser->server_id ;
		fox->next_server = chaser->next_server ;
		if (chaser->next_server != NULL) {
			fox->next_server = malloc(sizeof(struct FlexHash)) ;
			fox=fox->next_server ;
			fox->next_server = NULL ; /* Redundant */
		}
		chaser=chaser->next_server ;
	}
	
	W_Exit(copy_FlexHashrow) ;
	return(0) ;
}
