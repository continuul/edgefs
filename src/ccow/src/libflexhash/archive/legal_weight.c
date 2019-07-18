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
 * This routine verifies that a weighting value is in the legal range
 * At some point this should be a preprocessor macro
 */
bool legal_weight ( int weight )
/* END DECLARATION --> Do Not Delete used to create Headers */
{
	bool return_val ;

	W_Enter(legal_weight) ;
	W_Dump(weight,d) ;
	if ( (weight > 0 ) && (weight <= MAX_Weights))
	{
		return_val = TRUE ;
	} else {
		return_val = FALSE ;
	}
	W_Dump(return_val,d) ;
	W_Exit(legal_weight) ;
	return (return_val) ;
}
