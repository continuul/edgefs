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
#include "FH_Debug.h"

/* BEGIN DECLARATION --> Do Not Delete used to create Headers */
/*
 * The function that generates a random number in the interval
 * from Min to Max as uint64_t
 */
uint64_t llrandrange (
	uint64_t min,
	uint64_t max )
/* END DECLARATION --> Do Not Delete used to create Headers */
{
	uint64_t result ;
	double double_result ;
	uint64_t range ;
	uint64_t range_max = UINT64_MAX ;
	double double_range_max ;
	int64_t intermediate ;
	int64_t upper_unshifted ;
	int64_t upper ;
	int64_t lower ;
	double double_intermediate ;
	double double_range ;

	W_Enter(llrandrange) ;
	W_Dump(min,llX) ;
	W_Dump(max,llX) ;

	range = ((max-min) ) ;
	W_Dump(range,llX) ;

	double_range = range ;
	W_Dump(double_range,f) ;

	upper_unshifted = rand() ;
	W_Dump(upper_unshifted,llX) ;
	
	upper = (upper_unshifted << 32) ;
	W_Dump(upper,llX) ;

	lower = rand() ;
	W_Dump(lower,llX) ;

	intermediate = upper | lower ;
	W_Dump(intermediate,llX) ;

	double_intermediate = intermediate ;
	W_Dump(double_intermediate,f) ;

	double_range_max = range_max ;
	W_Dump(double_range_max,f) ;

	double_result = double_intermediate / double_range_max ;
	W_Dump(double_result,f) ;

	double_result = double_result * double_range ;
	W_Dump(double_result,f) ;

	result = double_result ;
	W_Dump(result,llX) ;

	result = result + min ;
	W_Dump(result,llX) ;
	W_Exit(llrandrange) ;

	return (result) ;
}
