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
#include "FH_Debug.h"

int main()
{

	int i ;
	int32_t longi ;
	int64_t longlongi ;
	uint64_t ulonglongi ;


	W_Enter(main) ;

	W_Dump("This is a string",s) ;
	for (i=0; i<65; i++) {
		printf("pow(2,%d) = %g\n",i,pow(2,i)) ;
		longi = pow(2,i); 
		printf("pow(2,%d) = %li\n",i,longi) ;
		longlongi = pow(2,i) ;
		printf("pow(2,%d) = %lli\n",i,longlongi) ;
		ulonglongi = pow(2,i) ;
		printf("pow(2,%d) = 0x%llX\n",i,longlongi) ;
		printf("pow(2,%d) = 0x%llX\n",i,ulonglongi) ;
		longlongi = pow(2,i)-1 ;
		printf("pow(2,%d)-1 = %lli\n",i,longlongi) ;
		ulonglongi = pow(2,i)-1 ;
		printf("pow(2,%d)-1 = 0x%llX\n",i,longlongi) ;
		printf("pow(2,%d)-1 = 0x%llX\n",i,ulonglongi) ;
		W_Dump(i,d) ;
		W_Dump(longi,ld) ;
		W_Dump(longlongi,lld) ;
		W_Dump(ulonglongi,llX) ;
	}
	W_Dump("This is a second string",s) ;
	W_Exit(main) ;
	exit(0) ;
}
