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
#include <string.h>
char ** __SUB__ /*/ = NULL /*/ ;
char ** NEW__SUB__ /*/ = NULL /*/ ;
#define FH_MINIMAL_DEBUG 0
#define FH_ENTRYEXIT_DEBUG 4
#define FH_VARIABLE_DEBUG 9
#define FH_INTERNAL_DEBUG 14
#if DEBUG > FH_MINIMAL_DEBUG
int FH_Debug /*/ = DEBUG /*/ ;
int DEBUG_Wave /*/ = 0 /*/ ;
char * __PROGRAM__ ;
#endif
#if DEBUG > FH_ENTRYEXIT_DEBUG
#define W_Enter_main(FUNC_NAME) \
{ \
	if (strcmp(#FUNC_NAME,"main")==0) { \
		__PROGRAM__ = malloc(strlen(argv[0])) ; \
		strcpy(__PROGRAM__, argv[0]) ; \
	} ; \
	W_Enter(FUNC_NAME) ; \
} ;
#define W_Enter(FUNC_NAME) \
{  \
	int i ; \
	DEBUG_Wave++ ;  \
	NEW__SUB__ = malloc (sizeof(char *)*DEBUG_Wave) ; \
	if (__SUB__ != NULL) {  \
		for(i=0; i<DEBUG_Wave-1; i++) {  \
			NEW__SUB__[i]=__SUB__[i] ;  \
		} ;  \
		free(__SUB__) ; \
	} ;  \
	__SUB__ = NEW__SUB__ ;  \
	__SUB__[DEBUG_Wave-1] = malloc(sizeof(#FUNC_NAME)) ;  \
	strcpy(__SUB__[DEBUG_Wave-1],#FUNC_NAME) ;  \
	for (i=0; i < DEBUG_Wave; i++ ) {  \
		fprintf(stderr,">>") ;  \
	} \
	fprintf(stderr, "%-20s: File: %25s: Line: %5d\n", \
		__SUB__[DEBUG_Wave-1], \
		__FILE__, \
		__LINE__ ) ; \
}
#define W_Exit(FUNC_NAME) \
{ \
	int i ; \
	for (i=0; i < DEBUG_Wave; i++ ) {\
		fprintf(stderr,"<<") ; \
	} ; \
	if (strcmp(__SUB__[DEBUG_Wave-1],#FUNC_NAME)!=0) { \
		fprintf(stderr, \
			"Name Mismatch on exit: Remembered %s; Got %s\t", \
			__SUB__[DEBUG_Wave-1], \
			#FUNC_NAME ) ; \
	} ; \
	fprintf(stderr, "%-20s:", \
		__SUB__[DEBUG_Wave-1] ) ;\
	fprintf(stderr, "File: %25s: Line: %5d\n", \
		__FILE__, \
		__LINE__ ) ; \
	fprintf( stderr, \
		"DEBUG_Wave is:=%d\n", \
		DEBUG_Wave) ; \
	free(__SUB__[DEBUG_Wave-1]) ; \
	DEBUG_Wave-- ; \
	for (i=0; i < DEBUG_Wave; i++ ) {\
		fprintf(stderr,"<>") ; \
	} ; \
	if (DEBUG_Wave>0) { \
		fprintf(stderr,"%s<-- Returning to...\n", __SUB__[DEBUG_Wave-1]) ; \
	} ; \
} ;
#else
#define W_Enter_main(FUNC_NAME) 
#define W_Enter(FUNC_NAME) 
#define W_Exit(FUNC_NAME) 
#endif
#if DEBUG > FH_VARIABLE_DEBUG
#define W_Dump128(Variable, Type) \
{ \
	char __Format_String__[200] ; \
	char __Uint128_String__[33] ; \
	if(strcmp(#Type,"llllX")==0) { \
		uint128_dump(&Variable, &__Uint128_String__[0], sizeof(__Uint128_String__)) ; \
	} \
	sprintf(__Format_String__, \
		"%-20s:=%%28%s; File: %25s; Line: %5d\n", \
		#Variable, \
		strcmp(#Type,"f")==0?".5f":#Type, \
		__FILE__, \
		__LINE__ ) ; \
	} else { \
		fprintf(stderr, \
			__Format_String__, \
			strcmp(#Type,"llllX")==0?__Uint128_String__:Variable ) ; \
	} \
}
#define W_Dump(Variable,Type) \
{ \
	char __Format_String__[200] ; \
	sprintf(__Format_String__, \
		"%-20s:=%%28%s; File: %25s; Line: %5d\n", \
		#Variable, \
		strcmp(#Type,"f")==0?".5f":#Type, \
		__FILE__, \
		__LINE__ ) ; \
	if (strcmp(#Type,"s")==0) { \
		fprintf(stderr, \
			__Format_String__, \
			#Variable ) ; \
	} else { \
		fprintf(stderr, \
			__Format_String__, \
			Variable ) ; \
	} \
}
#else
#define W_Dump128(Variable, Type)
#define W_Dump(Variable,Type)
#endif
