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
/**
 * @file talloc.c
 *
 * @brief Provides structure aware allocations
 *
 * @author Dario Sneidermanis
 *
 *
 * Each chunk of talloc'ed memory has a header of the following form:
 *
 * +-------+---------+---------+--------...
 * | first |  next   |  prev   | memory
 * | child | sibling | sibling | chunk
 * +-------+---------+---------+--------...
 *
 * Thus, a talloc hierarchy tree would look like this:
 *
 *   NULL <-- node --> NULL
 *            ^
 *            |
 *            +> node <--> node <--> node --> NULL
 *               v         v         ^
 *               NULL      NULL      |
 *                                   +> node <--> node --> NULL
 *                                      v         v
 *                                      NULL      NULL
 */

#include <stdlib.h>

#include "ccowutil.h"
#include "talloc.h"


/**
 * Allocate memory
 *
 * @param size    amount of memory requested
 * @param parent  pointer to previously talloc'ed memory from wich this chunk
 *                depends or NULL
 *
 * @return a pointer to the allocated memory
 */
void* talloc ( size_t size, void* parent ) {

    void** mem = je_malloc( size + sizeof( void* ) * 3 );

    if ( !mem ) return NULL;

    mem[0] = mem[1] = mem[2] = NULL;

    talloc_set_parent( mem + 3, parent );

    return mem + 3;
}


/**
 * Allocate zeroed memory
 *
 * @param size    amount of memory requested
 * @param parent  pointer to previously talloc'ed memory from wich this chunk
 *                depends or NULL
 *
 * @return a pointer to the allocated memory
 */
void* tcalloc ( size_t size, void* parent ) {

    void** mem = je_calloc( 1, size + sizeof( void* ) * 3 );

    if ( !mem ) return NULL;

    talloc_set_parent( mem + 3, parent );

    return mem + 3;
}


/**
 * Re-allocate memory
 *
 * @param mem   pointer to previously talloc'ed memory
 * @param size  amount of memory requested
 *
 * @return a pointer to the allocated memory if successful, NULL otherwise
 */
void* trealloc ( void* mem, size_t size ) {

    void*** aux = mem;

    if ( !mem ) return talloc( size, NULL );

    aux = je_realloc( aux - 3, size + sizeof( void* ) * 3 );

    if ( !aux ) return NULL;

    if ( aux + 3 != mem ) {

        if ( aux[0] ) aux[0][2] = aux;
        if ( aux[1] ) aux[1][2] = aux;
        if ( aux[2] ) aux[2][ aux[2][1] == (void**)mem - 3 ] = aux;
    }

    return aux + 3;
}


/**
 * This is for internal use
 *
 * @see tfree
 */
static void __tfree ( void** mem ) {

    if ( !mem || !mem[2] ) return;

    mem[2] = NULL;

    __tfree( mem[0] );
    __tfree( mem[1] );
       je_free( mem );
}


/**
 * Free memory
 *
 * @param mem  pointer to previously talloc'ed memory
 */
void tfree ( void* mem ) {

    void*** aux = mem;

    if ( !mem ) return;

    talloc_set_parent( mem, NULL );

    aux -= 3;
    __tfree( aux[0] );
       je_free( aux );
}


/**
 * Get parent of talloc'ed memory
 *
 * @param mem  pointer to previously talloc'ed memory
 *
 * @return pointer to previously talloc'ed memory from which this chunk depends
 */
void* talloc_get_parent ( void* mem ) {

    void*** aux = mem;

    if ( !mem || !aux[-1] ) return NULL;

    for ( aux -= 3; aux[2][1] == aux; aux = (void***)(aux[2]) ) ;

    return aux[2] + 3;
}


/**
 * Set parent of talloc'ed memory
 *
 * @param mem     pointer to previously talloc'ed memory
 * @param parent  pointer to previously talloc'ed memory from wich this chunk
 *                depends or NULL
 */
void talloc_set_parent ( void* mem, void* parent ) {

    void*** aux = mem;
    void*** dad = parent;

    if ( !mem ) return;

    aux -= 3;
    dad -= 3;

    if ( aux[2] ) { /* if !root, remove from tree */

        if ( aux[1] ) aux[1][2] = aux[2];

        aux[2][ aux[2][1] == aux ] = aux[1];
    }

    if ( parent ) { /* if parent, add to new tree */

        if ( dad[0] ) dad[0][2] = aux;

        aux[1] = dad[0];
        aux[2] = (void**)dad;
        dad[0] = (void**)aux;

        return;
    }

    aux[1] = aux[2] = NULL;
}


/**
 * Remove chunk of talloc'ed memory from dependency chain.
 *
 * @param mem     pointer to previously talloc'ed memory
 * @param parent  pointer to previously talloc'ed memory from wich this chunk's
 *                children will depend or NULL
 */
void talloc_steal ( void* mem, void* parent ) {

    void*** aux = mem;
    void*** dad = parent;
    void**  son;

    if ( !mem ) return;

    talloc_set_parent( mem, NULL );

    aux -= 3;

    if ( !aux[0] ) return;

    if ( parent ) {

        dad -= 3;

        if ( dad[0] ) {

            for ( son = aux[0]; son[1]; son = son[1] ) ;

            dad[0][2] = son;
            son[1] = dad[0];
        }

        dad[0] = aux[0];
    }

    aux[0][2] = dad;
    aux[0] = NULL;
}

