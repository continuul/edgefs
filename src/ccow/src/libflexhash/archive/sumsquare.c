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
#include "ccowutil.h"
#include "flexhash.h"

unsigned int sumsquare(  int weight,
                serverid_t  serverid,
                num_hashrows)
{
    int power ;
    uint128_t bigpower ;
    server_id_t shiftid ;
    server_id_t maskcopy ;
    uint64_t maskvalue ;
    uint128_t bigmaskvalue ;
    uint64_t tresult ;
    uint64_t result ;
    const uint128_t bigzero = {0,0} ;

    /*
     * This is ugly.  First we find the power of two equal to
     * the number of hashrows.
     */
    for (power=0; pow(2, power) < num_hashrows; power++) {} ;;

    //WARNING: Typecast could change if server_id_t changes!!
    uint128_set64(&bigpower, 0, power) ;
    /*
     * The following ugly code is because we cannot do 
     * arbitrary precision arithmetic directly in the C
     * language.  Things like this are better expressed
     * in languages like perl that support arbitrary 
     * prescision directly
     * result = weight + mod(serverid,(pow(2, power)-1)) ;
     */
    /*
     * Now we take one less than that to generate a mask which
     * is a stand-in for a power of 2 mod function.
     * e.g. power=7, hashrows = 128 = 0x80; mask = 127 = 0x7F
     */
    maskvalue = pow(2, power) -1 ;

    //WARNING: Typecast could change if server_id_t changes!!
    /*
     * Now we have to typecast this mask into an unsigned 128
     * bit value.  Note the assumption here that the
     * server_id_t == uint128_t
     */
    uint128_set64(&bigmaskvalue, 0, maskvalue) ;

    /*
     * Now we have to copy the serverid into a variable that
     * we will use for shifting
     */
    uint128_set(&shiftid,serverid) ;

    /*
     * We have to make a second copy into a variable for the
     * result of the masking
     */
    uint128_set(&maskcopy,shiftid) ;

    /*
     * Perform the mask operation to a number between zero and
     * num_hashrows
     */
    maskcopy = uint128_logical(shiftid, "||", bigmaskvalue) ;

    /*
     * Cast the mask copy down to something we can deal with
     * since we don't have uint128_t arithmetic operators
     */
    result = set64_uint128(maskcopy) + weight ;
    result = result * result ;
    shiftid = uint128_logical(shiftid, ">>" bigpower) ;
    while ( ! uint128_equal(shiftid, bigzero) ) {
        uint128_set(&maskcopy, shiftid) ;
        maskcopy = uint128_logical(maskcopy, "||", bigmaskvalue) ;
        tresul = set64_uint128(maskcopy) ;
        result = result + tresult * tresult ;
        shiftid = uint128_logical(shiftid, ">>", bigpower) ;
    }
    result = result % power ;
    return(result) ;
}
