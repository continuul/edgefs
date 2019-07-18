#!/bin/bash
##
## Copyright (c) 2015-2018 Nexenta Systems, inc.
##
## This file is part of EdgeFS Project
## (see https://github.com/Nexenta/edgefs).
##
## Licensed to the Apache Software Foundation (ASF) under one
## or more contributor license agreements.  See the NOTICE file
## distributed with this work for additional information
## regarding copyright ownership.  The ASF licenses this file
## to you under the Apache License, Version 2.0 (the
## "License"); you may not use this file except in compliance
## with the License.  You may obtain a copy of the License at
##
##   http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing,
## software distributed under the License is distributed on an
## "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
## KIND, either express or implied.  See the License for the
## specific language governing permissions and limitations
## under the License.
##
FILE_NAME=${1:-./erasure_coding_test.c}
SLEEP_TIME=${2:-1200}
INIT_TIME=${3:-150}
export CCOW_LOG_LEVEL=5
export CCOW_LOG_STDOUT=1
export CCOW_LOG_COLORS=1
rm -rf /data/*/{*,.*}
./cluster_test 
./put_file -o putfile -b 1024 -d 16 ${FILE_NAME}
./daemon_test -i ${INIT_TIME}
./reptrans_bg_test --tree putfile --gen 1
./put_file -o putfile -e -a 3 -w 4 -p 2
./daemon_test -i ${SLEEP_TIME}
./reptrans_bg_test --tree putfile --gen 2
# Removing some chunks
./delete_parity_chunk -n 1
./reptrans_bg_test --tree putfile --gen 2
# Recovery
daemon_test -i ${SLEEP_TIME} &
#./daemon_test -i 120 &
#echo $!
sleep 30
kill -USR2 $!
sleep ${SLEEP_TIME}
./reptrans_bg_test --tree putfile --gen 2

