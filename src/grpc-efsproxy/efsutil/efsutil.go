/*
 * Copyright (c) 2015-2018 Nexenta Systems, Inc.
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
package efsutil

import (
	"io/ioutil"
	"os"
	"runtime"
	"strings"
)

func GetLibccowConf() ([]byte, error) {
	conf, err := ioutil.ReadFile(os.Getenv("NEDGE_HOME") + "/etc/ccow/ccow.json")
	if err != nil {
		return nil, err
	}
	return conf, err
}

func IsSystemName(cl string) bool {
	if cl == "root" || strings.Compare("^TRLOG-", cl) >= 0 {
		return true
	}
	return false
}

func GetFUNC(depthList ...int) string {
	var depth int
	if depthList == nil {
		depth = 1
	} else {
		depth = depthList[0]
	}
	function, _, _, _ := runtime.Caller(depth)
	return runtime.FuncForPC(function).Name()
}
