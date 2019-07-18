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
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"strings"
)

func GetServerId() ([]byte, error) {
	sid, err := ioutil.ReadFile(os.Getenv("NEDGE_HOME") + "/var/run/serverid.cache")
	if err != nil {
		fmt.Print(err)
		return nil, err
	}
	return sid, err
}

func GetLibccowConf() ([]byte, error) {
	conf, err := ioutil.ReadFile(os.Getenv("NEDGE_HOME") + "/etc/ccow/ccow.json")
	if err != nil {
		fmt.Print(err)
		return nil, err
	}
	return conf, err
}

func GetFlexhashJson() ([]byte, error) {
	j, err := ioutil.ReadFile(os.Getenv("NEDGE_HOME") + "/var/run/flexhash.json")
	if err != nil {
		fmt.Print(err)
		return nil, err
	}
	return j, err
}

func AskForConfirmation(s string) bool {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Printf("%s [y/n]: ", s)

		response, err := reader.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}

		response = strings.ToLower(strings.TrimSpace(response))

		if response == "y" || response == "yes" {
			return true
		} else if response == "n" || response == "no" {
			return false
		}
	}
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
