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
package config

import (
	"fmt"
	"os"

	"github.com/Nexenta/edgefs/src/efscli/efsutil"
	"github.com/spf13/cobra"
)

func DetectRoleFnc(cmd *cobra.Command, args []string) {

	configFileName := nedgeHome + ConfigurationFile

	if nodename == "" {
		host_hostname := os.Getenv("HOST_HOSTNAME")

		var hostname string
		if host_hostname != "" {
			hostname = host_hostname
		} else {
			var err error
			hostname, err = os.Hostname()
			if err != nil {
				fmt.Printf("Error resolving local hostname: %s\n", err)
				os.Exit(1)
			}
		}
		nodename = hostname
	}

	err := efsutil.LoadJsonFile(&clusterConfig, configFileName)
	if err == nil {
		nodeConfig := clusterConfig[nodename]
		fmt.Printf("%s\n", nodeConfig.NodeType)
	}
}

var (
	RoleCmd = &cobra.Command{
		Use:   "role",
		Short: "detect a role of target",
		Long:  "detect a role of target by reading bind-mounted nesetup.json when provided",
		Run:   DetectRoleFnc,
	}
)

func init() {

	nedgeHome = os.Getenv("NEDGE_HOME")
	if nedgeHome == "" {
		nedgeHome = DefaultNedgePrefix
	}

	ConfigCmd.AddCommand(RoleCmd)
}
