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

var (
	ConfigurationFile = "/etc/config/nesetup.json"

	/* Optional file name */
	filename string

	/* Optional nodename filter */
	nodename string
)

func ConfigFileFnc(cmd *cobra.Command, args []string) {

	if len(args) > 0 {
		filename = args[0]
	}

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

	if len(filename) > 0 {
		configFileName = filename
	}

	err := efsutil.LoadJsonFile(&clusterConfig, configFileName)
	if err != nil {
		fmt.Printf("Error reading JSON config file: %s", err)
		os.Exit(1)
	}
	nodeConfig = clusterConfig[nodename]

	ConfigNode()
}

var (
	FileCmd = &cobra.Command{
		Use:   "file [/path/to/setup.json]",
		Short: "configure via JSON file",
		Long:  "setup cluster node via JSON configurational file",
		Run:   ConfigFileFnc,
	}
)

func init() {

	nedgeHome = os.Getenv("NEDGE_HOME")
	if nedgeHome == "" {
		nedgeHome = DefaultNedgePrefix
	}

	ConfigCmd.AddCommand(FileCmd)
	FileCmd.Flags().StringVarP(&nodename, "nodename", "n", "", "Optional nodename override. Using hostname if omitted")
}
