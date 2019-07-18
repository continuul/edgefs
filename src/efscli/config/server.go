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
	"strconv"

	"../efsutil"
	"github.com/spf13/cobra"
)

const (
	defaultSlaveServerPort int = 10700
)

func ConfigServerFnc(cmd *cobra.Command, args []string) {

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

	var di int = 0
	err := efsutil.LoadJsonFile(&clusterConfig, configFileName)
	if err == nil {
		nodeConfig := clusterConfig[nodename]

		if len(nodeConfig.RtrdSlaves) > 0 {
			diStr := os.Getenv("DAEMON_INDEX")
			di, err = strconv.Atoi(diStr)
			if err == nil && di > 0 && di <= len(nodeConfig.RtrdSlaves) {
				err := efsutil.MarshalToFile(nedgeHome+RTRDJsonFile, &nodeConfig.RtrdSlaves[di-1])
				if err != nil {
					fmt.Printf("Can't marshal JSON file %s Error: %v \n", nedgeHome+RTRDJsonFile, err)
					os.Exit(1)
				}
				fmt.Printf("Configured slave daemon %d %s\n", di-1, nedgeHome+RTRDJsonFile)
			} else {
				di = 0
			}
		}
	}

	var ccowConf CcowConf
	err = efsutil.LoadJsonFile(&ccowConf, nedgeHome+CCOWJsonFile)
	if err != nil {
		fmt.Printf("Error reading JSON config file: %s", err)
		os.Exit(1)
	}

	var ccowdConf CcowdConf
	err = efsutil.LoadJsonFile(&ccowdConf, nedgeHome+CCOWDJsonFile)
	if err != nil {
		fmt.Printf("Error reading JSON config file: %s", err)
		os.Exit(1)
	}

	if ccowConf.Network.ServerIP4addr != "" {
		serverIP, err := efsutil.GetIPv4Address(ccowdConf.Network.ServerInterfaces)
		if err != nil {
			fmt.Printf("Can't find IP accesible address via network interface %s Error: %v \n", ccowdConf.Network.ServerInterfaces, err)
			os.Exit(1)
		}
		brokerIP, err := efsutil.GetIPv4Address(ccowConf.Network.BrokerInterfaces)
		if err != nil {
			fmt.Printf("Can't find IP accesible address via network interface %s Error: %v \n", ccowConf.Network.BrokerInterfaces, err)
			os.Exit(1)
		}

		ccowConf.Network.BrokerIP4addr = brokerIP
		ccowConf.Network.ServerIP4addr = serverIP
		ccowdConf.Network.ServerIP4addr = serverIP

		if di > 0 {
			ccowConf.Network.ServerPort = defaultSlaveServerPort + di
			ccowdConf.Network.ServerPort = defaultSlaveServerPort + di
		}

		err = efsutil.MarshalToFile(nedgeHome+CCOWJsonFile, &ccowConf)
		if err != nil {
			fmt.Printf("Can't marshal JSON file %s Error: %v \n", nedgeHome+CCOWJsonFile, err)
			os.Exit(1)
		}
		fmt.Printf("Configured %s\n", nedgeHome+CCOWJsonFile)

		err = efsutil.MarshalToFile(nedgeHome+CCOWDJsonFile, &ccowdConf)
		if err != nil {
			fmt.Printf("Can't marshal JSON file %s Error: %v \n", nedgeHome+CCOWDJsonFile, err)
			os.Exit(1)
		}
		fmt.Printf("Configured %s\n", nedgeHome+CCOWDJsonFile)
	}
}

var (
	ServerCmd = &cobra.Command{
		Use:   "server",
		Short: "reconfigure server network",
		Long:  "configure server (including broker) network based on current settings",
		Run:   ConfigServerFnc,
	}
)

func init() {

	nedgeHome = os.Getenv("NEDGE_HOME")
	if nedgeHome == "" {
		nedgeHome = DefaultNedgePrefix
	}

	ConfigCmd.AddCommand(ServerCmd)
}
