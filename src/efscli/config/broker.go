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

func ConfigBrokerFnc(cmd *cobra.Command, args []string) {

	var ccowConf CcowConf
	err := efsutil.LoadJsonFile(&ccowConf, nedgeHome+CCOWJsonFile)
	if err != nil {
		fmt.Printf("Error reading JSON config file: %s", err)
		os.Exit(1)
	}

	if ccowConf.Network.BrokerIP4addr != "" {
		brokerIP, err := efsutil.GetIPv4Address(ccowConf.Network.BrokerInterfaces)
		if err != nil {
			fmt.Printf("Can't find IP accesible address via network interface %s Error: %v \n", ccowConf.Network.BrokerInterfaces, err)
			os.Exit(1)
		}

		ccowConf.Network.BrokerIP4addr = brokerIP

		err = efsutil.MarshalToFile(nedgeHome+CCOWJsonFile, &ccowConf)
		if err != nil {
			fmt.Printf("Can't marshal JSON file %s Error: %v \n", nedgeHome+CCOWJsonFile, err)
			os.Exit(1)
		}
		fmt.Printf("Configured %s\n", nedgeHome+CCOWJsonFile)
	}
}

var (
	BrokerCmd = &cobra.Command{
		Use:   "broker",
		Short: "reconfigure broker network",
		Long:  "configure broker network based on current settings",
		Run:   ConfigBrokerFnc,
	}
)

func init() {

	nedgeHome = os.Getenv("NEDGE_HOME")
	if nedgeHome == "" {
		nedgeHome = DefaultNedgePrefix
	}

	ConfigCmd.AddCommand(BrokerCmd)
}
