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
package system

import (
	"../efsutil"
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

func MaintenanceActivate(time int) error {
	ch, err := efsutil.CreateCcowdChannel(10000)
	if ch == nil {
		fmt.Println("Channel create error:", err)
		return err
	} else {
		defer ch.Close()
		cmd := fmt.Sprintf("SET_MAINTTIME%d", time)
		resp, err := ch.Request(cmd, 256)
		if err != nil {
			fmt.Println("Channel request error:", err)
		} else {
			reply := string(resp)
			var status int = -1
			fmt.Sscanf(reply, "SET_MAINT_REPLY%d", &status)
			if status != 0 {
				return fmt.Errorf("ERROR: the ccow-daemon replied with code %d",
					status)
			}
		}
	}
	return nil
}

var (
	maintainCmd = &cobra.Command{
		Use:   "maintenance",
		Short: "The maintenance mode management",
	}

	activateCmd = &cobra.Command{
		Use:   "activate",
		Short: "activate maintenance mode",
		Run: func(cmd *cobra.Command, args []string) {
			err := MaintenanceActivate(ccowdChannelRecvTimeout)
			if err != nil {
				os.Exit(1)
			} else {
				fmt.Println("The maintenance mode has been (re)activated for",
					ccowdChannelRecvTimeout, "minutes")
			}
		},
	}

	deactivateCmd = &cobra.Command{
		Use:   "deactivate",
		Short: "De-activate maintenance mode",
		Run: func(cmd *cobra.Command, args []string) {
			err := MaintenanceActivate(0)
			if err != nil {
				os.Exit(1)
			} else {
				fmt.Println("The maintenance mode de-activated")
			}
		},
	}

	ccowdChannelRecvTimeout int
)

func init() {
	activateCmd.Flags().IntVarP(&ccowdChannelRecvTimeout, "timeout", "t", 60,
		"Maintenance timeout, minutes")
	maintainCmd.AddCommand(activateCmd)
	maintainCmd.AddCommand(deactivateCmd)
	SystemCmd.AddCommand(maintainCmd)
}
