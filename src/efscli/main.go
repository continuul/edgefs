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
package main

import (
	"fmt"
	"os"

	"github.com/Nexenta/edgefs/src/efscli/bucket"
	"github.com/Nexenta/edgefs/src/efscli/cluster"
	"github.com/Nexenta/edgefs/src/efscli/config"
	"github.com/Nexenta/edgefs/src/efscli/object"
	"github.com/Nexenta/edgefs/src/efscli/service"
	"github.com/Nexenta/edgefs/src/efscli/system"
	"github.com/Nexenta/edgefs/src/efscli/tenant"
	"github.com/Nexenta/edgefs/src/efscli/user"
	"github.com/Nexenta/edgefs/src/efscli/device"

	"github.com/spf13/cobra"
)

var efscliCmd = &cobra.Command{
	Use:   "efscli",
	Short: "EdgeFS CLI tool",
	Long:  "EdgeFS CLI tool",
}

func main() {
	efscliCmd.AddCommand(bucket.BucketCmd)
	efscliCmd.AddCommand(cluster.ClusterCmd)
	efscliCmd.AddCommand(object.ObjectCmd)
	efscliCmd.AddCommand(service.ServiceCmd)
	efscliCmd.AddCommand(system.SystemCmd)
	efscliCmd.AddCommand(tenant.TenantCmd)
	efscliCmd.AddCommand(config.ConfigCmd)
	efscliCmd.AddCommand(user.UserCmd)
	efscliCmd.AddCommand(device.DeviceCommand)

	if err := efscliCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
