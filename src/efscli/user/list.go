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
package user

/*
#include "ccow.h"
*/
import "C"

import (
	"fmt"
	"os"
	"strings"

	"../efsutil"
	"../validate"
	"github.com/spf13/cobra"
)

func ListUsers(tpath string, marker string) error {
	s := strings.Split(tpath, "/")
	return efsutil.ListUser(s[0], s[1], 1000, marker)
}

var (
	name string

	listCmd = &cobra.Command{
		Use:   "list <cluster>/<tenant>",
		Short: "list users",
		Long:  "list tenant users",
		Args:  validate.Tenant,
		Run: func(cmd *cobra.Command, args []string) {
			err := ListUsers(args[0], name)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	listCmd.Flags().StringVarP(&name, "name", "n", "", "User name filter")
	UserCmd.AddCommand(listCmd)
}
