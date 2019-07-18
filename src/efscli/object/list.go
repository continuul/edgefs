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
package object

/*
#include "ccow.h"
*/
import "C"

import (
	"../efsutil"
	"../validate"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"strings"
)

func List(bpath string, name string) error {
	s := strings.Split(bpath, "/")
	var last string = name
	var cmp int = 0
	for {
		next, err := efsutil.PrintKeyValues(s[0], s[1], s[2], "", last, cmp, 1000, extended)
		if err != nil {
			return err
		}
		if next == "" || next <= last {
			break
		}
		last = next
		cmp = 1
	}
	return nil
}

var (
	name string
	extended bool

	listCmd = &cobra.Command{
		Use:   "list  <cluster>/<tenant>/<bucket>",
		Short: "list objects",
		Long:  "list bucket objects",
		Args:  validate.Bucket,
		Run: func(cmd *cobra.Command, args []string) {
			err := List(args[0], name)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	listCmd.Flags().StringVarP(&name, "name", "n", "", "Object Namespace filter")
	listCmd.Flags().BoolVarP(&extended, "ext", "x", false, "Show extended object information")
	ObjectCmd.AddCommand(listCmd)
}
