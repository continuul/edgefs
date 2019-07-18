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
package bucket

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

func Show(bpath string) error {
	s := strings.Split(bpath, "/")
	err := efsutil.PrintMD(s[0], s[1], s[2], "")
	if err != nil {
		return err
	}
	nhid, e := efsutil.GetMDKey(s[0], s[1], s[2], "", "ccow-name-hash-id")
	if e == nil {
		efsutil.PrintMDCustom(s[0], s[1], s[2], nhid)
	}
	return nil
}

var (
	showCmd = &cobra.Command{
		Use:   "show <cluster>/<tenant>/<bucket>",
		Short: "show bucket",
		Long:  "show parameters of existing bucket",
		Args:  validate.Bucket,
		Run: func(cmd *cobra.Command, args []string) {
			err := Show(args[0])
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	BucketCmd.AddCommand(showCmd)
}
