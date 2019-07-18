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
package cluster

/*
#include "ccow.h"
*/
import "C"
import "unsafe"

import (
	"fmt"
	"os"

	"../efsutil"
	"../validate"
	"github.com/spf13/cobra"
)

func ClusterCreate(clname string, flags []efsutil.FlagValue) error {
	e := validate.Flags(flags)
	if e != nil {
		return e
	}

	conf, err := efsutil.GetLibccowConf()
	if err != nil {
		return err
	}

	c_conf := C.CString(string(conf))
	defer C.free(unsafe.Pointer(c_conf))

	cl := C.CString("")
	defer C.free(unsafe.Pointer(cl))

	var tc C.ccow_t

	ret := C.ccow_admin_init(c_conf, cl, 1, &tc)
	if ret != 0 {
		return fmt.Errorf("ccow_admin_init err=%d", ret)
	}
	defer C.ccow_tenant_term(tc)

	var c C.ccow_completion_t
	ret = C.ccow_create_completion(tc, nil, nil, 1, &c)
	if ret != 0 {
		return fmt.Errorf("ccow_create_completion err=%d", ret)
	}

	c_clname := C.CString(clname)
	defer C.free(unsafe.Pointer(c_clname))

	err = efsutil.ModifyDefaultAttributes(unsafe.Pointer(c), flags)
	if err != nil {
		return err
	}

	ret = C.ccow_cluster_create(tc, c_clname,
		C.strlen(c_clname)+1, c)
	if ret != 0 {
		return fmt.Errorf("Cluster create err=%d", ret)
	}

	return efsutil.ModifyCustomAttributes(clname, "", "", "", flags)
}

var (
	flags []efsutil.FlagValue
	flagNames = []string {
	 "replication-count",
	 "select-policy",
	 "ec-data-mode",
	 "ec-trigger-policy-timeout",
	 "options",
	}

	createCmd = &cobra.Command{
		Use:   "create <cluster>",
		Short: "create a new cluster namespace",
		Long:  "create a new cluster namespace, also known as 'region'",
		Args:  validate.Cluster,
		Run: func(cmd *cobra.Command, args []string) {
			err := ClusterCreate(args[0], flags)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	flags = make([]efsutil.FlagValue, len(flagNames))
	efsutil.ReadAttributes(createCmd, flagNames, flags)
	ClusterCmd.AddCommand(createCmd)
}
