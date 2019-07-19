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
package tenant

/*
#include "ccow.h"
*/
import "C"
import "unsafe"

import (
	"github.com/Nexenta/edgefs/src/efscli/efsutil"
	"github.com/Nexenta/edgefs/src/efscli/validate"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"strings"
)

func TenantCreate(name string, flags []efsutil.FlagValue) error {
	e := validate.Flags(flags)
	if e != nil {
		return e
	}
	s := strings.Split(name, "/")

	cluster := C.CString(s[0])
	defer C.free(unsafe.Pointer(cluster))

	tenant := C.CString(s[1])
	defer C.free(unsafe.Pointer(tenant))

	conf, err := efsutil.GetLibccowConf()
	if err != nil {
		return err
	}

	c_conf := C.CString(string(conf))
	defer C.free(unsafe.Pointer(c_conf))

	var tc C.ccow_t

	ret := C.ccow_admin_init(c_conf, cluster, C.strlen(cluster)+1, &tc)
	if ret != 0 {
		return fmt.Errorf("ccow_admin_init err=%d", ret)
	}
	defer C.ccow_tenant_term(tc)

	var c C.ccow_completion_t
	ret = C.ccow_create_completion(tc, nil, nil, 1, &c)
	if ret != 0 {
		return fmt.Errorf("Tenant creare ccow_create_completion err=%d", ret)
	}

	err = efsutil.ModifyDefaultAttributes(unsafe.Pointer(c), flags)
	if err != nil {
		return err
	}

	ret = C.ccow_tenant_create(tc, tenant, C.strlen(tenant)+1, c)
	if ret != 0 {
		return fmt.Errorf("Tenant create err=%d", ret)
	}

	return efsutil.ModifyCustomAttributes(s[0], s[1], "", "", flags)
}

var (
	flags []efsutil.FlagValue
	flagNames = []string {
	 "replication-count",
	 "number-of-versions",
	 "sync-put",
	 "ec-data-mode",
	 "ec-trigger-policy-timeout",
	 "encryption-enabled",
	 "select-policy",
	 "options",
	}

	createCmd = &cobra.Command{
		Use:   "create <cluster>/<tenant>",
		Short: "create a new tenant namespace",
		Long:  "create a new tenant namespace, defined as cluster/tenant",
		Args:  validate.Tenant,
		Run: func(cmd *cobra.Command, args []string) {
			err := TenantCreate(args[0], flags)
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
	TenantCmd.AddCommand(createCmd)
}
