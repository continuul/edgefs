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

/*
#include "ccow.h"
*/
import "C"
import "unsafe"

import (
	"github.com/Nexenta/edgefs/src/efscli/efsutil"
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

func SystemInit() error {
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

	var guid *C.char
	guid = C.ccow_get_system_guid_formatted(tc)

	if guid == nil {
		fmt.Printf("\n" +
		           "System Initialization\n" +
		           "=====================\n\n" +
		           "Please review auto discovered FlexHash Table:\n\n")
		err := PrintFHTable(false)
		if err != nil {
			return err
		}

		fmt.Printf("\n");
		err = SystemCPSet(0, forceConfirm)
		if err != nil {
			return err
		}
	} else {
		fmt.Println("Already initialized\n")
		fmt.Println("System GUID:", C.GoString(guid))
	}

	ret = C.ccow_system_init(tc)
	if ret != 0 {
		return fmt.Errorf("ccow_system_init err=%d", ret)
	}

	guid = C.ccow_get_system_guid_formatted(tc)

	fmt.Println("System GUID:", C.GoString(guid))

	return nil
}

var (
	InitCmd = &cobra.Command{
		Use:   "init",
		Short: "initialize physical cluster",
		Long:  "initialize physical cluster",
		Run: func(cmd *cobra.Command, args []string) {
			err := SystemInit()
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	InitCmd.Flags().BoolVarP(&forceConfirm, "force-confirm", "f", false, "avoid interactive confirmations")

	SystemCmd.AddCommand(InitCmd)
}
