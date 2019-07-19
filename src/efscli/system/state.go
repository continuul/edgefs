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
#include "errno.h"
#include "ccow.h"
#include "auditd.h"
#include "private/trlog.h"
*/
import "C"
import "unsafe"

import (
	"fmt"
	"time"
	"github.com/Nexenta/edgefs/src/efscli/efsutil"
	"github.com/spf13/cobra"
	"os"
)

func SystemState(timeout int) int {
	ch := make(chan int, 1)

	go func () {
		count := 1000
		conf, err := efsutil.GetLibccowConf()
		if err != nil {
			ch <- -100
			return
		}
	
		c_conf := C.CString(string(conf))
		defer C.free(unsafe.Pointer(c_conf))
	
		cl := C.CString("")
		defer C.free(unsafe.Pointer(cl))
	
		var tc C.ccow_t
	
		ret := C.ccow_admin_init(c_conf, cl, 1, &tc)
		if ret != 0 {
			ch <- -101
			return
		}

		defer C.ccow_tenant_term(tc)
	
		c_pat := C.CString("")
		defer C.free(unsafe.Pointer(c_pat))
	
		var iter C.ccow_lookup_t
		ret = C.ccow_cluster_lookup(tc, c_pat, C.strlen(c_pat)+1, C.ulong(count), &iter)
		if iter != nil {
			C.ccow_lookup_release(iter)
		}
		ch <- int(ret)
	}()
	
	rc := 0

	select {
		case res := <-ch:
			if res == 0 {
				fmt.Printf("Alive.\n")
			} else if res == -2 {
				fmt.Printf("Alive. Not initialized.\n")
			} else {
				fmt.Printf("Dead. Error code %v.\n", res)
				rc = 1
			}
		case <-time.After(time.Duration(timeout) * time.Second):
			fmt.Printf("Dead. Communication timeout.\n")
			rc = 1
	}
	return rc
}

var (
	StateCmd = &cobra.Command{
		Use:   "state",
		Short: "show container liveness status",
		Long:  "show container liveness status",
		Run: func(cmd *cobra.Command, args []string) {
			err := SystemState(15)
			os.Exit(err)
		},
	}
)

func init() {
	SystemCmd.AddCommand(StateCmd)
}
