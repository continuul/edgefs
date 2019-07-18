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
#include "errno.h"
*/
import "C"
import "unsafe"

import (
	"../efsutil"
	"../validate"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"strings"
)

func BucketList(cluster_tenant string, pat string, count int) error {
	s := strings.Split(cluster_tenant, "/")

	c_cluster := C.CString(s[0])
	defer C.free(unsafe.Pointer(c_cluster))

	c_tenant := C.CString(s[1])
	defer C.free(unsafe.Pointer(c_tenant))

	conf, err := efsutil.GetLibccowConf()
	if err != nil {
		return err
	}

	c_conf := C.CString(string(conf))
	defer C.free(unsafe.Pointer(c_conf))

	var tc C.ccow_t

	ret := C.ccow_tenant_init(c_conf, c_cluster, C.strlen(c_cluster)+1,
		c_tenant, C.strlen(c_tenant)+1, &tc)
	if ret != 0 {
		return fmt.Errorf("ccow_tenant_init err=%d", ret)
	}
	defer C.ccow_tenant_term(tc)

	c_pat := C.CString(pat)
	defer C.free(unsafe.Pointer(c_pat))

	var iter C.ccow_lookup_t

	ret = C.ccow_bucket_lookup(tc, c_pat, C.strlen(c_pat)+1, C.ulong(count), &iter)
	if ret != 0 {
		if iter != nil {
			C.ccow_lookup_release(iter)
		}

		if ret == -C.ENOENT && (pat == "" || len(pat) == 0) {
			return nil
		}

		return fmt.Errorf("bucket_lookup err=%d", ret)
	}

	found := 0
	var kv *C.struct_ccow_metadata_kv

	for {
		kv = (*C.struct_ccow_metadata_kv)(C.ccow_lookup_iter(iter, C.CCOW_MDTYPE_NAME_INDEX, -1))
		if kv == nil {
			break
		}
		if kv.key_size == 0 {
			continue
		}

		if pat == "" || len(pat) == 0 {
			found = 1
			if !efsutil.IsSystemName(C.GoString(kv.key)) {
				fmt.Println(C.GoString(kv.key))
			}
			continue
		}

		cmpRes := strings.Compare(pat, C.GoString(kv.key))
		if cmpRes == 0 {
			found = 1
			efsutil.PrintMD(C.GoString(kv.key), "", "", "")
		} else if cmpRes < 0 {
			found = 2
			efsutil.PrintMD(C.GoString(kv.key), "", "", "")
		}
	}

	C.ccow_lookup_release(iter)

	if found == 0 || (found == 2 && count == 1) {
		return fmt.Errorf("bucket_lookup err=%d", -C.ENOENT)
	}

	return nil
}

var (
	name string

	listCmd = &cobra.Command{
		Use:   "list <cluster>/<tenant>",
		Short: "list buckets",
		Long:  "list existing buckets",
		Args:  validate.Tenant,
		Run: func(cmd *cobra.Command, args []string) {
			err := BucketList(args[0], name, 1000)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	listCmd.Flags().StringVarP(&name, "name", "n", "", "Bucket Name filter")
	BucketCmd.AddCommand(listCmd)
}
