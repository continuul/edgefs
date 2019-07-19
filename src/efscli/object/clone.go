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
#include <stdio.h>
#include "ccow.h"
*/
import "C"
import "unsafe"

import (
	"fmt"
	"os"
	"strings"
	"strconv"

	"github.com/Nexenta/edgefs/src/efscli/efsutil"
	"github.com/Nexenta/edgefs/src/efscli/validate"
	"github.com/spf13/cobra"
)

func objectClone(srcpath string, dstpath string, flags []efsutil.FlagValue) error {
	e := validate.Flags(flags)
	if e != nil {
		return e
	}

	s := strings.SplitN(srcpath, "/", 4)
	d := strings.SplitN(dstpath, "/", 4)

	if s[0] != d[0] {
		return fmt.Errorf("Cross-cluster clone isn't supported")
	}

	bucket, errb := efsutil.GetMDPat(d[0], d[1], d[2], "", "")
	if errb != nil {
		return errb
	}

	c_cluster_s := C.CString(s[0])
	defer C.free(unsafe.Pointer(c_cluster_s))

	c_tenant_s := C.CString(s[1])
	defer C.free(unsafe.Pointer(c_tenant_s))

	c_bucket_s := C.CString(s[2])
	defer C.free(unsafe.Pointer(c_bucket_s))

	c_object_s := C.CString(s[3])
	defer C.free(unsafe.Pointer(c_object_s))

	c_cluster_d := C.CString(d[0])
	defer C.free(unsafe.Pointer(c_cluster_d))

	c_tenant_d := C.CString(d[1])
	defer C.free(unsafe.Pointer(c_tenant_d))

	c_bucket_d := C.CString(d[2])
	defer C.free(unsafe.Pointer(c_bucket_d))

	c_object_d := C.CString(d[3])
	defer C.free(unsafe.Pointer(c_object_d))


	conf, err := efsutil.GetLibccowConf()
	if err != nil {
		return err
	}

	c_conf := C.CString(string(conf))
	defer C.free(unsafe.Pointer(c_conf))

	var tc C.ccow_t

	ret := C.ccow_tenant_init(c_conf, c_cluster_s, C.strlen(c_cluster_s)+1,
		c_tenant_s, C.strlen(c_tenant_s)+1, &tc)
	if ret != 0 {
		return fmt.Errorf("ccow_tenant_init err=%d", ret)
	}
	defer C.ccow_tenant_term(tc)

	var c C.ccow_completion_t	
	ret = C.ccow_create_completion(tc, nil, nil, 2, &c);
	/* Fetch metadata of the source object */
	ret = C.ccow_get(c_bucket_s, C.strlen(c_bucket_s)+1, c_object_s,
		C.strlen(c_object_s)+1, c, nil, 0, 0, nil);
	if ret != 0 {
		return fmt.Errorf("ccow_get err=%d", ret)
	}
	ret = C.ccow_wait(c, 0);
	if ret != 0 {
		return fmt.Errorf("ccow_wait error %d", err)
	}
	repCntStr,err := efsutil.CompletionAttribute(unsafe.Pointer(c), "replication-count")
	if err != nil {
		return fmt.Errorf("completionAttribute error %d", err)
	}

	origRC, err := strconv.Atoi(repCntStr)
	if err != nil {
		return fmt.Errorf("Wrong replication count value %v", repCntStr)
	}
	/* Inherrite from bucket */
	err = efsutil.InheritBucketAttributes(unsafe.Pointer(c), bucket)
	if err != nil {
		return err
	}

	/* Override by a user-provided default metadata */
	err = efsutil.ModifyDefaultAttributes(unsafe.Pointer(c), flags)
	if err != nil {
		return err
	}

	/* Verify iheritted/overriden metadata settings */
	repCntStr,err = efsutil.CompletionAttribute(unsafe.Pointer(c), "replication-count")
	if err != nil {
		return fmt.Errorf("completionAttribute error %d", err)
	}

	tgtRC, err := strconv.Atoi(repCntStr)
	if err != nil {
		return fmt.Errorf("Wrong replication count value %v", repCntStr)
	}

	var m efsutil.ECMode
	val,_ := efsutil.CompletionAttribute(unsafe.Pointer(c), "ec-enabled")
	if val == "1" {
		val,_ = efsutil.CompletionAttribute(unsafe.Pointer(c), "ec-data-mode")
		modeCode, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("Invalid ec-data-mode code string %v", val)
		}
		err = m.Decode(modeCode)
		if err != nil {
			return err
		}
	}

	if origRC != tgtRC {
		return fmt.Errorf("Clone operation isn't allowed to change replication count: object rc %v, bucket rc %v",
			origRC, tgtRC)
	} else if m.DodecID > 0 && m.Parity + 1 != origRC {
			return fmt.Errorf("Requested EC format %v doesn't match object's replication count %v.\n"+
			"	Expected number of parity chunks has to be %v", m.String(), origRC, origRC - 1)
	}

	// Preparing copy options

	var opts C.struct_ccow_copy_opts
	opts.tid = c_tenant_d
	opts.tid_size = C.strlen(c_tenant_d) + 1
	opts.bid = c_bucket_d
	opts.bid_size = C.strlen(c_bucket_d) + 1
	opts.oid = c_object_d
	opts.oid_size = C.strlen(c_object_d) + 1
	opts.genid = nil
	opts.version_vm_content_hash_id = nil
	opts.vm_chid = nil
	opts.md_override = 1;

	ret = C.ccow_clone(c, c_tenant_s, C.strlen(c_tenant_s)+1, c_bucket_s,
		C.strlen(c_bucket_s)+1, c_object_s, C.strlen(c_object_s) + 1, &opts)

	if ret != 0 {
		C.ccow_release(c)
		return fmt.Errorf("ccow_clone error %d", err)
	}

	ret = C.ccow_wait(c, 1);
	if ret != 0 {
		return fmt.Errorf("ccow_wait error %d", err)
	}

	if efsutil.HasCustomAttributes(flags) {
		return efsutil.ModifyCustomAttributes(s[0], s[1], s[2], s[3], flags)
	}

	return nil
}

var (
	flagsClone []efsutil.FlagValue

	cloneCmd = &cobra.Command{
		Use:   "clone  <cluster>/<tenant>/<bucket>/<object> <cluster>/<tenant>/<bucket>/<object>",
		Short: "clone an object",
		Long:  "clone an object from another",
		Args:  validate.ObjectClone,
		Run: func(cmd *cobra.Command, args []string) {
			err := objectClone(args[0], args[1], flagsClone)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	flagsClone = make([]efsutil.FlagValue, len(flagNames))
	efsutil.ReadAttributes(cloneCmd, flagNames, flagsClone)
	ObjectCmd.AddCommand(cloneCmd)
}


