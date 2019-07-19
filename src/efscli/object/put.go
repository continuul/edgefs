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

	"github.com/Nexenta/edgefs/src/efscli/efsutil"
	"github.com/Nexenta/edgefs/src/efscli/validate"
	"github.com/spf13/cobra"
)

func objectPut(opath string, fpath string, flags []efsutil.FlagValue) error {
	e := validate.Flags(flags)
	if e != nil {
		return e
	}

	c_fpath := C.CString(fpath)
	defer C.free(unsafe.Pointer(c_fpath))

	c_rb := C.CString("rb")
	defer C.free(unsafe.Pointer(c_rb))

	fp, err := C.fopen(c_fpath, c_rb)
	if err != nil {
		return fmt.Errorf("Read input file '%s' error: %v", fpath, err)
	}
	defer C.fclose(fp)

	c_opath := C.CString(opath)
	defer C.free(unsafe.Pointer(c_opath))

	s := strings.SplitN(opath, "/", 4)

	bucket, errb := efsutil.GetMDPat(s[0], s[1], s[2], "", "")
	if errb != nil {
		return errb
	}

	c_cluster := C.CString(s[0])
	defer C.free(unsafe.Pointer(c_cluster))

	c_tenant := C.CString(s[1])
	defer C.free(unsafe.Pointer(c_tenant))

	c_bucket := C.CString(s[2])
	defer C.free(unsafe.Pointer(c_bucket))

	c_object := C.CString(s[3])
	defer C.free(unsafe.Pointer(c_object))

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

	var c C.ccow_completion_t
	var cont_flags C.int = C.CCOW_CONT_F_REPLACE
	var max_io_count C.int = 50000
	var genid C.uint64_t = 0
	var n C.uint64_t
	var io_count C.int = 0
	var doff C.uint64_t = 0

	ret = C.ccow_create_stream_completion(tc, nil, nil, max_io_count, &c,
		c_bucket, C.strlen(c_bucket)+1, c_object, C.strlen(c_object)+1,
		&genid, &cont_flags, nil)
	if ret != 0 {
		return fmt.Errorf("ccow_create_stream_completion err=%d", ret)
	}

	err = efsutil.InheritBucketAttributes(unsafe.Pointer(c), bucket)
	if err != nil {
		return err
	}

	err = efsutil.ModifyDefaultAttributes(unsafe.Pointer(c), flags)
	if err != nil {
		return err
	}

	var chunk_size C.uint32_t = C.ccow_chunk_size(c)

	ret = C.ccow_attr_modify_default(c, C.CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
		unsafe.Pointer(&chunk_size), nil)

	ret = C.ccow_put_cont(c, nil, 0, 0, 1, &io_count)
	if ret != 0 {
		return fmt.Errorf("ccow_put_cont err=%d", ret)
	}

	var c_buf = C.malloc(C.ulong(chunk_size))
	defer C.free(unsafe.Pointer(c_buf))

	var iov C.struct_iovec

	for {
		n, _ = C.fread(unsafe.Pointer(c_buf), 1, C.ulong(chunk_size), fp)

		if n == 0 {
			break
		}

		iov.iov_base = unsafe.Pointer(c_buf)
		iov.iov_len = C.ulong(n)

		ret = C.ccow_put_cont(c, &iov, 1, doff, 1, &io_count)
		if ret != 0 {
			return fmt.Errorf("ccow_put_cont err=%d", ret)
		}

		ret = C.ccow_wait(c, io_count)
		if ret != 0 {
			return fmt.Errorf("ccow_wait err=%d", ret)
		}

		doff += n

		if io_count == max_io_count { // Reopen
			ret = C.ccow_finalize(c, nil)
			if ret != 0 {
				return fmt.Errorf("cannot finalize err=%d", ret)
			}
			io_count = 0

			ret = C.ccow_create_stream_completion(tc, nil, nil, max_io_count, &c,
				c_bucket, C.strlen(c_bucket)+1, c_object, C.strlen(c_object)+1,
				&genid, &cont_flags, nil)
			if ret != 0 {
				return fmt.Errorf("ccow_create_stream_completion err=%d", ret)
			}
		}
	}

	if io_count > 0 {
		ret = C.ccow_finalize(c, nil)
		if ret != 0 {
			return fmt.Errorf("cannot finalize err=%d", ret)
		}
	}

	if efsutil.HasCustomAttributes(flags) {
		return efsutil.ModifyCustomAttributes(s[0], s[1], s[2], s[3], flags)
	}

	return nil
}

var (
	flagsPut []efsutil.FlagValue

	putCmd = &cobra.Command{
		Use:   "put  <cluster>/<tenant>/<bucket>/<object> <file>",
		Short: "put a new object",
		Long:  "put a new object from file",
		Args:  validate.ObjectPutGet,
		Run: func(cmd *cobra.Command, args []string) {
			err := objectPut(args[0], args[1], flagsPut)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	flagsPut = make([]efsutil.FlagValue, len(flagNames))
	efsutil.ReadAttributes(putCmd, flagNames, flagsPut)
	ObjectCmd.AddCommand(putCmd)
}
