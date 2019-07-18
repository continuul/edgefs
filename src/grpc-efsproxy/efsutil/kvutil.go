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
package efsutil

/*
#include "ccow.h"
#include "ccowutil.h"
#include "errno.h"
*/
import "C"
import "unsafe"

import (
	"fmt"
	"strings"
)

func GetKeys(cl string, tn string, bk string, obj string) ([]string, error) {
	var res []string

	conf, err := GetLibccowConf()
	if err != nil {
		return nil, err
	}

	c_conf := C.CString(string(conf))
	defer C.free(unsafe.Pointer(c_conf))

	clempty := C.CString("")
	defer C.free(unsafe.Pointer(clempty))

	var tc C.ccow_t

	ret := C.ccow_admin_init(c_conf, clempty, 1, &tc)
	if ret != 0 {
		return nil, fmt.Errorf("ccow_admin_init err=%d", ret)
	}
	defer C.ccow_tenant_term(tc)

	c_cl := C.CString(cl)
	defer C.free(unsafe.Pointer(c_cl))

	c_tn := C.CString(tn)
	defer C.free(unsafe.Pointer(c_tn))

	c_bk := C.CString(bk)
	defer C.free(unsafe.Pointer(c_bk))

	c_obj := C.CString(obj)
	defer C.free(unsafe.Pointer(c_obj))

	var comp C.ccow_completion_t
	ret = C.ccow_create_completion(tc, nil, nil, 1, &comp)
	if ret != 0 {
		return nil, fmt.Errorf("%s: ccow_create_completion err=%d", GetFUNC(), ret)
	}

	var iov_name C.struct_iovec
	iov_name.iov_base = unsafe.Pointer(clempty)
	iov_name.iov_len = 1

	var iter C.ccow_lookup_t
	ret = C.ccow_admin_pseudo_get(c_cl, C.strlen(c_cl)+1, c_tn, C.strlen(c_tn)+1,
		c_bk, C.strlen(c_bk)+1, c_obj, C.strlen(c_obj)+1, &iov_name, 1, 1000, C.CCOW_GET_LIST,
		comp, &iter)
	if ret != 0 {
		C.ccow_release(comp)
		return nil, fmt.Errorf("%s: ccow_admin_pseudo_get err=%d", GetFUNC(), ret)
	}

	ret = C.ccow_wait(comp, 0)
	if ret == -C.ENOENT {
		return res, nil
	}
	if ret != 0 {
		return nil, fmt.Errorf("%s: ccow_wait err=%d", GetFUNC(), ret)
	}

	defer C.ccow_lookup_release(iter)
	var kv *C.struct_ccow_metadata_kv

	for {
		kv = (*C.struct_ccow_metadata_kv)(C.ccow_lookup_iter(iter,
			C.CCOW_MDTYPE_NAME_INDEX, -1))

		if kv == nil {
			break
		}
		if kv.key_size == 0 {
			continue
		}
		res = append(res, C.GoString(kv.key))
	}

	return res, nil
}

func GetMDPat(cl string, tn string, bk string, obj string, pat string) (map[string]string, error) {
        conf, err := GetLibccowConf()
        if err != nil {
                return nil, err
        }

        c_conf := C.CString(string(conf))
        defer C.free(unsafe.Pointer(c_conf))

        clempty := C.CString("")
        defer C.free(unsafe.Pointer(clempty))

        var tc C.ccow_t

        ret := C.ccow_admin_init(c_conf, clempty, 1, &tc)
        if ret != 0 {
                return nil, fmt.Errorf("ccow_admin_init err=%d", ret)
        }
        defer C.ccow_tenant_term(tc)

        c_cl := C.CString(cl)
        defer C.free(unsafe.Pointer(c_cl))

        c_tn := C.CString(tn)
        defer C.free(unsafe.Pointer(c_tn))

        c_bk := C.CString(bk)
        defer C.free(unsafe.Pointer(c_bk))

        c_obj := C.CString(obj)
        defer C.free(unsafe.Pointer(c_obj))

        var comp C.ccow_completion_t
        ret = C.ccow_create_completion(tc, nil, nil, 1, &comp)
        if ret != 0 {
                return nil,fmt.Errorf("%s: ccow_create_completion err=%d", GetFUNC(), ret)
        }

        var iter C.ccow_lookup_t
        ret = C.ccow_admin_pseudo_get(c_cl, C.strlen(c_cl)+1, c_tn, C.strlen(c_tn)+1,
                c_bk, C.strlen(c_bk)+1, c_obj, C.strlen(c_obj)+1, nil, 0, 0, C.CCOW_GET_LIST,
                comp, &iter)
        if ret != 0 {
                C.ccow_release(comp)
                return nil, fmt.Errorf("%s: ccow_admin_pseudo_get err=%d", GetFUNC(), ret)
        }

        ret = C.ccow_wait(comp, 0)
        if ret == -C.ENOENT {
                return nil, fmt.Errorf("Not found")
        }
        if ret != 0 {
                return nil, fmt.Errorf("%s: ccow_wait err=%d", GetFUNC(), ret)
        }
        defer C.ccow_lookup_release(iter)

        var kv *C.struct_ccow_metadata_kv

        props := make(map[string]string, 0)
        for {
                kv = (*C.struct_ccow_metadata_kv)(C.ccow_lookup_iter(iter,
                        C.CCOW_MDTYPE_METADATA|C.CCOW_MDTYPE_CUSTOM, -1))
                if kv == nil {
                        break
                }
                if kv.key_size == 0 {
                        continue
                }

                cmpRes := strings.HasPrefix(C.GoString(kv.key), pat)
                if !cmpRes {
                        continue
                }

                if kv._type == C.CCOW_KVTYPE_INT8 {
                        props[C.GoString(kv.key)] = fmt.Sprintf("%v", int(*(*C.char)(kv.value)))
                } else if kv._type == C.CCOW_KVTYPE_UINT8 {
                        props[C.GoString(kv.key)] = fmt.Sprintf("%v", uint(*(*C.uchar)(kv.value)))
                } else if kv._type == C.CCOW_KVTYPE_INT16 {
                        props[C.GoString(kv.key)] = fmt.Sprintf("%v", int(*(*C.short)(kv.value)))
                } else if kv._type == C.CCOW_KVTYPE_UINT16 {
                        props[C.GoString(kv.key)] = fmt.Sprintf("%v", uint(*(*C.ushort)(kv.value)))
                } else if kv._type == C.CCOW_KVTYPE_INT32 {
                        props[C.GoString(kv.key)] = fmt.Sprintf("%v", int(*(*C.int)(kv.value)))
                } else if kv._type == C.CCOW_KVTYPE_UINT32 {
                        props[C.GoString(kv.key)] = fmt.Sprintf("%v", uint(*(*C.uint)(kv.value)))
                } else if kv._type == C.CCOW_KVTYPE_INT64 {
                        props[C.GoString(kv.key)] = fmt.Sprintf("%v", int(*(*C.long)(kv.value)))
                } else if kv._type == C.CCOW_KVTYPE_UINT64 {
                        props[C.GoString(kv.key)] = fmt.Sprintf("%v", uint(*(*C.ulong)(kv.value)))
                } else if kv._type == C.CCOW_KVTYPE_RAW {
                        props[C.GoString(kv.key)] = fmt.Sprintf("%s", C.GoBytes((unsafe.Pointer)(kv.value), (C.int)(kv.value_size)))
                } else if kv._type == C.CCOW_KVTYPE_STR {
                        props[C.GoString(kv.key)] = fmt.Sprintf("%s", C.GoStringN((*C.char)(kv.value), (C.int)(kv.value_size)))
                } else if kv._type == C.CCOW_KVTYPE_UINT512 {
                        var vv [C.UINT512_BYTES*2 + 1]C.char
                        C.uint512_dump((*C.uint512_t)(kv.value), (*C.char)(&vv[0]), C.UINT512_BYTES*2+1)
                        props[C.GoString(kv.key)] = fmt.Sprintf("%s", C.GoStringN((*C.char)(&vv[0]), C.UINT512_BYTES))
                } else {
                        props[C.GoString(kv.key)] = fmt.Sprintf("%s", kv._type)
                }
        }

        return props, nil
}


