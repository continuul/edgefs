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
*/
import "C"
import "unsafe"

import (
	"fmt"
	"strings"
	"strconv"
	"os"
)

type KeyValue struct {
	Key   string
	Value string
}

func UpdateMD(cl string, tn string, bk string, obj string, key string, value string) error {
	conf, err := GetLibccowConf()
	if err != nil {
		return err
	}

	// update with empty values not supported yet
	if value == "" {
		return nil
	}

	c_conf := C.CString(string(conf))
	defer C.free(unsafe.Pointer(c_conf))

	clempty := C.CString("")
	defer C.free(unsafe.Pointer(clempty))

	var tc C.ccow_t

	ret := C.ccow_admin_init(c_conf, clempty, 1, &tc)
	if ret != 0 {
		return fmt.Errorf("ccow_admin_init err=%d", ret)
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

	ret = C.ccow_range_lock(tc, c_bk, C.strlen(c_bk)+1, c_obj,
	    C.strlen(c_obj)+1, 0, 1, C.CCOW_LOCK_EXCL);
	if ret != 0 {
		return fmt.Errorf("%s: ccow_range_lock err=%d", GetFUNC(), ret)
	}

	defer C.ccow_range_lock(tc, c_bk, C.strlen(c_bk)+1, c_obj,
	                C.strlen(c_obj)+1, 0, 1, C.CCOW_LOCK_UNLOCK);

	var comp C.ccow_completion_t
	ret = C.ccow_create_completion(tc, nil, nil, 2, &comp)
	if ret != 0 {
		return fmt.Errorf("%s: ccow_create_completion err=%d", GetFUNC(), ret)
	}

	var iter C.ccow_lookup_t
	ret = C.ccow_admin_pseudo_get(c_cl, C.strlen(c_cl)+1, c_tn, C.strlen(c_tn)+1,
		c_bk, C.strlen(c_bk)+1, c_obj, C.strlen(c_obj)+1, nil, 0, 0, C.CCOW_GET,
		comp, &iter)
	if ret != 0 {
		C.ccow_release(comp)
		return fmt.Errorf("%s: ccow_admin_pseudo_get err=%d", GetFUNC(), ret)
	}

	ret = C.ccow_wait(comp, 0)
	if ret != 0 {
		return fmt.Errorf("%s: ccow_wait err=%d", GetFUNC(), ret)
	}

	c_key := C.CString(key)
	defer C.free(unsafe.Pointer(c_key))

	c_value := C.CString(value)
	defer C.free(unsafe.Pointer(c_value))

	ret = C.ccow_attr_modify_custom(comp, C.CCOW_KVTYPE_RAW,
		c_key, C.int(C.strlen(c_key)+1),
		unsafe.Pointer(c_value), C.int(C.strlen(c_value)), iter)
	if ret != 0 {
		return fmt.Errorf("%s: ccow_attr_modify_custom err=%d", GetFUNC(), ret)
	}

	ret = C.ccow_admin_pseudo_put(c_cl, C.strlen(c_cl)+1, c_tn, C.strlen(c_tn)+1,
		c_bk, C.strlen(c_bk)+1, c_obj, C.strlen(c_obj)+1, nil,
		0, 0, C.CCOW_PUT, nil, comp)
	if ret != 0 {
		C.ccow_release(comp)
		return fmt.Errorf("%s: ccow_admin_pseudo_put err=%d", GetFUNC(), ret)
	}

	ret = C.ccow_wait(comp, 1)
	if ret != 0 {
		return fmt.Errorf("%s: ccow_wait err=%d", GetFUNC(), ret)
	}

	defer C.ccow_lookup_release(iter)

	return nil
}

func UpdateMDMany(cl string, tn string, bk string, obj string, par []KeyValue) error {
	conf, err := GetLibccowConf()
	if err != nil {
		return err
	}

	c_conf := C.CString(string(conf))
	defer C.free(unsafe.Pointer(c_conf))

	clempty := C.CString("")
	defer C.free(unsafe.Pointer(clempty))

	var tc C.ccow_t

	ret := C.ccow_admin_init(c_conf, clempty, 1, &tc)
	if ret != 0 {
		return fmt.Errorf("ccow_admin_init err=%d", ret)
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

	ret = C.ccow_range_lock(tc, c_bk, C.strlen(c_bk)+1, c_obj,
	    C.strlen(c_obj)+1, 0, 1, C.CCOW_LOCK_EXCL);
	if ret != 0 {
		return fmt.Errorf("%s: ccow_range_lock err=%d", GetFUNC(), ret)
	}

	defer C.ccow_range_lock(tc, c_bk, C.strlen(c_bk)+1, c_obj,
	                C.strlen(c_obj)+1, 0, 1, C.CCOW_LOCK_UNLOCK);

	var comp C.ccow_completion_t
	ret = C.ccow_create_completion(tc, nil, nil, 2, &comp)
	if ret != 0 {
		return fmt.Errorf("%s: ccow_create_completion err=%d", GetFUNC(), ret)
	}

	var iter C.ccow_lookup_t
	ret = C.ccow_admin_pseudo_get(c_cl, C.strlen(c_cl)+1, c_tn, C.strlen(c_tn)+1,
		c_bk, C.strlen(c_bk)+1, c_obj, C.strlen(c_obj)+1, nil, 0, 0, C.CCOW_GET,
		comp, &iter)
	if ret != 0 {
		C.ccow_release(comp)
		return fmt.Errorf("%s: ccow_admin_pseudo_get err=%d", GetFUNC(), ret)
	}

	ret = C.ccow_wait(comp, 0)
	if ret != 0 {
		return fmt.Errorf("%s: ccow_wait err=%d", GetFUNC(), ret)
	}

	for i := 0; i < len(par); i++ {
		c_key := C.CString(par[i].Key)
		defer C.free(unsafe.Pointer(c_key))

		if par[i].Key == C.RT_SYSKEY_CHUNKMAP_BTREE_MARKER {
			u64, err := strconv.ParseUint(par[i].Value, 10, 8)
			if err != nil {
				return fmt.Errorf("%s: parse btree marker err=%d", GetFUNC(), ret)
			}
			var c_value uint8 = uint8(u64)
			ret = C.ccow_attr_modify_default(comp, C.CCOW_ATTR_BTREE_MARKER,
				unsafe.Pointer(&c_value), iter)
			if ret != 0 {
				return fmt.Errorf("%s: ccow_attr_modify_default err=%d", GetFUNC(), ret)
			}
		} else if par[i].Key == C.RT_SYSKEY_NUMBER_OF_VERSIONS {
			u64, err := strconv.ParseUint(par[i].Value, 10, 16)
			if err != nil {
				return fmt.Errorf("%s: parse number of versions err=%d", GetFUNC(), ret)
			}
			var c_value uint16 = uint16(u64)
			ret = C.ccow_attr_modify_default(comp, C.CCOW_ATTR_NUMBER_OF_VERSIONS,
				unsafe.Pointer(&c_value), iter)
			if ret != 0 {
				return fmt.Errorf("%s: ccow_attr_modify_default err=%d", GetFUNC(), ret)
			}
		} else {

			var c_valuePtr unsafe.Pointer
			var c_len C.int
			if par[i].Value != "" {
				c_value := C.CString(par[i].Value)
				c_valuePtr = unsafe.Pointer(c_value)
				c_len = C.int(C.strlen(c_value))
			}
			defer C.free(c_valuePtr)

			ret = C.ccow_attr_modify_custom(comp, C.CCOW_KVTYPE_RAW,
				c_key, C.int(C.strlen(c_key)+1),
				c_valuePtr, c_len, iter)
			if ret != 0 {
				return fmt.Errorf("%s: ccow_attr_modify_custom err=%d", GetFUNC(), ret)
			}
		}
	}

	ret = C.ccow_admin_pseudo_put(c_cl, C.strlen(c_cl)+1, c_tn, C.strlen(c_tn)+1,
		c_bk, C.strlen(c_bk)+1, c_obj, C.strlen(c_obj)+1, nil,
		0, 0, C.CCOW_PUT, nil, comp)
	if ret != 0 {
		C.ccow_release(comp)
		return fmt.Errorf("%s: ccow_admin_pseudo_put err=%d", GetFUNC(), ret)
	}

	ret = C.ccow_wait(comp, 1)
	if ret != 0 {
		return fmt.Errorf("%s: ccow_wait err=%d", GetFUNC(), ret)
	}

	defer C.ccow_lookup_release(iter)

	return nil
}

// Service calls this function after it is certain that it is up
// and running, so that we can update service metadata with dynamic info
func K8sServiceUp(sname string) error {
	if p := os.Getenv("KUBERNETES_SERVICE_HOST"); p == "" {
		return nil
	}
	var nodeName string
	if nodeName = os.Getenv("HOST_HOSTNAME"); nodeName == "" {
		return nil
	}
	osHostname, err := os.Hostname()
	if err != nil {
		return err
	}
	cnIpv6 := "-" // FIXME: serviceUtils.getBrockerIpv6addr();
	serverId, err := GetServerId()
	if err != nil {
		return err
	}

        par := []KeyValue{
                {"X-Status", "enabled"},
                {"X-ContainerIPv6-" + string(serverId), cnIpv6},
                {"X-Container-Hostname-" + string(serverId), nodeName},
                {"X-ContainerId-" + string(serverId), osHostname},
        }

	// clean up abandoned service props in case of pod restart or version update

	propsToCleanup := []string{"X-ContainerIPv6-", "X-Container-Hostname-", "X-ContainerId-"}
	serviceProps, err := GetMDPat("", "svcs", sname, "", "")
	if err != nil {
                return err
        }

	for propName, _ := range serviceProps {
		for _, prefix := range propsToCleanup {
			if strings.HasPrefix(propName, prefix) {
				par = append(par, KeyValue{propName, ""})
			}
		}
	}

	return UpdateMDMany("", "svcs", sname, "", par)
}
