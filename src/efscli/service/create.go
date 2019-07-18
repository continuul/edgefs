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
package service

/*
#include "ccow.h"
*/
import "C"
import "unsafe"

import (
	"strconv"
	"../efsutil"
	"../validate"
	"hash/fnv"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"strings"
)

func ServiceCreate(stype string, sname string) error {
	service := C.CString(sname)
	defer C.free(unsafe.Pointer(service))

	conf, err := efsutil.GetLibccowConf()
	if err != nil {
		return err
	}

	c_conf := C.CString(string(conf))
	defer C.free(unsafe.Pointer(c_conf))

	cl := C.CString("")
	defer C.free(unsafe.Pointer(cl))

	svcs := C.CString("svcs")
	defer C.free(unsafe.Pointer(svcs))

	var tc C.ccow_t

	ret := C.ccow_admin_init(c_conf, cl, 1, &tc)
	if ret != 0 {
		return fmt.Errorf("ccow_admin_init err=%d", ret)
	}
	defer C.ccow_tenant_term(tc)

	ret = C.ccow_bucket_create(tc, service, C.strlen(service)+1, nil)
	if ret != 0 {
		return fmt.Errorf("service_create err=%d", ret)
	}

	if strings.Compare(stype, "nfs") == 0 {
		par := []efsutil.KeyValue{
			{"X-Service-Name", sname},
			{"X-Service-Type", stype},
			{"X-Description", "NFS Server"},
			{"X-Servers", "-"},
			{"X-Status", "disabled"},
			{"X-Auth-Type", "disabled"},
			{"X-MH-ImmDir", "1"},
			{"ccow-chunkmap-btree-marker", "1"},
		}
		return efsutil.UpdateMDMany("", "svcs", sname, "", par)
	}

	if strings.Compare(stype, "iscsi") == 0 {
		h := fnv.New32a()
		h.Write([]byte(sname))
		tid := int(h.Sum32() & 0xFFFF);
		par := []efsutil.KeyValue{
			{"X-Service-Name", sname},
			{"X-Service-Type", stype},
			{"X-Description", "iSCSI Target"},
			{"X-Servers", "-"},
			{"X-Status", "disabled"},
			{"X-ISCSI-Params", "{}"},
			{"X-ISCSI-TargetID", strconv.Itoa(tid)},
			{"X-ISCSI-TargetName", "iqn.2018-11.edgefs.io:"},
			{"X-ISCSI-AllowedInitiatorAddresses", "ALL"},
			{"ccow-chunkmap-btree-marker", "1"},
		}
		return efsutil.UpdateMDMany("", "svcs", sname, "", par)
	}

	if strings.Compare(stype, "s3x") == 0 {
		par := []efsutil.KeyValue{
			{"X-Service-Name", sname},
			{"X-Service-Type", stype},
			{"X-Description", "Edge-X S3 Object"},
			{"X-Servers", "-"},
			{"X-Status", "disabled"},
			{"X-Auth-Type", "disabled"},
			{"X-Need-MD5", "true"},
			{"X-List-Max-Size", "1000"},
			{"X-List-Cache", "true"},
			{"X-List-All-Buckets", "true"},
			{"X-ACL-On", "false"},
			{"X-HTTP-Port", "4000"},
			{"X-HTTPS-Port", "4443"},
			{"X-HTTPS-Key", "-"},
			{"X-HTTPS-Cert", "-"},
		}
		return efsutil.UpdateMDMany("", "svcs", sname, "", par)
	}

	if strings.Compare(stype, "swift") == 0 {
		par := []efsutil.KeyValue{
			{"X-Service-Name", sname},
			{"X-Service-Type", stype},
			{"X-Description", "Openstack/Swift"},
			{"X-Servers", "-"},
			{"X-Status", "disabled"},
			{"X-Auth-TTL", "600"},
			{"X-Need-MD5", "true"},
			{"X-ACL-On", "false"},
			{"X-List-Max-Size", "1000"},
			{"X-List-Cache", "true"},
			{"X-List-All-Buckets", "true"},
			{"X-HTTP-Port", "9981"},
			{"X-HTTPS-Port", "9442"},
			{"X-HTTPS-Key", "-"},
			{"X-HTTPS-Cert", "-"},
			{"X-Ciphers", "-"},
			{"X-Swift-Versioning", "disabled"},
			{"X-Trust-Proxy", "true"},
			{"X-Access-Log", "false"},
			{"X-Number-Of-Versions", "1"},
		}
		return efsutil.UpdateMDMany("", "svcs", sname, "", par)
	}

	if strings.Compare(stype, "s3s") == 0 {
		par := []efsutil.KeyValue{
			{"X-Service-Name", sname},
			{"X-Service-Type", stype},
			{"X-Description", "S3 Object DNS bucket style"},
			{"X-Region", "-"},
			{"X-Domain", "example.com"},
			{"X-Servers", "-"},
			{"X-Status", "disabled"},
			{"X-Auth-Type", "disabled"},
			{"X-Need-MD5", "true"},
			{"X-ACL-On", "false"},
			{"X-List-Max-Size", "1000"},
			{"X-List-Cache", "true"},
			{"X-List-All-Buckets", "true"},
			{"X-HTTP-Port", "9983"},
			{"X-HTTPS-Port", "9444"},
			{"X-HTTPS-Key", "-"},
			{"X-HTTPS-Cert", "-"},
			{"X-Ciphers", "-"},
			{"X-Default-Tenant", "-"},
			{"X-Default-Owner", "-"},
			{"X-Trust-Proxy", "true"},
			{"X-Access-Log", "false"},
			{"X-Number-Of-Versions", "1"},
		}
		return efsutil.UpdateMDMany("", "svcs", sname, "", par)
	}

	if strings.Compare(stype, "s3") == 0 {
		par := []efsutil.KeyValue{
			{"X-Service-Name", sname},
			{"X-Service-Type", stype},
			{"X-Description", "S3 Object"},
			{"X-Region", "-"},
			{"X-Servers", "-"},
			{"X-Status", "disabled"},
			{"X-Auth-Type", "disabled"},
			{"X-Need-MD5", "true"},
			{"X-ACL-On", "false"},
			{"X-List-Max-Size", "1000"},
			{"X-List-Cache", "true"},
			{"X-List-All-Buckets", "true"},
			{"X-HTTP-Port", "9982"},
			{"X-HTTPS-Port", "9443"},
			{"X-HTTPS-Key", "-"},
			{"X-HTTPS-Cert", "-"},
			{"X-Ciphers", "-"},
			{"X-Default-Tenant", "-"},
			{"X-Default-Owner", "-"},
			{"X-Trust-Proxy", "true"},
			{"X-Access-Log", "false"},
			{"X-Number-Of-Versions", "1"},
		}
		return efsutil.UpdateMDMany("", "svcs", sname, "", par)
	}

	if strings.Compare(stype, "isgw") == 0 {
		par := []efsutil.KeyValue{
			{"X-Service-Name", sname},
			{"X-Service-Type", stype},
			{"X-Description", "Inter Segment Gateway"},
			{"X-Auth-Type", "disabled"},
			{"X-Servers", "-"},
			{"X-Status", "disabled"},
			{"X-ISGW-Local", "-"},
			{"X-ISGW-DFLocal", "-"},
			{"X-ISGW-Remote", "-"},
			{"X-Container-Network", "-"},
			{"X-ISGW-Basic-Auth", "-"},
			{"X-ISGW-Direction", "-"},
			{"X-ISGW-Replication", "-"},
			{"X-ISGW-MDOnly", "-"},
			{"X-ISGW-Number-Of-Connections", "2"},
			{"X-ISGW-Encrypted-Tunnel", "-"},
		}
		return efsutil.UpdateMDMany("", "svcs", sname, "", par)
	}

	return fmt.Errorf("service_create invalid service")
}

var (
	createCmd = &cobra.Command{
		Use:   "create <type> <name>",
		Short: "create a new service",
		Long:  "create a new service of type: nfs, iscsi, s3, s3s, s3x, swift",
		Args:  validate.ServiceCreate,
		Run: func(cmd *cobra.Command, args []string) {
			err := ServiceCreate(args[0], args[1])
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	ServiceCmd.AddCommand(createCmd)
}
