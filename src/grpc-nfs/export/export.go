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
package export

import (
	"../../efscli/efsutil"
	"bufio"
	"fmt"
	"golang.org/x/net/context"
	"io/ioutil"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
)

var PREFIX = "/opt/nedge/"
var exportsList = PREFIX + "etc/ganesha/exportslist"
var exportsDir = PREFIX + "etc/ganesha/exports/"

type ExportImpl struct {
}

func ganeshaCommand(cmd string) ([]string, error) {
	var data []string

	conn, err := net.Dial("tcp", "127.0.0.1:980")
	if err != nil {
		// handle error
		log.Printf("cannot connect to nfs-ganesha daemon: %v", err)
		return nil, err
	}

	fmt.Fprintf(conn, cmd)

	connbuf := bufio.NewReader(conn)
	for {
		str, err := connbuf.ReadString('\n')
		if len(str) > 0 {
			data = append(data, str)
			if cmd != "EXPORT LIST\r\n" {
				// Only EXPORT LIST is multiline.
				break
			}
		}
		if err != nil {
			break
		}
		if str[0] == '.' {
			break
		}
	}
	conn.Close()

	return data, err
}

func (s *ExportImpl) ExportAdd(ctx context.Context, msg *ExportRequest) (*GenericResponse, error) {
	err := LocalExportAdd(msg.Service, msg.Cluster, msg.Tenant, msg.Bucket, msg.ExportId, true)

	if err == nil {
		return &GenericResponse{}, nil
	} else {
		return nil, err
	}
}

func getServiceValue(Service string, Key string) (string, error) {
	str, err := efsutil.GetMDKey("", "svcs", Service, "", Key)
	if err.Error() == "Key not found" {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return str, nil
}

func getAclBlock(Service string, Cluster string, Tenant string, Bucket string, export_config *string) error {
	var permissions = ""
	var exportOpts = "" // "RW=10.9.8.7 RO=*"

	// Check not standard value for compat
	acl, err := getServiceValue(Service, "X-NFS-ACL-"+Tenant+"/"+Bucket)
	if err != nil {
		return err
	}

	exportOpts = acl

	// default, high priority
	acl, err = getServiceValue(Service, "X-NFS-ACL-"+Tenant+"-"+Bucket)
	if err != nil {
		return err
	}
	if acl != "" {
		exportOpts = acl
	}

	// Service value, override per export, highest priority
	acl, err = getServiceValue(Service, "X-NFS-ACL")
	if err != nil {
		return err
	}
	if acl != "" {
		exportOpts = acl
	}

	if exportOpts != "" {
		spcRe := regexp.MustCompile(`\s+`)
		permList := spcRe.Split(exportOpts, -1)
		for _, line := range permList {
			items := strings.Split(line, "=")
			if len(items) != 2 || items[1] == "" {
				log.Printf("Invalid NFS permission: %s", line)
				continue
			}
			permType := strings.ToUpper(items[0])
			if permType != "RW" && permType != "RO" && permType != "NONE" {
				log.Printf("Invalid NFS access type: %s. It must be one of RW, RO or NONE", permType)
				continue
			}

			clientList := strings.Replace(items[1], ":", ",", -1)

			permissions +=
				"    CLIENT {\n" +
					"        Clients = " + clientList + ";\n" +
					"        Access_Type = " + permType + ";\n" +
					"        anonymous_uid = 65536;\n" +
					"        anonymous_gid = 65536;\n" +
					"    }\n"
		}
		*export_config = strings.Replace(*export_config, "Access_Type = RW;", "Access_Type = NONE;", 1)
	}

	// add default permissions if nothing is set by a caller
	if permissions == "" {
		permissions +=
			"    CLIENT {\n" +
				"        Clients = *;\n" +
				"        Access_Type = RW;\n" +
				"        anonymous_uid = 65536;\n" + // XXX
				"        anonymous_gid = 65536;\n" + // XXX
				"    }\n"
	}
	*export_config += permissions

	return nil
}

func LocalExportAdd(Service string, Cluster string, Tenant string, Bucket string, ExportId uint32, dynamic bool) error {
	var exportPath = Tenant + "/" + Bucket
	var filePath = Cluster + "-" + Tenant + "-" + Bucket
	var exportUri = Cluster + "/" + Tenant + "/" + Bucket

	var export_config = "EXPORT {\n" +
		"    Export_Id = " + fmt.Sprintf("%d", ExportId) + ";\n" +
		"    Path = \"/" + exportPath + "\";\n" +
		"    Pseudo = \"/" + exportPath + "\";\n" +
		"    Access_Type = RW;\n" +
		"    Squash = No_root_squash;\n" +
		"    Protocols = 3;\n" +
		"    MaxRead = 1048576;\n" +
		"    MaxWrite = 1048576;\n" +
		"    PrefRead = 1048576;\n" +
		"    PrefWrite = 1048576;\n" +
		"    FSAL {\n" +
		"        Name = NEDGE;\n" +
		"        ccow_config = \"" + PREFIX + "etc/ccow/ccow.json\";\n" +
		"        uri = \"" + exportUri + "\";\n" +
		"    }\n"

	err := getAclBlock(Service, Cluster, Tenant, Bucket, &export_config)

	export_config += "}\n"

	err = ioutil.WriteFile(exportsDir+filePath, []byte(export_config), 0644)
	if err != nil {
		// handle error
		log.Printf("cannot write to file: %v", err)
		return err
	}

	if dynamic {
		// Add export to online ganesha first, to let to decide if it correct
		_, err = ganeshaCommand("EXPORT ADD " + fmt.Sprintf("%d", ExportId) +
			" " + exportsDir + filePath + "\r\n")
		if err != nil { // XXX check for "ERR" response too
			// handle error
			log.Printf("cannot add export to nfs-ganesha daemon: %v", err)
			return err
		}
	}

	// Then append to list of includes
	explist, err := os.OpenFile(exportsList, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		// handle error
		log.Printf("cannot open export list file: %v", err)
		return err
	}
	defer explist.Close()

	_, err = explist.WriteString("%include " + exportsDir + filePath + "\n")
	if err != nil {
		// handle error
		log.Printf("cannot write to exportlist file: %v", err)
		return err
	}

	return nil
}

func (s *ExportImpl) ExportRemove(ctx context.Context, msg *ExportRequest) (*GenericResponse, error) {
	err := LocalExportRemove(msg.Service, msg.Cluster, msg.Tenant, msg.Bucket, msg.ExportId)

	if err == nil {
		return &GenericResponse{}, nil
	} else {
		return nil, err
	}
}

func LocalExportRemove(Service string, Cluster string, Tenant string, Bucket string, ExportId uint32) error {
	var filePath = Cluster + "-" + Tenant + "-" + Bucket

	// Offline export
	_, err := ganeshaCommand("EXPORT REMOVE " + fmt.Sprintf("%d", ExportId) + "\r\n")
	if err != nil {
		// handle error
		log.Printf("cannot remove export from nfs-ganesha daemon: %v", err)
		return err
	}

	// Remove export from exportslist
	explist, err := os.OpenFile(exportsList, os.O_RDWR, 0644)
	if err != nil {
		// handle error
		log.Printf("cannot open exportslist file: %v", err)
		return err
	}

	matchline := "%include " + exportsDir + filePath
	var lines []string
	scanner := bufio.NewScanner(explist)
	for scanner.Scan() {
		line := scanner.Text()
		if line != matchline {
			lines = append(lines, line)
		}
	}
	explist.Seek(0, 0)

	err = explist.Truncate(0)
	if err != nil {
		// handle error
		log.Printf("cannot truncate exportslist file: %v", err)
		return err
	}
	explist.Sync()

	for _, line := range lines {
		fmt.Fprintf(explist, "%s\n", line)
	}
	explist.Sync()
	explist.Close()

	// Remove export config file
	os.Remove(exportsDir + filePath)

	return nil
}

func (s *ExportImpl) ganeshaExportsList() ([]string, error) {
	data, err := ganeshaCommand("EXPORT LIST\r\n")
	if err != nil {
		// handle error
		return nil, err
	}
	return data[1:(len(data) - 1)], err
}

func (s *ExportImpl) ExportList(ctx context.Context, msg *ExportListRequest) (*ExportListResponse, error) {

	list, err := s.ganeshaExportsList()

	if err != nil {
		return nil, err
	}

	info := make(map[string]*ExportInfo)

	for _, export := range list {
		info[export] = &ExportInfo{Name: export}
	}

	return &ExportListResponse{Info: info}, nil
}
