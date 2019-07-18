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
package lunImpl

import (
        "log"
        "fmt"
        "strings"
        "os"
        "hash/fnv"
        "os/exec"
        "io"
        "bytes"

	"../../../efscli/efsutil"

	proto ".."
	"golang.org/x/net/context"
)

var (
	PREFIX = os.Getenv("NEDGE_HOME")
	RUNDIR = PREFIX + "/var/run"
)

type LunImpl struct {
}

func InitCmd(progname string, args []string) {
        var stdoutBuf, stderrBuf bytes.Buffer

        log.Printf("starting %s %+v\n", progname, args)

        cmd := exec.Command(progname, args...)

        stdoutIn, _ := cmd.StdoutPipe()
        stderrIn, _ := cmd.StderrPipe()

        var errStdout, errStderr error
        stdout := io.MultiWriter(os.Stdout, &stdoutBuf)
        stderr := io.MultiWriter(os.Stderr, &stderrBuf)
        err := cmd.Start()

        if err != nil {
                log.Fatalf("rpc.statd: cmd.Start() failed with '%s'\n", err)
        }

        go func() {
                _, errStdout = io.Copy(stdout, stdoutIn)
        }()

        go func() {
                _, errStderr = io.Copy(stderr, stderrIn)
        }()

        err = cmd.Wait()
        if err != nil {
                log.Fatalf("rpc.statd: cmd.Wait() failed with '%s'\n", err)
        }
}

func (s *LunImpl) AddLun(ctx context.Context, msg *proto.LunRequest) (*proto.GenericResponse, error) {
	var err error

	log.Printf("AddLun request: %+v", *msg)
	lunParams := "vendor_id=HPD,product_id=EDGEFS,product_rev=0000,removable=1,sense_format=0,thin_provisioning=1"

	objectPath := fmt.Sprintf("%s/%s/%s/%s", msg.Cluster, msg.Tenant, msg.Bucket, msg.Object)
	volumePath := fmt.Sprintf("%d@%s", msg.LunNumber, objectPath)

	tid, err := efsutil.GetMDKey("", "svcs", msg.Service, "", "X-ISCSI-TargetID")
        if err != nil {
                log.Fatalf(err.Error())
        }

        tname := "iqn.2018-11.edgefs.io"
        tname, _ = efsutil.GetMDKey("", "svcs", msg.Service, "", "X-ISCSI-TargetName")
        if t := os.Getenv("EFSISCSI_TARGET_NAME"); t != "" {
                tname = t
        }

        if strings.HasSuffix(tname, ":") {
                tname = tname[:len(tname)-1]
        }

	blkSize, err := efsutil.GetMDKey(msg.Cluster, msg.Tenant, msg.Bucket, msg.Object, "X-blocksize")
	if err != nil {
		log.Printf("Skipping LUN %s: cannot read X-blockSize key", objectPath)
		return &proto.GenericResponse{}, fmt.Errorf("Can't get X-blocksize value for %s", volumePath)
	}

	InitCmd("tgtadm", []string{"-x" + RUNDIR, "-C", "0", "--mode", "logicalunit",
		"--op", "new", "--tid", tid, "--lun", fmt.Sprintf("%d", msg.LunNumber), "-b", objectPath,
		"--device-type", "disk", "--bstype", "ccowbd",
		"--blocksize", blkSize})

	hpath := fnv.New64a()
	hpath.Write([]byte(objectPath))

	InitCmd("tgtadm", []string{"-x" + RUNDIR, "-C", "0", "--mode", "logicalunit",
		"--op", "update", "--tid", tid, "--lun", fmt.Sprintf("%d", msg.LunNumber), "--params",
		lunParams + ",scsi_id=" + fmt.Sprintf("%X", hpath.Sum64())})

	log.Printf("Added LUN %s", volumePath)

	if err == nil {
		return &proto.GenericResponse{}, nil
	} else {
		return nil, err
	}
}

func (s *LunImpl) RemoveLun(ctx context.Context, msg *proto.LunRequest) (*proto.GenericResponse, error) {

        tid, err := efsutil.GetMDKey("", "svcs", msg.Service, "", "X-ISCSI-TargetID")
        if err != nil {
                log.Fatalf(err.Error())
        }


	InitCmd("tgtadm", []string{"-x" + RUNDIR, "-C", "0", "--mode", "logicalunit",
                "--op", "delete", "--tid", tid, "--lun", fmt.Sprintf("%d", msg.LunNumber)})


	if err == nil {
		return &proto.GenericResponse{}, nil
	} else {
		return nil, err
	}
}
