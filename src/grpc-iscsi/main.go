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
package main

import (
	"log"
	"fmt"
	"time"
	"sync"
	"net"
	"strings"
	"os"
	"hash/fnv"
	"os/exec"
	"io"
	"bytes"
	"strconv"
	"encoding/json"

	"../efscli/efsutil"
	"./status"
	"./status/statusImpl"
	"./lun"
	"./lun/lunImpl"


	"github.com/pborman/getopt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var (
	release string
)

type logWriter struct {
}

func (writer logWriter) Write(bytes []byte) (int, error) {
	return fmt.Print(time.Now().UTC().Format("2006-01-02T15:04:05.999Z") + " " + string(bytes))
}


func main() {
	log.SetFlags(0)
	log.SetOutput(new(logWriter))

	serviceName := getopt.StringLong("service", 's', "", "Name of service")
	socket := getopt.StringLong("bind", 'b', "", "Bind to socket (default 0.0.0.0:49000)")
	optHelp := getopt.BoolLong("help", 0, "Help")
	getopt.Parse()

	if *optHelp {
		getopt.Usage()
		os.Exit(0)
	}

	ipnport := "0.0.0.0:49000"
	if ie := os.Getenv("EFSISCSI_BIND"); ie != "" {
		ipnport = ie
	}
	if *socket != "" {
		ipnport = *socket
	}

	if *serviceName == "" {
		log.Fatalf("No service name given")
		return
	}

	if !efsutil.CheckService(*serviceName) {
		log.Fatalf("Invalid gRPC service %s", *serviceName)
		return
	}

	InitGrpc(ipnport, *serviceName)
	InitIscsi(*serviceName, true)
}

// Server wraps the gRPC server
type Server struct {
	bind string
}

// New creates a new rpc server.
func New(bind string) *Server {
	return &Server{bind}
}

// Listen binds the server to the indicated interface:port.
func (s *Server) Listen() error {
	ln, err := net.Listen("tcp", s.bind)
	if err != nil {
		return err
	}
	gs := grpc.NewServer()
	status.RegisterStatusServer(gs, &statusImpl.StatusImpl{})
	lun.RegisterLunServer(gs, &lunImpl.LunImpl{})
	reflection.Register(gs)
	if release == "" {
		release = "dev"
	}
	log.Printf("iSCSI controller in version %v serving on %v is ready for gRPC clients", release, s.bind)
	return gs.Serve(ln)
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
		log.Fatalf("cmd.Start() failed with '%s'\n", err)
	}

	go func() {
		_, errStdout = io.Copy(stdout, stdoutIn)
	}()

	go func() {
		_, errStderr = io.Copy(stderr, stderrIn)
	}()

	err = cmd.Wait()
	if err != nil {
		log.Fatalf("cmd.Wait() failed with '%s'\n", err)
	}
}

func InitGrpc(ipnport, svc string) {

	log.Printf("starting gRPC ipnport=%s svc=%s\n", ipnport, svc)

	go func() {
		err := New(ipnport).Listen()
		if err != nil {
			log.Fatalf("Failed to launch the EFSISCSI due to %v", err)
		}
	}()
}

func InitIscsi(svc string, fgMode bool) {

	if fgMode {
		os.Setenv("CCOW_LOG_STDOUT", "1")
	}

	var PREFIX = os.Getenv("NEDGE_HOME")
	var RUNDIR = PREFIX + "/var/run"

	KUBERNETES_SERVICE_PREFIX := "rook-edgefs"

	serviceHostEnv := strings.ToUpper(KUBERNETES_SERVICE_PREFIX + "_iscsi_" + svc + "_service_host")
	serviceHostEnv = strings.Replace(serviceHostEnv, "-", "_", -1)

	portalPort := "3260"
	portalIP := "0.0.0.0"
	if envIP := os.Getenv(serviceHostEnv); envIP != "" {
		os.Setenv("TGT_PORTAL_OVERRIDE_ADDR", envIP)
	}

	var wg, wg2 sync.WaitGroup
	wg.Add(1)
	go func() {
		log.Printf("Starting tgtd for svc=%s portal=%s:%s\n", svc, portalIP, portalPort)
		wg.Done()
		wg2.Add(1)
		InitCmd("tgtd", []string{"-x" + RUNDIR, "-f",
		    "--iscsi", "portal="+ portalIP + ":" + portalPort})
		wg2.Done()
	}()
	wg.Wait()

	// give tgtd a chance to start
	time.Sleep(time.Second)

	log.Printf("Setting up iSCSI target svc=%s\n", svc)

	tid, err := efsutil.GetMDKey("", "svcs", svc, "", "X-ISCSI-TargetID")
	if err != nil {
		log.Fatalf(err.Error())
	}

	tname := "iqn.2018-11.edgefs.io"
	tname, _ = efsutil.GetMDKey("", "svcs", svc, "", "X-ISCSI-TargetName")
	if t := os.Getenv("EFSISCSI_TARGET_NAME"); t != "" {
		tname = t
	}

	if strings.HasSuffix(tname, ":") {
		tname = tname[:len(tname)-1]
	}

	// Apply targetName
        InitCmd("tgtadm", []string{"-x" + RUNDIR, "--lld", "iscsi", "--mode", "target",
	    "--op", "new", "--tid", tid, "-T", tname + ":" + tid})

	currentParamsJSON := "{}"
	currentParamsJSON, _ = efsutil.GetMDKey("", "svcs", svc, "", "X-ISCSI-Params")
	if p := os.Getenv("EFSISCSI_TARGET_PARAMS"); p != "" {
		currentParamsJSON = p
	}

	var currentParams map[string]interface{}
	json.Unmarshal([]byte(currentParamsJSON), &currentParams)

	defaultIntParams := map[string]int {
		"MaxRecvDataSegmentLength" : 524288,
		"DefaultTime2Retain" : 60,
		"DefaultTime2Wait" : 30,
		"FirstBurstLength" : 524288,
		"MaxBurstLength" : 1048576,
		"MaxQueueCmd" : 64,
	}

	for k, v := range defaultIntParams {
		for ck, cv := range currentParams {
			switch t := cv.(type) {
			case int:
				if k == ck {
					v = t
				}
			}
		}
		InitCmd("tgtadm", []string{"-x" + RUNDIR, "--lld", "iscsi", "--mode", "target",
		    "--op", "update", "--tid", tid, "-n", k, "-v", strconv.Itoa(v)})
	}

	defaultStrParams := map[string]string {
		"InitialR2T" : "No",
	}

	for k, v := range defaultStrParams {
		for ck, cv := range currentParams {
			switch t := cv.(type) {
			case string:
				if k == ck {
					v = t
				}
			}
		}
		InitCmd("tgtadm", []string{"-x" + RUNDIR, "--lld", "iscsi", "--mode", "target",
		    "--op", "update", "--tid", tid, "-n", k, "-v", v})
	}

	// TODO: implement
	//
	// X-ISCSI-AllowedInitiatorAddresses
	// X-ISCSI-AllowedInitiatorNames
	// X-ISCSI-Portal
	// X-ISCSI-ISNS
	// X-ISCSI-ISNS-Port
	// X-ISCSI-ISNS-AC
	// X-ISCSI-ISNS-Enable
	// X-ISCSI-AuthorizedUserList
	// X-ISCSI-AuthorizedUserPwds
	//

	// TODO: replace this with proper ACLs support
	InitCmd("tgtadm", []string{"-x" + RUNDIR, "--lld", "iscsi", "--mode", "target",
	    "--op", "bind", "--tid", tid, "-I", "ALL"})

	log.Printf("Loading serving objects for svc=%s\n", svc)

	keys, err := efsutil.GetKeys("", "svcs", svc, "", 10000)
	if err != nil {
		log.Fatalf(err.Error())
	}

	lunParams := "vendor_id=HPD,product_id=EDGEFS,product_rev=0000,removable=1,sense_format=0,thin_provisioning=1"

	for _, v := range keys {
		s := strings.Split(v, "@")
		id := s[0]
		path := s[1]

		s = strings.Split(path, "/")
		var cluster string = s[0]
		var tenant string = s[1]
		var bucket string = s[2]
		var object string = s[3]

		blkSize, err := efsutil.GetMDKey(cluster, tenant, bucket, object, "X-blocksize")
		if err != nil {
			log.Printf("Skipping LUN %s: cannot read X-blockSize key", path)
			continue
		}

		InitCmd("tgtadm", []string{"-x" + RUNDIR, "-C", "0", "--mode", "logicalunit",
		    "--op", "new", "--tid", tid, "--lun", id, "-b", path,
		    "--device-type", "disk", "--bstype", "ccowbd",
		    "--blocksize", blkSize})

		hpath := fnv.New64a()
		hpath.Write([]byte(path))

		scsi_id := fmt.Sprintf("%X", hpath.Sum64())
		scsi_sn := scsi_id[0:4] + "_" + object
		InitCmd("tgtadm", []string{"-x" + RUNDIR, "-C", "0", "--mode", "logicalunit",
		    "--op", "update", "--tid", tid, "--lun", id, "--params",
		    lunParams + ",scsi_id=" + scsi_id + ",scsi_sn=" + scsi_sn})

		log.Printf("Added LUN %s", v)
	}

	go func() {
		efsutil.K8sServiceUp(svc);
	}()

	wg2.Wait()
}
