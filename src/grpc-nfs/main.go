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
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"../efscli/efsutil"
	"./export"

	"github.com/pborman/getopt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var (
	release string
)

var PREFIX = "/opt/nedge/"
var exportsList = PREFIX + "etc/ganesha/exportslist"

type logWriter struct {
}

func (writer logWriter) Write(bytes []byte) (int, error) {
	return fmt.Print(time.Now().UTC().Format("2006-01-02T15:04:05.999Z") + " " + string(bytes))
}

func main() {
	log.SetFlags(0)
	log.SetOutput(new(logWriter))

	serviceName := getopt.StringLong("service", 's', "", "Name of service")
	socket := getopt.StringLong("bind", 'b', "", "Bind to socket")
	hostRpc := getopt.BoolLong("hostrpc", 0, "Do not start rpcbind and rpc.statd, use host provided /var/run/rpcbind.sock")
	optHelp := getopt.BoolLong("help", 0, "Help")
	getopt.Parse()

	if *optHelp {
		getopt.Usage()
		os.Exit(0)
	}

	ipnport := "0.0.0.0:49000"
	if ie := os.Getenv("EFSNFS_BIND"); ie != "" {
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

	if !*hostRpc {
		InitRpcbind()
		InitStatd()
	}
	InitGrpc(ipnport, *serviceName)
	InitGanesha(*serviceName, true)
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
	export.RegisterExportServer(gs, &export.ExportImpl{})
	reflection.Register(gs)
	if release == "" {
		release = "dev"
	}
	log.Printf("NFS controller in version %v serving on %v is ready for gRPC clients", release, s.bind)
	return gs.Serve(ln)
}

func InitCmd(progname string, args []string) {
	var stdoutBuf, stderrBuf bytes.Buffer

	log.Printf("starting %s %+v\n", progname, args)

	cmd := exec.Command(progname, args...)
	cmd.Env = os.Environ()

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

func InitRpcbind() {
	InitCmd("rpcbind", []string{"-w"})
}

func InitStatd() {
	InitCmd("rpc.statd", []string{"-p", "662"})
}

func InitGrpc(ipnport, svc string) {

	log.Printf("starting gRPC ipnport=%s svc=%s\n", ipnport, svc)

	name, err := efsutil.GetMDKey("", "svcs", svc, "", "X-Service-Name")
	if err != nil {
		log.Fatalf("gRPC service error: %v", err.Error())
		return
	}

	if name != svc {
		log.Fatalf("invalid gRPC service %s", svc)
		return
	}

	immDir := ""
	if envRDU := os.Getenv("EFSNFS_RELAXED_DIR_UPDATES"); envRDU != "" {
		immDir = "0"
	}
	mhImmDir, err := efsutil.GetMDKey("", "svcs", svc, "", "X-MH-ImmDir")
	if err != nil {
		log.Fatalf(err.Error())
	}
	if immDir != "" && mhImmDir != immDir {
		err = efsutil.UpdateMD("", "svcs", svc, "", "X-MH-ImmDir", immDir)
		if err != nil {
			log.Fatalf(err.Error())
		}
		mhImmDir = immDir
	}
	os.Setenv("CCOW_MH_IMMDIR", mhImmDir)

	log.Printf("nfs gRPC svc=%s, X-MH-ImmDir=%s\n", svc, mhImmDir)

	keys, err := efsutil.GetKeys("", "svcs", svc, "", 1000)
	if err != nil {
		log.Fatalf(err.Error())
	}

	explist, err := os.Create(exportsList)
	if err != nil {
		log.Fatalf(err.Error())
	}
	explist.Close()

	for _, v := range keys {
		x := strings.Split(v, ",")
		exportId := x[0]
		var ExportId uint64
		ExportId, _ = strconv.ParseUint(exportId, 0, 32)
		x = strings.Split(x[1], "@")
		//exportPath := x[0]
		exportUri := x[1]
		u := strings.Split(exportUri, "/")
		err = export.LocalExportAdd(svc, u[0], u[1], u[2], uint32(ExportId), false)
		if err != nil {
			log.Fatalf(err.Error())
		}
	}

	go func() {
		err = New(ipnport).Listen()
		if err != nil {
			log.Fatalf("Failed to launch the EFSNFS due to %v", err)
		}
	}()
}

func InitGanesha(svc string, fgMode bool) {
	if fgMode {
		path := os.Getenv("NEDGE_HOME") + "/etc/ganesha/ganesha.conf"
		read, err := ioutil.ReadFile(path)
		if err != nil {
			log.Fatalf(err.Error())
		}
		newContents := strings.Replace(string(read), "/opt/nedge/var/log/nfs-ganesha.log", "/dev/stdout", -1)
		err = ioutil.WriteFile(path, []byte(newContents), 0)
		if err != nil {
		}
	}
	go func() {
		efsutil.K8sServiceUp(svc)
	}()
	InitCmd("ganesha.nfsd", []string{"-F"})
	os.Exit(0)
}
