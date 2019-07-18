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
	"net"
	"os"
	"os/exec"
	"io"
	"strings"
	"bytes"

	"../efscli/efsutil"
	"./status"
	"./status/statusImpl"

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
	if ie := os.Getenv("EFSS3X_BIND"); ie != "" {
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
	InitS3x(*serviceName, true)
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
	reflection.Register(gs)
	if release == "" {
		release = "dev"
	}
	log.Printf("S3x controller in version %v serving on %v is ready for gRPC clients", release, s.bind)
	return gs.Serve(ln)
}

func InitCmd(svc, progname string, args []string) {
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
	} else {
		go func() {
			efsutil.K8sServiceUp(svc);
		}()
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
			log.Fatalf("Failed to launch the EFSS3X due to %v", err)
		}
	}()
}

func InitS3x(svc string, fgMode bool) {

	if fgMode {
		os.Setenv("CCOW_LOG_STDOUT", "1")
	}

	log.Printf("Loading serving object for svc=%s\n", svc)

	keys, err := efsutil.GetKeys("", "svcs", svc, "", 1000)
	if err != nil {
		log.Fatalf(err.Error())
	}

	stype, err := efsutil.GetMDKey("", "svcs", svc, "", "X-Service-Type")
	if err != nil {
		log.Fatalf(err.Error())
	}
	if strings.Compare(stype, "s3x") != 0 {
		log.Fatalf("Wrong service type %s != s3x for service %s", stype, svc)
	}

	// TODO: implement
	// authType, err := efsutil.GetMDKey("", "svcs", svc, "", "X-Auth-Type")
	// if err != nil {
	// }

	// TODO: implement
	//aclOn, err := efsutil.GetMDKey("", "svcs", svc, "", "X-ACL-On")
	//if err != nil {
	//}

	httpPort := "4000"
	httpPort, _ = efsutil.GetMDKey("", "svcs", svc, "", "X-HTTP-Port")
	if p := os.Getenv("EFSS3X_HTTP_PORT"); p != "" {
		httpPort = p
	}

	httpsPort := "4443"
	httpsPort, _ = efsutil.GetMDKey("", "svcs", svc, "", "X-HTTPS-Port")
	if p := os.Getenv("EFSS3X_HTTPS_PORT"); p != "" {
		httpsPort = p
	}

	if len(keys) == 0 {
		log.Fatalf("Service is not configured. Expecting to find serving tenant")
	}

	for _, v := range keys {
		s := strings.Split(v, "/")
		log.Printf("Starting ccowhttpd for svc=%s on ports %s and %s\n", svc, httpsPort, httpPort)
		InitCmd(svc, "ccowhttpd", []string{"-c", s[0], "-t", s[1], "-S", httpsPort, httpPort})
		break
	}

	os.Exit(0)
}
