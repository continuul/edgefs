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

	"./cluster"
	"./cluster/clusterImpl"
	"./service"
	"./service/serviceImpl"
	"./tenant"
	"./tenant/bucketImpl"
	"./tenant/tenantImpl"
	"./snapshot"
	"./snapshot/snapshotImpl"
	"./object"
	"./object/objectImpl"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"github.com/sevlyar/go-daemon"
)

var (
	release string
)

func Start() {
	ipnport := "0.0.0.0:6789" // Why is the number six afraid of seven? :-)
	if ie := os.Getenv("EFSPROXY_BIND"); ie != "" {
		ipnport = ie
	}

	err := New(ipnport).Listen()
	if err != nil {
		log.Fatalf("Failed to launch the EFSPROXY due to %v", err)
	}
}

type logWriter struct {
}

func (writer logWriter) Write(bytes []byte) (int, error) {
	return fmt.Print(time.Now().UTC().Format("2006-01-02T15:04:05.999Z") + " " + string(bytes))
}

func main() {
	log.SetFlags(0)
	log.SetOutput(new(logWriter))
	if len(os.Args) > 1 && os.Args[1] == "-f" {
		// foreground mode
		Start()
		return
	}
	cntxt := &daemon.Context{
		PidFileName: os.Getenv("NEDGE_HOME") + "/var/run/grpc-efsproxy.pid",
		PidFilePerm: 0644,
		LogFileName: os.Getenv("NEDGE_HOME") + "/var/log/grpc-efsproxy.log",
		LogFilePerm: 0640,
		WorkDir:     os.Getenv("NEDGE_HOME"),
		Args:        []string{"grpc-efsproxy"},
	}

	d, err := cntxt.Reborn()
	if err != nil {
		log.Fatal("Unable to run: ", err)
	}
	if d != nil {
		return
	}
	defer cntxt.Release()

	// child mode
	Start()
}

// Server wraps the gRPC server and implements tenant.EchoServer
type Server struct {
	bind string
}

// New creates a new rpc server.
func New(bind string) *Server {
	return &Server{bind}
}

func streamInterceptor(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if err := authorize(stream.Context()); err != nil {
		return err
	}

	return handler(srv, stream)
}

func unaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if err := authorize(ctx); err != nil {
		return nil, err
	}

	return handler(ctx, req)
}

func authorize(ctx context.Context) error {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if len(md["username"]) > 0 && md["username"][0] == "admin" &&
			len(md["password"]) > 0 && md["password"][0] == "admin" {
			return nil
		}

		return grpc.Errorf(codes.PermissionDenied, "Wrong username or password")
	}

	return grpc.Errorf(codes.Unauthenticated, "Empty metadata request")
}

// Listen binds the server to the indicated interface:port.
func (s *Server) Listen() error {
	ln, err := net.Listen("tcp", s.bind)
	if err != nil {
		return err
	}
	gs := grpc.NewServer(
		grpc.StreamInterceptor(streamInterceptor),
		grpc.UnaryInterceptor(unaryInterceptor),
	)
	cluster.RegisterClusterServer(gs, &clusterImpl.ClusterImpl{})
	tenant.RegisterTenantServer(gs, &tenantImpl.TenantImpl{})
	tenant.RegisterBucketServer(gs, &bucketImpl.BucketImpl{})
	service.RegisterServiceServer(gs, &serviceImpl.ServiceImpl{})
	snapshot.RegisterSnapshotServer(gs, &snapshotImpl.SnapshotImpl{})
	object.RegisterObjectServer(gs, &objectImpl.ObjectImpl{})
	reflection.Register(gs)
	if release == "" {
		release = "dev"
	}
	log.Printf("EFSPROXY in version %v serving on %v is ready for gRPC clients", release, s.bind)
	return gs.Serve(ln)
}
