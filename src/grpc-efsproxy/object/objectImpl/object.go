/*
 * Copyright (c) 2015-2019 Nexenta Systems, Inc.
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
package objectImpl

/*
#include "ccow.h"
#include "errno.h"
*/
import "C"

import (
	proto ".."
	"../../efsutil"
	"golang.org/x/net/context"
	"google.golang.org/grpc/status"
	"strconv"
)

type ObjectImpl struct {
}

const (
	BlockSizeKey  = "X-blocksize"
	VolumeSizeKey = "X-volsize"
	ChunkSizeKey  = "ccow-chunkmap-chunk-size"
)

func (s *ObjectImpl) ObjectGetInfo(ctx context.Context, msg *proto.ObjectGetInfoRequest) (*proto.ObjectGetInfoResponse, error) {

	props, err := efsutil.GetMDPat(msg.Cluster, msg.Tenant, msg.Bucket, msg.Object, "")
	if err != nil {
		return nil, status.Errorf(500, "%s", err)
	}

	objectInfo := proto.ObjectInfo{}
	if volumesize, ok := props[VolumeSizeKey]; ok {
		val, err := strconv.ParseInt(volumesize, 10, 64)
		if err == nil {
			objectInfo.VolumeSize = uint64(val)
		}
	}

	if blocksize, ok := props[BlockSizeKey]; ok {
		val, err := strconv.ParseInt(blocksize, 10, 32)
		if err == nil {
			objectInfo.BlockSize = uint32(val)
		}
	}

	if chunksize, ok := props[ChunkSizeKey]; ok {
		val, err := strconv.ParseInt(chunksize, 10, 32)
		if err == nil {
			objectInfo.ChunkSize = uint32(val)
		}
	}

	return &proto.ObjectGetInfoResponse{Info: &objectInfo}, nil
}
