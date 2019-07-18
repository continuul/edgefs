/*
 * Copyright (c) 2015-2018 Nexenta Systems, inc.
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
#ifndef __FSIO_NAMESPACE_H__
#define __FSIO_NAMESPACE_H__

int fsio_link_internal(ci_t * ci, inode_t parent_ino, char *name,
    inode_t child_ino, uint8_t link_count);
int fsio_namespace_clone(ci_t * src_ci, inode_t src_parent_ino, char *src_name,
    ci_t * dest_ci, inode_t dest_parent_ino, char *dest_name, uint32_t flags);
int fsio_namespace_init(ci_t * ci);
int fsio_namespace_term(ci_t * ci);

#endif /* __FSIO_NAMESPACE_H__ */
