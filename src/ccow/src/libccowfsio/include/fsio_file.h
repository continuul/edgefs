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
#ifndef __FSIO_FILE_H__
#define __FSIO_FILE_H__

int ccow_fsio_open(ci_t * ci, char *path, ccow_fsio_file_t ** file, int openflags);
int ccow_fsio_openi(ci_t * ci, inode_t ino, ccow_fsio_file_t ** f, int openflags);
int ccow_fsio_close(ccow_fsio_file_t * file);
int ccow_fsio_read(ccow_fsio_file_t * file, size_t offset, size_t buffer_size,
    void *buffer, size_t * read_amount, int *eof);
int ccow_fsio_write(ccow_fsio_file_t * file, size_t offset, size_t buffer_size,
    void *buffer, size_t * write_amount);
int ccow_fsio_get_size(ccow_fsio_file_t * file, size_t * size);
int ccow_fsio_flush(ccow_fsio_file_t * file);


#endif /* __FSIO_FILE_H__ */
