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
#ifndef __CCOW_FSIO_S3_TRANSPARENCY_H
#define __CCOW_FSIO_S3_TRANSPARENCY_H

#define CCOW_FSIO_S3OBJ_DIR_OID ""

#include "fsio_inode.h"

typedef struct __nfs_directory_table_attrs
{
	uint8_t ver;
	inode_t ino;

} nfs_directory_table_attrs;

/**
 * Get the root dir name to be used for all objects.
 * The returned string is allocated using je_calloc and need to be freed.
 * Hard coded to the bucket name for now.
 */
int get_object_root_dir(ci_t *ci, char **name);

/**
 * Parse inode number for the S3 objects.
 * Use the value from the bucket btree to get the inode number.
 */
int parse_s3_obj_inode(void *value, size_t value_size, inode_t * ino);

/**
 * Parse inode stats for the S3 objects.
 * Use the value from the bucket btree to get the inode stats.
 */
int parse_s3_obj_stats(ci_t *ci, void *value, size_t value_size,
    struct stat *stat);

/**
 * Get the object name.
 * Lookup the btree on the INODE_OBJECT_LOOKUP by inode number
 */
int get_s3_obj_name(ci_t *ci, char *ino_str, char **oid);

/**
 * Get the object attributes as stats.
 * Lookup the btree on the INODE_OBJECT_LOOKUP by inode number
 */
int get_s3_obj_stats(ci_t *ci, char *ino_str, struct stat *stat);

/**
 * Return latest bucket's generation. Used for dynamic invalidation
 */
int get_s3_index_genid(ci_t * ci, uint64_t *genid);

/**
 * Encode nfs attributes to be kept in the directory table
 */
int encode_nfs_attrs(nfs_directory_table_attrs *attrs, void **value,
    size_t *value_size);

/**
 * Decode nfs attributes kept in the directory table
 */
int decode_nfs_attrs(void *value, size_t value_size,
    nfs_directory_table_attrs * attrs);

/**
 * Replace "/" from object name by "%2F"
 * Truncate the name if it is getting bigger than the max_decoded_name_len
 * Caller does the memory allocation.
 */
int encode_s3_name(char *decoded_name, size_t decoded_name_len,
    char *encoded_name, size_t max_encoded_name_len);

/**
 * Replace "%2F" from object name by "/"
 * Caller does the memory allocation.
 */
int decode_s3_name(char *encoded_name, size_t encoded_name_len,
    char *decoded_name, size_t max_decoded_name_len);


int get_s3_json_handle(const char *jsons_tring, void **json_handle);
int put_s3_json_handle(void *json_handle);

typedef struct __s3_object_parts_maps__
{
    uint64_t number;
    uint64_t offset;
    uint64_t size;
    char    *name;
}s3_object_parts_maps;

int get_s3_multipart_parts(
    ccowfs_inode *inode, size_t file_offset, size_t data_size,
    s3_object_parts_maps **multipart_map, uint64_t *count);

int s3_transparency_init(ci_t * ci);

#endif /* __CCOW_FSIO_S3_TRANSPARENCY_H */
