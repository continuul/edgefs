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
/**
 * This modules implements a radix tree.
 * We use this for fast longest-prefix matching.
 *
 * It is not particularly space efficient as each of
 * the nodes are quite large, but it is suitable for the
 * small number of patterns that are needed for
 * histograms.
 *
 */

#ifndef RADIX_H
#define RADIX_H

typedef struct {
    char *key;
    void *value;
} radix_leaf;

typedef struct radix_node {
    char *key;
    int key_len;
    void *edges[256];
} radix_node;

typedef struct {
    radix_node root;
} radix_tree;

/**
 * Initializes the radix tree
 * @arg tree The tree to initialize
 * @return 0 on success
 */
int radix_init(radix_tree *tree);

/**
 * Destroys the tree
 * @arg tree The tree to destroy
 * @return 0 on success
 */
int radix_destroy(radix_tree *tree);

/**
 * Inserts a value into the tree
 * @arg t The tree to insert into
 * @arg key The key of the value
 * @arg value Initially points to the value to insert, replaced
 * by the value that was updated if any
 * @return 0 if the value was inserted, 1 if the value was updated.
 */
int radix_insert(radix_tree *t, char *key, void **value);

/**
 * Finds a value in the tree
 * @arg t The tree to search
 * @arg key The key to search
 * @arg value The value of the key
 * @return 0 if found
 */
int radix_search(radix_tree *t, char *key, void **value);

/**
 * Finds the longest matching prefix
 * @arg t The tree to search
 * @arg key The key to search
 * @arg value The value of the key with the longest prefix
 * @return 0 if found
 */
int radix_longest_prefix(radix_tree *t, char *key, void **value);

/**
 * Iterates through all the nodes in the radix tree
 * @arg t The tree to iter through
 * @arg data Opaque handle passed through to callback
 * @arg iter_func A callback function to iterate through. Returns
 * non-zero to stop iteration.
 * @return 0 on sucess. 1 if the iteration was stopped.
 */
int radix_foreach(radix_tree *t, void *data, int(*iter_func)(void* data, char *key, void *value));

#endif
