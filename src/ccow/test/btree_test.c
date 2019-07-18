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
#include <string.h>

#include "ccowutil.h"
#include "cmocka.h"
#include "btree.h"

/*******************************************************************************
 *
 ******************************************************************************/
#if 1
#define ASSERT_INT_EQUAL(_a, _b)						\
	if (_a != _b) {								\
		printf("%s : %s : %d : _a = %d : _b = %d \n",			\
		    __FUNCTION__, __FILE__, __LINE__,				\
		    _a, _b);							\
		assert(0);							\
	}
#else
	assert_int_equal(_a, _b)
#endif


/*******************************************************************************
 * test sequence 1 btree callback functions
 ******************************************************************************/

/**
 * btree_test_01_free_key_val
 */
static int
btree_test_01_free_key_val(btree_t *btree, bt_key_val_t *kv)
{
	BT_FREE(kv->kv_key);
	BT_FREE(kv->kv_val);
	BT_FREE(kv);
	return 0;
}

/**
 * btree_test_01_cmp_keys
 */
static int
btree_test_01_cmp_keys(void *key1, void *key2)
{
	char *str1 = (char *) key1;
	char *str2 = (char *) key2;

	return strcmp(str1, str2);
}

/**
 * btree_test_01_copy_key_val
 */
static int
btree_test_01_copy_key_val(btree_t *btree, bt_key_val_t *src, bt_key_val_t **dst)
{
	if (*dst != NULL)
		btree_test_01_free_key_val(btree, *dst);

	*dst = BT_MALLOC(sizeof(bt_key_val_t));
	assert_non_null(*dst != NULL);

	(*dst)->kv_key = BT_MALLOC(strlen(src->kv_key) + 1);
	assert_non_null((*dst)->kv_key);

	(*dst)->kv_val = BT_MALLOC(sizeof(uint64_t));
	assert_non_null((*dst)->kv_val);

	char *str = strcpy((char *) (*dst)->kv_key, (char *) src->kv_key);
	assert_non_null(str);
	assert_int_equal(strlen((char *) src->kv_key), strlen(str));

	*((uint64_t *) (*dst)->kv_val) = *((uint64_t *) src->kv_val);
	return 0;
}

/**
 * btree_test_01_copy_key
 */
static int
btree_test_01_copy_key(void **dst, void  *src)
{
	assert(*dst != NULL);
	assert(src != NULL);
	assert(strlen(*dst) >= strlen(src));

	char *s = src;
	char **d = (char **) dst;

	char *str = strcpy(*d, s);
	assert_non_null(s);
	assert_int_equal(strlen(s), strlen(str));

	return 0;
}

/**
 * btree_test_01_print_key
 */
static char *
btree_test_01_print_key(void *key, int prt)
{
	char *str = (char *) key;
	static char buf[1024];
	sprintf(buf, "%s", str);

	if (prt)
		printf("%s", buf);

	return buf;
}

/**
 *  btree_test_01_free_node
 */
static int
btree_test_01_free_node(struct _btree_ *btree, bt_node_t *node,
    node_pos_t parent_pos)
{
	for (int i = 0; i < node->nr_active; i++) {
		BT_FREE(node->key_vals[i]->kv_key);
		BT_FREE(node->key_vals[i]->kv_val);
		BT_FREE(node->key_vals[i]);
	}

	BT_FREE(node->children);
	BT_FREE(node->key_vals);
	BT_FREE(node);

	return 0;
}

/*******************************************************************************
 * test sequence 2 btree callback functions
 ******************************************************************************/
typedef struct _btree_test_02_data_
{
	uint64_t kv_val;
	uint64_t kv_key;
} btree_test_02_data_t;

/**
 * btree_test_02_free_key_val
 */
static int
btree_test_02_free_key_val(btree_t *btree, bt_key_val_t *kv)
{
	BT_FREE(kv->kv_val);
	BT_FREE(kv);
	return 0;
}

/**
 * btree_test_02_cmp_keys
 */
static int
btree_test_02_cmp_keys(void *key1, void *key2)
{
	uint64_t k1 = *((uint64_t *) key1);
	uint64_t k2 = *((uint64_t *) key2);

	if (k1 < k2) return -1;
	if (k1 > k2) return  1;
	return 0;
}

/**
 * btree_test_02_copy_key_val
 */
static int
btree_test_02_copy_key_val(btree_t *btree, bt_key_val_t *src, bt_key_val_t **dst)
{
	if (*dst != NULL) {
		btree_test_02_free_key_val(btree, *dst);
		*dst = NULL;
	}

	*dst = BT_MALLOC(sizeof(bt_key_val_t));
	assert_non_null(*dst != NULL);

	btree_test_02_data_t *tmp = BT_MALLOC(sizeof(btree_test_02_data_t));
	assert_non_null(tmp);

	tmp->kv_key = *((uint64_t *) src->kv_key);
	tmp->kv_val = *((uint64_t *) src->kv_val);

	(*dst)->kv_key = &tmp->kv_key;
	(*dst)->kv_val = &tmp->kv_val;

	return 0;
}

/**
 * btree_test_02_copy_key
 */
static int
btree_test_02_copy_key(void **dst, void  *src)
{
	uint64_t *d64 = *dst;
	uint64_t s64  = *((uint64_t *) src);

	*d64 = s64;
	return 0;
}

/**
 * btree_test_02_print_key
 */
static char *
btree_test_02_print_key(void *key, int prt)
{
	uint64_t k = *((uint64_t *) key);
	static char buf[64];

	sprintf(buf, "%"PRIu64"", k);

	if (prt)
		printf("%s/n", buf);

	return buf;
}

/**
 *  btree_test_02_free_node
 */
static int
btree_test_02_free_node(struct _btree_ *btree, bt_node_t *node,
    node_pos_t parent_pos)
{
	for (int i = 0; i < node->nr_active; i++) {
		BT_FREE(node->key_vals[i]->kv_val);
		BT_FREE(node->key_vals[i]);
	}

	BT_FREE(node->children);
	BT_FREE(node->key_vals);
	BT_FREE(node);

	return 0;
}

/*******************************************************************************
 * test sequence 1 test functions
 ******************************************************************************/

/**
 * btree_test_01_insert_keyval_str
 *
 * Insert a string based key into the the btree
 */
void
btree_test_01_insert_keyval_str(btree_t *btree, char *key, uint64_t val,
	int expected_err)
{
	bt_key_val_t *kv = BT_MALLOC(sizeof(bt_key_val_t));
	assert_non_null(kv);

	kv->kv_key = BT_MALLOC(strlen(key) + 1);
	assert_non_null(kv->kv_key);

	strcpy(kv->kv_key, key);

	kv->kv_val = BT_MALLOC(sizeof(uint64_t));
	*((uint64_t *) kv->kv_val) = val;

	int err = btree_insert_key(btree, kv, FALSE);

	if (err == -EEXIST) {
		BT_FREE(kv->kv_key);
		BT_FREE(kv->kv_val);
		BT_FREE(kv);
		kv = NULL;
	}

	assert_int_equal(err, expected_err);

	if (kv != NULL)
		btree_test_01_free_key_val(btree, kv);
}

/**
 * btree_test_01_delete_keyval_str
 *
 * Delete a string based key from the btree
 */
void
btree_test_01_delete_keyval_str(btree_t *btree, char *key)
{
	bt_key_val_t *kv = BT_MALLOC(sizeof(bt_key_val_t));
	assert_non_null(kv);

	kv->kv_key = BT_MALLOC(strlen(key) + 1);
	assert_non_null(kv->kv_key);

	strcpy(kv->kv_key, key);

	kv->kv_val = 0;

	int err = btree_delete_key(btree, kv);

	BT_FREE(kv->kv_key);
	BT_FREE(kv);

	assert_int_equal(err, 0);
}

/**
 * btree_test_01_01_create
 *
 * Test sequence 01, step 01.  Create a btree of order 2 and register
 * callbacks.
 */
static void
btree_test_01_01_create(void **state)
{
	btree_t *btree = btree_create(2);
	*state = btree;

	assert_non_null(btree);
	assert_non_null(btree->root);
	assert_int_equal(btree->root->nr_active, 0);
	assert_true(btree->root->leaf);

	for (int32_t i = 0; i < btree->order * 2; i++) {
		assert_null(btree->root->key_vals[i]);
		assert_null(btree->root->children[i]);
	}

	btree->cmp_keys     = btree_test_01_cmp_keys;
	btree->copy_key_val = btree_test_01_copy_key_val;
	btree->copy_key	    = btree_test_01_copy_key;
	btree->free_key_val = btree_test_01_free_key_val;
	btree->print_key    = btree_test_01_print_key;
	btree->free_node    = btree_test_01_free_node;
}

/**
 * btree_test_01_02_insert_abc
 *
 * Test sequence 01, step 02.  Insert a key/val of {"abc", 1000}.
 */
static void
btree_test_01_02_insert_abc(void **state)
{
	btree_t *btree = (btree_t*) *state;

	btree_test_01_insert_keyval_str(btree, "abc", 1000, 0);

	assert_non_null(btree);
	assert_non_null(btree->root);
	assert_int_equal(btree->root->nr_active, 1);
	assert_true(btree->root->leaf);
	assert_int_equal(btree->root->level, 0);

	for (int32_t i = 0; i < btree->order * 2; i++) {
		if (i < btree->root->nr_active) {
			assert_non_null(btree->root->key_vals[i]);
		} else {
			assert_null(btree->root->key_vals[i]);
		}
		assert_null(btree->root->children[i]);
	}

	assert_int_equal(*((uint64_t *) btree->root->key_vals[0]->kv_val), 1000);
	assert_int_equal(strcmp("abc", btree->root->key_vals[0]->kv_key), 0);
}

/**
 * btree_test_01_03_insert_def
 *
 * Test sequence 01, step 03.  Insert a key/val of {"def", 2000}.
 */
static void
btree_test_01_03_insert_def(void **state)
{
	btree_t *btree = (btree_t*) *state;
	bt_key_val_t *kv = BT_MALLOC(sizeof(bt_key_val_t));
	assert_non_null(kv);

	kv->kv_key = BT_MALLOC(strlen("def") + 1);
	assert_non_null(kv->kv_key);

	strcpy(kv->kv_key, "def");

	kv->kv_val = BT_MALLOC(sizeof(uint64_t));
	*((uint64_t *) kv->kv_val) = 2000;

	int err = btree_insert_key(btree, kv, FALSE);
	assert_int_equal(err, 0);

	assert_non_null(btree);
	assert_non_null(btree->root);

	assert_int_equal(btree->root->nr_active, 2);
	assert_true(btree->root->leaf);
	assert_int_equal(btree->root->level, 0);

	for (int32_t i = 0; i < btree->order * 2; i++) {
		if (i < btree->root->nr_active)
			assert_non_null(btree->root->key_vals[i]);
		else
			assert_null(btree->root->key_vals[i]);
		assert_null(btree->root->children[i]);
	}

	assert_int_equal(*((uint64_t *) btree->root->key_vals[0]->kv_val), 1000);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[1]->kv_val), 2000);

	assert_int_equal(strcmp("abc", btree->root->key_vals[0]->kv_key), 0);
	assert_int_equal(strcmp("def", btree->root->key_vals[1]->kv_key), 0);

	btree_test_01_free_key_val(btree, kv);
}

/**
 * btree_test_01_04_insert_abc
 *
 * Test sequence 01, step 04. Try to insert a key/val of {"abc", 3000}. This should
 * not overwrite the existing "abc" key/val {"abc", 1000}.
 */
static void
btree_test_01_04_insert_abc(void **state)
{
	btree_t *btree = (btree_t*) *state;

	btree_test_01_insert_keyval_str(btree, "abc", 3000, -EEXIST);

	assert_non_null(btree);
	assert_non_null(btree->root);
	assert_int_equal(btree->root->nr_active, 2);
	assert_true(btree->root->leaf);
	assert_int_equal(btree->root->level, 0);

	for (int32_t i = 0; i < btree->order * 2; i++) {
		if (i < btree->root->nr_active)
			assert_non_null(btree->root->key_vals[i]);
		else
			assert_null(btree->root->key_vals[i]);
		assert_null(btree->root->children[i]);
	}

	assert_int_equal(*((uint64_t *) btree->root->key_vals[0]->kv_val), 1000);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[1]->kv_val), 2000);

	assert_int_equal(strcmp("abc", btree->root->key_vals[0]->kv_key), 0);
	assert_int_equal(strcmp("def", btree->root->key_vals[1]->kv_key), 0);
}

/**
 * btree_test_01_05_insert_bcd
 *
 * Test sequence 01, step 05.  Insert a key/val of {"bcd", 4000}.
 */
static void
btree_test_01_05_insert_bcd(void **state)
{
	btree_t *btree = (btree_t*) *state;

	btree_test_01_insert_keyval_str(btree, "bcd", 4000, 0);

	assert_non_null(btree);
	assert_non_null(btree->root);
	assert_int_equal(btree->root->nr_active, 3);
	assert_true(btree->root->leaf);
	assert_int_equal(btree->root->level, 0);

	for (int32_t i = 0; i < btree->order * 2; i++) {
		if (i < btree->root->nr_active)
			assert_non_null(btree->root->key_vals[i]);
		else
			assert_null(btree->root->key_vals[i]);
		assert_null(btree->root->children[i]);
	}

	assert_int_equal(*((uint64_t *) btree->root->key_vals[0]->kv_val), 1000);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[1]->kv_val), 4000);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[2]->kv_val), 2000);

	assert_int_equal(strcmp("abc", btree->root->key_vals[0]->kv_key), 0);
	assert_int_equal(strcmp("bcd", btree->root->key_vals[1]->kv_key), 0);
	assert_int_equal(strcmp("def", btree->root->key_vals[2]->kv_key), 0);
}

/**
 * btree_test_01_06_insert_efg
 *
 * Test sequence 01, step 06.  Insert a key/val of {"efg", 5000}.
 */
static void
btree_test_01_06_insert_efg(void **state)
{
	btree_t *btree = (btree_t*) *state;

	btree_test_01_insert_keyval_str(btree, "efg", 5000, 0);

	assert_non_null(btree);
	assert_non_null(btree->root);
	assert_int_equal(btree->root->nr_active, 4);
	assert_true(btree->root->leaf);
	assert_int_equal(btree->root->level, 0);

	for (int32_t i = 0; i < btree->order * 2; i++) {
		if (i < btree->root->nr_active)
			assert_non_null(btree->root->key_vals[i]);
		else
			assert_null(btree->root->key_vals[i]);
		assert_null(btree->root->children[i]);
	}

	assert_int_equal(*((uint64_t *) btree->root->key_vals[0]->kv_val), 1000);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[1]->kv_val), 4000);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[2]->kv_val), 2000);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[3]->kv_val), 5000);

	assert_int_equal(strcmp("abc", btree->root->key_vals[0]->kv_key), 0);
	assert_int_equal(strcmp("bcd", btree->root->key_vals[1]->kv_key), 0);
	assert_int_equal(strcmp("def", btree->root->key_vals[2]->kv_key), 0);
	assert_int_equal(strcmp("efg", btree->root->key_vals[3]->kv_key), 0);
}

/**
 * btree_test_01_07_insert_ddd
 *
 * Test sequence 01, step 07.  Insert a key/val of {"ddd", 6000}.
 */
static void
btree_test_01_07_insert_ddd(void **state)
{
	btree_t *btree = (btree_t*) *state;

	btree_test_01_insert_keyval_str(btree, "ddd", 6000, 0);

	assert_non_null(btree);
	assert_non_null(btree->root);
	assert_int_equal(btree->root->nr_active, 2);
	assert_false(btree->root->leaf);
	assert_int_equal(btree->root->level, 1);

	for (int32_t i = 0; i < btree->order * 2; i++) {
		if (i < btree->root->nr_active) {
			assert_non_null(btree->root->key_vals[i]);
			assert_non_null(btree->root->children[i]);
		} else {
			assert_null(btree->root->key_vals[i]);
			assert_null(btree->root->children[i]);
		}
	}

	assert_int_equal(*((uint64_t *) btree->root->key_vals[0]->kv_val), 4000);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[1]->kv_val), 5000);

	assert_int_equal(strcmp("bcd", btree->root->key_vals[0]->kv_key), 0);
	assert_int_equal(strcmp("efg", btree->root->key_vals[1]->kv_key), 0);

	/* 1st child */
	bt_node_t *child;

	child = btree->root->children[0];

	assert_int_equal(child->nr_active, 2);
	assert_true(child->leaf);
	assert_int_equal(child->level, 0);

	for (int32_t i = 0; i < btree->order * 2; i++) {
		if (i < child->nr_active) {
			assert_non_null(child->key_vals[i]);
		} else {
			assert_null(child->key_vals[i]);
		}
		assert_null(child->children[i]);
	}

	assert_int_equal(*((uint64_t *) child->key_vals[0]->kv_val), 1000);
	assert_int_equal(*((uint64_t *) child->key_vals[1]->kv_val), 4000);

	assert_int_equal(strcmp("abc", child->key_vals[0]->kv_key), 0);
	assert_int_equal(strcmp("bcd", child->key_vals[1]->kv_key), 0);

	/* 2nd child */
	child = btree->root->children[1];

	assert_int_equal(child->nr_active, 3);
	assert_true(child->leaf);
	assert_int_equal(child->level, 0);

	for (int32_t i = 0; i < btree->order * 2; i++) {
		if (i < child->nr_active) {
			assert_non_null(child->key_vals[i]);
		} else {
			assert_null(child->key_vals[i]);
		}
		assert_null(child->children[i]);
	}

	assert_int_equal(*((uint64_t *) child->key_vals[0]->kv_val), 6000);
	assert_int_equal(*((uint64_t *) child->key_vals[1]->kv_val), 2000);
	assert_int_equal(*((uint64_t *) child->key_vals[2]->kv_val), 5000);

	assert_int_equal(strcmp("ddd", child->key_vals[0]->kv_key), 0);
	assert_int_equal(strcmp("def", child->key_vals[1]->kv_key), 0);
	assert_int_equal(strcmp("efg", child->key_vals[2]->kv_key), 0);

	bt_node_t * rt   = btree->root;
	bt_node_t * ch0  = btree->root->children[0];
	bt_node_t * ch1  = btree->root->children[1];
}

/**
 * btree_test_01_08_delete_bcd
 *
 * Test sequence 01, step 08. Delete key "bcd".
 */
static void
btree_test_01_08_delete_bcd(void **state)
{
	btree_t *btree = (btree_t*) *state;

	btree_test_01_delete_keyval_str(btree, "bcd");

	assert_non_null(btree);
	assert_non_null(btree->root);
	assert_int_equal(btree->root->nr_active, 2);
	assert_false(btree->root->leaf);
	assert_int_equal(btree->root->level, 1);

	for (int32_t i = 0; i < btree->order * 2; i++) {
		if (i < btree->root->nr_active) {
			assert_non_null(btree->root->key_vals[i]);
			assert_non_null(btree->root->children[i]);
		} else {
			assert_null(btree->root->key_vals[i]);
			assert_null(btree->root->children[i]);
		}
	}

	assert_int_equal(strcmp("bcd", btree->root->key_vals[0]->kv_key), 0);
	assert_int_equal(strcmp("efg", btree->root->key_vals[1]->kv_key), 0);

	/* 1st child */
	bt_node_t *child;

	child = btree->root->children[0];

	assert_int_equal(child->nr_active, 1);
	assert_true(child->leaf);
	assert_int_equal(child->level, 0);

	for (int32_t i = 0; i < btree->order * 2; i++) {
		if (i < child->nr_active) {
			assert_non_null(child->key_vals[i]);
		} else {
			assert_null(child->key_vals[i]);
		}
		assert_null(child->children[i]);
	}

	assert_int_equal(strcmp("abc", child->key_vals[0]->kv_key), 0);

	/* 2nd child */
	child = btree->root->children[1];

	assert_int_equal(child->nr_active, 3);
	assert_true(child->leaf);
	assert_int_equal(child->level, 0);

	for (int32_t i = 0; i < btree->order * 2; i++) {
		if (i < child->nr_active) {
			assert_non_null(child->key_vals[i]);
		} else {
			assert_null(child->key_vals[i]);
		}
		assert_null(child->children[i]);
	}

	assert_int_equal(*((uint64_t *) child->key_vals[0]->kv_val), 6000);
	assert_int_equal(*((uint64_t *) child->key_vals[1]->kv_val), 2000);
	assert_int_equal(*((uint64_t *) child->key_vals[2]->kv_val), 5000);

	assert_int_equal(strcmp("ddd", child->key_vals[0]->kv_key), 0);
	assert_int_equal(strcmp("def", child->key_vals[1]->kv_key), 0);
	assert_int_equal(strcmp("efg", child->key_vals[2]->kv_key), 0);

	bt_node_t * rt   = btree->root;
	bt_node_t * ch0  = btree->root->children[0];
	bt_node_t * ch1  = btree->root->children[1];
}

/**
 * btree_test_01_99_destroy
 *
 * Test sequence 01, step 99.  Destroy btree.
 */
static void
btree_test_01_99_destroy(void **state)
{
	btree_t *btree = (btree_t*) *state;
	btree_destroy(btree);
}

/*******************************************************************************
 * test sequence 2 test functions
 ******************************************************************************/

/**
 * btree_test_02_insert_keyval
 *
 * Insert a string based key into the the btree
 */
static void
btree_test_02_insert_keyval(btree_t *btree, uint64_t key, uint64_t val,
    int expected_err)
{
	bt_key_val_t *kv = BT_MALLOC(sizeof(bt_key_val_t));
	assert_non_null(kv);

	btree_test_02_data_t *tmp = BT_MALLOC(sizeof(btree_test_02_data_t));
	assert_non_null(tmp);

	tmp->kv_val = val;
	tmp->kv_key = key;

	kv->kv_val = &tmp->kv_val;
	kv->kv_key = &tmp->kv_key;

	int err = btree_insert_key(btree, kv, TRUE);
	ASSERT_INT_EQUAL(err, expected_err);

	btree_test_02_free_key_val(btree, kv);

}

/**
 * btree_test_02_01_create
 *
 * Test sequence 02, step 01.  Create a btree of order 2 and register
 * callbacks.
 */
static void
btree_test_02_01_create(void **state)
{
	btree_t *btree = btree_create(2);
	*state = btree;

	assert_non_null(btree);
	assert_non_null(btree->root);
	assert_int_equal(btree->root->nr_active, 0);
	assert_true(btree->root->leaf);

	for (int32_t i = 0; i < btree->order * 2; i++) {
		assert_null(btree->root->key_vals[i]);
		assert_null(btree->root->children[i]);
	}

	btree->cmp_keys     = btree_test_02_cmp_keys;
	btree->copy_key_val = btree_test_02_copy_key_val;
	btree->copy_key     = btree_test_02_copy_key;
	btree->free_key_val = btree_test_02_free_key_val;
	btree->print_key    = btree_test_02_print_key;
	btree->free_node    = btree_test_02_free_node;
}

/**
 * btree_test_02_02_insert_100
 *
 * Test sequence 02, step 02.  Insert a key/val of {100, 1000}.
 */
static void
btree_test_02_02_insert_100(void **state)
{
	btree_t *btree = (btree_t*) *state;

	btree_test_02_insert_keyval(btree, 100, 1000, 0);

	assert_non_null(btree);
	assert_non_null(btree->root);
	assert_int_equal(btree->root->nr_active, 1);
	assert_true(btree->root->leaf);
	assert_int_equal(btree->root->level, 0);

	for (int32_t i = 0; i < btree->order * 2; i++) {
		if (i < btree->root->nr_active)
			assert_non_null(btree->root->key_vals[i]);
		else
			assert_null(btree->root->key_vals[i]);
		assert_null(btree->root->children[i]);
	}

	assert_int_equal(*((uint64_t *) btree->root->key_vals[0]->kv_key), 100);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[0]->kv_val), 1000);

	bt_node_t * rt   = btree->root;
}

/**
 * btree_test_02_03_insert_200
 *
 * Test sequence 02, step 03.  Insert a key/val of {200, 2000}.
 */
static void
btree_test_02_03_insert_200(void **state)
{
	btree_t *btree = (btree_t*) *state;

	btree_test_02_insert_keyval(btree, 200, 2000, 0);

	assert_non_null(btree);
	assert_non_null(btree->root);
	assert_int_equal(btree->root->nr_active, 2);
	assert_true(btree->root->leaf);
	assert_int_equal(btree->root->level, 0);

	for (int32_t i = 0; i < btree->order * 2; i++) {
		if (i < btree->root->nr_active)
			assert_non_null(btree->root->key_vals[i]);
		else
			assert_null(btree->root->key_vals[i]);
		assert_null(btree->root->children[i]);
	}

	assert_int_equal(*((uint64_t *) btree->root->key_vals[0]->kv_val), 1000);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[1]->kv_val), 2000);

	assert_int_equal(*((uint64_t *) btree->root->key_vals[0]->kv_key), 100);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[1]->kv_key), 200);

	bt_node_t * rt   = btree->root;
}

/**
 * btree_test_02_04_insert_100
 *
 * Test sequence 02, step 04.  Insert a key/val of {100, 3000}.
 */
static void
btree_test_02_04_insert_100(void **state)
{
	btree_t *btree = (btree_t*) *state;

	btree_test_02_insert_keyval(btree, 100, 3000, 0);

	assert_non_null(btree);
	assert_non_null(btree->root);
	assert_int_equal(btree->root->nr_active, 2);
	assert_true(btree->root->leaf);
	assert_int_equal(btree->root->level, 0);

	for (int32_t i = 0; i < btree->order * 2; i++) {
		if (i < btree->root->nr_active)
			assert_non_null(btree->root->key_vals[i]);
		else
			assert_null(btree->root->key_vals[i]);
		assert_null(btree->root->children[i]);
	}

	assert_int_equal(*((uint64_t *) btree->root->key_vals[0]->kv_key), 100);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[0]->kv_val), 3000);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[1]->kv_key), 200);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[1]->kv_val), 2000);

	bt_node_t * rt   = btree->root;
}

/**
 * btree_test_02_05_insert_150
 *
 * Test sequence 02, step 05.  Insert a key/val of {150, 5000}.
 */
static void
btree_test_02_05_insert_150(void **state)
{
	btree_t *btree = (btree_t*) *state;

	btree_test_02_insert_keyval(btree, 150, 5000, 0);

	assert_non_null(btree);
	assert_non_null(btree->root);
	assert_int_equal(btree->root->nr_active, 3);
	assert_true(btree->root->leaf);
	assert_int_equal(btree->root->level, 0);

	for (int32_t i = 0; i < btree->order * 2; i++) {
		if (i < btree->root->nr_active)
			assert_non_null(btree->root->key_vals[i]);
		else
			assert_null(btree->root->key_vals[i]);
		assert_null(btree->root->children[i]);
	}

	assert_int_equal(*((uint64_t *) btree->root->key_vals[0]->kv_key), 100);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[0]->kv_val), 3000);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[1]->kv_key), 150);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[1]->kv_val), 5000);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[2]->kv_key), 200);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[2]->kv_val), 2000);

	bt_node_t * rt   = btree->root;
}

/**
 * btree_test_02_06_insert_400
 *
 * Test sequence 02, step 06.  Insert a key/val of {400, 6000}.
 */
static void
btree_test_02_06_insert_400(void **state)
{
	btree_t *btree = (btree_t*) *state;

	btree_test_02_insert_keyval(btree, 400, 6000, 0);

	assert_non_null(btree);
	assert_non_null(btree->root);
	assert_int_equal(btree->root->nr_active, 4);
	assert_true(btree->root->leaf);
	assert_int_equal(btree->root->level, 0);

	for (int32_t i = 0; i < btree->order * 2; i++) {
		if (i < btree->root->nr_active)
			assert_non_null(btree->root->key_vals[i]);
		else
			assert_null(btree->root->key_vals[i]);
		assert_null(btree->root->children[i]);
	}

	assert_int_equal(*((uint64_t *) btree->root->key_vals[0]->kv_key), 100);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[0]->kv_val), 3000);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[1]->kv_key), 150);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[1]->kv_val), 5000);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[2]->kv_key), 200);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[2]->kv_val), 2000);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[3]->kv_key), 400);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[3]->kv_val), 6000);

	bt_node_t * rt   = btree->root;
}

/**
 * btree_test_02_07_insert_300
 *
 * Test sequence 02, step 07.  Insert a key/val of {300, 7000}.
 */
static void
btree_test_02_07_insert_300(void **state)
{
	btree_t *btree = (btree_t*) *state;

	btree_test_02_insert_keyval(btree, 300, 7000, 0);

	assert_non_null(btree);
	assert_non_null(btree->root);
	assert_int_equal(btree->root->nr_active, 2);
	assert_false(btree->root->leaf);
	assert_int_equal(btree->root->level, 1);

	for (int32_t i = 0; i < btree->order * 2; i++) {
		if (i < btree->root->nr_active) {
			assert_non_null(btree->root->key_vals[i]);
			assert_non_null(btree->root->children[i]);
		} else {
			assert_null(btree->root->key_vals[i]);
			assert_null(btree->root->children[i]);
		}
	}

	assert_int_equal(*((uint64_t *) btree->root->key_vals[0]->kv_key), 150);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[0]->kv_val), 5000);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[1]->kv_key), 400);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[1]->kv_val), 6000);

	bt_node_t *child;

	// 1st child
	child = btree->root->children[0];

	assert_non_null(child);
	assert_int_equal(child->nr_active, 2);
	assert_true(child->leaf);
	assert_int_equal(child->level, 0);

	for (int32_t i = 0; i < btree->order * 2; i++) {
		if (i < child->nr_active) {
			assert_non_null(child->key_vals[i]);
		} else {
			assert_null(child->key_vals[i]);
		}

		assert_null(child->children[i]);
	}

	assert_int_equal(*((uint64_t *) child->key_vals[0]->kv_key), 100);
	assert_int_equal(*((uint64_t *) child->key_vals[0]->kv_val), 3000);
	assert_int_equal(*((uint64_t *) child->key_vals[1]->kv_key), 150);
	assert_int_equal(*((uint64_t *) child->key_vals[1]->kv_val), 5000);

	// 2nd child
	child = btree->root->children[1];

	assert_non_null(child);
	assert_int_equal(child->nr_active, 3);
	assert_true(child->leaf);
	assert_int_equal(child->level, 0);

	for (int32_t i = 0; i < btree->order * 2; i++) {
		if (i < child->nr_active) {
			assert_non_null(child->key_vals[i]);
		} else {
			assert_null(child->key_vals[i]);
		}

		assert_null(child->children[i]);
	}

	assert_int_equal(*((uint64_t *) child->key_vals[0]->kv_key), 200);
	assert_int_equal(*((uint64_t *) child->key_vals[0]->kv_val), 2000);
	assert_int_equal(*((uint64_t *) child->key_vals[1]->kv_key), 300);
	assert_int_equal(*((uint64_t *) child->key_vals[1]->kv_val), 7000);
	assert_int_equal(*((uint64_t *) child->key_vals[2]->kv_key), 400);
	assert_int_equal(*((uint64_t *) child->key_vals[2]->kv_val), 6000);

	bt_node_t * rt   = btree->root;
	bt_node_t * ch0  = btree->root->children[0];
	bt_node_t * ch1  = btree->root->children[1];
}

/**
 * btree_test_02_08_destroy
 *
 * Test sequence 02, step 08.  Destroy btree.
 */
static void
btree_test_02_08_destroy(void **state)
{
	btree_t *btree = (btree_t*) *state;
	btree_destroy(btree);
}

/*******************************************************************************
 * test sequence 3 test functions
 ******************************************************************************/

/**
 * btree_test_03_load_keyval
 *
 * Load a numeric based key into the the btree
 */
void
btree_test_03_load_kv(btree_t *btree, node_pos_t parent, bt_node_t **node,
    bool_t leaf, int level, uint64_t key, uint64_t val, int expected_err)
{
	bt_key_val_t *kv = BT_MALLOC(sizeof(bt_key_val_t));
	assert_non_null(kv);

	btree_test_02_data_t *tmp = BT_MALLOC(sizeof(btree_test_02_data_t));
	assert_non_null(tmp);

	tmp->kv_val = val;
	tmp->kv_key = key;

	kv->kv_val = &tmp->kv_val;
	kv->kv_key = &tmp->kv_key;

	int err = btree_load_kv(btree, parent, node, leaf, level, kv);
	assert_int_equal(err, expected_err);
}

/**
 * btree_test_03_01_create
 *
 * Test sequence 03, step 01.  Create a btree of order 2 and register
 * callbacks.
 */
static void
btree_test_03_01_create(void **state)
{
	btree_t *btree = btree_create(2);
	*state = btree;

	assert_non_null(btree);
	assert_non_null(btree->root);
	assert_int_equal(btree->root->nr_active, 0);
	assert_true(btree->root->leaf);

	for (int32_t i = 0; i < btree->order * 2; i++) {
		assert_null(btree->root->key_vals[i]);
		assert_null(btree->root->children[i]);
	}

	btree->cmp_keys     = btree_test_02_cmp_keys;
	btree->copy_key_val = btree_test_02_copy_key_val;
	btree->copy_key     = btree_test_02_copy_key;
	btree->free_key_val = btree_test_02_free_key_val;
	btree->print_key    = btree_test_02_print_key;
	btree->free_node    = btree_test_02_free_node;
}

/**
 * btree_test_03_02_load_100
 *
 * Test sequence 03, step 02.  Load a key/val of {100, 1000}.
 */
static void
btree_test_03_02_load_100(void **state)
{
	btree_t *btree = (btree_t*) *state;

	node_pos_t parent = {NULL, 0};
	bt_node_t * node = NULL;

	btree_test_03_load_kv(btree, parent, &node, TRUE, 0, 100, 1000, 0);

	assert_non_null(btree);
	assert_non_null(btree->root);
	assert_int_equal(btree->root->nr_active, 1);
	assert_true(btree->root->leaf);
	assert_int_equal(btree->root->level, 0);

	for (int32_t i = 0; i < btree->order * 2; i++) {
		if (i < btree->root->nr_active) {
			assert_non_null(btree->root->key_vals[i]);
		} else {
			assert_null(btree->root->key_vals[i]);
		}
		assert_null(btree->root->children[i]);
	}

	assert_int_equal(*((uint64_t *) btree->root->key_vals[0]->kv_key), 100);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[0]->kv_val), 1000);

	assert_int_equal(btree->root->key_vals[0]->kv_flags, 0x00);
	assert_int_equal(btree->root->bn_flags, 0x00);

	bt_node_t * rt   = btree->root;
}

/**
 * btree_test_03_03_load_200
 *
 * Test sequence 03, step 03.  Load a key/val of {200, 2000}.
 */
static void
btree_test_03_03_load_200(void **state)
{
	btree_t *btree = (btree_t*) *state;

	node_pos_t parent = {NULL, 0};
	bt_node_t * node = NULL;

	btree_test_03_load_kv(btree, parent, &node, TRUE, 0, 200, 2000, 0);

	assert_non_null(btree);
	assert_non_null(btree->root);
	assert_int_equal(btree->root->nr_active, 2);
	assert_true(btree->root->leaf);
	assert_int_equal(btree->root->level, 0);

	for (int32_t i = 0; i < btree->order * 2; i++) {
		if (i < btree->root->nr_active) {
			assert_non_null(btree->root->key_vals[i]);
		} else {
			assert_null(btree->root->key_vals[i]);
		}
		assert_null(btree->root->children[i]);
	}

	assert_int_equal(*((uint64_t *) btree->root->key_vals[0]->kv_key), 100);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[0]->kv_val), 1000);
	assert_int_equal(btree->root->key_vals[0]->kv_flags, 0x00);

	assert_int_equal(*((uint64_t *) btree->root->key_vals[1]->kv_key), 200);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[1]->kv_val), 2000);
	assert_int_equal(btree->root->key_vals[1]->kv_flags, 0x00);

	assert_int_equal(btree->root->bn_flags, 0x00);

	bt_node_t * rt   = btree->root;
}

/**
 * btree_test_03_04_load_150
 *
 * Test sequence 03, step 04.  Load a key/val of {150, 1500}.
 */
static void
btree_test_03_04_load_150(void **state)
{
	btree_t *btree = (btree_t*) *state;

	node_pos_t parent = {NULL, 0};
	bt_node_t * node = NULL;

	btree_test_03_load_kv(btree, parent, &node, TRUE, 0, 150, 1500, 0);

	assert_non_null(btree);
	assert_non_null(btree->root);
	assert_int_equal(btree->root->nr_active, 3);
	assert_true(btree->root->leaf);
	assert_int_equal(btree->root->level, 0);

	for (int32_t i = 0; i < btree->order * 2; i++) {
		if (i < btree->root->nr_active) {
			assert_non_null(btree->root->key_vals[i]);
		} else {
			assert_null(btree->root->key_vals[i]);
		}
		assert_null(btree->root->children[i]);
	}

	assert_int_equal(*((uint64_t *) btree->root->key_vals[0]->kv_key), 100);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[0]->kv_val), 1000);
	assert_int_equal(btree->root->key_vals[0]->kv_flags, 0x00);

	assert_int_equal(*((uint64_t *) btree->root->key_vals[1]->kv_key), 150);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[1]->kv_val), 1500);
	assert_int_equal(btree->root->key_vals[1]->kv_flags, 0x00);

	assert_int_equal(*((uint64_t *) btree->root->key_vals[2]->kv_key), 200);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[2]->kv_val), 2000);
	assert_int_equal(btree->root->key_vals[1]->kv_flags, 0x00);

	assert_int_equal(btree->root->bn_flags, 0x00);

	bt_node_t * rt   = btree->root;
}

/**
 * btree_test_03_05_insert_300
 *
 * Test sequence 03, step 05.  Insert a key/val of {300, 3000}.
 */
static void
btree_test_03_05_insert_300(void **state)
{
	btree_t *btree = (btree_t*) *state;

	node_pos_t parent = {NULL, 0};
	bt_node_t * node = NULL;

	btree_test_02_insert_keyval(btree, 300, 3000, 0);

	assert_non_null(btree);
	assert_non_null(btree->root);
	assert_int_equal(btree->root->nr_active, 4);
	assert_true(btree->root->leaf);
	assert_int_equal(btree->root->level, 0);

	for (int32_t i = 0; i < btree->order * 2; i++) {
		if (i < btree->root->nr_active) {
			assert_non_null(btree->root->key_vals[i]);
		} else {
			assert_null(btree->root->key_vals[i]);
		}
		assert_null(btree->root->children[i]);
	}

	assert_int_equal(*((uint64_t *) btree->root->key_vals[0]->kv_key), 100);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[0]->kv_val), 1000);
	assert_int_equal(btree->root->key_vals[0]->kv_flags, 0x00);

	assert_int_equal(*((uint64_t *) btree->root->key_vals[1]->kv_key), 150);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[1]->kv_val), 1500);
	assert_int_equal(btree->root->key_vals[1]->kv_flags, 0x00);

	assert_int_equal(*((uint64_t *) btree->root->key_vals[2]->kv_key), 200);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[2]->kv_val), 2000);
	assert_int_equal(btree->root->key_vals[1]->kv_flags, 0x00);

	assert_int_equal(*((uint64_t *) btree->root->key_vals[3]->kv_key), 300);
	assert_int_equal(*((uint64_t *) btree->root->key_vals[3]->kv_val), 3000);
	assert_int_equal(btree->root->key_vals[3]->kv_flags, 0x00);

	assert_int_equal(btree->root->bn_flags, 0x02);

	bt_node_t * rt   = btree->root;
}

/**
 * btree_test_03_99_destroy
 *
 * Test sequence 03, step 99.  Destroy btree.
 */
static void
btree_test_03_99_destroy(void **state)
{
	btree_t *btree = (btree_t*) *state;
	btree_destroy(btree);
}

/*******************************************************************************
 * test sequence 4 btree test functions
 ******************************************************************************/

/**
 * btree_test_04_01_create
 *
 * Test sequence 04, step 01.  Create a btree of order 2 and register
 * callbacks.
 */
static void
btree_test_04_01_create(void **state)
{
	btree_t *btree = btree_create(2);
	*state = btree;

	assert_non_null(btree);
	assert_non_null(btree->root);
	assert_int_equal(btree->root->nr_active, 0);
	assert_true(btree->root->leaf);

	for (int32_t i = 0; i < btree->order * 2; i++) {
		assert_null(btree->root->key_vals[i]);
		assert_null(btree->root->children[i]);
	}

	btree->cmp_keys     = btree_test_02_cmp_keys;
	btree->copy_key_val = btree_test_02_copy_key_val;
	btree->copy_key     = btree_test_02_copy_key;
	btree->free_key_val = btree_test_02_free_key_val;
	btree->print_key    = btree_test_02_print_key;
	btree->free_node    = btree_test_02_free_node;
}

/**
 * btree_test_04_02_misc
 *
 * Test sequence 04, step 02.
 *     Load a key/val of {100, 1000}.
 *     Load a key/val of {200, 2000}.
 *     Load a key/val of {300, 3000}.
 *     Load a key/val of {400, 4000}.
 *     Insert a key/val of {150, 1500}
 */
static void
btree_test_04_02(void **state)
{
	btree_t *btree = (btree_t*) *state;

	node_pos_t parent = {NULL, 0};
	bt_node_t * node = NULL;
	bt_node_t * root = NULL;
	bt_node_t * chd1 = NULL;
	bt_node_t * chd2 = NULL;

	btree_test_03_load_kv(btree, parent, &node, TRUE, 0, 100, 1000, 0);
	btree_test_03_load_kv(btree, parent, &node, TRUE, 0, 200, 2000, 0);
	btree_test_03_load_kv(btree, parent, &node, TRUE, 0, 300, 3000, 0);
	btree_test_03_load_kv(btree, parent, &node, TRUE, 0, 400, 4000, 0);
	btree_test_02_insert_keyval(btree, 150, 1500, 0);

	assert_non_null(btree);
	assert_non_null(btree->root);

	root = btree->root;

	assert_int_equal(root->nr_active, 2);
	assert_false(root->leaf);
	assert_int_equal(root->level, 1);
	assert_int_equal(root->bn_flags, 0x02);
	assert_true(root->key_vals[0] != NULL);
	assert_true(root->key_vals[1] != NULL);
	assert_true(root->key_vals[2] == NULL);
	assert_true(root->key_vals[3] == NULL);

	assert_true(root->children[0] != NULL);
	assert_true(root->children[1] != NULL);
	assert_true(root->children[2] == NULL);
	assert_true(root->children[3] == NULL);

	assert_int_equal(*((uint64_t *) root->key_vals[0]->kv_key), 200);
	assert_int_equal(*((uint64_t *) root->key_vals[1]->kv_key), 400);

	assert_int_equal(root->key_vals[0]->kv_flags, 0x00);
	assert_int_equal(root->key_vals[1]->kv_flags, 0x00);

	chd1 = root->children[0];

	assert_int_equal(chd1->nr_active, 3);
	assert_true(chd1->leaf);
	assert_int_equal(chd1->level, 0);
	assert_int_equal(chd1->bn_flags, 0x02);

	assert_true(chd1->key_vals[0] != NULL);
	assert_true(chd1->key_vals[1] != NULL);
	assert_true(chd1->key_vals[2] != NULL);
	assert_true(chd1->key_vals[3] == NULL);

	assert_true(chd1->children[0] == NULL);
	assert_true(chd1->children[1] == NULL);
	assert_true(chd1->children[2] == NULL);
	assert_true(chd1->children[3] == NULL);

	assert_int_equal(*((uint64_t *) chd1->key_vals[0]->kv_key), 100);
	assert_int_equal(*((uint64_t *) chd1->key_vals[1]->kv_key), 150);
	assert_int_equal(*((uint64_t *) chd1->key_vals[2]->kv_key), 200);

	assert_int_equal(chd1->key_vals[0]->kv_flags, 0x00);
	assert_int_equal(chd1->key_vals[1]->kv_flags, 0x00);
	assert_int_equal(chd1->key_vals[2]->kv_flags, 0x00);

	chd2 = root->children[1];

	assert_int_equal(chd2->nr_active, 2);
	assert_true(chd2->leaf);
	assert_int_equal(chd2->level, 0);
	assert_int_equal(chd2->bn_flags, 0x02);

	assert_true(chd2->key_vals[0] != NULL);
	assert_true(chd2->key_vals[1] != NULL);
	assert_true(chd2->key_vals[2] == NULL);
	assert_true(chd2->key_vals[3] == NULL);

	assert_true(chd2->children[0] == NULL);
	assert_true(chd2->children[1] == NULL);
	assert_true(chd2->children[2] == NULL);
	assert_true(chd2->children[3] == NULL);

	assert_int_equal(*((uint64_t *) chd2->key_vals[0]->kv_key), 300);
	assert_int_equal(*((uint64_t *) chd2->key_vals[1]->kv_key), 400);

	assert_int_equal(chd2->key_vals[0]->kv_flags, 0x00);
	assert_int_equal(chd2->key_vals[1]->kv_flags, 0x00);
}

/**
 * btree_test_04_99_destroy
 *
 * Test sequence 04, step 99.  Destroy btree.
 */
static void
btree_test_04_99_destroy(void **state)
{
	btree_t *btree = (btree_t*) *state;
	btree_destroy(btree);
}

/*******************************************************************************
 * test sequence 5 btree test functions
 ******************************************************************************/

/**
 * btree_test_05_01_create
 *
 * Test sequence 05, step 01.  Create a btree of order 2 and register
 * callbacks.
 */
static void
btree_test_05_01_create(void **state)
{
	btree_t *btree = btree_create(2);
	*state = btree;

	assert_non_null(btree);
	assert_non_null(btree->root);
	assert_int_equal(btree->root->nr_active, 0);
	assert_true(btree->root->leaf);

	for (int32_t i = 0; i < btree->order * 2; i++) {
		assert_null(btree->root->key_vals[i]);
		assert_null(btree->root->children[i]);
	}

	btree->cmp_keys     = btree_test_02_cmp_keys;
	btree->copy_key_val = btree_test_02_copy_key_val;
	btree->copy_key     = btree_test_02_copy_key;
	btree->free_key_val = btree_test_02_free_key_val;
	btree->print_key    = btree_test_02_print_key;
	btree->free_node    = btree_test_02_free_node;
}

/**
 * btree_test_05_02_misc
 */
static void
btree_test_05_02_misc(void **state)
{
	btree_t *btree = (btree_t*) *state;
	int i;

	node_pos_t parent = {NULL, 0};
	bt_node_t * node = NULL;
	bt_node_t * root = NULL;
	bt_node_t * rt =  NULL;

	btree_test_03_load_kv(btree, parent, &node, TRUE, 0, 0000, 0000, 0);
	btree_test_03_load_kv(btree, parent, &node, TRUE, 0, 1000, 1000, 0);
	btree_test_03_load_kv(btree, parent, &node, TRUE, 0, 2000, 2000, 0);
	btree_test_03_load_kv(btree, parent, &node, TRUE, 0, 3000, 3000, 0);

	rt = btree->root;

	for (i = 4; i < 8; i++) {
		btree_test_02_insert_keyval(btree, (i * 1000), (i * 1000), 0);
	}

	rt = btree->root;

	assert_int_equal(rt->nr_active, 3);
	assert_int_equal(rt->level, 1);

	bt_node_t * r_c0 = rt->children[0];
	bt_node_t * r_c1 = rt->children[1];
	bt_node_t * r_c2 = rt->children[2];

	assert_int_equal(r_c0->nr_active, 2);
	assert_int_equal(r_c0->level, 0);

	assert_int_equal(r_c1->nr_active, 2);
	assert_int_equal(r_c1->level, 0);

	assert_int_equal(r_c2->nr_active, 4);
	assert_int_equal(r_c2->level, 0);

	btree_test_02_insert_keyval(btree, 500, 500, 0);

	rt = btree->root;
	r_c0 = rt->children[0];
	r_c1 = rt->children[1];
	r_c2 = rt->children[2];

	assert_int_equal(rt->nr_active, 3);
	assert_int_equal(rt->level, 1);

	assert_int_equal(r_c0->nr_active, 3);
	assert_int_equal(r_c0->level, 0);

	assert_int_equal(r_c1->nr_active, 2);
	assert_int_equal(r_c1->level, 0);

	assert_int_equal(r_c2->nr_active, 4);
	assert_int_equal(r_c2->level, 0);

	btree_test_02_insert_keyval(btree, 1500, 500, 0);
}

/**
 * btree_test_05_99_destroy
 *
 * Test sequence 04, step 99.  Destroy btree.
 */
static void
btree_test_05_99_destroy(void **state)
{
	btree_t *btree = (btree_t*) *state;
	btree_destroy(btree);
}

/* ****************************************************************************
 *
 * ***************************************************************************/

/**
 * btree_test_setup
 */
static void
btree_test_setup(void **state)
{
}

/**
 * btree_test_teardown
 */
static void
btree_test_teardown(void **state)
{
}

/*******************************************************************************
 * main
 ******************************************************************************/
int
main()
{
	const UnitTest tests[] = {

		unit_test_setup( btree_test_01_01_create, btree_test_setup ),
		unit_test( btree_test_01_02_insert_abc ),
		unit_test( btree_test_01_03_insert_def ),
		unit_test( btree_test_01_04_insert_abc ),
		unit_test( btree_test_01_05_insert_bcd ),
		unit_test( btree_test_01_06_insert_efg ),
		unit_test( btree_test_01_07_insert_ddd ),
		unit_test( btree_test_01_08_delete_bcd ),
		unit_test_teardown( btree_test_01_99_destroy, btree_test_teardown ),

		unit_test_setup( btree_test_02_01_create, btree_test_setup ),
		unit_test( btree_test_02_02_insert_100 ),
		unit_test( btree_test_02_03_insert_200 ),
		unit_test( btree_test_02_04_insert_100 ),
		unit_test( btree_test_02_05_insert_150 ),
		unit_test( btree_test_02_06_insert_400 ),
		unit_test( btree_test_02_07_insert_300 ),
		unit_test_teardown( btree_test_02_08_destroy, btree_test_teardown ),

		unit_test_setup( btree_test_03_01_create, btree_test_setup ),
		unit_test( btree_test_03_02_load_100 ),
		unit_test( btree_test_03_03_load_200 ),
		unit_test( btree_test_03_04_load_150 ),
		unit_test( btree_test_03_05_insert_300 ),
		unit_test_teardown( btree_test_03_99_destroy, btree_test_teardown ),

		unit_test_setup( btree_test_04_01_create, btree_test_setup ),
		unit_test( btree_test_04_02),
		unit_test_teardown( btree_test_04_99_destroy, btree_test_teardown ),

		unit_test_setup( btree_test_05_01_create, btree_test_setup ),
		unit_test( btree_test_05_02_misc ),
		unit_test_teardown( btree_test_05_99_destroy, btree_test_teardown ),
	};
	return run_tests(tests);
}
