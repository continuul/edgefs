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
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include "btree.h"
#include "rtbuf.h"

#if _BTML_MEM_LEAK
void *  _BTML_TRACE[_BTML_MAX_TRACE];
#endif

static bt_node_t * allocate_btree_node(struct _btree_ *btree);
static int free_btree_node(btree_t * btree, bt_node_t * node,
    node_pos_t * parent_pos);

/*
 * btree_dump_node
 *
 * dump a specific btree node.
 */
void
btree_dump_node(const btree_t *btree, const bt_node_t *node)
{
	int i;

	printf(
	    "----------------------------------------------------------\n"
	    "NODE  : node      = %p \n"
	    "      : nr_active = %d \n"
	    "      : leaf      = %d \n"
	    "      : level     = %d \n"
	    "      : bn_flags  = 0x%2.2x \n",
	    node, node->nr_active, node->leaf, node->level, node->bn_flags);

	for (i = 0; i < node->nr_active; i++) {
		printf("             : key       = ");
		btree->print_key(node->key_vals[i]->kv_key, 1);
		printf("\n");
	}

	if (btree->print_val != NULL) {
		for (i = 0; i < node->nr_active; i++) {
			printf("             : val       = ");
			btree->print_val(node->key_vals[i]->kv_val);
			printf("\n");
		}
	}

	for (i = 0; i < node->nr_active; i++) {
		printf("             : child     = %p \n",
		    node->children[i]);
	}

	printf("----------------------------------------------------------\n");
}

/*
 * btree_dump_recurse
 *
 * recursively dump each btree node.
 */
static void
btree_dump_recurse(const btree_t *btree, const bt_node_t *node, int first)
{
	int i;
	static int node_count = 0;

	if (first)
		node_count = 1;
	else
		node_count++;

	printf(
	    "----------------------------------------------------------\n"
	    "BTREE : node      = %p (%4d) \n"
	    "      : nr_active = %d \n"
	    "      : leaf      = %d \n"
	    "      : level     = %d \n"
	    "      : bn_flags  = 0x%2.2x \n",
	    node, node_count, node->nr_active, node->leaf, node->level,
	    node->bn_flags);

	for (i = 0; i < node->nr_active; i++) {
		printf( "      : kv        = {%p, %p, %p}\n",
		    node->key_vals[i], node->key_vals[i]->kv_key,
		    node->key_vals[i]->kv_val);
	}

	for (i = 0; i < node->nr_active; i++) {
		printf( "      : key       = %s \n",
		    btree->print_key(node->key_vals[i]->kv_key, 0));
	}

	if (btree->print_val != NULL) {
		for (i = 0; i < node->nr_active; i++) {
			printf( "      : val       = ");
			btree->print_val(node->key_vals[i]->kv_val);
			printf( "\n");
		}
	}

	for (i = 0; i < node->nr_active; i++) {
		printf( "      : child     = %p \n",
		    node->children[i]);
	}

	for (i = 0; i < node->nr_active; i++) {
		if  (node->children[i] != NULL) {
			btree_dump_recurse(btree, node->children[i], 0);
		}
	}
}

/*
 * btree_dump
 *
 * dump the contents of the btree structure. then initiate a recursive dump
 * of all the btree nodes.
 */
void
btree_dump(btree_t *btree)
{
	printf( "==========================================================\n");
	printf(
	       "BTREE : btree     = %p \n"
	       "      : order     = %d \n"
	       "      : root      = %p \n",
	    btree, btree->order, btree->root);

	btree_dump_recurse(btree, btree->root, 1);

	printf( "==========================================================\n");
}

/*
 *  btree_bin_search
 *
 *  Binary search for the correct index for the specified key.
 *
 *  Returns:
 *     -1 : key is less than the key at position index.
 *      0 : key is equal to the key at position index.
 *      1 : key is greater than the key at position index.
 */
int btree_bin_search(btree_t * btree, bt_key_val_t * kv,
    bt_node_t * node, int * index)
{
	assert(btree != NULL);
	assert(kv != NULL);
	assert(node != NULL);
	assert(index != NULL);

	*index = 0;

	if (node->nr_active == 0)
		return 1;

	int s  = 0;					// starting index
	int e  = node->nr_active - 1;			// ending index
	int l  = (e - s) + 1;				// length
	int c  = 0;
	int i  = 0;
	int p  = e;

	if (node->leaf) {
		while (l > 0) {
			i = s + (l/2);
			c = btree->cmp_keys(kv->kv_key, node->key_vals[i]->kv_key);

			if (c < 0) {
				e = i - 1;
			} else if (c == 0) {
				break;
			} else {
				s = i + 1;
			}

			l = (e - s) + 1;
		}
	} else {
		while (l > 0) {
			i = s + (l/2);

			c = btree->cmp_keys(kv->kv_key, node->key_vals[i]->kv_key);

			if (c < 0) {
				if (i < p) p = i;
				e = i - 1;
			} else if (c == 0) {
				p = i;
				break;
			} else {
				s = i + 1;
			}

			l = (e - s) + 1;
		}

		i = p;
		if (c > 0) c = -1;
	}

	*index = i;
	return c;
}

/*
 * btree_create
 *
 * used to create a btree with just the root node
 */
CCOW_EI_TAG_DEFINE(btree_create_01, 1);

btree_t *
btree_create(unsigned int order)
{
	int err;

	assert(order > 1);
	assert((order & 0x001) == 0);

	btree_t * btree = (btree_t *) BT_MALLOC(sizeof(*btree));
	CCOW_EI_TAG_ALLOC_INC(btree_create_01, btree);

	if (btree == NULL) {
		return NULL;
	}
	memset(btree, 0, sizeof(*btree));

	btree->order = order;
	btree->root = allocate_btree_node(btree);

	if (btree->root == NULL) {
		BT_FREE(btree);
		return NULL;
	}

	btree->root->leaf = TRUE;
	btree->root->nr_active = 0;
	btree->root->level = 0;

	return btree;
}

/*
 * allocate_btree_node
 *
 * function used to allocate memory for the btree node
 */
CCOW_EI_TAG_DEFINE(allocate_btree_node_01, 1);
CCOW_EI_TAG_DEFINE(allocate_btree_node_02, 1);

static bt_node_t *
allocate_btree_node (struct _btree_ *btree)
{
	bt_node_t *node;
	size_t size;

	/* allocate memory for the node */
	node = (bt_node_t *) BT_MALLOC(sizeof(bt_node_t));
	CCOW_EI_TAG_ALLOC_INC(allocate_btree_node_01, node);

	if (node == NULL) {
		return NULL;
	}

	/*
	 * initialize the number of active nodes to zero, it's an empty node
	 * for now
	 */
	node->nr_active = 0;

	/* initialize the keyval array */
	size = 2 * btree->order * sizeof(bt_key_val_t *);
	node->key_vals = (bt_key_val_t **) BT_MALLOC(size);
	if (node->key_vals == NULL) {
		assert(0);
		BT_FREE(node);
		return NULL;
	}
	memset(node->key_vals, 0, size);

	/* initialize the child pointer array */
	size = 2 * btree->order * sizeof(bt_node_t *);
	node->children = (bt_node_t **) BT_MALLOC(size);
	if (node->children == NULL) {
		assert(0);
		BT_FREE(node->key_vals);
		BT_FREE(node);
		return NULL;
	}
	memset(node->children, 0, size);

	/* use to determine whether it is a leaf */
	node->leaf = TRUE;

	/* use to determine the level in the tree */
	node->level = 0;
	return node;
}

/*
 * free_btree_node
 *
 * function used to free the memory allocated to the b-tree node
 */
static int
free_btree_node(btree_t * btree, bt_node_t * node, node_pos_t * parent_pos)
{
	int i = 0;

	for (i = 0; i < node->nr_active; i++) {
		btree->free_key_val(btree, node->key_vals[i]);
	}

	BT_FREE(node->children);
	BT_FREE(node->key_vals);
	BT_FREE(node);

	return 0;
}

/*
 * btree_split_child
 *
 * split a full child node into two half-full child nodes and adjust the parent
 */
static int
btree_split_child(btree_t * btree, bt_node_t * parent, int index,
    bt_node_t * child)
{
	int i = 0, err = 0;

	assert(parent != NULL);
	assert(parent->nr_active < btree->order * 2);
	assert(index < btree->order * 2);

	/*
	 * allocate new child node
	 */

	bt_node_t * new_child = allocate_btree_node(btree);
	if (new_child == NULL)
		return -ENOMEM;

	assert(child->nr_active == btree->order * 2);

	new_child->leaf  = child->leaf;
	new_child->level = child->level;
	new_child->nr_active = btree->order;

	BN_FLAG_SET(new_child, BN_FLAG_DIRTY);
	BN_FLAG_SET(child, BN_FLAG_DIRTY);
	BN_FLAG_SET(parent, BN_FLAG_DIRTY);

	/*
	 * copy the higher order keys to the new child
	 */

	for(i=0; i < btree->order; i++) {
		assert(new_child->key_vals[i] == NULL);
		new_child->key_vals[i] = child->key_vals[i + btree->order];
		child->key_vals[i + btree->order] = NULL;

		if(!child->leaf) {
			new_child->children[i] = child->children[i + btree->order];
			child->children[i + btree->order] = NULL;
		}
	}

	child->nr_active = btree->order;

	assert(child->nr_active == btree->order);
	assert(new_child->nr_active == btree->order);
	assert(parent->children[index] == child);

	/*
	 * make room for, then set the the new child and key_vals pointers
	 * within the parent
	 */
	for(i = parent->nr_active; i > index; i--) {
		parent->children[i] = parent->children[i - 1];
		parent->children[i - 1] = NULL;
		assert(parent->key_vals[i] == NULL);
		parent->key_vals[i] = parent->key_vals[i - 1];
		parent->key_vals[i - 1] = NULL;
	}

	bt_key_val_t *tmp_kv = NULL;
	bt_key_val_t *nc_kv  = new_child->key_vals[btree->order - 1];

	/*
	 * special case: if the insert is happening at the right most
	 * (greatest) key-value, then preserve the parent's key-val
	 * if it is greater than the key-val in the new child.
	 */
	err = btree->copy_key_val(btree, nc_kv, &tmp_kv);
	if (err != 0) {
		return err;
	}
	assert(tmp_kv != 0);

	parent->children[index + 1] = new_child;

	err = btree->copy_key_val(btree, tmp_kv, &parent->key_vals[index + 1]);
	if (err != 0) {
		btree->free_key_val(btree, tmp_kv);
		return err;
	}

	err = btree->copy_key_val(btree, child->key_vals[btree->order - 1],
	    &tmp_kv);
	if (err != 0) {
		btree->free_key_val(btree, tmp_kv);
		return err;
	}
	assert(tmp_kv != 0);

	parent->children[index] = child;

	assert(tmp_kv != 0);
	err = btree->copy_key_val(btree, tmp_kv, &parent->key_vals[index]);
	if (err != 0) {
		btree->free_key_val(btree, tmp_kv);
		return err;
	}

	if (tmp_kv != NULL) {
		btree->free_key_val(btree, tmp_kv);
		tmp_kv = NULL;
	}

	BN_FLAG_SET(parent, BN_FLAG_DIRTY);

	parent->nr_active++;
	assert(parent->nr_active <= (btree->order * 2));

	return 0;
}

/*
 * btree_insert_nonfull
 *
 * insert a key in the non-full node
 */
static int
btree_insert_nonfull(btree_t * btree, bt_node_t * parent_node,
    bt_key_val_t * key_val)
{
	int i, err = 0, found = 0;
	bt_node_t * child;
	bt_node_t * node = parent_node;

	if (node->nr_active == 0) {
		/*
		 * this is a special case for btreenam where all the keys have
		 * been deleted.
		 */
		err = btree->copy_key_val(btree, key_val, &node->key_vals[0]);
		if (err != 0)
			return err;

		node->nr_active++;
		BN_FLAG_SET(node, BN_FLAG_DIRTY);

		return 0;
	}

insert: i = node->nr_active - 1;
	BN_FLAG_SET(node, BN_FLAG_DIRTY);

	if (node->leaf) {
		int j;
		int c;

		c = btree_bin_search(btree, key_val, node, &j);

		/*
		 * handle duplicate keys
		 */
		if (c == 0) {
			/* key found, replace kv and return */
			btree->copy_val(node->key_vals[j]->kv_val,
			    key_val->kv_val);

			BN_FLAG_SET(node, BN_FLAG_DIRTY);

			return 0;

		}

		/*
		 * insert the kv into the non-full leaf node
		 */
		if (node->nr_active == 0) {
			err = btree->copy_key_val(btree, key_val, &node->key_vals[0]);
			if (err != 0)
				return err;

			node->nr_active++;
			BN_FLAG_SET(node, BN_FLAG_DIRTY);

			return 0;
		}

		i = node->nr_active - 1;

		if (c > 0) {
			while ((i >= 0) && (i > j)) {
				node->key_vals[i + 1] = node->key_vals[i];
				node->key_vals[i] = NULL;
				i--;
			}
		}

		if (c < 0) {
			while ((i >= 0) && (i >= j)) {
				node->key_vals[i + 1] = node->key_vals[i];
				node->key_vals[i] = NULL;
				i--;
			}
		}

		err = btree->copy_key_val(btree, key_val, &node->key_vals[i + 1]);
		if (err != 0)
			return err;

		node->nr_active++;
		BN_FLAG_SET(node, BN_FLAG_DIRTY);
	} else {
		/*
		 * search the tree
		 */
		int j;
		int c;

		c = btree_bin_search(btree, key_val, node, &j);
		assert(c <= 0);
		i = j;

		if (i == (node->nr_active - 1)) {
			if (btree->cmp_keys(key_val->kv_key,
				    node->key_vals[i]->kv_key) >= 0) {
				/*
				 * the new key is greater than the greatest key 
				 * in the node.  reset the one in the node.
				 */
				err = btree->copy_key_val(btree, key_val,
				    &node->key_vals[i]);
				if (err != 0) {
					btree_destroy(btree);
					return err;
				}

				BN_FLAG_SET(node, BN_FLAG_DIRTY);
			}
		}

		child = node->children[i];

		if(child->nr_active == 2 * btree->order) {

			err = btree_split_child(btree, node, i, child);
			if (err != 0) {
				assert(0);
				btree_destroy(btree);
				return err;
			}

			if (i == (node->nr_active - 1)) {
				if (btree->cmp_keys(key_val->kv_key,
					    node->key_vals[i]->kv_key) >= 0) {
					/*
					 * the new key is greater than the
					 * greatest key in the node.  reset
					 * the one in the node.
					 */
					btree->free_key_val(btree,
					    node->key_vals[i]);
					node->key_vals[i] = key_val;
				}
			}
			if(btree->cmp_keys(key_val->kv_key, node->key_vals[i]->kv_key) > 0) {
				i++;
			}
		}
		node = node->children[i];
		goto insert;
	}

	return 0;
}

/*
 * btree_insert_key
 *
 * insert a key/value into a B-Tree
 */
int
btree_insert_key(btree_t * btree, bt_key_val_t * kv_in, int overwrite)
{
	bt_node_t * rnode = btree->root;
	node_pos_t pos;
	int i = 0;
	int err = 0;

	bt_key_val_t * kv = NULL;

	err = btree->copy_key_val(btree, kv_in, &kv);
	if (err != 0)
		return err;

	err = bt_get_node_pos_by_key(btree, kv->kv_key, &pos, NULL, FALSE,
	    TRUE, FALSE);

	assert((err == 0) || (err == -EAGAIN) || (err == -ENODATA));

	if (err == 0) {
		/* key_val was found. */

		if (overwrite) {

			/* overwrite existing key-val */
			bt_node_t * node = pos.node;
			int j = pos.index;

			err = btree->copy_key_val(btree, kv, &node->key_vals[j]);
			if (err != 0)
				return err;

			err = bt_get_node_pos_by_key(btree, kv->kv_key, &pos, NULL, FALSE,
			    TRUE, TRUE);

			BN_FLAG_SET(node, BN_FLAG_DIRTY);
			btree->free_key_val(btree, kv);

			return 0;
		} else {
			/* return error */
			btree->free_key_val(btree, kv);
			return -EEXIST;
		}
	}

	/*
	 * the key was not found in the btree, it needs to be added
	 */
	rnode = btree->root;

	if (rnode->nr_active == (2 * btree->order)) {
		/*
		 * the node is full and needs to be split
		 */
		bt_node_t * new_root;
		new_root = allocate_btree_node(btree);
		if (new_root == NULL)
			return -ENOMEM;

		new_root->level = btree->root->level + 1;
		btree->root = new_root;
		new_root->leaf = FALSE;

		new_root->nr_active = 1;
		new_root->children[0] = rnode;

		err = btree->copy_key_val(btree, kv, &new_root->key_vals[0]);
		if (err != 0)
			return err;

		btree_split_child(btree, new_root, 0, rnode);
		btree_insert_nonfull(btree, new_root, kv);

	} else {
		/*
		 * the node has space; no need to split
		 */
		btree_insert_nonfull(btree, rnode, kv);
	}

	/*
	 *  FIXME: this seems too heavy handed, explore alternatives.  the
	 *  idea here is to force the right hand branches to have the maximum
	 *  key.
	 */

	bt_key_val_t *max_kv = NULL;
	err = btree->copy_key_val(btree, kv, &max_kv);
	if (err != 0)
		return err;

	bt_node_t *k_node  = btree->root;
	bt_node_t *k_child = NULL;
	int k_n = 0;
	int k_c = 0;
	bt_key_val_t *k_kv = NULL;

	/*
	 * find the max key
	 */
	while (k_node != NULL) {

		k_n  = k_node->nr_active - 1;
		k_kv = k_node->key_vals[k_n];

		if (btree->cmp_keys(k_kv->kv_key, max_kv->kv_key) > 0) {
			/*
			 * the key in the current kv is the largest found so
			 * far, copy it.
			 */
			btree->copy_key(&max_kv->kv_key,  k_kv->kv_key);
		}

		if (k_node->children[k_n] != NULL) {
			k_node = k_node->children[k_n];
		} else {
			break;
		}
	}

	/*
	 * replace right most key with max
	 */
	k_node = btree->root;

	while (k_node != NULL) {

		k_n  = k_node->nr_active - 1;
		k_kv = k_node->key_vals[k_n];

		int cmp = btree->cmp_keys(k_kv->kv_key, max_kv->kv_key);

		if ((cmp < 0) && (!k_node->leaf)) {
			/*
			 * the kv in the node is less than the max, replace it.
			 */
			btree->copy_key(&k_kv->kv_key, max_kv->kv_key);
			BN_FLAG_SET(rnode, BN_FLAG_DIRTY);
		}

		if (k_node->children[k_n] != NULL) {
			k_node = k_node->children[k_n];
		} else {
			break;
		}
	}

	err = btree->free_key_val(btree, max_kv);
	assert(err == 0);

	err = btree->free_key_val(btree, kv);
	assert(err == 0);

	return 0;
}

/*
 * functions used to remove a key/value from a B-Tree
 */
static int
btree_delete_key_01(btree_t * btree, bt_node_t * node, int idx)
{
	int j = 0;
	int nr_active;

	assert(node->nr_active > 0);
	assert(idx < node->nr_active);

	uint8_t mask = (BN_FLAG_DIRTY);
	BN_FLAG_SET(node, mask);

	btree->free_key_val(btree, node->key_vals[idx]);
	node->key_vals[idx] = NULL;

	for (j = idx; j < node->nr_active - 1; j++) {
		node->key_vals[j] = node->key_vals[j + 1];
		node->children[j] = node->children[j + 1];
	}
	node->key_vals[j] = NULL;
	node->children[j] = NULL;

	node->nr_active--;

	nr_active = node->nr_active;

	if ((node == btree->root) && (nr_active == 0)) {
		node->leaf = 1;
		node->level = 0;
	}

	if ((node != btree->root) && (nr_active == 0)) {
		BT_FREE(node->key_vals);
		BT_FREE(node->children);
		BT_FREE(node);
	}

	return nr_active;
}

static int
btree_delete_key_02(btree_t * btree, bt_node_t * node, bt_key_val_t * key_val)
{
	int j = 0;
	int res = 0;
	int nr_active = 0;

	if (node->nr_active == 0) {
		if (node != btree->root) {
			BT_FREE(node->key_vals);
			BT_FREE(node->children);
			BT_FREE(node);
		}

		return -ENOENT;
	}

	uint8_t mask = (BN_FLAG_DIRTY);
	BN_FLAG_SET(node, mask);

	for (j = 0; j < node->nr_active; j++) {

		void *key1 = node->key_vals[j]->kv_key;
		void *key2 = key_val->kv_key;

		res = btree->cmp_keys(key1, key2);

		if (res < 0) {
			/*
			 * key in the j slot is smaller than the key
			 * being searched for.  need to move on to the next
			 * key in the node.
			 */
			continue;

		} else if (res > 0) {
			/*
			 * key in j slot is the 1st key in the node greater
			 * than the key being searched for.  the correct slot
			 * has been found.
			 */
			break;

		} else {
			/*
			 * key in slot j is equal to the key being serached
			 * for.  the correct slot has been found.
			 */
			break;
		}
	}

	if (res == 0) {

		assert(j < node->nr_active);

		if (node->leaf) {
			/* remove the entry from the node */
			nr_active = btree_delete_key_01(btree, node, j);
			return nr_active;
		} else {
			nr_active = btree_delete_key_02(btree, node->children[j],
			    key_val);

			if (nr_active == 0) {
				/* branch node now has zero entries,
				 * remove the entry from the node */
				nr_active = btree_delete_key_01(btree, node, j);
			}

			return nr_active;
		}

	} else if (res > 0) {

		assert(j < node->nr_active);

		if (node->leaf) {
			/* remove the entry from the node */
			return -ENOENT;
		} else {
			nr_active = btree_delete_key_02(btree, node->children[j],
			    key_val);

			if (nr_active == 0) {
				/* branch node now has zero entries,
				 * remove the entry from the node */
				nr_active = btree_delete_key_01(btree, node, j);
			}

			return nr_active;
		}

	} else {
		return -ENOENT;
	}

	assert(0);
	return 0;
}

int
btree_delete_key(btree_t * btree, bt_key_val_t * key_val)
{
	int err = btree_delete_key_02(btree, btree->root, key_val);

	if (err > 0)
		err = 0;

	return err;
}

/*
 *  bt_stack_dump
 *
 *  dump the contents of a bt_stack_t structure,  useful for debugging.
 */
void
bt_stack_dump(bt_stack_t *stack)
{
	int i;

	printf("BT_STACK : idx = %d \n", stack->idx);

	for (i = 0; i < BT_STACK_MAX; i++) {
		if (i < stack->idx) {
			printf("         : ent = %2d : pos.node = %p : "
			    "pos.index = %d : inc = %d\n",
			    i, stack->ent[i].pos.node, stack->ent[i].pos.index,
			    stack->ent[i].inc);
		} else {
			assert(stack->ent[i].pos.node == NULL);
		}
	}
}

/*
 * bt_stack_push
 *
 * push a position onto the stack.  the stack is used for btree traversal,
 * mostly when fetch nodes from persistent storage.
 */
void
bt_stack_push(bt_stack_t *stack, bt_stack_entry_t *ent)
{
	assert(stack != NULL);
	assert(stack->idx < BT_STACK_MAX);

	memcpy(&stack->ent[stack->idx++], ent, sizeof(bt_stack_entry_t));
}

/*
 * bt_stack_pop
 *
 * pop a position from the stack
 */
void
bt_stack_pop(bt_stack_t *stack, bt_stack_entry_t *ent)
{
	assert(stack != NULL);
	assert(stack->idx > 0);
	assert(stack->idx <= BT_STACK_MAX);

	memcpy(ent, &stack->ent[--stack->idx], sizeof(bt_stack_entry_t));
	memset(&stack->ent[stack->idx], 0, sizeof(bt_stack_entry_t));
}

/*
 * bt_stack_peek
 *
 * get the entry from the top of the stack without popping
 */
void
bt_stack_peek(bt_stack_t *stack, bt_stack_entry_t **ent)
{
	assert(stack != NULL);
	assert(stack->idx <= BT_STACK_MAX);

	if (stack->idx == 0) {
		*ent = NULL;
	} else {
		*ent = &stack->ent[stack->idx - 1];
	}
}

/*
 * bt_stack_clear
 *
 * clear the stack
 */
void
bt_stack_clear(bt_stack_t *stack)
{
	memset(stack, 0, sizeof(bt_stack_t));
}

/*
 * bt_get_node_pos_by_pos
 *
 * return the next position in the btree.  this function assumes that the stack
 *  contains the last position traversed for each level of the btree.
 *
 * returns:
 *    0		on success
 *
 *    -EAGAIN	if the search ran into a node that needs to be paged in.
 *		the caller should resume the search from the position
 *		returned after paging in the node.
 *
 *    -ENODATA	the key was not found in the tree.
 */
int
bt_get_node_pos_by_pos(btree_t *btree, node_pos_t *out_pos, bt_stack_t *stack)
{
	uint8_t inc = 0;
	int err = 0;
	bt_stack_entry_t * ent = NULL;
	bt_stack_entry_t child, junk;

	while (TRUE)
	{
		/*
		 * the position on the top of the stack is the last position
		 * returned. the normal case, is that the index for this pos
		 * will be incremented by 1 (unless, of course, this would
		 * span a node)
		 */
		BT_STACK_PEEK(stack, &ent);

		if (ent == NULL) {
			return -ENODATA;
		}

		assert(ent->pos.node != NULL);
		assert(ent->pos.index < ent->pos.node->nr_active);
		assert((ent->inc == 0) || (ent->inc == 1));

		if (ent->pos.node == btree->root) {

			if (ent->pos.index + ent->inc == ent->pos.node->nr_active) {
				/*
				 * the node is the root and there are no more
				 * entries, return -ENODATA
				 */
				BT_STACK_CLEAR(stack);

				out_pos->node  = NULL;
				out_pos->index = 0;

				err = -ENODATA;
				break;
			}

			if (ent->pos.node->leaf) {
				/*
				 * the node is the root and is a leaf and there 
				 * are more entries in the leaf, so increment
				 * the index and return SUCCESS.
				 */
				ent->pos.index += ent->inc;
				ent->inc = 1;

				err = 0;
				break;
			}

			/*
			 * the node is the root and is not a leaf and there are
			 * more entries.  increment the index and proceed with
			 * the child if it is paged into memory
			 */

			if (ent->pos.node->children[ent->pos.index + ent->inc] == NULL) {
				/*
				 * the node is a root and is not a leaf and
				 * there are more entries, but the child has
				 * not been paged in. return -EAGAIN and leave
				 * the position on the stack for re-processing.
				 */
				ent->pos.index += ent->inc;
				ent->inc = 0;

				err =  -EAGAIN;
				break;

			}

			if (ent->pos.node->children[ent->pos.index + ent->inc] != NULL) {
				/*
				 * the node is the root and is not a leaf and
				 * there are more entries.  proceed  with the
				 * child since it is already paged into memory
				 */
				ent->pos.index += ent->inc;
				ent->inc = 1;

				child.pos.node  = ent->pos.node->children[ent->pos.index];
				child.pos.index = 0;
				child.inc       = 0;

				BT_STACK_PUSH(stack, &child);

				continue;
			}
		}

		/*
		 * the node is not the root
		 */

		if (ent->pos.index + ent->inc == ent->pos.node->nr_active) {
			/*
			 * the node is not the root and there are no more
			 * entries, continue with the popped stack
			 */
			BT_STACK_POP(stack, &junk);

			BT_STACK_PEEK(stack, &ent);
			ent->inc = 1;

			continue;
		}

		if (ent->pos.node->leaf) {
			/*
			 * the node is not the root and is a leaf node and
			 * there are more entries.  increment the index and
			 * return SUCCESS.
			 */
			ent->pos.index += ent->inc;
			ent->inc = 1;

			err = 0;
			break;
		}

		if (ent->pos.node->children[ent->pos.index + ent->inc] == NULL) {
			/*
			 * the node is not the root and is not a leaf and
			 * there are more entries.  if the child link is
			 * NULL, the child has yet to be fetched into memory.
			 * return -EAGAIN to tell caller to fetch node.
			 */
			ent->pos.index += ent->inc;
			ent->inc = 0;

			err = -EAGAIN;
			break;
		}

		if (ent->pos.node->children[ent->pos.index + ent->inc] != NULL) {
			/*
			 * the node is not the root and is not a leaf and
			 * there are more entries.  proceed  with the child
			 * since it is paged into memory.
			 */
			ent->pos.index += ent->inc;
			ent->inc = 1;

			child.pos.node  = ent->pos.node->children[ent->pos.index];
			child.pos.index = 0;
			child.inc       = 0;

			BT_STACK_PUSH(stack, &child);

			continue;
		}

		assert(0);
	} /* while */

	*out_pos = ent->pos;

	return err;
}

/*
 * bt_get_node_pos_by_key
 *
 * finds the spefified key and returns the position.
 *
 * returns:
 *    0		on success
 *
 *    -EAGAIN	if the search ran into a node that needs to be paged in.
 *		the caller should resume the search from the position
 *		returned after paging in the node.
 *
 *    -ENODATA	the key was not found in the tree.
 */
int
bt_get_node_pos_by_key(btree_t *btree, void *key, node_pos_t *pos,
    bt_stack_t *stack, int update, int save_stack, int overwrite)
{
	assert(((save_stack == TRUE) && (stack == NULL)) ||
	       ((save_stack == FALSE) && (stack != NULL)));

	int i;
	int skip = 0;
	bt_stack_entry_t tmp;

	bt_node_t * node = NULL;

	if ((!save_stack) && (stack->idx > 0)) {
		i = stack->ent[stack->idx - 1].pos.index;
		node = stack->ent[stack->idx - 1].pos.node;
	} else {
		i = 0;
		node = btree->root;
	}

	assert(node != NULL);

	while (TRUE) {
		if (!skip) {

			/*
			 * find the index of the key which is of greater than or equal
			 * value to that of the key being searched for.  the position
			 * will be the node plus index
			 */

			i = 0;

			bt_key_val_t kv;
			kv.kv_key = key;
			kv.kv_val = NULL;
			kv.kv_flags = 0;

			btree_bin_search(btree, &kv, node, &i);

			/*
			 * push the node onto the stack, which may be used to traverse
			 * the tree
			 */

			tmp.pos.node  = node;
			tmp.pos.index = i;
			tmp.inc       = 1;

			if (!save_stack)
				BT_STACK_PUSH(stack, &tmp);
		}

		skip = 0;

		/*
		 * leaf node
		 */

		if (node->leaf) {

			if (i < node->nr_active) {

				/*
				 * a position within the leaf node was found,
				 * the key may be equal to the key at the
				 * position or may be less than the key at
				 * the position, in either case, the position
				 * will be returned.
				 */

				pos->node  = node;
				pos->index = i;

				if (overwrite)
					BN_FLAG_SET(node, BN_FLAG_DIRTY);

				int cmp = btree->cmp_keys(key, node->key_vals[i]->kv_key);

				if (cmp == 0) {
					/* the key was equal to the key found
					 * in the leaf node.  return success. */
					return 0;
				} else if (cmp == 1) {
					if (pos->index == pos->node->nr_active - 1) {
						/* the key was greater than any key
						 * in the leaf node.  return failure. */
						pos->node  = NULL;
						pos->index = 0;
						return -ENODATA;
					} else {
						/* the key is not found, so return
						 * the next largest key in the node. */
						return -ENODATA;
					}
				} else {
					/* the key was less than the key
					 * in the leaf node.  return failure. */
					return -ENODATA;
				}

			} else {

				/*
				 * a position within the leaf node could not be
				 * determined.
				 */

				pos->node  = NULL;
				pos->index = 0;
				return -ENODATA;
			}

			assert(0);
		}

		/*
		 * branch node
		 */

		if (i < node->nr_active) {

			if (node->children[i] == NULL) {

				/*
				 * a positon in the node was found, but the
				 * child pointer is is NULL. this is an
				 * indication that the child node has not been
				 * fetched into memory from storage.
				 */

				pos->node  = node;
				pos->index = i;
				if (!save_stack)
					BT_STACK_CLEAR(stack);
				return -EAGAIN;

			} else {

				/*
				 * a postion in the node was found and the
				 * child pointer refers to an in memory node.
				 * proceed with the child.
				 */
				if (!save_stack) {
					BT_STACK_POP(stack, &tmp);
					BT_STACK_PUSH(stack, &tmp);
				}
				node = node->children[i];
				if (overwrite)
					BN_FLAG_SET(node, BN_FLAG_DIRTY);
			}
		} else {

			/*
			 * there is no key in the btree which is greater than
			 * the one being searched for.
			 */
			if (update) {
				/*
				 * this is an update. keys may be being
				 * appended.  in this case, fetch in the
				 * right-most child
				 */
				if (i == 0) {
					if (!save_stack)
						BT_STACK_CLEAR(stack);
					return -ENODATA;
				} else if (node->children[i - 1] == NULL) {
					pos->node  = node;
					pos->index = i - 1;
					if (!save_stack)
						BT_STACK_CLEAR(stack);
					return -EAGAIN;
				} else {
					node = node->children[i - 1];
				}

			} else {

				/*
				 * this is a traverse (i.e. a get operation)
				 * return -ENODATA to indicate the key was
				 * not found.
				 */

				pos->node  = node;
				pos->index = i - 1;
				if (!save_stack)
					BT_STACK_CLEAR(stack);
				return -ENODATA;
			}
		}
	}

	/*
	 * gets here only if no leaf is found
	 */

	assert(0);
}

/*
 * btree_destroy_node
 *
 * used to delete a btree node and all its children (recursively).
 */
void
btree_destroy_node(btree_t * btree, bt_node_t *node, node_pos_t parent_pos)
{
	node_pos_t tmp_pos;

	if (node->leaf == TRUE) {
		/* end recursion on leaf node */
		btree->free_node(btree, node, parent_pos);
	} else {
		tmp_pos = parent_pos;

		/* destroy all children */
		for (int i = 0; i < node->nr_active; i++) {
			parent_pos.node  = node;
			parent_pos.index = i;

			if (node->children[i] != NULL) {
				btree_destroy_node(btree, node->children[i],
				    parent_pos);
				node->children[i] = NULL;
			}
		}

		parent_pos = tmp_pos;

		/* then destroy node */
		btree->free_node(btree, node, parent_pos);
	}
}

/*
 * btree_destroy
 *
 * used to destory btree. initiates recursive deletion of btree nodes.
 */
void btree_destroy(btree_t * btree)
{
	node_pos_t parent_pos = {
		.node  = NULL,
		.index = 0
	};

	btree_destroy_node(btree, btree->root, parent_pos);

	if (btree->cb_prev_good_vm != NULL)
		rtbuf_destroy(btree->cb_prev_good_vm);

	BT_FREE(btree);
#if _BTML_MEM_LEAK
	printf("_BTML : %s : %s : %d \n",
	    __FUNCTION__, __FILE__, __LINE__);
	_btml_dump();
#endif
}

/*
 * btree_get_node_recurse
 *
 * performs a depth first, recursive traversal of the in memory btree. the
 * caller provided call back is called once for each node.
 */
int
btree_get_node_recurse(btree_t *btree,
	       bt_node_t *node,
	       bt_node_t *parent,
	       void *context,
	       get_node_cb cb)
{
	int err = 0;

	assert(node != NULL);

	if (node->leaf == TRUE) {
		/* end recursion on leaf node */
		err = cb(btree, node, parent, context);
	} else {
		/* process all children */
		for (int i = 0; i < node->nr_active; i++) {
			if (node->children[i] != NULL) {
				err = btree_get_node_recurse(btree,
				    node->children[i], node, context, cb);

				if (err != 0)
					return err;
			}
		}

		/* then process node */
		err = cb(btree, node, parent, context);
	}
	// check to see if parent node IS the root?
	return err;
}

/*
 * btree_get_nodes
 *
 * used to find all btree nodes. initiates a depth first traversal of the
 * in-memory btree.
 */
int
btree_get_nodes(btree_t * btree,
	void *context,
	get_node_cb cb)
{
	int err;

	bt_node_t * node = btree->root;
	assert(node != NULL);

	btree->cb_pending_cnt = 0;
	btree->cb_node_cnt = 0;
	btree->cb_chnk_cnt = 0;
	btree->cb_done_cnt = 0;
	btree->cb_error_cnt = 0;
	btree->cb_node = NULL;
	btree->cb_parent = NULL;

	err = btree_get_node_recurse(btree, btree->root, NULL, context, cb);
	return err;
}

/*
 * btree_load_kv
 *
 * used to load a node with key-val's.  it was expected that the caller
 * will load the key-val's in order ... but it appears that was an invalid
 * assumption, so order will be enforced by this function.
 *
 * Note that btree will take owner ship of the kv in this function.
 */
int
btree_load_kv(btree_t *btree, node_pos_t parent, bt_node_t **node,
      bool_t leaf, int level, bt_key_val_t *kv)
{
	unsigned int i;
	int j;
	bt_node_t *tmp = *node;

	if (leaf) assert(level == 0);
	if (!leaf) assert(level > 0);

	/*
	 * the parent is null which implies the load is for the root node,
	 * which gets created in btree_create
	 */
	if (parent.node == NULL) {
		tmp = btree->root;
		assert(tmp->nr_active < (2 * btree->order));
	}

	/*
	 * no node was specified and there is a parent, implying that
	 * allocation of a new node is required
	 */
	if (tmp == NULL) {
		if (parent.node == NULL) {
			assert(0);
		}

		if (parent.node->children[parent.index] != NULL) {
			*node = parent.node->children[parent.index];
			return -EINVAL;
		}

		tmp = BT_MALLOC(sizeof(bt_node_t));
		if (tmp == NULL) {
			return -ENOMEM;
		}

		memset(tmp, 0, sizeof(bt_node_t));

		/*
		 * store the reference to the newly allocated child node
		 */
		parent.node->children[parent.index] = tmp;

		/* initialize new node */
		unsigned int order = btree->order;
		bt_key_val_t ** v = BT_MALLOC(2 * order * sizeof(bt_key_val_t*));
		bt_node_t ** n = BT_MALLOC(2 * order * sizeof(bt_node_t *));

		tmp->key_vals = v;
		tmp->children = n;

		for (i = 0; i < (order * 2); i++) {
			tmp->key_vals[i] = NULL;
			tmp->children[i] = NULL;
		}

		tmp->nr_active = 0;
	}

	if (tmp->nr_active > (2 * btree->order)) {
		assert(tmp->nr_active <= (2 * btree->order));
	}

	tmp->leaf  = leaf;
	tmp->level = level;

	if (kv == NULL) {
		return 0;
	}

	/* store the key-value */
	void *new_key = kv->kv_key;
	j = tmp->nr_active;

	while(j >= 0) {
		if (j == 0) {
			tmp->key_vals[j] = kv;
			tmp->children[j] = NULL;
			tmp->nr_active++;
			break;
		} else {
			void *key = tmp->key_vals[j - 1]->kv_key;
			if (btree->cmp_keys(key,new_key) > 0) {
				tmp->key_vals[j] = tmp->key_vals[j - 1];
				tmp->children[j] = tmp->children[j - 1];
				j--;
			} else if (btree->cmp_keys(key,new_key) < 0) {
				tmp->key_vals[j] = kv;
				tmp->children[j] = NULL;
				tmp->nr_active++;
				break;
			} else {
				if (tmp->key_vals[j - 1] != NULL) {
					btree->free_key_val(btree, tmp->key_vals[j - 1]);
				}
				tmp->key_vals[j - 1] = kv;
				break;
			}
		}
	}


	*node = tmp;
	return 0;
}
