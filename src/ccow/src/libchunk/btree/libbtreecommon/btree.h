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
#ifndef _BTREE_H_
#define _BTREE_H_
//
// Platform dependent headers
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <errno.h>

#include "ccowutil.h"

/*
 * bt_key_val
 */

#define KV_FLAG_UNUSED		0x01

typedef struct _bt_key_val_ {
	void *    kv_key;
	void *    kv_val;
	uint32_t  kv_flags;

} bt_key_val_t;

// #define BT_VERBOSE

/*
 * debug macros:
 */
#define _BTML_MEM_LEAK 0	// 1 - enable memory leak debug code
				// 0 - disable memory leak debug code

#if _BTML_MEM_LEAK

#define _BTML_MAX_TRACE 100000
#define _BTML_SIZE (24)

extern void *  _BTML_TRACE[_BTML_MAX_TRACE];

static inline void
_btml_malloc(size_t size, void * ptr)
{
	int i = 0;
	if (size == _BTML_SIZE) {
		for (i = 0; i < _BTML_MAX_TRACE; i++) {
			if (_BTML_TRACE[i] == NULL) {
				break;
			}
		}
		assert(i < _BTML_MAX_TRACE);
		_BTML_TRACE[i] = ptr;
	}
}

static inline void
_btml_calloc(size_t nmemb, size_t size, void * ptr)
{
	int i = 0;
	if (size * nmemb == _BTML_SIZE) {
		for (i = 0; i < _BTML_MAX_TRACE; i++) {
			if (_BTML_TRACE[i] == NULL) {
				break;
			}
		}
		assert(i < _BTML_MAX_TRACE);
		_BTML_TRACE[i] = ptr;
	}
}

static inline void
_btml_free(void * ptr)
{
	int i = 0;
	for (i = 0; i < _BTML_MAX_TRACE; i++) {
		if (_BTML_TRACE[i] ==  ptr) {
			_BTML_TRACE[i] = NULL;
			break;
		}
	}
}

static inline void
_btml_dump(void)
{
	int i = 0, t = 0;
	printf("_BTML : START \n");
	for (i = 0; i < _BTML_MAX_TRACE; i++) {
		if (_BTML_TRACE[i] != NULL) {
			t++;
			printf("_BTML : %6d : _BTML_TRACE[%6d] = %p \n",
			    t, i, _BTML_TRACE[i]);
		}
	}
	printf("_BTML : END \n");
}

#endif

static inline void *
bt_malloc(size_t size, const char * func, const char * file, const int line)
{
	void * rv = je_calloc(1, size);
//#ifdef BT_VERBOSE
#if 0
	printf("BT_MALLOC(%zu) returning %p : %s : %s : %d \n", size, rv,
	    func, file, line);
#endif
#if _BTML_MEM_LEAK
	_btml_malloc(size, rv);
#endif
	return rv;
}

static inline void
bt_free(void * ptr, const char * func, const char * file, const int line)
{
//#ifdef BT_VERBOSE
#if 0
	printf("BT_FREE(%p) : %s : %s : %d \n", ptr, func, file, line);
#endif
	assert(ptr != NULL);
	je_free(ptr);
#if _BTML_MEM_LEAK
	_btml_free(ptr);
#endif
}

static inline void *
bt_calloc(size_t nmemb, size_t size, const char * func, const char * file,
    const int line)
{
	void * rv = je_calloc(nmemb, size);
//#ifdef BT_VERBOSE
#if 0
	printf("BT_CALLOC(%zu, %zu) returning %p : %s : %s : %d \n",
	    nmemb, size, rv, func, file, line);
#endif
#if _BTML_MEM_LEAK
	_btml_calloc(nmemb, size, rv);
#endif
	return rv;
}

#define BT_FREE(_ptr)							\
	bt_free(_ptr, __FUNCTION__, __FILE__, __LINE__);

#define BT_MALLOC(_size)						\
	bt_malloc(_size, __FUNCTION__, __FILE__, __LINE__);

#define BT_CALLOC(_nmemb, _size)					\
	bt_calloc(_nmemb, _size, __FUNCTION__, __FILE__, __LINE__);

#ifndef BT_VERBOSE
#define DBG_PRINT(_format, _args...)
#else
#define DBG_PRINT(_format, _args...)					\
	printf("DEBUG : %s : %s : %d \n",				\
	    __FUNCTION__, __FILE__, __LINE__);				\
	printf("      : "_format"\n", ## _args);
#endif

// FIXME : #ifndef BT_VERBOSE
#if 1
#define BTREE_DUMP(_btree)
#else
#define BTREE_DUMP(_btree)						\
	printf("==========================================================\n"); \
	printf("BTREE_DUMP : %s : %s : %d \n",				\
	    __FUNCTION__, __FILE__, __LINE__);				\
	btree_dump(_btree);
#endif

/*
 * BT_STACK debug macros
 */
#define BT_STACK  0	// 0 - disable stack debug output
			// 1 - enable stack debug output

#if BT_STACK
#define BT_STACK_DUMP(_stack)							\
	printf("==========================================================\n"); \
	printf("BT_STACK_DUMP : %s : %s : %d : stack = %p \n",			\
	    __FUNCTION__, __FILE__, __LINE__, _stack);				\
	bt_stack_dump(_stack);							\
	printf("==========================================================\n"); \

#define BT_STACK_PUSH(_stack, _entry) ({					\
	printf("==========================================================\n"); \
	printf("BT_STACK_PUSH : %s : %s : %d : stack = %p \n",			\
	    __FUNCTION__, __FILE__, __LINE__, _stack);				\
	bt_stack_push(_stack, _entry);						\
	bt_stack_dump(_stack);							\
	printf("==========================================================\n"); \
	0;})


#define BT_STACK_POP(_stack, _entry) ({						\
	printf("==========================================================\n"); \
	printf("BT_STACK_POP : %s : %s : %d : stack = %p \n",			\
	    __FUNCTION__, __FILE__, __LINE__, _stack);				\
	bt_stack_dump(_stack);							\
	bt_stack_pop(_stack, _entry);						\
	printf("==========================================================\n"); \
	0;})

#define BT_STACK_PEEK(_stack, _entry) ({					\
	printf("==========================================================\n"); \
	printf("BT_STACK_PEEK : %s : %s : %d : stack = %p \n",			\
	    __FUNCTION__, __FILE__, __LINE__, _stack);				\
	bt_stack_dump(_stack);							\
	bt_stack_peek(_stack, _entry);						\
	printf("==========================================================\n"); \
	0;})

#define BT_STACK_CLEAR(_stack) ({						\
	printf("==========================================================\n"); \
	printf("BT_STACK_CLEAR : %s : %s : %d : stack = %p \n",			\
	    __FUNCTION__, __FILE__, __LINE__, _stack);				\
	bt_stack_clear(_stack);							\
	printf("==========================================================\n"); \
	0;})

#else
#define BT_STACK_DUMP(_stack)

#define BT_STACK_PUSH(_stack, _entry) ({					\
	bt_stack_push(_stack, _entry);						\
	0;})

#define BT_STACK_POP(_stack, _entry) ({						\
	bt_stack_pop(_stack, _entry);						\
	0;})

#define BT_STACK_PEEK(_stack, _entry) ({					\
	bt_stack_peek(_stack, _entry);						\
	0;})

#define BT_STACK_CLEAR(_stack) ({						\
	bt_stack_clear(_stack);							\
	0;})

#endif


/*
 *
 */

#ifndef BT_VERBOSE
#define CALLING(_func)
#define CALLED
#else
#define CALLING(_func)							\
	printf("CALLING(%s) : %s : %s : %d \n",				\
	    _func, __FUNCTION__, __FILE__, __LINE__);

#define CALLED								\
	printf("CALLED(%s) : %s : %s : %d \n",				\
	    __FUNCTION__, __FUNCTION__, __FILE__, __LINE__);
#endif

/*
 *
 */

#define bcopy bcopy
#define print printf

typedef enum  {
	FALSE = 0,
	TRUE  = 1
} bool_t;

/*
 * bt_node
 */

#define BN_FLAG_DEBUG 0			// 0 disable debug prints
					// 1 enable debug prints
#if BN_FLAG_DEBUG

#define BN_FLAG(_node, _flags) ({						\
	printf("_DBG : BN_FLAG : %s : %s : %d : node = %p : flags = %2.2x \n",	\
	    __FUNCTION__, __FILE__, __LINE__, _node, _node->bn_flags);		\
	((_node->bn_flags & _flags) == _flags);					\
})

#define BN_FLAG_SET(_node, _flags) ({						\
	printf("_DBG : BN_FLAG_SET : %s : %s : %d : node = %p \n",		\
	    __FUNCTION__, __FILE__, __LINE__, _node);				\
	(_node->bn_flags |= _flags);						\
})

#define BN_FLAG_CLR(_node, _flags) ({						\
	printf("_DBG : BN_FLAG_CLR : %s : %s : %d : node = %p \n",		\
	    __FUNCTION__, __FILE__, __LINE__, _node);				\
	(_node->bn_flags &= ~(_flags));						\
})

#else

#define BN_FLAG(_node, _flags) ({						\
	((_node->bn_flags & _flags) == _flags);					\
})

#define BN_FLAG_SET(_node, _flags) ({						\
	(_node->bn_flags |= _flags);						\
})

#define BN_FLAG_CLR(_node, _flags) ({						\
	(_node->bn_flags &= ~(_flags));						\
})

#endif

#define BN_FLAG_UNUSED		0x01
#define BN_FLAG_DIRTY		0x02

typedef struct _bt_node_ {
	bool_t leaf;			// Used to indicate whether leaf or not
        int nr_active;			// Number of active keys
	int level;			// Level in the B-Tree
        bt_key_val_t ** key_vals;	// Array of keys and values
        struct _bt_node_ ** children;	// Array of pointers to child nodes
	uint8_t bn_flags;
} bt_node_t;

typedef struct {
	bt_node_t * node;
	int index;
} node_pos_t;

/*
 * structure defining the btree
 */
typedef struct _btree_ {
	int order;				 // B-Tree order
	bt_node_t * root;			 // Root of the B-Tree
	void * btcm;				 // Pointer to btree-chunk-map
	unsigned long cb_pending_cnt;
	unsigned long cb_done_cnt;
	unsigned long cb_node_cnt;
	unsigned long cb_chnk_cnt;
	unsigned long cb_error_cnt;
	bt_node_t * cb_node;
	bt_node_t * cb_parent;
	void * cb_context;
	void * cb_chunks;
	void * cb_op;
	void * cb_prev_good_vm;

	// compare keys:
	//     negative if key1 < key2
	//     positive if key1 > key2
	//     0 if key1 == key2
	int (*cmp_keys)(void *key1, void *key2);

	// copy (in place) the val
	int (*copy_val)(void *dst, void *src);

	// copy the key
	int (*copy_key)(void **dst, void *src);

	// copy the key value from source to destination
	// (includes allocations for destination).
	int (*copy_key_val)(struct _btree_ *btree,
			    bt_key_val_t *src,
			    bt_key_val_t **dst);

	// free the memory associated with the key-val.
	int (*free_key_val)(struct _btree_ *btree,
			    bt_key_val_t *kv);

	// free the memory associated with the node.
	int (*free_node)(struct _btree_ *btree,
			 bt_node_t *node,
			 node_pos_t parent_pos);

	// print the key
	char * (*print_key)(void *key, int print);

	// print the value (from key_val)
	void (*print_val)(void *val);
} btree_t;

typedef int (*get_node_cb)(struct _btree_ *btree,      // Callback for node iteration
			   bt_node_t *node,
			   bt_node_t *parent,
			   void *context);

/*
 * define stack used in btree traversals:
 */
#define BT_STACK_MAX 20

typedef struct _bt_stack_entry_
{
	node_pos_t pos;
	uint8_t    inc;
} bt_stack_entry_t;

typedef struct _bt_stack_
{
	int8_t idx;
	bt_stack_entry_t ent[BT_STACK_MAX];
} bt_stack_t;

extern btree_t * btree_create(unsigned int order);
extern bt_key_val_t * btree_search(btree_t * btree,  void * key);
extern void btree_destroy(btree_t * btree);
extern void * btree_get_max_key(btree_t * btree);
extern void * btree_get_min_key(btree_t * btree);
//#ifdef DEBUG
extern void print_subtree(btree_t * btree, bt_node_t * node);
//#endif
extern int btree_get_nodes(btree_t *btree, void *contest, get_node_cb cb);

extern int btree_insert_key(btree_t * btree, bt_key_val_t * key_val, int overwrite);

extern int btree_delete_key(btree_t * btree, bt_key_val_t * key_val);

extern int btree_load_kv(btree_t *btree, node_pos_t parent, bt_node_t **node,
	bool_t leaf, int level, bt_key_val_t *kv);

extern int bt_get_node_pos_by_key(btree_t * btree, void * key, node_pos_t *pos, 
				  bt_stack_t *stack, int update, int save_stack,
				  int overwrite);

extern int bt_get_node_pos_by_pos(btree_t *btree, node_pos_t *pos,
				  bt_stack_t *stack);

extern void btree_dump(btree_t *btree);

extern void btree_dump_node(const btree_t *btree, const bt_node_t *node);

extern void btree_destroy_node(btree_t * btree, bt_node_t *node, node_pos_t parent_pos);

extern void btree_verify(btree_t *btree);

extern int btree_count_val(btree_t * btree, void * val);

extern void bt_stack_dump(bt_stack_t *stack);

extern void bt_stack_clear(bt_stack_t *stack);

extern int btree_bin_search(btree_t * btree, bt_key_val_t * kv,
    bt_node_t * node, int * index);

#endif
