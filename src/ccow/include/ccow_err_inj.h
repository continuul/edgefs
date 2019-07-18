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
#ifndef __CCOW_ERR_INJ__
#define __CCOW_ERR_INJ__

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Error Injection
 */

// use --enable-ccow-error-injection flag to ./configure to enable

#ifdef CCOW_EI

#define CCOW_EI_TAG_EXTERN(_tag)					\
	extern uint32_t _tag##__##loc;					\
	extern uint32_t _tag##__##lim;					\
	extern uint32_t _tag##__##ena;

#define CCOW_EI_TAG_DEFINE(_tag, _lim)					\
	uint32_t _tag##__##loc = 0;					\
	uint32_t _tag##__##lim = _lim;					\
	uint32_t _tag##__##ena = 0;

#define CCOW_EI_TAG_INIT(_tag, _lim)					\
	_tag##__##loc = 0;						\
	_tag##__##lim = _lim;						\
	_tag##__##ena = 1;

#define CCOW_EI_TAG_DISABLE(_tag)					\
	_tag##__##ena = 0;

#define CCOW_EI_TAG_INC(_tag, _err, _new) ({				\
	if (_tag##__##ena) {						\
		_tag##__##loc++;					\
		if (_tag##__##loc == _tag##__##lim) {			\
			_err = _new;					\
		}							\
	}								\
	_err;								\
    })

#define CCOW_EI_TAG_ALLOC_INC(_tag, _mem) ({				\
	if (_tag##__##ena) {						\
		_tag##__##loc++;					\
		if (_tag##__##loc == _tag##__##lim) {			\
			je_free(_mem);					\
			_mem = NULL;					\
		}							\
	}								\
	_mem;								\
    })


#else

#define CCOW_EI_TAG_EXTERN(_tag)
#define CCOW_EI_TAG_DEFINE(_tag, _lim)
#define CCOW_EI_TAG_INIT(_tag, _lim)
#define CCOW_EI_TAG_DISABLE(_tag)
#define CCOW_EI_TAG_INC(_tag, _err, _new) ({0;})
#define CCOW_EI_TAG_ALLOC_INC(_tag, _err) ({_err;})

#endif

#ifdef	__cplusplus
}
#endif

#endif
