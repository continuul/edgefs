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
#ifndef __STATE_H__
#define __STATE_H__

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * struct transition - represents row of the transition table
 *
 * Example of usage:
 *
 * const struct transition tbl[] = {
 * // FROM	EVENT		ACTION		TO		GUARD
 * //---------------------------------------------------------------------
 * { ST_INIT,	EV_HEADER,	&st_init,	ST_DATA,	NULL},
 * { ST_DATA,	EV_TRAILER,	&st_done,	ST_TERM,	NULL},
 * { ST_DATA,	EV_DATA,	&st_incoming,	ST_DATA,	NULL},
 * { ST_ANY,	EV_ANY,		&st_error,	ST_TERM,	NULL}
 * };
 */
struct state;
struct transition {
	int from;				/* from state */
	int ev;					/* event id */
	void (*action)(struct state *);		/* function to be called */
	int to;					/* to state */
	int (*condition)(struct state *);	/* condition to be evaluated */
};

struct ccow_io;

typedef void (*state_term_t)(struct state *);
struct state {
	const struct transition *table;	/* transition table */
	int32_t max;			/* max # of entries in the table */
	int32_t cur;			/* current state */
	int32_t prev;			/* previous state */
	struct ccow_io *io;		/* pointer to I/O in progress */
	int ev_cur;			/* current event */
	int ev_prev;			/* previous event (used for debug) */
	void *data;			/* pointer to context */
	state_term_t term_cb;		/* called at the end of state machine */
	int ev_next;			/* insert "next" event */
	int st_next;			/* override "next" state */
};

/* wildcard events and wildcard state */
#define EV_ANY		-1
#define ST_ANY		-1

/*
 * Events definitions and ranges
 *
 * 0 - 99	Replicast Opcodes (used as Event Ids)
 * 100 - 199	Common Events (shared in this header file)
 * 200 - 299	Custom Events (typically static defined in .c files)
 *
 * Some common events:
 */
#define EV_ERR		100
#define EV_CALL		101
#define EV_TIMEOUT	102
#define EV_START	103
#define EV_SEND		104
#define EV_DONE		105
#define EV_OFFLINE  106

/*
 * States definitions
 *
 * Transition table defines from/to states. States used to build Finite State
 * Machine and Events used to enter it within designed graph. Transition table
 * maps to FSM's directed graph one to one which makes life a little bit
 * easier...
 *
 * Some common states:
 */
#define ST_UNUSED	0
#define ST_INIT		1
#define ST_WAIT		2
#define ST_READY	3
#define ST_BUSY		4
#define ST_TERM		5
#define ST_OFFLINE  6

static inline void
state_init(struct state *s, const struct transition *tbl, int32_t states_nr,
	  void *data, state_term_t term_func)
{
	s->cur = ST_INIT;
	s->table = tbl;
	s->max = states_nr;
	s->data = data;
	s->term_cb = term_func;
}

static inline void
state_next(struct state *s, int ev)
{
	log_trace(lg, "st %p ev %d: prev %d ev_prev %d cur %d", s, ev,
	    s->prev, s->ev_prev, s->cur);
	s->ev_next = ev;
}

static inline void
state_override(struct state *s, int new_st)
{
	log_trace(lg, "st %p new_st %d: prev %d ev_prev %d cur %d", s, new_st,
	    s->prev, s->ev_prev, s->cur);
	s->st_next = new_st;
}

static inline int
state_check(struct state *s, int st)
{
	return s->cur == st;
}

static inline void
state_event(struct state *s, int ev)
{
	int i;

	log_trace(lg, "st %p ev %d: prev %d ev_prev %d cur %d", s, ev,
	    s->prev, s->ev_prev, s->cur);

	if (s->cur == ST_TERM) {
		log_debug(lg, "FSM %p: entering while it's in ST_TERM: "
		    "prev %d ev_prev %d cur %d", s, s->prev, s->ev_prev,
		    s->cur);
		return;
	}

	for (i = 0; i < s->max; i++) {
		if ((s->table[i].from != s->cur &&
			    s->table[i].from != ST_ANY) ||
		    (s->table[i].ev != ev && s->table[i].ev != EV_ANY))
			continue;

		s->ev_cur = ev;
		if (s->table[i].condition && !s->table[i].condition(s))
			goto skip_action;

		if (s->table[i].action)
			s->table[i].action(s);
		s->ev_prev = ev;
		s->prev = s->cur;
		if (!s->st_next)
			s->cur = s->table[i].to;
		else {
			s->cur = s->st_next;
			s->st_next = 0;
		}
		log_debug(lg, "FSM %p: prev %d ev_prev:ev_next %d:%d => "
		    "cur %d", s, s->prev, s->ev_prev, s->ev_next, s->cur);
skip_action:
		if (s->ev_next) {
			ev = s->ev_next;
			s->ev_next = 0;
			i = 0;
			continue;
		}
		break;
	}
	if (s->cur == ST_TERM) {
		assert(s->term_cb);
		s->term_cb(s);
	}
}

static inline int
state_verify_opcode(struct state *s, int opcode)
{
	for (int i = 0; i < s->max; i++) {
		if (s->table[i].ev == opcode || s->table[i].ev == EV_ANY)
			return 1;
	}
	return 0;
}

#ifdef	__cplusplus
}
#endif

#endif
