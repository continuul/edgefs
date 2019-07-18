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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <uv.h>
#include <queue.h>

#include "ccowutil.h"

struct repdev {
	QUEUE item;
	char *path;
	QUEUE call_queue;
};

struct repdev_call {
	QUEUE item;
	uv_barrier_t barrier;
	void (*method)(struct repdev_call *c);
	void *args[8];
	void *done;
	int rc;
};

struct dir_entry {
	char dir[32];
	char marker[32];
	QUEUE item;
};

static void
add_dir_entry(QUEUE *dir_queue, struct dir_entry *de)
{
	QUEUE_INIT(&de->item);
	QUEUE_INSERT_HEAD(dir_queue, &de->item);
}

static struct dir_entry *
top_dir_entry(QUEUE *dir_queue)
{
	QUEUE *q;
	struct dir_entry *de;
	if (QUEUE_EMPTY(dir_queue))
		return NULL;
	q = QUEUE_NEXT(dir_queue);
	de = QUEUE_DATA(q, struct dir_entry, item);
	return de;
}

static void
remove_free_dir_entry(struct dir_entry *de)
{
	QUEUE_REMOVE(&de->item);
	je_free(de);
}


static void
print_dir_queue(char *header, QUEUE *dir_queue)
{
	QUEUE *q;
	struct dir_entry *de;
	printf("Dir queue %s:\n", header);
	QUEUE_FOREACH(q, dir_queue) {
		de = QUEUE_DATA(q, struct dir_entry, item);
		printf("dir:  %s marker: %s\n", de->dir, de->marker);
	}
	printf("\n");
}

static void
free_dir_queue(QUEUE *dir_queue)
{
	QUEUE *q;
	struct dir_entry *de;
	while (!QUEUE_EMPTY(dir_queue)) {
		q = QUEUE_NEXT(dir_queue);
		QUEUE_REMOVE(q);
		de = QUEUE_DATA(q, struct dir_entry, item);
		je_free(de);
	}
}

static int
copy_dir_queue(QUEUE *queue_to, QUEUE *queue_from)
{
	QUEUE *q;
	struct dir_entry *de, *dee;
	QUEUE_INIT(queue_to);
	QUEUE_FOREACH(q, queue_from) {
		de = QUEUE_DATA(q, struct dir_entry, item);
		dee = je_calloc(1, sizeof(struct dir_entry));
		strcpy(dee->dir, de->dir);
		strcpy(dee->marker, de->marker);
		if (!dee) {
			return -ENOMEM;
		}
		add_dir_entry(queue_to, dee);
	}
	return 0;
}


static void
reptrans_notify_membership_change__async(struct repdev_call *c)
{
	struct repdev *dev = (struct repdev *)c->args[0];
	int join = (long)c->args[1];
	char *mcgrp = (char *)c->args[2];
	uint32_t if_index = (unsigned long)c->args[3];

	if (join) {
		printf("join  %s %s %d\n", dev->path, mcgrp, if_index);
	} else {
		printf("leave %s %s %d\n", dev->path, mcgrp, if_index);
	}
	je_free(mcgrp);
}

int reptrans_notify_membership_change(struct repdev *dev, int join,
	const char *mcgrp, uint32_t if_index)
{
	struct repdev_call *call =
	    je_calloc(1, sizeof(struct repdev_call));
	if (call == NULL) {
		return -ENOMEM;
	}
	call->method = reptrans_notify_membership_change__async;
	call->args[0] = dev;
	call->args[1] = (void *)(long)join;
	call->args[2] = (void *)je_strdup(mcgrp);
	call->args[3] = (void *)(long)if_index;
	QUEUE_INIT(&call->item);
	printf("Adding Queue Entry : %s %s\n", dev->path, mcgrp);
	QUEUE_INSERT_TAIL(&dev->call_queue, &call->item);
	return 0;
}

static void
reptrans_dev__on_call(struct repdev *dev)
{
	QUEUE* q;
	do {
		if (QUEUE_EMPTY(&dev->call_queue)) {
			return;
		}
		q = QUEUE_HEAD(&dev->call_queue);
		struct repdev_call *c = QUEUE_DATA(q, struct repdev_call, item);
		if (c->method == reptrans_notify_membership_change__async)
			printf("Removing Queue Entry: %s %s\n",
				((struct repdev *)c->args[0])->path,
				(char *)c->args[2]);
		QUEUE_REMOVE(q);

		c->method(c);
		je_free(c);
	} while (1);
}

int main(int argc, char *argv[])
{
	char *buf;
	int i;

	
	struct repdev *dev = je_calloc(1, sizeof(struct repdev));
	if (dev == NULL) {
		return -ENOMEM;
	}
	dev->path = "/dev/sdx";
	QUEUE_INIT(&dev->item);
	QUEUE_INIT(&dev->call_queue);


	for (i = 0; i < 8; ++i) {
	 	buf = je_calloc(16, sizeof(char));
	 	sprintf(buf, "ff02::c:%1d00:0:0", i + 1);
	 	reptrans_notify_membership_change(dev, 1, buf, i);
	 	je_free(buf);
	}

	reptrans_dev__on_call(dev);
	je_free(dev);
	
	printf("\n\n");

	QUEUE dir_queue1, dir_queue2;
	struct dir_entry *de;
	QUEUE_INIT(&dir_queue1);
	for (i = 0; i < 5; ++i) {
		de = je_calloc(1, sizeof(struct dir_entry));
		sprintf(de->dir, "d%d", i);
		sprintf(de->marker, "m%d", i);
		add_dir_entry(&dir_queue1, de);
	}	
	copy_dir_queue(&dir_queue2, &dir_queue1);

	print_dir_queue("queue1", &dir_queue1);

	print_dir_queue("queue2 (copy)", &dir_queue2);

	de = top_dir_entry(&dir_queue2);
	
	printf("Queue2 top dir:  %s marker: %s\n\n", de->dir, de->marker);
	remove_free_dir_entry(de);

	print_dir_queue("queue2", &dir_queue2);

	de = top_dir_entry(&dir_queue2);
	printf("Queue2 top dir:  %s marker: %s\n\n", de->dir, de->marker);
	remove_free_dir_entry(de);

	print_dir_queue("queue2", &dir_queue2);

	free_dir_queue(&dir_queue1);

	free_dir_queue(&dir_queue2);


	return 0;
}
