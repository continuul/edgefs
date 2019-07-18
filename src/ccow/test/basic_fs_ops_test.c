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
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#include <ccow.h>
#include <ccowd.h>
#include <ccowfsio.h>
#include <cmocka.h>

fsio_fsinfo_t fs_info;
ccow_t tc = NULL;
static ci_t *ci;
int dd = 0;

int
mkdirs(ci_t *ci, char *path, uint16_t mode, uint16_t uid, uint16_t gid)
{
	char *f, *sp, *name;
	inode_t inode, child, parent;
	int err;

	parent = CCOW_FSIO_ROOT_INODE;
	err = 0;
	f = je_strdup(path);

	/* Check to see if the directory already exists. */
	if (ccow_fsio_find(ci, f, &inode) == 0) {
		if (ccow_fsio_is_dir(ci, inode)) {
			printf("%d: directory=%s already exists\n", __LINE__, f);
			err = EEXIST;
			goto done;
		} else {
			printf("%d: path exists but it is not a directory:" " %s\n", __LINE__, f);
			err = EINVAL;
			goto fail;
		}
	}

	/*
	 * At this point, a directory should get created below unless a parent
	 * already exists as a file.
	 */
	sp = NULL;
	name = strtok_r(f, "/", &sp);
	while (name != NULL) {
		err = ccow_fsio_lookup(ci, parent, name, &child);
		if (err == ENOENT) {
			if (ccow_fsio_is_dir(ci, parent)) {
				err = ccow_fsio_mkdir(ci, parent, name, mode, uid, gid, &child);
				if (err != 0) {
					je_free(f);
					return (err);
				}
			} else {
				je_free(f);
				printf("One of path items is not a directory\n");
				return (EINVAL);
			}
		}
		if (err != 0) {
			je_free(f);
			return (err);
		}
		parent = child;
		name = strtok_r(NULL, "/", &sp);
	}

	if (err != 0) {
		printf("%d: mkdir failed on path f=%s, mode=%02o, err=%d\n", __LINE__, f, mode, err);
	}

fail:
done:
	je_free(f);
	return (err);
}

void
printFileStat(ci_t *ci, char *prefix, char *path)
{
	struct stat stat;
	int err;

	inode_t inode;
	err = ccow_fsio_find(ci, path, &inode);
	if (err != 0) {
		printf("%d: File \"%s\" not found\n", __LINE__, path);
		return;
	}
	err = ccow_fsio_get_file_stat(ci, inode, &stat);
	if (err != 0) {
		printf("%d: error '%s' getting file info : %s\n", __LINE__, strerror(err), path);
		return;
	}
	printf("%d: %s: %s: %03o %d:%d i:%ju, lnk:%ld\n", __LINE__, prefix,
	    path, stat.st_mode, stat.st_uid, stat.st_gid, stat.st_ino, (long)stat.st_nlink);
}

int
_touch(ci_t *ci, char *path, uint16_t mode, uint16_t uid, uint16_t gid)
{
	char *dir, *filename;
	inode_t inode;
	int err;

	err = ccow_fsio_find(ci, path, &inode);
	if (err == 0)
		return (EEXIST);
	if (err != ENOENT)
		return (err);

	dir = je_strdup(path);
	if (dir == NULL)
		return (ENOMEM);

	filename = strrchr(dir, '/');
	if (filename == NULL) {
		err = EINVAL;
		goto errout;
	}
	*filename = '\0';
	filename++;
	if (strlen(filename) == 0) {
		err = EINVAL;
		goto errout;
	}
	if (strlen(dir) == 0) {
		inode = CCOW_FSIO_ROOT_INODE;
	} else {
		err = ccow_fsio_find(ci, dir, &inode);
		if (err != 0)
			goto errout;
	}

	ccow_fsio_touch(ci, inode, filename, mode, uid, gid, NULL);

errout:
	je_free(dir);
	return (err);
}

int
dir_cb(inode_t parent, fsio_dir_entry *dir_entry, uint64_t count,  void *ptr)
{
	for (uint64_t i=0; i<count; i++) {
		puts(dir_entry[i].name);
	}
	return 0;
}

static void
readdir_helper(ci_t *ci, char *path, char *start)
{
	inode_t inode;
	assert_int_equal(ccow_fsio_find(ci, path, &inode), 0);
	bool eof;
	assert_int_equal(ccow_fsio_readdir_cb4(ci, inode, dir_cb, start, NULL, &eof), 0);
}

static void
test_dir_op(void **state)
{
	struct stat stat;
	inode_t inode;

	ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, "yyy", 0755, 1, 1, NULL);
	mkdirs(ci, "/etc/rc.d", 0700, 0, 0);
	_touch(ci, "/etc/rc.d/inetd.sh", 0755, 0, 0);
	_touch(ci, "/etc/rc.d/sshd.sh", 0755, 0, 0);
	_touch(ci, "/etc/rc.sh", 0755, 0, 0);
	mkdirs(ci, "/var/log", 0755, 0, 0);
	_touch(ci, "/var/log/messages", 0644, 0, 0);
	_touch(ci, "/var/log/maillog", 0640, 0, 0);
	mkdirs(ci, "/var/run", 0750, 0, 0);
	_touch(ci, "/var/run/inetd.pid", 0640, 0, 0);
	_touch(ci, "/var/run/sshd.pid", 0640, 22, 44);
	_touch(ci, "/README", 0640, 0, 0);

	readdir_helper(ci, "/", NULL);
	readdir_helper(ci, "/etc", NULL);
	readdir_helper(ci, "/var", NULL);
	readdir_helper(ci, "/var/log", NULL);

	assert_int_equal(ccow_fsio_find(ci, "/etc/rc.d/inetd.sh", &inode), 0);
	assert_int_equal(ccow_fsio_get_file_stat(ci, inode, &stat), 0);
	assert_int_equal(stat.st_mode & 0777, 0755);
	assert_int_equal(stat.st_uid, 0);
	assert_int_equal(stat.st_gid, 0);

	assert_int_equal(ccow_fsio_find(ci, "/var/run/sshd.pid", &inode), 0);
	assert_int_equal(ccow_fsio_get_file_stat(ci, inode, &stat), 0);
	assert_int_equal(stat.st_mode & 0777, 0640);
	assert_int_equal(stat.st_uid, 22);
	assert_int_equal(stat.st_gid, 44);
}

static void
test_chmod_chown_op(void **state)
{
	struct stat stat;
	inode_t inode;

	printf("===================== chmod/chown Test ==================\n");
	printFileStat(ci, "/var/run/inetd.pid: ", "/var/run/inetd.pid");
	assert_int_equal(ccow_fsio_find(ci, "/var/run/sshd.pid", &inode), 0);

	assert_int_equal(ccow_fsio_get_file_stat(ci, inode, &stat), 0);
	stat.st_mode = 0777;
	assert_int_equal(ccow_fsio_set_file_stat(ci, inode, &stat), 0);
	assert_int_equal(ccow_fsio_get_file_stat(ci, inode, &stat), 0);
	assert_int_equal(stat.st_mode & 0777, 0777);
	printFileStat(ci, "/var/run/inetd.pid: ", "/var/run/inetd.pid");

	stat.st_uid = 7;
	stat.st_gid = 5;
	assert_int_equal(ccow_fsio_set_file_stat(ci, inode, &stat), 0);
	assert_int_equal(ccow_fsio_get_file_stat(ci, inode, &stat), 0);
	assert_int_equal(stat.st_uid, 7);
	assert_int_equal(stat.st_gid, 5);
	printFileStat(ci, "/var/run/inetd.pid: ", "/var/run/inetd.pid");

	stat.st_mode = 0640;
	stat.st_uid = 0;
	stat.st_gid = 0;
	assert_int_equal(ccow_fsio_set_file_stat(ci, inode, &stat), 0);
	assert_int_equal(ccow_fsio_get_file_stat(ci, inode, &stat), 0);
	assert_int_equal(stat.st_mode & 0777, 0640);
	assert_int_equal(stat.st_uid, 0);
	assert_int_equal(stat.st_gid, 0);
	printFileStat(ci, "/var/run/inetd.pid: ", "/var/run/inetd.pid");
}

static void
test_move_op(void **state)
{
	inode_t inode, inode2, inodetmp;
	struct stat stat;

	printf("===================== Move Test ==========================\n");
	mkdirs(ci, "/aaa/bbb/ccc", 0750, 0, 0);
	_touch(ci, "/aaa/bbb/ccc/TEST", 0640, 0, 0);
	printFileStat(ci, "/aaa/bbb/ccc/TEST: ", "/aaa/bbb/ccc/TEST");
	assert_int_equal(ccow_fsio_find(ci, "/aaa/bbb/ccc/", &inode), 0);
	assert_int_equal(ccow_fsio_move(ci, inode, "TEST", inode, "TESTTEST"), 0);
	/* Will not print, if ok. */
	printFileStat(ci, "/aaa/bbb/ccc/TEST: ", "/aaa/bbb/ccc/TEST");
	printFileStat(ci, "/aaa/bbb/ccc/TESTTEST: ", "/aaa/bbb/ccc/TESTTEST");
	mkdirs(ci, "/AAA", 0750, 0, 0);
	assert_int_equal(ccow_fsio_find(ci, "/aaa", &inode), 0);
	assert_int_equal(ccow_fsio_find(ci, "/aaa/bbb/..", &inodetmp), 0);
	assert(inode == inodetmp);
	assert_int_equal(ccow_fsio_find(ci, "/AAA", &inode2), 0);
	/* Move /aaa/bbb into /AAA/BBB. */
	assert_int_equal(ccow_fsio_move(ci, inode, "bbb", inode2, "BBB"), 0);
	assert_int_equal(ccow_fsio_find(ci, "/AAA/BBB/..", &inodetmp), 0);
	assert(inode2 == inodetmp);

	printFileStat(ci, "/aaa/bbb/ccc/TESTTEST: ", "/aaa/bbb/ccc/TESTTEST");
	printFileStat(ci, "/AAA/BBB/ccc/TESTTEST: ", "/AAA/BBB/ccc/TESTTEST");
}

static void
test_link_op(void **state)
{
	struct stat stat;
	inode_t dir, tf;

	printf("===================== Link Test =========================\n");
	printFileStat(ci, "Dir: ", "/AAA/BBB/ccc");
	printFileStat(ci, "Src: ", "/AAA/BBB/ccc/TESTTEST");
	printFileStat(ci, "Lnk: ", "/AAA/BBB/ccc/TESTTEST.LINK");
	assert_int_equal(ccow_fsio_find(ci, "/AAA/BBB/ccc", &dir), 0);
	assert_int_equal(ccow_fsio_find(ci, "/AAA/BBB/ccc/TESTTEST", &tf), 0);

	assert_int_equal(ccow_fsio_get_file_stat(ci, tf, &stat), 0);
	printf("/AAA/BBB/ccc/TESTTEST has inode = %ju and refcount = %d\n", dir, (short)stat.st_nlink);

	printf("link /AAA/BBB/ccc/TESTTEST /AAA/BBB/ccc/TESTTEST.LINK\n");
	assert_int_equal(ccow_fsio_link(ci, dir, "TESTTEST.LINK", tf), 0);

	printFileStat(ci, "Src: ", "/AAA/BBB/ccc/TESTTEST");
	printFileStat(ci, "Lnk: ", "/AAA/BBB/ccc/TESTTEST.LINK");
	assert_int_equal(ccow_fsio_find(ci, "/AAA/BBB/ccc/TESTTEST", &tf), 0);
	assert_int_equal(ccow_fsio_get_file_stat(ci, tf, &stat), 0);
	printf("/AAA/BBB/ccc/TESTTEST has inode = %ju and refcount = %ld\n", tf, (long)stat.st_nlink);

	printf("unlink /AAA/BBB/ccc/TESTTEST.LINK\n");
	assert_int_equal(ccow_fsio_unlink(ci, dir, "TESTTEST.LINK"), 0);

	printFileStat(ci, "Src: ", "/AAA/BBB/ccc/TESTTEST");
	printFileStat(ci, "Lnk: ", "/AAA/BBB/ccc/TESTTEST.LINK");
	assert_int_equal(ccow_fsio_find(ci, "/AAA/BBB/ccc/TESTTEST", &tf), 0);
	assert_int_equal(ccow_fsio_get_file_stat(ci, tf, &stat), 0);
	printf("/AAA/BBB/ccc/TESTTEST has inode = %ju and refcount = %ld\n", tf, (long)stat.st_nlink);

	printf("link /AAA/BBB/ccc/TESTTEST /AAA/BBB/ccc/TESTTEST.LINK\n");
	assert_int_equal(ccow_fsio_link(ci, dir, "TESTTEST.LINK", tf), 0);

	printFileStat(ci, "Src: ", "/AAA/BBB/ccc/TESTTEST");
	printFileStat(ci, "Lnk: ", "/AAA/BBB/ccc/TESTTEST.LINK");
	assert_int_equal(ccow_fsio_find(ci, "/AAA/BBB/ccc/TESTTEST", &tf), 0);
	assert_int_equal(ccow_fsio_get_file_stat(ci, tf, &stat), 0);
	printf("/AAA/BBB/ccc/TESTTEST has inode = %ju and refcount = %ld\n", tf, (long)stat.st_nlink);

	printf("delete /AAA/BBB/ccc/TESTTEST.LINK\n");
	assert_int_equal(ccow_fsio_find(ci, "/AAA/BBB/ccc", &dir), 0);
	assert_int_equal(ccow_fsio_delete(ci, dir, "TESTTEST.LINK"), 0);

	printFileStat(ci, "Src: ", "/AAA/BBB/ccc/TESTTEST");
	printFileStat(ci, "Lnk: ", "/AAA/BBB/ccc/TESTTEST.LINK");
	assert_int_equal(ccow_fsio_find(ci, "/AAA/BBB/ccc/TESTTEST", &tf), 0);
	assert_int_equal(ccow_fsio_get_file_stat(ci, tf, &stat), 0);
	printf("/AAA/BBB/ccc/TESTTEST has inode = %ju and refcount = %ld\n", tf, (long)stat.st_nlink);
}

static void
test_write_op(void **state)
{
	char *data = "#!/bin/sh\n" "echo \"Starting inetd super server.\"";
	ccow_fsio_file_t *file;
	size_t write_amount;

	printf("===================== Write Test ========================\n");
	ccow_fsio_open(ci, "/etc/rc.d/inetd.sh", &file, O_WRONLY);
	char *data2 = je_strdup(data);
	ccow_fsio_write(file, 0, strlen(data2), (void *)data2, &write_amount);
	ccow_fsio_close(file);
}

static void
test_read_op(void **state)
{
	char *data = "#!/bin/sh\n" "echo \"Starting inetd super server.\"";
	ccow_fsio_file_t *file;
	struct stat stat;
	inode_t inode;
	size_t read;
	char *buf;
	int eof;

	printf("===================== Read Test =========================\n");
	ccow_fsio_open(ci, "/etc/rc.d/inetd.sh", &file, O_RDONLY);
	assert_int_equal(ccow_fsio_find(ci, "/etc/rc.d/inetd.sh", &inode), 0);
	assert_int_equal(ccow_fsio_get_file_stat(ci, inode, &stat), 0);
	assert_true(stat.st_size < 1000);
	assert_true(stat.st_size > 0);
	buf = je_malloc(stat.st_size + 1);
	assert_true(buf != NULL);
	ccow_fsio_read(file, 0, stat.st_size, (void *)buf, &read, &eof);
	ccow_fsio_close(file);
	buf[stat.st_size] = '\0';
	assert_int_equal(strcmp(data, buf), 0);

	printf("%d: file %s, data =\"\n%s\n\"\n", __LINE__, "/etc/rc.d/inetd.sh", buf);
	je_free(buf);
}

static void
test_holes_and_zeros(void **state)
{
	inode_t inode;
	struct stat stat;
	char *data;
	size_t size = 1024 * 1024 * 100;
	ccow_fsio_file_t *file;
	size_t write_amount;
	size_t random_offset = 1024 * 1024 + 10;

	data = (char *) je_malloc(size);
	assert_true(data != NULL);

	printf("===================== Sparse file using setattr ==========================\n");
	_touch(ci, "/file_with_holes", 0755, 0, 0);
	assert_int_equal(ccow_fsio_find(ci, "/file_with_holes", &inode), 0);
	assert_int_equal(ccow_fsio_get_file_stat(ci, inode, &stat), 0);
	stat.st_size = 1024 * 1024 * 1024;

	assert_int_equal(ccow_fsio_set_file_stat(ci, inode, &stat), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, "file_with_holes"), 0);

	printf("===================== Sparse file using seek ==========================\n");
	_touch(ci, "/file_with_holes", 0755, 0, 0);
	assert_int_equal(ccow_fsio_find(ci, "/file_with_holes", &inode), 0);
	assert_int_equal(ccow_fsio_get_file_stat(ci, inode, &stat), 0);


	assert_int_equal(ccow_fsio_open(ci, "/file_with_holes", &file, O_WRONLY), 0);
	assert_int_equal(ccow_fsio_write(file, random_offset, size, (void *)data, &write_amount), 0);
	assert_int_equal(ccow_fsio_close(file), 0);
	assert_int_equal(ccow_fsio_get_file_stat(ci, inode, &stat), 0);
	assert_int_equal(stat.st_size, random_offset + write_amount);

	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, "file_with_holes"), 0);
}

static void
test_cleanup(void **state)
{
	inode_t inode;

	printf("===================== Clean up ==========================\n");
	/* Delete everyting we create. */
	assert_int_equal(ccow_fsio_find(ci, "/etc/rc.d", &inode), 0);
	assert_int_equal(ccow_fsio_delete(ci, inode, "inetd.sh"), 0);
	assert_int_equal(ccow_fsio_delete(ci, inode, "sshd.sh"), 0);

	assert_int_equal(ccow_fsio_find(ci, "/etc", &inode), 0);
	assert_int_equal(ccow_fsio_delete(ci, inode, "rc.sh"), 0);
	assert_int_equal(ccow_fsio_delete(ci, inode, "rc.d"), 0);

	assert_int_equal(ccow_fsio_find(ci, "/var/log", &inode), 0);
	assert_int_equal(ccow_fsio_delete(ci, inode, "messages"), 0);
	assert_int_equal(ccow_fsio_delete(ci, inode, "maillog"), 0);

	assert_int_equal(ccow_fsio_find(ci, "/var/run", &inode), 0);
	assert_int_equal(ccow_fsio_delete(ci, inode, "inetd.pid"), 0);
	assert_int_equal(ccow_fsio_delete(ci, inode, "sshd.pid"), 0);

	assert_int_equal(ccow_fsio_find(ci, "/var", &inode), 0);
	assert_int_equal(ccow_fsio_delete(ci, inode, "log"), 0);
	assert_int_equal(ccow_fsio_delete(ci, inode, "run"), 0);

	assert_int_equal(ccow_fsio_find(ci, "/AAA/BBB/ccc", &inode), 0);
	assert_int_equal(ccow_fsio_delete(ci, inode, "TESTTEST"), 0);

	assert_int_equal(ccow_fsio_find(ci, "/AAA/BBB", &inode), 0);
	assert_int_equal(ccow_fsio_delete(ci, inode, "ccc"), 0);

	assert_int_equal(ccow_fsio_find(ci, "/AAA", &inode), 0);
	assert_int_equal(ccow_fsio_delete(ci, inode, "BBB"), 0);

	/* delete at root '/' */
	printf("Root dir before clean:\n");
	readdir_helper(ci, "/", NULL);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, "aaa"), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, "AAA"), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, "var"), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, "etc"), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, "README"), 0);
	assert_int_equal(ccow_fsio_delete(ci, CCOW_FSIO_ROOT_INODE, "yyy"), 0);
	printf("Root dir after clean:\n");
}

static void
libccowfsio_setup(void **state)
{
	assert_int_equal(ccow_fsio_init(), 0);
	ci = ccow_fsio_ci_alloc();

	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());

	assert_int_equal(ccow_fsio_create_export(ci, "cltest/test/test", path, 4096, NULL, NULL), 0);
}

static void
libccowfsio_teardown(void **state)
{
	ccow_fsio_delete_export(ci);
	ccow_fsio_ci_free(ci);
	ccow_fsio_term();
}

static void
libccowd_setup(void **state)
{
	if (!dd) {
		assert_int_equal(ccow_daemon_init(NULL), 0);
		usleep(2 * 1000000L);
	}
}

static void
libccowd_teardown(void **state)
{
	if (!dd) {
		ccow_daemon_term();
	}
}

static void
libccow_setup(void **state)
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
	int fd = open(path, O_RDONLY);
	assert_true(fd >= 0);
	char *buf = je_calloc(1, 16384);
	assert_non_null(buf);
	assert_true(read(fd, buf, 16383) != -1);
	assert_int_equal(close(fd), 0);
	assert_int_equal(ccow_tenant_init(buf, "cltest", 7, "test", 5, &tc), 0);
	je_free(buf);
}

static void
libccow_bucket_create(void **state)
{
	assert_non_null(tc);

	ccow_completion_t c = NULL;
	uint32_t cs = 1024 * 1024;

	int err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	assert(!err);

	err = ccow_attr_modify_default(c, CCOW_ATTR_CHUNKMAP_CHUNK_SIZE,
	    (void *) &cs, NULL);
	assert(!err);

	err = ccow_bucket_create(tc, "test", 5, c);
	if (err != EEXIST)
		assert_int_equal(err, 0);
}

static void
libccow_bucket_delete(void **state)
{
	int err;
	assert_non_null(tc);

	err = ccow_bucket_delete(tc, "test", 5);
	assert_int_equal(err, 0);
}

static void
libccow_teardown(void **state)
{
	assert_non_null(tc);
	ccow_tenant_term(tc);
}

static void
test_fsinfo_before(void **state)
{
	fsio_fsinfo_t fsinfo;
	int err;

	err = ccow_fsio_fsinfo(ci, &fsinfo);
	assert_int_equal(err, 0);
	printf("FS stats at the beginning\n"
	    "\tbytes { total: %lu, free: %lu, avail: %lu }\n"
	    "\tfiles { total: %lu, free: %lu, avail: %lu }\n",
	    fsinfo.total_bytes, fsinfo.free_bytes, fsinfo.avail_bytes,
	    fsinfo.total_files, fsinfo.free_files, fsinfo.avail_files);
	memcpy(&fs_info, &fsinfo, sizeof(fs_info));
}

static void
test_fsinfo_after(void **state)
{
	fsio_fsinfo_t fsinfo;
	int err;

	/* Wait write buffers to be flushed. */
#define TIMER_INTERVAL 5
	sleep(TIMER_INTERVAL + 1);

	err = ccow_fsio_fsinfo(ci, &fsinfo);
	assert_int_equal(err, 0);
	printf("FS stats at the end\n"
	    "\tbytes { total: %lu, free: %lu, avail: %lu } diff %ld\n"
	    "\tfiles { total: %lu, free: %lu, avail: %lu } diff %ld\n",
	    fsinfo.total_bytes, fsinfo.free_bytes, fsinfo.avail_bytes,
	    ((int64_t)fsinfo.total_bytes - (int64_t)fsinfo.free_bytes),
	    fsinfo.total_files, fsinfo.free_files, fsinfo.avail_files,
	    ((int64_t)fsinfo.total_files - (int64_t)fsinfo.free_files));
	assert_int_equal(fs_info.free_bytes, fsinfo.free_bytes);
	assert_int_equal(fs_info.free_files, fsinfo.free_files);
}

int
main(int argc, char **argv)
{
	if (argc == 2) {
		if (strcmp(argv[1], "-n") == 0)
			dd = 1;
	}

	const UnitTest tests[] = {
		unit_test(libccowd_setup),
		unit_test(libccow_setup),
		unit_test(libccow_bucket_create),
		unit_test(libccowfsio_setup),

		unit_test(test_fsinfo_before),
		unit_test(test_dir_op),
		unit_test(test_chmod_chown_op),
		unit_test(test_move_op),
		/* hard link not supported
		unit_test(test_link_op),
		*/
		unit_test(test_write_op),
		unit_test(test_read_op),
		unit_test(test_holes_and_zeros),
		unit_test(test_cleanup),
		unit_test(test_fsinfo_after),

		unit_test(libccowfsio_teardown),
		unit_test(libccow_bucket_delete),
		unit_test(libccow_teardown),
		unit_test(libccowd_teardown)
	};
	return run_tests(tests);
}
