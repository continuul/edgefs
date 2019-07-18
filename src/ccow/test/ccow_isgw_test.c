/*
 * ccow_isgw_test.c
 *
 *  Created on: Mar 27, 2019
 *      Author: root
 */

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include "ccowutil.h"
#include "cmocka.h"
#include "common.h"
#include "ccow.h"
#include "ccow-impl.h"
#include "ccowd.h"
#include "ccow-dynamic-fetch.h"

static ccow_t tc;

static char *config_buf = NULL;
static pthread_cond_t cond;
static pthread_mutex_t lock;
static int req_count = 0;

static void
libccow_setup(void **state)
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
	int fd = open(path, O_RDONLY);
	assert_true(fd >= 0);
	config_buf = je_calloc(1, 16384);
	assert_non_null(config_buf);
	assert_true(read(fd, config_buf, 16384) != -1);
	assert_int_equal(close(fd), 0);
	assert_int_equal(ccow_admin_init(config_buf, "", 1, &tc), 0);
}

static void
test_proto_cb_t (void *data, int status, void *rsp) {
	printf("data %p, status %d, rsp %p, req_count %d\n", data, status, rsp, req_count);
	je_free(data);
	pthread_mutex_lock(&lock);
	if (--req_count == 0)
		uv_cond_signal(&cond);
	pthread_mutex_unlock(&lock);
}


#define REQ_COUNT 20

static void
isgw_comm_test(void **state) {
	struct dynfetch_data msg = {
		.flags = eIsgwReqPayload,
		.n_chids = 2
	};
	pthread_mutex_init(&lock, NULL);
	pthread_cond_init(&cond, NULL);

	while(1) {

	req_count = REQ_COUNT;

	for (int i = 0; i < REQ_COUNT; i++) {
		msg.chids = je_calloc(2, sizeof(uint512_t));
		msg.chids[0].u.u.u = rand();
		msg.chids[1].u.u.u = rand();
		void* handle;
		assert_int_equal(ccow_isgw_dynamic_fetch_init( "10.3.30.36",
			&msg, test_proto_cb_t, msg.chids, &handle), 0);
	}
	uv_mutex_lock(&lock);
	while (req_count > 0)
		pthread_cond_wait(&cond, &lock);
	uv_mutex_unlock(&lock);
	}
}

static void
libccow_teardown(void **state)
{
	if (config_buf)
		je_free(config_buf);
	assert_non_null(tc);
	ccow_tenant_term(tc);
}

int
main(int argc, char **argv)
{
	const UnitTest tests[] = {
		unit_test(libccow_setup),
		unit_test(isgw_comm_test),
		unit_test(libccow_teardown),
	};
	return run_tests(tests);
}
