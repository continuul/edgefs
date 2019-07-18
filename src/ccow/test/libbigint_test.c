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
#include <unistd.h>
#include <string.h>

#include "ccowutil.h"
#include "cmocka.h"
#include "common.h"
#include "bigint.h"

static void
libbigint_setup(void **state)
{
}


#define STR128_SZ 	(SZ128_16 * 4)+1

#if defined(USE_TABLE)

typedef struct _fixed_table128
{
	uint64_t	firstone64;
	uint64_t	firsttwo64;
	uint64_t	secondone64;
	uint64_t	secondtwo64;
	char            oper;
	char		resultstr[STR128_SZ];
} fixed_table128_t;

static fixed_table128_t   fixedtable128[] = 
{
	{ 0x7FFFFFFFFFFFFF30, 0x7FFFFFFFFFFFEAE0, 0x787A11EF2A25B857, 0x7F0BC95FFFFFFECC, '+', "F87A11EF2A25B787FF0BC95FFFFFE9AC" },
	{ 0x0000000000000000, 0x7FFFFFFFFFFFEAE0, 0x787A11EF2A25B857, 0x0000000000000000, '+', "787A11EF2A25B8577FFFFFFFFFFFEAE0" },
	{ 0x0000000000000005, 0x0000000000000000, 0x0000000000000006, 0x0000000000000000, '+', "   0   0   0   B   0   0   0   0" },
	{ 0x0000000000000000, 0x000000000000000A, 0x0000000000000000, 0x000000000000000F, '+', "   0   0   0   0   0   0   0  19" },
	{ 0x7FFFFFFFFFFFFF30, 0x7FFFFFFFFFFFEAE0, 0x787A11EF2A25B857, 0x7F0BC95FFFFFFECC, '-', " 785EE10D5DA46D9  F4369FFFFFEC14" },
	{ 0x0000000000000000, 0x7FFFFFFFFFFFEAE0, 0x787A11EF2A25B857, 0x0000000000000000, '-', "787A11EF2A25B8568000   0   01520" },
	{ 0x0000000000000000, 0x0000000000000019, 0x0000000000000000, 0x000000000000000A, '-', "   0   0   0   0   0   0   0   F" }
};

#endif



/*  assign some numbers and get them back and check if they match */
static void
libbigint_128_init(void **state)
{
	uuint128_t   first_num;
	uuint128_t   second_num;

	char        *fstr  = "7FFFFFFFFFFFFFF87FFFFFFFFFFFFF94";

	char        *sstr  = "7FFFFFFFFFFFFF307FFFFFFFFFFFFECC";

	uuint128_t   *f1 = set128(&first_num, 0x7FFFFFFFFFFFFFF8, 0x7FFFFFFFFFFFFF94);
	assert_non_null(f1);

	uuint128_t   *s1 = set128(&second_num, 0x7FFFFFFFFFFFFF30, 0x7FFFFFFFFFFFFECC);
	assert_non_null(s1);

	char	outbuf[STR128_SZ];
	sdump_uuint128(&first_num, outbuf, STR128_SZ);

	int err = strcmp(fstr, outbuf);
	assert_int_equal(err, 0);

	sdump_uuint128(&second_num, outbuf, STR128_SZ);
	err = strcmp(sstr, outbuf);
	assert_int_equal(err, 0);

}

static void 
libbigint_128_add(void **state)
{
	uuint128_t   first_num;
	uuint128_t   second_num;
	uuint128_t   result;
	op_t         op;
	char	outbuf[STR128_SZ];

	/*
	 * simple addition first
	 * add known numbers, to known pre-calculated result snd compare
	 */


	uuint128_t   *f1 = set128(&first_num, 0x7FFFFFFFFFFFFF30, 0x7FFFFFFFFFFFEAE0);
	assert_non_null(f1);

	uuint128_t   *s1 = set128(&second_num, 0x787A11EF2A25B857, 0x7F0BC95FFFFFFECC);
	assert_non_null(s1);

	op.op = '+';
	uuint128_t   *res = op128(&result, f1, op, s1);
	assert_non_null(res);

	char *resstr1 = "F87A11EF2A25B787FF0BC95FFFFFE9AC";
	sdump_uuint128(&result, outbuf, STR128_SZ);

	int err = strcmp(resstr1, outbuf);
	assert_int_equal(err, 0);

	f1 = set128(&first_num, 0x0000000000000000, 0x7FFFFFFFFFFFEAE0);
	assert_non_null(f1);

	s1 = set128(&second_num, 0x787A11EF2A25B857, 0x0000000000000000);
	assert_non_null(s1);

	res = op128(&result, f1, op, s1);
	assert_non_null(res);

	char *resstr2 = "787A11EF2A25B8577FFFFFFFFFFFEAE0";
	sdump_uuint128(&result, outbuf, STR128_SZ);

	err = strcmp(resstr2, outbuf);
	assert_int_equal(err, 0);

	f1 = set128(&first_num, 0x0000000000000005, 0x0000000000000000);
	assert_non_null(f1);

	s1 = set128(&second_num, 0x0000000000000006, 0x0000000000000000);
	assert_non_null(s1);

	res = op128(&result, f1, op, s1);
	assert_non_null(res);

	char *resstr3 = "   0   0   0   B   0   0   0   0";
	sdump_uuint128(&result, outbuf, STR128_SZ);

	err = strcmp(resstr3, outbuf);
	assert_int_equal(err, 0);


	f1 = set128(&first_num, 0x0000000000000000, 0x000000000000000A);
	assert_non_null(f1);

	s1 = set128(&second_num, 0x0000000000000000, 0x000000000000000F);
	assert_non_null(s1);

	res = op128(&result, f1, op, s1);
	assert_non_null(res);

	char *resstr4 = "   0   0   0   0   0   0   0  19";
	sdump_uuint128(&result, outbuf, STR128_SZ);

	err = strcmp(resstr4, outbuf);
	assert_int_equal(err, 0);

}

static void 
libbigint_128_sub(void **state)
{
	uuint128_t   first_num;
	uuint128_t   second_num;
	uuint128_t   result;
	op_t         op;
	char	outbuf[STR128_SZ];

	uuint128_t   *f1 = set128(&first_num, 0x7FFFFFFFFFFFFF30, 0x7FFFFFFFFFFFEAE0);
	assert_non_null(f1);

	uuint128_t   *s1 = set128(&second_num, 0x787A11EF2A25B857, 0x7F0BC95FFFFFFECC);
	assert_non_null(s1);

	op.op = '-';
	uuint128_t   *res = op128(&result, f1, op, s1);
	assert_non_null(res);

	char *resstr1 = " 785EE10D5DA46D9  F4369FFFFFEC14";
	sdump_uuint128(&result, outbuf, STR128_SZ);

	// look at both 
	int err = strcmp(resstr1, outbuf);
	assert_int_equal(err, 0);

	f1 = set128(&first_num, 0x0000000000000000, 0x7FFFFFFFFFFFEAE0);
	assert_non_null(f1);

	s1 = set128(&second_num, 0x787A11EF2A25B857, 0x0000000000000000);
	assert_non_null(s1);

	res = op128(&result, s1, op, f1);
	assert_non_null(res);

	char *resstr2 = "787A11EF2A25B8568000   0   01520";
	sdump_uuint128(&result, outbuf, STR128_SZ);
	err = strcmp(resstr2, outbuf);
	assert_int_equal(err, 0);

	f1 = set128(&first_num, 0x0000000000000000, 0x0000000000000019);
	assert_non_null(f1);

	s1 = set128(&second_num, 0x0000000000000000, 0x000000000000000A);
	assert_non_null(s1);

	res = op128(&result, f1, op, s1);
	assert_non_null(res);

	char *resstr3 = "   0   0   0   0   0   0   0   F";
	sdump_uuint128(&result, outbuf, STR128_SZ);
	err = strcmp(resstr3, outbuf);
	assert_int_equal(err, 0);

}

static void 
libbigint_128_mul(void **state)
{
	uuint128_t    first_num, second_num;
	uuint128_t    mfactor;
	uint64_t      factor = 100;
	op_t          mop, aop, cop;
	uuint128_t    mresult;
	uuint128_t    aresult;
        uuint128_t    *res = NULL;
	uint64_t      i,j;

	aop.op = '+';
	mop.op = '*';
	cop.op = '=';

	uuint128_t   *f1 = set128(&first_num, 0x0000345678AF3401, 0x0000345678000000);
	assert_non_null(f1);

	for (i = 1; i <= factor; i++)
	{
                uuint128_t   *s1 = set128(&mfactor, 0x0000000000000000, i);
	        assert_non_null(s1);
                uuint128_t *res = op128(&mresult,f1, mop,s1);
	        assert_non_null(res);


		for (j=1; j <= i; j++)
		{
	                s1 = set128(&second_num, f1->big64[0], f1->big64[1]);
	                assert_non_null(s1);

	                res = op128(s1, f1, aop, s1);
	                assert_non_null(res);
		}

		bool cmpres = cmp128(res,cop, s1);
		assert_true(!cmpres);

	}

}

static void 
libbigint_128_div(void **state)
{
}

#if defined(USE_TABLE)

static void
libbigint_128_op(void **state)
{
	int numentries = sizeof(fixedtable128)/sizeof(fixed_table128_t);
	int i=0;
	fixed_table128_t *ft = &fixedtable128[0];
	uuint128_t	*firstnum, *secondnum, *result;
	op_t            op;
        int		err;
	char		outbuf[STR128_SZ];

	firstnum = je_malloc(sizeof(uuint128_t));
	secondnum = je_malloc(sizeof(uuint128_t));
	result = je_malloc(sizeof(uuint128_t));

	for (i=0; i < numentries; i++)
	{
                firstnum = set128(firstnum, ft->firstone64, ft->firsttwo64);
		assert_non_null(firstnum);

		secondnum = set128(secondnum, ft->secondone64, ft->secondtwo64);
		assert_non_null(secondnum);

		op.op = ft->oper;
		result = op128(result, firstnum, op, secondnum);
                assert_non_null(result);

		sdump_uuint128(result, outbuf, STR128_SZ);
		err = strcmp(ft->resultstr, outbuf);
		assert_int_equal(err, 0);

		ft++;
	}

	je_free(firstnum);
	je_free(secondnum);
	je_free(result);
}

#endif

static void
libbigint_128_logicalop(void **state)
{


}


static void
libbigint_128_cmp(void **state)
{
}

static void
libbigint_128_neg(void **state)
{
}

int
main()
{
	const UnitTest tests[] = {
		unit_test(libbigint_setup),
		unit_test(libbigint_128_init),
		unit_test(libbigint_128_add),
		unit_test(libbigint_128_sub),
#if 0
		unit_test(libbigint_128_neg)
		unit_test(libbigint_256_init),
		unit_test(libbigint_256_op),
		unit_test(libbigint_256_cmp),
		unit_test(libbigint_256_neg)
		unit_test(libbigint_512_init),
		unit_test(libbigint_512_op),
		unit_test(libbigint_512_cmp),
		unit_test(libbigint_512_neg)
#endif
	};
	return run_tests(tests);
}
