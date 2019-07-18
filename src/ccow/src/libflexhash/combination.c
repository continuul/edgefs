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
#include <pthread.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "ccowutil.h"
#include "logger.h"
#include "reptrans.h"
#include "serverid.h"
#include "flexhash.h"

/* Given a set of n numbers select k unique elements in the
 * set given by  n!/ ((n-k)!*k!).
 * Another way to describe this general formula is:
 * [ n * (n - 1) * (n - 2).......(n - k + 1) ]/k!
 *
 * The following algorithm works the following way:
 * If we have combinations C0, C1, C2 ... CN
 * we start from the back(K-1) and go backwards
 * if for a combination if the number is greater than
 * (n - k + 1 + i) incement the value and go to the next index
 *
 *  Essentially,
 *  find the rightmost element A[i] that is less than the max value it can
 *  have ( n - 1) - (k - 1) - i.
 *  Increment it.
 *  Move the index to the next lower value and increment the value
 *  to there can be a sequence
 */

uint32_t
next_combination(uint32_t *A, int k, int n)
{
	int i = k - 1;
	++A[i];

	while ((i > 0) && (A[i] >= (uint32_t) (n - k + 1 + i))) {
		--i;
		++A[i];
	}

	/* reached (n-k, n-k+1, ... n)
	 * no more combinations
	 */
	if (A[0] > (uint32_t) (n - k))
		return 0;

	for (i = i + 1; i < k; i++)
		A[i] = A[i - 1] + 1;

	return 1;
}

int
cmpfunc (const void * a, const void * b)
{
	return ( *(int*)a - *(int*)b );
}

int
combination_compare(uint32_t *haystack, uint32_t *subset, int numsubset)
{
	qsort(haystack, numsubset, sizeof (uint32_t), cmpfunc);
	return (memcmp(haystack, subset, numsubset * sizeof (uint32_t)));
}

// Generate combinations, match the given subset and return the
// index
// index is always greater than 0 because this becomes the offset into the
// Rendezvous group's address.
// approx data size:
// n = maxvdev
// k = replica size
// it is advised that the index retrieved be cached based on usage.
// If n and k are really large, this algorithm is horrible.
// returns 0 if not found, index otherwise.

uint32_t
flexhash_subset_index(uint32_t subset_needle[], int numsubset, int numvdevs)
{
	uint32_t k = numsubset;
	uint32_t i = 1;
	int j=0;
	uint32_t *haystack;

	if (numsubset >= numvdevs)
		return 0;

	haystack = je_calloc(numvdevs, sizeof (uint32_t));
	for (j = 0; j < numvdevs; j++)
		haystack[j] = j;

	qsort(subset_needle, numsubset, sizeof (uint32_t), cmpfunc);
	do {
		if (combination_compare(haystack, subset_needle,
			    numsubset) == 0) {
			je_free(haystack);
			return i;
		}
		i++;
	} while (next_combination(haystack, k, numvdevs));

	// Not found
	je_free(haystack);
	return 0;
}

/* use for debugging */
void
flexhash_show_table(int numsubset, int numvdevs)
{
	uint32_t k = numsubset;
	int i = 0;

	uint32_t *haystack = je_calloc(numvdevs, sizeof (uint32_t));

	if (!haystack) return;
	do {
		printf("[ ");
		for (i=0; i < numsubset; i++)
			printf(" %d ", haystack[i]);
		printf(" ] \n");
	} while (next_combination(haystack, k, numvdevs));

	je_free(haystack);
	return;
}


