#ifndef PMU_LFQ_H_
#define PMU_LFQ_H_

/*

 Lockless Fast Queues - Supports a single-producer/single-consumer
 shared memory queue that uses no locking. Atomic compare-and-swap
 instructions prevent consumer/producer races.

 This was created to support the pmu utility,n but it has no
 dependencies on the rest of the pmu package.

*/

#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>


struct pmu_lfq;
typedef struct pmu_lfq *pmu_lfq_t;

extern pmu_lfq_t pmu_lfq_create(void);
// TODO: consider making queue size dynamically configured.
// The main reason for not doing so is that the mod operation
// will end up being an actual division by a struct field,
// rather than a hard-coded % (power of 2 consitant)

extern void pmu_lfq_destroy(pmu_lfq_t h);
extern bool pmu_lfq_produce(pmu_lfq_t h, void *data_ptr);
	// returns true if data_ptr can be added to lfq h
	// false is returned when the queue is full
	//
	// Note that there is no check against producing NULL,.
	// but this will be indistinquishable from an empty queue
	// for the consumer
	//
	// This is a non-blocking routine.
extern void *pmu_lfq_consume(pmu_lfq_t h);
	// returns next element from queue, or NULL if queue is empty.

#endif
