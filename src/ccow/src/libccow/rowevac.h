/*
 * rowevac.h
 *
 *  Created on: Jul 5, 2018
 *      Author: root
 */

#ifndef SRC_LIBCCOW_ROWEVAC_H_
#define SRC_LIBCCOW_ROWEVAC_H_

typedef enum {
	EVAC_OP_START,
	EVAC_OP_RESUME,
	EVAC_OP_CANCEL
} evac_op_t;

typedef enum {
	ES_NONE = 0,
	ES_AWAITING,
	ES_IN_PROGRESS,
	ES_SUSPENDED,
	ES_CANCELED,
	ES_SUCCESS,
	ES_FAILED,
	ES_TOTAL
} evac_state_t;

#define EVAC_FLAG_DONT_EXCLUDE_SRC    (1<<0) /* Don't exclude source VDEV from the row */
#define EVAC_FLAG_AMOUNT_ABS          (1<<1) /* the amount filed is expressed in MBytes */
#define EVAC_FLAG_EVACUATE            (1<<2) /* Move whole row, keep source VDEV RO while moving */

struct rowevac_cmd {
	uint8_t	opcode; /* Evacuation operation code */
	uint64_t flags; /* Evacuation options */
	uint64_t amount; /* Amount of data to be moved from SRC to DEST, in % by default */
	uint128_t src_vdev; /* Evacuate a row from this VDEV */
	uint128_t dest_vdev; /* EVacuate a row to this VDEV */
	uint64_t id; /* Unique job ID */
	uint16_t row; /* Index of a row to be evacuted */
	/* Filled in response to the request */
	int8_t status;
};

int ccow_rowevac_request(struct ccow *tc, struct ccow_completion *c,
	struct rowevac_cmd* cmd);


#endif /* SRC_LIBCCOW_ROWEVAC_H_ */
