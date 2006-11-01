/*
 * Copyright (c) 2006, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the distribution.
 * * Neither the name of Intel Corporation nor the names of its contributors
 *   may be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id$
 */

#include <string.h>
#include <errno.h>
#include <assert.h>

#include "como.h"
#include "comopriv.h"
#include "ipc.h"

struct cca {
    int		id;
    int		cd;
    batch_t *	batch;
    pkt_t **	pktptr;
    int		count;
    int *	sampling;
    int		pkts_to_skip;
};

/**
 * -- cca_open
 * 
 * Associates the calling process with CAPTURE. The process takes the role
 * of client.
 */
cca_t *
cca_open(int cd)
{
    ipctype_t ret;
    ccamsg_t m;
    size_t sz;
    cca_t *cca;
    
    if (ipc_send_with_fd(cd, CCA_OPEN, NULL, 0) != IPC_OK) {
	panic("sending message to capture: %s\n", strerror(errno));
    }
    sz = sizeof(m);
    if (ipc_wait_reply_with_fd(cd, &ret, &m, &sz) != IPC_OK) {
	panic("receiving reply from capture: %s\n", strerror(errno));
    }
    
    if (ret == CCA_ERROR) {
	logmsg(LOGWARN, "client refused by capture\n");
	return NULL;
    }
    assert(ret == CCA_OPEN_RES);
    
    cca = safe_calloc(1, sizeof(cca_t));
    cca->id = m.open_res.id;
    cca->cd = cd;
    cca->sampling = m.open_res.sampling;
    
    return cca;
}

/**
 * -- cca_destroy
 * 
 * Destroys the client data.
 */
void
cca_destroy(cca_t * cca)
{
    free(cca);
}


/**
 * -- cca_send_ack
 */
static inline void
cca_send_ack(cca_t * cca)
{
    ccamsg_t m;
    size_t sz;

    m.ack_batch.id = cca->id;
    m.ack_batch.batch = cca->batch;
    sz = sizeof(m.ack_batch);
    if (ipc_send_with_fd(cca->cd, CCA_ACK_BATCH, &m, sz) != IPC_OK) {
	panic("sending message to capture: %s\n", strerror(errno));
    }
    cca->batch = NULL;
}


/**
 * -- cca_next_pkt
 * 
 * Returns the next available packet from the capture buffer.
 * This functions blocks if no packet is available and waits for notifications
 * from CAPTURE.
 */
pkt_t *cca_next_pkt(cca_t * cca)
{
    pkt_t *pkt;

next_batch:
    if (cca->batch == NULL) {
	ccamsg_t m;
	size_t sz;
	ipctype_t ret;
	int x;
	sz = sizeof(m);
	x = ipc_try_recv_with_fd(cca->cd, &ret, &m, &sz, NULL);
	if (x == IPC_ERR) {
	    panic("receiving message from capture: %s\n", strerror(errno));
	}
	if (ret == CCA_NEW_BATCH) {
	    assert(m.new_batch.id == cca->id);
	    cca->batch = m.new_batch.batch;
	    cca->pktptr = cca->batch->pkts0;
	    cca->count = 0;
	} else {
	    return NULL; /* TODO */
	}
    }
    pkt = *(cca->pktptr);
    if (*cca->sampling == 1) {
	cca->count++;
	cca->pktptr++;
	if (cca->count == cca->batch->pkts0_len) {
	    cca->pktptr = cca->batch->pkts1;
	}
    } else {
	/* random between 1 and cca->sampling */
	int pkts_to_skip;
	float s = (float) *cca->sampling;
	pkts_to_skip = 1 + (int) (s * (rand() / (RAND_MAX + 1.0)));
	logmsg(LOGWARN, "sampling: skipping %d pkts\n", pkts_to_skip);
	if (cca->count + pkts_to_skip > cca->batch->count) {
	    cca_send_ack(cca);
	    goto next_batch;
	}
	cca->count += pkts_to_skip;
	cca->pktptr += pkts_to_skip;
	if (cca->pktptr > cca->batch->pkts0 &&
	    cca->count > cca->batch->pkts0_len) {
	    cca->pktptr = cca->batch->pkts1 +
			  (cca->count - cca->batch->pkts0_len);
	}
    }
    if (cca->count == cca->batch->count) {
	cca_send_ack(cca);
    }
    return pkt;
}
