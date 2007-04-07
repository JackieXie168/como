/*
 * Copyright (c) 2004-2007, Intel Corporation
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
 * $Id: protocol.c 1012 2006-11-13 15:04:31Z jsanjuas $
 */

#include <strings.h>

#include "module.h"
#include "data.h"

/*
 * all the state we need is a single record which we keep updating.
 */
record_t *
ca_init(mdl_t *self, timestamp_t ts)
{
    record_t *r = mdl_alloc_tuple(self, record_t);
    r->ts = ts;
    bzero(r->bytes, sizeof(r->bytes));
    bzero(r->pkts, sizeof(r->pkts));

    return r;
}

int
capture(mdl_t *self, pkt_t *pkt, record_t *x)
{
    if (COMO(type) == COMOTYPE_NF) {
        x->bytes[IP(proto)] += H32(NF(pktcount))*COMO(len)*H16(NF(sampling));
        x->pkts[IP(proto)] += H32(NF(pktcount)) * (uint32_t) H16(NF(sampling));
    } else if (COMO(type) == COMOTYPE_SFLOW) {
	x->bytes[IP(proto)] += (uint64_t) COMO(len) * 
					(uint64_t) H32(SFLOW(sampling_rate));
	x->pkts[IP(proto)] += H32(SFLOW(sampling_rate));
    } else {
        x->bytes[IP(proto)] += COMO(len); 
        x->pkts[IP(proto)]++;
    }

    return 0;
}

