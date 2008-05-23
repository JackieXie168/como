/*
 * Copyright (c) 2004-2006, Intel Corporation
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

/*
 * Traffic Load 
 *
 * Compute input/output pkt/byte count on the monitored link.
 * Whether it tracks packets or bytes can be decided at configuration time. 
 *
 */

#include <stdio.h>
#include <time.h>
#include "como.h"
#include "data.h"

tuple_t *
ca_init(mdl_t * self, timestamp_t ts)
{
    tuple_t *t = mdl_alloc_tuple(self, tuple_t);
    t->ts = ts;
    return t; /* all state we need is the current tuple */
}

void
capture(mdl_t * self, pkt_t * pkt, tuple_t * t, double srate)
{
    const config_t *cf = mdl_get_config(self, config_t);
    double bytes[2], pkts[2];

    bytes[0] = bytes[1] = 0;
    pkts[0] = pkts[1] = 0;

    if (COMO(type) == COMOTYPE_NF) {
	if (cf->iface == -1 || H16(NF(input)) == cf->iface) {
	    bytes[0] = H32(NF(pktcount)) * COMO(len) * H16(NF(sampling));
	    pkts[0] = H32(NF(pktcount)) * (uint32_t) H16(NF(sampling));
	} else if (H16(NF(output)) == cf->iface) { 
	    bytes[1] = H32(NF(pktcount)) * COMO(len) * H16(NF(sampling));
	    pkts[1] = H32(NF(pktcount)) * (uint32_t) H16(NF(sampling));
	} 
    } else if (COMO(type) == COMOTYPE_SFLOW) {
	bytes[0] = (uint64_t) COMO(len) * 
		      (uint64_t) H32(SFLOW(sampling_rate));
	pkts[0] = H32(SFLOW(sampling_rate));
    } else {
	bytes[0] = COMO(len);
        pkts[0] = 1;
    }

    t->bytes[0] += bytes[0] / srate;
    t->bytes[1] += bytes[1] / srate;
    t->pkts[0] += pkts[0] / srate;
    t->pkts[1] += pkts[1] / srate;
}


