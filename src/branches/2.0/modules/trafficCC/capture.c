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
 * $Id: traffic.c 978 2006-11-01 15:23:18Z m_canini $
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
#include "module.h"
#include "data.h"

#define mdl_t void
#define mdl_allocate_tuple_mem(self, size) NULL
#define mdl_set_ca_state(self, size) NULL
#define mdl_get_ca_state(self) NULL
#define mdl_get_config(self) NULL

void
update(mdl_t * self, pkt_t *pkt)
{
    config_t *cf = (config_t *) mdl_get_config(self);
    tuple_t *t = (tuple_t *) mdl_get_ca_state(self);

    if (t == NULL) { /* state is null, create a new one */
        t = mdl_allocate_tuple_mem(self, sizeof(tuple_t));
	bzero(t, sizeof(tuple_t));
        mdl_set_ca_state(self, t); /* all state we need is the current tuple */
	t->ts = COMO(ts);
    }

    if (COMO(type) == COMOTYPE_NF) {
	if (cf->iface == -1 || H16(NF(input)) == cf->iface) {
	    t->bytes[0] += H32(NF(pktcount)) * COMO(len) * H16(NF(sampling));
	    t->pkts[0] += H32(NF(pktcount)) * (uint32_t) H16(NF(sampling));
	} else if (H16(NF(output)) == cf->iface) { 
	    t->bytes[1] += H32(NF(pktcount)) * COMO(len) * H16(NF(sampling));
	    t->pkts[1] += H32(NF(pktcount)) * (uint32_t) H16(NF(sampling));
	} 
    } else if (COMO(type) == COMOTYPE_SFLOW) {
	t->bytes[0] += (uint64_t) COMO(len) * 
		      (uint64_t) H32(SFLOW(sampling_rate));
	t->pkts[0] += H32(SFLOW(sampling_rate));
    } else {
	t->bytes[0] += COMO(len);
        t->pkts[0]++;
    }
}


