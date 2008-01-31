/*
 * Copyright (c) 2007, Universitat Politecnica de Catalunya
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
 * 5-tuple flow classifier
 *
 * This module computes 5-tuple flows. Every capture period it 
 * stores the 5-tuple that have been active (together with the 
 * bytes they have sent).  
 *
 */

#include "module.h"
#include "data.h"
#include "flowtable.h"
#include "uhash.h"

typedef struct ca_state ca_state_t;
struct ca_state {
    flowtable_t *table;
    uhash_t     hfunc;
};

static int
pkt_belongs_to_tuple_BY_SRC(pkt_t *pkt, tuple_t *r)
{
    return H32(IP(src_ip)) == r->addr;
}

static int
pkt_belongs_to_tuple_BY_DST(pkt_t *pkt, tuple_t *r)
{
    return H32(IP(dst_ip)) == r->addr;
}

ca_state_t *
ca_init(mdl_t *self, timestamp_t ivl)
{
    alc_t *alc = mdl_alc(self);
    config_t *config = mdl_get_config(self, config_t);
    ca_state_t *st = mdl_malloc(self, sizeof(ca_state_t));

    uhash_initialize(&st->hfunc);

    if (config->use_srcs)
        st->table = flowtable_new(alc, 2048, NULL,
                (flow_match_fn) pkt_belongs_to_tuple_BY_SRC, NULL);
    else
        st->table = flowtable_new(alc, 2048, NULL,
                (flow_match_fn) pkt_belongs_to_tuple_BY_DST, NULL);

    return st;
}

void
capture(mdl_t *self, pkt_t *pkt, ca_state_t *st, double srate)
{
    uint32_t hash, addr;
    uint8_t proto;
    config_t *config;
    tuple_t *r;
    double bytes;

    if (!isIP)
        return;

    config = mdl_get_config(self, config_t);

    if (config->use_srcs)
        addr = H32(IP(src_ip));
    else
        addr = H32(IP(dst_ip));

    /* hash the packet */
    hash = uhash(&st->hfunc, (uint8_t *)&addr, sizeof(uint32_t), UHASH_NEW);

    /* test if we already have a tuple for this one */
    r = (tuple_t *) flowtable_lookup(st->table, hash, pkt);

    if (r == NULL) { /* need to create a new entry */
        r = mdl_alloc_tuple(self, tuple_t);
        r->addr = addr;
	r->bytes = 0;
        flowtable_insert(st->table, hash, (void *) r);
    }

    /* update the tuple */
    if (COMO(type) == COMOTYPE_NF)
	bytes = H32(NF(pktcount)) * COMO(len);
    else if (COMO(type) == COMOTYPE_SFLOW)
	bytes = (uint64_t) COMO(len) * (uint64_t) H32(SFLOW(sampling_rate));
    else
	bytes = H16(IP(len));

    r->bytes += bytes / srate;
}

