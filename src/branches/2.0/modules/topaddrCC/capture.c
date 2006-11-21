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
 * This module ranks addresses in terms of bytes.
 * The IP addresses can be destination or sources. 
 */
#include "como.h"
#include "data.h"
#include "flowtable.h"
#include "uhash.h"

typedef struct ca_state ca_state_t;
struct ca_state {
    flowtable_t *table; /* ip to record */
    uhash_t      hfunc; /* hash function */
    int          use_dst; /* copy of cfg value for use_dst */
};

static int
BY_SRC_pkt_belongs_to_record(pkt_t *pkt, topaddr_tuple_t *t)
{
    return N32(IP(src_ip)) == t->addr;
}

static int
BY_DST_pkt_belongs_to_record(pkt_t *pkt, topaddr_tuple_t *t)
{
    return N32(IP(dst_ip)) == t->addr;
}


ca_state_t *
ca_init(mdl_t *self, timestamp_t *ivl)
{
    alc_t *alc = mdl_alc(self);
    topaddr_config_t *cfg = mdl_get_config(self, topaddr_config_t);
    ca_state_t *st = mdl_malloc(self, sizeof(ca_state_t));

    uhash_initialize(&st->hfunc);

    st->use_dst = cfg->use_dst;
    st->table = flowtable_new(alc, 2048, NULL,
        cfg->use_dst ?
            (flow_match_fn) BY_DST_pkt_belongs_to_record :
            (flow_match_fn) BY_SRC_pkt_belongs_to_record,
        NULL);
    return st;
}

int
capture(mdl_t *self, pkt_t *pkt, ca_state_t *st)
{
    topaddr_tuple_t *t;
    uint32_t key, hash;

    /* get the hash for the packet */
    key = st->use_dst ? N32(IP(dst_ip)) : N32(IP(src_ip));
    hash = uhash(&st->hfunc, (uint8_t *) &key, sizeof(uint32_t), UHASH_NEW);

    /* look for the record that matches the packet */
    t = (topaddr_tuple_t *) flowtable_lookup(st->table, hash, pkt);

    if (t == NULL) { /* tuple not found, create a new entry */
        t = mdl_alloc_tuple(self, topaddr_tuple_t);
        t->addr = key;
        t->bytes = 0;
        t->pkts = 0;
        t->hash = hash;
        flowtable_insert(st->table, hash, (void *) t);
    }

    /* update the entry */
    if (COMO(type) == COMOTYPE_NF) { 
	t->bytes += H32(NF(pktcount)) * COMO(len) * H16(NF(sampling));
	t->pkts += H32(NF(pktcount)) * H16(NF(sampling)); 
    } else if (COMO(type) == COMOTYPE_SFLOW) {
	t->bytes += (uint64_t) COMO(len) * (uint64_t) H32(SFLOW(sampling_rate));
	t->pkts += H32(SFLOW(sampling_rate));
    } else { 
	t->bytes += H16(IP(len));
	t->pkts++;
    } 

    return 0;
}

