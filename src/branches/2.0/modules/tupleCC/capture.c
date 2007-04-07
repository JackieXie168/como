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
 * $Id: tuple.c 1012 2006-11-13 15:04:31Z jsanjuas $
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
pkt_belongs_to_record(pkt_t *pkt, record_t *r)
{
    uint32_t src, dst;
    uint16_t sport, dport;
    uint8_t proto;

    get_pkt_info(pkt, &src, &dst, &sport, &dport, &proto);

    return src == r->src_ip && dst == r->dst_ip &&
        sport == r->src_port && dport == r->dst_port &&
        proto == r->proto;
}

ca_state_t *
ca_init(mdl_t *self, timestamp_t *ivl)
{
    alc_t *alc = mdl_alc(self);
    config_t *config = mdl_get_config(self, config_t);
    ca_state_t *st = mdl_malloc(self, sizeof(ca_state_t));

    uhash_initialize(&st->hfunc);
    st->table = flowtable_new(alc, 2048, NULL,
                                (flow_match_fn) pkt_belongs_to_record, NULL);

    return st;
}

void
capture(mdl_t *self, pkt_t *pkt, ca_state_t *st)
{
    uint32_t hash, src, dst;
    uint16_t sport, dport;
    uint8_t proto;
    record_t *r;

    if (!isIP)
        return;

    get_pkt_info(pkt, &src, &dst, &sport, &dport, &proto);

    /* hash the packet */
    hash = uhash(&st->hfunc, (uint8_t *)&src, sizeof(uint32_t), UHASH_NEW);
    hash = uhash(&st->hfunc, (uint8_t *)&dst, sizeof(uint32_t), UHASH_APPEND);
    hash = uhash(&st->hfunc, (uint8_t *)&sport, sizeof(uint16_t), UHASH_APPEND);
    hash = uhash(&st->hfunc, (uint8_t *)&dport, sizeof(uint16_t), UHASH_APPEND);
    hash = uhash(&st->hfunc, (uint8_t *)&proto, sizeof(uint8_t), UHASH_APPEND);

    /* test if we already have a record for this one */
    r = (record_t *) flowtable_lookup(st->table, hash, pkt);

    if (r == NULL) { /* need to create a new entry */
        r = mdl_alloc_tuple(self, record_t);
        r->start_ts = pkt->ts;
        r->src_ip = src;
        r->dst_ip = dst;
        r->src_port = sport;
        r->dst_port = dport;
        r->proto = proto;
	r->bytes = 0;
	r->pkts = 0;
    }

    /* update the record */
    r->last_ts = pkt->ts;
    if (COMO(type) == COMOTYPE_NF) {
	r->last_ts += 
	    TIME2TS(H32(NF(duration)) / 1000, (H32(NF(duration))%1000)*1000);
	r->sampling = H16(NF(sampling));
	r->bytes += H32(NF(pktcount)) * COMO(len);
	r->pkts += (uint64_t) H32(NF(pktcount));
    } else if (COMO(type) == COMOTYPE_SFLOW) {
    	r->sampling = (uint16_t) H32(SFLOW(sampling_rate));
	r->bytes += (uint64_t) COMO(len) * (uint64_t) H32(SFLOW(sampling_rate));
	r->pkts += (uint64_t) H32(SFLOW(sampling_rate));
    } else {
	r->sampling = 1;
	r->bytes += H16(IP(len));
	r->pkts++;
    } 
}

