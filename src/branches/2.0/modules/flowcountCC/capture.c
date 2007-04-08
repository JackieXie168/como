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
 * $Id: flowcount.c 1012 2006-11-13 15:04:31Z jsanjuas $
 */

/*
 * Flow counter.
 *
 * Provides a count of the active flows in the measurement interval.
 * The user can decide what the exact definition of a flow is (e.g. the
 * 5-tuple, or the pair of src and dst addresses)
 * 
 * It uses a techinque called "probabilistic counting" (see "A Linear-Time
 * Probabilistic Counting Algorithm for Database applications", by Kyu-Young
 * Whang, Brad T. Vander-Zanden and Howard M. Taylor) to provide an accurate
 * estimation of the number of flows, without the overhead of maintaining
 * per-flow entries in a hash table.
 *
 */
#include "module.h"
#include "data.h"
#include "uhash.h"
#include "bitmap.h"

struct ca_state {
    uhash_t hfunc;
    bitmap_t *bm;
    timestamp_t ts;
};
typedef struct ca_state ca_state_t;

ca_state_t *
ca_init(mdl_t *self, timestamp_t ts)
{
    config_t *cf = mdl_get_config(self, config_t);
    ca_state_t *st = mdl_malloc(self, sizeof(ca_state_t));

    st->ts = ts;
    st->bm = mdl_new_bitmap(self, cf->max_keys);
    uhash_initialize(&st->hfunc);

    return st;
}

void
capture(mdl_t *self, pkt_t *pkt, ca_state_t *st)
{
    config_t *cf = mdl_get_config(self, config_t);
    uint32_t hash;

    /*
     * incrementally hash relevant fields
     */
    hash = uhash(&st->hfunc, NULL, 0, UHASH_NEW);
    if (cf->flow_fields & USE_SRC)
        hash = uhash(&st->hfunc, (uint8_t *) &IP(src_ip), 4, UHASH_APPEND);
    if (cf->flow_fields & USE_DST)
        hash = uhash(&st->hfunc, (uint8_t *) &IP(dst_ip), 4, UHASH_APPEND);
    if (cf->flow_fields & USE_PROTO)
        hash = uhash(&st->hfunc, (uint8_t *) &IP(proto), 1, UHASH_APPEND);
    if (cf->flow_fields & USE_SPORT) {
        if (isTCP)
            hash = uhash(&st->hfunc,(uint8_t*) &TCP(src_port),2,UHASH_APPEND);
        else if (isUDP)
            hash = uhash(&st->hfunc,(uint8_t*) &UDP(src_port),2,UHASH_APPEND);
    }
    if (cf->flow_fields & USE_DPORT) {
        if (isTCP)
            hash = uhash(&st->hfunc, (uint8_t *) &TCP(dst_port),2,UHASH_APPEND);
        else if (isUDP)
            hash = uhash(&st->hfunc, (uint8_t *) &UDP(dst_port),2,UHASH_APPEND);
    }

    set_bit(st->bm, hash);  		/* update bitmap */
}

void
flush(mdl_t *self, ca_state_t *st)
{
    config_t * cf = mdl_get_config(self, config_t);
    record_t *rec = mdl_alloc_tuple(self, record_t);

    rec->ts = st->ts;
    rec->count = (uint32_t) estimate_unique_keys(st->bm);
}

