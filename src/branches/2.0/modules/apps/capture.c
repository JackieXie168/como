/*
 * Copyright (c) 2004-2008, Intel Corporation
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

#include "data.h"

tuple_t *
ca_init(mdl_t *self, timestamp_t ts)
{
    tuple_t *t = mdl_alloc_tuple(self, tuple_t);

    memset(t->bytes, 0, sizeof(t->bytes));
    memset(t->pkts, 0, sizeof(t->pkts));

    return t;
}

void
capture(mdl_t *self, pkt_t *pkt, tuple_t *st, double srate)
{
    config_t *config = mdl_get_config(self, config_t);
    int app, app1, app2;
    double b, p;

    if (! isTCP && ! isUDP) /* non-TCP, non-UDP traffic */
        app = 1;
    else {                  /* TCP and UDP traffic */
        if (isTCP) {
            app1 = config->tcp_port2app[H16(TCP(src_port))];
            app2 = config->tcp_port2app[H16(TCP(dst_port))];
        } else {
            app1 = config->udp_port2app[H16(UDP(src_port))];
            app2 = config->tcp_port2app[H16(UDP(dst_port))];
        }

        if (app1 == 0 || app2 == 0) /* at most 1 port matches a known app */
            app = app1 + app2;
        else if (app1 == app2)      /* both ports match the same app */
            app = app1;
        else                        /* ports match different apps, unknown */
            app = 0;
    }

    if (COMO(type) == COMOTYPE_NF) {
        b = H32(NF(pktcount)) * COMO(len) * H16(NF(sampling));
        p = H32(NF(pktcount)) * (uint32_t) H16(NF(sampling));
    } else if (COMO(type) == COMOTYPE_SFLOW) {
        b = (uint64_t) COMO(len) * (uint64_t) H32(SFLOW(sampling_rate));
        p = H32(SFLOW(sampling_rate));
    } else {
        b = COMO(len);
        p = 1;
    }

    /* scale with sampling rate */
    st->bytes[app] += b / srate;
    st->pkts[app] += p / srate;
}

