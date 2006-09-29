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
 * Signal strength per IP address (requires radio information & 802_11)
 */

#include <stdio.h>
#include <time.h>
#include "module.h"


#define MEASUREMENT_IVL TIME2TS(1, 0)

#define FLOWDESC    struct _macstrength
FLOWDESC {
    timestamp_t ts;
    int32_t signal_strength;
    size_t  samples;
    n32_t channel;
    n32_t addr;
};

static timestamp_t
init(void * self, __unused char *args[])
{
    pkt_t *pkt;
    metadesc_t *inmd;

    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = MEASUREMENT_IVL;
    
    pkt = metadesc_tpl_add(inmd, "radio:802.11:~ip:none");
    N32(IP(src_ip)) = 0xffffff;
    
    return MEASUREMENT_IVL;
}

static uint32_t
hash(__unused void * self, pkt_t *pkt)
{
    uint64_t x = (uint64_t) N32(IP(src_ip));
    x *= 7;
    return (uint32_t) (x % (1LL << 32));
}

static int
match(__unused void * self, pkt_t *pkt, void *fh)
{
    FLOWDESC *x = F(fh);
    return N32(IP(src_ip)) == N32(x->addr);
}

static int
update(__unused void * self, pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);

    if (isnew) {
        x->ts = COMO(ts) - COMO(ts) % MEASUREMENT_IVL;
        x->channel = RADIO(channel);
        x->signal_strength = 0;
        x->samples = 0;
	x->addr = IP(src_ip);
    }

    x->signal_strength += H32(RADIO(ssisignal));
    x->samples++;

    return 0; /* records are never full */
}

static ssize_t
store(__unused void * self, void *rp, char *buf)
{
    FLOWDESC *x = F(rp);

    PUTH64(buf, x->ts);
    PUTH32(buf, x->signal_strength);
    PUTH32(buf, x->samples);
    PUTN32(buf, N32(x->channel));
    PUTN32(buf, N32(x->addr));

    return sizeof(FLOWDESC);
}

static size_t
load(__unused void * self, char * buf, size_t len, timestamp_t * ts)
{
    if (len < sizeof(FLOWDESC)) {
        *ts = 0;
        return 0;
    }

    *ts = NTOHLL(((FLOWDESC *)buf)->ts);
    return sizeof(FLOWDESC);
}


static char *
print(__unused void *self, char *buf, size_t *len, __unused char *const args[])
{
    static char output[1024];
    uint32_t chan, samples;
    int32_t strength;
    timestamp_t ts;
    float mean_strength;
    FLOWDESC *x;
    struct in_addr addr;

    if (buf == NULL && args != NULL) {
        *len = sprintf(output, "ts                  IP               "
                "chan strength samples\n");
        return output;
    }

    if (buf == NULL) {
	*len = 0;
	return output;
    }

    x = (FLOWDESC *) buf;
    ts = NTOHLL(x->ts);
    chan = ntohl(N32(x->channel));
    samples = ntohl(x->samples);
    strength = ntohl(x->signal_strength);
    mean_strength = (float)strength / (float)samples;
    addr.s_addr = N32(x->addr);

    *len = sprintf(output, "%llu %s %02d   %.4f %d\n", ts, inet_ntoa(addr),
            chan, mean_strength, samples);
    return output;
}

MODULE(ipssi) = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0,
    st_recordsize: sizeof(FLOWDESC),
    capabilities: {has_flexible_flush: 0, 0},
    init: init,
    check: NULL,
    hash: hash,
    match: match,
    update: update,
    flush: NULL, 
    ematch: NULL,
    export: NULL,
    compare: NULL,
    action: NULL,
    store: store,
    load: load,
    print: print,
    replay: NULL,
    formats: "plain",
};

