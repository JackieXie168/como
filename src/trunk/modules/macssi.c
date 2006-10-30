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
 * Signal strength per MAC address (requires radio information & 802_11)
 */

#include <stdio.h>
#include <time.h>
#include "module.h"
#include "macutils.h"

#define MAC_ADDR_SIZE   6

#define MEASUREMENT_IVL TIME2TS(1, 0)

#define FLOWDESC    struct _macstrength
FLOWDESC {
    timestamp_t ts;
    int32_t signal_strength;
    size_t  samples;
    n32_t channel;
    uint8_t addr[MAC_ADDR_SIZE];
};

static timestamp_t
init(void * self, char *args[])
{
    pkt_t *pkt;
    metadesc_t *inmd;

    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = MEASUREMENT_IVL;
    
    pkt = metadesc_tpl_add(inmd, "radio:802.11:none:none");
    
    return MEASUREMENT_IVL;
}

static int
check(void * self, pkt_t *pkt)
{
    /* cannot handle CTRL packets */
    return IEEE80211_BASE(fc_type) != IEEE80211TYPE_CTRL;
}

static uint32_t
hash(void * self, pkt_t *pkt)
{
    uint32_t mix = 0;
    uint8_t *mac = IEEE80211_BASE(addr2);
    int i;
    
    for (i = 0; i < MAC_ADDR_SIZE; i++) /* shuffle from mac addr */
        mix = (mix << 4) ^ (mix >> 28) ^ mac[i];

    return mix;
}

static int
match(void * self, pkt_t *pkt, void *fh)
{
    FLOWDESC *x = F(fh);
    return 0 == memcmp(x->addr, IEEE80211_BASE(addr2), MAC_ADDR_SIZE);
}

static int
update(void * self, pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);

    if (isnew) {
        x->ts = COMO(ts) - COMO(ts) % MEASUREMENT_IVL;
        x->channel = RADIO(channel);
        x->signal_strength = 0;
        x->samples = 0;
        memcpy(x->addr, IEEE80211_BASE(addr2), MAC_ADDR_SIZE);
    }

    x->signal_strength += H32(RADIO(ssisignal));
    x->samples++;

    return 0; /* records are never full */
}

static ssize_t
store(void * self, void *rp, char *buf)
{
    FLOWDESC *x = F(rp);
    int i;

    PUTH64(buf, x->ts);
    PUTH32(buf, x->signal_strength);
    PUTH32(buf, x->samples);
    PUTN32(buf, N32(x->channel));
    for (i = 0; i < MAC_ADDR_SIZE; i++)
        PUTH8(buf, x->addr[i]);

    return sizeof(FLOWDESC);
}

static size_t
load(void * self, char * buf, size_t len, timestamp_t * ts)
{
    if (len < sizeof(FLOWDESC)) {
        *ts = 0;
        return 0;
    }

    *ts = NTOHLL(((FLOWDESC *)buf)->ts);
    return sizeof(FLOWDESC);
}

static char *
print(void *self, char *buf, size_t *len, char *const args[])
{
    static char output[1024];
    char ascii_mac[128];
    uint32_t chan, samples;
    int32_t strength;
    timestamp_t ts;
    float mean_strength;
    FLOWDESC *x;

    if (buf == NULL && args != NULL) {
        *len = sprintf(output, "ts                  MAC               "
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

    pretty_mac(x->addr, ascii_mac, sizeof(ascii_mac), 0);
    *len = sprintf(output, "%llu %s %02d   %.4f %d\n", ts, ascii_mac,
            chan, mean_strength, samples);
    return output;
}

MODULE(macssi) = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0,
    st_recordsize: sizeof(FLOWDESC),
    capabilities: {has_flexible_flush: 0, 0},
    init: init,
    check: check,
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

