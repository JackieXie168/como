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
 * $Id$
 */

#include <stdio.h>

#include "module.h"

#define FLOWDESC	struct _nfexlist
FLOWDESC {
    timestamp_t ts;
    n32_t exaddr;
};


#define CONFIGDESC   struct _nfexlist_config
CONFIGDESC {
    int meas_ivl;     /* measurement interval */
};


static timestamp_t 
init(void *self, char *args[])
{
    CONFIGDESC * config; 
    int i;
    pkt_t *pkt;
    metadesc_t *inmd;
    
    config = mem_mdl_malloc(self, sizeof(CONFIGDESC)); 
    config->meas_ivl = 1;
    for (i = 0; args && args[i]; i++) {
        if (strstr(args[i], "interval")) {
            char * val = index(args[i], '=') + 1;
            config->meas_ivl = atoi(val);
        }
    }
    
    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = TIME2TS(config->meas_ivl, 0);
    
    pkt = metadesc_tpl_add(inmd, "nf:none:none:none");
    
    CONFIG(self) = config;
    return TIME2TS(config->meas_ivl, 0);
}


static uint32_t
hash(void * self, pkt_t *pkt) 
{
    uint64_t x = (uint64_t) N32(NF(exaddr));
    x *= 7;
    return (uint32_t) (x % ((uint64_t) 1 << 32));
}


static int
match(void * self, pkt_t * pkt, void * fh)
{
    FLOWDESC * x = F(fh);
    return N32(x->exaddr) == N32(NF(exaddr));
}


static int
update(void * self, pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);

    if (isnew) {
	x->ts = COMO(ts);
	N32(x->exaddr) = N32(NF(exaddr));
    }
    return 0;		
}


static ssize_t
store(void * self, void *fh, char *buf)
{
    FLOWDESC *x = F(fh);
 
    PUTH64(buf, x->ts);
    PUTN32(buf, N32(x->exaddr));

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


#define PLAINFMT   "%12ld %15s\n"


static char *
print(void * self, char *buf, size_t *len, char * const args[])
{
    static char s[512];
    static char * fmt;
    FLOWDESC *x;
    timestamp_t ts;
    time_t t;
    struct in_addr addr;

    if (buf == NULL && args != NULL) {
        *len = 0;
        fmt = PLAINFMT;
        return s;
    }

    if (buf == NULL && args == NULL) {
        *len = 0;
        return s;
    }

    x = (FLOWDESC *) buf;
    ts = NTOHLL(x->ts);

    t = (time_t) TS2SEC(ts);
    addr.s_addr = N32(x->exaddr);
  
    *len = sprintf(s, fmt, (long int) t, inet_ntoa(addr));
    
    return s;
}


MODULE(nfexlist) = {
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
