/*
 * Copyright (c) 2004 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id$
 */

/*
 * Find specific destination prefix. 
 */

#include <stdio.h>
#include <time.h>
#include "como.h"
#include "module.h"

#define FLOWDESC    struct _tuple_stat
#define EFLOWDESC   FLOWDESC 

FLOWDESC {
    uint32_t ts; 
    uint32_t dst_ip;
    uint64_t bytes;
    uint64_t pkts;
};

static uint32_t meas_ivl = 30; 		/* 30s minimum reporting interval */

static uint32_t
hash(pkt_t *pkt)
{
    return (H32(IP(dst_ip)) >> 8);
}

static int
match(pkt_t *pkt, void *fh)
{
    FLOWDESC *x = F(fh);
    return ((H32(IP(dst_ip)) & 0xffffff00) == x->dst_ip); 
}

static int
update(pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);

    if (isnew) {
	x->ts = TS2SEC(pkt->ts); 
	x->bytes = 0;
	x->pkts = 0;
        x->dst_ip = H32(IP(dst_ip)) & 0xffffff00;
    }

    x->bytes += H16(IP(len));
    x->pkts++;

    return 0;
}

static ssize_t
store(void *efh, char *buf, size_t len)
{
    FLOWDESC *x = F(efh);
    
    if (len < sizeof(FLOWDESC))
        return -1;

    PUTH32(buf, x->ts);
    PUTH32(buf, x->dst_ip);
    PUTH64(buf, x->bytes);
    PUTH64(buf, x->pkts);

    return sizeof(FLOWDESC);
}

static size_t
load(char * buf, size_t len, timestamp_t * ts)
{
    if (len < sizeof(FLOWDESC)) {
        ts = 0;
        return 0;
    }

    *ts = TIME2TS(ntohl(((FLOWDESC *)buf)->ts), 0);
    return sizeof(FLOWDESC);
}

static int
ematch(void *efh, void *fh)
{
    FLOWDESC  *x  = F(fh);
    EFLOWDESC *ex = EF(efh);

    return (ex->dst_ip == x->dst_ip); 
}

static int
export(void *efh, void *fh, int isnew)
{
    FLOWDESC  *x  = F(fh);
    EFLOWDESC *ex = EF(efh);
    uint32_t ivl; 

    ivl = x->ts - x->ts % meas_ivl; 
    if (isnew) { 
	ex->ts = ivl; 
        ex->dst_ip = x->dst_ip;
        ex->bytes = 0;
        ex->pkts = 0;
    }
         
    ex->bytes += x->bytes;
    ex->pkts += x->pkts;
    return 0;
}

static int
action(void * fh, timestamp_t t, __unused int count)
{ 
    static timestamp_t last_ts = 0; 

    if (fh == NULL) {
	if (t >= last_ts + TIME2TS(meas_ivl, 0)) {
	    last_ts = t - (t % TIME2TS(meas_ivl, 0)); 
	    return ACT_GO; 
	} 
	return ACT_STOP; 
    } 

    return ACT_STORE | ACT_DISCARD;
}

static char *
print(char *buf, size_t *len, char * const args[])
{
    static char s[2048];
    static uint32_t dst; 
    static uint64_t bytes = 0; 
    static uint64_t pkts = 0; 
    FLOWDESC *x; 

    if (buf == NULL && args != NULL) { 
	int n; 

	for (n = 0; args[n]; n++) {
	    if (strstr(args[n], "dst")) { 
		char * wh = index(args[n],'=') + 1; 
		dst = (uint32_t) (inet_addr(wh) & 0x00ffffff); 
	    } 
	} 
        *len = 0; 
        return s; 
    } 

    if (buf == NULL && args == NULL) { 
	struct in_addr daddr;
	daddr.s_addr = dst;
	*len = sprintf(s, "%15s %8llu %8llu\n", inet_ntoa(daddr), bytes, pkts);
        return s; 
    } 

    x = (FLOWDESC *) buf;
    if (x->dst_ip == dst) {
	bytes += NTOHLL(x->bytes);	
	pkts += NTOHLL(x->pkts);	
    }

    *len = 0;
    return s;
};


callbacks_t callbacks = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: sizeof(EFLOWDESC),
    indesc: NULL, 
    outdesc: NULL,
    init: NULL,
    check: NULL, 
    hash: hash,
    match: match,
    update: update,
    ematch: ematch,
    export: export,
    compare: NULL,
    action: action,
    store: store,
    load: load,
    print: print,
    replay: NULL
};
