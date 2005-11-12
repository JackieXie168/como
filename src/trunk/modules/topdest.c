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
 * Top-N destinations Module.
 *
 * This module computes the top-N IP destination addresses
 *
 */

#include <stdio.h>
#include <time.h>
#include "como.h"
#include "module.h"

#define TOPN        20		/* Top-20 destinations */
#define EXPORT_IVL  5		/* export interval (seconds) */

#define FLOWDESC	struct _ca_topdest
#define EFLOWDESC	FLOWDESC

FLOWDESC {
    uint32_t ts;	/* timestamp of last packet */
    n32_t dst_ip;	/* destination IP address */
    uint64_t bytes;	/* number of bytes */
    uint64_t pkts;	/* number of packets */
};



static uint32_t
hash(pkt_t *pkt)
{
    return (N32(IP(dst_ip))); 
}

static int
match(pkt_t *pkt, void *fh)
{
    FLOWDESC *x = F(fh);
    return (N32(IP(dst_ip)) == N32(x->dst_ip));
}

static int
update(pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);

    if (isnew) {
	x->ts = TS2SEC(pkt->ts) - (TS2SEC(pkt->ts) % EXPORT_IVL);
        x->dst_ip = IP(dst_ip);
        x->bytes = 0;
        x->pkts = 0;
    }

    x->bytes += H16(IP(len));
    x->pkts ++;

    return 0;
}

static int
ematch(void *efh, void *fh)
{
    FLOWDESC *x = F(fh);
    EFLOWDESC *ex = EF(efh);

    return (N32(x->dst_ip) == N32(ex->dst_ip));
}

static int
export(void *efh, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);
    EFLOWDESC *ex = EF(efh);

    if (isnew) {
	ex->ts = x->ts; 
        ex->dst_ip = x->dst_ip;
        ex->bytes = 0;
        ex->pkts = 0;
    }

    ex->bytes += x->bytes;
    ex->pkts += x->pkts;

    return 0;
}

static int
compare(const void *efh1, const void *efh2)
{
    EFLOWDESC *ex1 = CMPEF(efh1);
    EFLOWDESC *ex2 = CMPEF(efh2);

    return ((ex1->bytes > ex2->bytes)? -1 : 1);
}

static int
action(void *efh, timestamp_t current_time, int count)
{
    static uint32_t last_export = 0; 

    if (efh == NULL) { 
	/* 
	 * this is the action for the entire table. 
	 * check if it is time to export the table. 
	 * if not stop. 
	 */
	uint32_t ivl = TS2SEC(current_time) - TS2SEC(current_time) % EXPORT_IVL;
	if (ivl - last_export < EXPORT_IVL) 
	    return ACT_STOP;		/* too early */

	last_export = ivl; 
	return ACT_GO; 		/* dump the records */
    }

    return (count < TOPN)? ACT_STORE|ACT_DISCARD : ACT_DISCARD; 
}


static ssize_t
store(void *efh, char *buf, size_t len)
{
    EFLOWDESC *ex = EF(efh);
    
    if (len < sizeof(EFLOWDESC))
        return -1;

    PUTH32(buf, ex->ts);
    PUTN32(buf, N32(ex->dst_ip));
    PUTH64(buf, ex->bytes);
    PUTH64(buf, ex->pkts);

    return sizeof(EFLOWDESC);
}

static size_t
load(char *buf, size_t len, timestamp_t *ts)
{
    if (len < sizeof(EFLOWDESC)) {
        ts = 0;
        return 0; 
    }

    *ts = TIME2TS(ntohl(((EFLOWDESC *)buf)->ts), 0);
    return sizeof(EFLOWDESC);
}


#define PRETTYHDR	\
    "Date                     Destination IP  Bytes      Packets   \n"

#define PRETTYFMT 	"%.24s %15s %10llu %10llu\n"

static char *
print(char *buf, size_t *len, char * const args[])
{
    EFLOWDESC *x; 
    static char s[2048];
    struct in_addr addr;
    time_t ts;

    if (buf == NULL && args != NULL) { 
	*len = sprintf(s, PRETTYHDR); 
	return s; 
    } 

    if (buf == NULL && args == NULL) { 
	*len = 0; 
  	return s; 
    } 

    x = (EFLOWDESC *) buf; 
    ts = (time_t) ntohl(x->ts);
    addr.s_addr = N32(x->dst_ip);
    *len = sprintf(s, PRETTYFMT, asctime(localtime(&ts)), inet_ntoa(addr), 
	       NTOHLL(x->bytes), NTOHLL(x->pkts));
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
    compare: compare,
    action: action,
    store: store,
    load: load,
    print: print,
    replay: NULL
};

