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
 * Protocol module
 *
 * This module computes the number of packets and bytes per protocol.
 * Output: packets/bytes per protocol over 1s intervals
 *
 */

#include <stdio.h>
#include <time.h>
#include "como.h"
#include "module.h"


#define FLOWDESC    struct _proto_stat

FLOWDESC {
    uint32_t    ts;
    uint32_t    proto;
    uint64_t    bytes;
    uint64_t    pkts;
};

static uint32_t
hash(pkt_t *pkt)
{
    if (pkt->l3type == ETH_P_IP)
	return IP(proto);
    else
	return 0;
}

static int
match(pkt_t *pkt, void *fh)
{
    FLOWDESC *x = F(fh);

    if (pkt->l3type == ETH_P_IP)
	return (x->proto == (uint32_t) IP(proto));
    else
	return x->proto == 0;
}

static int
update(pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);

    if (isnew) {
	x->ts = TS2SEC(pkt->ts);
	if (pkt->l3type == ETH_P_IP)
	    x->proto = (uint32_t) IP(proto);
	else
	    x->proto = 0;
        x->bytes = 0;
        x->pkts = 0;
    }

    if (pkt->l3type == ETH_P_IP)
	x->bytes += H16(IP(len));
    else
	x->bytes += pkt->len;
    x->pkts++;

    return 0;
}


static ssize_t
store(void *fh, char *buf, size_t len)
{
    FLOWDESC *x = F(fh);
    
    if (len < sizeof(FLOWDESC))
        return -1;

    PUTH32(buf, x->ts);
    PUTH32(buf, x->proto);
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


#define PRETTYHDR       \
    "Date                     Proto Bytes     Packets\n"

#define PRETTYFMT       "%.24s %5u %10llu %10llu\n"

static char *
print(char *buf, size_t *len, __unused char * const args[])
{
    static char s[2048];
    FLOWDESC *x;
    time_t ts; 
    
    if (buf == NULL && args != NULL) { 
        *len = sprintf(s, PRETTYHDR); 
        return s; 
    } 

    if (buf == NULL && args == NULL) { 
        *len = 0; 
        return s; 
    } 

    x = (FLOWDESC *) buf; 
    ts = (time_t)ntohl(x->ts);
    *len = sprintf(s, PRETTYFMT, 
	      asctime(localtime(&ts)), (uint) ntohl(x->proto), 
	      NTOHLL(x->bytes), NTOHLL(x->pkts));
    return s;
};


callbacks_t callbacks = {
    sizeof(FLOWDESC),
    0,
    NULL,
    NULL,
    NULL,
    NULL,
    hash,
    match,
    update,
    NULL,
    NULL,
    NULL,
    NULL,
    store,
    load,
    print,
    NULL
};
