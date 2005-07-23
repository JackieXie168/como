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
 * 5-tuple flow classifier
 *
 * This module computes 5-tuple flows. Every capture period it 
 * stores the 5-tuple that have been active (together with the 
 * bytes they have sent).  
 *
 */

#include <stdio.h>
#include <time.h>
#include "como.h"
#include "module.h"

#define FLOWDESC    struct _tuple_stat

FLOWDESC {
    uint32_t ts; 
    n32_t src_ip;
    n32_t dst_ip;
    n16_t src_port;
    n16_t dst_port;
    uint8_t proto;
    char padding[3];
    uint64_t bytes;
    uint64_t pkts;
};


static uint32_t
hash(pkt_t *pkt)
{
    uint sport, dport; 

    if (IP(proto) == IPPROTO_TCP) { 
	sport = N16(TCP(src_port)); 
	dport = N16(TCP(dst_port)); 
    } else if (IP(proto) == IPPROTO_UDP) { 
	sport = N16(UDP(src_port)); 
	dport = N16(UDP(dst_port)); 
    } else { 
	sport = dport = 0;
    } 

    return (N32(IP(src_ip)) ^ N32(IP(dst_ip)) ^ (sport << 3) ^ (dport << 3));
}

static int
match(pkt_t *pkt, void *fh)
{
    FLOWDESC *x = F(fh);
    uint sport, dport; 
    
    if (IP(proto) == IPPROTO_TCP) {
        sport = N16(TCP(src_port));
        dport = N16(TCP(dst_port));
    } else if (IP(proto) == IPPROTO_UDP) {
        sport = N16(UDP(src_port));
        dport = N16(UDP(dst_port));
    } else {
        sport = dport = 0;
    }

    return (
         N32(IP(src_ip)) == N32(x->src_ip) &&
         N32(IP(dst_ip)) == N32(x->dst_ip) &&
         sport == N16(x->src_port) && dport == N16(x->dst_port) &&
         IP(proto) == x->proto
    );
}

static int
check(pkt_t *pkt)
{
    return pkt->l3type == ETHERTYPE_IP;
}

static int
update(pkt_t *pkt, void *fh, int isnew, __unused unsigned drop_cntr)
{
    FLOWDESC *x = F(fh);

    if (isnew) {
	x->ts = TS2SEC(pkt->ts); 
	x->bytes = 0;
	x->pkts = 0;
        x->proto = IP(proto);
        x->src_ip = IP(src_ip);
        x->dst_ip = IP(dst_ip);

	if (IP(proto) == IPPROTO_TCP) {
	    x->src_port = TCP(src_port); 
	    x->dst_port = TCP(dst_port); 
	} else if (IP(proto) == IPPROTO_UDP) {
	    x->src_port = UDP(src_port); 
	    x->dst_port = UDP(dst_port); 
	} else {
	    N16(x->src_port) = N16(x->dst_port) = 0; 
	}

	if (IP(proto) == IPPROTO_TCP || IP(proto) == IPPROTO_UDP) { 
	} 
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
    PUTN32(buf, N32(x->src_ip));
    PUTN32(buf, N32(x->dst_ip));
    PUTN16(buf, N16(x->src_port));
    PUTN16(buf, N16(x->dst_port));
    PUTH8(buf, x->proto);
    PUTH8(buf, x->padding[0]);
    PUTH8(buf, x->padding[1]);
    PUTH8(buf, x->padding[2]);
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

#define PRETTYHDR       					\
    "Date                     "					\
    "Proto Source IP:Port      Destination IP:Port   " 		\
    "Bytes    Packets\n"

#define PRETTYFMT       "%.24s %6d %15s %5u %15s %5u %8llu %8llu\n"

static char *
print(char *buf, size_t *len, char * const args[])
{
    static char s[2048];
    char src[20], dst[20];
    struct in_addr saddr, daddr;
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
    saddr.s_addr = N32(x->src_ip);
    daddr.s_addr = N32(x->dst_ip);
    sprintf(src, "%s", inet_ntoa(saddr));
    sprintf(dst, "%s", inet_ntoa(daddr)); 

    *len = sprintf(s, PRETTYFMT, 
		asctime(localtime(&ts)), (uint) x->proto, 
		src, (uint) H16(x->src_port), 
		dst, (uint) H16(x->dst_port), 
	        NTOHLL(x->bytes), NTOHLL(x->pkts));
    return s;
};


callbacks_t callbacks = {
    sizeof(FLOWDESC),
    0, 
    NULL,
    NULL,
    NULL,
    check,
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
