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
 * Packet timestamps for each 5-tuple
 */

#include <stdio.h>
#include <time.h>
#include "como.h"
#include "module.h"

#define FLOWDESC    struct _flowts
#define EFLOWDESC   struct _eflowts

/* The record structures for CAPTURE and EXPORT are basically the same,
 * except that in EXPORT we can store more timestamps per record */

FLOWDESC {
    n32_t src_ip;
    n32_t dst_ip;
    n16_t src_port;
    n16_t dst_port;
    uint8_t proto;
    char padding[3];
    uint32_t nts;
    timestamp_t ts[10];
};

EFLOWDESC {
    n32_t src_ip;
    n32_t dst_ip;
    n16_t src_port;
    n16_t dst_port;
    uint8_t proto;
    char padding[3];
    uint32_t nts;
    uint8_t full;
    timestamp_t ts[1000];
};

static int
check(pkt_t *pkt)
{
    /* Accept only IP packets */
    return pkt->l3type == ETHERTYPE_IP;
}

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

    /* The hash is a bitwise XOR of IP addresses and ports */
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
update(pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);

    if (isnew) {
        x->nts = 0;
        
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
    }

    x->ts[x->nts] = pkt->ts;
    x->nts++;

    if (x->nts == 10) return 1;
    else return 0;
}

static int
ematch(void *efh, void *fh)
{
    FLOWDESC *x = F(fh);
    EFLOWDESC *ex = EF(efh);
    
    return (
         N32(ex->src_ip) == N32(x->src_ip) &&
         N32(ex->dst_ip) == N32(x->dst_ip) &&
         N16(ex->src_port) == N16(x->src_port) &&
         N16(ex->dst_port) == N16(x->dst_port) &&
         ex->proto == x->proto &&
         !(ex->full)
    );
}

static int
export(void *efh, void *fh, int isnew)
{
    unsigned int i;
    
    FLOWDESC  *x  = F(fh);
    EFLOWDESC *ex = EF(efh);

    if (isnew) {
        ex->nts = 0;
        ex->full = 0;
        
        ex->proto = x->proto;
        ex->src_ip = x->src_ip;
        ex->dst_ip = x->dst_ip;
	    ex->src_port = x->src_port;
	    ex->dst_port = x->dst_port;
    }
    
    /* Add the timestamps to the array */
    for (i = 0; i < x->nts; i++)
        ex->ts[ex->nts + i] = x->ts[i];

    ex->nts += x->nts;

    /* Check if we will overflow the record
     * the next time the export callback is called */
    if ((ex->nts + 10) >= 1000)
        ex->full = 1;
    
    return 0;
}

static int
compare(const void *efh1, const void *efh2)
{
    EFLOWDESC *ex1 = CMPEF(efh1);
    EFLOWDESC *ex2 = CMPEF(efh2);

    uint32_t srcip1, srcip2, dstip1, dstip2;
    uint16_t srcport1, srcport2, dstport1, dstport2;

    /* Sort by protocol, src/dst ip address, src/dst port
     * If they are equal, sort by the first timestamp
     */
    
    srcip1 = H32(ex1->src_ip);
    srcip2 = H32(ex2->src_ip);
    dstip1 = H32(ex1->dst_ip);
    dstip2 = H32(ex2->dst_ip);

    srcport1 = H16(ex1->src_port);
    srcport2 = H16(ex2->src_port);
    dstport1 = H16(ex1->dst_port);
    dstport2 = H16(ex2->dst_port);

    if (ex1->proto > ex2->proto) return 1;
    else if (ex1->proto < ex2->proto) return -1;
    else {
        if (srcip1 > srcip2) return 1;
        else if (srcip1 < srcip2) return -1;
        else {
            if (srcport1 > srcport2) return 1;
            else if (srcport1 < srcport2) return -1;
            else {
                if (dstip1 > dstip2) return 1;
                else if (dstip2 < dstip1) return -1;
                else {
                    if (dstport1 > dstport2) return 1;
                    else if (dstport2 < dstport1) return -1;
                    else
                        return ((ex1->ts[0] > ex2->ts[0])? 1 : -1);
                }   
            }
        }
    }
}

static int
action(void *efh, __unused timestamp_t current_time, __unused int count)
{
    if (efh == NULL) 
	    return ACT_GO;

    /* Always store the records */
    return (ACT_STORE | ACT_DISCARD);
}

static ssize_t
store(void *efh, char *buf, size_t len)
{
    EFLOWDESC *ex = EF(efh);
    uint32_t i;
    
    if (len < sizeof(EFLOWDESC))
        return -1;
    
    PUTN32(buf, N32(ex->src_ip));
    PUTN32(buf, N32(ex->dst_ip));
    PUTN16(buf, N16(ex->src_port));
    PUTN16(buf, N16(ex->dst_port));
    PUTH8(buf, ex->proto);
    PUTH8(buf, ex->padding[0]);
    PUTH8(buf, ex->padding[1]);
    PUTH8(buf, ex->padding[2]);
    PUTH32(buf, ex->nts);
    for (i = 0; i < ex->nts; i++)
        PUTH64(buf, ex->ts[i]);

    return sizeof(EFLOWDESC);
}

static size_t
load(char * buf, size_t len, timestamp_t * ts)
{
    EFLOWDESC *ex;
    timestamp_t tsaux;
    
    if (len < sizeof(EFLOWDESC)) {
        ts = 0;
        return 0;
    }
    
    ex = (EFLOWDESC *)buf;

    /* First timestamp observed for the 5-tuple in this record */
    tsaux = ex->ts[0];
    *ts = NTOHLL(tsaux);
    
    return sizeof(EFLOWDESC);
}

#define PRETTYHDR       					\
    "Proto Source IP:Port      Destination IP:Port      Timestamps\n"

#define PRETTYFMT       "%6d %15s %5u %15s %5u "

static char *
print(char *buf, size_t *len, char * const args[])
{
    static char s[32768];
    char src[20], dst[20];
    struct in_addr saddr, daddr;
    FLOWDESC *x; 
    uint32_t i;
    timestamp_t t;

    if (buf == NULL && args != NULL) { 
        *len = sprintf(s, PRETTYHDR); 
        return s; 
    } 

    if (buf == NULL && args == NULL) { 
        *len = 0; 
        return s; 
    } 

    x = (FLOWDESC *) buf;
    
    saddr.s_addr = N32(x->src_ip);
    daddr.s_addr = N32(x->dst_ip);
    sprintf(src, "%s", inet_ntoa(saddr));
    sprintf(dst, "%s", inet_ntoa(daddr)); 
    *len = sprintf(s, PRETTYFMT, 
		           (uint) x->proto, 
		           src, (uint) H16(x->src_port), 
		           dst, (uint) H16(x->dst_port));

    for (i = 0; i < ntohl(x->nts); i++) {
        t = NTOHLL(x->ts[i]);
        *len += sprintf(s + *len, "%12d.%06d ", TS2SEC(t), TS2USEC(t));
    }

    *len += sprintf(s + *len, "\n");
    
    return s;
};


callbacks_t callbacks = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: sizeof(EFLOWDESC),
    indesc: NULL,
    outdesc: NULL,
    init: NULL,
    check: check,
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
