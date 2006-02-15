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
 * This module computes 5-tuple flows 
 * It implements and idle timeout to expire flows and saves to 
 * file all flows as they expire. 
 *
 */

#include <stdio.h>
#include "module.h"


#define FLOWDESC    struct _tuple_stat
#define EFLOWDESC   FLOWDESC 


FLOWDESC {
    timestamp_t first;
    timestamp_t last;
    n32_t src_ip;
    n32_t dst_ip;
    n16_t src_port;
    n16_t dst_port;
    uint8_t proto;
    char padding[3];
    uint64_t bytes;
    uint64_t pkts;
};

static timestamp_t idle_timeout = TIME2TS(60,0);     /* idle timeout (secs) */

static timestamp_t
init(__unused void *mem, __unused size_t msize, char *args[])
{
    int i;

    for (i = 0; args && args[i]; i++) {
        if (strstr(args[i], "idle-timeout")) {
            char * val = index(args[i], '=') + 1;
            idle_timeout = TIME2TS(atoi(val), 0);
        }
    }
    return TIME2TS(1,0);
}

static uint32_t
hash(pkt_t *pkt)
{
    uint sport, dport;

    if (pkt->l3type != ETHERTYPE_IP) 
	return 0; 

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
    uint16_t sport = 0, dport = 0; 

    if (pkt->l3type != ETHERTYPE_IP) {
	if (x->proto == 0)
	    return 1;
	else
	    return 0;
    }

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
         sport == N16(x->src_port) &&
         dport == N16(x->dst_port) &&
         IP(proto) == x->proto
    );
}

static int
update(pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);

    if (isnew) {
	x->first = pkt->ts;
	x->bytes = 0;
	x->pkts = 0;

	if (isIP) { 
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

	    x->proto = IP(proto);
	}
    }

    x->last = pkt->ts;
    x->bytes += pkt->len;
    x->pkts++;

    return 0;
}

static int
ematch(void *efh, void *fh)
{
    FLOWDESC  *x  = F(fh);
    EFLOWDESC *ex = EF(efh);

    return (
         N32(ex->src_ip) == N32(x->src_ip) &&
         N32(ex->dst_ip) == N32(x->dst_ip) &&
         N16(ex->src_port) == N16(x->src_port) &&
         N16(ex->dst_port) == N16(x->dst_port) &&
         ex->proto == x->proto
    );
}

static int
export(void *efh, void *fh, int isnew)
{
    FLOWDESC  *x  = F(fh);
    EFLOWDESC *ex = EF(efh);

    if (isnew) {
        ex->src_ip = x->src_ip;
        ex->dst_ip = x->dst_ip;
        ex->src_port = x->src_port;
        ex->dst_port = x->dst_port;
        ex->proto = x->proto;
        ex->first = x->first;
	ex->bytes = 0;
	ex->pkts = 0;
    }

    ex->last = x->last;
    ex->bytes += x->bytes;
    ex->pkts += x->pkts;

    return 0;
}

static int
compare(const void *efh1, const void *efh2)
{
    EFLOWDESC *ex1 = CMPEF(efh1);
    EFLOWDESC *ex2 = CMPEF(efh2);

    /* we want to use LRU sorting */
    return ((ex1->last > ex2->last)? 1 : -1);
}

static int
action(void *efh, timestamp_t current_time, __unused int count)
{
    EFLOWDESC *ex = EF(efh);

    if (efh == NULL) 
	return ACT_GO;

    if (current_time - ex->last > idle_timeout) 
        return (ACT_STORE | ACT_DISCARD);

    /* are LRU sorted, STOP when we found the first flow not expired */
    return ACT_STOP;
}


static ssize_t
store(void *efh, char *buf, size_t len)
{
    EFLOWDESC *ex = EF(efh);
    
    if (len < sizeof(EFLOWDESC))
        return -1;

    PUTH64(buf, ex->first);
    PUTH64(buf, ex->last);
    PUTN32(buf, N32(ex->src_ip));
    PUTN32(buf, N32(ex->dst_ip));
    PUTN16(buf, N16(ex->src_port));
    PUTN16(buf, N16(ex->dst_port));
    PUTH8(buf, ex->proto);
    PUTH8(buf, ex->padding[0]);
    PUTH8(buf, ex->padding[1]);
    PUTH8(buf, ex->padding[2]);
    PUTH64(buf, ex->bytes);
    PUTH64(buf, ex->pkts);

    return sizeof(EFLOWDESC);
}

static size_t
load(char * buf, size_t len, timestamp_t * ts)
{
    if (len < sizeof(EFLOWDESC)) {
        ts = 0;
        return 0;
    }

    *ts = NTOHLL(((EFLOWDESC *)buf)->last); 
    return sizeof(EFLOWDESC);
}

#define PRETTYHDR                                               \
    "Proto Source IP:Port      Destination IP:Port   "          \
    "Bytes    Packets  Start        End\n"

#define PRETTYFMT  "%6d %15s %5u %15s %5u %8llu %8llu %12llu %12llu\n"


static char *
print(char *buf, size_t *len, char * const args[])
{
    EFLOWDESC *ex = (EFLOWDESC *) buf; 
    static char s[2048];
    struct in_addr saddr, daddr;
    char src[20], dst[20];

    if (buf == NULL && args != NULL) { 
        *len = sprintf(s, PRETTYHDR); 
        return s; 
    } 

    if (buf == NULL && args == NULL) { 
        *len = 0; 
        return s; 
    } 

    ex = (EFLOWDESC *) buf; 
    saddr.s_addr = N32(ex->src_ip);
    daddr.s_addr = N32(ex->dst_ip);
    sprintf(src, "%s", inet_ntoa(saddr));
    sprintf(dst, "%s", inet_ntoa(daddr));
    
    *len = sprintf(s, PRETTYFMT,
		(uint) ex->proto, src, ntohs(N16(ex->src_port)), 
		dst, ntohs(N16(ex->dst_port)), 
		NTOHLL(ex->bytes), NTOHLL(ex->pkts), 
		NTOHLL(ex->first), NTOHLL(ex->last));
    return s;
};


callbacks_t callbacks = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: sizeof(EFLOWDESC),
    st_recordsize: sizeof(EFLOWDESC),
    indesc: NULL,
    outdesc: NULL,
    init: init,
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
    replay: NULL,
    formats: "pretty"
};

