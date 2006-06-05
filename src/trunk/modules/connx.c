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
 * 5-tuple flow classifier
 *
 * This module computes 5-tuple flows 
 * It implements and idle timeout to expire flows and saves to 
 * file all flows as they expire. 
 *
 */

#include <stdio.h>
#include "module.h"


#define FLOWDESC    struct _connx_stat
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

#define CONFIGDESC   struct _connx_config
CONFIGDESC {
    timestamp_t idle_timeout;     /* idle timeout (secs) */
};

static timestamp_t
init(void * self, char *args[])
{
    CONFIGDESC *config;
    int i;
    pkt_t *pkt;
    metadesc_t *inmd;

    config = mem_mdl_malloc(self, sizeof(CONFIGDESC)); 
    config->idle_timeout = TIME2TS(60,0);

    /* 
     * process input arguments
     */
    for (i = 0; args && args[i]; i++) {
        if (strstr(args[i], "idle-timeout")) {
            char * val = index(args[i], '=') + 1;
            config->idle_timeout = TIME2TS(atoi(val), 0);
        }
    }

    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = TIME2TS(1,0);
    
    pkt = metadesc_tpl_add(inmd, "none:none:~ip:none");
    IP(proto) = 0xff;
    N16(IP(len)) = 0xffff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    
    pkt = metadesc_tpl_add(inmd, "none:none:~ip:~tcp");
    IP(proto) = 0xff;
    N16(IP(len)) = 0xffff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    N16(TCP(src_port)) = 0xffff;
    N16(TCP(dst_port)) = 0xffff;
    
    pkt = metadesc_tpl_add(inmd, "none:none:~ip:~udp");
    IP(proto) = 0xff;
    N16(IP(len)) = 0xffff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    N16(UDP(src_port)) = 0xffff;
    N16(UDP(dst_port)) = 0xffff;

    CONFIG(self) = config; 
    return TIME2TS(1,0);
}

static uint32_t
hash(__unused void * self, pkt_t *pkt)
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
match(__unused void * self, pkt_t *pkt, void *fh)
{
    FLOWDESC *x = F(fh);
    uint16_t sport = 0, dport = 0; 

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
update(__unused void * self, pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);

    if (isnew) {
	x->first = COMO(ts);
	x->bytes = 0;
	x->pkts = 0;

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

    x->last = COMO(ts);
    x->bytes += COMO(len);
    x->pkts++;

    return 0;
}

static int
ematch(__unused void * self, void *efh, void *fh)
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
export(__unused void * self, void *efh, void *fh, int isnew)
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
action(void * self, void *efh,  __unused timestamp_t ivl,
       timestamp_t current_time, __unused int count)
{
    EFLOWDESC *ex = EF(efh);
    CONFIGDESC * config = CONFIG(self);

    if (efh == NULL) 
	return ACT_GO;

    if (current_time - ex->last > config->idle_timeout) 
        return (ACT_STORE | ACT_DISCARD);

    /* are LRU sorted, STOP when we found the first flow not expired */
    return ACT_STOP;
}


static ssize_t
store(__unused void * self, void *efh, char *buf)
{
    EFLOWDESC *ex = EF(efh);
    
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
load(__unused void * self, char * buf, size_t len, timestamp_t * ts)
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
print(__unused void * self, char *buf, size_t *len, char * const args[])
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
    capabilities: {has_flexible_flush: 0, 0},
    init: init,
    check: NULL,
    hash: hash,  
    match: match,
    update: update,
    flush: NULL, 
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

