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
#include "module.h"

#define FLOWDESC    struct _flows
#define EFLOWDESC   struct _active_flows

FLOWDESC {
    uint32_t ts; 
    n32_t src_ip;
    n32_t dst_ip;
    n16_t src_port;
    n16_t dst_port;
    uint8_t proto;
    char padding[3];
};

EFLOWDESC { 
    uint32_t ts; 
    uint32_t count;
};

#define STATEDESC   struct _activeflows_state
STATEDESC {
    int meas_ivl;
    uint32_t flowcount; 
    uint32_t current_ts; 
};

static timestamp_t
init(void * self, char * args[])
{
    STATEDESC *state;
    int i; 

    state = mdl_mem_alloc(self, sizeof(STATEDESC));
    state->meas_ivl = 1;
    state->flowcount = 0; 
    state->current_ts = 0; 
    
    /*
     * process input arguments
     */
    for (i = 0; args && args[i]; i++) {
	if (strstr(args[i], "interval")) {
	    char * len = index(args[i], '=') + 1; 
	    state->meas_ivl = atoi(len); 
	}
    }

    STATE(self) = state;
    return TIME2TS(state->meas_ivl, 0);
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
update(__unused void * self, pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);

    if (isnew) {
	x->ts = TS2SEC(pkt->ts); 
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

    return 0;
}

static int 
export(void * self, __unused void *efh, __unused void *fh, int isnew)
{ 
    FLOWDESC *x = F(fh);
    STATEDESC * state = STATE(self);

    if (isnew) 
        state->current_ts = x->ts - x->ts % state->meas_ivl; 

    state->flowcount++;
    return 0;
}

static int
action(__unused void * self, void *efh, 
       __unused timestamp_t current_time, int count)
{
    if (efh == NULL) 
        return ACT_GO;          /* dump the records */

    if (count == 0) 
	return ACT_STORE|ACT_DISCARD; 

    return ACT_DISCARD;
}

static ssize_t
store(void * self, __unused void *efh, char *buf)
{
    STATEDESC * state = STATE(self);

    PUTH32(buf, state->current_ts);
    PUTH32(buf, state->flowcount); 
    state->flowcount = 0; 

    return sizeof(EFLOWDESC);
}

static size_t
load(__unused void * self, char * buf, size_t len, timestamp_t * ts)
{
    if (len < sizeof(EFLOWDESC)) {
        ts = 0;
        return 0;
    }

    *ts = TIME2TS(ntohl(((EFLOWDESC *)buf)->ts), 0);
    return sizeof(EFLOWDESC);
}


#define GNUPLOTHDR                                              \
    "set terminal postscript eps color solid lw 1 \"Helvetica\" 14;"    \
    "set grid;"                                                         \
    "set ylabel \"Active flows\";" 		                        \
    "set xlabel \"Time (HH:MM UTC)\";"                                  \
    "set yrange [0:*];"                                                 \
    "set autoscale xfix;"                                               \
    "set nokey;"                                                        \
    "set xdata time;"                                                   \
    "set timefmt \"%%s\";"                                              \
    "set format x \"%%H:%%M\";"                                         \
    "plot \"-\" using 1:2 with lines lt 3\n" 

#define GNUPLOTFMT      "%u %u\n"

static char *
print(void * self, char *buf, size_t *len, char * const args[])
{
    static char s[2048];
    static int granularity = 1;
    static int count = 0; 
    static int no_records = 0; 
    STATEDESC * state = STATE(self);
    EFLOWDESC *x; 

    if (buf == NULL && args != NULL) { 
	int n; 

        *len = sprintf(s, GNUPLOTHDR); 

        for (n = 0; args[n]; n++) {
            if (!strncmp(args[n], "granularity=", 10)) {
                char * val = index(args[n], '=') + 1;
 
                /* aggregate multiple records into one to reduce
                 * communication messages.
                 */
                granularity = MAX(atoi(val) / state->meas_ivl, 1);
	    } 
	}

        return s; 
    } 

    if (buf == NULL && args == NULL) { 
        *len = 0; 
        return s; 
    } 

    x = (EFLOWDESC *) buf;

    count += ntohl(x->count); 
    no_records++;
    if (no_records % granularity != 0) {
        *len = 0;
        return s;
    }

    count /= granularity; 
    *len = sprintf(s, GNUPLOTFMT, (uint) ntohl(x->ts), count); 
    count = 0; 
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
    ematch: NULL,
    export: export,
    compare: NULL,
    action: action,
    store: store,
    load: load,
    print: print,
    replay: NULL,
    formats: "gnuplot"
};
