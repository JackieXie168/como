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
 * Counter Module
 *
 * This module computes the number of captured packets and bytes
 * Output: packets/bytes seen every second. 
 *
 */

#include <stdio.h>
#include <time.h>
#include "module.h"


#define FLOWDESC    struct _counter
FLOWDESC {
    timestamp_t ts;
    uint64_t    bytes;
    uint32_t    pkts;
};

#define STATEDESC   struct _counter_state
STATEDESC {
    int meas_ivl;     /* measurement interval */
};

static timestamp_t 
init(void * self, char *args[])
{
    STATEDESC * state; 
    int i;
    pkt_t *pkt;
    metadesc_t *inmd;

    state = mdl_mem_alloc(self, sizeof(STATEDESC)); 
    state->meas_ivl = 1;
    for (i = 0; args && args[i]; i++) {
        if (strstr(args[i], "interval")) {
            char * val = index(args[i], '=') + 1;
            state->meas_ivl = atoi(val);
        }
    }
    
    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = TIME2TS(state->meas_ivl, 0);
    
    pkt = metadesc_tpl_add(inmd, "none:none:none:none");
    
/*    inmd = metadesc_define_in(self, 1, "sampling_rate");
    
    pkt = metadesc_tpl_add(inmd, "none:none:none:none");*/

    STATE(self) = state;
    return TIME2TS(state->meas_ivl, 0);
}

static int
check(__unused void * self, pkt_t * pkt)
{
    /*
     * if the stream contains per-flow information,
     * drop all packets after the first.
     */
    if ((COMO(type) == COMOTYPE_NF) && !(NF(flags) & COMONF_FIRST))
        return 0;
  
    return 1;
}

static int
update(__unused void * self, pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);

    if (isnew) {
	x->ts = COMO(ts);
        x->bytes = 0;
        x->pkts = 0;
    }

    if (COMO(type) == COMOTYPE_NF) {
        x->bytes += H64(NF(bytecount)) * (uint64_t) H16(NF(sampling));
        x->pkts += H32(NF(pktcount)) * (uint32_t) H16(NF(sampling));
    } else if (COMO(type) == COMOTYPE_SFLOW) {
	x->bytes += (uint64_t) COMO(len) * (uint64_t) H32(SFLOW(sampling_rate));
	x->pkts += (uint64_t) H32(SFLOW(sampling_rate));
    } else {
	x->bytes += COMO(len);
        x->pkts++;
    }

    return 0;
}

static ssize_t
store(void * self, void *rp, char *buf)
{
    FLOWDESC *x = F(rp);
    STATEDESC * state = STATE(self);

    PUTH64(buf, x->ts);
    PUTH64(buf, x->bytes/state->meas_ivl);
    PUTH32(buf, x->pkts/state->meas_ivl);

    return sizeof(FLOWDESC);
}

static size_t
load(__unused void * self, char * buf, size_t len, timestamp_t * ts)
{
    if (len < sizeof(FLOWDESC)) {
        ts = 0;
        return 0;
    }

    *ts = NTOHLL(((FLOWDESC *)buf)->ts);
    return sizeof(FLOWDESC);
}


#define PRETTYHDR		\
    "Date                     Timestamp          Bytes    Pkts\n"
#define PRETTYFMT	"%.24s %12d.%06d %8llu %8u\n"
#define PLAINFMT	"%12ld %16llu %12llu %12u\n"
#define MBPSFMT		"%4.2f Mbps\n"
#define GNUPLOTFMT	"%ld %f %u\n"

#define GNUPLOTHDR						\
    "set terminal postscript eps color solid lw 1 \"Helvetica\" 14;"	\
    "set grid;"								\
    "set ylabel \"Mbps\" textcolor lt 3;"				\
    "set xlabel \"Time (HH:MM UTC)\";"					\
    "set y2label \"Packets/sec\" textcolor lt 4;"			\
    "set y2tics nomirror;"						\
    "set ytics nomirror;"						\
    "set yrange [0:*];"							\
    "set y2range [0:*];"						\
    "set autoscale xfix;"						\
    "set nokey;"							\
    "set xdata time;"							\
    "set timefmt \"%%s\";"						\
    "set format x \"%%H:%%M\";"						\
    "plot \"-\" using 1:2 axis x1y1 with lines lt 3, "	\
    "\"-\" using 1:3 axis x1y2 with lines lt 4\n"	\

#define GNUPLOTFOOTER	"e\n"

static char *
print(void * self, char *buf, size_t *len, char * const args[])
{
    static char s[512];
    static char * fmt; 
    static int granularity = 1; 
    static int no_records = 0; 
    static uint64_t bytes = 0;
    static uint64_t pkts = 0;
    STATEDESC * state = STATE(self); 
    FLOWDESC *x; 
    timestamp_t ts;
    time_t t; 
    int n; 

    if (buf == NULL && args != NULL) { 
	/* by default, pretty print */
	*len = sprintf(s, PRETTYHDR);  
	fmt = PRETTYFMT; 

	/* first call of print, process the arguments and return */
	for (n = 0; args[n]; n++) {
	    if (!strcmp(args[n], "format=plain")) {
		*len = 0; 
		fmt = PLAINFMT;
	    } else if (!strcmp(args[n], "format=gnuplot")) {
		*len = sprintf(s, GNUPLOTHDR); 
		fmt = GNUPLOTFMT;
	    } else if (!strncmp(args[n], "granularity=", 10)) {
		char * val = index(args[n], '=') + 1;

		/* aggregate multiple records into one to reduce 
		 * communication messages. 
		 */
		granularity = MAX(atoi(val) / state->meas_ivl, 1);
	    } else if (!strcmp(args[n], "format=mbps")) {
		*len = 0; 
		fmt = MBPSFMT; 
	    } 
	} 

	return s; 
    } 

    if (buf == NULL && args == NULL) { 
	*len = 0;
	if (fmt == GNUPLOTFMT) 
	    *len = sprintf(s, GNUPLOTFOOTER);
	return s; 
    } 
	
    x = (FLOWDESC *) buf; 
    ts = NTOHLL(x->ts);
    t = (time_t) TS2SEC(ts); 

    /* aggregate records if needed */
    pkts += ntohl(x->pkts);
    bytes += NTOHLL(x->bytes);
    no_records++;
    if (no_records % granularity != 0) { 
	*len = 0;
	return s; 
    } 

    bytes /= granularity; 
    pkts /= granularity;

    /* print according to the requested format */
    if (fmt == PRETTYFMT) {
	*len = sprintf(s, fmt, 
	               asctime(localtime(&t)), TS2SEC(ts), TS2USEC(ts), 
		       bytes, pkts); 
    } else if (fmt == GNUPLOTFMT) {
	float mbps = 8.0 * (float) bytes / 1000000.0; 
	*len = sprintf(s, fmt, (long int)t, mbps, pkts);
    } else if (fmt == MBPSFMT) { 
	float mbps = 8.0 * (float) bytes / 1000000.0; 
	*len = sprintf(s, fmt, mbps); 
    } else { 
	*len = sprintf(s, fmt, (long int)t, ts, bytes, pkts); 
    } 
	
    pkts = bytes = 0;
    return s;
}

callbacks_t callbacks = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0,
    st_recordsize: sizeof(FLOWDESC),
    init: init,
    check: check,
    hash: NULL,
    match: NULL,
    update: update,
    ematch: NULL,
    export: NULL,
    compare: NULL,
    action: NULL,
    store: store,
    load: load,
    print: print,
    replay: NULL,
    formats: "gnuplot plain pretty mbps",
};
