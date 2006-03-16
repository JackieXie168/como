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
#include "module.h"

#define FLOWDESC    struct _proto_stat

FLOWDESC {
    timestamp_t ts;
    uint64_t bytes[IPPROTO_MAX];
    uint32_t pkts[IPPROTO_MAX];
};

#define STATEDESC   struct _protocol_state
STATEDESC {
    int meas_ivl;     /* measurement interval */
    char str[8192];
    uint8_t proto[256]; 
    int num_proto; 
    int fmt; 
    int granularity;
    int no_records;
    FLOWDESC values; 
};

static timestamp_t
init(void * self, char *args[])
{
    STATEDESC *state;
    int i;
    pkt_t *pkt;
    metadesc_t *inmd;

    state = mdl_mem_alloc(self, sizeof(STATEDESC));
    bzero(state, sizeof(STATEDESC));
    state->meas_ivl = 1;
    state->granularity = 1;

    /* reset protocols array */
    bzero(state->proto, IPPROTO_MAX); 
    state->proto[0] = IPPROTO_TCP; 
    state->proto[1] = IPPROTO_UDP; 
    state->proto[2] = IPPROTO_ICMP; 
    state->proto[3] = IPPROTO_ESP; 
    state->num_proto = 4; 

    /* 
     * process input arguments 
     */
    for (i = 0; args && args[i]; i++) {
        if (strstr(args[i], "interval")) {
            char * val = index(args[i], '=') + 1;
            state->meas_ivl = atoi(val);
        }
    }
    
    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = TIME2TS(state->meas_ivl, 0);
    
    pkt = metadesc_tpl_add(inmd, "none:none:~ip:none");
    IP(proto) = 0xff;
    N16(IP(len)) = 0xffff;
    
    STATE(self) = state; 
    return TIME2TS(state->meas_ivl, 0);
}

static int
update(__unused void * self, pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);

    if (isnew) {
	x->ts = pkt->ts;
        bzero(x->bytes, sizeof(x->bytes));
        bzero(x->pkts, sizeof(x->pkts));
    }

    if (COMO(type) == COMOTYPE_NF) {
        x->bytes[IP(proto)] += H64(NF(bytecount)) * (uint64_t)H16(NF(sampling));
        x->pkts[IP(proto)] += H32(NF(pktcount)) * (uint32_t) H16(NF(sampling));
    } else if (COMO(type) == COMOTYPE_SFLOW) {
	x->bytes[IP(proto)] += (uint64_t) COMO(len) * 
					(uint64_t) H32(SFLOW(sampling_rate));
	x->pkts[IP(proto)] += H32(SFLOW(sampling_rate));
    } else {
        x->bytes[IP(proto)] += H16(IP(len)); 
        /* CHECKME: is this more correct?
         * x->bytes[IP(proto)] += H16(COMO(len)); */
        x->pkts[IP(proto)]++;
    }

    return 0;
}


static ssize_t
store(__unused void * self, void *fh, char *buf)
{
    FLOWDESC *x = F(fh);
    int i; 
    
    PUTH64(buf, x->ts);
    for (i = 0; i < IPPROTO_MAX; i++) 
        PUTH64(buf, x->bytes[i]);
    for (i = 0; i < IPPROTO_MAX; i++) 
        PUTH32(buf, x->pkts[i]);

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



#define PRINT_PLAIN		0
#define PRINT_PRETTY		1
#define PRINT_GNUPLOT		2


/* 
 * Gnuplot 4.0 format. 
 * 
 * By default, this module will only plot the graph for TCP, UDP, ICNP and
 * ESP. All other protocols are considered in the OTHER column. 
 * If a user desires to see the other protocols then it can send a query 
 * with the option "include=<proto-number>" that would force print() to 
 * add one line to the graph. 
 * 
 * Note that in gnuplot format we only consider the contribution of each
 * protocol in bytes. 
 * 
 */

#define GNUPLOTHDR                                                      \
    "set terminal postscript eps color solid lw 1 \"Helvetica\" 14;"    \
    "set grid;"                                                         \
    "set ylabel \"Percentage\";"                                        \
    "set xlabel \"Time (H:M UTC)\";"                                    \
    "set yrange [0:100];"                                               \
    "set autoscale xfix;"                                               \
    "set key outside;"                                                  \
    "set xdata time;"                                                   \
    "set timefmt \"%%s\";"                                              \
    "set format x \"%%H:%%M\";"                                         
    
#define GNUPLOTFOOTER   "e\n"
     

/* 
 * -- do_header 
 * 
 * just to print header information  
 */
static size_t 
do_header(char * const args[], STATEDESC * state) 
{
    size_t len; 
    int n;

    /* first call of print, process the arguments and return */
    for (n = 0; args[n]; n++) {
	if (!strcmp(args[n], "format=plain")) {
	    len = 0;
	    state->fmt = PRINT_PLAIN;
	} else if (!strcmp(args[n], "format=pretty")) {
	    len = 0; 
	    state->fmt = PRINT_PRETTY;
	} else if (!strcmp(args[n], "format=gnuplot")) {
	    state->fmt = PRINT_GNUPLOT;
	} else if (!strncmp(args[n], "include=", 8)) { 
	    char * wh; 

	    wh = index(args[n], '=') + 1; 
	    state->proto[state->num_proto] = atoi(wh); 
	    state->num_proto++; 
	} else if (!strncmp(args[n], "granularity=", 12)) {
	    char * val = index(args[n], '=') + 1;

	    /* aggregate multiple records into one to reduce
	     * communication messages.
	     */
	    state->granularity = MAX(atoi(val) / state->meas_ivl,1);
	}
    }

    if (state->fmt == PRINT_GNUPLOT) { 
	/* 
	 * we need to print the header but make sure that we 
	 * include/exclude all protocols. 
	 */
	len = sprintf(state->str, GNUPLOTHDR); 

	len += sprintf(state->str + len, 
		       "plot \"-\" using 1:%d with filledcurve x1 "
		       "title \"Other\" lw 5",
		       state->num_proto + 2); 
	for (n = state->num_proto - 1; n >= 0; n--) { 
	    len += sprintf(state->str + len, 
		           ",\"-\" using 1:%d with filledcurve x1 "
		           "title \"%s (%d)\" lw 5",
		           n + 2, getprotoname(state->proto[n]), 
			   state->proto[n]); 
	} 

	len += sprintf(state->str + len, ";\n"); 
    } 

    return len; 
}


static size_t 
print_plain(STATEDESC * state) 
{
    size_t len; 
    int i;

    len = sprintf(state->str, "%12u.%06u ", 
		  (uint) TS2SEC(state->values.ts), 
		  (uint) TS2USEC(state->values.ts));
    for (i = 0; i < IPPROTO_MAX; i++) 
	len += sprintf(state->str + len, "%3d %8llu %8u ", 
		       i, state->values.bytes[i], state->values.pkts[i]);
    len += sprintf(state->str + len, "\n"); 
    return len; 
}
	

static size_t 
print_pretty(STATEDESC * state) 
{
    time_t ts; 
    size_t len; 
    uint64_t bytes_all, pkts_all;
    uint64_t bytes_chosen, pkts_chosen; 
    float bytes_prct, pkts_prct; 
    int i;

    ts = (time_t) TS2SEC(state->values.ts);
    len = sprintf(state->str, "%.24s ", asctime(localtime(&ts)));

    /* compute the sums of all bytes and packets */
    bytes_all = pkts_all = 0; 
    for (i = 0; i < IPPROTO_MAX; i++) { 
	bytes_all += state->values.bytes[i]; 
	pkts_all += state->values.pkts[i]; 
    } 

    if (bytes_all == 0) 
	return 0; 

    /* compute the sums of all bytes and packets of interest */
    bytes_chosen = pkts_chosen = 0; 
    for (i = 0; i < state->num_proto; i++) { 
	bytes_prct = 
		100 * (float) state->values.bytes[state->proto[i]] / bytes_all; 
	pkts_prct = 
		100 * (float) state->values.pkts[state->proto[i]] / pkts_all; 

	len += sprintf(state->str + len, "%s %5.2f %5.2f ", 
		      getprotoname(state->proto[i]), bytes_prct, pkts_prct); 

	bytes_chosen += state->values.bytes[state->proto[i]]; 
	pkts_chosen += state->values.pkts[state->proto[i]]; 
    } 

    bytes_prct = 100 - (100 * (float) bytes_chosen / bytes_all); 
    pkts_prct = 100 - (100 * (float) pkts_chosen / pkts_all); 
    len += sprintf(state->str + len, "Other %5.2f %5.2f\n", 
		   bytes_prct, pkts_prct); 
    return len; 
}


static size_t
print_gnuplot(STATEDESC * state) 
{
    size_t len; 
    uint64_t bytes_all;
    float bytes_sofar; 
    float bytes_prct; 
    int i;

    len = sprintf(state->str, "%u ", (uint) TS2SEC(state->values.ts)); 

    /* compute the sums of all bytes and packets */
    bytes_all = 0; 
    for (i = 0; i < IPPROTO_MAX; i++) 
	bytes_all += state->values.bytes[i]; 

    if (bytes_all == 0) 
	return 0; 

    /* compute the sums of all bytes and packets of interest */
    bytes_sofar = 0; 
    for (i = 0; i < state->num_proto; i++) { 
	bytes_prct = 
		100 * (float) state->values.bytes[state->proto[i]] / bytes_all; 
	len += sprintf(state->str + len, "%5.2f ", bytes_sofar + bytes_prct); 
	bytes_sofar += bytes_prct; 
    } 

    len += sprintf(state->str + len, "100 \n"); 

    return len;
}


static char *
print(void * self, char *buf, size_t *len, __unused char * const args[])
{
    STATEDESC * state = STATE(self);
    FLOWDESC *x;
    int i;
    
    if (buf == NULL && args != NULL) { 
	*len = do_header(args, state); 
	bzero(&state->values, sizeof(state->values)); 
	return state->str; 
    } 

    if (buf == NULL && args == NULL) {
        *len = 0;
        if (state->fmt == PRINT_GNUPLOT)
            *len = sprintf(state->str, GNUPLOTFOOTER);
        return state->str;
    }

    x = (FLOWDESC *) buf; 
    state->values.ts = NTOHLL(x->ts);

    /* aggregate records if needed */
    for (i = 0; i < IPPROTO_MAX; i++) { 
	state->values.bytes[i] += NTOHLL(x->bytes[i]); 
	state->values.pkts[i] += ntohl(x->pkts[i]); 
    } 
    state->no_records++;
    if (state->no_records % state->granularity != 0) {
        *len = 0;
        return state->str;
    }
    
    for (i = 0; i < IPPROTO_MAX; i++) { 
	state->values.bytes[i] /= state->granularity; 
	state->values.pkts[i] /= state->granularity;
    }

    if (state->fmt == PRINT_PLAIN) 
	*len = print_plain(state); 
    else if (state->fmt == PRINT_PRETTY) 
	*len = print_pretty(state); 
    else if (state->fmt == PRINT_GNUPLOT) 
	*len = print_gnuplot(state); 

    bzero(&state->values, sizeof(state->values));
    return state->str;
};


callbacks_t callbacks = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0,
    st_recordsize: sizeof(FLOWDESC),
    init: init,
    check: NULL,
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
    formats: "plain pretty gnuplot"
};

