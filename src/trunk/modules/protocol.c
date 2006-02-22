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

static int meas_ivl = 1;     /* measurement interval */

static timestamp_t
init(__unused void *mem, __unused size_t msize, char *args[])
{
    int i;

    for (i = 0; args && args[i]; i++) {
        if (strstr(args[i], "interval")) {
            char * val = index(args[i], '=') + 1;
            meas_ivl = atoi(val);
        }
    }
    return TIME2TS(meas_ivl, 0);
}

static int
update(pkt_t *pkt, void *fh, int isnew)
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
	x->bytes[IP(proto)] += (uint64_t) COMO(len) * (uint64_t) H32(SFLOW(sampling_rate));
	x->pkts[IP(proto)] += H32(SFLOW(sampling_rate));
    } else {
        x->bytes[IP(proto)] += H16(IP(len)); 
        x->pkts[IP(proto)]++;
    }

    return 0;
}


static ssize_t
store(void *fh, char *buf, size_t len)
{
    FLOWDESC *x = F(fh);
    int i; 
    
    if (len < sizeof(FLOWDESC))
        return -1;

    PUTH64(buf, x->ts);
    for (i = 0; i < IPPROTO_MAX; i++) 
        PUTH64(buf, x->bytes[i]);
    for (i = 0; i < IPPROTO_MAX; i++) 
        PUTH32(buf, x->pkts[i]);

    return sizeof(FLOWDESC);
}

static size_t
load(char * buf, size_t len, timestamp_t * ts)
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
do_header(char * const args[], char * s, int * fmt, 
	  uint8_t * proto, int * num_proto, int * granularity)
{
    size_t len; 
    int n;

    /* reset protocols array */
    bzero(proto, IPPROTO_MAX); 
    proto[0] = IPPROTO_TCP; 
    proto[1] = IPPROTO_UDP; 
    proto[2] = IPPROTO_ICMP; 
    proto[3] = IPPROTO_ESP; 
    *num_proto = 4; 

    /* first call of print, process the arguments and return */
    for (n = 0; args[n]; n++) {
	if (!strcmp(args[n], "format=plain")) {
	    len = 0;
	    *fmt = PRINT_PLAIN;
	} else if (!strcmp(args[n], "format=pretty")) {
	    len = 0; 
	    *fmt = PRINT_PRETTY;
	} else if (!strcmp(args[n], "format=gnuplot")) {
	    *fmt = PRINT_GNUPLOT;
	} else if (!strncmp(args[n], "include=", 8)) { 
	    char * wh; 

	    wh = index(args[n], '=') + 1; 
	    proto[*num_proto] = atoi(wh); 
	    *num_proto = *num_proto + 1;
	} else if (!strncmp(args[n], "granularity=", 12)) {
	    char * val = index(args[n], '=') + 1;

	    /* aggregate multiple records into one to reduce
	     * communication messages.
	     */
	    *granularity = MAX(atoi(val) / meas_ivl,1);
	}
    }

    if (*fmt == PRINT_GNUPLOT) { 
	/* 
	 * we need to print the header but make sure that we 
	 * include/exclude all protocols. 
	 */
	len = sprintf(s, GNUPLOTHDR); 

	len += sprintf(s + len, 
		       "plot \"-\" using 1:%d with filledcurve x1 "
		       "title \"Other\" lw 5",
		       *num_proto + 2); 
	for (n = *num_proto - 1; n >= 0; n--) { 
	    len += sprintf(s + len, 
		           ",\"-\" using 1:%d with filledcurve x1 "
		           "title \"%s (%d)\" lw 5",
		           n + 2, getprotoname(proto[n]), proto[n]); 
	} 

	len += sprintf(s + len, ";\n"); 
    } 

    return len; 
}


static size_t 
print_plain(FLOWDESC * x, char * s) 
{
    size_t len; 
    int i;

    len = sprintf(s, "%12u.%06u ", (uint) TS2SEC(x->ts), (uint) TS2USEC(x->ts));
    for (i = 0; i < IPPROTO_MAX; i++) 
	len += sprintf(s + len, "%3d %8llu %8u ", i, x->bytes[i], x->pkts[i]);
    len += sprintf(s + len, "\n"); 
    return len; 
}
	

static size_t 
print_pretty(FLOWDESC * x, char * s, int num_proto, uint8_t * proto) 
{
    time_t ts; 
    size_t len; 
    uint64_t bytes_all, pkts_all;
    uint64_t bytes_chosen, pkts_chosen; 
    float bytes_prct, pkts_prct; 
    int i;

    ts = (time_t) TS2SEC(x->ts);
    len = sprintf(s, "%.24s ", asctime(localtime(&ts)));

    /* compute the sums of all bytes and packets */
    bytes_all = pkts_all = 0; 
    for (i = 0; i < IPPROTO_MAX; i++) { 
	bytes_all += x->bytes[i]; 
	pkts_all += x->pkts[i]; 
    } 

    if (bytes_all == 0) 
	return 0; 

    /* compute the sums of all bytes and packets of interest */
    bytes_chosen = pkts_chosen = 0; 
    for (i = 0; i < num_proto; i++) { 
	bytes_prct = 100 * (float) x->bytes[proto[i]] / bytes_all; 
	pkts_prct = 100 * (float) x->pkts[proto[i]] / pkts_all; 

	len += sprintf(s + len, "%s %5.2f %5.2f ", 
		      getprotoname(proto[i]), bytes_prct, pkts_prct); 

	bytes_chosen += x->bytes[proto[i]]; 
	pkts_chosen += x->pkts[proto[i]]; 
    } 

    bytes_prct = 100 - (100 * (float) bytes_chosen / bytes_all); 
    pkts_prct = 100 - (100 * (float) pkts_chosen / pkts_all); 
    len += sprintf(s + len, "Other %5.2f %5.2f\n", bytes_prct, pkts_prct); 

    return len; 
}


static size_t
print_gnuplot(FLOWDESC * x, char * s, int num_proto, uint8_t * proto) 
{
    size_t len; 
    uint64_t bytes_all;
    float bytes_sofar; 
    float bytes_prct; 
    int i;

    len = sprintf(s, "%u ", (uint) TS2SEC(x->ts)); 

    /* compute the sums of all bytes and packets */
    bytes_all = 0; 
    for (i = 0; i < IPPROTO_MAX; i++) 
	bytes_all += x->bytes[i]; 

    if (bytes_all == 0) 
	return 0; 

    /* compute the sums of all bytes and packets of interest */
    bytes_sofar = 0; 
    for (i = 0; i < num_proto; i++) { 
	bytes_prct = 100 * (float) x->bytes[proto[i]] / bytes_all; 
	len += sprintf(s + len, "%5.2f ", bytes_sofar + bytes_prct); 
	bytes_sofar += bytes_prct; 
    } 

    len += sprintf(s + len, "100 \n"); 

    return len;
}


static char *
print(char *buf, size_t *len, __unused char * const args[])
{
    static char s[8192];
    static uint8_t proto[256]; 
    static int num_proto; 
    static int fmt; 
    static int granularity = 1;
    static int no_records = 0;
    static FLOWDESC values; 
    FLOWDESC *x;
    int i;
    
    if (buf == NULL && args != NULL) { 
	*len = do_header(args, s, &fmt, proto, &num_proto, &granularity); 
	bzero(values.bytes, sizeof(values.bytes));
	bzero(values.pkts, sizeof(values.pkts));
	return s; 
    } 

    if (buf == NULL && args == NULL) {
        *len = 0;
        if (fmt == PRINT_GNUPLOT)
            *len = sprintf(s, GNUPLOTFOOTER);
        return s;
    }

    x = (FLOWDESC *) buf; 
    values.ts = NTOHLL(x->ts);

    /* aggregate records if needed */
    for (i = 0; i < IPPROTO_MAX; i++) { 
	values.bytes[i] += NTOHLL(x->bytes[i]); 
	values.pkts[i] += ntohl(x->pkts[i]); 
    } 
    no_records++;
    if (no_records % granularity != 0) {
        *len = 0;
        return s;
    }
    
    for (i = 0; i < IPPROTO_MAX; i++) { 
	values.bytes[i] /= granularity; 
	values.pkts[i] /= granularity;
    }

    if (fmt == PRINT_PLAIN) 
	*len = print_plain(&values, s); 
    else if (fmt == PRINT_PRETTY) 
	*len = print_pretty(&values, s, num_proto, proto); 
    else if (fmt == PRINT_GNUPLOT) 
	*len = print_gnuplot(&values, s, num_proto, proto); 

    bzero(values.bytes, sizeof(values.bytes));
    bzero(values.pkts, sizeof(values.pkts));
    return s;
};


callbacks_t callbacks = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0,
    st_recordsize: sizeof(FLOWDESC),
    indesc: NULL, 
    outdesc: NULL,
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

