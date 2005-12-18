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
 * Ports module.
 *
 * This module counts the number of packets that use a certain 
 * port number (source or destination) and returns the aggregate 
 * value per measurement interval. It can also produce a scatter
 * plot where each dot has coordinates (x,y) where x is the least 
 * significant byte of the port number, y is the most significant byte.
 *
 */

#include <stdio.h>		/* sprintf */
#include "module.h"

#define FLOWDESC	struct _ports

FLOWDESC {
    uint32_t ts;			/* timestamp of first packet */
    uint64_t pkts[65536];		/* pkts per port number */
};

static uint32_t meas_ivl = 1;		/* interval (secs) */

static timestamp_t
init(__unused void *mem, __unused size_t msize, char *args[])
{
    int i;
    char *len;
    
    /* 
     * process input arguments 
     */
    for (i = 0; args && args[i]; i++) { 
	if (strstr(args[i], "interval")) {
	    len = index(args[i], '=') + 1; 
	    meas_ivl = atoi(len); 
	} 
    }

    return TIME2TS(meas_ivl, 0); 
}

static int
check(pkt_t *pkt)
{
    return (isTCP || isUDP); 	/* accept only TCP or UDP packets */
}


static int
update(pkt_t *pkt, void *rp, int isnew)
{
    FLOWDESC *x = F(rp);

    if (isnew) {
	bzero(x, sizeof(FLOWDESC)); 
	x->ts = TS2SEC(pkt->ts) - (TS2SEC(pkt->ts) % meas_ivl);
    }

    if (isTCP) {
	x->pkts[H16(TCP(src_port))]++;
	x->pkts[H16(TCP(dst_port))]++;
    } else { 
	x->pkts[H16(UDP(src_port))]++;
	x->pkts[H16(UDP(dst_port))]++;
    } 

    return 0;
}

static ssize_t
store(void *rp, char *buf, size_t len)
{
    FLOWDESC *x = F(rp);
    int i; 
    
    if (len < sizeof(FLOWDESC))
        return -1;

    PUTH32(buf, x->ts);
    for (i = 0; i < 65536; i++) 
	PUTH64(buf, x->pkts[i]); 

    return sizeof(FLOWDESC); 
}

static size_t
load(char *buf, size_t len, timestamp_t *ts)
{
    if (len < sizeof(FLOWDESC)) { 
        ts = 0;
        return 0; 
    }

    *ts = TIME2TS(ntohl(((FLOWDESC *)buf)->ts), 0);
    return sizeof(FLOWDESC); 
}


#define PLAINFMT	"%12u %5u %10llu\n"
#define GNUPLOTFMT      "%d %d\n"

#define GNUPLOTHDR                                              \
    "set terminal postscript eps color solid lw 1 \"Helvetica\" 14;"    \
    "set grid;"                                                         \
    "set ylabel \"most significant byte\";" 			        \
    "set xlabel \"least significant byte\";"       			\
    "set yrange [0:256];"                                               \
    "set xrange [0:256];"                                               \
    "set nokey;"                                                        \
    "plot \"-\" using 1:2 with dots lw 5 lt 3\n" 			\

static char *
print(char *buf, size_t *len, char * const args[])
{
    static char s[1024*1024];
    static char * fmt; 
    FLOWDESC *x; 
    time_t ts;
    int i; 

    if (buf == NULL && args != NULL) { 
	int n; 

        /* by default, pretty print */
        *len = 0;
        fmt = PLAINFMT; 

        /* first call of print, process the arguments and return */
        for (n = 0; args[n]; n++) {
            if (!strcmp(args[n], "format=gnuplot")) {
                *len = sprintf(s, GNUPLOTHDR); 
                fmt = GNUPLOTFMT;
            } 
        } 

	return s; 
    } 

    if (buf == NULL && args == NULL) { 
	*len = 0; 
  	return s; 
    } 

    x = (FLOWDESC *) buf;
    ts = (time_t) ntohl(x->ts);

    *len = 0;
    for (i = 0; i < 65536; i++) { 
	if (x->pkts[i] == 0) 
	    continue; 
	
	if (fmt == GNUPLOTFMT) { 
	    *len += sprintf(s + *len, fmt, (i+1) & 0x00ff, (i+1) >> 8);
	} else {
	    *len += sprintf(s + *len, fmt, ts, i, NTOHLL(x->pkts[i])); 
	} 
    }
	
    return s;
};


callbacks_t callbacks = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0, 
    st_recordsize: sizeof(FLOWDESC),
    indesc: NULL, 
    outdesc: NULL, 
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
    replay: NULL
};

