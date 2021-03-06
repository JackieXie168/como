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
#include "como.h"
#include "module.h"


#define FLOWDESC    struct _counters
FLOWDESC {
    timestamp_t ts;
    uint64_t    byts;
    uint64_t    pkts;
};


static int
update(pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);

    if (isnew) {
	x->ts = pkt->ts;
        x->byts = 0;
        x->pkts = 0;
    }

    x->byts += H16(IP(len));
    x->pkts++;

    return 0;
}

static ssize_t
store(void *rp, char *buf, size_t len)
{
    FLOWDESC *x = F(rp);

    if (len < sizeof(FLOWDESC)) 
	return -1; 

    PUTH64(buf, x->ts);
    PUTH64(buf, x->byts);
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

    *ts = NTOHLL(((FLOWDESC *)buf)->ts);
    return sizeof(FLOWDESC);
}


#define PRETTYHDR		\
    "Date                     Timestamp          Bytes    Pkts\n"
#define PRETTYFMT	"%.24s %12d.%06d %8llu %8llu\n"
#define PLAINFMT	"%12ld %16llu %12llu %12llu\n"
#define GNUPLOTFMT	"%12ld %12llu %12llu\n"

#define GNUPLOTHDR						\
    "set terminal postscript eps color \"Times-Roman\" 14;"		\
    "set ylabel \"Bytes\" font \"Times-Roman\",16;"			\
    "set xlabel \"Time\" font \"Times-Roman\",16;"			\
    "set grid;"								\
    "set ylabel \"Bytes\";"						\
    "set xlabel \"Time\";"						\
    "set y2label \"Packets\";"						\
    "set y2tics nomirror;"						\
    "set ytics nomirror;"						\
    "set autoscale x;"							\
    "set autoscale y;"							\
    "set xdata time;"							\
    "set timefmt \"%%s\";"						\
    "set format x \"%%H:%%M\";"						\
    "plot \"-\" using 1:2 t \"Bytes\" axis x1y1 smooth csplines lt 1, "	\
    "\"-\" using 1:3 t \"Packets\" axis x1y2 smooth csplines lt 2\n"	\

#define GNUPLOTFOOTER	"e\n"

static char *
print(char *buf, size_t *len, char * const args[])
{
    static char s[512];
    static char * fmt; 
    FLOWDESC *x; 
    timestamp_t ts;
    time_t t; 
    int n; 

    if (buf == NULL && args != NULL) { 
	/* first call of print, process the arguments and return */
	for (n = 0; args[n]; n++) {
	    if (!strcmp(args[n], "format=plain")) {
		*len = 0; 
		fmt = PLAINFMT;
		return s; 
	    } 
	    if (!strcmp(args[n], "format=gnuplot")) {
		*len = sprintf(s, GNUPLOTHDR); 
		fmt = GNUPLOTFMT;
		return s; 
	    } 
	} 

	/* by default, pretty print */
	*len = sprintf(s, PRETTYHDR);  
	fmt = PRETTYFMT; 
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

    /* print according to the requested format */
    if (fmt == PRETTYFMT) {
	*len = sprintf(s, fmt, 
	    asctime(localtime(&t)), TS2SEC(ts), TS2USEC(ts), 
	    NTOHLL(x->byts), NTOHLL(x->pkts));
    } else if (fmt == GNUPLOTFMT) {
	*len = sprintf(s, fmt, (long int)t, NTOHLL(x->byts), NTOHLL(x->pkts));
    } else {
	*len = sprintf(s, fmt, 
			(long int)t, ts, NTOHLL(x->byts), NTOHLL(x->pkts));
    } 
	
    return s;
}

callbacks_t callbacks = {
    sizeof(FLOWDESC),
    0, 
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
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
