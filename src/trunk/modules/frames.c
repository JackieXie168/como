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
 * 802.11 Frame Breakdown Report
 *
 * The sniffer reports statistics about frame types during the 
 * measurement duration 
 */

#include <stdio.h>
#include <time.h>
#include "module.h"

static int meas_ivl = 1; /* measurement interval */

#define FLOWDESC    struct _frames
FLOWDESC {
    timestamp_t ts;
    uint64_t    mgmtpkts;
    uint64_t    ctrlpkts;
    uint64_t    datapkts;
};


static int
update(pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);

    if (isnew) {
	x->ts = pkt->ts;
        x->mgmtpkts = x->ctrlpkts = x->datapkts = 0;
    }

    switch(WLANTYPE(COMO(l2type))) {
    case WLANTYPE_MGMT:
	x->mgmtpkts++;
        break;
    case WLANTYPE_CTRL:
	x->ctrlpkts++;
	break;
    case WLANTYPE_DATA: 
	x->datapkts++;
	break;
    default:
	break;
    }
   
    return 0;
}

static ssize_t
store(void *rp, char *buf, size_t len)
{
    FLOWDESC *x = F(rp);

    if (len < sizeof(FLOWDESC)) 
	return -1; 

    PUTH64(buf, x->ts);
    PUTH64(buf, x->mgmtpkts);
    PUTH64(buf, x->ctrlpkts);
    PUTH64(buf, x->datapkts);

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
    "Timestamp           Management frames    Control frames       Data frames\n"
#define PRETTYFMT	"%12d.%06d %-20llu %-20llu %-20llu\n"
#define PLAINFMT	"%12ld %16llu %12llu %12llu %12llu\n"
#define GNUPLOTFMT	"%ld %llu %llu %llu\n"

#define GNUPLOTHDR						\
    "set terminal postscript eps color solid lw 1 \"Helvetica\" 14;"	\
    "set grid;"								\
    "set ylabel \"Frame Count\" textcolor lt 3;"			\
    "set xlabel \"Time (HH:MM UTC)\";"					\
    "set yrange [0:*];"							\
    "set autoscale xfix;"						\
    "set key right nobox;"						\
    "set xdata time;"							\
    "set timefmt \"%%s\";"						\
    "set format x \"%%H:%%M\";"						\
    "plot \"-\" using 1:2 with filledcurve x1 title \"MGMT\" lw 5," \
    "     \"-\" using 1:3 with filledcurve x1 title \"CTRL\" lw 5," \
    "     \"-\" using 1:4 with filledcurve x1 title \"DATA\" lw 5;\n"

#define GNUPLOTFOOTER	"e\n"

static char *
print(char *buf, size_t *len, char * const args[])
{
    static char s[512];
    static char * fmt; 
    static int granularity = 1; 
    static int no_records = 0; 
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
	    } 
	    if (!strcmp(args[n], "format=gnuplot")) {
		*len = sprintf(s, GNUPLOTHDR); 
		fmt = GNUPLOTFMT;
	    } 
	    if (!strncmp(args[n], "granularity=", 10)) {
		char * val = index(args[n], '=') + 1;

		/* aggregate multiple records into one to reduce 
		 * communication messages. 
		 */
		granularity = MAX(atoi(val) / meas_ivl, 1);
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
    no_records++;
    
    if(no_records %  granularity != 0) {
	*len = 0;
	return s;
    }
    /* print according to the requested format */
    if (fmt == PRETTYFMT) {
	*len = sprintf(s, fmt, TS2SEC(ts), TS2USEC(ts), NTOHLL(x->mgmtpkts), 
				    NTOHLL(x->ctrlpkts), NTOHLL(x->datapkts)); 
    }
      else if (fmt == GNUPLOTFMT) {
	*len = sprintf(s, fmt, (long int)t, NTOHLL(x->mgmtpkts), 
				    NTOHLL(x->ctrlpkts), NTOHLL(x->datapkts)); 
    } else {
	*len = sprintf(s, fmt, (long int)t, ts, NTOHLL(x->mgmtpkts), 
				    NTOHLL(x->ctrlpkts), NTOHLL(x->datapkts)); 
    } 

    return s;
}

callbacks_t callbacks = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0,
    st_recordsize: 65535,
    indesc: NULL, 
    outdesc: NULL,
    init: NULL,
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
    replay: NULL
};
