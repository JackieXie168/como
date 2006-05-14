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
 * 802.11 frame statistics report 
 *
 */

#include <stdio.h>
#include <time.h>
#include "module.h"


#define FLOWDESC    struct _frames
FLOWDESC {
    timestamp_t ts;

    uint64_t    mgmtpkts;
    uint64_t    ctrlpkts;
    uint64_t    datapkts;

    uint64_t    mgmtbytes;
    uint64_t    ctrlbytes;
    uint64_t    databytes;
};

static timestamp_t
init(void * self, __unused char *args[])
{
    pkt_t *pkt;
    metadesc_t *inmd;
    
    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = TIME2TS(1, 0);
    
    pkt = metadesc_tpl_add(inmd, "radio:802.11:none:none");
    
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = TIME2TS(1, 0);
    
    pkt = metadesc_tpl_add(inmd, "none:802.11:none:none");
    
    return TIME2TS(1, 0);
}

static int
update(__unused void * self, pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);

    if (isnew) {
	x->ts = pkt->ts;
        x->mgmtpkts = x->ctrlpkts = x->datapkts = 0;
        x->mgmtbytes = x->ctrlbytes = x->databytes = 0;
    }
    
    switch(IEEE80211_BASE(fc_type)) {
    case IEEE80211TYPE_MGMT:
	x->mgmtpkts++;
        x->mgmtbytes += COMO(len);
        break;
    case IEEE80211TYPE_CTRL:
	x->ctrlpkts++;
        x->ctrlbytes += COMO(len);
	break;
    case IEEE80211TYPE_DATA: 
	x->datapkts++;
        x->databytes += COMO(len);
	break;
    default:
	break;
    }
   
    return 0;
}

static ssize_t
store(__unused void * self, void *rp, char *buf)
{
    FLOWDESC *x = F(rp);

    PUTH64(buf, x->ts);
    PUTH64(buf, x->mgmtpkts);
    PUTH64(buf, x->ctrlpkts);
    PUTH64(buf, x->datapkts);

    PUTH64(buf, x->mgmtbytes);
    PUTH64(buf, x->ctrlbytes);
    PUTH64(buf, x->databytes);

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


#define PRETTYHDR			\
    "date                       "	\
    "timestamp         "		\
    "mgmt (frames, bytes)       "	\
    "ctrl (frames, bytes)       "	\
    "data (frames, bytes)\n"

#define GNUPLOTFMT  "%ld %llu %llu %llu %llu %llu %llu %llu %llu %llu\n"
#define PRETTYFMT 		\
    "%.24s %12d.%06d %-5llu %-20llu %-5llu %-20llu %-5llu %-20llu\n"

#define GNUPLOTHDR						\
    "set terminal postscript eps color solid lw 1 \"Helvetica\" 14;"	\
    "set grid;"                                                         \
    "set ylabel \"Bytes per Second\";"	        	                \
    "set xlabel \"Time (HH:MM UTC)\";"					\
    "set yrange [0:*];"							\
    "set autoscale xfix;"						\
    "set key right nobox;"						\
    "set xdata time;"							\
    "set timefmt \"%%s\";"						\
    "set format x \"%%H:%%M\";"						\
    "plot \"-\" using 1:3 with filledcurve x1 title \"MGMT\" lw 5," \
    "     \"-\" using 1:5 with filledcurve x1 title \"CTRL\" lw 5," \
    "     \"-\" using 1:7 with filledcurve x1 title \"DATA\" lw 5;\n"

#define GNUPLOTFOOTER	"e\n"

static char *
print(__unused void * self, char *buf, size_t *len, char * const args[])
{
    static char s[512];
    static char * fmt; 
    static int granularity = 1; 
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
	    if (!strcmp(args[n], "format=gnuplot")) {
                *len = sprintf(s, GNUPLOTHDR);
                fmt = GNUPLOTFMT;
            } else if (!strncmp(args[n], "granularity=", 10)) {
                char * val = index(args[n], '=') + 1;

                /* aggregate multiple records into one to reduce
                 * communication messages.
                 */
                granularity = MAX(atoi(val), 1);
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

    /* print according to the requested format */
    if (fmt == PRETTYFMT) {
	*len = sprintf(s, fmt, asctime(localtime(&t)), TS2SEC(ts), TS2USEC(ts),
		NTOHLL(x->mgmtpkts), NTOHLL(x->mgmtbytes), NTOHLL(x->ctrlpkts),
		NTOHLL(x->ctrlbytes), NTOHLL(x->datapkts), 
		NTOHLL(x->databytes)); 
    } else if (fmt == GNUPLOTFMT) {
	*len = sprintf(s, fmt, (long int)t, NTOHLL(x->mgmtpkts), 
		NTOHLL(x->ctrlpkts), NTOHLL(x->datapkts), NTOHLL(x->mgmtbytes), 
		NTOHLL(x->ctrlbytes), NTOHLL(x->databytes)); 
    } 

    return s;
}

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
    formats: "pretty gnuplot",
};
