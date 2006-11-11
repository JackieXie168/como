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
 * $Id: traffic.c 978 2006-11-01 15:23:18Z m_canini $
 */

/*
 * Traffic Load 
 *
 * Compute input/output pkt/byte count on the monitored link.
 * Whether it tracks packets or bytes can be decided at configuration time. 
 *
 */

#include <stdio.h>
#include <time.h>
#include "module.h"
#include "data.h"


#define FLOWDESC    struct _counter
FLOWDESC {
    timestamp_t ts;
    uint64_t    bytes[2];
    uint32_t    pkts[2];
};

typedef struct {
    int meas_ivl;	/* measurement interval */
    int iface;		/* interface */
} config_t;

static timestamp_t 
init(void * self, char *args[])
{
    config_t * config; 
    int i;
    pkt_t *pkt;
    metadesc_t *inmd;

    config = mem_mdl_malloc(self, sizeof(config_t)); 
    config->meas_ivl = 1;
    config->iface = -1; 

    for (i = 0; args && args[i]; i++) {
	char * wh;

	wh = index(args[i], '=') + 1;
        if (strstr(args[i], "interval")) {
            config->meas_ivl = atoi(wh);
        } else if (strstr(args[i], "interface")) {
            config->iface = atoi(wh);
	} 
    }
    
    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = TIME2TS(config->meas_ivl, 0);
    
    pkt = metadesc_tpl_add(inmd, "none:none:none:none");
    
    CONFIG(self) = config;
    return TIME2TS(config->meas_ivl, 0);
}


static int
update(void * self, pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);
    config_t * cf = CONFIG(self);

    if (isnew) {
	bzero(x, sizeof(FLOWDESC));
	x->ts = COMO(ts);
    }

    if (COMO(type) == COMOTYPE_NF) {
	if (cf->iface == -1 || H16(NF(input)) == cf->iface) {
	    x->bytes[0] += H32(NF(pktcount)) * COMO(len) * H16(NF(sampling));
	    x->pkts[0] += H32(NF(pktcount)) * (uint32_t) H16(NF(sampling));
	} else if (H16(NF(output)) == cf->iface) { 
	    x->bytes[1] += H32(NF(pktcount)) * COMO(len) * H16(NF(sampling));
	    x->pkts[1] += H32(NF(pktcount)) * (uint32_t) H16(NF(sampling));
	} 
    } else if (COMO(type) == COMOTYPE_SFLOW) {
	x->bytes[0] += (uint64_t) COMO(len) * 
		      (uint64_t) H32(SFLOW(sampling_rate));
	x->pkts[0] += H32(SFLOW(sampling_rate));
    } else {
	x->bytes[0] += COMO(len);
        x->pkts[0]++;
    }

    return 0;
}


static ssize_t
store(void * self, void *rp, char *buf)
{
    FLOWDESC *x = F(rp);
    config_t * cf = CONFIG(self);

    PUTH64(buf, x->ts);
    PUTH64(buf, x->bytes[0]/cf->meas_ivl);
    PUTH64(buf, x->bytes[1]/cf->meas_ivl);
    PUTH32(buf, x->pkts[0]/cf->meas_ivl);
    PUTH32(buf, x->pkts[1]/cf->meas_ivl);

    return sizeof(FLOWDESC);
}


static size_t
load(void * self, char * buf, size_t len, timestamp_t * ts)
{
    if (len < sizeof(FLOWDESC)) {
        *ts = 0;
        return 0;
    }

    *ts = NTOHLL(((FLOWDESC *)buf)->ts);
    return sizeof(FLOWDESC);
}


#define PRETTYHDR		\
    "Date                     Timestamp          Input      Output\n"

#define PRETTYFMT	"%.24s %12d.%06d %8llu %8u\n"
#define PLAINFMT	"%12ld %16llu %12llu %12u\n"

#define GNUPLOTFMT 	"%ld %u %u\n"

#define GNUPLOTHDR						\
    "set terminal postscript eps color solid lw 1 \"Helvetica\" 14;"	\
    "set grid;"								\
    "set ylabel \"%s\" textcolor lt 3;"					\
    "set xlabel \"Time (HH:MM UTC)\";"					\
    "set yrange [0:*];"							\
    "set autoscale xfix;"						\
    "set nokey;"							\
    "set xdata time;"							\
    "set timefmt \"%%s\";"						\
    "set format x \"%%H:%%M\";"						\
    "plot \"-\" using 1:2 with filledcurve x1 lw 4, "			\
    "     \"-\" using 1:3 with filledcurve x1 lw 5\n"

#define GNUPLOTFOOTER	"e\n"

static char *
print(void * self, char *buf, size_t *len, char * const args[])
{
    static char s[512];
    static char * fmt; 
    static int granularity = 1; 
    static int use_bytes = 0; 
    static int no_records = 0; 
    static int64_t count[2] = {0, 0};
    config_t * cf = CONFIG(self); 
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
		fmt = GNUPLOTFMT;
	    } else if (!strcmp(args[n], "use-bytes")) { 
		use_bytes = 1;
	    } else if (!strncmp(args[n], "granularity=", 10)) {
		char * val = index(args[n], '=') + 1;

		/* aggregate multiple records into one to reduce 
		 * communication messages. 
		 */
		granularity = MAX(atoi(val) / cf->meas_ivl, 1);
	    }
	} 

	if (fmt == GNUPLOTFMT) { 
	    *len = sprintf(s, GNUPLOTHDR, use_bytes? "Mbps" : "packets/sec"); 
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
    count[0] += use_bytes? NTOHLL(x->bytes[0]) : ntohl(x->pkts[0]);
    count[1] -= use_bytes? NTOHLL(x->bytes[1]) : ntohl(x->pkts[1]);
    no_records++;
    if (no_records % granularity != 0) { 
	*len = 0;
	return s; 
    } 

    count[0] /= granularity; 
    count[1] /= granularity;

    /* print according to the requested format */
    if (fmt == PRETTYFMT) {  
	*len = sprintf(s, fmt, asctime(localtime(&t)), 
		       TS2SEC(ts), TS2USEC(ts), count[0], count[1]);
    } else if (fmt == GNUPLOTFMT) {  
	if (use_bytes) { 
	    float mbps_in = 8.0 * (float) count[0] / 1000000.0; 
	    float mbps_out = 8.0 * (float) count[1] / 1000000.0; 
	    *len = sprintf(s, "%ld %f %f\n", (long int) t, mbps_in, mbps_out);
	} else { 
	    *len = sprintf(s, "%ld %u %u\n", (long int) t, 
			   (uint32_t) count[0], (uint32_t) count[1]);
	} 
    } else { 
	*len = sprintf(s, fmt, (long int)t, ts, count[0], count[1]); 
    }
	
    count[0] = count[1] = 0; 
    return s;
}

