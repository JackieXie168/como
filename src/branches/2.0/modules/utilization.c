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
 * Utilization Module.
 *
 * This module computes the link utilization using the following four metrics:
 *
 *  . bits/sec averaged over 1s intervals;
 *  . high watermark (i.e., max utilization in 100ms interval) over 1s periods;
 *
 */

#include <stdio.h>
#include <time.h>
#include "module.h"


#define FLOWDESC        struct _util_stat
#define EFLOWDESC       struct _eutil_stat

FLOWDESC {
    uint32_t ts;
    uint32_t bytes;
    uint32_t hi_watermark;
    uint32_t bytes_ivl;
    timestamp_t last_watermark;
};

EFLOWDESC {
    uint32_t ts;
    uint32_t bytes;
    uint32_t hi_watermark;
};

#define CONFIGDESC   struct _utilization_config
CONFIGDESC {
    timestamp_t meas_ivl;
    timestamp_t wmark_ivl;
};

static timestamp_t
init(void * self, __unused char **args)
{
    CONFIGDESC * config;
    pkt_t *pkt;
    metadesc_t *inmd;
    
    config = mem_mdl_malloc(self, sizeof(CONFIGDESC));
    config->meas_ivl = TIME2TS(1, 0);
    config->wmark_ivl = TIME2TS(0, 100000);
    
    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = config->wmark_ivl;
    
    pkt = metadesc_tpl_add(inmd, "none:none:none:none");
    
    CONFIG(self) = config; 
    return config->meas_ivl;
}

static int
update(void * self, pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);
    CONFIGDESC * config = CONFIG(self); 

    if (isnew) {
	x->ts = TS2SEC(pkt->ts);
        x->bytes = 0;
        x->bytes_ivl = 0;
        x->hi_watermark = 0;
        x->last_watermark = pkt->ts;
    }

    x->bytes += pkt->len;

    if (pkt->ts - x->last_watermark > config->wmark_ivl) {
        x->last_watermark = pkt->ts;
        x->bytes_ivl = 0;
    }

    x->bytes_ivl += pkt->len; 
    if (x->bytes_ivl > x->hi_watermark)
        x->hi_watermark = x->bytes_ivl;

    return 0;
}

static int
export(__unused void * self, void *efh, void *fh, int isnew)
{
    FLOWDESC * x = F(fh);
    EFLOWDESC * ex = EF(efh);
    
    if (isnew) {
        ex->ts = x->ts;
        ex->bytes = 0;
        ex->hi_watermark = 0;
    }
    
    ex->bytes += x->bytes;
    if (x->hi_watermark > ex->hi_watermark)
        ex->hi_watermark = x->hi_watermark;
    
    return 0;
}

static int
action(void * self, void * fh, __unused timestamp_t ivl,
       timestamp_t t, __unused int count)
{
    EFLOWDESC * ex = EF(fh);
    CONFIGDESC * config = CONFIG(self);
    
    if (fh == NULL) 
        return ACT_GO;
    
    if (t > TIME2TS(ex->ts, 0) + config->meas_ivl)
        return ACT_STORE | ACT_DISCARD;
    
    return ACT_STOP;
}


static ssize_t
store(__unused void * self, void *efh, char *buf)
{
    EFLOWDESC *x = EF(efh);

    PUTH32(buf, x->ts);
    PUTH32(buf, x->bytes);
    PUTH32(buf, x->hi_watermark);
    return sizeof(EFLOWDESC);
}

static size_t
load(__unused void * self, char *buf, size_t len, timestamp_t *ts)
{
    if (len < sizeof(EFLOWDESC)) {
        *ts = 0;
        return 0;
    }

    *ts = TIME2TS(ntohl(*(uint32_t *)buf), 0);
    return sizeof(EFLOWDESC);
}


#define PRETTYFMT  	"%.24s %10u %10u\n"
#define PLAINFMT  	"%12u %10u %10u\n"
#define GNUPLOTFMT      "%u %.2f %.2f\n"

#define PRETTYHDR  	"Date                     Bytes      HighWaterMark\n"

#define GNUPLOTHDR                                                      \
    "set terminal postscript eps color solid lw 1 \"Helvetica\" 14;"    \
    "set grid;"                                                         \
    "set ylabel \"Mbps\";"                                              \
    "set xlabel \"Time\";"                                              \
    "set autoscale ymax;"                                               \
    "set autoscale xfix;"                                               \
    "set xdata time;"                                                   \
    "set timefmt \"%%s\";"                                              \
    "set format x \"%%H:%%M\";"                                         \
    "plot \"-\" using 1:2 with lines lt 3 title \"Avg traffic (1s)\", " \
    "\"-\" using 1:3 with lines lt 4 title \"High Watermark (100ms)\"\n"

#define GNUPLOTFOOTER   "e\n"

static char * 
print(void * self, char *buf, size_t *len, char * const args[])
{
    static char s[2048];
    static char * fmt; 
    static int granularity = 1;
    static int no_records = 0;
    static EFLOWDESC values;
    CONFIGDESC * config = CONFIG(self);
    EFLOWDESC *x; 
    int n;

    if (buf == NULL && args != NULL) { 
	for (n = 0; args[n]; n++) {
            if (!strcmp(args[n], "format=plain")) {
                *len = 0; 
                fmt = PLAINFMT; 
		return s; 
            } else if (!strcmp(args[n], "format=gnuplot")) {
                *len = sprintf(s, GNUPLOTHDR); 
                fmt = GNUPLOTFMT;
                return s; 
            } else if (!strncmp(args[n], "granularity=", 10)) {
                char * val = index(args[n], '=') + 1;

                /* aggregate multiple records into one to reduce 
                 * communication messages. 
                 */
                granularity = MAX(atoi(val)/TS2SEC(config->meas_ivl), 1);
            } 
	} 

	bzero(&values, sizeof(EFLOWDESC));

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

    x = (EFLOWDESC *) buf; 

    /* aggregate records if needed */
    values.ts = ntohl(x->ts);
    values.bytes += ntohl(x->bytes);
    if (ntohl(x->hi_watermark) > values.hi_watermark) 
	values.hi_watermark = ntohl(x->hi_watermark); 

    no_records++;
    if (no_records % granularity != 0) { 
        *len = 0;
        return s; 
    } 

    values.bytes /= granularity; 
    values.hi_watermark *= (config->meas_ivl / config->wmark_ivl); 

    if (fmt == PRETTYFMT) {
	time_t t = (time_t) values.ts;
	*len = sprintf(s, fmt, 
                       (char *) asctime(localtime(&t)), 
		       values.bytes, values.hi_watermark); 
    } else if (fmt == GNUPLOTFMT) { 
	*len = sprintf(s, fmt, values.ts, 
		   (float) values.bytes * 8.0 /1000000, 
		   (float) values.hi_watermark * 8.0 / 1000000);
    } else {
	*len = sprintf(s, fmt, values.ts, values.bytes, values.hi_watermark);
    } 

    bzero(&values, sizeof(EFLOWDESC));
    return s;
}

MODULE(utilization) = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: sizeof(EFLOWDESC),
    st_recordsize: sizeof(EFLOWDESC),
    capabilities: {has_flexible_flush: 0, 0},
    init: init,
    check: NULL,
    hash: NULL,
    match: NULL,
    update: update,
    flush: NULL,
    ematch: NULL,
    export: export,
    compare: NULL,
    action: action,
    store: store,
    load: load,
    print: print,
    replay: NULL,
    formats: "plain gnuplot",
};

