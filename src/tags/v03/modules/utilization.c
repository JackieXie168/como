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
#include "como.h"
#include "module.h"

#define WATERMARK_IVL   TIME2TS(0, 100000)     /* watermark ivl */
#define FLUSH_IVL       TIME2TS(1, 0)

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

static pktdesc_t reqs;

static int
init(__unused void *mem, __unused size_t msize, __unused char **args)
{
    bzero(&reqs, sizeof(pktdesc_t));
    reqs.ts = WATERMARK_IVL;
    N16(reqs.ih.len) = 0xffff;
    return 0;
}

static int
update(pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);

    if (isnew) {
	x->ts = TS2SEC(pkt->ts);
        x->bytes = 0;
        x->bytes_ivl = 0;
        x->hi_watermark = 0;
        x->last_watermark = pkt->ts;
    }

    x->bytes += H16(IP(len));

    if (pkt->ts - x->last_watermark > WATERMARK_IVL) {
        x->last_watermark = pkt->ts;
        x->bytes_ivl = 0;
    }

    x->bytes_ivl += H16(IP(len));
    if (x->bytes_ivl > x->hi_watermark)
        x->hi_watermark = x->bytes_ivl;

    return 0;
}

static int
export(void *efh, void *fh, int isnew)
{
    EFLOWDESC *ex = EF(efh);
    FLOWDESC *x = F(fh);
    
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
action(void * fh, timestamp_t t, __unused int count)
{
    EFLOWDESC *ex = EF(fh);
    
    if (fh == NULL) 
        return ACT_GO;
    
    if (t > TIME2TS(ex->ts, 0) + FLUSH_IVL)
        return ACT_STORE | ACT_DISCARD;
    
    return ACT_STOP;
}


static ssize_t
store(void *efh, char *buf, size_t len)
{
    EFLOWDESC *x = EF(efh);

    if (len < sizeof(EFLOWDESC))
        return -1;
    
    PUTH32(buf, x->ts);
    PUTH32(buf, x->bytes);
    PUTH32(buf, x->hi_watermark);
    return sizeof(EFLOWDESC);
}

static size_t
load(char *buf, size_t len, timestamp_t *ts)
{
    if (len < sizeof(EFLOWDESC)) {
        ts = 0;
        return 0;
    }

    *ts = TIME2TS(ntohl(*(uint32_t *)buf), 0);
    return sizeof(EFLOWDESC);
}


#define PRETTYFMT  	"%.24s %10u %10u\n"
#define PLAINFMT  	"%12ld %10u %10u\n"
#define GNUPLOTFMT      "%ld %u %u\n"

#define PRETTYHDR  	"Date                     Bytes      HighWaterMark\n"

#define GNUPLOTHDR                                              \
    "set terminal postscript eps color \"Times-Roman\" 14;"             \
    "set ylabel \"Mbps\" font \"Times-Roman\",16;"                      \
    "set xlabel \"Time\" font \"Times-Roman\",16;"                      \
    "set grid;"                                                         \
    "set ylabel \"Mbps\";"                                              \
    "set xlabel \"Time\";"                                              \
    "set autoscale x;"                                                  \
    "set autoscale y;"                                                  \
    "set xdata time;"                                                   \
    "set timefmt \"%%s\";"                                              \
    "set format x \"%%H:%%M\";"                                         \
    "plot \"-\" using 1:2 t \"Average\" w lines lt 1," 			\
    "\"-\" using 1:3 t \"Max 100ms\" w lines lt 2\n"    		\

#define GNUPLOTFOOTER   "e\n"

static char * 
print(char *buf, size_t *len, char * const args[])
{
    static char s[2048];
    static char * fmt; 
    EFLOWDESC *x; 
    time_t ts; 
    int ratio; 
    int n;

    if (buf == NULL && args != NULL) { 
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
    ts = (time_t) ntohl(x->ts);
    ratio = TIME2TS(1,0) / WATERMARK_IVL; 

    if (fmt == PRETTYFMT) { 
	*len = sprintf(s, fmt, 
		   (char *) asctime(localtime(&ts)), (uint) ntohl(x->bytes), 
		   (uint) ntohl(x->hi_watermark) * ratio);
    } else if (fmt == GNUPLOTFMT) { 
	*len = sprintf(s, fmt, 
		   (long int) ts, (uint) ntohl(x->bytes)*8/1024/1024, 
		   (uint) ntohl(x->hi_watermark) * ratio * 8 / 1024 / 1024);
    } else {
	*len = sprintf(s, fmt, 
		   (long int) ts, (uint) ntohl(x->bytes), 
		   (uint) ntohl(x->hi_watermark) * ratio);
    } 
    return s;
}

callbacks_t callbacks = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: sizeof(EFLOWDESC),
    indesc: &reqs,
    outdesc: NULL,
    init: init,
    check: NULL,
    hash: NULL,
    match: NULL,
    update: update,
    ematch: NULL,
    export: export,
    compare: NULL,
    action: action,
    store: store,
    load: load,
    print: print,
    replay: NULL
};

