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

#include "como.h"
#include "data.h"

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

enum {
    FORMAT_PRETTY,
    FORMAT_PLAIN,
    FORMAT_MBPS,
    FORMAT_GNUPLOT
};

QUERY_FORMATS_BEGIN
    {FORMAT_PRETTY, "pretty", "text/plain"},
    {FORMAT_PLAIN, "plain", "text/plain"},
    {FORMAT_MBPS, "mbps", "text/plain"},
    {FORMAT_GNUPLOT, "gnuplot", "text/plain"},
QUERY_FORMATS_END

static void
counter_rec_aggregate(tuple_t * agg, tuple_t * rec, mdl_t * self)
{
    agg->pkts += rec->pkts;
    agg->bytes += rec->bytes;
}

static void
counter_rec_normalize(tuple_t * agg, int granularity, mdl_t * self)
{
    agg->bytes /= granularity; 
    agg->pkts /= granularity;
}

void *
qu_init(mdl_t * self, qures_t * qr, int format_id, hash_t * args)
{
    int granularity = 1;
    char *val;
    
    switch (format_id) {
    case FORMAT_GNUPLOT:
	qures_print(qr, GNUPLOTHDR);
	break;
    case FORMAT_PRETTY:
	qures_print(qr, PRETTYHDR);
	break;
    }
    
    val = hash_lookup_string(args, "granularity");
    if (val != NULL) {
	    /* aggregate multiple records into one to reduce 
	     * communication messages. 
	     */
	    granularity = MAX(atoi(val) / TIME2SEC(self->flush_ivl, 1);
    }
    
    if (granularity != 1) {
	qures_enable_aggregation(qr, granularity,
				    counter_rec_aggregate,
				    counter_rec_normalize);
    }

    return NULL;
}

void
qu_finish(mdl_t * self, qures_t * qr, int format_id, void * ctx)
{
    if (format_id == FORMAT_GNUPLOT) {
	qures_print(qr, GNUPLOTFMT);
    }
}

void
print(mdl_t * self, qures_t * qr, int format_id, tuple_t * r, void * ctx)
{
    float mbps;
    time_t t;
    
    switch (format_id) {
    case FORMAT_PRETTY:
	t = (time_t) TS2SEC(r->ts);
	qures_printf(qr, PRETTYFMT, 
	            asctime(localtime(&t)), TS2SEC(r->ts), TS2USEC(r->ts), 
		    r->bytes, r->pkts); 
	break;
    case FORMAT_PLAIN:
	qures_printf(qr, PLAINFMT, mbps, r->pkts);
	break;
    case FORMAT_GNUPLOT:
	mbps = 8.0 * (float) bytes / 1000000.0; 
	qures_printf(qr, GNUPLOTFMT, TS2SEC(r->ts), mbps, r->pkts);
	break;
    case FORMAT_MBPS:
	mbps = 8.0 * (float) bytes / 1000000.0; 
	qures_printf(qr, MBPSFMT, TS2SEC(r->ts), r->ts, r->bytes, r->pkts);
	break;
    }
}

