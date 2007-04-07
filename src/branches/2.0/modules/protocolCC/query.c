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
 * $Id: protocol.c 1012 2006-11-13 15:04:31Z jsanjuas $
 */

/*
 * Protocol module
 *
 * This module computes the number of packets and bytes per protocol.
 * Output: packets/bytes per protocol over 1s intervals
 *
 */

#include <time.h>
#include "module.h"
#include "data.h"

#define FLOWDESC    struct _proto_stat

enum {
    FORMAT_PLAIN,
    FORMAT_PRETTY,
    FORMAT_GNUPLOT,
};

QUERY_FORMATS_BEGIN
    { FORMAT_PLAIN, "plain", "text/plain" },
    { FORMAT_PRETTY, "pretty", "text/plain" },
    { FORMAT_GNUPLOT, "gnuplot", "text/plain" },
QUERY_FORMATS_END

DEFAULT_FORMAT = "pretty";

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



#define MAX_PROTO 256
typedef struct qstate qstate_t;
struct qstate {
    int granularity;
    int num_proto;
    uint8_t proto[MAX_PROTO];

    int num_records; /* for aggregation */
    record_t aggr;
};

void *
qu_init(mdl_t *self, int format_id, hash_t *args)
{
    static qstate_t st;
    config_t *config = mdl_get_config(self, config_t);
    char *val;

    st.num_proto = 0;
    st.num_records = 0;
    st.granularity = 1;
    bzero(&st.aggr, sizeof(st.aggr));

    /*
     * process the arguments
     */

    /* protocols to include in the result */
    if ((val = hash_lookup_string(args, "include"))) {
        char *n;

        n = strtok(val, ",");
        st.proto[st.num_proto++] = atoi(n);
        while((n = strtok(NULL, ",")))
            if (st.num_proto < MAX_PROTO)
                st.proto[st.num_proto++] = atoi(n);
    }

    /* aggregate multiple records to reduce communication messages. */
    if ((val = hash_lookup_string(args, "granularity")))
        st.granularity = MAX(atoi(val) / config->meas_ivl, 1);

    switch (format_id) {
        case FORMAT_GNUPLOT: {
            int n;
            /* 
             * we need to print the header but make sure that we 
             * include/exclude all protocols. 
             */
            mdl_printf(self, GNUPLOTHDR); 

            mdl_printf(self, "plot \"-\" using 1:%d with filledcurve x1 "
                       "title \"Other\" lw 5",
                       config->num_proto + 2); 

            for (n = config->num_proto - 1; n >= 0; n--) { 
                mdl_printf(self, ",\"-\" using 1:%d with filledcurve x1 "
                           "title \"%s (%d)\" lw 5",
                           n + 2, getprotoname(config->proto[n]), 
                           config->proto[n]); 
            } 

            mdl_print(self, ";\n"); 
        }
    } 

    return &st;
}

void
qu_finish(mdl_t *self, int format_id, qstate_t *state)
{
    if (format_id == FORMAT_GNUPLOT)
        mdl_printf(self, GNUPLOTFOOTER);
}

static void print_pretty(mdl_t *self, qstate_t *state);
static void print_gnuplot(mdl_t *self, qstate_t *state);

void
print_rec(mdl_t *self, int format_id, record_t *r, qstate_t *state)
{
    int i;

    state->aggr.ts = r->ts;

    /* aggregate records if needed */
    for (i = 0; i < IPPROTO_MAX; i++) { 
	state->aggr.bytes[i] += r->bytes[i]; 
	state->aggr.pkts[i] += r->pkts[i]; 
    } 
    state->num_records++;
    if (state->num_records % state->granularity != 0)
        return;

    /* get the average across the aggregated records */
    for (i = 0; i < IPPROTO_MAX; i++) { 
	state->aggr.bytes[i] /= state->granularity;
	state->aggr.pkts[i] /= state->granularity;
    }

    switch (format_id) {
        case FORMAT_PLAIN:
            mdl_printf(self, "%12u.%06u ", (uint) TS2SEC(state->aggr.ts),
                (uint) TS2USEC(state->aggr.ts));
            for (i = 0; i < IPPROTO_MAX; i++) 
                mdl_printf(self, "%3d %8llu %8u ", i, state->aggr.bytes[i],
                        state->aggr.pkts[i]);
            mdl_print(self, "\n");
            break;
        case FORMAT_PRETTY:
            print_pretty(self, state); 
            break;
        case FORMAT_GNUPLOT:
            print_gnuplot(self, state); 
            break;
    }

    bzero(&state->aggr, sizeof(state->aggr));
}

static void
print_pretty(mdl_t *self, qstate_t *state) 
{
    record_t *r = &state->aggr;
    uint64_t bytes_all, pkts_all;
    uint64_t bytes_chosen, pkts_chosen; 
    float bytes_prct, pkts_prct; 
    size_t len; 
    time_t ts; 
    int i;

    ts = (time_t) TS2SEC(state->aggr.ts);
    mdl_printf(self, "%.24s ", asctime(localtime(&ts)));

    /* compute the sums of all bytes and packets */
    bytes_all = pkts_all = 0; 
    for (i = 0; i < IPPROTO_MAX; i++) { 
	bytes_all += r->bytes[i]; 
	pkts_all += r->pkts[i]; 
    } 

    if (bytes_all == 0) 
	return; 

    /* compute the sums of all bytes and packets of interest */
    bytes_chosen = pkts_chosen = 0; 
    for (i = 0; i < state->num_proto; i++) { 
	bytes_prct = 100 * (float) r->bytes[state->proto[i]] / bytes_all; 
	pkts_prct = 100 * (float) r->pkts[state->proto[i]] / pkts_all; 

	mdl_printf(self, "%s %5.2f %5.2f ", getprotoname(state->proto[i]),
                    bytes_prct, pkts_prct); 

	bytes_chosen += r->bytes[state->proto[i]]; 
	pkts_chosen += r->pkts[state->proto[i]]; 
    } 

    bytes_prct = 100 - (100 * (float) bytes_chosen / bytes_all); 
    pkts_prct = 100 - (100 * (float) pkts_chosen / pkts_all); 
    mdl_printf(self, "Other %5.2f %5.2f\n", bytes_prct, pkts_prct); 
}


static void
print_gnuplot(mdl_t *self, qstate_t *state)
{
    record_t *r = &state->aggr;
    uint64_t bytes_all;
    float bytes_sofar; 
    float bytes_prct; 
    size_t len; 
    int i;

    mdl_printf(self, "%u ", (uint) TS2SEC(r->ts)); 

    /* compute the sums of all bytes and packets */
    bytes_all = 0; 
    for (i = 0; i < IPPROTO_MAX; i++) 
	bytes_all += r->bytes[i]; 

    if (bytes_all == 0) 
	return; 

    /* compute the sums of all bytes and packets of interest */
    bytes_sofar = 0; 
    for (i = 0; i < state->num_proto; i++) { 
	bytes_prct = 100 * (float) r->bytes[state->proto[i]] / bytes_all; 
	mdl_printf(self, "%5.2f ", bytes_sofar + bytes_prct); 
	bytes_sofar += bytes_prct; 
    } 

    mdl_printf(self, "100 \n"); 
}

