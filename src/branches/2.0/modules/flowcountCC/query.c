/*
 * Copyright (c) 2006-2007, Intel Corporation
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
 * $Id: flowcount.c 1012 2006-11-13 15:04:31Z jsanjuas $
 */

#include <time.h> /* asctime, localtime */

#include "data.h"
#include "module.h"

#define GNUPLOTHDR                                              \
    "set terminal postscript eps color solid lw 1 \"Helvetica\" 14;"    \
    "set grid;"                                                         \
    "set ylabel \"Active flows\";" 		                        \
    "set xlabel \"Time (HH:MM UTC)\";"                                  \
    "set yrange [0:*];"                                                 \
    "set autoscale xfix;"                                               \
    "set nokey;"                                                        \
    "set xdata time;"                                                   \
    "set timefmt \"%%s\";"                                              \
    "set format x \"%%H:%%M\";"                                         \
    "plot \"-\" using 1:2 with lines lt 3\n" 

#define GNUPLOTFMT      "%u %u\n"

#define GNUPLOTFOOTER   "e\n"

enum {
    FORMAT_PRETTY,
    FORMAT_GNUPLOT,
};

QUERY_FORMATS_BEGIN
    { FORMAT_PRETTY, "pretty", "text/plain" },
    { FORMAT_GNUPLOT, "gnuplot", "text/plain" },
QUERY_FORMATS_END

DEFAULT_FORMAT = "gnuplot";

typedef struct qustate qu_state_t;
struct qustate {
    int granularity;
    int print_count;
    int flow_count;
};

void *
qu_init(mdl_t *self, int format_id, hash_t *args)
{
    config_t *config = mdl_get_config(self, config_t);
    qu_state_t *st = mdl_malloc(self, sizeof(qu_state_t));
    char *val;
    
    st->granularity = 1;
    st->print_count = 0;
    st->flow_count = 0;

    if ((val = hash_lookup_string(args, "granularity")))
        st->granularity = MAX(atoi(val) / config->meas_ivl, 1);

    mdl_printf(self, GNUPLOTHDR);

    return st;
}

void
qu_finish(mdl_t *self, int format_id, void *state)
{
    mdl_print(self, GNUPLOTFOOTER);
}

void
print_rec(mdl_t *self, int format_id, record_t *r, qu_state_t *st)
{
    config_t * config = mdl_get_config(self, config_t);

    st->flow_count += r->count; 

    st->print_count++;
    if (st->print_count % st->granularity != 0)
        return;

    st->flow_count /= st->granularity; 
    switch(format_id) {
        case FORMAT_GNUPLOT:
            mdl_printf(self, GNUPLOTFMT, TS2SEC(r->ts), st->flow_count); 
            break;
        case FORMAT_PRETTY: {
            time_t t = (time_t) TS2SEC(r->ts);

            mdl_printf(self, "%.24s %u\n", asctime(localtime(&t)),
                    st->flow_count); 
        }
    }

    st->flow_count = 0; 
}

