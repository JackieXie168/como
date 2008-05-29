/*
 * Copyright (c) 2004-2008, Intel Corporation
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
 * $Id: query.c 1228 2008-02-01 11:38:16Z jsanjuas $
 */

#include <time.h>

#include "data.h"

enum {
    FORMAT_PLAIN,
    FORMAT_PRETTY,
    FORMAT_GNUPLOT,
};

QUERY_FORMATS_BEGIN
    { FORMAT_PLAIN,   "plain",   "text/plain" },
    { FORMAT_PRETTY,  "pretty",  "text/plain" },
    { FORMAT_GNUPLOT, "gnuplot", "text/plain" },
QUERY_FORMATS_END

struct qstate {
    uint64_t aggr_pkts[CLASSES_MAX];
    uint64_t aggr_bytes[CLASSES_MAX];
    uint64_t ts;
    int record_count;
    int granularity;
    int meas_ivl;
    int relative;
    int classes;
};
typedef struct qstate qstate_t;


#define GNUPLOTHDR                                                      \
    "set terminal postscript eps color solid lw 1 \"Helvetica\" 14;\n"  \
    "set grid;\n"                                                       \
    "set ylabel \"%s\";\n"                                              \
    "set xlabel \"Time (H:M UTC)\";\n"                                  \
    "set yrange [0:%s];\n"                                              \
    "set autoscale xfix;\n"                                             \
    "set key outside;\n"                                                \
    "set xdata time;\n"                                                 \
    "set timefmt \"%%s\";\n"                                            \
    "set format x \"%%H:%%M\";\n"                                       \
    "plot \"-\" using 1:%d with filledcurve x1 title \"%s\" lw 5\n"

#define GNUPLOTLINE                                                     \
    ",\"-\" using 1:%d with filledcurve x1 title \"%s\" lw 5"   

#define GNUPLOTFOOTER "e\n"


qstate_t *
qu_init(mdl_t *self, int format_id, hash_t *args)
{
    qstate_t *s = mdl_malloc(self, sizeof(qstate_t));
    config_t *config = mdl_get_config(self, config_t);
    char *val;
    int n;

    bzero(s, sizeof(qstate_t));
    s->granularity = 1;
    s->meas_ivl = config->meas_ivl;
    s->classes = config->classes;

    if ((val = hash_lookup_string(args, "granularity")))
        s->granularity = MAX(1, atoi(val) / config->meas_ivl);
    if ((val = hash_lookup_string(args, "relative")))
        s->relative = atoi(val);

    if (format_id == FORMAT_GNUPLOT) {
        int i;

        if (s->relative)
            mdl_printf(self, GNUPLOTHDR, "Percentage", "100", 2,
                    config->names[0]);
        else
            mdl_printf(self, GNUPLOTHDR, "Mbps", "*", 2, config->names[0]);

        for (i = 1; i < config->classes; i++)
            mdl_printf(self, GNUPLOTLINE, 2 * (i + 1), config->names[i]);
        
        mdl_printf(self, "\n");
    }

    return s;
}

void
qu_finish(mdl_t *self, int format_id, qstate_t *s)
{
    if (format_id == FORMAT_GNUPLOT)
        mdl_printf(self, GNUPLOTFOOTER);
}


void
print_rec(mdl_t *self, int format_id, record_t *rec, qstate_t *s)
{
    char *t_str;
    time_t t;
    int i;

    /* aggregate records */
    if (s->record_count % s->granularity == 0) {
        s->ts = rec->ts;
        memset(s->aggr_pkts, 0, sizeof(s->aggr_pkts));
        memset(s->aggr_bytes, 0, sizeof(s->aggr_bytes));
    }
    
    for (i = 0; i < s->classes; i++) {
        s->aggr_pkts[i] += rec->pkts[i];
        s->aggr_bytes[i] += rec->bytes[i];
    }

    s->record_count++;
    if (s->record_count % s->granularity != 0)
        return; /* next record still belongs to aggregation interval */

    /* normalize to pkts and bytes per second */
    for (i = 0; i < s->classes; i++)
        s->aggr_pkts[i] /= s->meas_ivl * s->granularity;

    /* print */
    t = (time_t) TS2SEC(s->ts);
    t_str = asctime(localtime(&t));

    if (format_id == FORMAT_PLAIN) {
        mdl_printf(self, "%12llu", (uint) t);
        for (i = 0; i < s->classes; i++)
            mdl_printf(self, " %8llu %8u", s->aggr_bytes[i], s->aggr_pkts[i]);
        mdl_printf(self, "\n");
    }
    else if (format_id == FORMAT_PRETTY) {

        mdl_printf(self, "%.24s", asctime(localtime(&t)));

        for (i = 0; i < s->classes; i++)
            mdl_printf(self, " %8llu %8u", s->aggr_bytes[i], s->aggr_pkts[i]);

        mdl_printf(self, "\n");
    }
    else if (format_id == FORMAT_GNUPLOT && s->relative) {
        double total_bytes, total_pkts, b, p;
        time_t t;

        for (i = 0; i < s->classes; i++) {
            total_pkts += s->aggr_pkts[i];
            total_bytes += s->aggr_bytes[i];
        }

        t = (time_t) TS2SEC(s->ts);
        mdl_printf(self, "%u", (uint) t);

        for (i = 0; i < s->classes - 1; i++) {
            b = total_bytes == 0 ? 0 : ((double)s->aggr_bytes[i]) / total_bytes;
            p = total_pkts == 0 ? 0 : ((double)s->aggr_pkts[i]) / total_pkts;

            b *= 100;
            p *= 100;

            mdl_printf(self, " %.2f %.2f", b, p);
        }

        if (total_pkts == 0)
            b = p = 0;
        else
            b = p = 100;

        mdl_printf(self, " %.2f %.2f\n", b, p);
    }
    else if (format_id == FORMAT_GNUPLOT) {
        double mbps = 0;
        uint32_t pkts = 0;

        mdl_printf(self, "%u", (uint) t); /* print the ts */

        for (i = 0; i < s->classes; i++) {
            mbps += ((double) s->aggr_bytes[i]) * 8.0 / 1000000.0;
            pkts += s->aggr_pkts[i];
            mdl_printf(self, " %.2f %u", mbps, pkts);
        }
        mdl_printf(self, "\n");
    }
}

