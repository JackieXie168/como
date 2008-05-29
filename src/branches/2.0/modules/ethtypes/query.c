/*
 * Copyright (c) 2004-2007, Intel Corporation
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
 * Ethtypes module
 *
 * This module computes the number of packets and bytes per ethtype.
 * Output: packets/bytes per ethtype over measurement interval
 *
 */

#include <stdio.h>
#include <time.h>
#include <ctype.h>

#include "module.h"
#include "data.h"

enum {
    FORMAT_PLAIN,
    FORMAT_PRETTY,
    FORMAT_GNUPLOT,
    FORMAT_HTML
};

QUERY_FORMATS_BEGIN 
    { FORMAT_PLAIN,   "plain",   "text/plain" },
    { FORMAT_PRETTY,  "pretty",  "text/plain" },
    { FORMAT_GNUPLOT, "gnuplot", "text/plain" },
    { FORMAT_HTML,    "html",    "text/html" },
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

#define HTML_HEADER \
    "<html>\n"                                                              \
    "<head>\n"                                                              \
    "  <style type=\"text/css\">\n"                                         \
    "   body { font-family: \"lucida sans unicode\", verdana, arial;\n"     \
    "          font-size: 9pt; margin: 0; padding: 0;}\n"                   \
    "   table, tr, td {background-color: #DDD;\n"                           \
    "     font-family: \"lucida sans unicode\", verdana, arial;\n"          \
    "     font-size: 9pt;}\n"                                               \
    "   a, a:visited { color: #475677; text-decoration: none;}\n"           \
    "   .netviewbar{ \n"                                                    \
    "     color :#FFF; width :100%%; padding :2px; text-align:center;}\n"   \
    "   .netview {\n"                                                       \
    "     top: 0px; width: 100%%; vertical-align:top;\n"                    \
    "     margin: 2; padding-left: 5px;\n"                                  \
    "     padding-right: 5px; text-align:left;}\n"                          \
    "   .nvtitle {\n"                                                       \
    "     font-weight: bold; font-size: 9pt; padding-bottom: 3px;\n"        \
    "     color: #475677;}\n"                                               \
    "  </style>\n"                                                          \
    "</head>\n"                                                             \
    "<body>\n"                                                              \
    "<table>\n"                                                             \

#define HTML_FOOTER \
    "</table>\n" \
    "</body>\n"  \
    "</html>\n"  \

typedef struct qstate qstate_t;
struct qstate {
    int granularity;
    int no_records;
    timestamp_t ts; /* aggregated data */
    uint64_t bytes[MAX_TYPES];
    uint32_t pkts[MAX_TYPES];

    mdl_t *self; /* having these here makes life easier */
    uint32_t count;
};

qstate_t *
qu_init(mdl_t *self, int format_id, hash_t *args)
{
    qstate_t *s = mdl_malloc(self, sizeof(qstate_t));
    config_t *config = mdl_get_config(self, config_t);
    char *val;
    int n;

    s->self = self;
    s->granularity = 1;

    if ((val = hash_lookup_string(args, "granularity")))
        s->granularity = MAX(1, atoi(val) / config->meas_ivl);

    switch(format_id) {
        case FORMAT_GNUPLOT:
            /* 
             * we need to print the header but make sure that we 
             * include/exclude all protocols. 
             */
            mdl_printf(self, GNUPLOTHDR);

            mdl_printf(self,
                    "plot \"-\" using 1:%d with filledcurve x1 "
                    "title \"Other\" lw 5",
                    config->types_count + 1);
            for (n = config->types_count - 2; n >= 0; n--) {
                mdl_printf(self,
                        ",\"-\" using 1:%d with filledcurve x1 "
                        "title \"%s (%d)\" lw 5",
                        n + 2, config->name[n], config->code[n]);
            }

            mdl_printf(self, ";\n"); 
            break;
        case FORMAT_PRETTY:
            mdl_printf(self, "Timestamp               ");
            for (n = 0; n < config->types_count; n++) {
                mdl_printf(self, " %s Bytes [%%] Pkts [%%]", config->name[n]);
            }
            mdl_printf(self, "\n"); 
            break;

        case FORMAT_HTML:
            mdl_printf(self, HTML_HEADER "<tr class=nvtitle><td>date</td>");
            for (n = 0; n < config->types_count; n++) {
                mdl_printf(self, "<td>%s - bytes [%%]</td>"
                            "<td>%s - pkts [%%]</td>",
                            config->name[n], config->name[n]);
            }
            mdl_printf(self, "</tr>\n");
            break;
    }

    return s;
}

void
qu_finish(mdl_t *self, int format_id, qstate_t *s)
{
    if (format_id == FORMAT_GNUPLOT)
        mdl_printf(self, GNUPLOTFOOTER);
}

static void print_plain(qstate_t *s, config_t *config);
static void print_pretty(qstate_t *s, config_t *config);
static void print_gnuplot(qstate_t *s, config_t *config);
static void print_html(qstate_t *s, config_t *config);

void
print_rec(mdl_t *self, int format_id, record_t *rec, qstate_t *s)
{
    config_t *config;
    uint32_t i;

    s->count = rec->count;

    /* aggregate records if needed */
    if (s->no_records % s->granularity == 0) {
        s->ts = rec->ts;
        bzero(s->bytes, sizeof(s->bytes));
        bzero(s->pkts, sizeof(s->pkts));
    }

    for (i = 0; i < rec->count; i++) { 
	s->bytes[i] += rec->entry[i].bytes; 
	s->pkts[i] += rec->entry[i].pkts;
    }

    s->no_records++;

    /* if need more aggregation, stop here */
    if (s->no_records % s->granularity != 0)
        return;

    /* going to print, normalize */
    for (i = 0; i < rec->count; i++) {
        s->bytes[i] /= s->granularity;
        s->pkts[i] /= s->granularity;
    }

    config = mdl_get_config(self, config_t);

    switch(format_id) {
        case FORMAT_PLAIN:
            print_plain(s, config);
            break;
        case FORMAT_PRETTY:
            print_pretty(s, config);
            break;
        case FORMAT_GNUPLOT:
            print_gnuplot(s, config);
            break;
        case FORMAT_HTML:
            print_html(s, config);
            break;
    }

    s->ts = 0;
    for (i = 0; i < rec->count; i++)
        s->bytes[i] = s->pkts[i] = 0;
}


static void
print_plain(qstate_t * qs, config_t * config) 
{
    size_t len; 
    uint32_t i;

    mdl_printf(qs->self, "%12u.%06u ", 
		  (uint) TS2SEC(qs->ts), 
		  (uint) TS2USEC(qs->ts));
    for (i = 0; i < qs->count; i++) 
	mdl_printf(qs->self, "0x%04x %8llu %8u ", 
		       config->code[i],
		       qs->bytes[i],
		       qs->pkts[i]);
    mdl_printf(qs->self, "\n"); 
}
	
static void
print_pretty(qstate_t * qs, config_t * config) 
{
    time_t ts; 
    size_t len; 
    uint64_t bytes_all, pkts_all;
    float bytes_prct, pkts_prct; 
    uint32_t i;

    ts = (time_t) TS2SEC(qs->ts);
    mdl_printf(qs->self, "%.24s ", asctime(localtime(&ts)));

    /* compute the sums of all bytes and packets */
    bytes_all = pkts_all = 0; 
    for (i = 0; i < qs->count; i++) { 
	bytes_all += qs->bytes[i];
	pkts_all += qs->pkts[i];
    } 

    if (bytes_all == 0)
	return; 

    /* compute the sums of all bytes and packets of interest */
    for (i = 0; i < qs->count; i++) { 
	bytes_prct = 100.0 * (float) qs->bytes[i] / bytes_all;
	pkts_prct = 100.0 * (float) qs->pkts[i] / pkts_all;
	mdl_printf(qs->self, "        %5.2f %5.2f ",
		       bytes_prct, pkts_prct);
    }

    mdl_printf(qs->self, "\n");
}

static void
print_html(qstate_t * qs, config_t * config) 
{
    time_t ts; 
    size_t len; 
    uint64_t bytes_all, pkts_all;
    float bytes_prct, pkts_prct; 
    uint32_t i;

    ts = (time_t) TS2SEC(qs->ts);
    mdl_printf(qs->self, "<tr><td>%s</td>", asctime(localtime(&ts)));

    /* compute the sums of all bytes and packets */
    bytes_all = pkts_all = 0; 
    for (i = 0; i < qs->count; i++) { 
	bytes_all += qs->bytes[i];
	pkts_all += qs->pkts[i];
    } 

    if (bytes_all == 0)
	return; 

    /* compute the sums of all bytes and packets of interest */
    for (i = 0; i < qs->count; i++) { 
	bytes_prct = 100.0 * (float) qs->bytes[i] / bytes_all;
	pkts_prct = 100.0 * (float) qs->pkts[i] / pkts_all;
	mdl_printf(qs->self, "<td>%.2f</td><td>%.2f</td>",
		       bytes_prct, pkts_prct);
    }

    mdl_printf(qs->self, "</tr>\n");
}

static void
print_gnuplot(qstate_t * qs, config_t * config) 
{
    size_t len; 
    uint64_t bytes_all;
    float bytes_sofar; 
    float bytes_prct; 
    uint32_t i;

    mdl_printf(qs->self, "%u ", (uint32_t) TS2SEC(qs->ts)); 

    /* compute the sums of all bytes and packets */
    bytes_all = 0; 
    for (i = 0; i < qs->count; i++) 
	bytes_all += qs->bytes[i];

    if (bytes_all == 0) 
	return; 

    /* compute the sums of all bytes and packets of interest */
    bytes_sofar = 0; 
    for (i = 0; i < qs->count; i++) { 
	bytes_prct = 100 * (float) qs->bytes[i] / bytes_all;
	mdl_printf(qs->self, "%5.2f ", bytes_sofar + bytes_prct); 
	bytes_sofar += bytes_prct; 
    } 

    mdl_printf(qs->self, "\n");
}


