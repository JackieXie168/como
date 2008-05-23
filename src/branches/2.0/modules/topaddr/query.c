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
 * This module ranks addresses in terms of bytes.
 * The IP addresses can be destination or sources. 
 */

#include <time.h>
#include "data.h"
#include "module.h"

#define PRETTYHDR	\
    "Date                     rank  %-15s Bytes      Packets   \n"

#define PRETTYFMT 	"%.24s %4d %15s %10llu %8u\n"

#define PLAINFMT	"%12u %d %15s %10llu %8u\n"

#define HTMLHDR							\
    "<html>\n"							\
    "<head>\n"                                                  \
    "  <style type=\"text/css\">\n"                             \
    "   body { font-family: \"lucida sans unicode\", verdana, arial;\n" \
    "          font-size: 9pt; margin: 0; padding: 0;}\n"	\
    "   table, tr, td {background-color: #DDD;\n"		\
    "     font-family: \"lucida sans unicode\", verdana, arial;\n" \
    "     font-size: 9pt;}\n"				\
    "   a, a:visited { color: #475677; text-decoration: none;}\n" \
    "   .netviewbar{ \n"                                        \
    "     color :#FFF; width :100%%; padding :2px; text-align:center;}\n" \
    "   .netview {\n"                                           \
    "     top: 0px; width: 100%%; vertical-align:top;\n"        \
    "     margin: 2; padding-left: 5px;\n" \
    "     padding-right: 5px; text-align:left;}\n" \
    "   .nvtitle {\n"                                           \
    "     font-weight: bold; font-size: 9pt; padding-bottom: 3px;\n" \
    "     color: #475677;}\n"                                   \
    "  </style>\n"                                              \
    "</head>\n"                                                 \
    "<body>\n"							

#define HTMLTITLE 						\
    "<div class=nvtitle style=\"border-top: 1px solid;\">"	\
    "Top-%d %s</div>\n" \
    "<table class=netview>\n"					\
    "  <tr class=nvtitle>\n"					\
    "    <td>#</td>\n" 	                			\
    "    <td>IP Address</td>\n"					\
    "    <td>bps</td>\n"					\
    "    <td>pps</td>\n"					\
    "  </tr>\n"							

#define HTMLFOOTER						\
    "</table>\n"						\
    "</body></html>\n"						

#define HTMLFMT							\
    "<tr><td>%d</td><td><a href=%s target=_new>%15s</a></td>"	\
    "<td>%.2f%c</td><td>%.2f%c</td></tr>\n"

#define SIDEBOXTITLE 						\
    "<table class=netview>\n"					\
    "  <tr class=nvtitle>\n"					\
    "    <td>#</td>\n"						\
    "    <td>IP Address</td>\n"					\
    "    <td>bps</td>\n"					\
    "    <td>pps</td>\n"					\
    "  </tr>\n"							

enum {
    FORMAT_PRETTY,
    FORMAT_PLAIN,
    FORMAT_HTML,
    FORMAT_SIDEBOX,
};

QUERY_FORMATS_BEGIN
    {FORMAT_PRETTY, "pretty", "text/plain"},
    {FORMAT_PLAIN, "plain", "text/plain"},
    {FORMAT_HTML, "html", "text/html"},
    {FORMAT_SIDEBOX, "sidebox", "text/html"},
QUERY_FORMATS_END

DEFAULT_FORMAT = "pretty";

static char * what[] = {"Source IP", "Destination IP"}; 

typedef struct qstate qstate_t;
struct qstate {
    time_t current;
    int count;
    uint32_t query_ivl;
};

qstate_t *
qu_init(mdl_t * self, int format_id, hash_t * args)
{
    static qstate_t qs;
    char *val;
    qs.current = 0;

    topaddr_config_t * config = mdl_get_config(self, topaddr_config_t);

    switch(format_id) {
    case FORMAT_PRETTY:
        mdl_printf(self, PRETTYHDR, what[config->use_dst]); 
        break;
    case FORMAT_SIDEBOX:
    case FORMAT_HTML:
        mdl_print(self, HTMLHDR);
        mdl_printf(self, HTMLTITLE, config->topn, what[config->use_dst]);
    }

    /*
     * in single_ivl mode, we need the query ivl in order to
     * know how to scale to bps / pps
     */
    if ((val = hash_lookup_string(args, "query_ivl")))
        qs.query_ivl = atoi(val);

    return &qs;
}

void
qu_finish(mdl_t * self, int format_id, void * state)
{
    if (format_id == FORMAT_HTML || format_id == FORMAT_SIDEBOX)
	mdl_print(self, HTMLFOOTER);  
}

void
print_rec(mdl_t * self, int format_id, topaddr_record_t *r, qstate_t *state)
{
    static char urlstr[2048] = "#"; 
    static time_t last_ts = 0; 
    topaddr_config_t * config =  mdl_get_config(self, topaddr_config_t);
    struct in_addr addr;
    time_t ts;

    ts = (time_t) (r->ts >> 32);
    if (state->current != ts && ! config->single_ivl) {
        state->current = ts;
        state->count = 0;
    }

    state->count++;
    addr.s_addr = r->addr & htonl(config->mask);

    switch(format_id) {
    case FORMAT_PRETTY:
	mdl_printf(self, PRETTYFMT, asctime(localtime(&ts)), state->count, 
                    inet_ntoa(addr), r->bytes, r->pkts);
        break;
    case FORMAT_SIDEBOX:
    case FORMAT_HTML: {
        float bps, pps; 
        char bunit = ' ';
        char punit = ' ';
	char tmp[2048] = "#";
        float ivl = config->single_ivl ? state->query_ivl : config->meas_ivl;

        bps = (float) (r->bytes * 8) / ivl;
	if (bps > 1000000) {
	    bunit = 'M';
	    bps /= 1000000;
	} else  if (bps > 1000) {
	    bunit = 'K';
	    bps /= 1000;
	}

        pps = (float) r->pkts / ivl;
	if (pps > 1000000) {
	    punit = 'M';
	    pps /= 1000000;
	} else if (pps > 1000) {
	    punit = 'K';
	    pps /= 1000;
	}

	/* TODO if (urlstr[0] != '#')
	    sprintf(tmp, urlstr, inet_ntoa(addr));*/
        mdl_printf(self, HTMLFMT, state->count, tmp, inet_ntoa(addr), bps,
                    bunit, pps, punit);
        }
        break;
    case FORMAT_PLAIN:
	mdl_printf(self, PLAINFMT, ts, state->count, inet_ntoa(addr), 
		   r->bytes, r->pkts);
    } 
}


