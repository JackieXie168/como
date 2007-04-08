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
 * $Id: query.c 1122 2007-04-07 11:30:50Z jsanjuas $
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
    "    <td>HW Address</td>\n"					\
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
    "    <td>HW Address</td>\n"					\
    "    <td>bps</td>\n"					\
    "    <td>pps</td>\n"					\
    "  </tr>\n"							

enum {
    FORMAT_PRETTY,
    FORMAT_PLAIN,
    FORMAT_HTML,
};

QUERY_FORMATS_BEGIN
    {FORMAT_PRETTY, "pretty", "text/plain"},
    {FORMAT_PLAIN, "plain", "text/plain"},
    {FORMAT_HTML, "html", "text/plain"},
QUERY_FORMATS_END

DEFAULT_FORMAT = "pretty";

static char * what[] = {"Source HW", "Destination HW"}; 

typedef struct qstate qstate_t;
struct qstate {
    time_t current;
    int count;
};

qstate_t *
qu_init(mdl_t * self, int format_id, hash_t * args)
{
    static qstate_t qs;
    qs.current = 0;

    tophwaddr_config_t * config = mdl_get_config(self, tophwaddr_config_t);

    switch(format_id) {
    case FORMAT_PRETTY:
        mdl_printf(self, PRETTYHDR, what[config->use_dst]); 
        break;
    case FORMAT_HTML:
        mdl_print(self, HTMLHDR);
        mdl_printf(self, HTMLTITLE, config->topn, what[config->use_dst]);
    }

    return &qs;
}

void
qu_finish(mdl_t * self, int format_id, void * state)
{
    if (format_id == FORMAT_HTML)
	mdl_print(self, HTMLFOOTER);  
}

void
print_rec(mdl_t * self, int format_id, tophwaddr_record_t *r, qstate_t *state)
{
    static char urlstr[2048] = "#"; 
    static time_t last_ts = 0; 
    tophwaddr_config_t * config =  mdl_get_config(self, tophwaddr_config_t);
    time_t ts;

    ts = (time_t) (r->ts >> 32);
    if (state->current != ts) {
        state->current = ts;
        state->count = 0;
    }

    state->count++;

    switch(format_id) {
    case FORMAT_PRETTY:
	mdl_printf(self, PRETTYFMT, asctime(localtime(&ts)), state->count, 
                    ether_ntoa((struct ether_addr *) &r->addr), r->bytes,
                    r->pkts);
        break;
    case FORMAT_HTML: {
        float bps, pps; 
        char bunit = ' ';
        char punit = ' ';
	char tmp[2048] = "#";
	
        bps = (float) (r->bytes * 8) / (float) config->meas_ivl;
	if (bps > 1000000) {
	    bunit = 'M';
	    bps /= 1000000;
	} else  if (bps > 1000) {
	    bunit = 'K';
	    bps /= 1000;
	}

        pps = (float) r->pkts / (float) config->meas_ivl;
	if (pps > 1000000) {
	    punit = 'M';
	    pps /= 1000000;
	} else if (pps > 1000) {
	    punit = 'K';
	    pps /= 1000;
	}

	/* TODO if (urlstr[0] != '#')
	    sprintf(tmp, urlstr, inet_ntoa(addr));*/
        mdl_printf(self, HTMLFMT, state->count, tmp,
                    ether_ntoa((struct ether_addr *) r->addr), bps, bunit, pps,
                    punit);
        }
        break;
    case FORMAT_PLAIN:
	mdl_printf(self, PLAINFMT, ts, state->count,
                    ether_ntoa((struct ether_addr *) r->addr), r->bytes,
                    r->pkts);
    } 
}


