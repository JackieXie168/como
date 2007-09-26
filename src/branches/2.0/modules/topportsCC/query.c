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
 * Top-N ports module.
 *
 * This module finds the top N port numbers (source or destination) with the 
 * largest number of bytes sent during a given interval. 
 *
 */

#include <stdio.h>
#include <time.h>
#include <assert.h>
#include "module.h"
#include "data.h"



#define PRETTYHDR	\
    "Date                      Port     Name       Bytes       Packets   \n"

#define PRETTYFMT 	"%.24s %5u/%s %s %10llu %8u\n"

#define PLAINFMT	"%u %u %s %s %llu %u\n"

#define HTMLHDR                                                 \
    "<html>\n"                                                  \
    "<head>\n"                                                  \
    "  <style type=\"text/css\">\n"                             \
    "   body {font-size: 9pt; margin: 0; padding: 0; \n"	\
    "     font-family: \"lucida sans unicode\", verdana, arial;}\n" \
    "   table,tr,td {background-color: #ddd;\n" 	        \
    "     font-size: 9pt; \n"		            		\
    "     font-family: \"lucida sans unicode\", verdana, arial;}\n" \
    "   a, a:visited { color: #475677; text-decoration: none;}\n" \
    "   .netview {\n"                                           \
    "     top: 0px; width: 100%%; vertical-align:top;\n"        \
    "     margin: 2; padding-left: 5px;\n" 			\
    "     padding-right: 5px; text-align:left;}\n" 		\
    "   .nvtitle {\n"                                           \
    "     font-weight: bold; padding-bottom: 3px;\n" 		\
    "     font-family: \"lucida sans unicode\", verdana, arial;\n" \
    "     font-size: 9pt; \n"		            		\
    "     color: #475677;}\n"                                   \
    "  </style>\n"                                              \
    "</head>\n"                                                 \
    "<body>\n"                                                  \

#define HTMLTITLE						\
    "<div class=nvtitle>Top-%d Port Numbers</div>\n" 		\
    "<table class=netview>\n" 					\
    "  <tr class=nvtitle>\n"					\
    "    <td>#</td>\n" 	                			\
    "    <td>Port</td>\n"                 			\
    "    <td>Name</td>\n"                 			\
    "    <td>Mbps</td></tr>\n"

#define SIDEBOXHDR						\
    "<table class=netview>\n" 					\
    "  <tr class=nvtitle>\n"					\
    "    <td>#</td>\n" 	                			\
    "    <td>Port</td>\n"                 			\
    "    <td>Name</td>\n"                 			\
    "    <td>Mbps</td></tr>\n"

#define HTMLFOOTER						\
    "</table>\n"						\
    "</body></html>\n"						

#define HTMLFMT							\
    "<tr><td>%d</td><td>%5u/%s</td><td>%s</td><td>%.2f</td></tr>\n"

enum {
    FORMAT_PLAIN,
    FORMAT_PRETTY,
    FORMAT_HTML,
    FORMAT_SIDEBOX
};

QUERY_FORMATS_BEGIN
    { FORMAT_PLAIN,   "plain",   "text/plain" },
    { FORMAT_PRETTY,  "pretty",  "text/plain" },
    { FORMAT_HTML,    "html",    "text/html"  },
    { FORMAT_SIDEBOX, "sidebox", "text/html"  },
QUERY_FORMATS_END

DEFAULT_FORMAT = "pretty";

static int result_count;

void *
qu_init(mdl_t *self, int format_id, hash_t *args)
{
    switch (format_id) {
        case FORMAT_PRETTY:
            mdl_printf(self, PRETTYHDR);
            break;
        case FORMAT_HTML: {
            config_t *config = mdl_get_config(self, config_t);
            mdl_printf(self, HTMLHDR);
            mdl_printf(self, HTMLTITLE, config->topn);
            break;
        }
        case FORMAT_SIDEBOX:
            mdl_printf(self, HTMLHDR); 
            mdl_printf(self, SIDEBOXHDR); 
            break;
    }

    return &result_count;
}

void
qu_finish(mdl_t *self, int format_id, int *state)
{
    switch(format_id) {
        case FORMAT_HTML:
        case FORMAT_SIDEBOX:
            mdl_printf(self, HTMLFOOTER);
    }
}

void
print_rec(mdl_t *self, int format_id, record_t *rec, int *state)
{
    config_t *config = mdl_get_config(self, config_t);
    char *name;
    time_t ts;

    name = rec->proto == IPPROTO_TCP ? config->tcp_service[rec->port] :
        config->udp_service[rec->port];

    if (name == NULL) 
	name = "Unknown"; 

    ts = TS2SEC(rec->ts);

    switch (format_id) {
        case FORMAT_PRETTY:
            mdl_printf(self, PRETTYFMT, asctime(localtime(&ts)), rec->port,
                    getprotoname(rec->proto), name, rec->bytes, rec->pkts); 
            break;
        case FORMAT_HTML:
        case FORMAT_SIDEBOX:
            mdl_printf(self, HTMLFMT, ++(*state), rec->proto,
                    getprotoname(rec->proto), name, rec->bytes, rec->pkts);
            break;
        case FORMAT_PLAIN:
            mdl_printf(self, PLAINFMT, ts, rec->port, getprotoname(rec->proto),
                    name, rec->bytes, rec->pkts); 
    }
}

