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
 * 5-tuple flow classifier
 *
 * This module computes 5-tuple flows. Every capture period it 
 * stores the 5-tuple that have been active (together with the 
 * bytes they have sent).  
 *
 */

#include <stdio.h>
#include <time.h>
#include "module.h"
#include "data.h"

enum {
    FORMAT_PRETTY,
    FORMAT_PLAIN,
    FORMAT_HTML,
};

QUERY_FORMATS_BEGIN
    { FORMAT_PRETTY, "pretty", "text/plain" },
    { FORMAT_PLAIN, "plain", "text/plain" },
    { FORMAT_HTML, "html", "text/html" },
QUERY_FORMATS_END

DEFAULT_FORMAT = "pretty";


#define PLAINFMT       "%10u.%06d %3d.%06d %3d %15s %5u %15s %5u %8llu %8llu\n"

#define PRETTYHDR       					\
    "Start                         "				\
    "Duration     "						\
    "Proto Source IP:Port      Destination IP:Port   " 		\
    "Bytes    Packets\n"

#define PRETTYFMT       "%s.%06d %3d.%06d %5s %15s %5u %15s %5u %8llu %8llu\n"

#define HTMLHDR                                                 \
    "<html>\n"                                                  \
    "<head>\n"                                                  \
    "  <style type=\"text/css\">\n"                             \
    "   body { font-family: \"lucida sans unicode\", verdana, arial;\n" \
    "          font-size: 9pt; margin: 0; padding: 0;}\n"       \
    "   table, tr, td {background-color: #eee;\n"               \
    "     font-family: \"lucida sans unicode\", verdana, arial;\n" \
    "     font-size: 9pt;}\n"                           \
    "   a, a:visited { color: #475677; text-decoration: none;}\n" \
    "   .netviewbar{ \n"                                        \
    "     color :#FFF; width :100%%; padding :2px; text-align:center;}\n" \
    "   .netview {\n"                                           \
    "     top: 0px; width: 98%%; vertical-align:top;\n"        \
    "     margin: 2; padding-left: 5px;\n" \
    "     padding-right: 5px; text-align:left;}\n" \
    "   .nvtitle {\n"                                           \
    "     font-weight: bold; font-size: 9pt; padding-bottom: 3px;\n" \
    "     color: #475677;}\n"                                   \
    "  </style>\n"                                              \
    "</head>\n"                                                 \
    "<body>\n"                                                  \
    "<div class=nvtitle style=\"border-top: 1px solid;\">"      \
    "Active connections</div>\n" \
    "<table class=netview>\n"                                   \
    "  <tr class=nvtitle>\n"					\
    "    <td>Start Time</td>\n"               			\
    "    <td>Duration</td>\n"               			\
    "    <td>Protocol</td>\n"                 			\
    "    <td>Source IP:Port</td>\n"                 		\
    "    <td>Destination IP:Port</td>\n"                 	\
    "    <td>Bytes</td>\n"                 			\
    "    <td>Packets</td>\n"                 			\
    "  </tr>\n"		

#define HTMLFOOTER                                              \
    "</table>\n"                                                \
    "</body></html>\n"

#define HTMLFMT                                                 \
    "<tr><td>%s.%06d</td><td>%d.%06d</td><td>%s</td>"		\
    "<td>%15s:%u</td><td>%15s:%u</td>" 				\
    "<td>%llu</td><td>%llu</td></tr>\n"


void *
qu_init(mdl_t *self, int format_id, hash_t *args)
{
    switch(format_id) {
        case FORMAT_HTML:
            mdl_printf(self, HTMLHDR);
            break;
        case FORMAT_PRETTY:
            mdl_printf(self, PRETTYHDR);
            break;
    }

    return NULL;
}

void
qu_finish(mdl_t *self, int format_id, void *state)
{
    if (format_id == FORMAT_HTML)
        mdl_printf(self, HTMLFOOTER);
}


void
print_rec(mdl_t *self, int format_id, record_t *rec, void *state)
{
    config_t *config = mdl_get_config(self, config_t);
    char src[20], dst[20]; 
    struct in_addr saddr, daddr;
    uint start_sec, start_usec; 
    uint duration_sec, duration_usec; 

    start_sec = TS2SEC(rec->start_ts); 
    start_usec = TS2USEC(rec->start_ts);
    duration_sec = TS2SEC(rec->last_ts - rec->start_ts); 
    duration_usec = TS2USEC(rec->last_ts - rec->start_ts); 

    /* get IP addresses */
    saddr.s_addr = rec->src_ip & htonl(config->mask);
    daddr.s_addr = rec->dst_ip & htonl(config->mask);
    sprintf(src, "%s", inet_ntoa(saddr));
    sprintf(dst, "%s", inet_ntoa(daddr)); 

    switch (format_id) {
        case FORMAT_PLAIN:
            mdl_printf(self, PLAINFMT, start_sec, start_usec, 
		    duration_sec, duration_usec, rec->proto, 
		    src, (uint) ntohs(rec->src_port), 
		    dst, (uint) ntohs(rec->dst_port), 
		    rec->bytes * rec->sampling, 
		    rec->pkts * rec->sampling);
            break;

        case FORMAT_HTML: /* fallthrough */

        case FORMAT_PRETTY: {
            char datestr[30]; 
            char *fmt;
            struct tm * timeptr; 
            time_t t = (time_t) start_sec;

            if (format_id == FORMAT_PRETTY)
                fmt = PRETTYFMT;
            else
                fmt = HTMLFMT;

            timeptr = gmtime(&t); 
            strftime(datestr, sizeof(datestr), "%b %e %Y %T", timeptr);

            mdl_printf(self, fmt, 
		    datestr, start_usec, duration_sec, duration_usec, 
		    getprotoname(rec->proto), 
		    src, (uint) ntohs(rec->src_port), 
		    dst, (uint) ntohs(rec->dst_port), 
		    rec->bytes * rec->sampling, 
		    rec->pkts * rec->sampling);
        }
    } 
}

void
replay(mdl_t *self, record_t *r, void *state)
{
    unsigned int i;
    timestamp_t pkt_ts, inter_ts; 
    uint32_t pkt_duration;
    uint64_t nbytes, npkts; 
    int pktsz, paysz, pleft;

    nbytes = r->bytes;
    npkts = r->pkts;

    /* initialize packet left count */
    pleft = npkts;
    
    /* fill the output buffer */
    #define paysz \
        (sizeof(struct _como_nf)        \
         + sizeof(struct _como_iphdr)   \
         + sizeof(struct _como_udphdr)  \
         + sizeof(pkt_t))

    while (pleft > 0) {
	pkt_t * pkt;
	uint32_t plen;
 	int pcount; 
        char out[paysz];

	pkt = (pkt_t *) out;
	pkt->payload = (char *) pkt + sizeof(pkt_t);

#ifdef BUILD_FOR_ARM
	COMOX(caplen, paysz);
	COMOX(type, COMOTYPE_NF);
	COMOX(l2type, LINKTYPE_NONE);
	COMOX(l3type, ETHERTYPE_IP);
	COMOX(l3ofs, sizeof(struct _como_nf)); 
	COMOX(l4type, x->proto); 
	COMOX(l4ofs, COMO(l3ofs) + sizeof(struct _como_iphdr));
	COMOX(l7ofs, COMO(l4ofs) + sizeof(struct _como_udphdr));

	NFX(sampling, x->sampling);
	IPX(version, 0x4);
	IPX(ihl, 0x5);
        IPX(proto, x->proto);
	IPX(len, htons((uint16_t) COMO(len))); 
        IPX(src_ip, x->src_ip);
        IPX(dst_ip, x->dst_ip);
        
        UDP(src_port, x->src_port);
        UDP(dst_port, x->dst_port);
#else
	COMO(len) = COMO(caplen) = paysz - sizeof(pkt_t);
	COMO(type) = COMOTYPE_NF;
	COMO(l2type) = LINKTYPE_NONE;
	COMO(l3type) = ETHERTYPE_IP;
	COMO(l3ofs) = sizeof(struct _como_nf); 
	COMO(l4type) = r->proto; 
	COMO(l4ofs) = COMO(l3ofs) + sizeof(struct _como_iphdr);
	COMO(l7ofs) = COMO(l4ofs) + sizeof(struct _como_udphdr);

	N16(NF(sampling)) = htons(r->sampling);

	IP(version) = 0x4;
	IP(ihl) = 0x5;
        IP(proto) = r->proto;
	N16(IP(len)) = htons((uint16_t) COMO(len)); 
        N32(IP(src_ip)) = r->src_ip;
        N32(IP(dst_ip)) = r->dst_ip;

        N16(UDP(src_port)) = r->src_port;
        N16(UDP(dst_port)) = r->dst_port;
#endif

	pcount = 1; 
	plen = nbytes / npkts; 
	if (pleft == 1) 
	     plen += nbytes % npkts; 

        #if 0 /* XXX what is compact mode? */
	if (config->compact && pleft != 1) {
 	    /* 
	     * in compact mode we need to make sure we generate a number 
	     * of packets with the correct size taking into account that 
	     * the first packet will always weigh more (i.e. NF(pktcount)). 
	     * therefore we need n packets with size bytes/pkts and 1 last 
 	     * packet with size "bytes/pkts + bytes%pkts" to carry the 
	     * leftovers.
	     * 
	     */
	    pcount = pleft; 
	    if (nbytes % npkts != 0) 
		pcount--; 
	}
        #endif

	inter_ts = r->last_ts - r->start_ts; 
	inter_ts /= (uint64_t) npkts;
	pkt_ts = r->start_ts + (npkts - pleft) * inter_ts; 
	pkt_duration = TS2SEC(inter_ts * (pcount - 1)) * 1000 + 
		       TS2MSEC(inter_ts * (pcount - 1)); 

#ifdef BUILD_FOR_ARM
	COMOX(ts, pkt_ts);
	COMOX(len, plen);
	NFX(pktcount, htonl(pcount));
	NFX(duration, htonl(pduration));
#else
	COMO(ts) = pkt_ts;
	COMO(len) = plen; 
	N32(NF(pktcount)) = htonl(pcount);
	N32(NF(duration)) = htonl(pkt_duration);
#endif

        mdl_write(self, out, paysz);
	pleft -= pcount;
    }

    #undef paysz
}

