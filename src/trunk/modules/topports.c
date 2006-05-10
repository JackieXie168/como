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
 * Top-N ports module.
 *
 * This module finds the top N port numbers (source or destination) with the 
 * largest number of bytes sent during a given interval. 
 *
 */

#include <stdio.h>
#include <time.h>
#include "module.h"

#define FLOWDESC	struct _topports

FLOWDESC {
    uint32_t ts;			/* timestamp of first packet */
    uint64_t bytes[65536];		/* bytes per port number */
    uint64_t pkts[65536];		/* pkts per port number */
};

#define CONFIGDESC   struct _topports_config
CONFIGDESC {
    uint32_t meas_ivl;		/* interval (secs) */
    int topn;    		/* number of top ports */
};

static timestamp_t
init(void * self, char *args[])
{
    CONFIGDESC *config;
    char *len;
    int i;
    pkt_t *pkt;
    metadesc_t *inmd;
    
    config = mem_mdl_malloc(self, sizeof(CONFIGDESC)); 
    config->meas_ivl = 1;
    config->topn = 20;

    /* 
     * process input arguments 
     */
    for (i = 0; args && args[i]; i++) { 
	if (strstr(args[i], "interval")) {
	    len = index(args[i], '=') + 1; 
	    config->meas_ivl = atoi(len); 
	} 
	if (strstr(args[i], "topn")) {
	    len = index(args[i], '=') + 1;
	    config->topn = atoi(len);
	}
    }
    
    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = TIME2TS(config->meas_ivl, 0);
    
    pkt = metadesc_tpl_add(inmd, "none:none:none:~tcp");
    N16(TCP(src_port)) = 0xffff;
    N16(TCP(dst_port)) = 0xffff;
    
    pkt = metadesc_tpl_add(inmd, "none:none:none:~udp");
    N16(UDP(src_port)) = 0xffff;
    N16(UDP(dst_port)) = 0xffff;

    CONFIG(self) = config; 
    return TIME2TS(config->meas_ivl, 0); 
}


static int
update(void * self, pkt_t *pkt, void *rp, int isnew)
{
    CONFIGDESC * config = CONFIG(self);
    FLOWDESC *x = F(rp);
    uint64_t newbytes = H16(IP(len)); 
    uint32_t newpkts = 1; 

    if (isnew) {
	bzero(x, sizeof(FLOWDESC)); 
	x->ts = TS2SEC(pkt->ts) - (TS2SEC(pkt->ts) % config->meas_ivl);
    }

    if (COMO(type) == COMOTYPE_NF) {
        newbytes = H32(NF(pktcount)) * COMO(len) * H16(NF(sampling));
        newpkts = H32(NF(pktcount)) * (uint32_t) H16(NF(sampling));
    } else if (COMO(type) == COMOTYPE_SFLOW) {
	newbytes = (uint64_t) COMO(len) * (uint64_t) H32(SFLOW(sampling_rate));
	newpkts = H32(SFLOW(sampling_rate));
    } 

    if (isTCP) {
	x->bytes[H16(TCP(src_port))] += newbytes; 
	x->bytes[H16(TCP(dst_port))] += newbytes; 
	x->pkts[H16(TCP(src_port))] += newpkts;
	x->pkts[H16(TCP(dst_port))] += newpkts; 
    } else { 
	x->bytes[H16(UDP(src_port))] += newbytes; 
	x->bytes[H16(UDP(dst_port))] += newbytes;
	x->pkts[H16(UDP(src_port))] += newpkts; 
	x->pkts[H16(UDP(dst_port))] += newpkts; 
    } 

    return 0;
}


struct topports {
    uint32_t ts;		/* timestamp of first packet */
    uint32_t port; 		/* port number */
    uint64_t bytes; 		/* bytes/port number */
    uint64_t pkts;		/* pkts/port number */
};


static ssize_t
store(void * self, void *rp, char *buf)
{
    CONFIGDESC * config = CONFIG(self);
    FLOWDESC *x = F(rp);
    int top_ports[65536 + 1];		/* we need one more than max port */
    int i, j;
    
    /* go thru the array of bytes to find the topn port 
     * numbers. store them in the top_ports array. 
     */
    bzero(top_ports, sizeof(top_ports));
    for (i = 0; i < 65536; i++) { 
	if (x->bytes[i] == 0)
	    continue;

	for (j = config->topn - 1; j >= 0; j--) {
	    if (x->bytes[i] < x->bytes[top_ports[j]])
		break;

	    top_ports[j + 1] = top_ports[j];
	    top_ports[j] = i;
	}
    }

    /* 
     * save the first top N entries 
     */
    for (i = 0; i < config->topn && x->bytes[top_ports[i]] > 0; i++) { 
	PUTH32(buf, x->ts);
	PUTH32(buf, top_ports[i]); 
	PUTH64(buf, x->bytes[top_ports[i]]);
	PUTH64(buf, x->pkts[top_ports[i]]);
    } 

    return i * sizeof(struct topports);
}

static size_t
load(__unused void * self, char *buf, size_t len, timestamp_t *ts)
{
    if (len < sizeof(struct topports)) {
        ts = 0;
        return 0; 
    }

    *ts = TIME2TS(ntohl(((struct topports *)buf)->ts), 0);
    return sizeof(struct topports);
}


#define PRETTYHDR	\
    "Date                     Port  Bytes       Packets   \n"

#define PRETTYFMT 	"%.24s %5u %10llu %10llu\n"

#define PLAINFMT	"%12u %5u %10llu %10llu\n"

#define HTMLHDR                                                 \
    "<html>\n"                                                  \
    "<head>\n"                                                  \
    "  <style type=\"text/css\">\n"                             \
    "   body {font-size: 9pt; margin: 0; padding: 0 \n"		\
    "     font-family: \"lucida sans unicode\", verdana, arial;}\n" \
    "   table,tr,td {background-color: #ddd;\n" 	           \
    "     font-size: 9pt; \n"		            \
    "     font-family: \"lucida sans unicode\", verdana, arial;}\n" \
    "   a, a:visited { color: #475677; text-decoration: none;}\n" \
    "   .netview {\n"                                           \
    "     top: 0px; width: 100%%; vertical-align:top;\n"        \
    "     margin: 2; padding-left: 5px;\n" \
    "     padding-right: 5px; text-align:left;}\n" \
    "   .nvtitle {\n"                                           \
    "     font-weight: bold; padding-bottom: 3px;\n" \
    "     font-family: \"lucida sans unicode\", verdana, arial;\n" \
    "     font-size: 9pt; \n"		            \
    "     color: #475677;}\n"                                   \
    "  </style>\n"                                              \
    "</head>\n"                                                 \
    "<body>\n"                                                  \
    "<div class=nvtitle style=\"border-top: 1px solid;\">"	\
    "Top-%d Port Numbers</div>\n" 		\
    "<table class=netview>\n" 			\
    "  <tr class=nvtitle>\n"					\
    "      <td>Port</td>\n"                 	\
    "      <td width=60>Mbps</td></tr>\n"

#define HTMLFOOTER						\
    "</table>\n"						\
    "</body></html>\n"						

#define HTMLFMT		"<tr><td>%5u</td><td>%.2f</td></tr>\n"

static char *
print(void * self, char *buf, size_t *len, char * const args[])
{
    static char s[2048];
    static char * fmt; 
    CONFIGDESC * config = CONFIG(self);
    struct topports *x; 
    time_t ts;

    if (buf == NULL && args != NULL) { 
	int n; 

        /* by default, pretty print */
        *len = sprintf(s, PRETTYHDR);  
        fmt = PRETTYFMT; 

        /* first call of print, process the arguments and return */
        for (n = 0; args[n]; n++) {
            if (!strcmp(args[n], "format=plain")) {
                *len = 0; 
                fmt = PLAINFMT;
            } 
            if (!strcmp(args[n], "format=html")) {
                *len = sprintf(s, HTMLHDR, config->topn); 
                fmt = HTMLFMT;
            } 
        } 

	return s; 
    } 

    if (buf == NULL && args == NULL) { 
	*len = 0; 
	if (fmt == HTMLFMT) 
	    *len = sprintf(s, HTMLFOOTER);  
  	return s; 
    } 

    x = (struct topports *) buf;
    ts = (time_t) ntohl(x->ts);
    if (fmt == PRETTYFMT) { 
	*len = sprintf(s, fmt, asctime(localtime(&ts)), ntohl(x->port),
		   NTOHLL(x->bytes), NTOHLL(x->pkts));
    } else if (fmt == HTMLFMT) { 
	float mbps = (float) NTOHLL(x->bytes) * 8 / (float) config->meas_ivl;
	mbps /= 1000000;
	*len = sprintf(s, fmt, ntohl(x->port), mbps); 
    } else { 
	*len = sprintf(s, fmt, ts, ntohl(x->port), 
		   NTOHLL(x->bytes), NTOHLL(x->pkts));
    } 
	
    return s;
};


callbacks_t callbacks = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0, 
    st_recordsize: sizeof(FLOWDESC),
    init: init,
    check: NULL,
    hash: NULL,
    match: NULL,
    update: update,
    ematch: NULL,
    export: NULL,
    compare: NULL,
    action: NULL,
    store: store,
    load: load,
    print: print,
    replay: NULL,
    formats: "plain pretty html"
};

