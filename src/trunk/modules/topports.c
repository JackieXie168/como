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
#include "como.h"
#include "module.h"

#define FLOWDESC	struct _topports

FLOWDESC {
    uint32_t ts;			/* timestamp of first packet */
    uint64_t bytes[65536];		/* bytes per port number */
    uint64_t pkts[65536];		/* pkts per port number */
};

static timestamp_t meas_ivl = TIME2TS(1, 0);	/* interval (secs) */
static int topn = 20;    			/* number of top ports */

static timestamp_t
init(__unused void *mem, __unused size_t msize, char *args[])
{
    int i;
    char *len;
    
    /* 
     * process input arguments 
     */
    for (i = 0; args && args[i]; i++) { 
	if (strstr(args[i], "interval")) {
	    len = index(args[i], '=') + 1; 
	    meas_ivl = TIME2TS(atoi(len), 0); 
	} 
	if (strstr(args[i], "topn")) {
	    len = index(args[i], '=') + 1;
	    topn = atoi(len);
	}
    }

    return meas_ivl; 
}

static int
check(pkt_t *pkt)
{
    return (isTCP || isUDP); 	/* accept only TCP or UDP packets */
}


static int
update(pkt_t *pkt, void *rp, int isnew)
{
    FLOWDESC *x = F(rp);

    if (isnew) {
	bzero(x, sizeof(FLOWDESC)); 
	x->ts = TS2SEC(pkt->ts - pkt->ts % meas_ivl);
    }

    if (isTCP) {
	x->bytes[H16(TCP(src_port))] += H16(IP(len));
	x->bytes[H16(TCP(dst_port))] += H16(IP(len));
	x->pkts[H16(TCP(src_port))]++;
	x->pkts[H16(TCP(dst_port))]++;
    } else { 
	x->bytes[H16(UDP(src_port))] += H16(IP(len));
	x->bytes[H16(UDP(dst_port))] += H16(IP(len));
	x->pkts[H16(UDP(src_port))]++;
	x->pkts[H16(UDP(dst_port))]++;
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
store(void *rp, char *buf, size_t len)
{
    FLOWDESC *x = F(rp);
    int top_ports[65536 + 1];		/* we need one more the max topN */
    int i, j;
    
    if (len < topn * sizeof(struct topports))
        return -1;

    /* go thru the array of bytes to find the topn port 
     * numbers. store them in the top_ports array. 
     */
    bzero(top_ports, sizeof(top_ports));
    for (i = 0; i < 65536; i++) { 
	if (x->bytes[i] == 0)
	    continue;

	for (j = topn - 1; j >= 0; j--) {
	    if (x->bytes[i] < x->bytes[top_ports[j]])
		break;

	    top_ports[j + 1] = top_ports[j];
	    top_ports[j] = i;
	}
    }

    /* 
     * save the first top N entries 
     */
    for (i = 0; i < topn && x->bytes[top_ports[i]] > 0; i++) { 
	PUTH32(buf, x->ts);
	PUTH32(buf, top_ports[i]); 
	PUTH64(buf, x->bytes[top_ports[i]]);
	PUTH64(buf, x->pkts[top_ports[i]]);
    } 

    return i * sizeof(struct topports);
}

static size_t
load(char *buf, size_t len, timestamp_t *ts)
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

#define HTMLHDR							\
    "<html><body>\n"						\
    "<table cellpadding=1>\n"					\
    "  <tr>\n"							\
    "    <td width=200 style=\"border-bottom:1px solid\">\n"	\
    "      <b>Port</b></td>\n"			                \
    "    <td width=150 style=\"border-bottom:1px solid\">\n"	\
    "      <b>Mbps</b></td>\n"					\
    "  </tr>\n"						

#define HTMLFOOTER						\
    "</table>\n"						\
    "</body></html>\n"						

#define HTMLFMT		"<tr><td>%5u</td><td>%.2f</td></tr>\n"

static char *
print(char *buf, size_t *len, char * const args[])
{
    static char s[2048];
    static char * fmt; 
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
                *len = sprintf(s, HTMLHDR); 
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
	float mbps = (float) NTOHLL(x->bytes) * 8 / (float) TS2SEC(meas_ivl);
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
    indesc: NULL, 
    outdesc: NULL, 
    init: init,
    check: check,
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
    replay: NULL
};

