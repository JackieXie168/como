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
 * Top-N port pairs module.
 *
 * This module computes the top-N port pairs with more bytes transmitted
 * between them.
 *
 */

#include <stdio.h>
#include <time.h>
#include "como.h"
#include "module.h"

#define TOPN        20		/* top-20 port pairs by default */
#define GRANULARITY  5		/* default measurement granularity (secs) */

#define FLOWDESC	struct _topports
#define EFLOWDESC	FLOWDESC

FLOWDESC {
    uint32_t ts;	/* timestamp of first packet */
    n16_t sport;        /* source port number */
    n16_t dport;        /* destination port number */
    uint64_t bytes;	/* number of bytes */
    uint64_t pkts;	/* number of packets */
};

/* 
 * static variable for the modules. 
 * XXX we should get rid of these to force callbacks to be closures. 
 */
static unsigned int granularity = GRANULARITY;   /* measurement
                                                  * granularity (secs) */
static int topn = TOPN;    /* number of top port pairs */

static timestamp_t
init(__unused void *mem, __unused size_t msize, char *args[])
{
    int i;
    char *len;
    
    granularity = GRANULARITY;  
    topn = TOPN;    

    /* 
     * process input arguments 
     */
    for (i = 0; args && args[i]; i++) { 
	if (strstr(args[i], "granularity")) {
	    len = index(args[i], '=') + 1; 
	    granularity = atoi(len); 
	} 
	if (strstr(args[i], "topn")) {
	    len = index(args[i], '=') + 1;
	    topn = atoi(len);
	}
    }

    return TIME2TS(granularity, 0);
}

static int
check(pkt_t *pkt)
{
    /* accept only TCP or UDP packets */
    return (isTCP || isUDP);
}

static uint32_t
hash(pkt_t *pkt)
{
    /* hash by source port */
    if (IP(proto) == IPPROTO_TCP)
	return N16(TCP(src_port));
    else /* UDP */
	return N16(UDP(src_port));
}

static int
match(pkt_t *pkt, void *fh)
{
    FLOWDESC *x = F(fh);
    
    /* match by destination port */
    if (IP(proto) == IPPROTO_TCP)
        return (N16(TCP(dst_port)) == N16(x->dport));
    else /* UDP */
        return (N16(UDP(dst_port)) == N16(x->dport));
}

static int
update(pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);

    if (isnew) {
	x->ts = TS2SEC(pkt->ts) - (TS2SEC(pkt->ts) % granularity);
        if (IP(proto) == IPPROTO_TCP) {
            x->sport = TCP(src_port);
            x->dport = TCP(dst_port);
        } else /* UDP */ {
            x->sport = UDP(src_port);
            x->dport = UDP(dst_port);
        }
        x->bytes = 0;
        x->pkts = 0;
    }

    x->bytes += H16(IP(len));
    x->pkts++;

    return 0;
}

static int
ematch(void *efh, void *fh)
{
    FLOWDESC *x = F(fh);
    EFLOWDESC *ex = EF(efh);

    return (N16(x->dport) == N16(ex->dport));
}

static int
export(void *efh, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);
    EFLOWDESC *ex = EF(efh);

    if (isnew) {
	ex->ts = x->ts; 
        ex->sport = x->sport;
        ex->dport = x->dport;
        ex->bytes = 0;
        ex->pkts = 0;
    }

    ex->bytes += x->bytes;
    ex->pkts += x->pkts;

    return 0;
}

static int
compare(const void *efh1, const void *efh2)
{
    EFLOWDESC *ex1 = CMPEF(efh1);
    EFLOWDESC *ex2 = CMPEF(efh2);

    return ((ex1->bytes > ex2->bytes)? -1 : 1);
}

static int
action(void *efh, timestamp_t current_time, int count)
{
    static uint32_t last_export = 0; 

    if (efh == NULL) { 
	/* 
	 * this is the action for the entire table. 
	 * check if it is time to export the table. 
	 * if not stop. 
	 */
	uint32_t ivl = TS2SEC(current_time) -
                       TS2SEC(current_time) % granularity;
	if (ivl - last_export < granularity) 
	    return ACT_STOP;		/* too early */

	last_export = ivl; 
	return ACT_GO; 		/* dump the records */
    }

    return (count < topn)? ACT_STORE|ACT_DISCARD : ACT_DISCARD; 
}

static ssize_t
store(void *efh, char *buf, size_t len)
{
    EFLOWDESC *ex = EF(efh);
    
    if (len < sizeof(EFLOWDESC))
        return -1;

    PUTH32(buf, ex->ts);
    PUTN16(buf, N16(ex->sport));
    PUTN16(buf, N16(ex->dport));
    PUTH64(buf, ex->bytes);
    PUTH64(buf, ex->pkts);

    return sizeof(EFLOWDESC);
}

static size_t
load(char *buf, size_t len, timestamp_t *ts)
{
    if (len < sizeof(EFLOWDESC)) {
        ts = 0;
        return 0; 
    }

    *ts = TIME2TS(ntohl(((EFLOWDESC *)buf)->ts), 0);
    return sizeof(EFLOWDESC);
}


#define PRETTYHDR	\
    "Date                     Sport Dport       Bytes       Packets   \n"

#define PRETTYFMT 	"%.24s %5u %5u %10llu %10llu\n"

#define PLAINFMT	"%12u %5u %5u %10llu %10llu\n"

#define HTMLHDR							\
    "<html><body>\n"						\
    "<table cellpadding=1>\n"					\
    "  <tr>\n"							\
    "    <td width=200 style=\"border-bottom:1px solid\">\n"	\
    "      <b>Sport</b></td>\n"			                \
    "    <td width=200 style=\"border-bottom:1px solid\">\n"	\
    "      <b>Dport</b></td>\n"			                \
    "    <td width=150 style=\"border-bottom:1px solid\">\n"	\
    "      <b>Bytes</b></td>\n"					\
    "    <td width=150 style=\"border-bottom:1px solid\">\n"	\
    "      <b>Packets</b></td>\n"				\
    "  </tr>\n"						

#define HTMLFOOTER						\
    "</table>\n"						\
    "</body></html>\n"						

#define HTMLFMT		"<tr><td>%5u</td><td>%5u</td><td>%10llu</td>" \
                        "<td>%10llu</td></tr>\n"

static char *
print(char *buf, size_t *len, char * const args[])
{
    static char s[2048];
    static char * fmt; 
    EFLOWDESC *x; 
    uint16_t sport, dport;
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

    x = (EFLOWDESC *) buf;
    ts = (time_t) ntohl(x->ts);
    sport = H16(x->sport);
    dport = H16(x->dport);
    if (fmt == PRETTYFMT) { 
	*len = sprintf(s, fmt, asctime(localtime(&ts)), sport, dport,
		   NTOHLL(x->bytes), NTOHLL(x->pkts));
    } else if (fmt == HTMLFMT) { 
	*len = sprintf(s, fmt, sport, dport,
		   NTOHLL(x->bytes), NTOHLL(x->pkts));
    } else { 
	*len = sprintf(s, fmt, ts, sport, dport,
		   NTOHLL(x->bytes), NTOHLL(x->pkts));
    } 
	
    return s;
};


callbacks_t callbacks = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: sizeof(EFLOWDESC),
    st_recordsize: sizeof(EFLOWDESC),
    indesc: NULL, 
    outdesc: NULL, 
    init: init,
    check: check,
    hash: hash,
    match: match,
    update: update,
    ematch: ematch,
    export: export,
    compare: compare,
    action: action,
    store: store,
    load: load,
    print: print,
    replay: NULL
};

