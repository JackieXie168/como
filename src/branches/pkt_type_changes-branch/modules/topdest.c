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
 * Top-N destinations Module.
 *
 * This module computes the top-N IP destination addresses
 *
 */

#include <stdio.h>
#include <time.h>
#include "module.h"

#define FLOWDESC	struct _ca_topdest
#define EFLOWDESC	FLOWDESC

FLOWDESC {
    uint32_t ts;	/* timestamp of last packet */
    uint32_t dst_ip;	/* destination IP address */
    uint64_t bytes;	/* number of bytes */
    uint32_t pkts;	/* number of packets */
};

static uint32_t meas_ivl = 5;  		  /* interval (secs) */
static int topn = 20;                     /* number of top destinations */
static uint32_t mask = 0xffffffff;        /* prefix mask */

static timestamp_t
init(__unused void *mem, __unused size_t msize, char *args[])
{
    int i;
    char *len;
    
    /* 
     * process input arguments 
     */
    for (i = 0; args && args[i]; i++) { 
	if (!strncmp(args[i], "interval", 8)) {
	    len = index(args[i], '=') + 1; 
	    meas_ivl = atoi(len); 
	} else if (!strncmp(args[i], "topn", 4)) {
	    len = index(args[i], '=') + 1;
	    topn = atoi(len);
	} else if (!strncmp(args[i], "mask", 4)) {
	    len = index(args[i], '=') + 1;
	    mask <<= atoi(len); 
	}
    }

    return TIME2TS(meas_ivl, 0);
}

static int
check(pkt_t * pkt)
{ 
    /*
     * if the stream contains per-flow information,
     * drop all packets after the first.
     */
    if ((COMO(type) == COMOTYPE_NF) && !(NF(flags) & COMONF_FIRST))
        return 0;

    return 1;
}


static uint32_t
hash(pkt_t *pkt)
{
    return (H32(IP(dst_ip)));
}

static int
match(pkt_t *pkt, void *fh)
{
    FLOWDESC *x = F(fh);
    return (H32(IP(dst_ip)) == x->dst_ip);
}

static int
update(pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);

    if (isnew) {
	x->ts = TS2SEC(pkt->ts) - (TS2SEC(pkt->ts) % meas_ivl);
        x->dst_ip = H32(IP(dst_ip)); 
        x->bytes = 0;
        x->pkts = 0;
    }

    if (COMO(type) == COMOTYPE_NF) { 
	x->bytes += H64(NF(bytecount)) * (uint64_t) H16(NF(sampling)); 
	x->pkts += H32(NF(pktcount)) * H16(NF(sampling)); 
    } else { 
	x->bytes += H16(IP(len));
	x->pkts++;
    } 

    return 0;
}

static int
ematch(void *efh, void *fh)
{
    FLOWDESC *x = F(fh);
    EFLOWDESC *ex = EF(efh);

    return (x->dst_ip == ex->dst_ip);
}

static int
export(void *efh, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);
    EFLOWDESC *ex = EF(efh);

    if (isnew) {
	ex->ts = x->ts; 
        ex->dst_ip = x->dst_ip;
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
        uint32_t now = TS2SEC(current_time);
	uint32_t ivl = now - now %meas_ivl; 
	if (ivl - last_export < meas_ivl) 
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
    PUTH32(buf, ex->dst_ip);
    PUTH64(buf, ex->bytes);
    PUTH32(buf, ex->pkts);

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
    "Date                     Destination IP  Bytes      Packets   \n"

#define PRETTYFMT 	"%.24s %15s %10llu %8u\n"

#define PLAINFMT	"%12u %15s %10llu %8u\n"

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
    "<body>\n"							\
    "<div class=nvtitle style=\"border-top: 1px solid;\">"	\
    "Top-%d Destinations</div>\n" \
    "<table class=netview>\n"					\
    "  <tr class=nvtitle><td>IP Address</td>\n"			\
    "      <td>Mbps</td></tr>\n"						

#define HTMLFOOTER						\
    "</table>\n"						\
    "</body></html>\n"						

#define HTMLFMT							\
    "<tr><td><a href=%s target=_new>%15s</a></td><td>%.2f</td></tr>\n"

static char *
print(char *buf, size_t *len, char * const args[])
{
    static char s[2048];
    static char * fmt; 
    static char urlstr[2048] = "#"; 
    EFLOWDESC *x; 
    struct in_addr addr;
    time_t ts;

    if (buf == NULL && args != NULL) { 
	char * url = NULL;
	char * urlargs[20];
	int no_urlargs = 0;
	int n; 

        /* by default, pretty print */
        *len = sprintf(s, PRETTYHDR);  
        fmt = PRETTYFMT; 

        /* first call of print, process the arguments and return */
        for (n = 0; args[n]; n++) {
            if (!strcmp(args[n], "format=plain")) {
                *len = 0; 
                fmt = PLAINFMT;
            } else if (!strcmp(args[n], "format=html")) {
                *len = sprintf(s, HTMLHDR, topn); 
                fmt = HTMLFMT;
            } else if (!strncmp(args[n], "url=", 4)) {
		url = args[n] + 4; 
	    } else if (!strncmp(args[n], "urlargs=", 8)) {
		urlargs[no_urlargs] = args[n] + 8;
		no_urlargs++;
	    } 
        } 

	if (url != NULL) {
	    int w, k; 

	    w = sprintf(urlstr, "%s?", url); 
	    for (k = 0; k < no_urlargs; k++) 
		w += sprintf(urlstr + w, "%s&", urlargs[k]);
	    w += sprintf(urlstr + w ,"ip=%%s/24");
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
    addr.s_addr = x->dst_ip & htonl(mask);
    if (fmt == PRETTYFMT) { 
	*len = sprintf(s, fmt, asctime(localtime(&ts)), inet_ntoa(addr), 
		   NTOHLL(x->bytes), ntohl(x->pkts));
    } else if (fmt == HTMLFMT) { 
        float mbps; 
	char tmp[2048] = "#";
	
        mbps = (float) (NTOHLL(x->bytes) * 8) / (float) meas_ivl;
	mbps /= 1000000;
	if (urlstr[0] != '#') 
	    sprintf(tmp, urlstr, inet_ntoa(addr));
	*len = sprintf(s, fmt, tmp, inet_ntoa(addr), mbps);
    } else { 
	*len = sprintf(s, fmt, ts, inet_ntoa(addr), 
		   NTOHLL(x->bytes), ntohl(x->pkts));
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
    replay: NULL,
    formats: "plain pretty html"
};

