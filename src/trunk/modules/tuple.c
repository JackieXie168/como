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
 * 5-tuple flow classifier
 *
 * This module computes 5-tuple flows. Every capture period it 
 * stores the 5-tuple that have been active (together with the 
 * bytes they have sent).  
 *
 */

#include <stdio.h>
#include <time.h>
#include "comofunc.h"
#include "module.h"

#define FLOWDESC    struct _tuple_stat

FLOWDESC {
    uint32_t ts; 
    n32_t src_ip;
    n32_t dst_ip;
    n16_t src_port;
    n16_t dst_port;
    uint8_t proto;
    char padding[3];
    uint64_t bytes;
    uint64_t pkts;
};

/*
 * packet description and templates for the
 * replay() callback or to know if we can process
 * the packets from given sniffer
 */    
static pktdesc_t indesc, outdesc;

static timestamp_t
init(__unused void *mem, __unused size_t msize, char *args[])
{
    timestamp_t flush_ivl = TIME2TS(1,0);
    int i; 

    /*
     * process input arguments
     */
    for (i = 0; args && args[i]; i++) {
	if (strstr(args[i], "interval")) {
	    char * len = index(args[i], '=') + 1; 
	    flush_ivl = TIME2TS(atoi(len), 0);
	}
    }

    /*
     * our input stream needs to contain the port numbers and
     * a packet length. for the timestamp, we use a default value of
     * one second or whatever we receive from configuration
     */
    bzero(&indesc, sizeof(pktdesc_t));
    indesc.ts = flush_ivl; 
    indesc.ih.proto = 0xff;
    N16(indesc.ih.len) = 0xffff;
    N32(indesc.ih.src_ip) = ~0; 
    N32(indesc.ih.dst_ip) = ~0; 
    N16(indesc.tcph.src_port) = 0xffff;
    N16(indesc.tcph.dst_port) = 0xffff;
    N16(indesc.udph.src_port) = 0xffff;
    N16(indesc.udph.dst_port) = 0xffff;
    
    bzero(&outdesc, sizeof(pktdesc_t));
    outdesc.ts = flush_ivl; 
    outdesc.flags = COMO_AVG_PKTLEN;
    N16(outdesc.ih.len) = 0xffff;
    outdesc.ih.proto = 0xff;
    N32(outdesc.ih.src_ip) = 0xffffffff;
    N32(outdesc.ih.dst_ip) = 0xffffffff;
    N16(outdesc.tcph.src_port) = 0xffff;
    N16(outdesc.tcph.dst_port) = 0xffff;
    N16(outdesc.udph.src_port) = 0xffff;
    N16(outdesc.udph.dst_port) = 0xffff;
    
    return flush_ivl;
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
    uint sport, dport; 

    if (IP(proto) == IPPROTO_TCP) { 
	sport = N16(TCP(src_port)); 
	dport = N16(TCP(dst_port)); 
    } else if (IP(proto) == IPPROTO_UDP) { 
	sport = N16(UDP(src_port)); 
	dport = N16(UDP(dst_port)); 
    } else { 
	sport = dport = 0;
    } 

    return (N32(IP(src_ip)) ^ N32(IP(dst_ip)) ^ (sport << 3) ^ (dport << 3));
}

static int
match(pkt_t *pkt, void *fh)
{
    FLOWDESC *x = F(fh);
    uint sport, dport; 
    
    if (IP(proto) == IPPROTO_TCP) {
        sport = N16(TCP(src_port));
        dport = N16(TCP(dst_port));
    } else if (IP(proto) == IPPROTO_UDP) {
        sport = N16(UDP(src_port));
        dport = N16(UDP(dst_port));
    } else {
        sport = dport = 0;
    }

    return (
         N32(IP(src_ip)) == N32(x->src_ip) &&
         N32(IP(dst_ip)) == N32(x->dst_ip) &&
         sport == N16(x->src_port) && dport == N16(x->dst_port) &&
         IP(proto) == x->proto
    );
}

static int
update(pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);

    if (isnew) {
	x->ts = TS2SEC(pkt->ts); 
	x->bytes = 0;
	x->pkts = 0;
        x->proto = IP(proto);
        x->src_ip = IP(src_ip);
        x->dst_ip = IP(dst_ip);

	if (IP(proto) == IPPROTO_TCP) {
	    x->src_port = TCP(src_port); 
	    x->dst_port = TCP(dst_port); 
	} else if (IP(proto) == IPPROTO_UDP) {
	    x->src_port = UDP(src_port); 
	    x->dst_port = UDP(dst_port); 
	} else {
	    N16(x->src_port) = N16(x->dst_port) = 0; 
	}
    }

    if (COMO(type) == COMOTYPE_NF) {
	x->bytes += H64(NF(bytecount)); 
	x->pkts += (uint64_t) H32(NF(pktcount));
    } else {
	x->bytes += H16(IP(len));
	x->pkts++;
    } 

    return 0;
}

static ssize_t
store(void *efh, char *buf, size_t len)
{
    FLOWDESC *x = F(efh);
    
    if (len < sizeof(FLOWDESC))
        return -1;

    PUTH32(buf, x->ts);
    PUTN32(buf, N32(x->src_ip));
    PUTN32(buf, N32(x->dst_ip));
    PUTN16(buf, N16(x->src_port));
    PUTN16(buf, N16(x->dst_port));
    PUTH8(buf, x->proto);
    PUTH8(buf, x->padding[0]);
    PUTH8(buf, x->padding[1]);
    PUTH8(buf, x->padding[2]);
    PUTH64(buf, x->bytes);
    PUTH64(buf, x->pkts);

    return sizeof(FLOWDESC);
}

static size_t
load(char * buf, size_t len, timestamp_t * ts)
{
    if (len < sizeof(FLOWDESC)) {
        ts = 0;
        return 0;
    }

    *ts = TIME2TS(ntohl(((FLOWDESC *)buf)->ts), 0);
    return sizeof(FLOWDESC);
}

#define PLAINFMT       "%10u %3d %15s %5u %15s %5u %8llu %8llu\n"

#define PRETTYHDR       					\
    "Date                     "					\
    "Proto Source IP:Port      Destination IP:Port   " 		\
    "Bytes    Packets\n"

#define PRETTYFMT       "%.24s %s %15s %5u %15s %5u %8llu %8llu\n"

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
    "<tr><td>%.24s</td><td>%s</td><td>%15s:%u</td><td>%15s:%u</td>" \
    "<td>%llu</td><td>%llu</td></tr>\n"


static char *
print(char *buf, size_t *len, char * const args[])
{
    static char s[2048];
    static char * fmt;
    char src[20], dst[20];
    struct in_addr saddr, daddr;
    FLOWDESC *x; 
    time_t ts;


    if (buf == NULL && args != NULL) { 
	int n; 

        *len = sprintf(s, PRETTYHDR); 
	fmt = PRETTYFMT; 

        /* first call of print, process the arguments and return */
        for (n = 0; args[n]; n++) {
            if (!strcmp(args[n], "format=html")) {
                *len = sprintf(s, HTMLHDR);
                fmt = HTMLFMT;
	    } else if (!strcmp(args[n], "format=plain")) {
                *len = 0;
                fmt = PLAINFMT;
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

    x = (FLOWDESC *) buf;
    ts = (time_t)ntohl(x->ts);
    saddr.s_addr = N32(x->src_ip);
    daddr.s_addr = N32(x->dst_ip);
    sprintf(src, "%s", inet_ntoa(saddr));
    sprintf(dst, "%s", inet_ntoa(daddr)); 

    if (fmt == PLAINFMT) {
	*len = sprintf(s, fmt, ts, x->proto, 
		    src, (uint) H16(x->src_port), 
		    dst, (uint) H16(x->dst_port), 
		    NTOHLL(x->bytes), NTOHLL(x->pkts));
    } else { 
	*len = sprintf(s, fmt, 
		    asctime(localtime(&ts)), getprotoname(x->proto), 
		    src, (uint) H16(x->src_port), 
		    dst, (uint) H16(x->dst_port), 
		    NTOHLL(x->bytes), NTOHLL(x->pkts));
    } 
    return s;
};


static int
replay(char *buf, char *out, size_t * len, int *count)
{
    FLOWDESC * x;
    size_t outlen;
    uint64_t nbytes, npkts; 
    int pktsz, howmany;

    if (buf == NULL) {
	*len = 0;
	*count = 0;
	return 0; 		/* nothing to do */
    } 

    /* 
     * generate packets as long as we have space in the output 
     * buffer. the packets will all be equal with the same timestamps
     * and a packet length equal to the average packet lengths. 
     */
    x = (FLOWDESC *) buf; 
    nbytes = NTOHLL(x->bytes);
    npkts = NTOHLL(x->pkts);
    howmany = *count;

    /* fill the output buffer */
    outlen = 0; 
    pktsz = sizeof(pkt_t) + sizeof(struct _como_iphdr) + 
					sizeof(struct _como_udphdr); 
    while (outlen + pktsz < *len && howmany < (int) npkts) { 
	pkt_t * pkt;

	howmany++;

	pkt = (pkt_t *) (out + outlen); 
	pkt->payload = (char *) pkt + sizeof(pkt_t);

#ifdef BUILD_FOR_ARM

	COMOX(ts, TIME2TS(ntohl(x->ts), 0)); 
	COMOX(caplen, sizeof(struct _como_iphdr) +
                        sizeof(struct _como_udphdr));
	COMOX(type, COMOTYPE_NONE);
	COMOX(l3type, ETHERTYPE_IP);
	COMOX(l3ofs, 0); 
	COMOX(l4type, x->proto); 
	COMOX(l4ofs, sizeof(struct _como_iphdr));

	COMOX(len, (uint32_t) nbytes/npkts); 
	if (howmany == (int) npkts) 
	    COMOX(len, COMO(len) + ((uint32_t) nbytes % npkts)); 

        IPX(proto, x->proto);
	IPX(len, htons((uint16_t) COMO(len))); 
        IPX(src_ip, x->src_ip);
        IPX(dst_ip, x->dst_ip);

        UDPX(src_port, x->src_port);
        UDPX(dst_port, x->dst_port);
        
#else

	COMO(ts) = TIME2TS(ntohl(x->ts), 0); 
	COMO(caplen) = sizeof(struct _como_iphdr) + sizeof(struct _como_udphdr);
	COMO(type) = COMOTYPE_NONE;
	COMO(l3type) = ETHERTYPE_IP;
	COMO(l3ofs) = 0; 
	COMO(l4type) = x->proto; 
	COMO(l4ofs) = sizeof(struct _como_iphdr);

	COMO(len) = (uint32_t) nbytes/npkts; 
	if (howmany == (int) npkts) 
	    COMO(len) += (uint32_t) nbytes % npkts; 

        IP(proto) = x->proto;
	N16(IP(len)) = htons((uint16_t) COMO(len)); 
        IP(src_ip) = x->src_ip;
        IP(dst_ip) = x->dst_ip;

        UDP(src_port) = x->src_port;
        UDP(dst_port) = x->dst_port;

#endif

	outlen += pktsz; 
    } 

    *len = outlen;
    *count = howmany;
    return (npkts - howmany);
}


callbacks_t callbacks = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0,
    st_recordsize: sizeof(FLOWDESC), 
    indesc: &indesc,
    outdesc: &outdesc,
    init: init,
    check: check,
    hash: hash,
    match: match,
    update: update,
    ematch: NULL,
    export: NULL,
    compare: NULL,
    action: NULL,
    store: store,
    load: load,
    print: print,
    replay: replay,
    formats: "plain pretty html"
};
