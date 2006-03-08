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
 * netflow module 
 *
 * This module stores netflow records. It works only with COMOTYPE_NF 
 * packets and stores all records exactly the way they are received. 
 * Some information in the netflow v5 records is not stored to disk. 
 */

#include <stdio.h>
#include <time.h>
#include "comofunc.h"
#include "module.h"

#define FLOWDESC    struct _tuple_stat

FLOWDESC {
    timestamp_t start_ts; 
    n32_t src_ip;
    n32_t dst_ip;
    n16_t src_port;
    n16_t dst_port;
    uint8_t proto;
    uint8_t padding;
    n16_t input;
    n16_t output; 
    n16_t src_as; 
    n16_t dst_as; 
    n16_t sampling;
    uint64_t bytes;
    uint64_t pkts;
    n32_t duration; 
};

/*
 * packet description and templates for the
 * replay() callback or to know if we can process
 * the packets from given sniffer
 */    
static pktdesc_t indesc, outdesc;
static int compact = 0;
static uint32_t mask = ~0;

static timestamp_t
init(__unused void *mem, __unused size_t msize, char *args[])
{
    timestamp_t ivl = TIME2TS(1,0); 
    int i; 

    /*
     * process input arguments
     */
    for (i = 0; args && args[i]; i++) {
	char * x; 

	if (strstr(args[i], "period")) {
	    x = index(args[i], '=') + 1; 
	    ivl = TIME2TS(atoi(x), 0);
	}
	if (strstr(args[i], "compact")) {
	    compact = 1;
	}
        if (strstr(args[i], "mask")) { 
	    x = index(args[i], '=') + 1; 
	    mask <<= atoi(x);
	}
    }

    /*
     * our input stream needs to contain the port numbers and
     * a packet length. for the timestamp, we use a default value of
     * one second or whatever we receive from configuration
     */
    bzero(&indesc, sizeof(pktdesc_t));
    indesc.ts = ivl; 
    indesc.ih.proto = 0xff;
    N16(indesc.ih.len) = 0xffff;
    N32(indesc.ih.src_ip) = ~0; 
    N32(indesc.ih.dst_ip) = ~0; 
    N16(indesc.tcph.src_port) = 0xffff;
    N16(indesc.tcph.dst_port) = 0xffff;
    N16(indesc.udph.src_port) = 0xffff;
    N16(indesc.udph.dst_port) = 0xffff;
    
    bzero(&outdesc, sizeof(pktdesc_t));
    outdesc.ts = ivl; 
    outdesc.flags = COMO_AVG_PKTLEN;
    N16(outdesc.ih.len) = 0xffff;
    outdesc.ih.proto = 0xff;
    N32(outdesc.ih.src_ip) = 0xffffffff;
    N32(outdesc.ih.dst_ip) = 0xffffffff;
    N16(outdesc.tcph.src_port) = 0xffff;
    N16(outdesc.tcph.dst_port) = 0xffff;
    N16(outdesc.udph.src_port) = 0xffff;
    N16(outdesc.udph.dst_port) = 0xffff;
    N16(outdesc.nf.input) = ~0;
    N16(outdesc.nf.output) = ~0;
    N16(outdesc.nf.src_as) = ~0;
    N16(outdesc.nf.dst_as) = ~0;
    N64(outdesc.nf.bytecount) = ~0;
    N32(outdesc.nf.pktcount) = ~0;
    outdesc.nf.flags = COMONF_FIRST;
    
    return TIME2TS(1,0);
}

static int
check(pkt_t * pkt)
{
    if (COMO(type) != COMOTYPE_NF) 
	return 0;

    /*
     * if the stream contains per-flow information, 
     * drop all packets after the first. 
     */
    return (NF(flags) & COMONF_FIRST); 
}


static int
update(pkt_t *pkt, void *fh, __unused int isnew)
{
    FLOWDESC *x = F(fh);

    x->start_ts = pkt->ts; 
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

    x->sampling = NF(sampling);
    x->bytes += H64(NF(bytecount)); 
    x->pkts += H32(NF(pktcount));
    x->src_as = NF(src_as);
    x->dst_as = NF(dst_as);
    x->input = NF(input);
    x->output = NF(output);
    x->duration = NF(duration); 

    return 1;
}

static ssize_t
store(void *efh, char *buf, size_t len)
{
    FLOWDESC *x = F(efh);
    
    if (len < sizeof(FLOWDESC))
        return -1;

    PUTH64(buf, x->start_ts);
    PUTN32(buf, N32(x->src_ip));
    PUTN32(buf, N32(x->dst_ip));
    PUTN16(buf, N16(x->src_port));
    PUTN16(buf, N16(x->dst_port));
    PUTN8(buf, x->proto);
    PUTN8(buf, x->padding);
    PUTN16(buf, N16(x->input));
    PUTN16(buf, N16(x->output));
    PUTN16(buf, N16(x->src_as));
    PUTN16(buf, N16(x->dst_as));
    PUTN16(buf, N16(x->sampling)); 
    PUTH64(buf, x->bytes);
    PUTH64(buf, x->pkts);
    PUTN32(buf, N32(x->duration));

    return sizeof(FLOWDESC);
}

static size_t
load(char * buf, size_t len, timestamp_t * ts)
{
    if (len < sizeof(FLOWDESC)) {
        ts = 0;
        return 0;
    }

    *ts = NTOHLL(((FLOWDESC *)buf)->start_ts);
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
    "    <td>Start Time (UTC)</td>\n"               			\
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
    ts = (time_t) TS2SEC(NTOHLL(x->start_ts)); 
    saddr.s_addr = N32(x->src_ip) & htonl(mask);
    daddr.s_addr = N32(x->dst_ip) & htonl(mask);
    sprintf(src, "%s", inet_ntoa(saddr));
    sprintf(dst, "%s", inet_ntoa(daddr)); 

    if (fmt == PLAINFMT) {
	*len = sprintf(s, fmt, ts, x->proto, 
		    src, (uint) H16(x->src_port), 
		    dst, (uint) H16(x->dst_port), 
		    NTOHLL(x->bytes), 
		    NTOHLL(x->pkts));
    } else { 
	*len = sprintf(s, fmt, 
		    asctime(gmtime(&ts)), getprotoname(x->proto), 
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

	COMOX(ts, NTOHLL(x->start_ts));  
	COMOX(caplen, sizeof(struct _como_iphdr) +
                        sizeof(struct _como_udphdr));
	COMOX(type, COMOTYPE_NF);
	COMOX(l3type, ETHERTYPE_IP);
	COMOX(l3ofs, sizeof(struct _como_nf)); 
	COMOX(l4type, x->proto); 
	COMOX(l4ofs, sizeof(struct _como_nf) + sizeof(struct _como_iphdr));

	COMOX(len, (uint32_t) nbytes/npkts); 
	if (howmany == (int) npkts) 
	    COMOX(len, COMO(len) + ((uint32_t) nbytes % npkts)); 

	NFX(flags, outlen == 0? COMONF_FIRST : 0); 
        NFX(src_as, x->src_as);
        NFX(dst_as, x->dst_as);
        NFX(input, x->input);
        NFX(output, x->output);
	NFX(sampling, x->sampling);
	NFX(bytecount, x->bytes); 
	NFX(pktcount, htonl((uint32_t) npkts));
	NFX(duration, x->duration);
	
        IPX(proto, x->proto);
	IPX(len, htons((uint16_t) COMO(len))); 
        IPX(src_ip, x->src_ip);
        IPX(dst_ip, x->dst_ip);

        UDPX(src_port, x->src_port);
        UDPX(dst_port, x->dst_port);
        
#else

	COMO(ts) = NTOHLL(x->start_ts); 
	COMO(caplen) = sizeof(struct _como_iphdr) + sizeof(struct _como_udphdr);
	COMO(type) = COMOTYPE_NF;
	COMO(l3type) = ETHERTYPE_IP;
	COMO(l3ofs) = sizeof(struct _como_nf); 
	COMO(l4type) = x->proto; 
	COMO(l4ofs) = sizeof(struct _como_nf) + sizeof(struct _como_iphdr);

	COMO(len) = (uint32_t) nbytes/npkts; 
	if (howmany == (int) npkts) 
	    COMO(len) += (uint32_t) nbytes % npkts; 

	NF(flags) = (outlen == 0)? COMONF_FIRST : 0; 
        NF(src_as) = x->src_as;
        NF(dst_as) = x->dst_as;
        NF(input) = x->input;
        NF(output) = x->output;
	NF(sampling) = x->sampling;
	N64(NF(bytecount)) = x->bytes;
	N32(NF(pktcount)) = htonl((uint32_t) npkts);
	NF(duration) = x->duration;

        IP(proto) = x->proto;
	N16(IP(len)) = htons((uint16_t) COMO(len)); 
        IP(src_ip) = x->src_ip;
        IP(dst_ip) = x->dst_ip;

        UDP(src_port) = x->src_port;
        UDP(dst_port) = x->dst_port;

#endif

	outlen += pktsz; 

	if (compact) 	/* just one packet per flow */
	    break;
    } 

    *len = outlen;
    *count = howmany;
    return (compact? 0 : (npkts - howmany));
}


callbacks_t callbacks = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0,
    st_recordsize: sizeof(FLOWDESC), 
    indesc: &indesc,
    outdesc: &outdesc,
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
    replay: replay,
    formats: "plain pretty html"
};
