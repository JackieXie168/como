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
    char padding;
    uint16_t sampling;
    uint64_t bytes;
    uint64_t pkts;
};

#define STATEDESC   struct _tuple_state
STATEDESC {
    /*
     * packet description and templates for the
     * replay() callback or to know if we can process
     * the packets from given sniffer
     */    
    int compact;
    uint32_t mask;
};

static timestamp_t
init(void * self, char *args[])
{
    STATEDESC * state;
    timestamp_t flush_ivl = TIME2TS(1,0);
    int i; 
    pkt_t * pkt; 
    metadesc_t *inmd, *outmd;

    state = mdl_mem_alloc(self, sizeof(STATEDESC)); 
    state->compact = 0;
    state->mask = ~0;
    
    /*
     * process input arguments
     */
    for (i = 0; args && args[i]; i++) {
	char * x; 

	if (strstr(args[i], "interval")) {
	    x = index(args[i], '=') + 1; 
	    flush_ivl = TIME2TS(atoi(x), 0);
	}
	if (strstr(args[i], "compact")) {
	    state->compact = 1;
	}
        if (strstr(args[i], "mask")) { 
	    x = index(args[i], '=') + 1; 
	    state->mask <<= atoi(x);
	}
    }

    /*
     * our input stream needs to contain the port numbers and
     * a packet length. for the timestamp, we use a default value of
     * one second or whatever we receive from configuration
     */
    
    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = flush_ivl;
    
    pkt = metadesc_tpl_add(inmd, "none:none:~ip:none");
    IP(proto) = 0xff;
    N16(IP(len)) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    
    pkt = metadesc_tpl_add(inmd, "none:none:~ip:~tcp");
    IP(proto) = 0xff;
    N16(IP(len)) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    N16(TCP(src_port)) = 0xffff;
    N16(TCP(dst_port)) = 0xffff;
    
    pkt = metadesc_tpl_add(inmd, "none:none:~ip:~udp");
    IP(proto) = 0xff;
    N16(IP(len)) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    N16(UDP(src_port)) = 0xffff;
    N16(UDP(dst_port)) = 0xffff;
    
    /* setup outdesc */
    outmd = metadesc_define_out(self, 0);
    outmd->ts_resolution = flush_ivl;
    outmd->flags = META_PKT_LENS_ARE_AVERAGED;
    
    pkt = metadesc_tpl_add(outmd, "nf:none:~ip:none");
    IP(proto) = 0xff;
    N16(IP(len)) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    
    pkt = metadesc_tpl_add(outmd, "nf:none:~ip:~tcp");
    IP(proto) = 0xff;
    N16(IP(len)) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    N16(TCP(src_port)) = 0xffff;
    N16(TCP(dst_port)) = 0xffff;
    
    pkt = metadesc_tpl_add(outmd, "nf:none:~ip:~udp");
    IP(proto) = 0xff;
    N16(IP(len)) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    N16(UDP(src_port)) = 0xffff;
    N16(UDP(dst_port)) = 0xffff;
    
    STATE(self) = state; 
    return flush_ivl;
}

static int
check(__unused void * self, pkt_t * pkt)
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
hash(__unused void * self, pkt_t *pkt)
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
match(__unused void * self, pkt_t *pkt, void *fh)
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
update(__unused void * self, pkt_t *pkt, void *fh, int isnew)
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
	x->sampling = H16(NF(sampling));
	x->bytes += H64(NF(bytecount)); 
	x->pkts += (uint64_t) H32(NF(pktcount));
    } else if (COMO(type) == COMOTYPE_SFLOW) {
    	x->sampling = (uint16_t) H32(SFLOW(sampling_rate));
	x->bytes += (uint64_t) COMO(len) * (uint64_t) H32(SFLOW(sampling_rate));
	x->pkts += (uint64_t) H32(SFLOW(sampling_rate));
    } else {
	x->sampling = 1;
	x->bytes += H16(IP(len));
	x->pkts++;
    } 

    return 0;
}

static ssize_t
store(__unused void * self, void *efh, char *buf)
{
    FLOWDESC *x = F(efh);
    
    PUTH32(buf, x->ts);
    PUTN32(buf, N32(x->src_ip));
    PUTN32(buf, N32(x->dst_ip));
    PUTN16(buf, N16(x->src_port));
    PUTN16(buf, N16(x->dst_port));
    PUTH8(buf, x->proto);
    PUTH8(buf, x->padding);
    PUTH16(buf, x->sampling); 
    PUTH64(buf, x->bytes);
    PUTH64(buf, x->pkts);

    return sizeof(FLOWDESC);
}

static size_t
load(__unused void * self, char * buf, size_t len, timestamp_t * ts)
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
print(void * self, char *buf, size_t *len, char * const args[])
{
    static char s[2048];
    static char * fmt;
    STATEDESC * state = STATE(self);
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
    saddr.s_addr = N32(x->src_ip) & htonl(state->mask);
    daddr.s_addr = N32(x->dst_ip) & htonl(state->mask);
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
		    asctime(localtime(&ts)), getprotoname(x->proto), 
		    src, (uint) H16(x->src_port), 
		    dst, (uint) H16(x->dst_port), 
		    NTOHLL(x->bytes), NTOHLL(x->pkts));
    } 
    return s;
};


static int
replay(void * self, char *buf, char *out, size_t * len, int *count)
{
    STATEDESC * state = STATE(self);
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
	COMOX(type, COMOTYPE_NF);
	COMOX(l3type, ETHERTYPE_IP);
	COMOX(l3ofs, sizeof(struct _como_nf)); 
	COMOX(l4type, x->proto); 
	COMOX(l4ofs, sizeof(struct _como_nf) + sizeof(struct _como_iphdr));

	COMOX(len, (uint32_t) nbytes/npkts); 
	if (howmany == (int) npkts) 
	    COMOX(len, COMO(len) + ((uint32_t) nbytes % npkts)); 

	NFX(flags, outlen == 0? COMONF_FIRST : 0); 
	NFX(sampling, x->sampling);
	NFX(bytecount, x->bytes); 
	NFX(pktcount, htonl((uint32_t) npkts));
	
        IPX(proto, x->proto);
	IPX(len, htons((uint16_t) COMO(len))); 
        IPX(src_ip, x->src_ip);
        IPX(dst_ip, x->dst_ip);

        UDPX(src_port, x->src_port);
        UDPX(dst_port, x->dst_port);
        
#else

	COMO(ts) = TIME2TS(ntohl(x->ts), 0); 
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
	N16(NF(sampling)) = x->sampling;
	N64(NF(bytecount)) = x->bytes;
	N32(NF(pktcount)) = htonl((uint32_t) npkts);

        IP(proto) = x->proto;
	N16(IP(len)) = htons((uint16_t) COMO(len)); 
        IP(src_ip) = x->src_ip;
        IP(dst_ip) = x->dst_ip;

        UDP(src_port) = x->src_port;
        UDP(dst_port) = x->dst_port;

#endif

	outlen += pktsz; 

	if (state->compact) 	/* just one packet per flow */
	    break;
    } 

    *len = outlen;
    *count = howmany;
    return (state->compact? 0 : (npkts - howmany));
}


callbacks_t callbacks = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0,
    st_recordsize: sizeof(FLOWDESC), 
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
