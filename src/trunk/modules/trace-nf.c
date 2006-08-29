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

#define FLOWDESC    struct _trace_nf_stat

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
    uint32_t bytes;
    uint32_t pkts;
    n32_t duration; 
};

#define CONFIGDESC   struct _trace_nf_config
CONFIGDESC {
    int compact;
    uint32_t mask;
};

MODULE(trace_nf);

static timestamp_t
init(void * self, char *args[])
{
    CONFIGDESC * config;
    timestamp_t ivl;
    int i; 
    pkt_t * pkt; 
    metadesc_t *inmd, *outmd;

    config = mem_mdl_malloc(self, sizeof(CONFIGDESC));
    
    /*
     * process input arguments
     */
    ivl = TIME2TS(1,0); 
    config->compact = 0;
    config->mask = ~0;
    for (i = 0; args && args[i]; i++) {
	char * x; 

	if (strstr(args[i], "period")) {
	    x = index(args[i], '=') + 1; 
	    ivl = TIME2TS(atoi(x), 0);
	}
	if (strstr(args[i], "compact")) {
	    config->compact = 1;
	}
        if (strstr(args[i], "mask")) { 
	    x = index(args[i], '=') + 1; 
	    config->mask <<= atoi(x);
	}
    }

    /*
     * our input stream needs to contain the port numbers and
     * a packet length. for the timestamp, we use a default value of
     * one second or whatever we receive from configuration
     */
    
    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = ivl;
    
    pkt = metadesc_tpl_add(inmd, "nf:none:~ip:none");
    IP(proto) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    
    pkt = metadesc_tpl_add(inmd, "nf:none:~ip:~tcp");
    IP(proto) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    N16(TCP(src_port)) = 0xffff;
    N16(TCP(dst_port)) = 0xffff;
    
    pkt = metadesc_tpl_add(inmd, "nf:none:~ip:~udp");
    IP(proto) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    N16(UDP(src_port)) = 0xffff;
    N16(UDP(dst_port)) = 0xffff;
    
    /* setup outdesc */
    outmd = metadesc_define_out(self, 0);
    outmd->ts_resolution = ivl;
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

    CONFIG(self) = config;
    return TIME2TS(1,0);
}


static int
update(__unused void * self, pkt_t *pkt, void *fh, __unused int isnew)
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
    x->bytes = H32(NF(pktcount)) * COMO(len);
    x->pkts = H32(NF(pktcount));
    x->src_as = NF(src_as);
    x->dst_as = NF(dst_as);
    x->input = NF(input);
    x->output = NF(output);
    x->duration = NF(duration); 

    return 1;
}

static ssize_t
store(__unused void * self, void *efh, char *buf)
{
    FLOWDESC *x = F(efh);
    
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
    PUTH32(buf, x->bytes);
    PUTH32(buf, x->pkts);
    PUTN32(buf, N32(x->duration));

    return sizeof(FLOWDESC);
}

static size_t
load(__unused void * self, char * buf, size_t len, timestamp_t * ts)
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
print(__unused void * self, char *buf, size_t *len, char * const args[])
{
    CONFIGDESC * config = CONFIG(self);
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
    saddr.s_addr = N32(x->src_ip) & htonl(config->mask);
    daddr.s_addr = N32(x->dst_ip) & htonl(config->mask);
    sprintf(src, "%s", inet_ntoa(saddr));
    sprintf(dst, "%s", inet_ntoa(daddr)); 

    if (fmt == PLAINFMT) {
	*len = sprintf(s, fmt, ts, x->proto, 
		    src, (uint) H16(x->src_port), 
		    dst, (uint) H16(x->dst_port), 
		    htonl(x->bytes), 
		    htonl(x->pkts));
    } else { 
	*len = sprintf(s, fmt, 
		    asctime(localtime(&ts)), getprotoname(x->proto), 
		    src, (uint) H16(x->src_port), 
		    dst, (uint) H16(x->dst_port), 
		    htonl(x->bytes), htonl(x->pkts));
    } 
    return s;
};

static int  
replay(__unused void * self, char *buf, char *out, size_t * len, 
       __unused int left)
{
    FLOWDESC * x;
    uint64_t nbytes, npkts; 
    size_t pktsz, paysz;
    pkt_t * pkt;

    if (buf == NULL) {
	*len = 0;
	return 0; 		/* nothing to do */
    } 

    /* 
     * generate packets as long as we have space in the output 
     * buffer. the packets will all be equal with the same timestamps
     * and a packet length equal to the average packet lengths. 
     */
    x = (FLOWDESC *) buf; 
    nbytes = htonl(x->bytes);
    npkts = htonl(x->pkts);

    /* fill the output buffer */
    paysz = sizeof(struct _como_nf) + sizeof(struct _como_iphdr) +
	    sizeof(struct _como_udphdr);
    pktsz = sizeof(pkt_t) + paysz;
    
    if (*len < pktsz)
	return -1;
    
    pkt = (pkt_t *) out;
    
    COMO(ts) = NTOHLL(x->start_ts);
    COMO(caplen) = paysz;
    COMO(len) = nbytes / npkts; 
    COMO(type) = COMOTYPE_NF;
    COMO(l2type) = LINKTYPE_NONE;
    COMO(l3type) = ETHERTYPE_IP;
    COMO(l3ofs) = sizeof(struct _como_nf); 
    COMO(l4type) = x->proto; 
    COMO(l4ofs) = COMO(l3ofs) + sizeof(struct _como_iphdr);
    COMO(l7ofs) = COMO(l4ofs) + sizeof(struct _como_udphdr);
    COMO(payload) = out + sizeof(pkt_t);
    
    N16(NF(sampling)) = N16(x->sampling);
    N32(NF(pktcount)) = x->pkts;
    N32(NF(duration)) = N32(x->duration);
    
    N16(NF(src_as)) = N16(x->src_as);
    N16(NF(dst_as)) = N16(x->dst_as);
    N16(NF(input)) = N16(x->input);
    N16(NF(output)) = N16(x->output);
    
    IP(version) = 0x4;
    IP(ihl) = 0x5;
    IP(proto) = x->proto;
    N16(IP(len)) = htons((uint16_t) COMO(len)); 
    IP(src_ip) = x->src_ip;
    IP(dst_ip) = x->dst_ip;
    
    UDP(src_port) = x->src_port;
    UDP(dst_port) = x->dst_port;
    
    *len = pktsz;
    return 0; 
}

MODULE(trace_nf) = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0,
    st_recordsize: sizeof(FLOWDESC), 
    capabilities: {has_flexible_flush: 0, 0},
    init: init,
    check: NULL,
    hash: NULL,
    match: NULL,
    update: update,
    flush: NULL, 
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
