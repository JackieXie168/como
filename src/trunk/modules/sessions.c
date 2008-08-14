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
 * $Id: tuple.c 976 2006-10-30 19:01:52Z jsanjuas $
 */

/*
 * Session tracker.
 *
 * This module tracks all sessions (defined by the usual 5 tuple). 
 * It uses a timeout approach to decide when to terminate a session. 
 * Any packet can start a session. Sessions are reported ordered by
 * last packet timestamp.
 * 
 */

#include <stdio.h>
#include <time.h>
#include "comofunc.h"
#include "module.h"

#define FLOWDESC    struct _tuple_stat
FLOWDESC {
    timestamp_t start_ts; 
    timestamp_t last_ts; 
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

#define EFLOWDESC   struct _session
EFLOWDESC {
    timestamp_t start_ts; 
    timestamp_t last_ts; 
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

#define CONFIGDESC   struct _tuple_config
CONFIGDESC {
    /*
     * packet description and templates for the
     * replay() callback or to know if we can process
     * the packets from given sniffer
     */    
    int compact;
    uint32_t mask;
    uint32_t timeout;
};

static timestamp_t
init(void * self, char *args[])
{
    CONFIGDESC * config;
    int i; 
    pkt_t * pkt; 
    metadesc_t *inmd, *outmd;

    config = mem_mdl_malloc(self, sizeof(CONFIGDESC)); 
    config->compact = 0;
    config->mask = ~0;
    config->timeout = 60; 
    
    /*
     * process input arguments
     */
    for (i = 0; args && args[i]; i++) {
	char * x; 

	if (strstr(args[i], "compact")) {
	    config->compact = 1;
	} else if (strstr(args[i], "mask")) { 
	    x = index(args[i], '=') + 1; 
	    config->mask <<= atoi(x);
	} else if (strstr(args[i], "timeout")) { 
	    x = index(args[i], '=') + 1; 
	    config->timeout = atoi(x); 
	} 
    }

    /*
     * our input stream needs to contain the port numbers and
     * a packet length. for the timestamp, we use a default value of
     * one second or whatever we receive from configuration
     */
    
    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    
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
    outmd->flags = META_PKT_LENS_ARE_AVERAGED;
    
    pkt = metadesc_tpl_add(outmd, "~nf:none:~ip:none");
    N16(NF(sampling)) = 0xffff;
    N32(NF(duration)) = 0xffffffff;
    N32(NF(pktcount)) = 0xffffffff;
    IP(proto) = 0xff;
    N16(IP(len)) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    
    pkt = metadesc_tpl_add(outmd, "~nf:none:~ip:~tcp");
    N16(NF(sampling)) = 0xffff;
    N32(NF(duration)) = 0xffffffff;
    N32(NF(pktcount)) = 0xffffffff;
    IP(proto) = 0xff;
    N16(IP(len)) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    N16(TCP(src_port)) = 0xffff;
    N16(TCP(dst_port)) = 0xffff;
    
    pkt = metadesc_tpl_add(outmd, "~nf:none:~ip:~udp");
    N16(NF(sampling)) = 0xffff;
    N32(NF(duration)) = 0xffffffff;
    N32(NF(pktcount)) = 0xffffffff;
    IP(proto) = 0xff;
    N16(IP(len)) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    N16(UDP(src_port)) = 0xffff;
    N16(UDP(dst_port)) = 0xffff;
    
    CONFIG(self) = config; 
    return TIME2TS(1, 0);
}


static uint32_t
hash(void * self, pkt_t *pkt)
{
    uint sport, dport; 

    if (isTCP) { 
	sport = N16(TCP(src_port)); 
	dport = N16(TCP(dst_port)); 
    } else if (isUDP) { 
	sport = N16(UDP(src_port)); 
	dport = N16(UDP(dst_port)); 
    } else { 
	sport = dport = 0;
    } 

    return (N32(IP(src_ip)) ^ N32(IP(dst_ip)) ^ (sport << 3) ^ (dport << 3));
}

static int
match(void * self, pkt_t *pkt, void *fh)
{
    FLOWDESC *x = F(fh);
    uint sport, dport; 
    
    if (isTCP) { 
        sport = N16(TCP(src_port));
        dport = N16(TCP(dst_port));
    } else if (isUDP) { 
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
update(void * self, pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);

    if (isnew) {
	x->start_ts = pkt->ts; 
	x->bytes = 0;
	x->pkts = 0;
        x->proto = IP(proto);
        x->src_ip = IP(src_ip);
        x->dst_ip = IP(dst_ip);

	if (isTCP) { 
	    x->src_port = TCP(src_port); 
	    x->dst_port = TCP(dst_port); 
	} else if (isUDP) { 
	    x->src_port = UDP(src_port); 
	    x->dst_port = UDP(dst_port); 
	} else {
	    N16(x->src_port) = N16(x->dst_port) = 0; 
	}
    }

    x->last_ts = pkt->ts;
    if (COMO(type) == COMOTYPE_NF) {
	x->last_ts += 
	    TIME2TS(H32(NF(duration)) / 1000, (H32(NF(duration))%1000)*1000);
	x->sampling = H16(NF(sampling));
	x->bytes += H32(NF(pktcount)) * COMO(len);
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

static int
compare(const void *efh1, const void *efh2)
{
    return CMPEF(efh1)->last_ts < CMPEF(efh2)->last_ts ? -1 : 1;
}

static int
ematch(void *self, void *efh, void *fh)
{
    FLOWDESC *x = F(fh);
    EFLOWDESC *ex = EF(efh);

    return (
	N32(x->src_ip) == N32(ex->src_ip) && 
	N32(x->dst_ip) == N32(ex->dst_ip) && 
	N16(x->src_port) == N16(ex->src_port) && 
	N16(x->dst_port) == N16(ex->dst_port) && 
	x->proto == ex->proto
    ); 
}

static int
export(void * self, void *efh, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);
    EFLOWDESC *ex = EF(efh);

    if (isnew) { 
	bcopy(x, ex, sizeof(EFLOWDESC));
    } else { 
	ex->pkts += x->pkts; 
	ex->bytes += x->bytes; 
	ex->last_ts = x->last_ts; 
    } 
    
    return 0;
}

static int
action(void *self, void *efh, timestamp_t ivl,
        timestamp_t current_time, int count)
{
    CONFIGDESC * config = CONFIG(self);
    EFLOWDESC *ex = EF(efh);

    if (efh == NULL)
	return ACT_GO; 		/* always process all records */

    /* 
     * if the flow has not seen any packets in the last 
     * config->timeout seconds, store it and discard the record
     */ 
    if (TS2SEC(current_time - ex->last_ts) > config->timeout) 
	return (ACT_STORE | ACT_DISCARD); 

    return ACT_GO; 
}

static ssize_t
store(void * self, void *efh, char *buf)
{
    FLOWDESC *x = F(efh);
    
    PUTH64(buf, x->start_ts);
    PUTH64(buf, x->last_ts);
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
load(void * self, char * buf, size_t len, timestamp_t * ts)
{
    if (len < sizeof(FLOWDESC)) {
        *ts = 0;
        return 0;
    }

    *ts = NTOHLL(((FLOWDESC *)buf)->start_ts);
    return sizeof(FLOWDESC);
}


#define PRETTYHDR       					\
    "Start                         "				\
    "Duration     "						\
    "Proto Source IP:Port      Destination IP:Port   " 		\
    "Bytes    Packets\n"

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

static char plainfmt[] = 
	"%10u.%06d %3d.%06d %3d %15s %5u %15s %5u %8llu %8llu\n";
static char prettyfmt[] = 
	"%s.%06d %3d.%06d %5s %15s %5u %15s %5u %8llu %8llu\n";
static char htmlfmt[] = 
    "<tr><td>%s.%06d</td><td>%d.%06d</td><td>%s</td>"		
    "<td>%15s:%u</td><td>%15s:%u</td>" 			
    "<td>%llu</td><td>%llu</td></tr>\n";

static char *
print(void * self, char *buf, size_t *len, char * const args[])
{
    static char s[2048];
    static char * fmt;
    CONFIGDESC * config = CONFIG(self);
    char src[20], dst[20]; 
    struct in_addr saddr, daddr;
    FLOWDESC *x; 
    timestamp_t start_ts, last_ts;
    uint start_sec, start_usec; 
    uint duration_sec, duration_usec; 


    if (buf == NULL && args != NULL) { 
	int n; 

        *len = sprintf(s, PRETTYHDR); 
	fmt = prettyfmt; 

        /* first call of print, process the arguments and return */
        for (n = 0; args[n]; n++) {
            if (!strcmp(args[n], "format=html")) {
                *len = sprintf(s, HTMLHDR);
                fmt = htmlfmt;
	    } else if (!strcmp(args[n], "format=plain")) {
                *len = 0;
                fmt = plainfmt;
	    }
	} 

        return s; 
    } 

    if (buf == NULL && args == NULL) { 
        *len = 0; 
        if (fmt == htmlfmt)
            *len = sprintf(s, HTMLFOOTER);
        return s; 
    } 

    x = (FLOWDESC *) buf;
    start_ts = NTOHLL(x->start_ts);
    last_ts = NTOHLL(x->last_ts); 

    start_sec = TS2SEC(start_ts); 
    start_usec = TS2USEC(x->start_ts);
    duration_sec = TS2SEC(last_ts - start_ts); 
    duration_usec = TS2USEC(last_ts - start_ts); 

    /* get IP addresses */
    saddr.s_addr = N32(x->src_ip) & htonl(config->mask);
    daddr.s_addr = N32(x->dst_ip) & htonl(config->mask);
    sprintf(src, "%s", inet_ntoa(saddr));
    sprintf(dst, "%s", inet_ntoa(daddr)); 

    if (fmt == plainfmt) {
	*len = sprintf(s, fmt, start_sec, start_usec, 
		    duration_sec, duration_usec, x->proto, 
		    src, (uint) H16(x->src_port), 
		    dst, (uint) H16(x->dst_port), 
		    NTOHLL(x->bytes) * ntohs(x->sampling), 
		    NTOHLL(x->pkts) * ntohs(x->sampling));
    } else { 
	char datestr[30]; 
        struct tm * timeptr; 
        time_t t = (time_t) start_sec;

	timeptr = gmtime(&t); 
	strftime(datestr, sizeof(datestr), "%b %e %Y %T", timeptr);

	*len = sprintf(s, fmt, 
		    datestr, start_usec, duration_sec, duration_usec, 
		    getprotoname(x->proto), 
		    src, (uint) H16(x->src_port), 
		    dst, (uint) H16(x->dst_port), 
		    NTOHLL(x->bytes) * ntohs(x->sampling), 
		    NTOHLL(x->pkts) * ntohs(x->sampling));
    } 
    return s;
};


static int
replay(void * self, char *buf, char *out, size_t * len, int pleft)
{
    CONFIGDESC * config = CONFIG(self);
    FLOWDESC * x;
    timestamp_t pkt_ts, inter_ts; 
    uint32_t pkt_duration;
    size_t outlen;
    uint64_t nbytes, npkts; 
    int pktsz, paysz;

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
    nbytes = NTOHLL(x->bytes);
    npkts = NTOHLL(x->pkts);

    /* initialize packet left count */
    if (pleft == 0) 
	pleft = npkts;
    
    /* fill the output buffer */
    outlen = 0;
    paysz = sizeof(struct _como_nf) + sizeof(struct _como_iphdr) +
	    sizeof(struct _como_udphdr);
    pktsz = sizeof(pkt_t) + paysz; 
    while (outlen + pktsz < *len && pleft > 0) {
	pkt_t * pkt;
	uint32_t plen;
 	int pcount; 

	pkt = (pkt_t *) (out + outlen); 
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
	COMO(caplen) = paysz;
	COMO(type) = COMOTYPE_NF;
	COMO(l2type) = LINKTYPE_NONE;
	COMO(l3type) = ETHERTYPE_IP;
	COMO(l3ofs) = sizeof(struct _como_nf); 
	COMO(l4type) = x->proto; 
	COMO(l4ofs) = COMO(l3ofs) + sizeof(struct _como_iphdr);
	COMO(l7ofs) = COMO(l4ofs) + sizeof(struct _como_udphdr);

	N16(NF(sampling)) = x->sampling;

	IP(version) = 0x4;
	IP(ihl) = 0x5;
        IP(proto) = x->proto;
	N16(IP(len)) = htons((uint16_t) COMO(len)); 
        IP(src_ip) = x->src_ip;
        IP(dst_ip) = x->dst_ip;

        UDP(src_port) = x->src_port;
        UDP(dst_port) = x->dst_port;
#endif

	pcount = 1; 
	plen = nbytes / npkts; 
	if (pleft == 1) 
	     plen += nbytes % npkts; 

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

	inter_ts = NTOHLL(x->last_ts) - NTOHLL(x->start_ts); 
	inter_ts /= (uint64_t) npkts;
	pkt_ts = NTOHLL(x->start_ts) + (npkts - pleft) * inter_ts; 
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

	pleft -= pcount;
	outlen += pktsz; 
    } 

    *len = outlen;
    return pleft; 
}

MODULE(tuple) = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: sizeof(FLOWDESC),
    st_recordsize: sizeof(FLOWDESC), 
    capabilities: {has_flexible_flush: 0, 0},
    init: init,
    check: NULL,
    hash: hash,
    match: match,
    update: update,
    flush: NULL, 
    ematch: ematch,
    export: export,
    compare: compare,
    action: action,
    store: store,
    load: load,
    print: print,
    replay: replay,
    formats: "plain pretty html"
};
