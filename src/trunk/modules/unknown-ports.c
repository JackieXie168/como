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
 * List unknown ports (i.e. ports that have not been associated by the 
 * user to any known application) with a count of the packets, bytes and 
 * hosts that are using those ports. The ports are ordered by the number 
 * of hosts. 
 */

#include <stdio.h>
#include <time.h>
#include <assert.h>
#include "module.h"
#include "bitmap.h"
#include "uhash.h"

#define FLOWDESC	struct _topports

FLOWDESC {
    uint32_t ts;			/* timestamp of first packet */
    int count;				/* total number of unknown ports */
}; 

typedef struct { 
    uint16_t max_port; 
    uint16_t min_port; 
    uint32_t bytes[65536];		/* TCP bytes per port number */
    uint32_t pkts[65536];		/* TCP pkts per port number */
    bitmap_t * hosts[65536];		/* TCP hosts */
} state_t;

typedef struct {
    uint32_t meas_ivl;			/* interval (secs) */
    char tcp_known[65536]; 		/* TCP known ports */ 
    char udp_known[65536];		/* UDP known ports */ 
    uhash_t hfunc;    		        /* universal hash function */
    size_t max_keys;                    /* max unique IPs we expect */
} config_t;


static timestamp_t
init(void * self, char *args[])
{
    config_t * cf;
    metadesc_t *inmd;
    pkt_t *pkt;
    int i;
    
    cf = mem_mdl_calloc(self, 1, sizeof(config_t)); 
    cf->meas_ivl = 1;
    cf->max_keys = 100000; 		/* no more than 100,000 IPs */
    uhash_initialize(&cf->hfunc);

    /* 
     * process input arguments 
     */
    for (i = 0; args && args[i]; i++) { 
	char * wh; 

        wh = index(args[i], '=') + 1;
        if (!strncmp(args[i], "interval", 8)) {
            cf->meas_ivl = atoi(wh);
        } else if (strstr(args[i], "udp")) {
            int port = atoi(args[i]);
	    cf->udp_known[port] = 1; 
        } else if (strstr(args[i], "tcp")) {
            int port = atoi(args[i]);
	    cf->tcp_known[port] = 1; 
        }
    }
    
    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = TIME2TS(cf->meas_ivl, 0);
    
    pkt = metadesc_tpl_add(inmd, "none:none:none:~tcp");
    N16(TCP(src_port)) = 0xffff;
    N16(TCP(dst_port)) = 0xffff;
    
    pkt = metadesc_tpl_add(inmd, "none:none:none:~udp");
    N16(UDP(src_port)) = 0xffff;
    N16(UDP(dst_port)) = 0xffff;

    CONFIG(self) = cf; 
    return TIME2TS(cf->meas_ivl, 0); 
}


static int
check(void * self, pkt_t * pkt) 
{
    config_t * cf = CONFIG(self); 
    int known = 1; 

    if (isTCP) {
	known = cf->tcp_known[H16(TCP(src_port))] | 
	        cf->tcp_known[H16(TCP(dst_port))]; 
    } else if (isUDP) {
	known = cf->udp_known[H16(UDP(src_port))] | 
		cf->udp_known[H16(UDP(dst_port))]; 
    } 

    return !known; 
}


static void *
flush(void *self)
{
    state_t * st;
    
    st = mem_mdl_calloc(self, 2, sizeof(state_t));
    st[0].min_port = ~0; 
    st[1].min_port = ~0; 
    return st;
}


static int
update(void * self, pkt_t *pkt, void *rp, int isnew)
{
    FLOWDESC *x = F(rp);
    config_t * cf = CONFIG(self);
    state_t * st = FSTATE(self); 
    uint64_t newbytes = H16(IP(len)); 
    uint32_t newpkts = 1; 
    uint32_t hash;
    int sport, dport, idx; 

    if (isnew) {
	bzero(x, sizeof(FLOWDESC)); 
	x->ts = TS2SEC(pkt->ts) - (TS2SEC(pkt->ts) % cf->meas_ivl);
    }

    if (COMO(type) == COMOTYPE_NF) {
        newbytes = H32(NF(pktcount)) * COMO(len) * H16(NF(sampling));
        newpkts = H32(NF(pktcount)) * (uint32_t) H16(NF(sampling));
    } else if (COMO(type) == COMOTYPE_SFLOW) {
	newbytes = (uint64_t) COMO(len) * (uint64_t) H32(SFLOW(sampling_rate));
	newpkts = H32(SFLOW(sampling_rate));
    } 

    if (isTCP) {
	sport = H16(TCP(src_port)); 
	dport = H16(TCP(dst_port)); 
	idx = 0; 
    } else { 
	sport = H16(UDP(src_port)); 
	dport = H16(UDP(dst_port)); 
	idx = 1; 
    } 

    if (st[idx].bytes[sport] == 0) { 
	/* allocate a new bitmap for this port number */ 
	st[idx].hosts[sport] = mdl_new_bitmap(self, cf->max_keys);
	x->count++; 
	if (sport > st[idx].max_port) 
	    st[idx].max_port = sport; 
	if (sport < st[idx].min_port) 
	    st[idx].min_port = sport; 
    } 

    if (st[idx].bytes[dport] == 0) { 
	/* allocate a new bitmap for this port number */ 
	st[idx].hosts[dport] = mdl_new_bitmap(self, cf->max_keys);
	x->count++; 
	if (dport > st[idx].max_port) 
	    st[idx].max_port = dport; 
	if (dport < st[idx].min_port) 
	    st[idx].min_port = dport; 
    } 

    st[idx].bytes[sport] += newbytes; 
    st[idx].bytes[dport] += newbytes; 

    st[idx].pkts[sport] += newpkts; 
    st[idx].pkts[dport] += newpkts; 

    hash = uhash(&cf->hfunc, (uint8_t *) &IP(src_ip), 4, UHASH_NEW);
    set_bit(st[idx].hosts[sport], hash); 
    set_bit(st[idx].hosts[dport], hash); 

    hash = uhash(&cf->hfunc, (uint8_t *) &IP(dst_ip), 4, UHASH_NEW);
    set_bit(st[idx].hosts[sport], hash); 
    set_bit(st[idx].hosts[dport], hash); 

    return 0;
}

struct info { 
    uint8_t proto;		/* protocol */
    uint8_t padding; 
    uint16_t port; 		/* port number */
    uint32_t bytes; 		/* bytes/port number */
    uint32_t pkts;		/* pkts/port number */
    uint32_t hosts;		/* pkts/port number */
};

static int
cmp(const void * a, const void * b) 
{
    return (((struct info *)a)->pkts < ((struct info *)b)->pkts)? 1 : -1; 
}

static ssize_t
store(void * self, void *rp, char *buf)
{
    state_t * st = FSTATE(self); 
    FLOWDESC * x = F(rp);
    struct info * tp; 
    int i, j, k, n;
    
    /* allocate the array with the results */
    tp = mem_mdl_calloc(self, x->count, sizeof(struct info)); 

    /* 
     * we browse the list of ports and save them in the 
     * unknowns_t array sorted according to the number of 
     * packets. 
     */
    k = 0; 
    for (i = 0; i < 2; i++) { 
	uint8_t proto = (i == 0)? IPPROTO_TCP : IPPROTO_UDP;

	for (j = st[i].min_port; j <= st[i].max_port; j++) { 
	    if (st[i].pkts[j] == 0) 
		continue;

	    tp[k].proto = proto;
            tp[k].port = j; 
	    tp[k].bytes = st[i].bytes[j];
	    tp[k].pkts = st[i].pkts[j];
	    tp[k].hosts = estimate_unique_keys(st[i].hosts[j]); 
	    k++;
	} 
    }

    if (k == 0) {
	mem_mdl_free(self, tp);
	return 0;
    } 

    /* now sort the tp array */ 
    qsort(tp, k, sizeof(struct info), cmp); 

    /* store just the first 256 ports */ 
    PUTH32(buf, x->ts);
    n = MIN(256, k);
    PUTH32(buf, n);
    for (i = 0; i < n; i++) {
	PUTH8(buf, tp[i].proto); 
	PUTH8(buf, tp[i].padding); 	/* padding */
	PUTH16(buf, tp[i].port); 
	PUTH32(buf, tp[i].bytes); 
	PUTH32(buf, tp[i].pkts); 
	PUTH32(buf, tp[i].hosts); 
    }
    
    mem_mdl_free(self, tp);

    return n * sizeof(struct info) + 8; 
}

static size_t
load(void * self, char *buf, size_t len, timestamp_t *ts)
{
    int n;

    *ts = TIME2TS(ntohl(((FLOWDESC *)buf)->ts), 0);
    n = ntohl(((FLOWDESC *)buf)->count);
    return n * sizeof(struct info) + 8; 
}


#define PRETTYHDR	\
    "Date                      Port     Name       Bytes       Packets   \n"

#define HTMLHDR                                                 \
    "<html>\n"                                                  \
    "<head>\n"                                                  \
    "  <style type=\"text/css\">\n"                             \
    "   body {font-size: 9pt; margin: 0; padding: 0; \n"	\
    "     font-family: \"lucida sans unicode\", verdana, arial;}\n" \
    "   table,tr,td {background-color: #ddd;\n" 	        \
    "     font-size: 9pt; \n"		            		\
    "     font-family: \"lucida sans unicode\", verdana, arial;}\n" \
    "   a, a:visited { color: #475677; text-decoration: none;}\n" \
    "   .netview {\n"                                           \
    "     top: 0px; width: 100%%; vertical-align:top;\n"        \
    "     margin: 2; padding-left: 5px;\n" 			\
    "     padding-right: 5px; text-align:left;}\n" 		\
    "   .nvtitle {\n"                                           \
    "     font-weight: bold; padding-bottom: 3px;\n" 		\
    "     font-family: \"lucida sans unicode\", verdana, arial;\n" \
    "     font-size: 9pt; \n"		            		\
    "     color: #475677;}\n"                                   \
    "  </style>\n"                                              \
    "</head>\n"                                                 \
    "<body>\n"                                                  \

#define HTMLTITLE						\
    "<div class=nvtitle>Unknown Port Numbers</div>\n" 		\

#define SIDEBOXHDR						\
    "<table class=netview>\n" 					\
    "  <tr class=nvtitle>\n"					\
    "    <td>Port</td>\n"                 			\
    "    <td>Packets</td>\n"                 			\
    "    <td>Bytes</td>\n"					\
    "    <td>Hosts</td></tr>\n"

#define HTMLFOOTER						\
    "</table>\n"						\
    "</body></html>\n"						

static char prettyfmt[] = "%5u/%s %8u %5u%c %5u\n";
static char plainfmt[] = "%u/%s %u %u%c %u\n";
static char htmlfmt[] = 
	"<tr><td>%u/%s</td><td>%u</td><td>%u%c</td><td>%u</td></tr>\n";

static char *
print(void * self, char *buf, size_t *len, char * const args[])
{
    static char s[4096];
    static char * fmt; 
    struct info * tp; 
    time_t ts;
    uint8_t count; 
    int i; 
    FLOWDESC *x;
    

    *len = 0;
    
    if (buf == NULL && args != NULL) { 
	int n; 

        /* by default, pretty print */
        *len = sprintf(s, PRETTYHDR);  
        fmt = prettyfmt; 

        /* first call of print, process the arguments and return */
        for (n = 0; args[n]; n++) {
            if (!strcmp(args[n], "format=plain")) {
                *len = 0; 
                fmt = plainfmt;
            } else if (!strcmp(args[n], "format=html")) {
                *len = sprintf(s, HTMLHDR); 
                *len += sprintf(s + *len, HTMLTITLE); 
                *len += sprintf(s + *len, SIDEBOXHDR); 
                fmt = htmlfmt;
            } else if (!strcmp(args[n], "format=sidebox")) {
                *len = sprintf(s, HTMLHDR); 
                *len += sprintf(s + *len, SIDEBOXHDR); 
                fmt = htmlfmt;
	    }
        } 

	return s; 
    } 

    if (buf == NULL && args == NULL) { 
	if (fmt == htmlfmt) 
	    *len = sprintf(s, HTMLFOOTER);  
  	return s; 
    } 

    x = (FLOWDESC *) buf; 
    ts = (time_t) ntohl(x->ts);
    count = ntohl(x->count);
    tp = (struct info *) (buf + sizeof(FLOWDESC)); 

    /* read each field of the record */
    for (i = 0; i < count; i++) { 
	uint32_t bytes = ntohl(tp[i].bytes); 
	char unit = 'B';

	if (bytes > 1024*1024) {
	    bytes >>= 20; 
	    unit = 'M';
	} else if (bytes > 1024) { 
	    bytes >>= 10; 
	    unit = 'K';
        } 
	    
	if (fmt == prettyfmt)
	    *len += sprintf(s + *len, "%.24s ", asctime(localtime(&ts))); 
	else if (fmt == plainfmt)
	    *len += sprintf(s + *len, "%u ", (uint) ts); 
	    
	*len += sprintf(s + *len, fmt, ntohs(tp[i].port), 
		   getprotoname(tp[i].proto), ntohl(tp[i].pkts), 
		   bytes, unit, ntohl(tp[i].hosts)); 
    } 
	    
    return s;
}


MODULE(unknown_ports) = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0, 
    st_recordsize: 256 * sizeof(struct info) + 8, 
    capabilities: {has_flexible_flush: 0, 0},
    init: init,
    check: check,
    hash: NULL,
    match: NULL,
    update: update,
    flush: flush,
    ematch: NULL,
    export: NULL,
    compare: NULL,
    action: NULL,
    store: store,
    load: load,
    print: print,
    replay: NULL,
    formats: "plain pretty html sidebox"
};

