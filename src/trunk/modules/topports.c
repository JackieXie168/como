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
 * Top-N ports module.
 *
 * This module finds the top N port numbers (source or destination) with the 
 * largest number of bytes sent during a given interval. 
 *
 */

#include <stdio.h>
#include <time.h>
#include <assert.h>
#include "module.h"

#define FLOWDESC	struct _topports
#define EFLOWDESC	struct _topports

FLOWDESC {
    uint32_t ts;			/* timestamp of first packet */
    uint16_t maxtcpport;		/* max TCP port used */
    uint16_t maxudpport;		/* max UDP port used */
    uint64_t tcpbytes[65536];		/* TCP bytes per port number */
    uint32_t tcppkts[65536];		/* TCP pkts per port number */
    uint64_t udpbytes[65536];		/* UDP bytes per port number */
    uint32_t udppkts[65536];		/* UDP pkts per port number */
};

#define CONFIGDESC   struct _topports_config
CONFIGDESC {
    uint16_t topn;    			/* number of top ports */
    uint32_t meas_ivl;			/* interval (secs) */
    uint32_t last_export;       	/* last export time */
    char * tcp_service[65536]; 		/* TCP application names */ 
    char * udp_service[65536];		/* UDP application names */
};


static timestamp_t
init(void * self, char *args[])
{
    CONFIGDESC *config;
    metadesc_t *inmd;
    pkt_t *pkt;
    int i;
    
    config = mem_mdl_calloc(self, 1, sizeof(CONFIGDESC)); 
    config->meas_ivl = 1;
    config->topn = 20;

    /* 
     * process input arguments 
     */
    for (i = 0; args && args[i]; i++) { 
	char * wh; 

        wh = index(args[i], '=') + 1;
        if (!strncmp(args[i], "interval", 8)) {
            config->meas_ivl = atoi(wh);
        } else if (!strncmp(args[i], "topn", 4)) {
            config->topn = atoi(wh);
        } else if (!strncmp(args[i], "align-to", 8)) {
            config->last_export = atoi(wh);
        } else if (strstr(args[i], "udp")) {
            int port = atoi(args[i]);
	    char *x, *z; 
	    z = index(wh, ',') + 1;
	    x = strpbrk(z, "\t\n\0");
	    config->udp_service[port] = mem_mdl_calloc(self, 1, x - z);
	    strncpy(config->udp_service[port], z, x - z);
        } else if (strstr(args[i], "tcp")) {
            int port = atoi(args[i]);
	    char *x, *z; 
	    z = index(wh, ',') + 1;
	    x = strpbrk(z, "\t\n\0");
	    config->udp_service[port] = mem_mdl_calloc(self, 1, x - z);
	    strncpy(config->udp_service[port], z, x - z);
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
	uint sport = H16(TCP(src_port)); 
	uint dport = H16(TCP(dst_port)); 

	x->tcpbytes[sport] += newbytes; 
	x->tcpbytes[dport] += newbytes; 
	x->tcppkts[sport] += newpkts;
	x->tcppkts[dport] += newpkts; 

	if (sport > x->maxtcpport)
	    x->maxtcpport = sport; 
	if (dport > x->maxtcpport)
	    x->maxtcpport = dport; 
    } else if (isUDP) { 
	uint sport = H16(UDP(src_port)); 
	uint dport = H16(UDP(dst_port)); 

	x->udpbytes[sport] += newbytes; 
	x->udpbytes[dport] += newbytes; 
	x->udppkts[sport] += newpkts;
	x->udppkts[dport] += newpkts; 

	if (sport > x->maxudpport)
	    x->maxudpport = sport; 
	if (dport > x->maxudpport)
	    x->maxudpport = dport; 
    } 

    return 0;
}


static int
export(__unused void * self, void *efh, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);
    EFLOWDESC *ex = EF(efh);
    int i;

    if (isnew) {
	bcopy(x, ex, sizeof(EFLOWDESC)); 
	return 0;
    } 

    for (i = 0; i < 65536; i++) { 
	ex->tcpbytes[i] += x->tcpbytes[i];
	ex->tcppkts[i] += x->tcppkts[i];
	ex->udpbytes[i] += x->udpbytes[i];
	ex->udppkts[i] += x->udppkts[i];
    } 

    if (x->maxtcpport > ex->maxtcpport)
	ex->maxtcpport = x->maxtcpport; 
    if (x->maxudpport > ex->maxudpport)
	ex->maxudpport = x->maxudpport; 
    return 0;
}


static int
action(void * self, void *efh,  __unused timestamp_t ivl,
       timestamp_t current_time, __unused int count)
{
    CONFIGDESC * config = CONFIG(self);

    if (efh == NULL) {
        /*
         * this is the action for the entire table.
         * check if it is time to export the table.
         * if not stop.
         */
        if (TS2SEC(current_time) < config->last_export + config->meas_ivl)
            return ACT_STOP;            /* too early */

        config->last_export = TS2SEC(ivl);
        return ACT_GO;          /* dump the records */
    }

    return ACT_STORE|ACT_DISCARD; 
}


struct topports {
    uint32_t ts; 		/* timestamp */
    uint8_t  proto;		/* protocol */
    uint8_t  reserved;		/* padding */
    uint16_t port; 		/* port number */
    uint64_t bytes; 		/* bytes/port number */
    uint32_t pkts;		/* pkts/port number */
};

static ssize_t
store(void * self, void *rp, char *buf)
{
    CONFIGDESC * config = CONFIG(self);
    EFLOWDESC *x = EF(rp);
    struct topports * tp; 
    int i, j;
    
    /* allocate the array with the results */
    tp = mem_mdl_calloc(self, config->topn + 1, sizeof(struct topports)); 

    /* 
     * go thru the array of bytes to find the topn port 
     * numbers. store them in the tp array. first process the 
     * TCP ports, then the UDP ports 
     *
     */
    for (i = 0; i <= x->maxtcpport; i++) { 
	if (x->tcpbytes[i] == 0) 
	    continue;

	for (j = config->topn - 1; j >= 0; j--) {
	    if (x->tcpbytes[i] < tp[j].bytes)
		break;

	    tp[j + 1] = tp[j]; 
	    tp[j].proto = IPPROTO_TCP;
	    tp[j].port = i;
	    tp[j].bytes = x->tcpbytes[i];
	    tp[j].pkts = x->tcppkts[i];
	}
    }

    /* now run thru the UDP ports */
    for (i = 0; i <= x->maxudpport; i++) { 
	if (x->udpbytes[i] == 0)
	    continue;

	for (j = config->topn - 1; j >= 0; j--) {
	    if (x->udpbytes[i] < tp[j].bytes)
		break;

	    tp[j + 1] = tp[j]; 
	    tp[j].proto = IPPROTO_UDP;
	    tp[j].port = i;
	    tp[j].bytes = x->udpbytes[i];
	    tp[j].pkts = x->udppkts[i];
	}
    }

    /*
     * save the entries with a header that contains the timestamp 
     * and the number of entries we are saving. 
     */
    for (i = 0; i < config->topn && tp[i].pkts != 0; i++) { 
	PUTH32(buf, x->ts);
	PUTH8(buf, tp[i].proto); 
	PUTH8(buf, tp[i].reserved); 	/* padding */
	PUTH16(buf, tp[i].port); 
	PUTH64(buf, tp[i].bytes); 
	PUTH32(buf, tp[i].pkts); 
    } 

    mem_mdl_free(self, tp);
    return (i * sizeof(struct topports)); 
}

static size_t
load(__unused void * self, char *buf, size_t len, timestamp_t *ts)
{
    time_t timestamp; 

    if (len < sizeof(struct topports)) {
        ts = 0;
        return 0; 
    }

    GETH32(buf, &timestamp)
    *ts = TIME2TS(timestamp, 0);
    return sizeof(struct topports); 
}


#define PRETTYHDR	\
    "Date                      Port     Name       Bytes       Packets   \n"

#define PRETTYFMT 	"%.24s %5u/%s %s %10llu %8u\n"

#define PLAINFMT	"%u %u %s %s %llu %u\n"

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
    "<div class=nvtitle>Top-%d Port Numbers</div>\n" 		\
    "<table class=netview>\n" 					\
    "  <tr class=nvtitle>\n"					\
    "    <td>Port</td>\n"                 			\
    "    <td width=60>Mbps</td></tr>\n"

#define SIDEBOXHDR						\
    "<table class=netview>\n" 					\
    "  <tr class=nvtitle>\n"					\
    "    <td>Port</td>\n"                 			\
    "    <td width=60>Mbps</td></tr>\n"

#define HTMLFOOTER						\
    "</table>\n"						\
    "</body></html>\n"						

#define HTMLFMT		"<tr><td>%5u/%s</td><td>%s</td><td>%.2f</td></tr>\n"

static char *
print(void * self, char *buf, size_t *len, char * const args[])
{
    static char s[2048];
    static char * fmt; 
    CONFIGDESC * config = CONFIG(self);
    char * name; 
    uint8_t proto, res; 
    uint16_t port; 
    uint64_t bytes; 
    uint32_t pkts; 
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
            } else if (!strcmp(args[n], "format=html")) {
                *len = sprintf(s, HTMLHDR); 
                *len += sprintf(s + *len, HTMLTITLE, config->topn); 
                fmt = HTMLFMT;
            } else if (!strcmp(args[n], "format=sidebox")) {
                *len = sprintf(s, HTMLHDR); 
                *len += sprintf(s + *len, SIDEBOXHDR); 
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

    GETH32(buf, &ts); 
    GETH8(buf, &proto); 
    GETH8(buf, &res); 
    GETH16(buf, &port); 
    GETH64(buf, &bytes); 
    GETH32(buf, &pkts); 

    name = (proto == IPPROTO_TCP)? 
	    config->tcp_service[port] : config->udp_service[port]; 
    if (name == NULL) 
	name = "Unknown"; 

    /* read each field of the record */
    if (fmt == PRETTYFMT) { 
	*len = sprintf(s, fmt, asctime(localtime(&ts)), 
		   port, getprotoname(proto), name, bytes, pkts); 
    } else if (fmt == HTMLFMT) { 
	float mbps = ((float) bytes * 8 / (float) config->meas_ivl) / 1000000;
	*len = sprintf(s, fmt, port, getprotoname(proto), name, mbps); 
    } else 
	*len = sprintf(s, fmt, ts, port, getprotoname(proto), 
		       name, bytes, pkts); 
	
    return s;
}


callbacks_t callbacks = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: sizeof(EFLOWDESC), 
    st_recordsize: sizeof(FLOWDESC),
    capabilities: {has_flexible_flush: 0, 0},
    init: init,
    check: NULL,
    hash: NULL,
    match: NULL,
    update: update,
    flush: NULL,
    ematch: NULL,
    export: export,
    compare: NULL,
    action: action,
    store: store,
    load: load,
    print: print,
    replay: NULL,
    formats: "plain pretty html"
};

