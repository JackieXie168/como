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
 * This module ranks addresses in terms of bytes.
 * The IP addresses can be destination or sources. 
 */

#include <stdio.h>
#include <time.h>
#include "module.h"

#define FLOWDESC	struct _ranking
#define EFLOWDESC	FLOWDESC

FLOWDESC {
    uint32_t addr;  	/* src/dst address */ 
    uint64_t bytes;	/* number of bytes */
    uint32_t pkts;	/* number of packets */
};

#define CONFIGDESC   struct _ranking_config
CONFIGDESC {
    int use_dst; 		/* set if we should use destination address */ 
    int topn;			/* number of top destinations */
    uint32_t meas_ivl;		/* interval (secs) */
    uint32_t mask; 		/* privacy mask */
    uint32_t last_export;	/* last export time */
};


static timestamp_t
init(void * self, char *args[])
{
    CONFIGDESC *config;
    int i;
    pkt_t *pkt;
    metadesc_t *inmd;
    
    config = mem_mdl_malloc(self, sizeof(CONFIGDESC)); 
    config->use_dst = 1; 
    config->meas_ivl = 5;
    config->topn = 20;
    config->mask = ~0;
    config->last_export = 0; 
    
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
	} else if (!strncmp(args[i], "mask", 4)) {
	    config->mask = atoi(wh); 
	} else if (!strncmp(args[i], "align-to", 8)) {
	    config->last_export = atoi(wh); 
	} else if (!strncmp(args[i], "use-dst", 7)) {
	    config->use_dst = 1;
	} else if (!strncmp(args[i], "use-src", 7)) {
	    config->use_dst = 0;
	}
    }

    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = TIME2TS(config->meas_ivl, 0);
    
    pkt = metadesc_tpl_add(inmd, "none:none:~ip:none");
    IP(proto) = 0xff;
    N16(IP(len)) = 0xffff;
    if (config->use_dst) 
	N32(IP(dst_ip)) = 0xffffffff;
    else 
	N32(IP(src_ip)) = 0xffffffff;

    CONFIG(self) = config; 
    return TIME2TS(config->meas_ivl, 0);
}

static uint32_t
hash(void * self, pkt_t *pkt)
{
    CONFIGDESC * config = CONFIG(self);
    return config->use_dst? H32(IP(dst_ip)) : H32(IP(src_ip));
}

static int
match(void * self, pkt_t *pkt, void *fh)
{
    FLOWDESC *x = F(fh);
    CONFIGDESC * config = CONFIG(self);
    uint32_t addr = config->use_dst? H32(IP(dst_ip)) : H32(IP(src_ip)); 
    return (addr == x->addr);
}

static int
update(void * self, pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);
    CONFIGDESC * config = CONFIG(self);

    if (isnew) {
	/* 
	 * we need to make sure that the timestamp is aligned for 
         * all the records of the same interval. force alignment if 
	 * needed. 
	 */ 
        x->addr = config->use_dst? H32(IP(dst_ip)) : H32(IP(src_ip)); 
        x->bytes = 0;
        x->pkts = 0;
    }

    if (COMO(type) == COMOTYPE_NF) { 
	x->bytes += H32(NF(pktcount)) * COMO(len) * H16(NF(sampling));
	x->pkts += H32(NF(pktcount)) * H16(NF(sampling)); 
    } else if (COMO(type) == COMOTYPE_SFLOW) {
	x->bytes += (uint64_t) COMO(len) * (uint64_t) H32(SFLOW(sampling_rate));
	x->pkts += H32(SFLOW(sampling_rate));
    } else { 
	x->bytes += H16(IP(len));
	x->pkts++;
    } 

    return 0;
}

static int
ematch(void * self, void *efh, void *fh)
{
    FLOWDESC *x = F(fh);
    EFLOWDESC *ex = EF(efh);

    return (x->addr == ex->addr);
}

static int
export(void * self, void *efh, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);
    EFLOWDESC *ex = EF(efh);

    if (isnew) {
        ex->addr = x->addr;
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
action(void * self, void *efh, timestamp_t ivl, timestamp_t current_time,
       int count)
{
    CONFIGDESC * config = CONFIG(self);

    if (efh == NULL) { 
	/* 
	 * this is the action for the entire table. 
	 * check if it is time to export the table. 
	 * if not stop. 
	 */
	if (TS2SEC(current_time) < config->last_export + config->meas_ivl) 
	    return ACT_STOP;		/* too early */

	config->last_export = TS2SEC(ivl); 
	return ACT_GO; 		/* dump the records */
    }
    
    return (count < config->topn)? ACT_STORE|ACT_DISCARD : ACT_DISCARD; 
}


struct disk_record { 
    uint32_t ts; 
    uint32_t addr;  	/* src/dst address */ 
    uint64_t bytes;	/* number of bytes */
    uint32_t pkts;	/* number of packets */
};

static ssize_t
store(void * self, void *efh, char *buf)
{
    EFLOWDESC *ex = EF(efh);
    CONFIGDESC *config = CONFIG(self); 

    PUTH32(buf, config->last_export); 
    PUTH32(buf, ex->addr);
    PUTH64(buf, ex->bytes);
    PUTH32(buf, ex->pkts);

    return sizeof(struct disk_record);
}

static size_t
load(void * self, char *buf, size_t len, timestamp_t *ts)
{
    if (len < sizeof(struct disk_record)) {
        *ts = 0;
        return 0; 
    }

    *ts = TIME2TS(ntohl(((struct disk_record *)buf)->ts), 0);
    return sizeof(struct disk_record);
}


#define PRETTYHDR	\
    "Date                     %-15s Bytes      Packets   \n"

#define PRETTYFMT 	"%.24s %d %15s %10llu %8u\n"

#define PLAINFMT	"%12u %d %15s %10llu %8u\n"

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
    "<body>\n"							

#define HTMLTITLE 						\
    "<div class=nvtitle style=\"border-top: 1px solid;\">"	\
    "Top-%d %s</div>\n" \
    "<table class=netview>\n"					\
    "  <tr class=nvtitle>\n"					\
    "    <td>#</td>\n" 	                			\
    "    <td>IP Address</td>\n"					\
    "    <td>bps</td>\n"					\
    "    <td>pps</td>\n"					\
    "  </tr>\n"							

#define HTMLFOOTER						\
    "</table>\n"						\
    "</body></html>\n"						

#define HTMLFMT							\
    "<tr><td>%d</td><td><a href=%s target=_new>%15s</a></td>"	\
    "<td>%.2f%c</td><td>%.2f%c</td></tr>\n"

#define SIDEBOXTITLE 						\
    "<table class=netview>\n"					\
    "  <tr class=nvtitle>\n"					\
    "    <td>#</td>\n"						\
    "    <td>IP Address</td>\n"					\
    "    <td>bps</td>\n"					\
    "    <td>pps</td>\n"					\
    "  </tr>\n"							

static char *
print(void * self, char *buf, size_t *len, char * const args[])
{
    static char s[2048];
    static char * fmt; 
    static char urlstr[2048] = "#"; 
    static time_t last_ts = 0; 
    static int count = 0; 
    CONFIGDESC * config = CONFIG(self);
    struct disk_record *x; 
    struct in_addr addr;
    time_t ts;

    if (buf == NULL && args != NULL) { 
	char * what[] = {"Source IP", "Destination IP"}; 
	char * url = NULL;
	char * urlargs[20];
	int no_urlargs = 0;
	int n; 

        /* by default, pretty print */
        *len = sprintf(s, PRETTYHDR, what[config->use_dst]); 
        fmt = PRETTYFMT; 

        /* first call of print, process the arguments and return */
        for (n = 0; args[n]; n++) {
            if (!strcmp(args[n], "format=plain")) {
                *len = 0; 
                fmt = PLAINFMT;
            } else if (!strcmp(args[n], "format=html")) {
                *len = sprintf(s, HTMLHDR); 
		*len += sprintf(s + *len, HTMLTITLE, config->topn, 
			        what[config->use_dst]); 
                fmt = HTMLFMT;
            } else if (!strcmp(args[n], "format=sidebox")) {
                *len = sprintf(s, HTMLHDR); 
                *len += sprintf(s + *len, SIDEBOXTITLE); 
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
	    w += sprintf(urlstr + w ,"ip=%%s");
	} 
	    
	count = 0; 	/* reset count */ 
	return s; 
    } 

    if (buf == NULL && args == NULL) { 
	*len = 0; 
	if (fmt == HTMLFMT) 
	    *len = sprintf(s, HTMLFOOTER);  
	count = 0; 	/* reset count */ 
        last_ts = 0; 	/* reset timestamp */ 
  	return s; 
    } 

    x = (struct disk_record *) buf; 
    ts = (time_t) ntohl(x->ts);

    /* maintain the count */ 
    if (ts != last_ts) 
	count = 0; 
    last_ts = ts; 
    count++; 

    addr.s_addr = x->addr & htonl(config->mask);

    if (fmt == PRETTYFMT) { 
	*len = sprintf(s, fmt, asctime(localtime(&ts)), count, inet_ntoa(addr), 
		   NTOHLL(x->bytes), ntohl(x->pkts));
    } else if (fmt == HTMLFMT) { 
        float bps, pps; 
        char bunit = ' '; 
        char punit = ' '; 
	char tmp[2048] = "#";
	
        bps = (float) (NTOHLL(x->bytes) * 8) / (float) config->meas_ivl;
	if (bps > 1000000) { 
	    bunit = 'M'; 
	    bps /= 1000000;
	} else  if (bps > 1000) {
	    bunit = 'K'; 
	    bps /= 1000; 
	} 

        pps = (float) ntohl(x->pkts) / (float) config->meas_ivl;
	if (pps > 1000000) { 
	    punit = 'M'; 
	    pps /= 1000000;
	} else if (pps > 1000) {
	    punit = 'K'; 
	    pps /= 1000; 
	} 

	if (urlstr[0] != '#') 
	    sprintf(tmp, urlstr, inet_ntoa(addr));
	*len = sprintf(s, fmt, count, tmp, inet_ntoa(addr), 
		       bps, bunit, pps, punit);
    } else { 
	*len = sprintf(s, fmt, ts, count, inet_ntoa(addr), 
		   NTOHLL(x->bytes), ntohl(x->pkts));
    } 
	
    return s;
};


MODULE(topaddr) = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: sizeof(EFLOWDESC),
    st_recordsize: sizeof(struct disk_record),
    capabilities: {has_flexible_flush: 1, 0},
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
    replay: NULL,
    formats: "plain pretty html sidebox",
};

