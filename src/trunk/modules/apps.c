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
 * $Id: application.c 605 2006-06-05 16:37:25Z iannak1 $
 */

#include <stdio.h>
#include <errno.h>
#include <time.h>

#include "module.h"


/* 
 * APPS Module
 * 
 * This module classifies packets in applications using source and 
 * destination port numbers. During configuration, the application classes
 * are defined together with the port numbers that fall within each class. 
 * 
 * NOTE: the classes once defined are used for an entire run of this 
 *       module. The database does not contain any explicit knowledge 
 *       of the existing classes therefore between multiple runs with 
 *       different configurations, the database should be deleted.
 * 
 */

/* 
 * Maximum number of application classes. The limit is given by the 
 * number of bits used to identify the class, i.e. we are using uint16_t 
 * for the port2app arrays, hence 16 classes max. 
 */
#define MAX_CLASSES		16 

/* 
 * Two classes are always there: Unknowns and not TCP/UDP packets. 
 * The others are available to the user 
 */
#define MAX_USER_CLASSES	(MAX_CLASSES - 2)

/*
 * Convert the index of the application class to a code. 
 * Lower index is used to break ties when a packet matches
 * multiple applications.
 */
#define APP_TO_CODE(x)		((((uint) 1) << (x)) - 1) 


#define FLOWDESC    struct _app_stat
FLOWDESC {
    uint32_t ts;
    uint64_t bytes[MAX_CLASSES];
    uint32_t pkts[MAX_CLASSES];
};

typedef struct {
    int meas_ivl; 			/* measurement granularity (secs) */
    int classes; 			/* no. of categories */ 
    char * names[16]; 			/* category names */
    uint16_t tcp_port2app[65536];	/* mapping tcp port number to app */
    uint16_t udp_port2app[65536];	/* mapping udp port number to app */
    char template[1024]; 
} config_t;


static timestamp_t 
init(void * self, char * args[])
{
    config_t * config;
    pkt_t * pkt; 
    int i;	
    metadesc_t *inmd, *outmd;

    config = mem_mdl_calloc(self, 1, sizeof(config_t));
    config->meas_ivl = 1;
    memset(config->tcp_port2app, 0xff, sizeof(config->tcp_port2app)); 
    memset(config->udp_port2app, 0xff, sizeof(config->udp_port2app)); 

    /* 
     * process input arguments 
     */
    for (i = 0; args && args[i]; i++) { 
	char * wh; 

	wh = index(args[i], '=') + 1;

	if (strstr(args[i], "interval")) {
	    config->meas_ivl = atoi(wh); 
	} else if (strstr(args[i], "class")) { 
	    /* silently ignore more than MAX_USER_CLASSES classes */ 
	    if (config->classes < MAX_USER_CLASSES) { 
		char * x = strpbrk(wh, "\n\0"); 
		config->names[config->classes] = mem_mdl_calloc(self, 1, x-wh); 
		strncpy(config->names[config->classes], wh, x - wh);
		config->classes++;
	    } 
	} else if (strstr(args[i], "udp")) {
	    int port = atoi(args[i]); 
	    char * x = index(wh, ','); 
	    int j; 

	    for (j = 0; j < config->classes; j++) { 
		if (!strncmp(config->names[j], wh, (x - wh))) {
		    config->udp_port2app[port] = APP_TO_CODE(j); 
		    break; 
		} 
	    } 
	} else if (strstr(args[i], "tcp")) {
	    int port = atoi(args[i]); 
	    char * x = index(wh, ','); 
	    int j; 

	    for (j = 0; j < config->classes; j++) { 
		if (!strncmp(config->names[j], wh, (x - wh))) {
		    config->tcp_port2app[port] = APP_TO_CODE(j); 
		    break; 
		} 
	    } 
	} 
    }

    /* add the "UNKNWON" class for all TCP/UDP packets that cannot be 
     * classified. we also go thru the port2app arrays and 
     * set all entries that are 0xffff to be APP_TO_CODE(config->classes) 
     */ 
    config->names[config->classes] = mem_mdl_malloc(self, 8);
    snprintf(config->names[config->classes], 8, "Unknown");

    for (i = 0; i < 65536; i++) { 
	if (config->tcp_port2app[i] == 0xffff) 
	    config->tcp_port2app[i] = APP_TO_CODE(config->classes); 
	if (config->udp_port2app[i] == 0xffff) 
	    config->udp_port2app[i] = APP_TO_CODE(config->classes); 
    } 

    config->classes++;

    /* 
     * finally add one class for all packets that are not TCP or UDP
     */ 
    config->names[config->classes] = mem_mdl_malloc(self, 12);
    snprintf(config->names[config->classes], 12, "Not TCP/UDP");
    config->classes++;
	 
    /* 
     * our input stream needs to contain the port numbers and 
     * a packet length. for the timestamp, we use a default value of 
     * one second or whatever we receive from configuration 
     */ 
    
    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = TIME2TS(config->meas_ivl, 0);
    
    pkt = metadesc_tpl_add(inmd, "none:none:none:none");
    
    pkt = metadesc_tpl_add(inmd, "none:none:none:~tcp");
    N16(TCP(src_port)) = 0xffff;
    N16(TCP(dst_port)) = 0xffff;
    
    pkt = metadesc_tpl_add(inmd, "none:none:none:~udp");
    N16(UDP(src_port)) = 0xffff;
    N16(UDP(dst_port)) = 0xffff;
    
    /* setup outdesc */
    outmd = metadesc_define_out(self, 0);
    outmd->ts_resolution = TIME2TS(config->meas_ivl, 0);
    outmd->flags = META_PKT_LENS_ARE_AVERAGED;
    
    pkt = metadesc_tpl_add(outmd, "como:none:~ip:none");
    IP(version) = 0xf;
    
    /* create packet template used in replay function */
    pkt = (pkt_t *) config->template; 
    COMO(caplen) = sizeof(struct _como_iphdr);
    COMO(len) = COMO(caplen);
    COMO(type) = COMOTYPE_COMO;
    COMO(l2type) = 0;
    COMO(l2ofs) = 0;
    COMO(l3type) = ETHERTYPE_IP;
    COMO(l3ofs) = 0;
    COMO(l4ofs) = sizeof(struct _como_iphdr);
    COMO(l7ofs) = COMO(l4ofs);
    COMO(payload) = config->template + sizeof(pkt_t);
    IP(version) = 0x4;
    
    CONFIG(self) = config; 
    return TIME2TS(config->meas_ivl, 0);
}


static int
update(void * self, pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);
    config_t * cf = CONFIG(self);
    int app; 

    if (isnew) {
	bzero(x, sizeof(FLOWDESC)); 
	x->ts = TS2SEC(COMO(ts));
    }

    if (isTCP) { 
	app = cf->tcp_port2app[H16(TCP(src_port))] &
	      cf->tcp_port2app[H16(TCP(dst_port))];
    } else if (isUDP) { 
	app = cf->udp_port2app[H16(UDP(src_port))] &
	      cf->udp_port2app[H16(UDP(dst_port))];
    } else {
	/* other protocols */
	app = APP_TO_CODE(cf->classes - 1); 
    } 

    if (COMO(type) == COMOTYPE_NF) {
	x->bytes[app] += H32(NF(pktcount)) * COMO(len) * H16(NF(sampling));
	x->pkts[app] += H32(NF(pktcount)) * (uint32_t) H16(NF(sampling));
    } else if (COMO(type) == COMOTYPE_SFLOW) {
	x->bytes[app] += (uint64_t) COMO(len) * 
			 (uint64_t) H32(SFLOW(sampling_rate));
	x->pkts[app] += H32(SFLOW(sampling_rate));
    } else {
	x->bytes[app] += COMO(len);
	x->pkts[app]++;
    }

    return 0;
}


typedef struct _app { 
    uint64_t bytes; 
    uint32_t pkts; 
} app_t; 


static ssize_t
store(void * self, void *fh, char *buf)
{
    config_t * cf = CONFIG(self);
    FLOWDESC *x = F(fh);
    int i;
    
    PUTH32(buf, x->ts); 
    for (i = 0; i < cf->classes; i++) {
	PUTH64(buf, x->bytes[APP_TO_CODE(i)] / cf->meas_ivl);
	PUTH32(buf, x->pkts[APP_TO_CODE(i)] / cf->meas_ivl);
    } 

    return sizeof(uint32_t) + cf->classes * sizeof(app_t);
}


static size_t
load(void * self, char * buf, size_t len, timestamp_t * ts)
{
    config_t * config = CONFIG(self);
    size_t sz = sizeof(uint32_t) + config->classes * sizeof(app_t);

    if (len < sz) {
        ts = 0;
        return 0; 
    }

    *ts = TIME2TS(ntohl(*(uint32_t *)buf), 0);
    return sz;
}


#define GNUPLOTHDR 							\
    "set terminal postscript eps color solid lw 1 \"Helvetica\" 14;"	\
    "set grid;"								\
    "set ylabel \"%s\";"						\
    "set xlabel \"Time (H:M UTC)\";"					\
    "set yrange [0:%s];"						\
    "set autoscale xfix;"						\
    "set key outside;"							\
    "set xdata time;"							\
    "set timefmt \"%%s\";"						\
    "set format x \"%%H:%%M\";"						\
    "plot \"-\" using 1:%d with filledcurve x1 title \"%s\" lw 5"	

#define GNUPLOTLINE							\
    ",\"-\" using 1:%d with filledcurve x1 title \"%s\" lw 5"	

#define GNUPLOTFOOTER	"e\n"

#define PRETTYFMT	"%.24s "	/* 24 char to skip \n in asctime() */
#define GNUPLOTFMT	"%ld "
#define PLAINFMT	"%12ld "	

static char *
print(void * self, char *buf, size_t *len, char * const args[])
{
    static char s[4096];
    static char * fmt; 
    static int granularity = 1; 
    static int no_records = 0;
    static int isrelative = 0; 
    static app_t values[MAX_CLASSES];
    config_t * cf = CONFIG(self);
    time_t ts; 
    app_t * x;
    int i; 

    if (buf == NULL && args != NULL) { 
	int n, j; 

	/* default is pretty printing */
	fmt = PRETTYFMT;

        /* first call of print, process the arguments and return */
        for (n = 0; args[n]; n++) {
            if (!strcmp(args[n], "format=plain")) {
                fmt = PLAINFMT;
            } else if (!strcmp(args[n], "format=pretty")) {
		fmt = PRETTYFMT;
            } else if (!strcmp(args[n], "format=gnuplot")) {
                fmt = GNUPLOTFMT;
		isrelative = 0; 
            } else if (!strcmp(args[n], "isrelative")) { 
		isrelative = 1; 
            } else if (!strncmp(args[n], "granularity=", 10)) {
                char * val = index(args[n], '=') + 1;

                /* aggregate multiple records into one to reduce
                 * communication messages.
                 */
                granularity = MAX(atoi(val) / cf->meas_ivl, 1);   
            } 
        } 

        if (fmt == PRETTYFMT) { 
	    *len = sprintf(s, "%-24s", "Date");
	    for (j = 0; j < cf->classes; j++) 
		*len += sprintf(s + *len, "%-10s ", cf->names[j]);   
	    *len += sprintf(s + *len, "\n"); 
	} else if (fmt == GNUPLOTFMT && isrelative) { 
	    *len = sprintf(s, GNUPLOTHDR, "Percentage", "100", 
			   2 * cf->classes, cf->names[cf->classes-1]);  
	    for (j = cf->classes - 1; j > 0; j--) 
		*len += sprintf(s + *len, GNUPLOTLINE, 2*j, cf->names[j-1]); 
	    *len += sprintf(s + *len, "\n"); 
	} else if (fmt == GNUPLOTFMT) {
	    *len = sprintf(s, GNUPLOTHDR, "Mbps", "*", 
				2 * cf->classes, cf->names[cf->classes - 1]);  
	    for (j = cf->classes - 1; j > 0; j--) 
		*len += sprintf(s + *len, GNUPLOTLINE, 2*j, cf->names[j-1]); 
	    *len += sprintf(s + *len, "\n"); 
        } else if (fmt == PLAINFMT) { 
	    *len = 0; 
        } 

	bzero(values, sizeof(values));

	/* send the header back */
	return s; 
    } 

    if (buf == NULL && args == NULL) {
	/* no footer */
	*len = 0; 
        if (fmt == GNUPLOTFMT) 
            *len = sprintf(s, GNUPLOTFOOTER);
	return s; 
    } 
	
    ts = ntohl(*(uint32_t *)buf); 
    x = (app_t *) (buf + sizeof(uint32_t)); 

    /* aggregate records if needed */
    for (i = 0; i < cf->classes; i++) { 
        values[i].bytes += NTOHLL(x[i].bytes); 
	values[i].pkts += ntohl(x[i].pkts); 
    }

    no_records++;
    if (no_records % granularity != 0) {
        *len = 0;
        return s;
    }

    for (i = 0; i < cf->classes; i++) { 
        values[i].bytes /= granularity;
	values[i].pkts /= granularity;
    }

    if (fmt == PRETTYFMT) { 
	*len = sprintf(s, fmt, asctime(localtime(&ts))); 
	for (i = 0; i < cf->classes; i++) 
	    *len += sprintf(s + *len, "%8llu %8u ", 
			    values[i].bytes, values[i].pkts);
    } else if (fmt == PLAINFMT) {  
	*len = sprintf(s, fmt, ts) ; 
	for (i = 0; i < cf->classes; i++) 
	    *len += sprintf(s + *len, "%8llu %8u ", 
			    values[i].bytes, values[i].pkts);
    } else if (fmt == GNUPLOTFMT  && isrelative) { 
	/* 
	 * we plot the percentage of traffic that we can 
	 * map to each application.
	 * we compute them here and then output. 
	 */
	float bytessum = 0; 
	float pktssum = 0; 
	float bytes = 0; 
	float pkts = 0; 

	/* print the timestamp */
	*len = sprintf(s, "%u ", ts) ; 

	for (i = 0; i < cf->classes; i++) {
	    bytessum += values[i].bytes; 
	    pktssum += values[i].pkts; 
	}
	
	/* now print the values */
	for (i = 0; i < cf->classes - 1; i++) { 
	    bytes += (100 * (float) values[i].bytes) / bytessum; 
	    pkts += (100 * (float) values[i].pkts) / pktssum; 
	    *len += sprintf(s + *len, "%.2f %.2f ", bytes, pkts); 
	}

	/* for the last value to be 100 */
	*len += sprintf(s + *len, "%u %u ", 100, 100); 
    } else if (fmt == GNUPLOTFMT && !isrelative) { 
	/* 
	 * we do not need relative values but the absolute 
	 * contribution of each application 
	 */
	float mbps = 0; 
	uint32_t pkts = 0; 

	/* print the timestamp */
	*len = sprintf(s, "%u ", ts) ; 

	/* now print the values */
	for (i = 0; i < cf->classes; i++) { 
	    mbps += (((float) values[i].bytes) * 8.0 / 1000000.0); 
	    pkts += values[i].pkts; 
	    *len += sprintf(s + *len, "%.2f %u ", mbps, pkts); 
	}
    } 

    /* reset the values */
    bzero(values, sizeof(values));

    *len += sprintf(s + *len, "\n"); 
    return s;
}

callbacks_t callbacks = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0, 
    st_recordsize: sizeof(uint32_t) + MAX_CLASSES * sizeof(app_t),
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
    replay: NULL,
    formats: "plain pretty gnuplot",
};
