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
 * Application module
 *
 * This module computes the number of packets and bytes per application.
 * Output: packets/bytes per application over 1s intervals
 *
 * It supports only TCP packets. 
 * 
 * This implementation requires that min-flush = max-flush and equal to 
 * the desired granularity of the measurement. 
 * 
 * Optional arguments for init():  
 * 
 * .  "interval = 4"
 * 
 *    specifies the measurement interval. this is used for the output 
 *    description for a packet trace generated by this module. 
 * 
 * Optional arguments for print():
 * 
 * .  "granularity = <number>"
 * 
 *    specifies the granularity of the query results. it cannot be smaller
 *    than the measurement interval and it results in computing the average 
 *    across multiple records in the database. 
 * 
 *    XXX no checks are done to make sure the database is complete and
 *        does not skip records. this optional argument should be used
 *        only when a data reduction is needed (e.g., for plotting
 *        figures with a lower number of data points).
 *
 * 
 */

#include <stdio.h>
#include <errno.h>
#include <time.h>

#include "module.h"

/*
 * List of known applications
 * Application code means also application priority
 */
#define WEB		0x00
#define NETWORK		0x01	/* ssh, telnet, dns, ntp, nfs, ftp, etc. */
#define EMAIL		0x03	/* email, news, etc. */
#define STREAM		0x07
#define GAMES		0x0f
#define SHARING		0x1f
#define UNKNOWN		0x3f    

#define APPLICATIONS       7 
#define APPCODE(x)	   ((((uint) 1) << x) - 1) 

#define FLOWDESC    struct _app_stat
FLOWDESC {
    timestamp_t ts;
    uint64_t bytes[UNKNOWN + 1];
    uint32_t pkts[UNKNOWN + 1];
};

/* 
 * this is the data record that we store on disk
 */
typedef struct {
    uint32_t ts;
    uint64_t bytes[APPLICATIONS];
    uint32_t pkts[APPLICATIONS];
} app_t;


#define STATEDESC   struct _application_state
STATEDESC {
    char template[1024]; 
    int meas_ivl; 		/* measurement granularity (secs) */
    uint8_t port2app[65536];	/* mapping port number to app */
};

static timestamp_t 
init(void * self, char *args[])
{
    STATEDESC *state;
    pkt_t * pkt; 
    int i;
    metadesc_t *inmd, *outmd;

    state = mdl_mem_alloc(self, sizeof(STATEDESC));
    memset(state->port2app, UNKNOWN, sizeof(state->port2app));

    /* initialize the port-to-application mapping array */
    state->port2app[80]    = WEB;
    state->port2app[443]   = WEB;
    state->port2app[8080]  = WEB;
    state->port2app[3128]  = WEB;             // SQUID
    state->port2app[3130]  = WEB;             // SQUID
    state->port2app[9090]  = WEB;             // AUTOPROXY 

    state->port2app[6688]  = SHARING;
    state->port2app[6697]  = SHARING;
    state->port2app[6699]  = SHARING;
    state->port2app[4329]  = SHARING;
    state->port2app[4444]  = SHARING;
    state->port2app[5555]  = SHARING;
    state->port2app[6666]  = SHARING;
    state->port2app[7777]  = SHARING;
    state->port2app[6346]  = SHARING;
    state->port2app[1214]  = SHARING;
    for (i = 4000; i <= 4999; i++) {
        state->port2app[i] = SHARING;
    }

    state->port2app[22]    = NETWORK;         // SSH
    state->port2app[23]    = NETWORK;         // TELNET
    state->port2app[992]   = NETWORK;         // TELNET

    state->port2app[25]    = EMAIL;             //SMTP
    state->port2app[465]   = EMAIL;             //SMTPS
    state->port2app[109]   = EMAIL;             //POP
    state->port2app[110]   = EMAIL;             //POP
    state->port2app[995]   = EMAIL;             //POP
    state->port2app[143]   = EMAIL;             //IMAP
    state->port2app[220]   = EMAIL;             //IMAP
    state->port2app[993]   = EMAIL;             //IMAP
    state->port2app[119]   = EMAIL;             //NNTP
    state->port2app[563]   = EMAIL;             //NNTP

    state->port2app[20]    = NETWORK;	// FTP
    state->port2app[21]    = NETWORK;	// FTP
    state->port2app[989]   = NETWORK;	// FTP
    state->port2app[990]   = NETWORK;	// FTP
    state->port2app[53]    = NETWORK;      //DNS
    state->port2app[161]   = NETWORK;          //SNMP
    state->port2app[162]   = NETWORK;          //SNMP
    state->port2app[123]   = NETWORK;          //NTP
    state->port2app[873]   = NETWORK;    	//RSYNC
    state->port2app[1110]  = NETWORK;     //NFS
    state->port2app[2049]  = NETWORK;     //NFS
    state->port2app[135]   = NETWORK;        //NETBIOS
    state->port2app[137]   = NETWORK;        //NETBIOS
    state->port2app[138]   = NETWORK;        //NETBIOS
    state->port2app[139]   = NETWORK;        //NETBIOS
    state->port2app[445]   = NETWORK;        //NETBIOS
    state->port2app[568]   = NETWORK;        //NETBIOS
    state->port2app[569]   = NETWORK;        //NETBIOS
    state->port2app[1512]  = NETWORK;        //NETBIOS
    state->port2app[311]   = NETWORK;        //APPLETALK
    state->port2app[387]   = NETWORK;        //APPLETALK
    state->port2app[548]   = NETWORK;        //APPLETALK

    state->port2app[4662]  = SHARING;              //E_DONKEY
    state->port2app[7070]  = SHARING;              //E_DONKEY
    state->port2app[1214]  = SHARING;              //FASTTRACK
    state->port2app[6346]  = SHARING;              //GNUTELLA
    state->port2app[412]   = SHARING;              //DIRECT_CONNECT
    state->port2app[5000]  = SHARING;              //IMESH_CONTROL
    state->port2app[4329]  = SHARING;              //IMESH_DATA
    state->port2app[6574]  = SHARING;              //ROMNET
    state->port2app[8311]  = SHARING;              //SCOUR_EX
    state->port2app[5500]  = SHARING;              //HOTLINE
    state->port2app[5501]  = SHARING;              //HOTLINE
    
    
    /* 
     * process input arguments 
     */
    state->meas_ivl = 1;
    for (i = 0; args && args[i]; i++) { 
	if (strstr(args[i], "interval")) {
	    char * len = index(args[i], '=') + 1;
	    state->meas_ivl = atoi(len); 
	} 
    }
	 
    /* 
     * our input stream needs to contain the port numbers and 
     * a packet length. for the timestamp, we use a default value of 
     * one second or whatever we receive from configuration 
     */ 
    
    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = TIME2TS(state->meas_ivl, 0);
    
    pkt = metadesc_tpl_add(inmd, "none:none:none:~tcp");
    N16(TCP(src_port)) = 0xffff;
    N16(TCP(dst_port)) = 0xffff;
    
    /* setup outdesc */
    outmd = metadesc_define_out(self, 0);
    outmd->ts_resolution = TIME2TS(state->meas_ivl, 0);
    outmd->flags = META_PKT_LENS_ARE_AVERAGED;
    
    pkt = metadesc_tpl_add(outmd, "como:none:~ip:none");
    IP(vhl) = 0xff;
    IP(proto) = 0xff;
    
    /* create packet template used in replay function */
    pkt = (pkt_t *) state->template; 
    COMO(caplen) = sizeof(struct _como_iphdr);
    COMO(len) = COMO(caplen);
    COMO(type) = COMOTYPE_COMO;
    COMO(l2type) = 0;
    COMO(l2ofs) = 0;
    COMO(l3type) = ETHERTYPE_IP;
    COMO(l3ofs) = 0;
    COMO(l4ofs) = sizeof(struct _como_iphdr);
    COMO(l7ofs) = COMO(l4ofs);
    COMO(payload) = state->template + sizeof(pkt_t);
    IP(vhl) = 0x45;
    IP(proto) = IPPROTO_TCP;
    
    
#if 0
    /* setup indesc */
    indesc = flowdesc_new("option1", "option2");
    indesc->ts_resolution = TIME2TS(meas_ivl, 0);

    pkt = flowdesc_tpl_add(&indesc, "any:any:~ip:~tcp");
/*    			   COMOTYPE_ANY, 0
    			   LINKTYPE_ANY, 0
    			   ETHERTYPE_IP, 1
    			   IPPROTO_TCP,  1);*/

    COMO(caplen) = sizeof(_como_iphdr) + sizeof(_como_tcphdr);
    N16(IP(len)) = 0xffff;
    N16(TCP(src_port)) = 0xffff;
    N16(TCP(dst_port)) = 0xffff;

    pkt = flowdesc_tpl_add(&indesc,
    			   COMOTYPE_ANY,
    			   LINKTYPE_ANY,
    			   ETHERTYPE_IP,
    			   IPPROTO_UDP);

    COMO(caplen) = sizeof(_como_iphdr) + sizeof(_como_udphdr);
    N16(IP(len)) = 0xffff;
    N16(UDP(src_port)) = 0xffff;
    N16(UDP(dst_port)) = 0xffff;


    /* free desc */
    flowdesc_free(indesc);

    /* pktoption writer */
    myopt_t myopt;
    COMO(pktopts) = buf + sizeof(pkt_t);
    pktoption_set_with_name(pkt, "option1", &myopt, sizeof(myopt));
    COMO(payload) = (char *) pkt + pkt->caplen + pkt->pktoptslen;

    /* pktoption reader */
    myopt_t *myopt;
    uint32_t myoptlen;
    pktoption_get_with_name(pkt, "option1", &myopt, &myoptlen);
#endif

    STATE(self) = state; 
    return TIME2TS(state->meas_ivl, 0);
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

    return isTCP;
}

static int
update(void * self, pkt_t *pkt, void *fh, int isnew)
{
    STATEDESC * state = STATE(self);
    FLOWDESC *x = F(fh);
    int app; 

    if (isnew) {
	x->ts = TS2SEC(COMO(ts));
        bzero(x->bytes, sizeof(x->bytes)); 
        bzero(x->pkts, sizeof(x->pkts)); 
    }

    app = state->port2app[H16(TCP(src_port))] &
	  state->port2app[H16(TCP(dst_port))];
    if (COMO(type) == COMOTYPE_NF) {
	x->bytes[app] += H64(NF(bytecount)) * (uint64_t) H16(NF(sampling));
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


static ssize_t
store(void * self, void *fh, char *buf)
{
    STATEDESC * state = STATE(self);
    FLOWDESC *x = F(fh);
    int i;
    
    PUTH32(buf, x->ts); 
    for (i = 0; i < APPLICATIONS; i++) 
	PUTH64(buf, x->bytes[APPCODE(i)] / state->meas_ivl);
    for (i = 0; i < APPLICATIONS; i++) 
	PUTH32(buf, x->pkts[APPCODE(i)] / state->meas_ivl);
    return sizeof(app_t);
}

static size_t
load(__unused void * self, char * buf, size_t len, timestamp_t * ts)
{
    if (len < sizeof(app_t)) {
        ts = 0;
        return 0; 
    }

    *ts = TIME2TS(ntohl(((app_t *)buf)->ts), 0);
    return sizeof(app_t);
}


#define PRETTYHDR               \
    "Date                     " \
    "  Web (bytes/pkts)"	\
    "          Terminal"	\
    "             Email" 	\
    "           Network"	\
    "            Stream"	\
    "             Games"	\
    "               P2P"	\
    "           Unknown\n"

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
    "plot \"-\" using 1:14 with filledcurve x1 title \"Unknown\" lw 5,"	\
    "     \"-\" using 1:12 with filledcurve x1 title \"P2P\" lw 5,"	\
    "     \"-\" using 1:10 with filledcurve x1 title \"Games\" lw 5,"	\
    "     \"-\" using 1:8 with filledcurve x1 title \"Stream\" lw 5,"	\
    "     \"-\" using 1:6 with filledcurve x1 title \"Email\" lw 5,"	\
    "     \"-\" using 1:4 with filledcurve x1 title \"Network\" lw 5,"	\
    "     \"-\" using 1:2 with filledcurve x1 title \"Web\" lw 5;\n"	

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
    static app_t values;
    STATEDESC * state = STATE(self);
    app_t * x; 
    int i; 

    if (buf == NULL && args != NULL) { 
	int n; 

	/* default is pretty printing */
	*len = sprintf(s, PRETTYHDR);  
	fmt = PRETTYFMT;

        /* first call of print, process the arguments and return */
        for (n = 0; args[n]; n++) {
            if (!strcmp(args[n], "format=plain")) {
                *len = 0; 
                fmt = PLAINFMT;
            } else if (!strcmp(args[n], "format=pretty")) {
	        *len = sprintf(s, PRETTYHDR);  
                fmt = PRETTYFMT;
            } else if (!strcmp(args[n], "format=gnuplot")) {
                *len = sprintf(s, GNUPLOTHDR, "Mbps", "*"); 
                fmt = GNUPLOTFMT;
		isrelative = 0; 
            } else if (!strcmp(args[n], "format=gnuplot-relative")) {
                *len = sprintf(s, GNUPLOTHDR, "Percentage", "100"); 
                fmt = GNUPLOTFMT;
		isrelative = 1; 
            } else if (!strncmp(args[n], "granularity=", 10)) {
                char * val = index(args[n], '=') + 1;

                /* aggregate multiple records into one to reduce
                 * communication messages.
                 */
                granularity = MAX(atoi(val) / state->meas_ivl, 1);   
            } 
        } 

	bzero(&values, sizeof(app_t));

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
	
    x = (app_t *) buf; 

    /* aggregate records if needed */
    values.ts = ntohl(x->ts);
    for (i = 0; i < APPLICATIONS; i++) { 
        values.bytes[i] += NTOHLL(x->bytes[i]); 
	values.pkts[i] += ntohl(x->pkts[i]); 
    }

    no_records++;
    if (no_records % granularity != 0) {
        *len = 0;
        return s;
    }

    for (i = 0; i < APPLICATIONS; i++) { 
        values.bytes[i] /= granularity;
	values.pkts[i] /= granularity;
    }

    if (fmt == PRETTYFMT) { 
	*len = sprintf(s, fmt, asctime(localtime((time_t *)&values.ts))); 
	for (i = 0; i < APPLICATIONS; i++) 
	    *len += sprintf(s + *len, "%8llu %8u ", 
			    values.bytes[i], values.pkts[i]);
    } else if (fmt == PLAINFMT) {  
	*len = sprintf(s, fmt, values.ts) ; 
	for (i = 0; i < APPLICATIONS; i++) 
	    *len += sprintf(s + *len, "%8llu %8u ", 
			    values.bytes[i], values.pkts[i]);
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
	*len = sprintf(s, "%u ", values.ts) ; 

	for (i = 0; i < APPLICATIONS; i++) {
	    bytessum += values.bytes[i]; 
	    pktssum += values.pkts[i]; 
	}
	
	/* now print the values */
	for (i = 0; i < APPLICATIONS - 1; i++) { 
	    bytes += (100 * (float) values.bytes[i]) / bytessum; 
	    pkts += (100 * (float) values.pkts[i]) / pktssum; 
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
	*len = sprintf(s, "%u ", values.ts) ; 

	/* now print the values */
	for (i = 0; i < APPLICATIONS; i++) { 
	    mbps += (((float) values.bytes[i]) * 8.0 / 1000000.0); 
	    pkts += values.pkts[i]; 
	    *len += sprintf(s + *len, "%.2f %u ", mbps, pkts); 
	}
    } 

    /* reset the values */
    bzero(&values, sizeof(app_t));

    *len += sprintf(s + *len, "\n"); 
    return s;
}

static int
replay(void * self, char *buf, char *out, size_t * len, int *count)
{
    static int npkts = 0; 
    STATEDESC * state = STATE(self);
    pkt_t * pkt; 
    size_t out_len; 
    size_t plen; 
    
    pkt = (pkt_t *) state->template; 
    plen = COMO(caplen) + sizeof(pkt_t);

    if (*len < plen) 
        return -1;
    
    /* 
     * if there are no pending packets, this must be a new record. 
     * build the template accordingly. 
     */
    if (npkts == 0) { 
	app_t * app = (app_t *) buf;
	timestamp_t ts; 
	int nbytes; 
	int i; 
	struct _como_iphdr *iph = (struct _como_iphdr *)(COMO(payload) +
							 COMO(l3ofs));
	nbytes = 0; 
	for (i = 0; i < APPLICATIONS; i++) { 
	    npkts += ntohl(app->pkts[i]); 
	    nbytes += NTOHLL(app->bytes[i]); 
	} 
	if (npkts > 0)
            N16(iph->len) = htons((uint16_t) (nbytes / npkts));
	ts = TIME2TS(ntohl(app->ts), 0);
	COMO(ts) = ts;
        *count = npkts;
    }
    
    for (out_len = 0; out_len < *len && npkts > 0; npkts--) { 
	COMO(payload) = out + out_len + sizeof(pkt_t);
	bcopy(state->template, out + out_len, sizeof(pkt_t) + COMO(caplen));
	out_len += sizeof(pkt_t) + COMO(caplen);
    } 
    
    *len = out_len; 
    *count -= npkts;
    return npkts; 
}


callbacks_t callbacks = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0, 
    st_recordsize: sizeof(app_t),
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
    formats: "plain pretty gnuplot gnuplot-relative",
};
