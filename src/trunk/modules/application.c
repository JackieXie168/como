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
 * .  "granularity = 4"
 * 
 *    specifies the measurement interval. this is used for the output 
 *    description for a packet trace generated by this module. 
 *    the granularity must be equal to min-flush and max-flush. 
 * 
 * Optional arguments for print():
 * 
 * .  "granularity = <number"
 * 
 *    specifies the measurement interval for the data to be returned
 *    by a query. it cannot be below the granularitiy of the measurement
 *    and it results in computing the average across multiple records 
 *    in the database. 
 * 
 *    XXX no checks are done to make sure the database is complete and
 *        does not skip records. this optional argument should be used
 *        we care only when a data reduction is needed (e.g., for plotting
 *        figures with a lower number of data points).
 *
 * 
 */

#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <math.h>

#include "como.h"
#include "module.h"

/*
 * List of known applications
 * Application code means also application priority
 */
#define WEB		0x00
#define TERMINAL	0x01	/* ssh, telnet, etc. */
#define EMAIL		0x03	/* email, news, etc. */
#define NETWORKDATA	0x07	/* dns, ntp, netbios, nfs, ftp, etc. */
#define STREAM		0x0f
#define GAMES		0x1f
#define SHARING		0x3f
#define UNKNOWN		0x7f    

#define APPLICATIONS       8 
#define APPCODE(x)	   ((((uint) 1) << x) - 1) 

#define FLOWDESC    struct _app_stat
FLOWDESC {
    timestamp_t ts;
    uint64_t bytes[UNKNOWN + 1];
    uint64_t pkts[UNKNOWN + 1];
};

/* 
 * this is the data record that we store on disk
 */
typedef struct {
    uint32_t ts;
    uint64_t bytes[APPLICATIONS];
    uint64_t pkts[APPLICATIONS];
} app_t;


/* 
 * packet description and templates for the 
 * replay() callback or to know if we can process
 * the packets from given sniffer
 */
static pktdesc_t indesc, outdesc;
static char template[1024]; 


/* 
 * static variable for the modules. 
 * XXX we should get rid of these to force callbacks to be closures. 
 */
static int meas_ivl = 1; 		/* measurement granularity (secs) */
static uint8_t port2app[65536];		/* mapping port number to app */

static int
init(__unused void *mem, __unused size_t msize, char *args[])
{
    pkt_t * pkt; 
    int i;
    struct _como_iphdr *iph;

    memset(port2app, UNKNOWN, sizeof(port2app));

    /* initialize the port-to-application mapping array */
    port2app[80]    = WEB;
    port2app[443]   = WEB;
    port2app[8080]  = WEB;
    port2app[3128]  = WEB;             // SQUID
    port2app[3130]  = WEB;             // SQUID
    port2app[9090]  = WEB;             // AUTOPROXY 

    port2app[6688]  = SHARING;
    port2app[6697]  = SHARING;
    port2app[6699]  = SHARING;
    port2app[4329]  = SHARING;
    port2app[4444]  = SHARING;
    port2app[5555]  = SHARING;
    port2app[6666]  = SHARING;
    port2app[7777]  = SHARING;
    port2app[6346]  = SHARING;
    port2app[1214]  = SHARING;
    for (i = 4000; i <= 4999; i++) {
        port2app[i] = SHARING;
    }

    port2app[22]    = TERMINAL;         // SSH
    port2app[23]    = TERMINAL;         // TELNET
    port2app[992]   = TERMINAL;         // TELNET

    port2app[25]    = EMAIL;             //SMTP
    port2app[465]   = EMAIL;             //SMTPS
    port2app[109]   = EMAIL;             //POP
    port2app[110]   = EMAIL;             //POP
    port2app[995]   = EMAIL;             //POP
    port2app[143]   = EMAIL;             //IMAP
    port2app[220]   = EMAIL;             //IMAP
    port2app[993]   = EMAIL;             //IMAP
    port2app[119]   = EMAIL;             //NNTP
    port2app[563]   = EMAIL;             //NNTP

    port2app[20]    = NETWORKDATA;	// FTP
    port2app[21]    = NETWORKDATA;	// FTP
    port2app[989]   = NETWORKDATA;	// FTP
    port2app[990]   = NETWORKDATA;	// FTP
    port2app[53]    = NETWORKDATA;      //DNS
    port2app[161]   = NETWORKDATA;          //SNMP
    port2app[162]   = NETWORKDATA;          //SNMP
    port2app[123]   = NETWORKDATA;          //NTP
    port2app[873]   = NETWORKDATA;    	//RSYNC
    port2app[1110]  = NETWORKDATA;     //NFS
    port2app[2049]  = NETWORKDATA;     //NFS
    port2app[135]   = NETWORKDATA;        //NETBIOS
    port2app[137]   = NETWORKDATA;        //NETBIOS
    port2app[138]   = NETWORKDATA;        //NETBIOS
    port2app[139]   = NETWORKDATA;        //NETBIOS
    port2app[445]   = NETWORKDATA;        //NETBIOS
    port2app[568]   = NETWORKDATA;        //NETBIOS
    port2app[569]   = NETWORKDATA;        //NETBIOS
    port2app[1512]  = NETWORKDATA;        //NETBIOS
    port2app[311]   = NETWORKDATA;        //APPLETALK
    port2app[387]   = NETWORKDATA;        //APPLETALK
    port2app[548]   = NETWORKDATA;        //APPLETALK

    port2app[4662]  = SHARING;              //E_DONKEY
    port2app[7070]  = SHARING;              //E_DONKEY
    port2app[1214]  = SHARING;              //FASTTRACK
    port2app[6346]  = SHARING;              //GNUTELLA
    port2app[412]   = SHARING;              //DIRECT_CONNECT
    port2app[5000]  = SHARING;              //IMESH_CONTROL
    port2app[4329]  = SHARING;              //IMESH_DATA
    port2app[6574]  = SHARING;              //ROMNET
    port2app[8311]  = SHARING;              //SCOUR_EX
    port2app[5500]  = SHARING;              //HOTLINE
    port2app[5501]  = SHARING;              //HOTLINE
    
    
    /* 
     * process input arguments 
     */
    if (args != NULL) { 
	for (i = 0; args[i]; i++) { 
	    if (strstr(args[i], "granularity")) {
		char * len; 

		len = index(args[i], '='); 
		len++; 	/* skip '=' */

		meas_ivl = atoi(len); 
	    } 
	}
    } 
	 
    /* 
     * our input stream needs to contain the port numbers and 
     * a packet length. for the timestamp, we use a default value of 
     * one second or whatever we receive from configuration 
     */ 
    bzero(&indesc, sizeof(pktdesc_t));
    indesc.ts = TIME2TS(meas_ivl, 0); 
    indesc.ih.proto = 0xff;
    N16(indesc.ih.len) = 0xffff;
    N16(indesc.tcph.src_port) = 0xffff;
    N16(indesc.tcph.dst_port) = 0xffff;
    
    bzero(&outdesc, sizeof(pktdesc_t));
    outdesc.ts = TIME2TS(meas_ivl, 0);
    outdesc.flags = COMO_AVG_PKTLEN; 
    N16(outdesc.ih.len) = 0xffff;
    
    pkt = (pkt_t *) template; 
    pkt->caplen = sizeof(struct _como_iphdr); 
    pkt->len = pkt->caplen;
    pkt->type = COMOTYPE_NONE; 
    pkt->l3type = ETHERTYPE_IP;
    pkt->l3ofs = 0; 
    pkt->l4ofs = sizeof(struct _como_iphdr);
    pkt->payload = template + sizeof(pkt_t); 
    iph = (struct _como_iphdr *)(pkt->payload + pkt->l3ofs);
    iph->vhl = 0x45; 
    iph->proto = IPPROTO_TCP; 

    return 0;
}


static int
update(pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);
    int app; 

    if (isnew) {
	x->ts = TS2SEC(pkt->ts);
        bzero(x->bytes, sizeof(x->bytes)); 
        bzero(x->pkts, sizeof(x->pkts)); 
    }

    if (pkt->l3type == ETHERTYPE_IP && pkt->l4type == IPPROTO_TCP) {
	app = port2app[H16(TCP(src_port))] & port2app[H16(TCP(dst_port))];
	x->bytes[app] += H16(IP(len));
	x->pkts[app]++;
    }

    return 0;
}


static ssize_t
store(void *fh, char *buf, size_t len)
{
    FLOWDESC *x = F(fh);
    int i;
    
    if (len < sizeof(app_t))
        return -1;

    PUTH32(buf, x->ts); 
    for (i = 0; i < APPLICATIONS; i++) 
	PUTH64(buf, x->bytes[APPCODE(i)] / meas_ivl);
    for (i = 0; i < APPLICATIONS; i++) 
	PUTH64(buf, x->pkts[APPCODE(i)] / meas_ivl);
    return sizeof(app_t);
}

static size_t
load(char * buf, size_t len, timestamp_t * ts)
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
    "set ylabel \"Percentage\";"					\
    "set xlabel \"Time (H:M UTC)\";"					\
    "set yrange [0:100];"						\
    "set autoscale xfix;"						\
    "set key outside;"							\
    "set xdata time;"							\
    "set timefmt \"%%s\";"						\
    "set format x \"%%H:%%M\";"						\
    "plot \"-\" using 1:16 with filledcurve x1 title \"Unknown\"," 	\
    "     \"-\" using 1:14 with filledcurve x1 title \"P2P\","		\
    "     \"-\" using 1:12 with filledcurve x1 title \"Games\","	\
    "     \"-\" using 1:10 with filledcurve x1 title \"Stream\","	\
    "     \"-\" using 1:8 with filledcurve x1 title \"Network\","	\
    "     \"-\" using 1:6 with filledcurve x1 title \"Email\","		\
    "     \"-\" using 1:4 with filledcurve x1 title \"Terminal\","	\
    "     \"-\" using 1:2 with filledcurve x1 title \"Web\";\n"	

#define GNUPLOTFOOTER	"e\n"

#define PRETTYFMT	"%.24s "	/* 24 char to skip \n in asctime() */
#define GNUPLOTFMT	"%ld "
#define PLAINFMT	"%12ld "	

static char *
print(char *buf, size_t *len, char * const args[])
{
    static char s[4096];
    static char * fmt; 
    static int granularity = 1; 
    static int no_records = 0;
    static app_t values;
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
                *len = sprintf(s, GNUPLOTHDR); 
                fmt = GNUPLOTFMT;
            } else if (!strncmp(args[n], "granularity=", 10)) {
                char * val = index(args[n], '=') + 1;

                /* aggregate multiple records into one to reduce
                 * communication messages.
                 */
                granularity = MAX(atoi(val) / meas_ivl, 1);   
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
	values.pkts[i] += NTOHLL(x->pkts[i]); 
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

    if (fmt == PRETTYFMT) 
	*len = sprintf(s, fmt, asctime(localtime((time_t *)&values.ts))); 
    else 
	*len = sprintf(s, fmt, values.ts) ; 

    if (fmt == GNUPLOTFMT) { 
	/* 
	 * in gnuplot we plot the percentage of traffic. 
	 * we compute them here and then output. 
	 */
	float bytessum = 0; 
	float pktssum = 0; 
	float bytes = 0; 
	float pkts = 0; 

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
    } else {
	/* print the value as they are */
	for (i = 0; i < APPLICATIONS; i++) 
	    *len += sprintf(s + *len, "%8llu %8llu ", 
			    values.bytes[i], values.pkts[i]);
    } 

    *len += sprintf(s + *len, "\n"); 
    return s;
}

static int
replay(char *buf, char *out, size_t * len, int *count)
{
    static int npkts = 0; 
    pkt_t * pkt; 
    size_t out_len; 
    size_t plen; 
    
    pkt = (pkt_t *) template; 
    plen = pkt->caplen + sizeof(pkt_t); 

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
	struct _como_iphdr *iph = (struct _como_iphdr *)(pkt->payload +
							 pkt->l3ofs);
	nbytes = 0; 
	for (i = 0; i < APPLICATIONS; i++) { 
	    npkts += NTOHLL(app->pkts[i]); 
	    nbytes += NTOHLL(app->bytes[i]); 
	} 
	if (npkts > 0)
            N16(iph->len) = htons((uint16_t) (nbytes / npkts));
	ts = TIME2TS(ntohl(app->ts), 0);
	pkt->ts = ts; 
        *count = npkts;
    }
    
    for (out_len = 0; out_len < *len && npkts > 0; npkts--) { 
	pkt->payload = out + out_len + sizeof(pkt_t);
	bcopy(template, out + out_len, sizeof(pkt_t) + pkt->caplen); 
	out_len += sizeof(pkt_t) + pkt->caplen; 
    } 
    
    *len = out_len; 
    *count -= npkts;
    return npkts; 
}


callbacks_t callbacks = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0, 
    indesc: &indesc,
    outdesc: &outdesc,
    init: init,
    check: NULL,
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
    replay: replay 
};

