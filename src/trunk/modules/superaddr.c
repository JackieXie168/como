/*
 * Copyright (c) 2007 Universitat Politecnica de Catalunya
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
 * Super Sources and Destinations detection module. Based on
 * "Detection of Super Sources and Destinations in High-Speed
 * Networks: Algorithms, Analysis and Evaluation" by Qi Zhao
 * et al.
 * 
 * This module mantains a meter of the number of destinations
 * per source or vice versa.
 */

#include <stdio.h>
#include <time.h>
#include <assert.h>

#include "module.h"
#include "printpkt.h"
#include "uhash.h"
#include "hash.h"
#include "bitmap.h"

#define FLOWDESC    struct _saddr_fd
FLOWDESC{
    timestamp_t ts;             /* timestamp */
    uint32_t ip_addr;           /* ip address */
    double meter;               /* number of sources/destinations */
};

#define EFLOWDESC   struct _saddr_efd
EFLOWDESC {
    uint32_t stamp;             /* timestamp */
    uint32_t ip_addr;           /* ip address */
    double meter;               /*  number of sources/destinations */
};

#define DISK_RECORD   struct _saddr_disk
DISK_RECORD {
    uint32_t stamp;             /* timestamp */
    uint32_t ip_addr;           /* ip address */
    uint32_t meter;             /* number of sources/destinations */
};


#define CONFIGDESC    struct _saddr_config
CONFIGDESC{
    uint32_t meas_ivl;          /* measurement interval (secs) */
    uint32_t last_export;       /* last export time */
    int use_dst;                /* reporting sources or destinations */
    uhash_t hfunc;              /* universal hash function */
    uint32_t threshold;         /* minimum number of src's/dst's to consider
                                   an ip address as a supersrc/superdst */
    uint32_t mask;              /* privacy mask */
};

#define STATE struct _state
STATE {
    bitmap_t *bm;               /* bitmap used to estimate number of flows */
};

#define UNIQUE_ELEMENTS 1894900u


/*
 * -- init
 */
static timestamp_t
init(void *self, char *args[])
{
    int i;
    pkt_t * pkt; 
    metadesc_t *inmd;
    CONFIGDESC * config;

    /*
     * set default configuration values
     */
    config = mem_mdl_calloc(self, 1, sizeof(CONFIGDESC));
    config->meas_ivl = 5;
    config->last_export = 0;
    config->use_dst = 0;
    config->threshold = 15;
    config->mask = ~0;

    /*
     * process input arguments
     */
    for (i = 0; args && args[i]; i++) {  
        char *x;

        x = index(args[i], '=') + 1; 
        
        if (strstr(args[i], "use_dst"))
            config->use_dst = 1;
        else if (strstr(args[i], "use_src"))
            config->use_dst = 0;
        else if (strstr(args[i], "interval"))
            config->meas_ivl = atoi(x);
        else if (strstr(args[i], "threshold"))
            config->threshold = atoi(x);
        else if (strstr(args[i], "mask"))
            config->mask = (uint32_t) strtoll(x, NULL, 0);
    }

    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = TIME2TS(config->meas_ivl, 0);

    pkt = metadesc_tpl_add(inmd, "none:none:~ip:none");
    IP(proto) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;

    pkt = metadesc_tpl_add(inmd, "none:none:~ip:~tcp");
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;

    pkt = metadesc_tpl_add(inmd, "none:none:~ip:~udp");
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;

    CONFIG(self) = config; 

    /* initialize hash function */
    uhash_initialize(&config->hfunc);

    return TIME2TS(config->meas_ivl, 0);
}

/*
 * -- check
 */
static int
check(void * self, pkt_t * pkt) 
{
    CONFIGDESC * config = CONFIG(self);
    int bit_value;
    uint32_t h;
    STATE * state = FSTATE(self);

    /* source and destination ip addresses  hash */
    h = uhash(&config->hfunc, (uint8_t *) &IP(src_ip), 4, UHASH_NEW);
    h = uhash(&config->hfunc, (uint8_t *) &IP(dst_ip), 4, UHASH_APPEND);
    bit_value = test_and_set_bit(state->bm, h);

    if (bit_value)  /* this flow has already been seen */
        return 0;

    return 1;       /* the flow is new, so we allow the packet to continue */
}

/*
 * -- hash
 */
static uint32_t
hash(void * self, pkt_t *pkt)
{
    CONFIGDESC * config = CONFIG(self);

    if (config->use_dst)
        return uhash(&config->hfunc, (uint8_t *) &IP(dst_ip), 4, UHASH_NEW);

    return uhash(&config->hfunc, (uint8_t *) &IP(src_ip), 4, UHASH_NEW);
}


/*
 * -- match
 */
static int
match(void * self, pkt_t *pkt, void *fh)
{
    FLOWDESC * fd = F(fh);
    CONFIGDESC * config = CONFIG(self);

    if (config->use_dst)
        return H32(IP(dst_ip)) == fd->ip_addr;
    else
        return H32(IP(src_ip)) == fd->ip_addr;
}


/*
 * -- update
 *
 *  keep updated the capture hash table
 */
static int
update(void *self, pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC * fd = F(fh);
    CONFIGDESC * config = CONFIG(self);
    STATE * state = FSTATE(self);

    if (isnew) {
        fd->ip_addr = config->use_dst? H32(IP(dst_ip)): H32(IP(src_ip));
        fd->ts = pkt->ts;
        fd->meter = 0;
    }

    /* 
     * the load factor of the bitmap serves to estimate how
     * many new flows should be attributed to the addr.
     */
    double load_factor = (double) (get_nbits(state->bm)) / 
                         (double) (count_zeros(state->bm));
    fd->meter += load_factor;

    return 0;
}

/*
 * -- flush
 */
static void *
flush(void *self)
{
    CONFIGDESC * config = CONFIG(self);
    STATE *st;

    uhash_initialize(&config->hfunc);
    st = mem_mdl_malloc(self, sizeof(STATE));
    st->bm = mdl_new_bitmap(self, UNIQUE_ELEMENTS);
    return st;
}

/*
 * -- ematch
 */
static int
ematch(void *self, void *efh, void *fh)
{
    CONFIGDESC * config = CONFIG(self);
    FLOWDESC * fd = F(fh);
    EFLOWDESC * efd = EF(efh);

    return efd->ip_addr == fd->ip_addr;
}


/*
 * -- export
 *
 *  keep updated the export hash table
 */
static int
export(void * self, void *efh, void *fh, int isnew)
{
    FLOWDESC *fd = F(fh);
    EFLOWDESC *efd = EF(efh);

    if (isnew) {
        bzero(efd, sizeof (EFLOWDESC));
        efd->ip_addr = fd->ip_addr;
    }
    efd->meter += fd->meter;

    return 0;
}

/*
 * -- compare
 *
 *  the records are sorted by number of srcs/dsts
 */
static int
compare(const void *efh1, const void *efh2)
{
    EFLOWDESC *efd1 = CMPEF(efh1);
    EFLOWDESC *efd2 = CMPEF(efh2);

    if (efd1->meter > efd2->meter)
        return -1;
    if (efd1->meter < efd2->meter)
        return 1;

    return 0;
}

/*
 * -- action
 */
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
            return ACT_STOP;    /* too early */

        config->last_export = TS2SEC(ivl); 
        return ACT_GO;  /* start scanning all the records */
    }

    return (ACT_STORE | ACT_DISCARD);   /* store and discard */ 
}


/*
 * -- store
 */
static ssize_t
store(void *self, void *efh, char *buf)
{
    CONFIGDESC * config = CONFIG(self);
    EFLOWDESC *efd = EF(efh);

    PUTH32(buf, config->last_export);
    PUTH32(buf, efd->ip_addr);
    PUTH32(buf, (uint32_t) efd->meter);

    return sizeof(DISK_RECORD);
}


/*
 * -- load
 */
static size_t
load(void *self, char * buf, size_t len, timestamp_t * ts)
{

    DISK_RECORD * dr =  (DISK_RECORD *) buf;

    if (len < sizeof(DISK_RECORD) ) {
        *ts = 0;
        return 0;
    }

    *ts = TIME2TS(ntohl(dr->stamp), 0);

    return sizeof(DISK_RECORD);
}


#define PRETTY_HDR_SRC_DSTS                                                 \
    "\tTimestamp\t\t\t\tSource IP\t\t\t\t#Destinations\n"

#define PRETTY_HDR_DST_SRCS                                                 \
    "\tTimestamp\t\t\t\tDestination IP\t\t\t\t#Sources\n"


#define HTML_HDR							    \
    "<html>\n"							            \
"<head>\n"                                                                  \
"  <style type=\"text/css\">\n"                                             \
"   body { font-family: \"lucida sans unicode\", verdana, arial;\n"         \
"          font-size: 9pt; margin: 0; padding: 0;}\n"	                    \
"   table, tr, td {background-color: #DDD;\n"		                    \
"     font-family: \"lucida sans unicode\", verdana, arial;\n"              \
"     font-size: 9pt;}\n"				                    \
"   a, a:visited { color: #475677; text-decoration: none;}\n"               \
"   .netviewbar{ \n"                                                        \
"     color :#FFF; width :100%%; padding :2px; text-align:center;}\n"       \
"   .netview {\n"                                                           \
"     top: 0px; width: 100%%; vertical-align:top;\n"                        \
"     margin: 2; padding-left: 5px;\n"                                      \
"     padding-right: 5px; text-align:left;}\n"                              \
"   .nvtitle {\n"                                                           \
"     font-weight: bold; font-size: 9pt; padding-bottom: 3px;\n"            \
"     color: #475677;}\n"                                                   \
"  </style>\n"                                                              \
"</head>\n"                                                                 \
"<body>\n"

#define HTML_TITLE 						            \
    "<div class=nvtitle style=\"border-top: 1px solid;\">"	            \
"Top %s</div>\n"                                                            \
"<table class=netview>\n"					            \
"  <tr class=nvtitle>\n"					            \
"    <td>Position</td>\n" 	                			    \
"    <td>%s</td>\n"					                    \
"    <td>%s</td>\n"					                    \
"  </tr>\n"

#define HTML_FOOTER						            \
    "</table>\n"						            \
"</body></html>\n"

#define HTML_FMT2						            \
    "<tr><tr><td><br></td></tr>"                                            \
"<td>%d</td>"                               	                            \
"<td>%s</td>"                               	                            \
"<td>%u</td></tr>\n"

#define GNUPLOT_HDR						            \
    "set terminal postscript eps color solid lw 1 \"Helvetica\" 14;"        \
"set grid;"                                                                 \
"set ylabel \"%s\";" 		                                            \
"set xlabel \"Time (HH:MM UTC)\";"                                          \
"set yrange [0:*];"                                                         \
"set autoscale xfix;"                                                       \
"set nokey;"                                                                \
"set xdata time;"                                                           \
"set timefmt \"%%s\";"                                                      \
"set format x \"%%H:%%M\";"                                                 \
"plot \"-\" using 1:2 with lines lt 4\n" 

#define GNUPLOT_FOOTER "e\n"

#define SIDEBOX_TITLE 						            \
"<table class=netview>\n"					            \
"  <tr class=nvtitle>\n"					            \
"    <td>Pos</td>\n"						            \
"    <td>%s</td>\n"					                    \
"    <td>%s</td>\n"					                    \
"  </tr>\n"							

static char prettyfmt[] = "\t%u\t\t\t\t%s\t\t\t\t%u\n";
static char plainfmt[] = "\t%u\t\t\t\t%s\t\t\t\t%u\n";
static char gnuplotfmt[] = "%u %u\n"; 
static char htmlfmt[] = "<tr><td>%d</td><td>%s</td><td>%u</td></tr>\n";

/*
 * -- print
 */
static char *
print(void *self, char *buf, size_t *len, char * const args[])
{

    DISK_RECORD * dr = (DISK_RECORD *) buf;
    CONFIGDESC * config = CONFIG(self);
    static char s[64*1024];
    char * header;
    struct in_addr addr;
    time_t ts;
    static time_t last_ts = 0;
    char *t;
    uint32_t meter;
    uint32_t stamp;
    static char * fmt; 
    static int count = 0; 
    static uint32_t super_addrs = 0;
    static uint32_t prev_super_addrs = 0;

    /* first call to print */
    if (buf == NULL && args != NULL) {

        char * what1[] = {"SuperSources", "SuperDestinations"};
        char * what2[] = {"Source IP", "Destination IP"};
        char * what3[] = {"#Destinations", "#Sources"};
        int n;

        /* by default, pretty print */
        if (config->use_dst)
            *len = sprintf(s, PRETTY_HDR_DST_SRCS); 
        else
            *len = sprintf(s, PRETTY_HDR_SRC_DSTS); 

        fmt = prettyfmt; 

        /* first call of print, process the arguments and return */
        for (n = 0; args[n]; n++) {
            if (!strcmp(args[n], "format=plain")) {
                *len = 0; 
                fmt = plainfmt;
            } else if (!strcmp(args[n], "format=html")) {
                *len = sprintf(s, HTML_HDR); 
                *len += sprintf(s + *len, HTML_TITLE, what1[config->use_dst],
                        what2[config->use_dst],
                        what3[config->use_dst]);
                fmt = htmlfmt;
            } else if (!strcmp(args[n], "format=gnuplot")) {
                *len = sprintf(s, GNUPLOT_HDR, what3[config->use_dst]);
                fmt = gnuplotfmt;
            } else if (!strcmp(args[n], "format=sidebox")) {
                *len = sprintf(s, HTML_HDR); 
                *len += sprintf(s + *len, SIDEBOX_TITLE, 
                        what2[config->use_dst],
                        what3[config->use_dst]);
                fmt = htmlfmt;
            }
        } 
        count = 0; 	/* reset count */ 
        return s; 
    }

    /* last call of print */
    if (buf == NULL && args == NULL) { 
        *len = 0;
        if (fmt == htmlfmt) 
            *len = sprintf(s, HTML_FOOTER);
        if (fmt == gnuplotfmt)
            *len = sprintf(s, GNUPLOT_FOOTER);
        count = 0;      /* reset count */
        last_ts = 0; 	/* reset timestamp */ 
        return s; 
    } 

    /* get data from buffer */
    stamp = ntohl(dr->stamp);
    ts = (time_t) stamp;
    t = asctime(localtime(&ts));
    meter = ntohl(dr->meter);
    /* apply the privacy mask */
    addr.s_addr = dr->ip_addr & htonl(config->mask);

    if (ts != last_ts) {
        count = 0; /* reset count */
        prev_super_addrs = super_addrs;
        super_addrs = 0; /* restart the meter of superaddrs for the new ivl */
    }

    last_ts = ts; 

    /* all the outputs are filtered by the config threshold */
    if (meter >= config->threshold){
        count++; 
        super_addrs++;

        if (fmt == plainfmt)
            *len = sprintf(s, fmt, ts, inet_ntoa(addr), meter);
        else if (fmt == prettyfmt)
            *len = sprintf(s, fmt, ts, inet_ntoa(addr), meter);
        else if (fmt == htmlfmt) { 
            if (count == 1)
                *len = sprintf(s, HTML_FMT2, count, inet_ntoa(addr), meter);
            else
                *len = sprintf(s, fmt, count, inet_ntoa(addr), meter);
        } else {
            /* gnuplot format */
            if (prev_super_addrs) {
                *len = sprintf(s, fmt, ts, prev_super_addrs);
                prev_super_addrs = 0;
            }
            else
                *len = 0;
        }
    }

    else 
        *len = 0;

    return s;
}

MODULE(superaddrs) = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: sizeof(EFLOWDESC),
    st_recordsize: sizeof(DISK_RECORD),
    capabilities: {has_flexible_flush: 0, 0},
    init: init,
    check: check,
    hash: hash,  
    match: match,
    update: update,
    flush: flush,
    ematch: ematch,
    export: export,
    compare: compare,
    action: action,
    store: store,
    load: load,
    print: print,
    replay: NULL,
    formats: "plain pretty html gnuplot sidebox"
};

