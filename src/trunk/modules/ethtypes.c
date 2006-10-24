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
 * Ethtypes module
 *
 * This module computes the number of packets and bytes per ethtype.
 * Output: packets/bytes per ethtype over measurement interval
 *
 */

#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include "module.h"

#define MAX_TYPES		15

#define FLOWDESC    struct _ethtype_stat

FLOWDESC {
    timestamp_t ts;
    uint64_t bytes[MAX_TYPES + 1];
    uint32_t pkts[MAX_TYPES + 1];
};

struct stat {
    uint64_t bytes;
    uint32_t pkts;
};

#define STREC    struct _ethtype_strec

STREC {
    timestamp_t	ts;
    int		count;
    struct stat	stats[MAX_TYPES + 1];
};

#define ETHTYPE_MAX_NAME	22
typedef struct ethtype {
    uint16_t	code;
    char	name[ETHTYPE_MAX_NAME];
} ethtype_t;

#define CONFIGDESC   struct _ethtype_config
CONFIGDESC {
    int		meas_ivl;	/* measurement interval */
    int		types_count;
    ethtype_t *	types_ltbl;	/* types lookup table, ideally a binary search
				   tree */
};

static timestamp_t
init(void * self, char *args[])
{
    CONFIGDESC *config;
    int i;
    pkt_t *pkt;
    metadesc_t *inmd;

    config = mem_mdl_calloc(self, 1, sizeof(CONFIGDESC));
    config->meas_ivl = 1;
    
    /* create the type lookup table */
    config->types_ltbl = mem_mdl_calloc(self, MAX_TYPES + 1,
					sizeof(ethtype_t));
    
    /* 
     * process input arguments 
     */
    for (i = 0; args && args[i]; i++) {
	if (strstr(args[i], "interval")) {
	    char *val = index(args[i], '=') + 1;
	    config->meas_ivl = atoi(val);
	} else if (strstr(args[i], "ethtype ")) { 
	    char *val;
	    int base;
	    uint16_t type;
	    ethtype_t *t;
	    char *name;
	    int namelen;
	    
	    /* silently ignore more than MAX_TYPES types */ 
	    if (config->types_count >= MAX_TYPES)
		continue;
	    
	    val = index(args[i], '=') + 1;
	    while (*val && isspace (*val)) val++;
	    if (val[0] == '0' && val[1] == 'x')
		base = 16;
	    else
		base = 10;
	    
	    type = strtol(val, NULL, base);
	    
	    namelen = (val - 2) - (args[i] + 8);
	    name = strndup(args[i] + 8, namelen);
	    strchug(strchomp(name));
	    
	    t = &config->types_ltbl[config->types_count];
	    t->code = type;
	    strncpy(t->name, name, ETHTYPE_MAX_NAME);
	    
	    free(name);
	    
	    config->types_count++; 
	}
    }
    
    if (config->types_count == 0) {
	/* add some default */
	ethtype_t *t;
	t = &config->types_ltbl[0];
	t->code = ETHERTYPE_IP;
	sprintf(t->name, "IP");
	t = &config->types_ltbl[1];
	t->code = ETHERTYPE_ARP;
	sprintf(t->name, "ARP");
	t = &config->types_ltbl[2];
	t->code = ETHERTYPE_IPV6;
	sprintf(t->name, "IPv6");
	
	config->types_count = 3;
    }
    
    /* other types */
    config->types_ltbl[config->types_count].code = 0;
    sprintf(config->types_ltbl[config->types_count].name, "Other");
    config->types_count++;
    
    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = TIME2TS(config->meas_ivl, 0);

    pkt = metadesc_tpl_add(inmd, "none:~eth:none:none");
    N16(ETH(type)) = 0xffff;
    
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = TIME2TS(config->meas_ivl, 0);

    pkt = metadesc_tpl_add(inmd, "none:~vlan:none:none");
    N16(VLAN(ethtype)) = 0xffff;

    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = TIME2TS(config->meas_ivl, 0);

    pkt = metadesc_tpl_add(inmd, "none:~hdlc:none:none");
    N16(HDLC(type)) = 0xffff;

    CONFIG(self) = config; 
    return TIME2TS(config->meas_ivl, 0);
}

static int
update(void * self, pkt_t *pkt, void *fh, int isnew)
{
    CONFIGDESC *config = CONFIG(self);
    FLOWDESC *x = F(fh);
    int i;
    ethtype_t *t = config->types_ltbl;

    if (isnew) {
	x->ts = pkt->ts;
        memset(x->bytes, 0, sizeof(x->bytes));
        memset(x->pkts, 0, sizeof(x->pkts));
    }

    for (i = 0; t[i].code != COMO(l3type) && i < config->types_count - 1; i++)
	;
    x->bytes[i] += COMO(len); 
    x->pkts[i]++;

    return 0;
}


static ssize_t
store(__unused void * self, void *fh, char *buf)
{
    CONFIGDESC *config = CONFIG(self);
    FLOWDESC *x = F(fh);
    int i;
    
    PUTH64(buf, x->ts);
    PUTH32(buf, config->types_count);
    for (i = 0; i < config->types_count; i++) {
        PUTH64(buf, x->bytes[i]);
        PUTH32(buf, x->pkts[i]);
    }

    return 12 + (12 * config->types_count);
}

static size_t
load(__unused void * self, char * buf, size_t len, timestamp_t * ts)
{
    size_t sz;
    STREC *x = (STREC *) buf;
    
    sz = ntohl(x->count);
    
    if (len < sz) {
        *ts = 0;
        return 0;
    }

    *ts = NTOHLL(x->ts);
    return 12 + (12 * sz);
}



#define PRINT_PLAIN		0
#define PRINT_PRETTY		1
#define PRINT_GNUPLOT		2


/* 
 * Gnuplot 4.0 format. 
 * 
 * By default, this module will only plot the graph for TCP, UDP, ICNP and
 * ESP. All other protocols are considered in the OTHER column. 
 * If a user desires to see the other protocols then it can send a query 
 * with the option "include=<proto-number>" that would force print() to 
 * add one line to the graph. 
 * 
 * Note that in gnuplot format we only consider the contribution of each
 * protocol in bytes. 
 * 
 */

#define GNUPLOTHDR                                                      \
    "set terminal postscript eps color solid lw 1 \"Helvetica\" 14;"    \
    "set grid;"                                                         \
    "set ylabel \"Percentage\";"                                        \
    "set xlabel \"Time (H:M UTC)\";"                                    \
    "set yrange [0:100];"                                               \
    "set autoscale xfix;"                                               \
    "set key outside;"                                                  \
    "set xdata time;"                                                   \
    "set timefmt \"%%s\";"                                              \
    "set format x \"%%H:%%M\";"                                         
    
#define GNUPLOTFOOTER   "e\n"

#define QUERYSTATE	struct ethtypes_query
QUERYSTATE {
    int fmt;
    int granularity;
    int no_records;
    char str[8192];
    STREC strec;
};


/* 
 * -- do_header 
 * 
 * just to print header information  
 */
static size_t 
do_header(char * const args[], QUERYSTATE * qs, CONFIGDESC * config) 
{
    size_t len = 0; 
    int n;
    
    qs->granularity = 1;

    /* first call of print, process the arguments and return */
    for (n = 0; args[n]; n++) {
	if (!strcmp(args[n], "format=plain")) {
	    len = 0;
	    qs->fmt = PRINT_PLAIN;
	} else if (!strcmp(args[n], "format=pretty")) {
	    len = 0; 
	    qs->fmt = PRINT_PRETTY;
	} else if (!strcmp(args[n], "format=gnuplot")) {
	    qs->fmt = PRINT_GNUPLOT;
	} else if (!strncmp(args[n], "granularity=", 12)) {
	    char *val = index(args[n], '=') + 1;
	    int gr = atoi(val) / config->meas_ivl;

	    /* aggregate multiple records into one to reduce
	     * communication messages.
	     */
	    qs->granularity = MAX(gr, 1);
	}
    }

    if (qs->fmt == PRINT_GNUPLOT) {
	ethtype_t *t = config->types_ltbl;
	/* 
	 * we need to print the header but make sure that we 
	 * include/exclude all protocols. 
	 */
	len = sprintf(qs->str, GNUPLOTHDR);

	len += sprintf(qs->str + len,
		       "plot \"-\" using 1:%d with filledcurve x1 "
		       "title \"Other\" lw 5",
		       config->types_count + 1);
	for (n = config->types_count - 2; n >= 0; n--) {
	    len += sprintf(qs->str + len,
		           ",\"-\" using 1:%d with filledcurve x1 "
		           "title \"%s (%d)\" lw 5",
		           n + 2, t[n].name, t[n].code);
	}

	len += sprintf(qs->str + len, ";\n"); 
    } else if (qs->fmt == PRINT_PRETTY) {
	ethtype_t *t = config->types_ltbl;
	len = sprintf(qs->str, "Timestamp               ");
	for (n = 0; n < config->types_count; n++) {
	    len += sprintf(qs->str + len, " %s Bytes [%%] Pkts [%%]",
		           t[n].name);
	}

	len += sprintf(qs->str + len, "\n"); 
    }

    return len; 
}


static size_t 
print_plain(QUERYSTATE * qs, CONFIGDESC * config) 
{
    size_t len; 
    int i;

    len = sprintf(qs->str, "%12u.%06u ", 
		  (uint) TS2SEC(qs->strec.ts), 
		  (uint) TS2USEC(qs->strec.ts));
    for (i = 0; i < qs->strec.count; i++) 
	len += sprintf(qs->str + len, "0x%04x %8llu %8u ", 
		       config->types_ltbl[i].code,
		       qs->strec.stats[i].bytes,
		       qs->strec.stats[i].pkts);
    len += sprintf(qs->str + len, "\n"); 
    return len; 
}
	

static size_t 
print_pretty(QUERYSTATE * qs, __unused CONFIGDESC * config) 
{
    time_t ts; 
    size_t len; 
    uint64_t bytes_all, pkts_all;
    float bytes_prct, pkts_prct; 
    int i;

    ts = (time_t) TS2SEC(qs->strec.ts);
    len = sprintf(qs->str, "%.24s ", asctime(localtime(&ts)));

    /* compute the sums of all bytes and packets */
    bytes_all = pkts_all = 0; 
    for (i = 0; i < qs->strec.count; i++) { 
	bytes_all += qs->strec.stats[i].bytes;
	pkts_all += qs->strec.stats[i].pkts;
    } 

    if (bytes_all == 0) 
	return 0; 

    /* compute the sums of all bytes and packets of interest */
    for (i = 0; i < qs->strec.count; i++) { 
	bytes_prct = 100.0 * (float) qs->strec.stats[i].bytes / bytes_all;
	pkts_prct = 100.0 * (float) qs->strec.stats[i].pkts / pkts_all;

	len += sprintf(qs->str + len, "        %5.2f %5.2f ",	
		       bytes_prct, pkts_prct);
    }

    return len;
}


static size_t
print_gnuplot(QUERYSTATE * qs, __unused CONFIGDESC * config) 
{
    size_t len; 
    uint64_t bytes_all;
    float bytes_sofar; 
    float bytes_prct; 
    int i;

    len = sprintf(qs->str, "%u ", (uint32_t) TS2SEC(qs->strec.ts)); 

    /* compute the sums of all bytes and packets */
    bytes_all = 0; 
    for (i = 0; i < qs->strec.count; i++) 
	bytes_all += qs->strec.stats[i].bytes;

    if (bytes_all == 0) 
	return 0; 

    /* compute the sums of all bytes and packets of interest */
    bytes_sofar = 0; 
    for (i = 0; i < qs->strec.count; i++) { 
	bytes_prct = 100 * (float) qs->strec.stats[i].bytes / bytes_all;
	len += sprintf(qs->str + len, "%5.2f ", bytes_sofar + bytes_prct); 
	bytes_sofar += bytes_prct; 
    } 

    len += sprintf(qs->str + len, "\n"); 

    return len;
}


static char *
print(void * self, char * buf, size_t * len, char * const args[])
{
    CONFIGDESC * config = CONFIG(self);
    STREC *x;
    int i;
    static QUERYSTATE qs;
    
    if (buf == NULL && args != NULL) {
	memset(&qs, 0, sizeof(QUERYSTATE));
	*len = do_header(args, &qs, config);
	return qs.str;
    } 

    if (buf == NULL && args == NULL) {
        *len = 0;
        if (qs.fmt == PRINT_GNUPLOT)
            *len = sprintf(qs.str, GNUPLOTFOOTER);
        return qs.str;
    }

    x = (STREC *) buf;
    qs.strec.ts = NTOHLL(x->ts);
    qs.strec.count = ntohl(x->count);

    /* aggregate records if needed */
    for (i = 0; i < qs.strec.count; i++) { 
	qs.strec.stats[i].bytes += NTOHLL(x->stats[i].bytes); 
	qs.strec.stats[i].pkts += ntohl(x->stats[i].pkts); 
    }

    qs.no_records++;
    if (qs.no_records % qs.granularity != 0) {
        *len = 0;
        return qs.str;
    }
    if (qs.granularity != 1) {
	for (i = 0; i < qs.strec.count; i++) {
	    qs.strec.stats[i].bytes /= qs.granularity; 
	    qs.strec.stats[i].pkts /= qs.granularity;
	}
    }

    if (qs.fmt == PRINT_PLAIN) 
	*len = print_plain(&qs, config); 
    else if (qs.fmt == PRINT_PRETTY) 
	*len = print_pretty(&qs, config); 
    else if (qs.fmt == PRINT_GNUPLOT) 
	*len = print_gnuplot(&qs, config); 

    return qs.str;
};


MODULE(ethtypes) = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0,
    st_recordsize: sizeof(STREC),
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
    formats: "plain pretty gnuplot"
};

