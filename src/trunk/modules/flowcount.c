/*
 * Copyright (c) 2006, Intel Corporation
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
 * Flow counter.
 *
 * Provides a count of the active flows in the measurement interval.
 * The user can decide what the exact definition of a flow is (e.g. the
 * 5-tuple, or the pair of src and dst addresses)
 * 
 * It uses a techinque called "probabilistic counting" (see "A Linear-Time
 * Probabilistic Counting Algorithm for Database applications", by Kyu-Young
 * Whang, Brad T. Vander-Zanden and Howard M. Taylor) to provide an accurate
 * estimation of the number of flows, without the overhead of maintaining
 * per-flow entries in a hash table.
 *
 */

#include <stdio.h>
#include <time.h>
#include <stdlib.h> /* strtoul */
#include "module.h"
#include "bitmap.h"
#include "uhash.h"
#include "comopriv.h"

#define FLOWDESC    struct _flows
FLOWDESC {
    int ts;
};

#define STATE struct _state
STATE {
    bitmap_t *bm; /* bitmap used to estimate number of flows */
};

#define RECORD  struct _flows_record
RECORD {
    int ts;
    uint32_t count;
};

#define USE_SRC     0x01
#define USE_DST     0x02
#define USE_SPORT   0x04
#define USE_DPORT   0x08
#define USE_PROTO   0x10
#define USE_ALL     (USE_SRC|USE_DST|USE_SPORT|USE_DPORT|USE_PROTO)

typedef struct {
    int  meas_ivl; 		/* measurement interval */
    size_t max_keys; 		/* max unique keys we expect */ 
    int flow_fields;
    uhash_t hfunc; 		/* universal hash function */
} config_t;


static timestamp_t
init(void * self, char * args[])
{
    config_t * cf;
    metadesc_t * inmd;
    pkt_t * pkt;
    int i;

    cf = mem_mdl_malloc(self, sizeof(config_t));
    cf->meas_ivl = 1;
    cf->max_keys = 2000000;  	/* by default expect max 2M keys */
    cf->flow_fields = 0;
    uhash_initialize(&cf->hfunc);

    /*
     * parse input arguments
     */
    for (i = 0; args && args[i]; i++) {
        char * value;

        value = index(args[i], '=') + 1;

#define have_kw(string, keyword) \
        (! strncmp(string, keyword, sizeof(keyword) - 1))

        if (have_kw(args[i], "interval")) {
            cf->meas_ivl = atoi(value);
        } else if (have_kw(args[i], "flowdef")) {
            cf->flow_fields |= strstr(value, "src_ip") ? USE_SRC : 0;
            cf->flow_fields |= strstr(value, "dst_ip") ? USE_DST : 0;
            cf->flow_fields |= strstr(value, "src_port") ? USE_SPORT : 0;
            cf->flow_fields |= strstr(value, "dst_port") ? USE_DPORT : 0;
            cf->flow_fields |= strstr(value, "proto") ? USE_PROTO : 0;
        } else if (have_kw(args[i], "maxflows")) {
            cf->max_keys = strtoul(value, NULL, 0);
        }
#undef has_kw
    }

    /*
     * if the user did not define the concept of flow then
     * pick the 5-tuple as a safe default.
     */
    if (cf->flow_fields == 0)
        cf->flow_fields = USE_ALL; 

    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = TIME2TS(cf->meas_ivl, 0);

    pkt = metadesc_tpl_add(inmd, "none:none:~ip:none");
    IP(proto) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;

    pkt = metadesc_tpl_add(inmd, "none:none:~ip:~tcp");
    IP(proto) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    N16(TCP(src_port)) = 0xffff;
    N16(TCP(dst_port)) = 0xffff;
    
    pkt = metadesc_tpl_add(inmd, "none:none:~ip:~udp");
    IP(proto) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    N16(UDP(src_port)) = 0xffff;
    N16(UDP(dst_port)) = 0xffff;

    CONFIG(self) = cf;
    return TIME2TS(cf->meas_ivl, 0);
}

static int
update(void * self, pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);
    config_t * cf = CONFIG(self);
    STATE *st = FSTATE(self);
    uint32_t hash;

    if (isnew)
	x->ts = TS2SEC(pkt->ts);

    /*
     * incrementally hash relevant fields
     */
    if (cf->flow_fields & USE_SRC)
        hash = uhash(&cf->hfunc, (uint8_t *) &IP(src_ip), 4, UHASH_NEW);
    if (cf->flow_fields & USE_DST)
        hash = uhash(&cf->hfunc, (uint8_t *) &IP(dst_ip), 4, UHASH_APPEND);
    if (cf->flow_fields & USE_PROTO)
        hash = uhash(&cf->hfunc, (uint8_t *) &IP(proto), 1, UHASH_APPEND);
    if (cf->flow_fields & USE_SPORT) {
        if (isTCP)
            hash = uhash(&cf->hfunc,(uint8_t*) &TCP(src_port),2,UHASH_APPEND);
        else if (isUDP)
            hash = uhash(&cf->hfunc,(uint8_t*) &UDP(src_port),2,UHASH_APPEND);
    }
    if (cf->flow_fields & USE_DPORT) {
        if (isTCP)
            hash = uhash(&cf->hfunc, (uint8_t *) &TCP(dst_port),2,UHASH_APPEND);
        else if (isUDP)
            hash = uhash(&cf->hfunc, (uint8_t *) &UDP(dst_port),2,UHASH_APPEND);
    }

    set_bit(st->bm, hash);  		/* update bitmap */

    return 0;
}

static void *
flush(void *self)
{
    config_t * cf = CONFIG(self);
    STATE *st;

    st = mem_mdl_malloc(self, sizeof(STATE));
    st->bm = mdl_new_bitmap(self, cf->max_keys);
    return st;
}

static ssize_t
store(void * self, void *rp, char *buf)
{
    FLOWDESC *x = F(rp);
    STATE *st = FSTATE(self);

    PUTH32(buf, x->ts);
    PUTH32(buf, (uint32_t) estimate_unique_keys(st->bm));

    return sizeof(RECORD);
}

static size_t
load(__unused void * self, char * buf, size_t len, timestamp_t * ts)
{
    RECORD *r = (RECORD *) buf;

    if (len < sizeof(RECORD)) {
        ts = 0;
        return 0;
    }

    *ts = TIME2TS(ntohl(r->ts), 0);
    return sizeof(RECORD);
}

#define GNUPLOTHDR                                              \
    "set terminal postscript eps color solid lw 1 \"Helvetica\" 14;"    \
    "set grid;"                                                         \
    "set ylabel \"Active flows\";" 		                        \
    "set xlabel \"Time (HH:MM UTC)\";"                                  \
    "set yrange [0:*];"                                                 \
    "set autoscale xfix;"                                               \
    "set nokey;"                                                        \
    "set xdata time;"                                                   \
    "set timefmt \"%%s\";"                                              \
    "set format x \"%%H:%%M\";"                                         \
    "plot \"-\" using 1:2 with lines lt 3\n" 

#define GNUPLOTFMT      "%u %u\n"

static char *
print(void * self, char *buf, size_t *len, char * const args[])
{
    static char s[2048];
    static int granularity = 1;
    static int count = 0; 
    static int no_records = 0; 
    config_t * config = CONFIG(self);
    RECORD *x; 

    if (buf == NULL && args != NULL) { 
	int n; 

        *len = sprintf(s, GNUPLOTHDR); 

        for (n = 0; args[n]; n++) {
            if (!strncmp(args[n], "granularity=", 10)) {
                char * val = index(args[n], '=') + 1;
 
                /* aggregate multiple records into one to reduce
                 * communication messages.
                 */
                granularity = MAX(atoi(val) / config->meas_ivl, 1);
	    } 
	}

        return s; 
    } 

    if (buf == NULL && args == NULL) { 
        *len = 0; 
        return s; 
    } 

    x = (RECORD *) buf;

    count += ntohl(x->count); 
    no_records++;
    if (no_records % granularity != 0) {
        *len = 0;
        return s;
    }

    count /= granularity; 
    *len = sprintf(s, GNUPLOTFMT, (uint) ntohl(x->ts), count); 
    count = 0; 
    return s;
};

callbacks_t callbacks = {
    ca_recordsize: sizeof(FLOWDESC),
    st_recordsize: sizeof(RECORD), 
    capabilities: {has_flexible_flush: 0, 0},
    init: init,
    check: NULL,
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
    formats: "gnuplot"
};

