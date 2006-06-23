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

#define USE_SRC     1
#define USE_DST     2
#define USE_SPORT   4
#define USE_DPORT   8
#define USE_PROTO  16

#define CONFIGDESC   struct _flow_counter_config
CONFIGDESC {
    int  meas_ivl; /* measurement interval */
    size_t bitmap_size; /* size of bitmaps, the higher the more accurate */
    uint32_t mask;
    int flow_fields;
    uhash_t hfunc; /* universal hash function */
};

struct bitmap_size_descr {
    size_t size;
    size_t max_unique_keys;
    
};

static timestamp_t
init(void * self, char * args[])
{
    CONFIGDESC *config;
    metadesc_t *inmd;
    pkt_t *pkt;
    int i;

    /*
     * We will be selecting the size of the bitmap depending on the max
     * amount of unique keys the user expects. The following table provides,
     * given the maximum expected number of unique keys, the bitmap size
     * required to count with at most 1% of error.
     *
     * Bitmap sizes must be (in our implementation) a power of 2.
     */
    struct bitmap_size_descr bitmap_sizes[] = {
        { 1<<13,      10869u },
        { 1<<14,      46382u },
        { 1<<15,     134190u },
        { 1<<16,     342020u },
        { 1<<17,     819660u },
        { 1<<18,    1894900u },
        { 1<<19,    4278600u },
        { 1<<20,    9502100u },
        { 1<<21,   20844000u },
        { 1<<22,   45289000u },
        { 1<<23,   97654000u },
        { 1<<24,  209250000u },
        { 1<<25,  446030000u },
        { 1<<26,  946540000u },
        { 1<<27, 2001000000u },
        { 1<<28, 4216000000u },
        { 0, 0 }
    };

    config = mem_mdl_malloc(self, sizeof(CONFIGDESC));
    config->meas_ivl = 1;
    config->bitmap_size = 1 << 18; /* by default up to 2+e06 unique keys */
    config->mask = config->bitmap_size - 1;
    config->flow_fields = 0;
    uhash_initialize(&config->hfunc);

    /*
     * parse input arguments
     */
    for (i = 0; args && args[i]; i++) {
        char * value;

        value = index(args[i], '=') + 1;

#define have_kw(string, keyword) \
        (! strncmp(string, keyword, sizeof(keyword) - 1))

        if (have_kw(args[i], "interval")) {
            config->meas_ivl = atoi(value);
        } else if (have_kw(args[i], "flowdef")) {
            config->flow_fields |= strstr(value, "src_ip") ? USE_SRC : 0;
            config->flow_fields |= strstr(value, "dst_ip") ? USE_DST : 0;
            config->flow_fields |= strstr(value, "src_port") ? USE_SPORT : 0;
            config->flow_fields |= strstr(value, "dst_port") ? USE_DPORT : 0;
            config->flow_fields |= strstr(value, "proto") ? USE_PROTO : 0;
        } else if (have_kw(args[i], "maxflows")) {
            size_t keys = strtoul(value, NULL, 0);
            int j;
            
            for (j = 0; bitmap_sizes[j].size != 0; j++)
                if (bitmap_sizes[j].max_unique_keys > keys)
                    break;

            if (bitmap_sizes[j].size == 0)
                j -= 1; /* XXX issue a warning to the user? cannot handle
                         * that many keys
                         */

            config->bitmap_size = bitmap_sizes[j].size;
            config->mask = config->bitmap_size - 1;
        }
#undef has_kw
    }

    /*
     * if the user did not define the concept of flow then
     * pick the 5-tuple as a safe default.
     */
    if (config->flow_fields == 0)
        config->flow_fields = USE_SRC | USE_DST | USE_SPORT | USE_DPORT |
            USE_PROTO;

    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = TIME2TS(config->meas_ivl, 0);

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

    CONFIG(self) = config;
    return TIME2TS(config->meas_ivl, 0);
}

static int
update(void * self, pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);
    CONFIGDESC * config = CONFIG(self);
    STATE *st = FSTATE(self);
    uint32_t hash;

    if (isnew)
	x->ts = TS2SEC(pkt->ts);

    uhash_restart(&config->hfunc); /* prepare to hash data */

    /*
     * incrementally hash relevant fields
     */
    if (config->flow_fields & USE_SRC)
        hash = uhash(&config->hfunc, (uint8_t *) &IP(src_ip), 4);
    if (config->flow_fields & USE_DST)
        hash = uhash(&config->hfunc, (uint8_t *) &IP(dst_ip), 4);
    if (config->flow_fields & USE_PROTO)
        hash = uhash(&config->hfunc, (uint8_t *) &IP(proto), 1);
    if (config->flow_fields & USE_SPORT) {
        if (isTCP)
            hash = uhash(&config->hfunc, (uint8_t *) &TCP(src_port), 2);
        else if (isUDP)
            hash = uhash(&config->hfunc, (uint8_t *) &UDP(src_port), 2);
    }
    if (config->flow_fields & USE_DPORT) {
        if (isTCP)
            hash = uhash(&config->hfunc, (uint8_t *) &TCP(dst_port), 2);
        else if (isUDP)
            hash = uhash(&config->hfunc, (uint8_t *) &UDP(dst_port), 2);
    }

    set_bit(st->bm, hash & config->mask); /* update bitmap */

    return 0;
}

static void *
flush(void *self)
{
    CONFIGDESC * config = CONFIG(self);
    STATE *st;

    st = mem_mdl_malloc(self, sizeof(STATE));
    st->bm = mdl_new_bitmap(self, config->bitmap_size);
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
    CONFIGDESC * config = CONFIG(self);
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

