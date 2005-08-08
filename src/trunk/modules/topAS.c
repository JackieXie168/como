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
 * Top-K Autonomous Systems (in bytes). 
 *
 */

#include <stdio.h>
#include <time.h>
#include "como.h"
#include "module.h"

#define TOPN		20
#define MEAS_IVL	3600

#define FLOWDESC	struct _ca_topas
#define EFLOWDESC	FLOWDESC

FLOWDESC {
    uint32_t ts;	
    uint64_t bytes[65536]; 	
    uint64_t pkts[65536]; 
};


static int
update(pkt_t *pkt, void *fh, int isnew, __unused unsigned drop_cntr)
{
    FLOWDESC *x = F(fh);

    if (isnew) {
	bzero(x, sizeof(FLOWDESC)); 
	x->ts = TS2SEC(pkt->ts); 
    }

    x->bytes[H16(NF(src_as))] += H16(IP(len));
    x->bytes[H16(NF(dst_as))] += H16(IP(len));
    x->pkts[H16(NF(src_as))]++;
    x->pkts[H16(NF(dst_as))]++;

    return 0;
}

static int
export(void *efh, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);
    EFLOWDESC *ex = EF(efh);
    int i;

    if (isnew) {
	bzero(ex, sizeof(EFLOWDESC)); 
        ex->ts = x->ts;
    }

    for (i = 0; i < 65536; i++) {
	ex->bytes[i] += x->bytes[i]; 
	ex->pkts[i] += x->pkts[i]; 
    }
    return 0;
}


static int
action(void *efh, timestamp_t current_time, __unused int count)
{
    static uint32_t last_export = 0;

    if (efh == NULL) {
        /*
         * this is the action for the entire table.
         * check if it is time to export the table.
         * if not stop.
         */
        uint32_t ivl = TS2SEC(current_time) - TS2SEC(current_time) % MEAS_IVL;
        if (ivl - last_export < MEAS_IVL)
            return ACT_STOP;            /* too early */

        last_export = ivl;
        return ACT_GO;          /* dump the records */
    }

    return ACT_STORE|ACT_DISCARD; 
}


struct diskrecord { 
    uint32_t ts; 
    uint32_t as; 
    uint64_t bytes; 
    uint64_t pkts; 
}; 

struct sortedas { 
    uint32_t as; 
    uint64_t bytes; 
    uint64_t pkts; 
};

static int
cmp(const void * a, const void * b)
{
    struct sortedas *aa, *bb; 

    aa = (struct sortedas *) a; 
    bb = (struct sortedas *) b; 
    return ((aa->bytes > bb->bytes)? -1 : 1);
}

static ssize_t
store(void *efh, char *buf, size_t len)
{
    EFLOWDESC *ex = EF(efh);
    struct sortedas asval[65536]; 
    int i;
    
    if (len < TOPN*sizeof(struct diskrecord))
        return -1;

    /* prepare the array */
    for (i = 0; i < 65536; i++) {
	asval[i].as = i; 
	asval[i].bytes = ex->bytes[i];
	asval[i].pkts = ex->pkts[i];
    } 
	
    /* sort the array */
    qsort(asval, 65536, sizeof(struct sortedas), cmp); 
	    
    for (i = 0; i < TOPN && asval[i].bytes > 0; i++) { 
	PUTH32(buf, ex->ts);
	PUTH32(buf, asval[i].as); 
	PUTH64(buf, asval[i].bytes); 
	PUTH64(buf, asval[i].pkts); 
    } 

    return (i * sizeof(struct diskrecord));
}

static size_t
load(char *buf, size_t len, timestamp_t *ts)
{
    if (len < sizeof(struct diskrecord)) {
        ts = 0;
        return 0; 
    }

    *ts = TIME2TS(ntohl(((struct diskrecord *)buf)->ts), 0);
    return sizeof(struct diskrecord);
}


#define PRETTYHDR	\
    "Date                     AS Bytes      Packets   \n"

#define PRETTYFMT 	"%.24s AS%d %10llu %10llu\n"

static char *
print(char *buf, size_t *len, char * const args[])
{
    struct diskrecord *x; 
    static char s[2048];
    time_t ts;

    if (buf == NULL && args != NULL) { 
	*len = sprintf(s, PRETTYHDR); 
	return s; 
    } 

    if (buf == NULL && args == NULL) { 
	*len = 0; 
  	return s; 
    } 

    x = (struct diskrecord *) buf; 
    ts = (time_t) ntohl(x->ts);
    *len = sprintf(s, PRETTYFMT, asctime(localtime(&ts)), 
	       ntohl(x->as), NTOHLL(x->bytes), NTOHLL(x->pkts));
    return s;
};


callbacks_t callbacks = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: sizeof(EFLOWDESC),
    indesc: NULL,
    outdesc: NULL, 
    init: NULL,
    check: NULL,
    hash: NULL,
    match: NULL,
    update: update,
    ematch: NULL,
    export: export,
    compare: NULL,
    action: action,
    store: store,
    load: load,
    print: print,
    replay: NULL
};

