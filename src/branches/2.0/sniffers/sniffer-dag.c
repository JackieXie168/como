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

#include <dagapi.h>
#include <string.h>     /* bcopy */

#include "como.h"
#include "sniffers.h"

#include "capbuf.c"

/*
 * SNIFFER  ---    Endace DAG card
 *
 * Any Endace DAG card is support. Deals directly with DAG API. 
 *
 * XXX it does not open another stream if 0 is used by another process
 * 
 */


#define DAG_BUFSIZE	(me->sniff.max_pkts * sizeof(pkt_t))

struct dag_me {
    sniffer_t		sniff;		/* common fields, must be the first */
    const char *	device;		/* capture device */
    const char *	args;		/* arguments */
    uint8_t *		top;		/* pointer to top of stream mem */
    uint8_t *		bottom;		/* pointer to bottom of stream mem */
    capbuf_t		capbuf;
};


/*
 * -- sniffer_init
 * 
 */
static sniffer_t *
sniffer_init(const char * device, const char * args, alc_t *alc)
{
    struct dag_me *me;
    
    me = alc_new0(alc, struct dag_me);

    me->sniff.max_pkts = 65536;
    me->sniff.flags = SNIFF_POLL | SNIFF_SHBUF;
    me->sniff.polling = TIME2TS(0, 1000);
    me->device = device;
    me->args = args;

    /* create the capture buffer */
    if (capbuf_init(&me->capbuf, NULL, NULL, DAG_BUFSIZE, DAG_BUFSIZE) < 0)
	goto error;    

    return (sniffer_t *) me;
error:
    alc_free(alc, me);
    return NULL;
}


static metadesc_t *
sniffer_setup_metadesc(UNUSED sniffer_t * s, alc_t *alc)
{
    metadesc_t *outmd;
    pkt_t *pkt;

    /* setup output descriptor */
    outmd = metadesc_new(NULL, alc, 0);
    
    pkt = metadesc_tpl_add(outmd, "link:eth:any:any");
    pkt = metadesc_tpl_add(outmd, "link:vlan:any:any");
    pkt = metadesc_tpl_add(outmd, "link:isl:any:any");
    pkt = metadesc_tpl_add(outmd, "link:hdlc:any:any");

    return outmd;
}


/*
 * -- sniffer_start
 *  
 * open and configure the Endace DAG card. The input arguments 
 * are passed directly to DAG API and used commonly to define how 
 * many bytes of the packet to capture (e.g., "slen=1536 varlen"). 
 * It returns 0 on success, -1 on failure.
 * 
 */
static int
sniffer_start(sniffer_t * s)
{
    struct dag_me *me = (struct dag_me *) s;
    struct timeval tout, poll;

    /* open DAG */
    me->sniff.fd = dag_open((char *) me->device);
    if (me->sniff.fd < 0)
        return -1;  /* errno is set */

    /* configure DAG */ 
    if (dag_configure(me->sniff.fd, (char *) (me->args ? me->args : "")) < 0)
        return -1;  /* errno is set */

    /* attach to stream 0 */
    if (dag_attach_stream(me->sniff.fd, 0, 0, 0) < 0)
        return -1;  /* errno is set */

    /* start capture on stream 0 */
    if (dag_start_stream(me->sniff.fd, 0))
        return -1;  /* errno is set */

    /* init DAG polling parameters to return immediately */
    tout.tv_sec  = 0;
    tout.tv_usec = 0;   /* disable wait timeout */
    poll.tv_sec  = 0;
    poll.tv_usec = 0;   /* no sleep */
    if (dag_set_stream_poll(me->sniff.fd, 0, 0, &tout, &poll) < 0)
        return -1;      /* errno is set */

    return 0;		/* success */
}


/*
 * -- sniffer_next
 * 
 * advance the stream and read all packets to fill the out_buf. 
 * return the number of packets read. 
 */
static int
sniffer_next(sniffer_t * s, int max_pkts,
             __attribute__((__unused__)) timestamp_t max_ivl,
	     pkt_t * first_ref_pkt, int * dropped_pkts) 
{
    struct dag_me *me = (struct dag_me *) s;
    pkt_t *pkt;                 /* CoMo record structure */
    uint8_t *top;           	/* pointer to top of stream buffer */
    uint8_t *base;              /* current position in stream */
    uint8_t *bottom;
    int npkts;			/* number of pkts processed */

    /* update base pointer using the first_ref_pkt */
    if (first_ref_pkt != NULL) {
        me->bottom = (uint8_t *)(first_ref_pkt->payload -
                (dag_record_size + 2));
        bottom = me->bottom;
    }
    else
        me->bottom = me->top;

    /* read ERF records from stream 0 */
    top = dag_advance_stream(me->sniff.fd, 0, &me->bottom); 
    if (top == NULL)
        return -1; /* errno is set */

    /* check if we read something */
    if (top == me->bottom) {
        me->top = top;
        return 0;
    }

    if (first_ref_pkt != NULL) {
        if (top < me->top) /* wrapping */
            base = me->bottom + ((uint32_t)me->top - (uint32_t)bottom);
        else
            base = me->top;
    } else
        base = me->bottom;
    
    *dropped_pkts = 0;
    capbuf_begin(&me->capbuf, first_ref_pkt);
    
    npkts = 0;
    while (npkts < max_pkts) { 
	dag_record_t *rec;          /* DAG record structure */ 
	int len;                    /* total record length */
        int l2type;
        int left;
        
        left = top - base;
        me->top = base;

        /* access to packet record */
        rec = (dag_record_t *) base;

        /* check if there is one record */
	if (left < dag_record_size)
	    break; 

	len = ntohs(rec->rlen);
        /* check if entire record is available */
        if (len > left) 
            break;

	/* 
	 * skip the DAG header 
	 */
	base += dag_record_size; 
        len -= dag_record_size;
        
	/* 
	 * we need to figure out what interface we are monitoring. 
	 * some information is in the DAG record but for example Cisco 
 	 * ISL is not reported. 
	 */
	switch (rec->type) { 
	case TYPE_LEGACY: 		
	    /* we consider legacy to be only packet-over-sonet. this 
	     * is just pass through. 
	     */

	case TYPE_HDLC_POS: 
	    l2type = LINKTYPE_HDLC; 
	    break; 

	case TYPE_ETH: 
	    l2type = LINKTYPE_ETH; 
	    base += 2; 	/* DAG adds 2 bytes to Ethernet headers */
	    len -= 2;
	    break; 

	default: 
            /* other types are not supported */
            base += len;
            continue;
	} 

	/* reserve the space in the buffer for the pkt_t */
	pkt = (pkt_t *) capbuf_reserve_space(&me->capbuf, sizeof(pkt_t));
    
        /*
         * ok, data is good now, copy the packet over
         */
	COMO(ts) = rec->ts;
	COMO(len) = ntohs(rec->wlen);
	COMO(type) = COMOTYPE_LINK;

        /* 
         * copy the packet payload 
         */
	COMO(caplen) = len;
	COMO(payload) = (char *) base;

        /* 
         * update layer2 information and offsets of layer 3 and above. 
         * this sniffer only runs on ethernet frames. 
         */
	updateofs(pkt, L2, l2type);
	npkts++;
	ppbuf_capture(me->sniff.ppbuf, pkt, s);

	/* move to next packet in the buffer */
        base += len; 
    }

    return 0;
}


static float
sniffer_usage(sniffer_t * s, pkt_t * first, pkt_t * last)
{
    struct dag_me *me = (struct dag_me *) s;
    size_t sz;
    void * y;
    
    y = ((void *) last) + sizeof(pkt_t);
    sz = capbuf_region_size(&me->capbuf, first, y);
    return (float) sz / (float) me->capbuf.size;
}


static void
sniffer_stop(sniffer_t * s)
{
    struct dag_me *me = (struct dag_me *) s;
    
    /* stop capture on stream 0 */
    dag_stop_stream(me->sniff.fd, 0);

    /* detach from stream 0 */
    dag_detach_stream(me->sniff.fd, 0);

    /* close DAG */
    dag_close(me->sniff.fd);
}


static void
sniffer_finish(sniffer_t * s, alc_t *alc)
{
    struct dag_me *me = (struct dag_me *) s;

    capbuf_finish(&me->capbuf);
    alc_free(alc, me);
}


SNIFFER(dag) = {
    name: "dag",
    init: sniffer_init,
    finish: sniffer_finish,
    setup_metadesc: sniffer_setup_metadesc,
    start: sniffer_start,
    next: sniffer_next,
    stop: sniffer_stop,
    usage: sniffer_usage
};
