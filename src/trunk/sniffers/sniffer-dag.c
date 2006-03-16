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


#include <dagapi.h>
#include <string.h>     /* bcopy */

#include "como.h"
#include "sniffers.h"

/*
 * SNIFFER  ---    Endace DAG card
 *
 * Any Endace DAG card is support. Deals directly with DAG API. 
 *
 * XXX it does not open another stream if 0 is used by another process
 * 
 */


/* sniffer specific information */
struct _snifferinfo { 
    void * bottom; 	   	/* pointer to bottom of stream buffer */
};


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
sniffer_start(source_t * src) 
{
    struct timeval tout, poll;
    struct _snifferinfo * info;
    int fd;
    metadesc_t *outmd;
    pkt_t *pkt;

    /* open DAG */
    if ((fd = dag_open(src->device)) < 0)
        return -1;  /* errno is set */

    /* configure DAG */ 
    if (dag_configure(fd, src->args) < 0)
        return -1;  /* errno is set */

    /* attach to stream 0 */
    if (dag_attach_stream(fd, 0, 0, 0) < 0)
        return -1;  /* errno is set */

    /* start capture on stream 0 */
    if (dag_start_stream(fd, 0))
        return -1;  /* errno is set */

    /* init DAG polling parameters to return immediately */
    tout.tv_sec  = 0;
    tout.tv_usec = 0;   /* disable wait timeout */
    poll.tv_sec  = 0;
    poll.tv_usec = 0;   /* no sleep */
    if (dag_set_stream_poll(fd, 0, 0, &tout, &poll) < 0)
        return -1;      /* errno is set */

    src->ptr = safe_malloc(sizeof(struct _snifferinfo));
    info = (struct _snifferinfo *) src->ptr; 
    info->bottom = NULL;

    src->fd = fd; 
    src->flags = SNIFF_TOUCHED|SNIFF_POLL; 
    src->polling = TIME2TS(0, 1000); 

    /* setup output descriptor */
    outmd = metadesc_define_sniffer_out(src, 0);
    
    pkt = metadesc_tpl_add(outmd, "link:eth:any:any");
    pkt = metadesc_tpl_add(outmd, "link:vlan:any:any");
    pkt = metadesc_tpl_add(outmd, "link:isl:any:any");
    pkt = metadesc_tpl_add(outmd, "link:hdlc:any:any");

    return 0;		/* success */
}


/*
 * -- sniffer_next
 * 
 * advance the stream and read all packets to fill the out_buf. 
 * return the number of packets read. 
 */
static int
sniffer_next(source_t * src, pkt_t * out, int max_no) 
{
    struct _snifferinfo * info; /* sniffer information */
    pkt_t *pkt;                 /* CoMo record structure */
    char *top;           	/* pointer to top of stream buffer */
    char *base;                 /* current position in stream */
    int npkts;			/* number of pkts processed */

    info = (struct _snifferinfo *) src->ptr;

    /* read ERF records from stream 0 */
    top = dag_advance_stream(src->fd, 0, &info->bottom); 
    if (top == NULL)
        return -1; /* errno is set */

    /* check if we read something */
    if (top == (char *) info->bottom)
        return 0;

    base = info->bottom; 
    for (npkts = 0, pkt = out; npkts < max_no; npkts++, pkt++) { 
	dag_record_t *rec;          /* DAG record structure */ 
	int len;                    /* total record length */
        int l2type; 

        /* access to packet record */
        rec = (dag_record_t *) base;

        /* check if there is one record */
	if (top - base < dag_record_size)
	    break; 

        /* check if entire record is available */
        if (ntohs(rec->rlen) > top - base) 
            break;
    
        /*
         * ok, data is good now, copy the packet over
         */
	COMO(ts) = rec->ts;
	COMO(len) = ntohs(rec->wlen);
	COMO(type) = COMOTYPE_LINK;

	/* 
	 * skip the DAG header 
	 */
	base += dag_record_size; 
        len = ntohs(rec->rlen) - dag_record_size;
        
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
	    base += 2; 	/* DAG adds 4 bytes to Ethernet headers */
	    len -= 2; 
	    break; 

	default: 
            /* other types are not supported */
            base += len;
            continue;
	} 

        /* 
         * copy the packet payload 
         */
	COMO(caplen) = len;
	COMO(payload) = base;

        /* 
         * update layer2 information and offsets of layer 3 and above. 
         * this sniffer only runs on ethernet frames. 
         */
	updateofs(pkt, L2, l2type);

	/* move to next packet in the buffer */
        base += len; 
    }

    info->bottom = base; 
    return npkts;
}

static void
sniffer_stop(source_t * src)
{
    /* stop capture on stream 0 */
    dag_stop_stream(src->fd, 0);

    /* detach from stream 0 */
    dag_detach_stream(src->fd, 0);

    /* close DAG */
    dag_close(src->fd);

    free(src->ptr); 
}

sniffer_t dag_sniffer = { 
    "dag", sniffer_start, sniffer_next, sniffer_stop
};
