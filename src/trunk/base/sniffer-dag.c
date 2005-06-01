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

#define BUFSIZE   (1024 * 1024)


/* sniffer specific information */
struct _snifferinfo { 
    void * bottom; 	   	/* pointer to bottom of stream buffer */
    int flags; 			/* DAG flags */
#define SNIFF_USE_ISL		0x1
};


/* Cisco ISL header size. 
 * We do nothing with it. Just skip. 
 */
#define ISL_HDRSIZE 	26 	/* ISL header is 24 byte long but it takes
				 * 26 bytes in the DAG card for some weird 
				 * reason. 
				 */

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
    info->flags = 0;
    if (src->args && strstr(src->args, "useISL") != NULL) 
	info->flags |= SNIFF_USE_ISL; 

    src->fd = fd; 
    return 0;		/* success */
}


/*
 * -- sniffer_next
 * 
 * advance the stream and read all packets to fill the out_buf. 
 * return the number of packets read. 
 */
static int
sniffer_next(source_t * src, void *out_buf, size_t out_buf_size)
{
    struct _snifferinfo * info; /* sniffer information */
    char *top;           	/* pointer to top of stream buffer */
    uint npkts;			/* number of pkts processed */
    uint out_buf_used; 		/* bytes in output buffer */
    char *base;                 /* current position in stream */

    info = (struct _snifferinfo *) src->ptr;

    /* read ERF records from stream 0 */
    top = dag_advance_stream(src->fd, 0, &info->bottom); 
    if (top == NULL)
        return -1; /* errno is set */

    /* check if we read something */
    if (top == (char *) info->bottom)
        return 0;

    base = info->bottom; 
    npkts = out_buf_used = 0; 
    while (top - base > dag_record_size) {
	dag_record_t *rec;          /* DAG record structure */ 
	pkt_t *pkt;                 /* CoMo record structure */
	int len;                    /* total record length */
        int pktofs;                 /* offset in current record */

        /* access to packet record */
        rec = (dag_record_t *) base;
        len = ntohs(rec->rlen);

        /* check if we have enough space in output buffer */
        if (sizeof(pkt_t) + len > out_buf_size - out_buf_used)
            break;
   
        /* check if entire record is available */
        if (len > top - base) 
            break;
    
        /*
         * ok, data is good now, copy the packet over
         */
        pkt = (pkt_t *)((char *)out_buf + out_buf_used);
        pkt->ts = rec->ts;
        pkt->caplen = 0;
        pkt->flags = 0; 
        pkt->len = ntohs(rec->wlen);
        pktofs = dag_record_size;

        switch (rec->type) {
        case TYPE_HDLC_POS:
	    pkt->type = COMO_L2_HDLC; 
            bcopy(&rec->rec.pos.hdlc, &pkt->layer2.hdlc, 4);

            /* check if this is an IP packet */
            if (H16(pkt->layer2.hdlc.type) != 0x0800) { 
                logmsg(V_LOGCAPTURE, "non-IP packet received (%04x)\n",
                    H16(pkt->layer2.hdlc.type));  
                base += len;
                continue;
            }
    
            pktofs += 4;
            break;
    
        case TYPE_ETH:
	    if (info->flags & SNIFF_USE_ISL) { 
		/* 
		 * if SNIFF_USE_ISL is set, this interface is monitoring 
		 * a link where frames are encapsulated using Cisco ISL. We 
		 * strip the ISL header off and discard it (no info there). 
		 * Then we process the rest as a normal packet. Given that 
		 * the DAG card does not support ISL we have to play with 
		 * the dag_record_t to get the timestamp and then to get 
		 * to the actual packet. 
		 */
		base += ISL_HDRSIZE; 
		len -= ISL_HDRSIZE; 
		rec = (dag_record_t *) base;
		pkt->len -= ISL_HDRSIZE; 
	    } 

	    /* copy MAC information */
	    pkt->type = COMO_L2_ETH; 
            bcopy(&rec->rec.eth.dst, &pkt->layer2.eth, 14);

            /* check if this is an IP packet */
            if (ntohs(rec->rec.eth.etype) != 0x0800) {
                logmsg(V_LOGCAPTURE, "non-IP packet received (%04x)\n",
                    H16(pkt->layer2.eth.type));
                base += len;
                continue;  
            }
            pktofs += 16;
            break;

        default:
            /* other types are not supported */
            base += len;
            continue;
        }

        /* copy IP header (if any) */
        base += pktofs;
        pkt->ih = *(struct _como_iphdr *) base;
        pkt->caplen += sizeof(struct _como_iphdr);

        /* skip the IP header
         *
         * XXX we are losing IP options if any in the packets.
         *     need to find a place to put them in the como packet
         *     data structure...
         */
        pktofs += (IP(vhl) & 0x0f) << 2;
        base += (IP(vhl) & 0x0f) << 2;

        /* copy layer 4 header and payload */
        bcopy(base, &pkt->layer4, len - pktofs);
        pkt->caplen += (len - pktofs);

        /* increment the number of processed packets */
        npkts++;
        base += (len - pktofs);
        out_buf_used += STDPKT_LEN(pkt); 
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
    "dag", sniffer_start, sniffer_next, sniffer_stop, SNIFF_POLL 
};
