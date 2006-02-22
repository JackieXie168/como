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

#include <fcntl.h>
#include <dagapi.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>     /* bcopy */

#include "como.h"
#include "sniffers.h"


/*
 * SNIFFER  ---    Endace ERF file 
 *
 * Endace ERF trace format. 
 *
 * XXX  This sniffer is reading a trace from disk. Reads are not 
 *      optimized although it is sequential and some prefetching 
 *      could help as well as using mmap() instead of read(). 
 */


/* sniffer specific information */
#define BUFSIZE 	(1024*1024) 
struct _snifferinfo { 
    char buf[BUFSIZE];          /* temporary packet buffer */
    int nbytes; 	        /* valid bytes in buffer */
};


/*
 * -- sniffer_start
 * 
 * open the trace file and return the file descriptors. 
 * No arguments are supported so far. It returns 0 in case 
 * of success, -1 in case of failure.
 */
static int
sniffer_start(source_t * src) 
{
    /* open the ERF trace file */
    src->fd = open(src->device, O_RDONLY); 
    if (src->fd < 0)
        return -1; 

    src->flags = SNIFF_FILE|SNIFF_SELECT|SNIFF_TOUCHED; 
    src->polling = 0; 
    src->ptr = safe_calloc(1, sizeof(struct _snifferinfo));
    return 0;		/* success */
}


/*
 * -- sniffer_next
 * 
 * Reads one chunk of the file (BUFSIZE) and fill the out_buf 
 * with packets in the _como_pkt format. Return the number of 
 * packets read. 
 *
 */
static int
sniffer_next(source_t * src, pkt_t *out, int max_no)
{
    struct _snifferinfo * info; /* sniffer specific information */
    pkt_t *pkt;                 /* packet records */
    char * base; 	 	/* current position in input buffer */
    int npkts;                  /* processed pkts */
    int rd;

    info = (struct _snifferinfo *) src->ptr; 

    /* read ERF records from fd */
    rd = read(src->fd, info->buf + info->nbytes, BUFSIZE - info->nbytes); 
    if (rd < 0) 
	return rd; 

    /* update number of bytes to read */ 
    info->nbytes += rd;
    if (info->nbytes == 0) 
	return -1; 	/* end of file, nothing left to do */

    base = info->buf; 
    for (npkts = 0, pkt = out; npkts < max_no; npkts++, pkt++) { 
	dag_record_t * rec;         /* DAG record structure */
	int len;                    /* total record length */
	int l2type; 		    /* interface type */

	/* see if we have a record */
	if (info->nbytes - (base - info->buf) < dag_record_size)  
	    break; 

        /* access to packet record */
        rec = (dag_record_t *) base;
        len = ntohs(rec->rlen) - dag_record_size;

        /* check if entire record is available */
        if (len > info->nbytes - (int) (base - info->buf)) 
	    break; 

        /* 
	 * ok, data is good now, copy the packet over 
	 */
	COMO(ts) = rec->ts;
	COMO(len) = (uint32_t) ntohs(rec->wlen);
	COMO(type) = COMOTYPE_LINK;

	/* skip DAG header */
	base += dag_record_size; 

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
	    base += 2; 		/* ethernet frames have padding */
	    len -= 2; 
            break;

        default:
            /* other types are not supported */
            base += len;
            continue;
        }

	/*
	 * point to the packet payload
	 */
	COMO(caplen) = len;
	COMO(payload) = base;

	/*
	 * update layer2 information and offsets of layer 3 and above.
	 * this sniffer only runs on ethernet frames.
	 */
	updateofs(pkt, L2, l2type);

        /* increment the number of processed packets */
	base += len; 
    }

    /* if we have zero packets to give and we reached the 
     * end of file, then return -1 to indicate that there 
     * are no more packets. 
     */
    if (npkts == 0 && rd == 0) 
	return -1; 

    info->nbytes -= (base - info->buf); 
    bcopy(base, info->buf, info->nbytes); 
    return npkts;
}


/*
 * -- sniffer_stop
 * 
 * close the file descriptor. 
 */
static void
sniffer_stop(source_t * src)
{
    close(src->fd);
    free(src->ptr);
}

sniffer_t erf_sniffer = { 
    "erf", sniffer_start, sniffer_next, sniffer_stop
};
