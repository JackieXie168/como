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

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h> /* socket */
#include <netinet/in.h> /* struct sockaddr_in */
#include <string.h>     /* strerror */
#include <errno.h>
#include <assert.h>

#include "como.h" 
#include "sniffers.h" 



/*
 * SNIFFER  ---		CoMo systems
 * 
 * Connects to live CoMo nodes through the query interface and receives
 * the output data of a given module. It then generates a packet stream 
 * out of the module data. 
 *
 */

/* sniffer-specific information */
#define BUFSIZE		(1024*1024)
struct _snifferinfo { 
    char buf[BUFSIZE]; 	     /* base of the capture buffer */
    char * base; 	     /* pointer to first valid byte in buffer */
    int nbytes; 	     /* valid bytes in buffer */
};

/**
 * -- sniffer_start
 * 
 * This function sends the query (via HTTP) to the destination 
 * and receives back the packet description. 
 *
 */
static int
sniffer_start(source_t * src) 
{
    int ret, sd;
    char *msg, *local;
    
    sd = create_socket(src->device, &local);
    if (sd < 0) { 
        logmsg(LOGWARN, "sniffer-como: cannot create socket: %s\n", 
	    strerror(errno)); 
	return -1; 
    } 
    
    /* send the query string followed by "\n\n" */
    asprintf(&msg, "GET %s HTTP/1.0\n\n", local);
    ret = como_writen(sd, msg, strlen(msg));
    free(msg);
    if (ret < 0) {
        logmsg(LOGWARN, "sniffer-como: write error: %s\n", strerror(errno));
	return -1;
    } 

#if 0
    /* FIXME: sniffer-como can't get pktdesc anymore */
    /*
     * a pktdesc_t for the stream is the first data to be received
     */
    ret = como_readn(sd, (char *) &src->output, sizeof(pktdesc_t));
    if (ret < 0) {
        logmsg(LOGWARN, "sniffer-como: read error: %s\n", strerror(errno));
	return -1; 
    } 
#endif

    src->fd = sd; 
    src->flags = SNIFF_TOUCHED|SNIFF_SELECT; 	
    src->ptr = safe_calloc(1, sizeof(struct _snifferinfo)); 
    return sd;
}


/**
 * -- sniffer_next
 *
 * Copies sizeof(pkt_t) bytes from the stream in a pkt_t struct 
 * Returns how many packets were read or -1 if an unrecoverable
 * error occurred.
 * 
 */
static int
sniffer_next(source_t * src, pkt_t * out, int max_no)
{
    struct _snifferinfo * info; 
    pkt_t * pkt; 
    char * base;                /* current position in input buffer */
    int npkts;                  /* processed pkts */
    int rd;
    timestamp_t first_seen;

    assert(src->ptr != NULL); 

    info = (struct _snifferinfo *) src->ptr; 

    if (info->nbytes > 0) {
	/*
	 * NOTE: this assertion is here to catch the undesired situation in
	 * which the input stream is wrong and this sniffer continues to
	 * attempt to read packets.
	 */
	assert(info->buf != info->base);
	memmove(info->buf, info->base, info->nbytes); 
    }

    /* read CoMo packets from stream */
    rd = read(src->fd, info->buf + info->nbytes, BUFSIZE - info->nbytes);
    if (rd < 0)   
        return rd; 

    /* update number of bytes to read */
    info->nbytes += rd;  
    if (info->nbytes == 0)
        return -1;      /* end of file, nothing left to do */

    base = info->buf;
    for (npkts = 0, pkt = out; npkts < max_no; npkts++, pkt++) { 
	pkt_t * p = (pkt_t *) base; 
	uint left = info->nbytes - (base - info->buf); 
	
	/* check if we have enough for a new packet record */
	if (left < sizeof(pkt_t)) 
	    break;

	/* check if we have the payload as well */
        if (left < p->caplen + sizeof(pkt_t)) 
            break;

	if (npkts > 0) {
	    if (p->ts - first_seen > TIME2TS(1,0)) {
		/* Never returns more than 1sec of traffic */
		break;
	    }
	} else {
	    first_seen = p->ts;
	}
	
	/* ok, copy the packet header */
	/* XXX we assume to receive packet in the same endianness 
	 *     we are running in. we need to make the replay() callback
	 *     operate in network-byte order or start having the 
 	 *     COMO header always in network-byte order. 
	 */     
	bcopy(p, pkt, sizeof(pkt_t)); 

	/* the payload is just after the packet. update 
	 * the payload pointer. 
	 */
	COMO(payload) = base + sizeof(pkt_t); 

	/* move forward */
	base += COMO(caplen) + sizeof(pkt_t); 
    }

    info->nbytes -= (base - info->buf);
    info->base = base; 
    return npkts;
}

/*
 * -- sniffer_stop
 *
 * just close the socket
 */
static void
sniffer_stop(source_t * src) 
{
    free(src->ptr);
    close(src->fd);
}

struct _sniffer como_sniffer = { 
    "como", sniffer_start, sniffer_next, sniffer_stop
};
