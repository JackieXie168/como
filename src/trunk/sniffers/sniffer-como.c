/*-
 * Copyright (c) 2004, Intel Corporation
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
    ret = como_writen(sd, msg, 0);
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
    src->flags = SNIFF_TOUCHED|SNIFF_POLL; 	/* just to slow it down... */
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

    assert(src->ptr != NULL); 

    info = (struct _snifferinfo *) src->ptr; 

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
        if (left < ntohl(p->caplen) + sizeof(pkt_t)) 
            break;

	/* ok, copy the packet header */
	COMO(ts) = NTOHLL(p->ts); 
	COMO(len) = ntohl(p->len); 
	COMO(caplen) = ntohl(p->caplen);
        COMO(type) = ntohs(p->type); 
        COMO(dropped) = ntohs(p->dropped); 
        COMO(type) = ntohs(p->type); 
        COMO(l2type) = ntohs(p->l2type); 
  	COMO(l3type) = ntohs(p->l3type); 
  	COMO(l4type) = ntohs(p->l4type); 
        COMO(l2ofs) = ntohs(p->l2ofs); 
        COMO(l3ofs) = ntohs(p->l3ofs); 
        COMO(l4ofs) = ntohs(p->l4ofs); 

	/* the payload is just after the packet. update 
	 * the payload pointer. 
	 */
	COMO(payload) = base + sizeof(pkt_t); 

	/* move forward */
	base += COMO(caplen) + sizeof(pkt_t); 
    }

    info->nbytes -= (base - info->buf);
    bcopy(base, info->buf, info->nbytes);
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
