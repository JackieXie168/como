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

#include "como.h" 
#include "sniffers.h" 

#define BUFSIZE		(1024*1024)


/*
 * SNIFFER  ---		CoMo systems
 * 
 * Connects to live CoMo nodes through the query interface and receives
 * the output data of a given module. It then generates a packet stream 
 * out of the module data. 
 *
 */


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
    
    /*
     * a pktdesc_t for the stream is the first data to be received
     */
    ret = como_readn(sd, (char *) &src->output, sizeof(pktdesc_t));
    if (ret < 0) {
        logmsg(LOGWARN, "sniffer-como: read error: %s\n", strerror(errno));
	return -1; 
    } 

    src->fd = sd; 
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
sniffer_next(source_t * src, void * out_buf, size_t out_buf_size)
{
    static char buf[BUFSIZE];   /* base of the capture buffer */
    static int nbytes = 0;      /* valid bytes in buffer */
    char * base;                /* current position in input buffer */
    uint npkts;                 /* processed pkts */
    int out_buf_used;           /* bytes in output buffer */
    int rd;

    /* read CoMo packets from stream */
    rd = read(src->fd, buf + nbytes, BUFSIZE - nbytes);
    if (rd < 0)   
        return rd; 

    /* update number of bytes to read */
    nbytes += rd;  
    if (nbytes == 0)
        return -1;      /* end of file, nothing left to do */

    base = buf;
    npkts = out_buf_used = 0;
    while (nbytes - (base - buf) > (int) sizeof(pkt_t)) {
        pkt_t * pkt;                 /* CoMo record structure */ 

	pkt = (pkt_t *) base; 
	
        /* check if we have enough space in output buffer */
        if (NTOH_STDPKT_LEN(pkt) > out_buf_size - out_buf_used)
            break;

        /* check if entire record is available */
        if (NTOH_STDPKT_LEN(pkt) > (size_t) nbytes - (base - buf))
            break;

	bcopy(base, out_buf + out_buf_used, NTOH_STDPKT_LEN(pkt)); 
	base += NTOH_STDPKT_LEN(pkt); 
	
	/* we need to fix byte order of CoMo header */
	pkt = (pkt_t *) (out_buf + out_buf_used);
	pkt->ts = NTOHLL(pkt->ts); 
	pkt->len = ntohl(pkt->len); 
	pkt->caplen = ntohl(pkt->caplen);
	out_buf_used += STDPKT_LEN(pkt); 
	npkts++; 
    }

    nbytes -= (base - buf);
    bcopy(base, buf, nbytes);
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
    close(src->fd);
}

struct _sniffer como_sniffer = { 
    "como", sniffer_start, sniffer_next, sniffer_stop, SNIFF_POLL
};
