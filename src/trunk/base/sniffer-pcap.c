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


#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <pcap.h>	/* DLT_* on linux */
#include <net/if.h>

#include "como.h"
#include "sniffers.h"

#define BUFSIZE (1024*1024) 


/* 
 * -- sniffer_start
 * 
 * Open the pcap file and read the header. We support ethernet
 * frames only. Return the file descriptor and set the type variable. 
 * It returns 0 on success and -1 on failure.
 *
 */
static int
sniffer_start(source_t * src) 
{
    uint32_t hdr[6];
    int rd;
    int fd;

    fd = open(src->device, O_RDONLY);
    if (fd < 0) {
	logmsg(LOGWARN, "pcap sniffer: opening file %s (%s)\n", 
	    src->device, strerror(errno));
	return -1; 
    } 

    rd = read(fd, &hdr, sizeof(hdr));
    if (rd != sizeof(hdr)) {
	logmsg(LOGWARN, "pcap sniffer: failed to read header\n");
	return -1; 
    } 

    if (hdr[5] != DLT_EN10MB) { 
	logmsg(LOGWARN, "pcap sniffer: unrecognized datalink (%d)\n", hdr[5]); 
	close(fd);
	return -1; 
    }

    src->fd = fd; 
    return 0;
}


/* 
 * PCAP header. It precedes every packet in the file. 
 */
typedef struct {
    struct timeval ts; 		/* time stamp */
    int caplen;        		/* length of portion present */
    int len;			/* length this packet (on the wire) */
} pcap_hdr_t;


/*
 * sniffer_next
 *
 * Fill a structure with a copy of the next packet and its metadata.
 * Each packet is preceded by the following header
 *
 */
static int
sniffer_next(source_t * src, void *out_buf, size_t out_buf_size)
{
    static char buf[BUFSIZE];   /* base of the capture buffer */
    static int nbytes = 0;      /* valid bytes in buffer */
    char * base;                /* current position in input buffer */
    uint npkts;                 /* processed pkts */
    uint out_buf_used;          /* bytes in output buffer */
    int rd;

    /* read pcap records from fd */
    rd = read(src->fd, buf + nbytes, BUFSIZE - nbytes);
    if (rd < 0)
        return rd;

    /* update number of bytes to read */
    nbytes += rd;
    if (nbytes == 0)
        return -1;       /* end of file, nothing left to do */

    base = buf;
    npkts = out_buf_used = 0;
    while (nbytes - (base - buf) > (int) sizeof(pcap_hdr_t)) {
        pcap_hdr_t * ph;            /* PCAP record structure */
        pkt_t *pkt;                 /* CoMo record structure */

        ph = (pcap_hdr_t *) base; 

        /* check if we have enough space in output buffer */
        if (sizeof(pkt_t) + ph->caplen > out_buf_size - out_buf_used)
            break;

        /* check if entire record is available */
        if ((int) sizeof(pcap_hdr_t) + ph->caplen > nbytes - (int) (base - buf))
            break;

        /*      
         * Now we have a packet: start filling a new pkt_t struct
         * (beware that it could be discarded later on)
         */
        pkt = (pkt_t *) ((char *)out_buf + out_buf_used); 
        pkt->ts = TIME2TS(ph->ts.tv_sec, ph->ts.tv_usec);
        pkt->len = ph->len;
        pkt->caplen = ph->caplen; 

        /* 
         * copy the packet payload 
         */
        bcopy(base + sizeof(pcap_hdr_t), pkt->payload, ph->caplen); 
        
        /* 
         * update layer2 information and offsets of layer 3 and above. 
         * this sniffer only runs on ethernet frames. 
         */
        updateofs(pkt, COMO_L2_ETH); 

        /* increment the number of processed packets */
        npkts++;
        base += sizeof(pcap_hdr_t) + ph->caplen; 
        out_buf_used += STDPKT_LEN(pkt); 
    }

    if (base == buf) 
	logmsg(LOGCAPTURE, "buffer %d byte long, no packets read\n", nbytes);
    nbytes -= (base - buf);
    bcopy(base, buf, nbytes);
    return npkts;
}


/* 
 * -- sniffer_stop
 * 
 * Close the file descriptor. 
 */
static void
sniffer_stop (source_t * src)
{
    close(src->fd);
}


sniffer_t pcap_sniffer = {
    "pcap", sniffer_start, sniffer_next, sniffer_stop, SNIFF_FILE
};
