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
#include <net/if.h>

#ifndef BUILD_FOR_ARM
#include <pcap.h>	/* DLT_* on linux */
#else 
#include "pcap-stargate.h"
#endif 

#include "como.h"
#include "sniffers.h"
#include "stdwlan.h"


/*
 * SNIFFER  ---    pcap files 
 *
 * Reads pcap trace files. 
 *
 */

/* sniffer specific information */
#define BUFSIZE (1024*1024) 
struct _snifferinfo { 
    uint16_t type; 	 	/* CoMo packet type */
    int littleendian;		/* set if pcap headers are bigendian */
    char buf[BUFSIZE];   	/* base of the capture buffer */
    int nbytes;      	 	/* valid bytes in buffer */

    /* 
     * the following are needed to deal 
     * with IEEE 802.11 frames 
     */
    char pktbuf[BUFSIZE];	/* buffer for pre-processed packets */
    int pkt_nbytes; 	 	/* valid bytes in pktbuf */
};


/* libpcap magic */
#define PCAP_MAGIC 0xa1b2c3d4

/* 
 * swapl(), swaps()
 * 
 * swap bytes from network byte order to host byte order 
 * cannot use ntoh macros because we do really need to swap now. 
 */
static __inline__ uint32_t 
swapl(uint32_t x) 
{
    return (((x & 0xff) << 24) | ((x & 0x0000ff00) << 8) | 
	    ((x >> 8) & 0x0000ff00) | ((x >> 24) & 0x000000ff));
}

static __inline__ uint32_t 
swaps(uint16_t x) 
{
    return (((x & 0x00ff) << 8) | ((x >> 8) & 0x00ff));
}


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
    struct _snifferinfo * info; 
    struct pcap_file_header pf; 
    uint16_t type; 
    int swapped; 
    int rd;
    int fd;

    fd = open(src->device, O_RDONLY);
    if (fd < 0) {
	logmsg(LOGWARN, "pcap sniffer: opening file %s (%s)\n", 
	    src->device, strerror(errno));
	return -1; 
    } 

    rd = read(fd, &pf, sizeof(pf));
    if (rd != sizeof(pf)) {
	logmsg(LOGWARN, "pcap sniffer: failed to read header\n");
	return -1; 
    } 

    if (pf.magic != PCAP_MAGIC) { 
        if (pf.magic != swapl(PCAP_MAGIC)) {
             logmsg(LOGWARN, "pcap sniffer: invalid pcap file\n"); 
            return -1;
        } else {
            pf.version_major = swaps(pf.version_major);
            pf.version_minor = swaps(pf.version_minor);
            pf.thiszone = swapl(pf.thiszone);
            pf.sigfigs = swapl(pf.sigfigs);
            pf.snaplen = swapl(pf.snaplen);
            pf.linktype = swapl(pf.linktype);
            swapped = 1;
        }
    }


    switch (pf.linktype) { 
    case DLT_EN10MB: 
	logmsg(LOGSNIFFER, "datalink Ethernet (%d)\n", pf.linktype); 
	type = COMOTYPE_ETH; 
	break; 

    case DLT_IEEE802_11: 
	logmsg(LOGSNIFFER, "datalink 802.11 (%d)\n", pf.linktype); 
	type = COMOTYPE_80211;
	break;

    case DLT_PRISM_HEADER: 
	logmsg(LOGSNIFFER, 
	       "datalink 802.11 with Prism header (%d)\n",
	       pf.linktype); 
	type = COMOTYPE_RADIO;
	break;

    default: 
	logmsg(LOGWARN, 
	       "pcap sniffer %s: unrecognized datalink (%d)\n", 
	       src->device, pf.linktype); 
	close(fd);
	return -1; 
    }

    src->fd = fd; 
    src->flags = SNIFF_TOUCHED|SNIFF_FILE|SNIFF_SELECT; 
    src->polling = 0; 
    src->ptr = safe_calloc(1, sizeof(struct _snifferinfo)); 
    info = (struct _snifferinfo *) src->ptr; 
    info->type = type; 
    info->littleendian = swapped;
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
sniffer_next(source_t * src, pkt_t *out, int max_no) 
{
    struct _snifferinfo * info; 
    pkt_t *pkt;                 /* CoMo record structure */
    char * base;                /* current position in input buffer */
    char * pl;                  /* position in buffer for processed packets */
    int npkts;                  /* processed pkts */
    int rd;
  
    info = (struct _snifferinfo *) src->ptr; 

    /* read pcap records from fd */
    rd = read(src->fd, info->buf + info->nbytes, BUFSIZE - info->nbytes);
    if (rd < 0)
        return rd;

    /* update number of bytes to read */
    info->nbytes += rd;
    if (info->nbytes == 0)
        return -1;       /* end of file, nothing left to do */

    info->pkt_nbytes = 0; 
    base = info->buf;
    for (npkts = 0, pkt = out; npkts < max_no; npkts++, pkt++) { 
        pcap_hdr_t * ph = (pcap_hdr_t *) base ; 
	int left = info->nbytes - (base - info->buf); 

	/* convert the header if needed */
	if (info->littleendian) { 
            ph->ts.tv_sec = swapl(ph->ts.tv_sec);
            ph->ts.tv_usec = swapl(ph->ts.tv_usec);
            ph->caplen = swapl(ph->caplen);
            ph->len = swapl(ph->len);
        } 

	/* do we have a pcap header? */
	if (left < (int) sizeof(pcap_hdr_t)) 
	    break; 

        /* check if entire record is available */
        if (left < (int) sizeof(pcap_hdr_t) + ph->caplen) 
            break;

        pkt->ts = TIME2TS(ph->ts.tv_sec, ph->ts.tv_usec);
        pkt->len = ph->len;
        pkt->caplen = ph->caplen; 

	/*      
	 * Now we have a packet: start filling a new pkt_t struct
	 * (beware that it could be discarded later on)
	 */
	if (info->type == COMOTYPE_80211 || info->type == COMOTYPE_RADIO) { 
	    int n; 

	    /* 
	     * point to memory region to receive pre-processed 802.11 
	     * frame. this frame may be larger than original frame 
	     * captured from the medium. (we do it this way for performance
	     * reasons and to simplify the code in the modules)
	     */
            pkt->payload = info->pktbuf + info->pkt_nbytes;
            pl =  pkt->payload;
	    n = parse80211_frame(pkt,base,pl,info->type); 
	    if (n == 0) 
		break; 
	    info->pkt_nbytes += n; 
	} else {  
	    pkt->payload = base + sizeof(pcap_hdr_t); 
            /* 
             * update layer2 information and offsets of layer 3 and above. 
             * this sniffer runs on ethernet frames
             */
            updateofs(pkt, info->type); 
	} 
        /* increment the number of processed packets */
	base += sizeof(pcap_hdr_t) + ph->caplen; 
    }
    info->nbytes -= (base - info->buf);
    bcopy(base, info->buf, info->nbytes);
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
    free(src->ptr);
    close(src->fd);
}


sniffer_t pcap_sniffer = {
    "pcap", sniffer_start, sniffer_next, sniffer_stop
};
