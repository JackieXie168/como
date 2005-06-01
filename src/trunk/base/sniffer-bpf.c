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

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <pcap.h>
#include <net/if.h>

#include "sniffers.h"
#include "como.h"

/*
 * SNIFFER  ---    Berkeley Packet Filter
 *
 * Ethernet cards that support BPF.
 * It directly accesses the bpf device.
 *
 */

#define BUFSIZE (500*1024) 	/* NOTE: bpf max buffersize is 0x80000 */


/*
 * -- sniffer_start
 * 
 * it looks for an available bpf device and sets it 
 * up accordingly. It returns 0 on success and -1 on failure.
 */
static int
sniffer_start(source_t *src) 
{
    char bpfdev[sizeof("/dev/bpf000")];
    int bufsize = BUFSIZE;
    struct ifreq ifr;
    int fd = -1;
    int n;

    if (strlen(src->device)+1 > sizeof(ifr.ifr_name)) {
        errno = EINVAL;
        return -1;
    }

    for (n = 0; n < 32 ; n++) {	/* XXX at most 32 devices */
        sprintf(bpfdev, "/dev/bpf%d", n);
	errno = 0;
        fd = open(bpfdev, O_RDWR);
	if (fd >= 0)	/* found a valid one */
	    break; 
	
	/*
	 * typical errors are
	 * EBUSY	in use (eg by dhcp or the like)
	 * EACCES	permission denied (eg bad ownership)
	 * ENOENT	no file (eg end of bpf devices)
	 * We can exit at the first ENOENT, or keep trying up to
	 * a given max if we suspect holes in the list of devices.
	 */
    }

    if (fd < 0) {
	logmsg(LOGWARN, "sniffer-bpf: cannot find a usable bpf device: %s\n",
	    strerror(errno));
        return -1;
    }

    /* setting the buffer size for next read calls */
    if (ioctl(fd, BIOCSBLEN, &bufsize)) {
	logmsg(LOGWARN, "sniffer-bpf: BIOCSBLEN failed\n");
        close(fd);
        return -1;
    }

    /* read packets as soon as they are received */
    n = 1;
    if (ioctl(fd, BIOCIMMEDIATE, &n) < 0) {
	logmsg(LOGWARN, "sniffer-bpf: BIOCIMMEDIATE failed\n");
        close(fd);
        return -1;
    }

    /* no timeout on read requests */
    n = 0;
    if (ioctl(fd, BIOCSRTIMEOUT, &n) < 0) {
	logmsg(LOGWARN, "sniffer-bpf: BIOCSRTIMEOUT failed\n");
        close(fd);
        return -1;
    }

    /* interface we capture packets from */
    strncpy(ifr.ifr_name, src->device, sizeof(ifr.ifr_name));
    if (ioctl(fd, BIOCSETIF, &ifr)) {
	logmsg(LOGWARN, "sniffer-bpf: BIOCSETIF failed\n");
        close(fd);
        return -1;
    }

    /* set the interface in promiscous mode */
    if (ioctl(fd, BIOCPROMISC) < 0) {
	logmsg(LOGWARN, "sniffer-bpf: BIOCPROMISC failed\n");
        close(fd);
        return -1;
    }

    /* check the type of frames, we only support Ethernet */
    if (ioctl(fd, BIOCGDLT, &n) < 0) {
	logmsg(LOGWARN, "sniffer-bpf: BIOCGDLT failed\n");
        close(fd);
        return -1;
    }

    if (n != DLT_EN10MB) {
        logmsg(LOGWARN, "bpf sniffer: unrecognized type (%d)\n", n);
        close(fd);
        return -1;
    }

    src->fd = fd; 
    return 0;		/* success */
}


/*
 * sniffer_next
 *
 * Fill a structure with a copy of the next packet and its metadata.
 * Return 1 if packet is available, 0 if not and we need to read again.
 *
 * BPF: each packet is preceded by the following header:
 *  struct timeval  bh_tstamp;      time stamp
 *  bpf_u_int32     bh_caplen;      length of captured portion
 *  bpf_u_int32     bh_datalen;     original length of packet
 *  u_short         bh_hdrlen;      length of bpf header (this struct
 *                                      plus alignment padding)
 */
static int
sniffer_next(source_t *src, void *out_buf, size_t out_buf_size)
{
    static char buf[BUFSIZE];   /* base of the capture buffer */
    char *base;                 /* where to copy from */
    uint npkts;                 /* processed pkts */
    uint out_buf_used;          /* bytes in output buffer */
    int nbytes;			/* bytes in input buffer */

    /* read next batch of packets */
    nbytes = read(src->fd, buf, BUFSIZE);
    if (nbytes < 0)   
        return nbytes;

    base = buf;
    npkts = out_buf_used = 0;
    while (nbytes - (base - buf) > (int) sizeof(struct bpf_hdr)) { 
        struct bpf_hdr * bh;        /* BPF record structure */
        pkt_t *pkt;                 /* CoMo record structure */
        int len;                    /* total record length */
        int pktofs;                 /* offset in current record */
 
        bh = (struct bpf_hdr *) base; 
        len = (int) bh->bh_caplen + (int) bh->bh_hdrlen; 

        /* check if we have enough space in output buffer */
        if (sizeof(pkt_t) + len > out_buf_size - out_buf_used)
            break;

        /* check if entire record is available */
        if (len > nbytes - (int) (base - buf))
            break;

        /*
         * Now we have a packet: start filling a new pkt_t struct
         * (beware that it could be discarded later on)
         */
        pkt = (pkt_t *) ((char *)out_buf + out_buf_used);
        pkt->ts = TIME2TS(bh->bh_tstamp.tv_sec, bh->bh_tstamp.tv_usec);
        pkt->len = bh->bh_datalen; 
	pkt->type = COMO_L2_ETH; 
	pkt->flags = 0; 
        pkt->caplen = 0;        /* NOTE: we update caplen as we go given
                                 * that we may not store all fields that
                                 * exists in the actual bpf packet (e.g.,
                                 * IP options)
                                 */

        /* skip BPF header, move the base pointer in the batch of 
	 * packets and the offset within this packet  
	 */
        pktofs = bh->bh_hdrlen; 
        base += bh->bh_hdrlen;

        /* copy MAC information
         * XXX we do this only for ethernet frames.
         *     should look into how many pcap format exists and are
         *     actually used.
         */
        bcopy(base, &pkt->layer2.eth, 14);
        if (H16(pkt->layer2.eth.type) != 0x0800) {
            /*
             * this is not an IP packet. move the base pointer to next
             * packet and restart.
             */
            logmsg(LOGSNIFFER, "non-IP packet received (%04x)\n",
                H16(pkt->layer2.eth.type));
            base = (char*)bh + BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
            continue;
        }
        pktofs += 14;
        base += 14;

        /* copy IP header */
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

	/* bpf aligns packets to long word */
	base = (char *)bh + BPF_WORDALIGN(bh->bh_caplen + bh->bh_hdrlen); 
        out_buf_used += STDPKT_LEN(pkt); 
    }

    /* return the number of copied packets */
    return npkts;
}


/*
 * -- sniffer_stop
 *  
 * close file descriptor.
 */
static void
sniffer_stop(source_t * src)
{
    close(src->fd);
}

struct _sniffer bpf_sniffer = {
    "bpf", sniffer_start, sniffer_next, sniffer_stop, 0};
