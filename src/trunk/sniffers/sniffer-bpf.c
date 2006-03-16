/*
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
#include <net/if.h>
#include <net/bpf.h>

#include "sniffers.h"
#include "como.h"

/*
 * SNIFFER  ---    Berkeley Packet Filter
 *
 * Ethernet cards that support BPF.
 * It directly accesses the bpf device.
 *
 */

/* sniffer specific information */
#define BUFSIZE (500*1024) 	/* NOTE: bpf max buffersize is 0x80000 */
struct _snifferinfo { 
    char buf[BUFSIZE]; 
};


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
    metadesc_t *outmd;
    pkt_t *pkt;

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
    src->flags = SNIFF_SELECT|SNIFF_TOUCHED; 
    src->polling = 0; 
    src->ptr = safe_malloc(sizeof(struct _snifferinfo)); 
    
    /* setup output descriptor */
    outmd = metadesc_define_sniffer_out(src, 0);
    
    pkt = metadesc_tpl_add(outmd, "link:eth:any:any");
    pkt = metadesc_tpl_add(outmd, "link:vlan:any:any");
    pkt = metadesc_tpl_add(outmd, "link:isl:any:any");

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
sniffer_next(source_t *src, pkt_t *out, int max_no) 
{
    struct _snifferinfo * info; /* sniffer specific information */
    pkt_t * pkt; 		/* CoMo packet structure */
    char * wh;                  /* where to copy from */
    int npkts;                  /* processed pkts */
    int nbytes; 		/* valid bytes in buffer */

    info = (struct _snifferinfo *) src->ptr; 

    /* read next batch of packets */
    nbytes = read(src->fd, info->buf, BUFSIZE);
    if (nbytes < 0)   
        return nbytes;

    wh = info->buf;
    for (npkts = 0, pkt = out; npkts < max_no; npkts++, pkt++) { 
        struct bpf_hdr * bh;        /* BPF record structure */
        int left; 
 
        bh = (struct bpf_hdr *) wh; 
	left = nbytes - (int) (wh - info->buf); 

	/* check if there is a full bpf header */
	if (left < (int) sizeof(struct bpf_hdr)) 
	    break; 

        /* check if entire record is available */
        if (left < (int) (bh->bh_hdrlen + bh->bh_caplen)) 
            break;

        /*
         * Now we have a packet: start filling a new pkt_t struct
         * (beware that it could be discarded later on)
         */
	COMO(ts) = TIME2TS(bh->bh_tstamp.tv_sec, bh->bh_tstamp.tv_usec);
	COMO(len) = bh->bh_datalen;
	COMO(caplen) = bh->bh_caplen;
	COMO(payload) = wh + bh->bh_hdrlen;
	COMO(type) = COMOTYPE_LINK;

	/* 
	 * update layer2 information and offsets of layer 3 and above. 
	 * this sniffer only runs on ethernet frames. 
	 */
	updateofs(pkt, L2, LINKTYPE_ETH);

	/* bpf aligns packets to long word */
	wh += BPF_WORDALIGN(bh->bh_caplen + bh->bh_hdrlen); 
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
    free(src->ptr); 
    close(src->fd);
}

struct _sniffer bpf_sniffer = {
    "bpf", sniffer_start, sniffer_next, sniffer_stop
};
