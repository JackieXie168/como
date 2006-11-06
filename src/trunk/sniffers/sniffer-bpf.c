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

#include "capbuf.c"

/*
 * SNIFFER  ---    Berkeley Packet Filter
 *
 * Ethernet cards that support BPF.
 * It directly accesses the bpf device.
 *
 */

/* sniffer-specific information */
#define BPF_DEFAULT_MIN_PROC_SIZE	(65536 * 2)
#define BPF_DEFAULT_READ_SIZE		(500 * 1024) /* NOTE: bpf max buffer
							size is 0x80000 */
#define BPF_MIN_BUFSIZE			(BPF_DEFAULT_READ_SIZE * 2)
#define BPF_MAX_BUFSIZE			(BPF_MIN_BUFSIZE * 2)
#define BPF_MIN_PKTBUFSIZE		(me->sniff.max_pkts * sizeof(pkt_t))
#define BPF_MAX_PKTBUFSIZE		(BPF_MIN_PKTBUFSIZE * 2)

struct bpf_me {
    sniffer_t		sniff;		/* common fields, must be the first */
    const char *	device;
    size_t		min_proc_size;
    size_t		read_size;
    capbuf_t		capbuf;		/* payload capture buffer */
    capbuf_t		pktbuf;		/* pkt_t buffer */
};

/*
 * -- sniffer_init
 * 
 */
static sniffer_t *
sniffer_init(const char * device, const char * args)
{
    struct bpf_me *me;
    
    me = safe_calloc(1, sizeof(struct bpf_me));

    me->sniff.max_pkts = 8192;
    me->sniff.flags = SNIFF_SELECT | SNIFF_SHBUF;
    me->device = device;
    
    /* create the capture buffer */
    if (capbuf_init(&me->capbuf, args, NULL, BPF_MIN_BUFSIZE,
		    BPF_MAX_BUFSIZE) < 0)
	goto error;

    /* create the pkt_t buffer */
    if (capbuf_init(&me->pktbuf, args, "pktbuf=", BPF_MIN_PKTBUFSIZE,
		    BPF_MAX_PKTBUFSIZE) < 0)
	goto error;

    me->read_size = me->capbuf.size / 2;
    me->min_proc_size = BPF_DEFAULT_MIN_PROC_SIZE;
    
    return (sniffer_t *) me;
error:
    free(me);
    return NULL; 
}


static void
sniffer_setup_metadesc(__attribute__((__unused__)) sniffer_t * s)
{
    metadesc_t *outmd;
    pkt_t *pkt;

    /* setup output descriptor */
    outmd = metadesc_define_sniffer_out(s, 0);
    
    pkt = metadesc_tpl_add(outmd, "link:eth:any:any");
    pkt = metadesc_tpl_add(outmd, "link:vlan:any:any");
    pkt = metadesc_tpl_add(outmd, "link:isl:any:any");
}


/*
 * -- sniffer_start
 * 
 * it looks for an available bpf device and sets it 
 * up accordingly. It returns 0 on success and -1 on failure.
 */
static int
sniffer_start(sniffer_t * s)
{
    struct bpf_me *me = (struct bpf_me *) s;
    char bpfdev[PATH_MAX];
    struct ifreq ifr;
    int fd = -1;
    int n;

    if (strlen(me->device) + 1 > sizeof(ifr.ifr_name)) {
        errno = EINVAL;
        logmsg(LOGWARN, "sniffer-bpf: invalid device name\n");
        goto error;
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
        goto error;
    }

    /* setting the buffer size for next read calls */
    n = me->read_size;
    if (ioctl(fd, BIOCSBLEN, &n)) {
	logmsg(LOGWARN, "sniffer-bpf: BIOCSBLEN failed\n");
        goto error;
    }

    /* read packets as soon as they are received */
    n = 1;
    if (ioctl(fd, BIOCIMMEDIATE, &n) < 0) {
	logmsg(LOGWARN, "sniffer-bpf: BIOCIMMEDIATE failed\n");
        goto error;
    }

    /* no timeout on read requests */
    n = 0;
    if (ioctl(fd, BIOCSRTIMEOUT, &n) < 0) {
	logmsg(LOGWARN, "sniffer-bpf: BIOCSRTIMEOUT failed\n");
        goto error;
    }

    /* interface we capture packets from */
    strncpy(ifr.ifr_name, me->device, sizeof(ifr.ifr_name));
    if (ioctl(fd, BIOCSETIF, &ifr)) {
	logmsg(LOGWARN, "sniffer-bpf: BIOCSETIF failed\n");
        goto error;
    }

    /* set the interface in promiscous mode */
    if (ioctl(fd, BIOCPROMISC) < 0) {
	logmsg(LOGWARN, "sniffer-bpf: BIOCPROMISC failed\n");
        goto error;
    }

    /* check the type of frames, we only support Ethernet */
    if (ioctl(fd, BIOCGDLT, &n) < 0) {
	logmsg(LOGWARN, "sniffer-bpf: BIOCGDLT failed\n");
        goto error;
    }

    if (n != DLT_EN10MB) {
        logmsg(LOGWARN, "bpf sniffer: unrecognized link type (%d)\n", n);
        goto error;
    }

    me->sniff.fd = fd;

    return 0;		/* success */
error:
    close(fd);
    return -1;
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
sniffer_next(sniffer_t * s, int max_pkts,
             __attribute__((__unused__)) timestamp_t max_ivl,
	     pkt_t * first_ref_pkt, int * dropped_pkts)
{
    struct bpf_me *me = (struct bpf_me *) s;
    char * base;                /* current position in input buffer */
    int npkts;                  /* processed pkts */
    size_t avn;
    ssize_t rdn;

    *dropped_pkts = 0;
    
    capbuf_begin(&me->capbuf, first_ref_pkt);
    capbuf_begin(&me->pktbuf, first_ref_pkt? first_ref_pkt->payload : NULL);
    
    base = capbuf_reserve_space(&me->capbuf, me->read_size);
    /* read packets */
    rdn = read(me->sniff.fd, base, me->read_size);
    if (rdn <= 0) {
	return -1;
    }
    avn = BPF_WORDALIGN((size_t) rdn);
    if (avn < me->read_size) {
	capbuf_truncate(&me->capbuf, base + avn);
    }

    for (npkts = 0; npkts < max_pkts; npkts++) {
	size_t sz;
	pkt_t *pkt;
	struct bpf_hdr *bh; /* BPF record structure */
        
	/* check if we have enough for a new packet record */
	if (sizeof(struct bpf_hdr) > avn)
	    break;

	bh = (struct bpf_hdr *) base;
	
	/* check if we have the payload as well */
        if (bh->bh_hdrlen + bh->bh_caplen > avn)
            break;

	/* reserve the space in the buffer for the pkt_t */
	pkt = (pkt_t *) capbuf_reserve_space(&me->pktbuf, sizeof(pkt_t));

	COMO(ts) = TIME2TS(bh->bh_tstamp.tv_sec, bh->bh_tstamp.tv_usec);
	COMO(len) = bh->bh_datalen;
	COMO(caplen) = bh->bh_caplen;
	COMO(payload) = base + bh->bh_hdrlen;
	COMO(type) = COMOTYPE_LINK;

	/* 
	 * update layer2 information and offsets of layer 3 and above. 
	 * this sniffer only runs on ethernet frames. 
	 */
	updateofs(pkt, L2, LINKTYPE_ETH);

	ppbuf_capture(me->sniff.ppbuf, pkt);

	/* bpf aligns packets to long word */
	sz = BPF_WORDALIGN(bh->bh_caplen + bh->bh_hdrlen);
	/* move forward */
	base += sz;
	avn -= sz;
    }

    return 0;
}


static float
sniffer_usage(sniffer_t * s, pkt_t * first, pkt_t * last)
{
    struct bpf_me *me = (struct bpf_me *) s;
    size_t sz;
    void * y;
    float u1, u2;
    
    y = ((void *) last) + last->caplen;
    sz = capbuf_region_size(&me->capbuf, first, y);
    u1 = (float) sz / (float) me->capbuf.size;

    y = ((void *) last) + sizeof(pkt_t);
    sz = capbuf_region_size(&me->pktbuf, first, y);
    u2 = (float) sz / (float) me->pktbuf.size;

    return (u1 > u2) ? u1 : u2; /* return the maximum */
}


/*
 * -- sniffer_stop
 *  
 * close file descriptor.
 */
static void
sniffer_stop(sniffer_t * s) 
{
    struct bpf_me *me = (struct bpf_me *) s;
    
    close(me->sniff.fd);
}


static void
sniffer_finish(sniffer_t * s)
{
    struct bpf_me *me = (struct bpf_me *) s;

    capbuf_finish(&me->capbuf);
    capbuf_finish(&me->pktbuf);
    free(me);
}


SNIFFER(bpf) = {
    name: "bpf",
    init: sniffer_init,
    finish: sniffer_finish,
    setup_metadesc: sniffer_setup_metadesc,
    start: sniffer_start,
    next: sniffer_next,
    stop: sniffer_stop,
    usage: sniffer_usage
};
