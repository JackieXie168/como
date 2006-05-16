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
#include <assert.h>

#include "como.h"
#include "sniffers.h"
#include "pcap.h"


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
    uint16_t l2type;		/* Layer 2 type */
    int littleendian;		/* set if pcap headers are bigendian */
    char buf[BUFSIZE];   	/* base of the capture buffer */
    int nbytes;      	 	/* valid bytes in buffer */
    char *base;			/* pointer to first valid byte in buffer */

    /* 
     * the following are needed to deal 
     * with IEEE 802.11 frames 
     */
    char mgmt_buf[BUFSIZE];	/* buffer for pre-processed packets */
    int mgmt_nbytes;		/* valid bytes in mgmt_buf */
    to_como_radio_fn to_como_radio;
};

static char s_protos[32];

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
    struct _snifferinfo *info;
    struct pcap_file_header pf;
    int swapped = 0;
    uint16_t type, l2type;
    int rd;
    int fd;
    to_como_radio_fn to_como_radio = NULL;
    metadesc_t *outmd;
    pkt_t *pkt;
    const headerinfo_t *lchi, *l2hi;

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
	type = COMOTYPE_LINK;
	l2type = LINKTYPE_ETH;
	break;
    case DLT_C_HDLC: 
	logmsg(LOGSNIFFER, "datalink HDLC (%d)\n", pf.linktype); 
	type = COMOTYPE_LINK;
	l2type = LINKTYPE_HDLC;
	break;
    case DLT_IEEE802_11: 
	logmsg(LOGSNIFFER, "datalink 802.11 (%d)\n", pf.linktype); 
	type = COMOTYPE_LINK;
	l2type = LINKTYPE_80211;
	break;
    case DLT_IEEE802_11_RADIO_AVS:
	logmsg(LOGSNIFFER,
	       "datalink 802.11 with AVS header (%d)\n", pf.linktype);
	type = COMOTYPE_LINK;
	l2type = LINKTYPE_80211;
	to_como_radio = avs_header_to_como_radio;
	break;
    case DLT_PRISM_HEADER:
	logmsg(LOGSNIFFER,
	       "datalink 802.11 with Prism header (%d)\n", pf.linktype);
	type = COMOTYPE_RADIO;
	l2type = LINKTYPE_80211;
	to_como_radio = avs_or_prism2_header_to_como_radio;
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
    info->l2type = l2type;
    info->littleendian = swapped;
    info->to_como_radio = to_como_radio;
    
    /* setup output descriptor */
    outmd = metadesc_define_sniffer_out(src, 0);
    
    lchi = headerinfo_lookup_with_type_and_layer(type, LCOMO);
    l2hi = headerinfo_lookup_with_type_and_layer(l2type, L2);
    assert(lchi);
    assert(lchi);
    
    snprintf(s_protos, 32, "%s:%s:any:any", lchi->name, l2hi->name);
    pkt = metadesc_tpl_add(outmd, s_protos);
    COMO(caplen) = pf.snaplen;
    
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
sniffer_next(source_t * src, pkt_t *out, int max_no, timestamp_t max_ivl) 
{
    struct _snifferinfo * info; 
    pkt_t *pkt;                 /* CoMo record structure */
    char * base;                /* current position in input buffer */
    int npkts;                  /* processed pkts */
    int rd;
    timestamp_t first_seen = 0;

    info = (struct _snifferinfo *) src->ptr;
    
    if (info->nbytes > 0) {
	memmove(info->buf, info->base, info->nbytes);
    }

    /* read pcap records from fd */
    rd = read(src->fd, info->buf + info->nbytes, BUFSIZE - info->nbytes);
    if (rd < 0)
        return rd;

    /* update number of bytes to read */
    info->nbytes += rd;
    if (info->nbytes == 0)
        return -1;       /* end of file, nothing left to do */

    info->mgmt_nbytes = 0;
    base = info->buf;
    pkt = out;
    npkts = 0;

    while (npkts < max_no) {
	pcap_hdr_t ph;
	int left = info->nbytes - (base - info->buf);
	int drop_this = 0;

	/* do we have a pcap header? */
	if (left < (int) sizeof(pcap_hdr_t))
	    break;

	/* XXX We use bcopy here because the base pointer may not be word
	 * aligned. This is an issue on some platforms like the Stargate */
	bcopy(base, &ph, sizeof(pcap_hdr_t));

	/* convert the header if needed */
	if (info->littleendian) {
	    ph.ts.tv_sec = swapl(ph.ts.tv_sec);
	    ph.ts.tv_usec = swapl(ph.ts.tv_usec);
	    ph.caplen = swapl(ph.caplen);
	    ph.len = swapl(ph.len);
	}

	/* check if entire record is available */
	if (left < (int) sizeof(pcap_hdr_t) + ph.caplen)
	    break;


	/*      
	 * Now we have a packet: start filling a new pkt_t struct
	 * (beware that it could be discarded later on)
	 */
	COMO(ts) = TIME2TS(ph.ts.tv_sec, ph.ts.tv_usec);
	
	if (npkts > 0) {
	    if (COMO(ts) - first_seen > max_ivl) {
		/* Never returns more than 1sec of traffic */
		break;
	    }
	} else {
	    first_seen = COMO(ts);
	}
	COMO(len) = ph.len;
	COMO(type) = info->type;

	if (info->type != COMOTYPE_RADIO && info->l2type != LINKTYPE_80211) {

	    COMO(caplen) = ph.caplen;
	    COMO(payload) = base + sizeof(pcap_hdr_t);
	} else {
	    char *buf, *dest;
	    int buf_len, dest_len;
	    int frame_len;

	    buf = base + sizeof(pcap_hdr_t);
	    buf_len = ph.caplen;

	    COMO(payload) = dest = info->mgmt_buf + info->mgmt_nbytes;
	    COMO(caplen) = dest_len = 0;

	    if (info->type == COMOTYPE_RADIO) {
		int info_len;
		struct _como_radio *radio;

		radio = (struct _como_radio *) dest;
		info_len = info->to_como_radio(buf, radio);

		buf += info_len;
		buf_len -= info_len;

		dest_len = sizeof(struct _como_radio);
		dest += dest_len;
	    }

	    frame_len = ieee80211_capture_frame(buf, buf_len, dest);
	    if (frame_len > 0) {
		dest_len += frame_len;
		COMO(caplen) = dest_len;
		info->mgmt_nbytes += dest_len;
	    } else {
		drop_this = 1;
	    }
	}

	if (drop_this == 0) {
	    /* 
	     * update layer2 information and offsets of layer 3 and above. 
	     * this sniffer runs on ethernet frames
	     */
	    updateofs(pkt, L2, info->l2type);
	    npkts++;
	    pkt++;
	} else {
	    src->drops++;
	}
	/* increment the number of processed packets */
	base += sizeof(pcap_hdr_t) + ph.caplen;
    }
    info->nbytes -= (base - info->buf);
    info->base = base;
    return npkts;
}


/* 
 * -- sniffer_stop
 * 
 * Close the file descriptor. 
 */
static void
sniffer_stop(source_t * src)
{
    free(src->ptr);
    close(src->fd);
}


sniffer_t pcap_sniffer = {
    "pcap", sniffer_start, sniffer_next, sniffer_stop
};
