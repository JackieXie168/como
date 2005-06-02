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

#include <sys/stat.h>
#include <fcntl.h>      /* open */
#include <unistd.h>     /* close */
#include <string.h>     /* memset */
#include <pcap.h>

#include "sniffers.h"
#include "como.h"

/*
 * Many pcap_* functions require a buffer of PCAP_ERRBUF_SIZE bytes to
 * store possible error messages. So don't touch :)
 */
static char errbuf[PCAP_ERRBUF_SIZE];

/* 
 * default values for libpcap 
 */
#define LIBPCAP_DEFAULT_PROMISC 1		/* promiscous mode */
#define LIBPCAP_DEFAULT_SNAPLEN 96		/* packet capture */
#define LIBPCAP_DEFAULT_TIMEOUT 0		/* timeout to serve packets */

/*
 * This data structure will be stored in the source_t structure and 
 * used for successive callbacks.
 */
struct _snifferinfo {
    pcap_t *pcap;	/* pcap handle */
    uint snaplen; 
}; 
    

/*
 * -- sniffer_start
 * 
 * open the pcap device using the options provided.
 * this sniffer needs to keep some information in the source_t 
 * data structure. It returns 0 on success and -1 on failure.
 * 
 */
static int
sniffer_start(source_t * src)
{
    struct _snifferinfo * info;
    uint promisc = LIBPCAP_DEFAULT_PROMISC; 
    uint snaplen = LIBPCAP_DEFAULT_SNAPLEN; 
    uint timeout = LIBPCAP_DEFAULT_TIMEOUT; 

    errbuf[0] = '\0';

    if (src->args) { 
	/* process input arguments */
	char * p; 

	if ((p = strstr(src->args, "promisc=")) != NULL) 
            promisc = atoi(p + 8);
	if ((p = strstr(src->args, "snaplen=")) != NULL) 
            snaplen = atoi(p + 8);
	if ((p = strstr(src->args, "timeout=")) != NULL) 
            timeout = atoi(p + 8);
    }

    logmsg(V_LOGSNIFFER, 
	"sniffer-libpcap: promisc %d, snaplen %d, timeout %d\n",
	promisc, snaplen, timeout); 

    /* 
     * allocate the _snifferinfo and link it to the 
     * source_t data structure
     */
    src->ptr = safe_malloc(sizeof(struct _snifferinfo)); 
    info = (struct _snifferinfo *) src->ptr; 

    /* initialize the pcap handle */
    info->pcap = pcap_open_live(src->device, snaplen, promisc, timeout, errbuf);
    info->snaplen = snaplen; 
    
    /* check for initialization errors */
    if (info->pcap == NULL) {
        logmsg(LOGWARN, "%s\n", errbuf);
	free(src->ptr); 
        return -1;
    }
    if (errbuf[0] != '\0')
        logmsg(LOGWARN, "%s\n", errbuf);
    
    /*
     * It is very important to set pcap in non-blocking mode, otherwise
     * sniffer_next() will try to fill the entire buffer before returning.
     */
    if (pcap_setnonblock(info->pcap, 1, errbuf) < 0) {
        logmsg(LOGWARN, "%s\n", errbuf);
	free(src->ptr);
        return -1;
    }
    
    /* 
     * we only support Ethernet frames so far. 
     */
    if (pcap_datalink(info->pcap) != DLT_EN10MB) {
	logmsg(LOGWARN, "libpcap sniffer: Unrecognized datalink format\n" );
	pcap_close(info->pcap);
	return -1;
    }
    
    src->fd = pcap_fileno(info->pcap);
    return 0; 		/* success */
}


/*
 * Here, we basically replicate the implementation of pcap_next():
 * this is because the pcap(3) man page (which is wrong in many respects)i
 * claims that pcap_next() is unaffected by pcap_setnonblock(), while
 * pcap_dispatch() is declared affected; this is crearly wrong as
 * pcap_next() is itself implemented through a call to pcap_dispatch()!
 * Anyway, as this implementation detail could change in the future, we
 * stick to the man page and call pcap_dispatch() anyway.
 */
typedef struct {
    struct pcap_pkthdr *hdr;
    const u_char *pkt;
} libpcap_pkt;

/* this is the callback as needed by pcap_dispatch */
static void
libpcap_onepkt(u_char *userData, const struct pcap_pkthdr *h, const u_char *pkt)
{
    libpcap_pkt *sp = (libpcap_pkt*)userData;
    *sp->hdr = *h;
    sp->pkt = pkt;
}

static const u_char*
libpcap_fetch_one_pkt(pcap_t *p, struct pcap_pkthdr *h)
{
    libpcap_pkt s = {h, 0};
    if (pcap_dispatch(p, 1, libpcap_onepkt, (u_char*)&s) <= 0)
	return NULL;
    return s.pkt;
}

/*
 * -- sniffer_next 
 *
 * Reads all the available packets and fills an array of variable sized
 * pkt_t accordingly. Returns the number of packets in the buffer or -1 
 * in case of error 
 *
 * The raw data format depends on the input device.
 * Using libpcap, each packet is preceded by the following header:
 *   struct timeval ts;    time stamp
 *   int32 caplen;         length of the actually available data
 *   int32 len;            length of the entire packet (off wire)
 * 
 */
static int
sniffer_next(source_t * src, void * out_buf, size_t out_buf_size)
{
    struct _snifferinfo * info = (struct _snifferinfo *) src->ptr; 
    uint npkts;				/* processed packets */
    uint out_buf_used;			/* bytes in output buffer */

    npkts = out_buf_used = 0;
    while (sizeof(pkt_t) + info->snaplen < out_buf_size - out_buf_used) {
        struct pcap_pkthdr pkthdr;
        pkt_t *pkt;
        char *pcappkt;
	int pktofs; 
        
	/*
         * we have to retreive one packet at a time 
         * because of their variable length
         */
	pktofs = 0;
        memset(&pkthdr, 0, sizeof(struct pcap_pkthdr));
        pcappkt = (u_char *) libpcap_fetch_one_pkt(info->pcap, &pkthdr);
        if (pcappkt == NULL)
	    break;
       
	/*
	 * Now we have a packet: start filling a new pkt_t struct 
	 * (beware that it could be discarded later on)
	 */
        pkt = (pkt_t *) ((char *)out_buf + out_buf_used);
        pkt->ts = TIME2TS(pkthdr.ts.tv_sec, pkthdr.ts.tv_usec);
        pkt->len = pkthdr.len;
	pkt->caplen = pkthdr.caplen; 

        /*
         * copy the packet payload
         */
        bcopy(pcappkt, pkt->payload, pkt->caplen); 

        /*
         * update layer2 information and offsets of layer 3 and above.
         * this sniffer only runs on ethernet frames.
         */
        updateofs(pkt, COMO_L2_ETH);

        /* increment the number of processed packets */
        npkts++;
        out_buf_used += STDPKT_LEN(pkt);
    }
    
    return npkts;
}


/*
 * -- sniffer_stop 
 * 
 * close the pcap descriptor and destroy the entry in the
 * list of pcap devices. 
 */
static void
sniffer_stop(source_t * src) 
{
    struct _snifferinfo * info = (struct _snifferinfo *) src->ptr; 
    
    close(src->fd);
    pcap_close(info->pcap);
    free(src->ptr);
}

struct _sniffer libpcap_sniffer = { 
    "libpcap", sniffer_start, sniffer_next, sniffer_stop, 0};
