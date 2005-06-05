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
#include <errno.h>
#include <dlfcn.h>	/* dlopen */
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
 * functions that we need from libpcap.so 
 */
typedef int (*sniff_pcap_dispatch)(pcap_t *, int, pcap_handler, u_char *); 
typedef pcap_t * (*sniff_pcap_open)(const char *, int, int, int, char *);
typedef void (*sniff_pcap_close)(pcap_t *); 
typedef int (*sniff_pcap_noblock)(pcap_t *, int, char *); 
typedef int (*sniff_pcap_fileno)(pcap_t *); 
typedef int (*sniff_pcap_datalink)(pcap_t *); 

/*
 * This data structure will be stored in the source_t structure and 
 * used for successive callbacks.
 */
struct _snifferinfo {
    void * handle;  			/* handle to libpcap.so */
    sniff_pcap_dispatch dispatch;	/* ptr to pcap_dispatch function */
    pcap_t *pcap;			/* pcap handle */
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
    sniff_pcap_open sp_open; 
    sniff_pcap_fileno sp_fileno;
    sniff_pcap_noblock sp_noblock; 
    sniff_pcap_datalink sp_link; 
    sniff_pcap_close sp_close; 

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

    /* link the libpcap library */
    info->handle = dlopen("libpcap.so", RTLD_NOW);
    if (info->handle == NULL) { 
	logmsg(LOGWARN, "sniffer %s opening libpcap.so: %s\n", 
	    src->cb->name, strerror(errno)); 
	free(src->ptr); 
	return -1; 
    } 

    /* find all the symbols that we will need */
    sp_open = (sniff_pcap_open) dlfunc(info->handle, "pcap_open_live");  
    sp_noblock = (sniff_pcap_noblock) dlfunc(info->handle, "pcap_setnonblock"); 
    sp_link = (sniff_pcap_datalink) dlfunc(info->handle, "pcap_datalink"); 
    sp_fileno = (sniff_pcap_fileno) dlfunc(info->handle, "pcap_fileno"); 
    sp_close = (sniff_pcap_close) dlfunc(info->handle, "pcap_close"); 
    info->dispatch = (sniff_pcap_dispatch) dlfunc(info->handle,"pcap_dispatch");
	    
    /* initialize the pcap handle */
    info->pcap = sp_open(src->device, snaplen, promisc, timeout, errbuf);
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
    if (sp_noblock(info->pcap, 1, errbuf) < 0) {
        logmsg(LOGWARN, "%s\n", errbuf);
	free(src->ptr);
        return -1;
    }
    
    /* 
     * we only support Ethernet frames so far. 
     */
    if (sp_link(info->pcap) != DLT_EN10MB) {
	logmsg(LOGWARN, "libpcap sniffer: Unrecognized datalink format\n" );
	sp_close(info->pcap);
	return -1;
    }
    
    src->fd = sp_fileno(info->pcap);
    return 0; 		/* success */
}


/* 
 * -- processpkt
 * 
 * this is the callback needed by pcap_dispatch. we use it to 
 * copy the data from the pcap packet into a pkt_t data structure. 
 * 
 */
static void
processpkt(u_char *data, const struct pcap_pkthdr *h, const u_char *buf)
{
    pkt_t * pkt = (pkt_t *) data; 
    pkt->ts = TIME2TS(h->ts.tv_sec, h->ts.tv_usec);
    pkt->len = h->len;
    pkt->caplen = h->caplen;

    /*
     * copy the packet payload
     */
    bcopy(buf, pkt->payload, pkt->caplen);
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
	int count; 
	char * buf;
        pkt_t *pkt;
        
	/*
	 * we use pcap_dispatch() because pcap_next() is assumend unaffected
	 * by the pcap_setnonblock() call. (but it doesn't seem that this is 
	 * actually the case but we still believe the man page. 
 	 * 
	 * we retrieve one packet at a time for simplicity. 
	 * XXX check the cost of processing one packet at a time? 
	 * 
	 */
	buf = out_buf + out_buf_used; 
	count = info->dispatch(info->pcap, 1, processpkt, buf); 
	if (count == 0) 
	    break;; 

        /*
         * update layer2 information and offsets of layer 3 and above.
         * this sniffer only runs on ethernet frames.
         */
	pkt = (pkt_t *) buf; 
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
    sniff_pcap_close sp_close; 
    
    close(src->fd);
    sp_close = (sniff_pcap_close) dlfunc(info->handle, "pcap_close"); 
    sp_close(info->pcap);
    free(src->ptr);
}

struct _sniffer libpcap_sniffer = { 
    "libpcap", sniffer_start, sniffer_next, sniffer_stop, 0};
