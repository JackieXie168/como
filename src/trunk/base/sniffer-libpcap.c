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

#ifndef USE_STARGATE
#include <pcap.h>
#else
#include "pcap-stargate.h"
#endif

#include "sniffers.h"
#include "como.h"


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
#define BUFSIZE		(1024 * 1024)
struct _snifferinfo {
    void * handle;  			/* handle to libpcap.so */
    sniff_pcap_dispatch dispatch;	/* ptr to pcap_dispatch function */
    pcap_t *pcap;			/* pcap handle */
    int type; 				/* como type (link layer) */
    uint snaplen; 			/* capture length */
    char pktbuf[BUFSIZE];		/* packet buffer */
    char errbuf[PCAP_ERRBUF_SIZE + 1];	/* error buffer for libpcap */
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
    src->ptr = safe_calloc(1, sizeof(struct _snifferinfo)); 
    info = (struct _snifferinfo *) src->ptr; 

    /* link the libpcap library */
    info->handle = dlopen("libpcap.so", RTLD_NOW);
    if (info->handle == NULL) { 
	logmsg(LOGWARN, "sniffer %s error opening libpcap.so: %s\n", 
	    src->cb->name, strerror(errno)); 
	free(src->ptr); 
	return -1; 
    } 

    /* find all the symbols that we will need */
    sp_open = (sniff_pcap_open) dlsym(info->handle, "pcap_open_live");  
    sp_noblock = (sniff_pcap_noblock) dlsym(info->handle, "pcap_setnonblock"); 
    sp_link = (sniff_pcap_datalink) dlsym(info->handle, "pcap_datalink"); 
    sp_fileno = (sniff_pcap_fileno) dlsym(info->handle, "pcap_fileno"); 
    sp_close = (sniff_pcap_close) dlsym(info->handle, "pcap_close"); 
    info->dispatch = (sniff_pcap_dispatch) dlsym(info->handle,"pcap_dispatch");
	    
    /* initialize the pcap handle */
    info->pcap = sp_open(src->device, snaplen, promisc, timeout, info->errbuf);
    info->snaplen = snaplen; 
    
    /* check for initialization errors */
    if (info->pcap == NULL) {
        logmsg(LOGWARN, "%s\n", info->errbuf);
	free(src->ptr); 
        return -1;
    }
    if (info->errbuf[0] != '\0')
        logmsg(LOGWARN, "%s\n", info->errbuf);
    
    /*
     * It is very important to set pcap in non-blocking mode, otherwise
     * sniffer_next() will try to fill the entire buffer before returning.
     */
    if (sp_noblock(info->pcap, 1, info->errbuf) < 0) {
        logmsg(LOGWARN, "%s\n", info->errbuf);
	free(src->ptr);
        return -1;
    }
    
    /* 
     * we only support Ethernet frames so far. 
     */
    switch (sp_link(info->pcap)) { 
    case DLT_EN10MB: 
	info->type = COMOTYPE_ETH; 
	break; 

    case DLT_IEEE802_11: 
	info->type = COMOTYPE_WLAN; 
	break; 

#ifdef DLT_IEEE802_11_RADIO		
    /* some version of libpcap do not support this */
    case DLT_IEEE802_11_RADIO: 
	info->type = COMOTYPE_WLANR;	/* w/radio information */ 
	break; 
#endif

    default: 
	logmsg(LOGWARN, "libpcap sniffer: Unrecognized datalink format\n" );
	sp_close(info->pcap);
	return -1;
    }
    
    src->fd = sp_fileno(info->pcap);
    src->flags = SNIFF_SELECT; 
    src->polling = 0;
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
sniffer_next(source_t * src, pkt_t * out, int max_no) 
{
    struct _snifferinfo * info = (struct _snifferinfo *) src->ptr; 
    pkt_t * pkt;
    int npkts;				/* processed packets */
    int nbytes = 0; 

    for (npkts = 0, pkt = out; npkts < max_no; npkts++, pkt++) { 
	int count; 
        
	/* point the packet payload to next packet */
	pkt->payload = info->pktbuf + nbytes; 

	/*
	 * we use pcap_dispatch() because pcap_next() is assumend unaffected
	 * by the pcap_setnonblock() call. (but it doesn't seem that this is 
	 * actually the case but we still believe the man page. 
 	 * 
	 * we retrieve one packet at a time for simplicity. 
	 * XXX check the cost of processing one packet at a time? 
	 * 
	 */
	count = info->dispatch(info->pcap, 1, processpkt, (char *) pkt); 
	if (count == 0) 
	    break;

        /*
         * update layer2 information and offsets of layer 3 and above.
         * this sniffer only runs on ethernet frames.
         */
        updateofs(pkt, info->type);

	nbytes += pkt->caplen; 
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
    sp_close = (sniff_pcap_close) dlsym(info->handle, "pcap_close"); 
    sp_close(info->pcap);
    free(src->ptr);
}

struct _sniffer libpcap_sniffer = { 
    "libpcap", sniffer_start, sniffer_next, sniffer_stop
};
