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

#include <sys/ioctl.h>	/* ioctl for monitor mode */
#include <sys/socket.h>	/* socket for monitor mode */
#include <net/if.h>	/* struct ifr */

#include "como.h"
#include "sniffers.h"
#include "pcap.h"


/* 
 * default values for libpcap 
 */
#define LIBPCAP_DEFAULT_SNAPLEN 1500		/* packet capture */
#define LIBPCAP_DEFAULT_TIMEOUT 0		/* timeout to serve packets */

/* 
 * functions that we need from libpcap.so 
 */
typedef int (*sniff_pcap_dispatch)
			(pcap_t *, int, pcap_handler, u_char *); 
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
    uint32_t type; 
    sniff_pcap_dispatch dispatch;	/* ptr to pcap_dispatch function */
    pcap_t *pcap;			/* pcap handle */
    uint snaplen; 			/* capture length */
    char pktbuf[BUFSIZE];		/* packet buffer */
    char errbuf[PCAP_ERRBUF_SIZE + 1];	/* error buffer for libpcap */
}; 
    

#ifdef linux

/* 
 * under Linux we use the Wireless Extensions as they do in iwconfig. 
 * all the values for the ioctl() are different than in FreeBSD.
 * other OSes are supposed to behave like FreeBSD. 
 */

struct iw_freq { 
    int32_t m;
    int16_t e;
    uint8_t i;
    uint8_t flags; 
}; 

struct wlan_req { 
    char name[16]; 
    union {
        struct iw_freq  freq;
        uint32_t mode; 
    } u; 
};

#define SET_OPERATIONMODE	0x8B06
#define SET_CHANNEL		0x8B04
#define MONITOR_MODE		0x06 
#define FIXED_CHANNEL		0x01

#else 

/* 
 * ioctl request to set the interface in 
 * monitor mode. 
 */
struct wlan_req {
    u_int16_t       len;
    u_int16_t       type;
    u_int16_t	    val[512];
};

#define SET_OPERATIONMODE	_IOW('i', 137, struct ifreq)
#define SET_CHANNEL		_IOW('i', 137, struct ifreq)
#define MONITOR_MODE 		0x0B
#define FIXED_CHANNEL	        0x08

#endif


/* 
 * -- send_ioctl
 * 
 * ioctl to configure interface 
 */
void 
send_ioctl(char * device, struct wlan_req * req, int request) 
{
    struct ifreq ifr; 
    int s; 

#ifdef linux
    strcpy(req->name, device);
    bcopy(req, &ifr, sizeof(ifr)); 
#else 
    bzero((char *)&ifr, sizeof(ifr));
    strcpy(ifr.ifr_name, device);
    ifr.ifr_data = (caddr_t) req;
#endif

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == -1)
	panic("socket %s", ifr.ifr_name); 
    if (ioctl(s, request, &ifr) == -1)
	panic("ioclt %s (0x%x)", ifr.ifr_name, request); 
    close(s); 
}


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
    uint snaplen = LIBPCAP_DEFAULT_SNAPLEN; 
    uint timeout = LIBPCAP_DEFAULT_TIMEOUT; 
    uint channel = 0;
    sniff_pcap_open sp_open; 
    sniff_pcap_fileno sp_fileno;
    sniff_pcap_noblock sp_noblock; 
    sniff_pcap_datalink sp_link; 
    sniff_pcap_close sp_close; 
    struct wlan_req wreq;

    if (src->args) { 
	/* process input arguments */
	char * p; 
	char * val;

	if ((p = strstr(src->args, "snaplen")) != NULL) {
	    /* number of bytes to read from packet */
	    val = index(p, '=') + 1; 
            snaplen = atoi(val);
	} 
	if ((p = strstr(src->args, "timeout")) != NULL) {
	    /* timeout to regulate reception of packets */
	    val = index(p, '=') + 1; 
            timeout = atoi(val);
	}
	if ((p = strstr(src->args, "channel")) != NULL) {
	    /* frequency channel to monitor */
	    val = index(p, '=') + 1; 
            channel = atoi(val);
	    if (channel < 1) 
		channel = 1; 
	    else if (channel > 14) 
		channel = 14; 
	}
    }

    logmsg(V_LOGSNIFFER, 
	"sniffer-prism2: snaplen %d, timeout %d, channel %d\n", 
	snaplen, timeout, channel); 

    /* 
     * set the interface in monitor mode
     */
    bzero((char *)&wreq, sizeof(wreq));
#ifdef linux
    wreq.u.mode = MONITOR_MODE; 
#else 
    wreq.type = MONITOR_MODE; 
    wreq.len = 0;
#endif
    send_ioctl(src->device, &wreq, SET_OPERATIONMODE); 

    /* 
     * fix the channel, if requested 
     */
    if (channel != 0) { 
	bzero((char *)&wreq, sizeof(wreq));
#ifdef linux
        wreq.u.freq.m = 0; 
        wreq.u.freq.e = 0; 
        wreq.u.freq.i = channel; 
        wreq.u.freq.flags = FIXED_CHANNEL; 
#else
	wreq.type = FIXED_CHANNEL; 
	wreq.len = 1; 
	wreq.val[0] = channel; 
#endif
	send_ioctl(src->device, &wreq, SET_CHANNEL); 
    } 

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
    info->pcap = sp_open(src->device, snaplen, 0, timeout, info->errbuf);
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
   
    /* check datalink type.  support 802.11 DLT_ values */
    switch (sp_link(info->pcap)) {
    case DLT_PRISM_HEADER:
	info->type = COMOTYPE_RADIO;
	break;
    case DLT_IEEE802_11:
	info->type = COMOTYPE_80211;
	break;
    default:
        logmsg(LOGWARN, "libpcap sniffer: Unrecognized datalink format\n" );
        sp_close(info->pcap);
        return -1;
    }

    src->fd = sp_fileno(info->pcap);
    src->flags = SNIFF_TOUCHED|SNIFF_SELECT; 
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
 
    /* pkt->caplen padded to be 4 byte aligned. This takes care of
     * alignment issues on the ARM architecture.
     */

    /*
     * the management frame is redefined to include the 802.11 hdr +
     * capture hdr) plus the como management body structure
     */
    parse80211_frame(pkt, (char *) buf, pkt->payload, pkt->type);
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
    pkt_t * pkt = out;
    int npkts = 0 ;			/* processed packets */
    int nbytes = 0; 

    while (npkts < max_no) {
	int count; 
	
	/* point the packet payload to next packet */
	pkt->payload = info->pktbuf + nbytes; 
        /* specify 802.11 type */
	pkt->type = info->type; 

	/*
	 * we use pcap_dispatch() because pcap_next() is assumend unaffected
	 * by the pcap_setnonblock() call. (but it doesn't seem that this is 
	 * actually the case but we still believe the man page. 
 	 * 
	 * we retrieve one packet at a time for simplicity. 
	 * XXX check the cost of processing one packet at a time... 
	 * 
	 */

	count = info->dispatch(info->pcap, 1, processpkt, (u_char *) pkt); 
	if (count == 0) 
	    break;

	nbytes += pkt->caplen; 
	npkts++; 
	pkt++;
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

struct _sniffer prism2_sniffer = { 
    "prism2", sniffer_start, sniffer_next, sniffer_stop

};
