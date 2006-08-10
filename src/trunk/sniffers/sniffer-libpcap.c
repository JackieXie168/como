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


#include <sys/stat.h>
#include <fcntl.h>      /* open */
#include <unistd.h>     /* close */
#include <string.h>     /* memset */
#include <errno.h>
#include <dlfcn.h>	/* dlopen */

#include "como.h"
#include "sniffers.h"
#include "pcap.h"

#include "capbuf.c"

/* 
 * default values for libpcap 
 */
#define LIBPCAP_DEFAULT_PROMISC	1		/* promiscous mode */
#define LIBPCAP_DEFAULT_SNAPLEN	96		/* packet capture */
#define LIBPCAP_DEFAULT_TIMEOUT	0		/* timeout to serve packets */
#define LIBPCAP_MIN_BUFSIZE	(1024 * 1024)
#define LIBPCAP_MAX_BUFSIZE	(LIBPCAP_MIN_BUFSIZE * 2)

/* 
 * functions that we need from libpcap.so 
 */
typedef int (*pcap_dispatch_fn)(pcap_t *, int, pcap_handler, u_char *); 
typedef pcap_t * (*pcap_open_live_fn)(const char *, int, int, int, char *);
typedef void (*pcap_close_fn)(pcap_t *); 
typedef int (*pcap_setnonblock_fn)(pcap_t *, int, char *); 
typedef int (*pcap_fileno_fn)(pcap_t *); 
typedef int (*pcap_datalink_fn)(pcap_t *); 

/*
 * This data structure will be stored in the source_t structure and 
 * used for successive callbacks.
 */

struct libpcap_me {
    sniffer_t		sniff;		/* common fields, must be the first */
    void *		handle;		/* handle to libpcap.so */
    pcap_dispatch_fn	sp_dispatch;	/* ptr to pcap_dispatch function */
    pcap_close_fn	sp_close;	/* ptr to pcap_close function */
    pcap_t *		pcap;		/* pcap handle */
    enum LINKTYPE	l2type; 	/* link layer type */
    const char *	device;		/* capture device */
    int			promisc;	/* set interface in promisc mode */
    int			snaplen; 	/* capture length */
    int			timeout;	/* capture timeout */
    char		errbuf[PCAP_ERRBUF_SIZE + 1]; /* error buffer */
    capbuf_t		capbuf;
};

/*
 * -- sniffer_init
 * 
 */
static sniffer_t *
sniffer_init(const char * device, const char * args)
{
    struct libpcap_me *me;

    me = safe_calloc(1, sizeof(struct libpcap_me));
    
    me->sniff.max_pkts = 128;
    me->sniff.flags = SNIFF_SELECT;
    me->promisc = LIBPCAP_DEFAULT_PROMISC;
    me->snaplen = LIBPCAP_DEFAULT_SNAPLEN;
    me->timeout = LIBPCAP_DEFAULT_TIMEOUT;
    me->device = device;

    if (args) { 
	/* process input arguments */
	char *p; 

	if ((p = strstr(args, "promisc=")) != NULL) {
	    me->promisc = atoi(p + 8);
	}
	if ((p = strstr(args, "snaplen=")) != NULL) {
	    me->snaplen = atoi(p + 8);
	    if (me->snaplen < 1 || me->snaplen > 65536) {
		logmsg(LOGWARN,
		       "sniffer-libpcap: invalid snaplen %d, using %d\n",
		       me->snaplen, LIBPCAP_DEFAULT_SNAPLEN);
		me->snaplen = LIBPCAP_DEFAULT_SNAPLEN;
	    }
	}
	if ((p = strstr(args, "timeout=")) != NULL) {
	    me->timeout = atoi(p + 8);
	}
    }

    logmsg(V_LOGSNIFFER, 
	   "sniffer-libpcap: device %s, promisc %d, snaplen %d, timeout %d\n",
	   device, me->promisc, me->snaplen, me->timeout);

    /* link the libpcap library */
    me->handle = dlopen("libpcap.so", RTLD_NOW);
    if (me->handle == NULL) { 
	logmsg(LOGWARN, "sniffer-libpcap: error opening libpcap.so: %s\n",
	       dlerror());
	goto error;
    } 

    /* find all the symbols that we will need */
#define SYMBOL(name) dlsym(me->handle, name)

    me->sp_close = (pcap_close_fn) SYMBOL("pcap_close"); 
    me->sp_dispatch = (pcap_dispatch_fn) SYMBOL("pcap_dispatch");

    /* create the capture buffer */
    if (capbuf_init(&me->capbuf, args, LIBPCAP_MIN_BUFSIZE,
		    LIBPCAP_MAX_BUFSIZE) < 0)
	goto error;

    return (sniffer_t *) me;
error:
    if (me->handle) {
	dlclose(me->handle);
    }
    free(me);
    return NULL;
}


static void
sniffer_setup_metadesc(sniffer_t * s)
{
    struct libpcap_me *me = (struct libpcap_me *) s;
    metadesc_t *outmd;
    pkt_t *pkt;

    /* setup output descriptor */
    outmd = metadesc_define_sniffer_out(s, 0);
    
    pkt = metadesc_tpl_add(outmd, "link:eth:any:any");
    COMO(caplen) = me->snaplen;
    pkt = metadesc_tpl_add(outmd, "link:vlan:any:any");
    COMO(caplen) = me->snaplen;
    pkt = metadesc_tpl_add(outmd, "link:isl:any:any");
    COMO(caplen) = me->snaplen;
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
sniffer_start(sniffer_t * s)
{
    struct libpcap_me *me = (struct libpcap_me *) s;
    pcap_open_live_fn sp_open_live;
    pcap_setnonblock_fn sp_setnonblock;
    pcap_datalink_fn sp_datalink;
    pcap_fileno_fn sp_fileno;

    /* find all the symbols that we will need */
    sp_open_live = (pcap_open_live_fn) SYMBOL("pcap_open_live");  
    sp_setnonblock = (pcap_setnonblock_fn) SYMBOL("pcap_setnonblock"); 
    sp_datalink = (pcap_datalink_fn) SYMBOL("pcap_datalink"); 
    sp_fileno = (pcap_fileno_fn) SYMBOL("pcap_fileno"); 

    /* initialize the pcap handle */
    me->pcap = sp_open_live(me->device, me->snaplen, me->promisc,
			    me->timeout, me->errbuf);
    
    /* check for initialization errors */
    if (me->pcap == NULL) {
	logmsg(LOGWARN, "sniffer-libpcap: error: %s\n", me->errbuf);
	goto error;
    }
    if (me->errbuf[0] != '\0') {
	logmsg(LOGWARN, "sniffer-libpcap: %s\n", me->errbuf);
    }
    
    /*
     * It is very important to set pcap in non-blocking mode, otherwise
     * sniffer_next() will try to fill the entire buffer before returning.
     */
    if (sp_setnonblock(me->pcap, 1, me->errbuf) < 0) {
        logmsg(LOGWARN, "%s\n", me->errbuf);
        goto error;
    }
    
    /* 
     * we only support Ethernet frames so far. 
     */
    switch (sp_datalink(me->pcap)) { 
    case DLT_EN10MB: 
	me->l2type = LINKTYPE_ETH; 
	break; 
    default: 
    /* we do not support DLT_ values different from EN10MB. for 802.11
     * frames one can use sniffer-radio instead. 
     */
	logmsg(LOGWARN, "sniffer-libpcap: unrecognized datalink format\n" );
	goto error;
    }
    
    me->sniff.fd = sp_fileno(me->pcap);

    return 0; 		/* success */
error:
    if (me->pcap) {
	me->sp_close(me->pcap);
    }
    return -1;
}


/* 
 * -- processpkt
 * 
 * this is the callback needed by pcap_dispatch. we use it to 
 * copy the data from the pcap packet into a pkt_t data structure. 
 * 
 */
static void
processpkt(u_char * data, const struct pcap_pkthdr * h, const u_char * buf)
{
    size_t sz;
    pkt_t *pkt;
    struct libpcap_me *me = (struct libpcap_me *) data;

    sz = sizeof(pkt_t);
    sz += (size_t) h->caplen;
#ifdef BUILD_FOR_ARM
    sz += 2; /* 2 bytes of padding for ethernet header */
#endif

    /* reserve the space in the buffer for the packet */
    pkt = (pkt_t *) capbuf_reserve_space(&me->capbuf, sz);

    /* the payload points to the end of the pkt_t structure */
    COMO(payload) = (char *) (pkt + 1);
    
    COMO(ts) = TIME2TS(h->ts.tv_sec, h->ts.tv_usec);
    COMO(len) = h->len;
    COMO(caplen) = h->caplen;
    COMO(type) = COMOTYPE_LINK;

    /*
     * copy the packet payload
     */
#ifdef BUILD_FOR_ARM
  #if sizeof(struct _como_eth) != 14
    #error "ethernet header is 14 bytes!"
  #endif
    memcpy(COMO(payload), buf, 14);
    memcpy(COMO(payload) + 16, buf, h->caplen - 14);
#else
    memcpy(COMO(payload), buf, h->caplen);
#endif

    /*
     * update layer2 information and offsets of layer 3 and above.
     * this sniffer only runs on ethernet frames.
     */
    updateofs(pkt, L2, me->l2type);

    ppbuf_capture(me->sniff.ppbuf, pkt);
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
sniffer_next(sniffer_t * s, int max_pkts, __unused timestamp_t max_ivl,
	     int * dropped_pkts)
{
    struct libpcap_me *me = (struct libpcap_me *) s;
    int count, x;
    
    for (count = 0, x = 1; x > 0 && count < max_pkts; count += x) {
	x = me->sp_dispatch(me->pcap, max_pkts, processpkt,
			   (u_char *) me);
    }
    
    *dropped_pkts = 0;
    
    return (x >= 0) ? 0 : -1;
}


/*
 * -- sniffer_stop 
 * 
 * close the pcap descriptor and destroy the entry in the
 * list of pcap devices. 
 */
static void
sniffer_stop(sniffer_t * s) 
{
    struct libpcap_me *me = (struct libpcap_me *) s;
    
    me->sp_close(me->pcap);
}


static void
sniffer_finish(sniffer_t * s)
{
    struct libpcap_me *me = (struct libpcap_me *) s;
    
    dlclose(me->handle);
    capbuf_finish(&me->capbuf);
    free(me);
}


SNIFFER(libpcap) = {
    name: "libpcap",
    init: sniffer_init,
    finish: sniffer_finish,
    setup_metadesc: sniffer_setup_metadesc,
    start: sniffer_start,
    next: sniffer_next,
    stop: sniffer_stop,
};
