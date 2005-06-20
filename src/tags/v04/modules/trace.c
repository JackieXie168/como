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

/*
 * Packet trace Module
 *
 * This module collects a packet level trace.
 * The packet is dumped as it is layed out in pkt_t. 
 *
 * The hash table has only one entry in order to preserve arrival order.
 *
 */

#include <time.h>
#include <string.h>         /* bcopy */
#include <stdio.h>          /* fprintf, stderr */
#include <sys/types.h>
#include <net/ethernet.h>   /* ether_addr, ether_ntoa */

#include "como.h"
#include "module.h"


/* 
 * FLOWDESC just contains one packet. 
 * We will always match the record in the table so that CAPTURE will 
 * create a nice queue of packets for us and EXPORT will process it in 
 * FIFO order. 
 */
#define FLOWDESC	struct _trace
#define REC_SIZE	2048

FLOWDESC {
    int len; 
    char buf[REC_SIZE]; 
};


/*
 * bytes to capture in each packet. this excludes the layer2 header 
 * that is always as well as the CoMo header (with timestamp, etc.) 
 */
static int snaplen = 40; 

/* 
 * description of the output trace for sniffer-como
 */
static pktdesc_t outdesc;


static int 
init(__unused void *mem, __unused size_t msize, char * args[])
{
    if (args == NULL) 
	return 0; 

    if (strstr(args[0], "snaplen=")) { 
	char * len; 

	len = index(args[0], '='); 
	len++; 	/* skip '=' */
	snaplen = atoi(len); 		/* set the snaplen */
    } 

    memset(&outdesc, 0xff, sizeof(pktdesc_t));
    outdesc.caplen = snaplen; 
    return 0; 
}


static int
update(pkt_t *pkt, void *fh, __unused int isnew)
{
    FLOWDESC *x = F(fh);

    memcpy(x->buf, pkt, sizeof(pkt_t)); 
    memcpy(x->buf + sizeof(pkt_t), pkt->payload, pkt->caplen); 

    return 1;		/* records are always full */
}


static ssize_t
store(void *fh, char *buf, size_t len)
{
    FLOWDESC *x = F(fh);
    pkt_t * pkt; 
    size_t need;
    
    pkt = (pkt_t *) x->buf; 
    need = pkt->caplen + sizeof(pkt_t) ; 

    if (len < need)
        return -1;

    /* convert the CoMo header in network byte order */
    pkt->ts = HTONLL(pkt->ts); 
    pkt->caplen = htonl(pkt->caplen); 
    pkt->len = htonl(pkt->len); 
    pkt->l2type = htons(pkt->l2type); 
    pkt->l3type = htons(pkt->l3type); 
    pkt->layer3ofs = htons(pkt->layer3ofs); 
    pkt->layer4ofs = htons(pkt->layer4ofs); 
    pkt->payload = NULL; 

    memcpy(buf, pkt, need); 
    return need; 
}


static size_t
load(char * buf, size_t len, timestamp_t * ts)
{
    pkt_t * pkt; 

    if (len < REC_SIZE) {
        ts = 0;
        return 0;
    }

    pkt = (pkt_t *) buf; 
    *ts = NTOHLL(pkt->ts);
    return (sizeof(pkt_t) + ntohl(pkt->caplen)); 
}


#if 0 

/* XXX this is not needed for now. someone will have to spend some 
 *     time cleaning it up. right now it does not work. -gianluca
 *
 */

/*
 * utility function used to pretty print tcp's control bits status
 * TODO: could be moved in a shared utility file
 */
#define ADD_STR(m,x)    if(flags&(m)){strncpy(&s[i]," "x,4);i+=4;}

static char*
print_tcp_flags(uint8_t flags) {
    static char s[36];
    size_t i = 0;
    
    if (flags == 0)
        return NULL;
    
    ADD_STR(0x80, "cwr");
    ADD_STR(0x40, "ece");
    ADD_STR(0x20, "urg");
    ADD_STR(0x10, "ack");
    ADD_STR(0x08, "psh");
    ADD_STR(0x04, "rst");
    ADD_STR(0x02, "syn");
    ADD_STR(0x01, "fin");
    
    s[i] = '\0';
    return s;
}


#define OFFCOPY(d,s,n)  ((memcpy(d,s,n)),(n))

#define OUT_BUFF_SIZ    2048
#define  TIMESTR_LEN      15    /* strlen("MON DD HH:MM:SS") */
#define  IP_ADDR_LEN      15    /* strlen("XXX.XXX.XXX.XXX") */
#define MAC_ADDR_LEN      17    /* strlen("XX:XX:XX:XX:XX:XX") */

/* Ugly CPP tweak, needed to use macro constants *
 * within strings - see CPP manual chapter 3.4   */
#define STR(LEN)          #LEN
#define NUM(LEN)          STR(LEN)

/* TODO: move subsequent macros to a common file such as module.h */
#define GETH64(x)  NTOHLL(*(uint64_t*)(x))
#define GETH32(x)  ntohl(*(uint32_t*)(x))
#define GETH16(x)  ntohl(*(uint16_t*)(x))
#define GETH8(x)   (*(uint8_t*)(x))

#define MAC_ADDR(x)     (ether_ntoa((struct ether_addr*)&(x)))
#define IP_ADDR(x)      (inet_ntoa(*(struct in_addr*)&(N32(x))))

static char *
print (char *buf, size_t *out_len, __unused char * const args[])
{
    static char out[OUT_BUFF_SIZ];
    static char tss[TIMESTR_LEN + 1];
    static char src[IP_ADDR_LEN + 1];
    static char dst[IP_ADDR_LEN + 1];
#if PRINT_MAC
    static char msrc[MAC_ADDR_LEN + 1];
    static char mdst[MAC_ADDR_LEN + 1];
#endif
    uint16_t flags_ofs, flags, ofs;
    size_t len;
    time_t ts;
    pkt_t p;
    int off;
    
    /* copy the packet back in a pkt_t structure */
    memset(&p, 0, sizeof(pkt_t));
    
    p.ts      = GETH64(buf);
    p.caplen  = GETH32(buf + 8);
    p.len     = GETH32(buf + 12);

    off = 16;
    
    off += OFFCOPY(&p.mach, buf + off, MAC_H_SIZE);
    off += OFFCOPY(&p.ih,   buf + off,  IP_H_SIZE);
    off += OFFCOPY(&p.p,    buf + off, APP_H_SIZE);
    
    buf += off;
    
    /*
     * prepare a string with our desired timestamp output format
     *
     * if you want to display the year as well,
     * define TIMESTAMP_LEN as 20 and use "%Y %b %e %T" as format
     */
    ts = (time_t)TS2SEC(p.ts);
    strftime(tss, TIMESTR_LEN + 1, "%b %e %T", localtime(&ts));
    
    /* prepare ASCII strings for IP and MAC addresses */
#if PRINT_MAC
    snprintf(msrc, MAC_ADDR_LEN + 1, "%s", MAC_ADDR(p.mach.src));
    snprintf(mdst, MAC_ADDR_LEN + 1, "%s", MAC_ADDR(p.mach.dst));
#endif
    snprintf(src, IP_ADDR_LEN + 1, "%s", IP_ADDR(p.ih.src_ip));
    snprintf(dst, IP_ADDR_LEN + 1, "%s", IP_ADDR(p.ih.dst_ip));
    
    /* 
     * flags and offset from IP header are packet together
     * in the same field, so we have to split them
     */
    flags_ofs   = H16(p.ih.ofs);
    flags       = (flags_ofs & 0xe000) >> 13;
    ofs         = flags_ofs & 0x1fff;
    
    sprintf(out, "%s:%03u "
            "(%4u/%4uB) "
            "v%1hx %1uw tos:%2u %4uB "
            "id:%5u F(d%1hxm%1hx) +%4u "
            "ttl:%3u sip:%" NUM(IP_ADDR_LEN) "s"
#if PRINT_MAC
            " (%" NUM(MAC_ADDR_LEN) "s)"
#endif
            " dip:%" NUM(IP_ADDR_LEN) "s"
#if PRINT_MAC
            " (%" NUM(MAC_ADDR_LEN) "s)"
#endif
            " ",
            tss, TS2MSEC(p.ts),
            p.caplen, p.len,
            p.ih.vhl >> 4, p.ih.vhl & 0x0f, p.ih.tos, H16(p.ih.len),
            H16(p.ih.id), (flags & 0x2) > 1, flags & 0x1, ofs,
            p.ih.ttl, src
#if PRINT_MAC
            , msrc
#endif
            , dst
#if PRINT_MAC
            , mdst
#endif
            );
    
    len = strlen(out);
    
    /* TODO: print a richer output, esp. for ICMP */
    if (p.ih.proto == 0x06) {        /* TCP */
        sprintf(out + len, "[TCP] sp:%5u dp:%5u seq:%10u ack:%10u "
                "win:%5u %s",
                H16(p.p.tcph.src_port), H16(p.p.tcph.dst_port),
                (uint)H32(p.p.tcph.seq), (uint)H32(p.p.tcph.ack),
                H16(p.p.tcph.win), print_tcp_flags(p.p.tcph.flags)
                );
    } else if (p.ih.proto == 0x11) { /* UDP */
        sprintf(out + len, "[UDP] sp:%5u dp:%5u len:%5u",
                H16(p.p.udph.src_port), H16(p.p.udph.dst_port),
                H16(p.p.udph.len));
    } else if (p.ih.proto == 0x01) { /* ICMP */
        uint8_t type = p.p.icmph.type;
        char* icmp_type = type == 0 ? "\"echo reply\"" :
                    type == 3 ? "\"desination unreachable\"" :
                    type == 4 ? "\"source quench\"" :
                    type == 5 ? "\"redirect\"" :
                    type == 8 ? "\"echo\"" :
                    type == 11 ? "\"time exceeded\"" :
                    type == 12 ? "\"parameter problem\"" :
                    type == 13 ? "\"timestamp\"" :
                    type == 14 ? "\"timestamp reply\"" :
                    type == 15 ? "\"information request\"" :
                    type == 16 ? "\"information reply\"" :
                    "unknown type";
        sprintf(out + len, "[ICMP] %s (%hu), code %hu",
                icmp_type, p.p.icmph.type, p.p.icmph.code);
    } else {
        sprintf(out + len, "[unrecognized protocol...]");
    }

    *out_len = strlen(out);
    out[(*out_len)++] = '\n';

    return out;
}

#endif

static int
replay(char *buf, char *out, size_t * len)
{
    pkt_t * pkt = (pkt_t *) buf; 
    size_t need = ntohl(pkt->caplen) + sizeof(pkt_t); 

    if (*len < need) 
	return -1; 

    bcopy(buf, out, need); 
    pkt = (pkt_t *) out; 
    pkt->payload = out + sizeof(pkt_t); 
    *len = need; 
    return 0;	
}

callbacks_t callbacks = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0, 
    indesc: NULL, 
    outdesc: &outdesc, 
    init: init,
    check: NULL,
    hash: NULL,
    match: NULL,
    update: update,
    ematch: NULL,
    export: NULL,
    compare: NULL,
    action: NULL,
    store: store,
    load: load,
    print: NULL,
    replay: replay 
};

