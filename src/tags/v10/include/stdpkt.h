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

#ifndef _COMO_STDPKT_H
#define _COMO_STDPKT_H

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>          /* inet_ntop */
#include <strings.h>            /* bcopy */

#include "nettypes.h"
#include "ethernet.h"
#include "ieee80211.h"
#include "linklayer.h"
#include "ipv4.h"
#include "ipv6.h"
#include "wlan.h"


/*
 * Object types
 */
typedef struct _como_pkt        pkt_t;  	/* CoMo packet record */


/*
 * struct _como_pkt (pkt_t) is the structure describing a packet
 * passed around the capture module.
 * 
 * NOTE: the CoMo header information (ts, caplen, len -- for now) are 
 *       all encoded in host byte order. The rest of the packet (payload)
 *       is as seen on the wire. 
 *       The byte ordering is changed only when a CoMo system sends 
 *       a packet stream to another CoMo system (via the sniffer-dump). 
 *       In that case the CoMo header is all in network byte order. 
 * 
 * XXX should we make it consistently network byte order? -gianluca
 */
struct _como_pkt {
    uint64_t ts;		/* timestamp */
    uint32_t len;		/* length on the wire */
    uint32_t caplen;		/* capture length */
    uint16_t type; 		/* packet type (COMOTYPE_*) */
    uint16_t dropped;		/* dropped packets since last (max 0xffff) */ 
    uint16_t l2type; 		/* layer2 type using mac codes */ 
    uint16_t l3type; 		/* layer3 type using ethernet codes */
    uint16_t l4type;            /* layer4 type using layer3 specific codes */
    uint16_t l2ofs;		/* offset where layer2 header starts */
    uint16_t l3ofs;		/* offset where layer3 header starts */
    uint16_t l4ofs; 		/* offset where layer4 header starts */
    char * payload; 		/* pointer to packet */ 
};


/* 
 * Known packet types 
 */
#define COMOTYPE_NONE		0x0000  /* CoMo-specific (e.g., replay()) */
#define COMOTYPE_ETH		0x0001	/* Ethernet */
#define COMOTYPE_HDLC		0x0002	/* Cisco HDLC */
#define COMOTYPE_VLAN		0x0003	/* 802.1q packet */
#define COMOTYPE_ISL		0x0004	/* Cisco ISL */
#define COMOTYPE_NF		0x0005	/* Flow records (NetFlow v5 info) */
#define COMOTYPE_80211   	0x0006  /* IEEE 802.11 header */
#define COMOTYPE_RADIO		0x0007  /* IEEE 802.11 with radio info */ 
 

/*
 * macros to use for packet header fields. these can be
 * used in the filters present in the como.conf file.
 */

#ifdef BUILD_FOR_ARM

/* These functions (get_field, set_field) take into account
   the word alignment of a pointer */

__inline__ static uint64_t
get_field(char *ptr, size_t size)
{
    uint64_t result = 0;
    char *r = NULL, *p = NULL;
    size_t s = 0, left = 0;
    uint32_t off = 0;

    r = (char *)&result;
    
    off = (uint)ptr % 4;
    
    if (off == 0)
        /* The pointer is word aligned, we don't need to do anything here,
         * just copy size bytes */
        bcopy(ptr, r, size);
    else {
        /* The pointer is not word aligned, we need to get the correct data */
        p = ptr - off;
        for (left = size; left > 0; p += 4) {
            s = (left < (4 - off))? left : (4 - off);
            bcopy(p + off, r + size - left, s);
            left -= s;
            /* The offset only applies to the first read, on the rest
             * we are reading starting at word-aligned memory positions */
            off = 0;
        }
    }
    return result;
}

__inline__ static void
set_field(char *ptr, size_t size, uint64_t value)
{
    char *r = NULL, *p = NULL;
    size_t s = 0, left = 0;
    uint32_t off = 0;

    r = (char *)&value;
    
    off = (uint)ptr % 4;
    
    if (off == 0)
        /* The pointer is word aligned, we don't need to do anything here,
         * just copy size bytes */
        bcopy(r, ptr, size);
    else {
        /* The pointer is not word aligned, we need to align it and then
         * copy the data in the correct places */
        p = ptr - off;
        for (left = size; left > 0; p += 4) {
            s = (left < (4 - off))? left : (4 - off);
            bcopy(r + size - left, p + off, s);
            left -= s;
            /* The offset only applies to the first write, on the rest
             * we are writing starting at word-aligned memory positions */
            off = 0;
        }
    }
}

#define COMO(field)              \
    ((typeof(((struct _como_pkt *)NULL)->field)) \
     get_field((char *)&(((struct _como_pkt *)pkt)->field), \
     sizeof(typeof(((struct _como_pkt *)NULL)->field))))

#define COMOX(field, value)              \
    (set_field((char *)&(((struct _como_pkt *)pkt)->field), \
     sizeof(typeof(((struct _como_pkt *)NULL)->field)), (uint64_t)value))

#else

#define COMO(field)             (((struct _como_pkt *) pkt)->field)

#endif

/*
 * we use two definitions of the macros. one that checks that the
 * packet actually has the field that the macro is looking for. the
 * other one does not have this check. the more safe" methods can be
 * enabled by defining the variable SAFEMACROS
 */

#ifdef SAFEMACROS

#define __EXTRACT_L2_FIELD(type, tag, field) \
    (pkt->l2type == type ? \
     (((struct tag *)pkt->payload)->field) : \
     (abort(), ((struct tag *)NULL)->field))
#define ETH(field) __EXTRACT_L2_FIELD(COMOTYPE_ETH, _como_eth, field)
#define VLAN(field) __EXTRACT_L2_FIELD(COMOTYPE_VLAN, _como_vlan, field)
#define HDLC(field) __EXTRACT_L2_FIELD(COMOTYPE_HDLC, _como_hdlc, field)
#define ISL(field) __EXTRACT_L2_FIELD(COMOTYPE_ISL, _como_isl, field)



#define IP(field)               \
    (pkt->l3type == ETHERTYPE_IP ?  \
     (((struct _como_iphdr *) (pkt->payload + pkt->l3ofs))->field) : \
     (abort(),((struct _como_iphdr *)NULL)->field))
#define TCP(field)              \
    (pkt->l3type == ETHERTYPE_IP && pkt->l4type == IPPROTO_TCP ? \
     (((struct _como_tcphdr *) (pkt->payload + pkt->l4ofs))->field) : \
     (abort(),((struct _como_tcphdr *)NULL)->field))
#define UDP(field)              \
    (pkt->l3type == ETHERTYPE_IP && pkt->l4type == IPPROTO_UDP ? \
     (((struct _como_udphdr *) (pkt->payload + pkt->l4ofs))->field) : \
     (abort(), ((struct _como_udphdr *)NULL)->field))
#define ICMP(field)             \
    (pkt->l3type == ETHERTYPE_IP && pkt->l4type == IPPROTO_ICMP ? \
     (((struct _como_icmphdr *) (pkt->payload + pkt->l4ofs))->field) : \
     (abort(), ((struct _como_icmphdr *)NULL)->field))

#define ETHP(pkt, field)        ETH(field)
#define IPP(pkt, field)         \
    (pkt->l3type == ETHERTYPE_IP ?  \
     (((struct _como_iphdr *) (pkt->payload + pkt->l3ofs))->field) : \
     (abort(), ((struct _como_iphdr *)NULL)->field))

#else		/* unsafe macros... */

#ifdef BUILD_FOR_ARM

#define ETH(field)              \
    ((typeof(((struct _como_eth *)NULL)->field)) \
     get_field((char *)&(((struct _como_eth *)pkt->payload)->field), \
     sizeof(typeof(((struct _como_eth *)NULL)->field))))
#define ETHX(field, value)              \
    (set_field((char *)&(((struct _como_eth *)pkt->payload)->field), \
     sizeof(typeof(((struct _como_eth *)NULL)->field)), (uint64_t)value))

#define VLAN(field)             \
    ((typeof(((struct _como_vlan *)NULL)->field)) \
     get_field((char *)&(((struct _como_vlan *)pkt->payload)->field), \
     sizeof(typeof(((struct _como_vlan *)NULL)->field))))
#define VLANX(field, value)              \
    (set_field((char *)&(((struct _como_vlan *)pkt->payload)->field), \
     sizeof(typeof(((struct _como_vlan *)NULL)->field)), (uint64_t)value))

#define HDLC(field)             \
    ((typeof(((struct _como_hdlc *)NULL)->field)) \
     get_field((char *)&(((struct _como_hdlc *)pkt->payload)->field), \
     sizeof(typeof(((struct _como_hdlc *)NULL)->field))))
#define HDLCX(field, value)              \
    (set_field((char *)&(((struct _como_hdlc *)pkt->payload)->field), \
     sizeof(typeof(((struct _como_hdlc *)NULL)->field)), (uint64_t)value))

#define ISL(field)              \
    ((typeof(((struct _como_isl *)NULL)->field)) \
     get_field((char *)&(((struct _como_isl *)pkt->payload)->field), \
     sizeof(typeof(((struct _como_isl *)NULL)->field))))
#define ISLX(field, value)              \
    (set_field((char *)&(((struct _como_isl *)pkt->payload)->field), \
     sizeof(typeof(((struct _como_isl *)NULL)->field)), (uint64_t)value))

#define NF(field)               \
    ((typeof(((struct _como_nf *)NULL)->field)) \
     get_field((char *)&(((struct _como_nf *)pkt->payload)->field), \
     sizeof(typeof(((struct _como_nf *)NULL)->field))))
#define NFX(field, value)              \
    (set_field((char *)&(((struct _como_nf *)pkt->payload)->field), \
     sizeof(typeof(((struct _como_nf *)NULL)->field)), (uint64_t)value))

#define IP(field)               \
    ((typeof(((struct _como_iphdr *)NULL)->field)) \
     get_field((char *)&(((struct _como_iphdr *) \
     (pkt->payload + pkt->l3ofs))->field), \
     sizeof(typeof(((struct _como_iphdr *)NULL)->field))))
#define IPX(field, value)              \
    (set_field((char *)&(((struct _como_iphdr *) \
     (pkt->payload + pkt->l3ofs))->field), \
     sizeof(typeof(((struct _como_iphdr *)NULL)->field)), (uint64_t)value))

#define TCP(field)              \
    ((typeof(((struct _como_tcphdr *)NULL)->field)) \
     get_field((char *)&(((struct _como_tcphdr *) \
     (pkt->payload + pkt->l4ofs))->field), \
     sizeof(typeof(((struct _como_tcphdr *)NULL)->field))))
#define TCPX(field, value)              \
    (set_field((char *)&(((struct _como_tcphdr *) \
     (pkt->payload + pkt->l4ofs))->field), \
     sizeof(typeof(((struct _como_tcphdr *)NULL)->field)), (uint64_t)value))

#define UDP(field)              \
    ((typeof(((struct _como_udphdr *)NULL)->field)) \
     get_field((char *)&(((struct _como_udphdr *) \
     (pkt->payload + pkt->l4ofs))->field), \
     sizeof(typeof(((struct _como_udphdr *)NULL)->field))))
#define UDPX(field, value)              \
    (set_field((char *)&(((struct _como_udphdr *) \
     (pkt->payload + pkt->l4ofs))->field), \
     sizeof(typeof(((struct _como_udphdr *)NULL)->field)), (uint64_t)value))

#define ICMP(field)             \
    ((typeof(((struct _como_icmphdr *)NULL)->field)) \
     get_field((char *)&(((struct _como_icmphdr *) \
     (pkt->payload + pkt->l4ofs))->field), \
     sizeof(typeof(((struct _como_icmphdr *)NULL)->field))))
#define ICMPX(field, value)              \
    (set_field((char *)&(((struct _como_icmphdr *) \
     (pkt->payload + pkt->l4ofs))->field), \
     sizeof(typeof(((struct _como_icmphdr *)NULL)->field)), (uint64_t)value))

#define ETHP(pkt, field)        ETH(field)
#define IPP(pkt, field)         IP(field)

#else

#define ETH(field)              \
    (((struct _como_eth *) pkt->payload)->field)
#define VLAN(field)             \
    (((struct _como_vlan *) pkt->payload)->field)
#define HDLC(field)             \
    (((struct _como_hdlc *) pkt->payload)->field)
#define ISL(field)              \
    (((struct _como_isl *) pkt->payload)->field)
#define NF(field)               \
    (((struct _como_nf *) pkt->payload)->field)
#define IP(field)               \
    (((struct _como_iphdr *) (pkt->payload + pkt->l3ofs))->field)
#define TCP(field)              \
    (((struct _como_tcphdr *) (pkt->payload + pkt->l4ofs))->field)
#define UDP(field)              \
    (((struct _como_udphdr *) (pkt->payload + pkt->l4ofs))->field)
#define ICMP(field)             \
    (((struct _como_icmphdr *) (pkt->payload + pkt->l4ofs))->field)
#define IPV6(field)                                                     \
     (((union _como_ipv6hdr *) (pkt->payload + pkt->l3ofs))->field)
#define ICMPV6(field)                                                   \
     (((struct _como_icmpv6hdr *) (pkt->payload + pkt->l4ofs))->field)


#define ETHP(pkt, field)        ETH(field)
#define IPP(pkt, field)         \
    (((struct _como_iphdr *) (pkt->payload + pkt->l3ofs))->field)
#define IPV6P(pkt, field)                                               \
     (((union _como_ipv6hdr *) (pkt->payload + pkt->l3ofs))->field)

#endif

#endif
  
/*
 * Timestamp macros
 * 
 * Convert times into NTP format timestamps -- 64 bits with
 * the high 32 for seconds and the low 32 for the fractional part.
 *
 */
#define TS2SEC(ts)      ((uint32_t) ((ts) >> 32))
#define TS2MSEC(ts)     ((uint32_t) ((((ts) & 0xffffffff) * 1000) >> 32))
#define TS2USEC(ts)     ((uint32_t) ((((ts) & 0xffffffff) * 1000000) >> 32))
#define TIME2TS(s, u)   ((((uint64_t) (s)) << 32) + \
                        ((((uint64_t) (u)) << 32) / 1000000))
#define TIMEVAL2TS(rec) (TIME2TS((rec)->unix_secs,(rec)->unix_nsecs))

/*
 * Helper macros
 */
#define isIP            (COMO(l3type) == ETHERTYPE_IP)
#define isTCP           (isIP && (IP(proto) == IPPROTO_TCP))
#define isUDP           (isIP && (IP(proto) == IPPROTO_UDP))
#define isICMP          (isIP && (IP(proto) == IPPROTO_ICMP))
#define isIPv6          (COMO(l3type) == ETHERTYPE_IPV6)

#endif/* _COMO_STDPKT_H */
