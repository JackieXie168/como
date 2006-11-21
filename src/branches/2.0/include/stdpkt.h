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


#ifndef _COMO_STDPKT_H
#define _COMO_STDPKT_H

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef linux 
#include <netinet/ether.h>
#else
#include <net/ethernet.h>
#endif
#include <arpa/inet.h>          /* inet_ntop */
#include <strings.h>            /* bcopy */

#include "nettypes.h"
#include "ethernet.h"
#include "ieee80211.h"
#include "linklayer.h"
#include "ipv4.h"
#include "ipv6.h"
#include "wlan.h"
#include "radio.h"
#include "dhcp.h"

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
 *       a packet stream to another CoMo system (via the sniffer-como). 
 *       In that case the CoMo header is all in network byte order. 
 * 
 * XXX should we make it consistently network byte order? -gianluca
 */
struct _como_pkt {
    uint64_t ts;		/* timestamp */
    uint32_t len;		/* length on the wire */
    uint32_t caplen;		/* capture length */
    uint8_t input;		/* input sniffer id */
    uint8_t reserved[3];	/* reserved (padding for now) */
    uint16_t type;		/* packet type (COMOTYPE_*) */
    uint16_t dropped;		/* dropped packets since last (max 0xffff) */
    uint16_t l2type;		/* layer2 type (LINKTYPE_*) */
    uint16_t l3type;		/* layer3 type using ethernet codes */
    uint16_t l4type;		/* layer4 type using layer3 specific codes */
    uint16_t l2ofs;		/* offset where layer2 header starts */
    uint16_t l3ofs;		/* offset where layer3 header starts */
    uint16_t l4ofs; 		/* offset where layer4 header starts */
    uint16_t l7ofs; 		/* offset where layer4 header ends */
    uint32_t pktmetaslen;
    char * pktmetas;
    char * payload; 		/* pointer to packet */ 
};


/* 
 * CoMo packet types 
 */
enum COMOTYPE {
    COMOTYPE_NONE =		0x0000, /* No-type */
    COMOTYPE_COMO =		0x0010,	/* CoMo-specific (e.g., replay()) */
    COMOTYPE_NF =		0x0015,	/* NetFlow records (NetFlow v5 info) */
    COMOTYPE_SFLOW =		0x0018,	/* sFlow records (sFlow v5 info) */
    COMOTYPE_LINK =		0x0019,	/* Encapsulated in supported l2
					   protocol */
    COMOTYPE_RADIO =		0x0017,	/* Radio info */
    COMOTYPE_ANY =		0xffff
};

/* 
 * Known layer 2 types 
 */
enum LINKTYPE {
    LINKTYPE_NONE =		0x0000, /* No-type */
    LINKTYPE_ETH =		0x0001,	/* Ethernet */
    LINKTYPE_HDLC =		0x0002,	/* Cisco HDLC */
    LINKTYPE_VLAN =		0x0003,	/* 802.1q packet */
    LINKTYPE_ISL =		0x0004,	/* Cisco ISL */
    LINKTYPE_80211 =		0x0006,	/* IEEE 802.11 header */
    LINKTYPE_ANY =		0xffff
};

enum L3TYPE {
    L3TYPE_NONE =		0x0000, /* No-type */
    L3TYPE_ANY =		0xffff
};

enum L4TYPE {
    L4TYPE_NONE =		0x0000, /* No-type */
    L4TYPE_ANY =		0xffff
};

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
#define COMOP(pkt,field)	(((struct _como_pkt *) pkt)->field)

#endif

/*
 * we use two definitions of the macros. one that checks that the
 * packet actually has the field that the macro is looking for. the
 * other one does not have this check. the more safe" methods can be
 * enabled by defining the variable SAFEMACROS
 */
#ifdef SAFEMACROS
#error "SAFEMACROS are broken"

#define __EXTRACT_L2_FIELD(type, tag, field) \
    (pkt->l2type == type ? \
     (((struct tag *) (pkt->payload + pkt->l2ofs))->field) : \
     (abort(), ((struct tag *)NULL)->field))


#define ETH(field) __EXTRACT_L2_FIELD(COMOL2TYPE_ETH, _como_eth, field)
#define VLAN(field) __EXTRACT_L2_FIELD(COMOL2TYPE_VLAN, _como_vlan, field)
#define HDLC(field) __EXTRACT_L2_FIELD(COMOL2TYPE_HDLC, _como_hdlc, field)
#define ISL(field) __EXTRACT_L2_FIELD(COMOL2TYPE_ISL, _como_isl, field)

#define IP(field)               \
    (pkt->l3type == ETHERTYPE_IP ?  \
     (((struct _como_iphdr *) (pkt->payload + pkt->l3ofs))->field) : \
     (abort(), ((struct _como_iphdr *)NULL)->field))

#define TCP(field)              \
    (pkt->l3type == ETHERTYPE_IP && pkt->l4type == IPPROTO_TCP ? \
     (((struct _como_tcphdr *) (pkt->payload + pkt->l4ofs))->field) : \
     (abort(), ((struct _como_tcphdr *)NULL)->field))
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

#else				/* unsafe macros... */

#ifdef BUILD_FOR_ARM

#define NF(field)							\
    ((typeof(((struct _como_nf *)NULL)->field))				\
     get_field((char *)&(((struct _como_nf *) pkt->payload)->field),	\
     sizeof(typeof(((struct _como_nf *)NULL)->field))))
#define NFX(field, value)						\
    (set_field((char *)&(((struct _como_nf *) pkt->payload)->field),	\
     sizeof(typeof(((struct _como_nf *)NULL)->field)), (uint64_t)value))

#define SFLOW(field)							\
    ((typeof(((struct _como_sflow *)NULL)->field))			\
     get_field((char *)&(((struct _como_nf *) pkt->payload)->field),	\
     sizeof(typeof(((struct _como_sflow *)NULL)->field))))
#define SFLOWX(field, value)						\
    (set_field((char *)&(((struct _como_sflow *) pkt->payload)->field),	\
     sizeof(typeof(((struct _como_sflow *)NULL)->field)), (uint64_t)value))

/* Layer 2 macros */
#define ETH(field)							\
    ((typeof(((struct _como_eth *)NULL)->field))			\
     get_field((char *)&(((struct _como_eth *)				\
     (pkt->payload + pkt->l2ofs))->field),				\
     sizeof(typeof(((struct _como_eth *)NULL)->field))))
#define ETHX(field, value)						\
    (set_field((char *)&(((struct _como_eth *)				\
    (pkt->payload + pkt->l2ofs))->field),				\
     sizeof(typeof(((struct _como_eth *)NULL)->field)), (uint64_t)value))

#define VLAN(field)							\
    ((typeof(((struct _como_vlan *)NULL)->field))			\
     get_field((char *)&(((struct _como_vlan *)				\
     (pkt->payload + pkt->l2ofs))->field),				\
     sizeof(typeof(((struct _como_vlan *)NULL)->field))))
#define VLANX(field, value)						\
    (set_field((char *)&(((struct _como_vlan *)				\
    (pkt->payload + pkt->l2ofs))->field),				\
     sizeof(typeof(((struct _como_vlan *)NULL)->field)), (uint64_t)value))

#define HDLC(field)							\
    ((typeof(((struct _como_hdlc *)NULL)->field))			\
     get_field((char *)&(((struct _como_hdlc *)				\
     (pkt->payload + pkt->l2ofs))->field),				\
     sizeof(typeof(((struct _como_hdlc *)NULL)->field))))
#define HDLCX(field, value)						\
    (set_field((char *)&(((struct _como_hdlc *)				\
    (pkt->payload + pkt->l2ofs))->field),				\
     sizeof(typeof(((struct _como_hdlc *)NULL)->field)), (uint64_t)value))

#define ISL(field)							\
    ((typeof(((struct _como_isl *)NULL)->field))			\
     get_field((char *)&(((struct _como_isl *)				\
     (pkt->payload + pkt->l2ofs))->field),				\
     sizeof(typeof(((struct _como_isl *)NULL)->field))))
#define ISLX(field, value)						\
    (set_field((char *)&(((struct _como_isl *)				\
    (pkt->payload + pkt->l2ofs))->field),				\
     sizeof(typeof(((struct _como_isl *)NULL)->field)), (uint64_t)value))

/* Layer 3 macros */
#define IP(field)							\
    ((typeof(((struct _como_iphdr *)NULL)->field))			\
     get_field((char *)&(((struct _como_iphdr *)			\
     (pkt->payload + pkt->l3ofs))->field),				\
     sizeof(typeof(((struct _como_iphdr *)NULL)->field))))
#define IPX(field, value)						\
    (set_field((char *)&(((struct _como_iphdr *)			\
     (pkt->payload + pkt->l3ofs))->field),				\
     sizeof(typeof(((struct _como_iphdr *)NULL)->field)), (uint64_t)value))

/* Layer 4 macros */
#define TCP(field)							\
    ((typeof(((struct _como_tcphdr *)NULL)->field))			\
     get_field((char *)&(((struct _como_tcphdr *)			\
     (pkt->payload + pkt->l4ofs))->field),				\
     sizeof(typeof(((struct _como_tcphdr *)NULL)->field))))
#define TCPX(field, value)						\
    (set_field((char *)&(((struct _como_tcphdr *)			\
     (pkt->payload + pkt->l4ofs))->field),				\
     sizeof(typeof(((struct _como_tcphdr *)NULL)->field)), (uint64_t)value))

#define UDP(field)							\
    ((typeof(((struct _como_udphdr *)NULL)->field))			\
     get_field((char *)&(((struct _como_udphdr *)			\
     (pkt->payload + pkt->l4ofs))->field),				\
     sizeof(typeof(((struct _como_udphdr *)NULL)->field))))
#define UDPX(field, value)						\
    (set_field((char *)&(((struct _como_udphdr *)			\
     (pkt->payload + pkt->l4ofs))->field),				\
     sizeof(typeof(((struct _como_udphdr *)NULL)->field)), (uint64_t)value))

#define ICMP(field)							\
    ((typeof(((struct _como_icmphdr *)NULL)->field))			\
     get_field((char *)&(((struct _como_icmphdr *)			\
     (pkt->payload + pkt->l4ofs))->field),				\
     sizeof(typeof(((struct _como_icmphdr *)NULL)->field))))
#define ICMPX(field, value)						\
    (set_field((char *)&(((struct _como_icmphdr *)			\
     (pkt->payload + pkt->l4ofs))->field),				\
     sizeof(typeof(((struct _como_icmphdr *)NULL)->field)), (uint64_t)value))

#else				/* BUILD_FOR_ARM */

#define NF(field)	NFP(pkt,field)
#define NFP(pkt,field)							\
    (((struct _como_nf *) (pkt)->payload)->field)

#define SFLOW(field)	SFLOWP(pkt,field)
#define SFLOWP(pkt,field)						\
    (((struct _como_sflow *) (pkt)->payload)->field)

/* Layer 2 macros */
#define ETH(field)	ETHP(pkt,field)
#define ETHP(pkt,field)							\
    (((struct _como_eth *) (pkt->payload + pkt->l2ofs))->field)

#define VLAN(field)	VLANP(pkt,field)
#define VLANP(pkt,field)						\
    (((struct _como_vlan *) (pkt->payload + pkt->l2ofs))->field)

#define HDLC(field)	HDLCP(pkt,field)
#define HDLCP(pkt,field)						\
    (((struct _como_hdlc *) (pkt->payload + pkt->l2ofs))->field)

#define ISL(field)	ISLP(pkt,field)
#define ISLP(pkt,field)							\
    (((struct _como_isl *) (pkt->payload + pkt->l2ofs))->field)

/* Layer 3 macros */
#define IP(field)	IPP(pkt,field)
#define IPP(pkt,field)							\
    (((struct _como_iphdr *) (pkt->payload + pkt->l3ofs))->field)

#define IPV6(field)	IPV6P(pkt,field)
#define IPV6P(pkt,field)						\
     (((union _como_ipv6hdr *) (pkt->payload + pkt->l3ofs))->field)

/* Layer 4 macros */
#define TCP(field)	TCPP(pkt,field)
#define TCPP(pkt,field)							\
    (((struct _como_tcphdr *) (pkt->payload + pkt->l4ofs))->field)

#define UDP(field)	UDPP(pkt,field)
#define UDPP(pkt,field)							\
    (((struct _como_udphdr *) (pkt->payload + pkt->l4ofs))->field)

#define ICMP(field)	ICMPP(pkt,field)
#define ICMPP(pkt,field)						\
    (((struct _como_icmphdr *) (pkt->payload + pkt->l4ofs))->field)

#define ICMPV6(field)	ICMPV6P(pkt,field)
#define ICMPV6P(pkt,field)						\
    (((struct _como_icmpv6hdr *) (pkt->payload + pkt->l4ofs))->field)

/* Application layer */
#define DHCP(field)	DHCPP(pkt,field)
#define DHCPP(pkt,field)						\
    (((struct _como_dhcp *) (pkt->payload + pkt->l7ofs))->field)

#endif				/* BUILD_FOR_ARM */

#endif				/* SAFEMACROS */

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

#define TS_MAX	(timestamp_t) (~0)

/*
 * Helper macros
 */
#define isLINK		(COMO(type) == COMOTYPE_LINK)
#define isNF		(COMO(type) == COMOTYPE_NF)
#define isSFLOW		(COMO(type) == COMOTYPE_SFLOW)
#define isRADIO		(COMO(type) == COMOTYPE_RADIO)

#define is80211		(COMO(l2type) == LINKTYPE_80211)
#define isETH		(COMO(l2type) == LINKTYPE_ETH)
#define isHDLC		(COMO(l2type) == LINKTYPE_HDLC)
#define isISL		(COMO(l2type) == LINKTYPE_ISL)
#define isVLAN		(COMO(l2type) == LINKTYPE_VLAN)

#define isIP		(COMO(l3type) == ETHERTYPE_IP)

#define isTCP           (isIP && (IP(proto) == IPPROTO_TCP))
#define isUDP           (isIP && (IP(proto) == IPPROTO_UDP))
#define isICMP          (isIP && (IP(proto) == IPPROTO_ICMP))
#define isIPV6          (COMO(l3type) == ETHERTYPE_IPV6)

#define hasL2		hasL2P(pkt)
#define hasL3		hasL3P(pkt)
#define hasL4		hasL4P(pkt)

#define hasL2P(pkt)	(COMOP(pkt,l2ofs) < COMOP(pkt,l3ofs))
#define hasL3P(pkt)	(COMOP(pkt,l3ofs) < COMOP(pkt,l4ofs))
#define hasL4P(pkt)	(COMOP(pkt,l4ofs) < COMOP(pkt,l7ofs))

#define sizeofL2	(COMO(l3ofs) - COMO(l2ofs))
#define sizeofL3	(COMO(l4ofs) - COMO(l3ofs))
#define sizeofL4	(COMO(l7ofs) - COMO(l4ofs))

#define sizeofL2P(pkt)	(COMOP(pkt,l3ofs) - COMOP(pkt,l2ofs))
#define sizeofL3P(pkt)	(COMOP(pkt,l4ofs) - COMOP(pkt,l3ofs))
#define sizeofL4P(pkt)	(COMOP(pkt,l7ofs) - COMOP(pkt,l4ofs))

#define iptoa(ip) \
    inet_ntoa(*(struct in_addr *)&ip)

#endif				/* _COMO_STDPKT_H */
