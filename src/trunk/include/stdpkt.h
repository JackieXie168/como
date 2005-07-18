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
#ifndef	__CYGWIN32__		/* file not present there */
#include <net/ethernet.h>       /* ETHERTYPE_IP */
#endif
#include <netinet/in.h>
#include <arpa/inet.h>          /* inet_ntop */

/* temporarily */
void logmsg(int flags, const char *fmt, ...);
#define	LOGCAPTURE	0x0010

#ifndef ETHERTYPE_IPV6
#define	ETHERTYPE_IPV6	0x86dd	/* not in net/ethernet.h for some reason */
#endif


/*
 * Object types
 */
typedef struct _como_pkt        pkt_t;  	/* CoMo packet record */
typedef struct _como_pktdesc    pktdesc_t; 	/* Packet description */

/* typedefs for entries in network format. C99 types are used for native.
 * This makes the code a bit more boring to write, but safer in that
 * the compiler can catch error for us.
 * Access to network fields must be mediated by the 'N16()' and N32() macros
 * so it is easier to spot violations (never access explicitly
 * the field names).
 * Also never use explicitly the ntoh*(), hton*() macros.
 */
#define	N16(x)	((x).__x16)
#define	H16(x)	(ntohs(N16(x)))
#define	N32(x)	((x).__x32)
#define	H32(x)	(ntohl(N32(x)))
#define	N64(x)	((x).__x64)
#define	H64(x)	(NTOHLL(N64(x)))

struct _n16_t {
    uint16_t __x16;
};

struct _n32_t {
    uint32_t __x32;
};

struct _n64_t {
    uint64_t __x64;
};

struct _n128_t {
    uint64_t __x64;
    uint64_t __y64;
};

typedef	struct _n16_t	n16_t;	/* network format */
typedef	struct _n32_t	n32_t;	/* network format */
typedef	struct _n64_t	n64_t;	/* network format */
typedef	struct _n128_t	n128_t;	/* network format */

/*
 * Macros to convert a uint64_t from host to network byte order
 * and vice-versa
 */
#define HTONLL(x)   ((uint64_t)htonl((uint32_t)((x) >> 32)) |   \
            (uint64_t)htonl((uint32_t)((x) & 0xffffffff)) << 32)

#define NTOHLL(x)   ((uint64_t)ntohl((uint32_t)(x >> 32)) |     \
            (uint64_t)ntohl((uint32_t)(x & 0xffffffff)) << 32)


/* 
 * Ethernet framing 
 */
struct _como_eth {
    char	dst[6];
    char	src[6];
    n16_t	type;
};


/*
 * VLAN header 
 */
struct _como_vlan {
    char dst[6];
    char src[6];
    n16_t type;			/* 0x8100 for 802.1q */
    n16_t vlan; 
    n16_t ethtype; 
};


/* 
 * Cisco HDLC framing (used for POS point-to-point links) 
 */
struct _como_hdlc {
    uint8_t address; 		/* 0x0F unicast, 0x8F broadcast */
    uint8_t control;		/* always 0 */
    n16_t type; 		/* Ethernet-like type codes */
};

/* 
 * Cisco ISL framing (used for VLAN trunking) 
 */ 
struct _como_isl { 
    char da[5]; 		/* dest. address 0x01000c0000 or 0x03000c0000 */
    uint8_t type:4; 		/* 0 for ethernet */
    uint8_t user:4; 		/* priority */
    char sa[6];			/* source address */
    n16_t len; 			/* packet length (excluding ISL) */
    char snap[3];		/* SNAP, constant 0xaaaa03 */
    char hsa[3];		/* source address, 0x00000c */
    n16_t vlan;			/* vlan ID (15bit), last bit is BPDU */
    n16_t index; 		/* index, ignored */
    n16_t res; 			/* reserved */

    char dst[6];		/* ethernet frame, dst address */
    char src[6];		/* ethernet frame, src address */
    n16_t ethtype;		/* ethernet frame, type field */
};


/* 
 * IP header 
 */
struct _como_iphdr {	
    uint8_t	vhl;
    uint8_t	tos;
    n16_t	len;
    n16_t	id;
    n16_t	ofs;	/* and flags */
    uint8_t	ttl;
    uint8_t	proto;
    n16_t	cksum;
    n32_t	src_ip;
    n32_t	dst_ip;
    char        options[0];
};

/* 
 * IPv6 headers
 */

union _como_ipv6hdr {
    /* Base header */
    struct {
	uint32_t vtcfl;		/* version, traffic class, flow label */
	n16_t	len;		/* packet length */
	uint8_t	nxthdr;		/* next header */
	uint8_t	ttl;		/* hop limit */
	n128_t	src_addr;	/* source address */
	n128_t	dst_addr;	/* destination address */
    } base;

    /* Hop-by-hop or destination options */
    struct {
	uint8_t	nxthdr;		/* next header */
	uint8_t	len;		/* header length in 64-bit words,
				 * excluding first word */
	char  	payload[0];
    } opts;

    /* Routing header */
    struct {
	uint8_t	nxthdr;		/* next header */
	uint8_t	len;		/* header length in 64-bit words,
				 * excluding first word */
	uint8_t	type;		/* routing type */
	uint8_t	segs;		/* segments left */
	char  	payload[0];
    } routing;

    /* Fragment header */
    struct {
	uint8_t	nxthdr;		/* next header */
	uint8_t	reserved;	/* reserved */
	n16_t offset;		/* offset, reserved, more flag */
	n32_t id;		/* identification */
    } fragment;

    /* Authentication header */
    struct {
	uint8_t	nxthdr;		/* next header */
	uint8_t	len;		/* header length in *32-bit* words,
				 * excluding 2 words */
	n16_t reserved;		/* reserved */
	n32_t spi;		/* security parameters index */
	n32_t seq;		/* sequence number */
	char  	payload[0];
    } auth;

    /* Encapsulating security payload */
    struct {
	n32_t spi;		/* security parameters index */
	n32_t seq;		/* sequence number */
	char  	payload[0];
    } esp;
};

/* 
 * TCP header 
 */
struct _como_tcphdr {
    n16_t	src_port;
    n16_t	dst_port;
    n32_t	seq;
    n32_t	ack;
    uint8_t	hlen;
    uint8_t	flags;
    n16_t	win;
    n16_t	cksum;
    n16_t	urg;
    char  	payload[0]; 
};

/* 
 * UDP header 
 */
struct _como_udphdr {
    n16_t	src_port;
    n16_t	dst_port;
    n16_t	len;
    n16_t	cksum;
    char  	payload[0]; 
};

/* 
 * ICMP header 
 */
struct _como_icmphdr {
    uint8_t     type;
    uint8_t     code; 	/* XXX stuff missing... */
    char  	payload[0]; 
};

/* 
 * ICMPv6 header 
 */
struct _como_icmpv6hdr {
    uint8_t     type;
    uint8_t     code;
    n16_t	cksum;
    char  	payload[0]; 
};
    

/*
 * macros to use for packet header fields. these can be 
 * used in the filters present in the como.conf file. 
 */
#define COMO(field)		\
    (((struct _como_pkt *) pkt)->field)
#define __EXTRACT_L2_FIELD(type, tag, field) \
    (pkt->l2type == type ? \
     (((struct tag *)pkt->payload)->field) : \
     (abort(), ((struct tag *)NULL)->field))
#define ETH(field) __EXTRACT_L2_FIELD(COMOTYPE_ETH, _como_eth, field)
#define VLAN(field) __EXTRACT_L2_FIELD(COMOTYPE_VLAN, _como_vlan, field)
#define HDLC(field) __EXTRACT_L2_FIELD(COMOTYPE_HDLC, _como_hdlc, field)
#define ISL(field) __EXTRACT_L2_FIELD(COMOTYPE_ISL, _como_isl, field)

#define IP(field)		\
    (pkt->l3type == ETH_P_IP ?  \
     (((struct _como_iphdr *) (pkt->payload + pkt->layer3ofs))->field) : \
     (abort(),((struct _como_iphdr *)NULL)->field))
#define IPV6(field)		\
    (pkt->l3type == ETH_P_IPV6 ?  \
     (((union _como_ipv6hdr *) (pkt->payload + pkt->layer3ofs))->field) : \
     (abort(),((union _como_ipv6hdr *)NULL)->field))
#define TCP(field)		\
    (pkt->l3type == ETH_P_IP && pkt->l4type == IPPROTO_TCP ? \
     (((struct _como_tcphdr *) (pkt->payload + pkt->layer4ofs))->field) : \
     (abort(),((struct _como_tcphdr *)NULL)->field))
#define UDP(field)		\
    (pkt->l3type == ETH_P_IP && pkt->l4type == IPPROTO_UDP ? \
     (((struct _como_udphdr *) (pkt->payload + pkt->layer4ofs))->field) : \
     (abort(), ((struct _como_udphdr *)NULL)->field))
#define TCPUDP(field)           \
    (pkt->l4type == IPPROTO_TCP ? TCP(field) : UDP(field))
#define ICMP(field)		\
    (pkt->l3type == ETH_P_IP && pkt->l4type == IPPROTO_ICMP ? \
     (((struct _como_icmphdr *) (pkt->payload + pkt->layer4ofs))->field) : \
     (abort(), ((struct _como_icmphdr *)NULL)->field))
#define ICMPV6(field)		\
    (pkt->l3type == ETH_P_IPV6 && pkt->l4type == IPPROTO_ICMPV6 ? \
     (((struct _como_icmpv6hdr *) (pkt->payload + pkt->layer4ofs))->field) : \
     (abort(), ((struct _como_icmpv6hdr *)NULL)->field))

#define ETHP(pkt, field)	ETH(field)
#define IPP(pkt, field)		\
    (pkt->l3type == ETH_P_IP ?  \
     (((struct _como_iphdr *) (pkt->payload + pkt->layer3ofs))->field) : \
     (abort(), ((struct _como_iphdr *)NULL)->field))
#define IPV6P(pkt, field)		\
    (pkt->l3type == ETH_P_IPV6 ?  \
     (((union _como_ipv6hdr *) (pkt->payload + pkt->layer3ofs))->field) : \
     (abort(), ((union _como_ipv6hdr *)NULL)->field))


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
    uint32_t l2type; 		/* layer2 type */
    uint16_t l3type; 		/* layer3 type using ethernet codes */
    uint16_t l4type;            /* layer4 type using whatever codes
				   are appropriate for the layer2 in
				   use */
    uint16_t layer3ofs;		/* offset where layer3 header starts */
    uint16_t layer4ofs; 	/* offset where layer4 header starts */
    char * payload; 		/* pointer to packet */ 
};


/* 
 * Known layer2 types 
 */
#define COMOTYPE_NONE	0x0000	/* no layer2 (e.g., replayed data) */
#define COMOTYPE_ETH	0x0001	/* Ethernet */
#define COMOTYPE_HDLC	0x0002	/* Cisco HDLC */
#define COMOTYPE_VLAN	0x0003	/* 802.1q packet */
#define COMOTYPE_ISL	0x0004	/* Cisco ISL */
#define COMOTYPE_WLAN	0x0005  /* IEEE 802.11 */
#define COMOTYPE_WLANR  0x0006  /* IEEE 802.11 w/radio information */

/*
 * pktdesc_t describes both what a module is going to read or what a
 * sniffer/module is going to write in its ingoing/outgoing pkt_t streams.
 * The fields within the "bm" structure are all bitmasks.
 */
struct _como_pktdesc {
    uint64_t ts;			/* timestamp granularity */
    uint16_t caplen; 			/* packet capture lenght (max) */
    uint16_t flags; 			/* flags for several options */
#define COMO_AVG_PKTLEN 	0x0001	/* pkt len are averaged */
#define COMO_FULL_PKT 		0x0002	/* full packet capture */
	
    struct _como_isl isl; 		/* Cisco ISL bitmask */
    struct _como_eth eth; 		/* Ethernet bitmask */
    struct _como_hdlc hdlc;		/* Cisco HDLC bitmask */
    struct _como_vlan vlan; 		/* 802.1q bitmask */
    struct _como_iphdr ih;		/* IP header bitmask */
    union _como_ipv6hdr i6h;		/* IPv6 header bitmask */
    struct _como_tcphdr tcph;		/* TCP header bitmask */
    struct _como_udphdr udph;		/* UDP header bitmask */
    struct _como_icmphdr icmph;		/* ICMP header bitmask */
    struct _como_icmpv6hdr icmpv6h;	/* ICMPv6 header bitmask */
}; 


/* 
 * IPv6 macros
 *
 * Helper macro to advance a pointer by a specified number of octets
 */
#define ADVANCE(ptr, octets)	\
    { ptr = (__typeof__(ptr)) (((char *) ptr) + octets); }

/* 
 * Helper function to traverse IPv6 header to find upper-layer header type
 */
inline uint8_t IPV6_PROTO(struct _como_pkt *pkt) {
    /* get layer 3 header */
    if (pkt->l3type != ETH_P_IPV6)
	return (abort(),((union _como_ipv6hdr *)NULL)->base.nxthdr);
    union _como_ipv6hdr *hdr = (union _como_ipv6hdr *) (pkt->payload + pkt->layer3ofs);

    /* initialize */
    int32_t len = H16(hdr->base.len);
    uint8_t hdrtype = hdr->base.nxthdr;
    uint8_t hdrlen = sizeof(hdr->base);
    ADVANCE(hdr, hdrlen);

    /* while more extension headers */
    while (len > 0) {
	switch (hdrtype) {
	case IPPROTO_HOPOPTS:
	case IPPROTO_ROUTING:
	case IPPROTO_DSTOPTS:
	    /* advance to next header (using 64-bit words) */
	    hdrtype = hdr->opts.nxthdr;
	    hdrlen = 8 * (1 + hdr->opts.len);
            ADVANCE(hdr, hdrlen);
	    len -= hdrlen;
	    break;
	case IPPROTO_AH:
	    /* advance to next header (using 32-bit words) */
	    hdrtype = hdr->auth.nxthdr;
	    hdrlen = 4 * (2 + hdr->auth.len);
            ADVANCE(hdr, hdrlen);
	    len -= hdrlen;
	    break;
	case IPPROTO_FRAGMENT:
	case IPPROTO_NONE:
	case IPPROTO_ESP:
	default:
	    len = -1;	/* force exit and return this header */
	    break;
	}
    }

    return hdrtype;
}


/* 
 * hdrtype macros 
 *
 * Convert times into NTP format timestamps -- 64 bits with
 * the high 32 for seconds and the low 32 for the fractional part.
 * 
 */
#define TS2SEC(ts) 	((uint32_t) ((ts) >> 32))
#define TS2MSEC(ts)	((u_int32_t) ((((ts) & 0xffffffff) * 1000) >> 32))
#define TS2USEC(ts)	((u_int32_t) ((((ts) & 0xffffffff) * 1000000) >> 32))
#define TIME2TS(s, u)	((((u_int64_t) (s)) << 32) + \
			((((u_int64_t) (u)) << 32) / 1000000))
#define TIMEVAL2TS(rec) (TIME2TS((rec)->unix_secs,(rec)->unix_nsecs))

/* 
 * useful macros 
 */
#define isIP            (COMO(l3type) == ETHERTYPE_IP)
#define isIPv6          (COMO(l3type) == ETHERTYPE_IPV6)
#define isTCP           ((isIP && IP(proto) == IPPROTO_TCP) ||	\
			 (isIPv6 && IPV6_PROTO(pkt) == IPPROTO_TCP))
#define isUDP           ((isIP && IP(proto) == IPPROTO_UDP) ||	\
			 (isIPv6 && IPV6_PROTO(pkt) == IPPROTO_UDP))


#endif /* _COMO_STDPKT_H */
