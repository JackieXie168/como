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

typedef	struct _n16_t	n16_t;	/* network format */
typedef	struct _n32_t	n32_t;	/* network format */
typedef	struct _n64_t	n64_t;	/* network format */

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
    char	pad[2];		/* padding to align to 32 bits */
};

/* 
 * Cisco HDLC framing (used for POS point-to-point links) 
 */
struct _como_hdlc {
    uint8_t 	address; 	/* 0x0F unicast, 0x8F broadcast */
    uint8_t	control;	/* always 0 */
    n16_t	type; 		/* Ethernet-like type codes */
};

/* 
 * IP header 
 */
struct _como_iphdr {	/* XXX possibly have __packed */
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
    uint8_t payload[0]; 
};

/* 
 * UDP header 
 */
struct _como_udphdr {
    n16_t	src_port;
    n16_t	dst_port;
    n16_t	len;
    n16_t	cksum;
    uint8_t payload[0]; 
};

/* 
 * ICMP header 
 */
struct _como_icmphdr {
    uint8_t     type;
    uint8_t     code; 	/* XXX stuff missing... */
    uint8_t payload[0]; 
};
    

/*
 * macros to use for packet header fields
 * There are more macros in modules/generic_filter.c
 */
#define ETH(field)	(pkt->layer2.eth.field)
#define IP(field)	(pkt->ih.field)
#define TCP(field)	(pkt->layer4.tcph.field)
#define UDP(field)	(pkt->layer4.udph.field)
#define ICMP(field)	(pkt->layer4.icmph.field)


/* 
 * CoMo header size. 
 * That is all the information we add on top of the packet 
 * we collect from the wire. Right now this include timestamp (8 bytes), 
 * wire length (4 bytes), capture length (2 bytes), layer2 type (1 bytes) 
 * and flags (1 bytes -- no flags are defined so far)
 */
#define COMO_HDR_SIZE	16


/*
 * struct _como_pkt (pkt_t) is the structure describing a packet
 * passed around the capture module.
 * 
 * NOTE: the CoMo header information (ts, caplen, len -- for now) are 
 *       all encoded in host byte order. The rest of the packet is in 
 *       network byte order instead. 
 *       The byte ordering is changed only when a CoMo system sends 
 *       a packet stream to another CoMo system (via the sniffer-dump). 
 *       In that case the CoMo header is all in network byte order. 
 * 
 *       XXX this is done mainly to keep the code simple. there are no 
 *           other reasons. comments? --gianluca
 */
struct _como_pkt {
    uint64_t ts;		/* timestamp */
    uint32_t len;		/* length on the wire */
    uint16_t caplen;		/* capture length (excluding layer2) */
    uint8_t  type; 		/* layer 2 type */
    uint8_t  flags; 		/* flags */
    union _como_mac { 
	struct _como_eth eth; 	/* ethernet frame */
	struct _como_hdlc hdlc;	/* Cisco HDLC frame */
	char padding[16]; 	/* force all compilers to align this to 32bit */
    } layer2; 
    struct _como_iphdr ih;      /* the IP header */
    union _como_transport {
        struct _como_tcphdr tcph;
        struct _como_udphdr udph;
        struct _como_icmphdr icmph;
	uint8_t payload[0]; 
    } layer4;
};


/* 
 * Known layer2 types 
 */
#define COMO_L2_SIZE	sizeof(union _como_mac)	/* size of layer2 part */
#define COMO_L2_NONE	0		/* no layer2 (e.g., replayed data) */
#define COMO_L2_ETH	1		/* ethernet */
#define COMO_L2_HDLC	2		/* Cisco HDLC */


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
	
    struct _como_eth eth; 		/* Ethernet bitmask */
    struct _como_hdlc hdlc;		/* Cisco HDLC bitmask */
    struct _como_iphdr ih;		/* IP header bitmask */
    struct _como_tcphdr tcph;		/* TCP header bitmask */
    struct _como_udphdr udph;		/* UDP header bitmask */
    struct _como_icmphdr icmph;		/* ICMP header bitmask */
}; 


/* 
 * macro to move in a packet batch. 
 */
#define STDPKT_LEN(p)   (COMO_HDR_SIZE + COMO_L2_SIZE + (p)->caplen) 
#define STDPKT_NEXT(p)  ((pkt_t *)((char *)p + STDPKT_LEN(p)))

/* packet length when packet is in network byte order */
#define NTOH_STDPKT_LEN(p)   (COMO_HDR_SIZE + COMO_L2_SIZE + ntohs((p)->caplen))

/* 
 * timestamp macros 
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


#endif /* _COMO_STDPKT_H */
