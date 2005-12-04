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
#include <strings.h>            /* bcopy */


/* typedefs for entries in network format. C99 types are used for native.
 * This makes the code a bit more boring to write, but safer in that
 * the compiler can catch error for us.
 * Access to network fields must be mediated by the 'N16()' and N32() macros
 * so it is easier to spot violations (never access explicitly
 * the field names).
 * Also never use explicitly the ntoh*(), hton*() macros.
 */

#ifdef BUILD_FOR_ARM

#define N16(x)  (x)
#define H16(x)  (ntohs(x))
#define N32(x)  (x)
#define H32(x)  (ntohl(x))
#define N64(x)  (x)
#define H64(x)  (NTOHLL(x))

#else

#define N16(x)  ((x).__x16)
#define H16(x)  (ntohs(N16(x)))
#define N32(x)  ((x).__x32)
#define H32(x)  (ntohl(N32(x)))
#define N64(x)  ((x).__x64)
#define H64(x)  (NTOHLL(N64(x)))

#endif

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

#ifdef BUILD_FOR_ARM

typedef uint16_t n16_t;  /* network format */
typedef uint32_t n32_t;  /* network format */
typedef uint64_t n64_t;  /* network format */

#else

typedef struct _n16_t   n16_t;  /* network format */
typedef struct _n32_t   n32_t;  /* network format */
typedef struct _n64_t   n64_t;  /* network format */

#endif

typedef struct _n128_t  n128_t; /* network format */

/*
 * Macros to convert a uint64_t from host to network byte order
 * and vice-versa
 */
#define HTONLL(x)   ((uint64_t)htonl((uint32_t)((x) >> 32)) |   \
            (uint64_t)htonl((uint32_t)((x) & 0xffffffff)) << 32)

#define NTOHLL(x)   ((uint64_t)ntohl((uint32_t)(x >> 32)) |     \
            (uint64_t)ntohl((uint32_t)(x & 0xffffffff)) << 32)


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
 * Known layer2 types 
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
 * NetFlow-like record 
 * It contains some information that can be derived from 
 * NetFlow or cflowd records...
 * Currently the fields reflect V5 NetFlow
 * 
 * XXX still under development. we may want to add information 
 *     that is present in the various versions of NetFlow. 
 */
struct _como_nf { 
    uint8_t src_mask;	  /* source prefix mask */
    uint8_t dst_mask; 	  /* destination prefix mask */
    uint8_t padding; 	  /* padding to make it word-aligned */
    n16_t src_as;	  /* source AS (could be peer AS or origin AS) */
    n16_t dst_as; 	  /* destination AS (peer AS or origin AS for dst IP) */
    n32_t exaddr;         /* Exporter IP Address */
    n32_t nexthop;        /* Next hop router's IP Address */
    uint8_t engine_type;  /* Type of flow switching engine (RP,VIP,etc.) */
    uint8_t engine_id;    /* Slot number of the flow switching engine) */
    uint8_t tcp_flags;    /* OR of TCP header bits */
    n16_t input; 	  /* Input interface index */
    n16_t output; 	  /* Output interface index */
};
 

/* 
 * IP header 
 */
struct _como_iphdr {	
    uint8_t	vhl;
    uint8_t	tos;
    n16_t	len;
    n16_t	id;
    n16_t	ofs;		/* and flags */
    uint8_t	ttl;
    uint8_t	proto;
    n16_t	cksum;
    n32_t	src_ip;
    n32_t	dst_ip;
    char        options[0];
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
    n16_t       cksum;
    char  	payload[0]; 
};


/* some missing defines (mostly missing in Linux) */
#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN  0x8100
#endif

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

#define ETHP(pkt, field)        ETH(field)
#define IPP(pkt, field)         \
    (((struct _como_iphdr *) (pkt->payload + pkt->l3ofs))->field)

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
#define TS2MSEC(ts)     ((u_int32_t) ((((ts) & 0xffffffff) * 1000) >> 32))
#define TS2USEC(ts)     ((u_int32_t) ((((ts) & 0xffffffff) * 1000000) >> 32))
#define TIME2TS(s, u)   ((((u_int64_t) (s)) << 32) + \
                        ((((u_int64_t) (u)) << 32) / 1000000))
#define TIMEVAL2TS(rec) (TIME2TS((rec)->unix_secs,(rec)->unix_nsecs))

/*
 * Helper macros
 */
#define isIP            (COMO(l3type) == ETHERTYPE_IP)
#define isTCP           (isIP && (IP(proto) == IPPROTO_TCP))
#define isUDP           (isIP && (IP(proto) == IPPROTO_UDP))
#define isICMP          (isIP && (IP(proto) == IPPROTO_ICMP))

#endif/* _COMO_STDPKT_H */
