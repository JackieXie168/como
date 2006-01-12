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

#ifndef _COMO_STDIPV6_H
#define _COMO_STDIPV6_H

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#ifndef	__CYGWIN32__		/* file not present there */
#include <net/ethernet.h>       /* ETHERTYPE_IP */
#endif
#include <netinet/in.h>
#include <arpa/inet.h>          /* inet_ntop */

#include "stdpkt.h" 

#ifndef ETHERTYPE_IPV6
#define	ETHERTYPE_IPV6	0x86dd	/* not in net/ethernet.h for some reason */
#endif

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


#define IPV6(field)		\
    (pkt->l3type == ETHERTYPE_IPV6 ?  \
     (((union _como_ipv6hdr *) (pkt->payload + pkt->layer3ofs))->field) : \
     (abort(),((union _como_ipv6hdr *)NULL)->field))
#define ICMPV6(field)		\
    (pkt->l3type == ETHERTYPE_IPV6 && pkt->l4type == IPPROTO_ICMPV6 ? \
     (((struct _como_icmpv6hdr *) (pkt->payload + pkt->layer4ofs))->field) : \
     (abort(), ((struct _como_icmpv6hdr *)NULL)->field))

#define IPV6P(pkt, field)		\
    (pkt->l3type == ETHERTYPE_IPV6 ?  \
     (((union _como_ipv6hdr *) (pkt->payload + pkt->layer3ofs))->field) : \
     (abort(), ((union _como_ipv6hdr *)NULL)->field))


/* 
 * useful macros 
 */
#define isIPv6          (COMO(l3type) == ETHERTYPE_IPV6)

#endif /* _COMO_STDIPV6_H */
