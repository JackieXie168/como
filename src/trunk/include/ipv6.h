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

#ifndef _COMO_IPV6_H
#define _COMO_IPV6_H

#include "ethernet.h" 

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

#endif /* _COMO_IPV6_H */
