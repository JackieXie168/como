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


#ifndef _COMO_IPV4_H
#define _COMO_IPV4_H

#include "comoendian.h"

/* 
 * IP header 
 */
struct _como_iphdr {	
#ifdef COMO_LITTLE_ENDIAN
    uint8_t	ihl:4;
    uint8_t	version:4;
#else
    uint8_t	version:4;
    uint8_t	ihl:4;
#endif
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
    n32_t	ack_seq;
#ifdef COMO_LITTLE_ENDIAN
    uint16_t	res1:4;
    uint16_t	hlen:4;
    uint16_t	fin:1;
    uint16_t	syn:1;
    uint16_t	rst:1;
    uint16_t	psh:1;
    uint16_t	ack:1;
    uint16_t	urg:1;
    uint16_t	ece:1;
    uint16_t	cwr:1;
#else
    uint16_t	hlen:4;
    uint16_t	res1:4;
    uint16_t	cwr:1;
    uint16_t	ece:1;
    uint16_t	urg:1;
    uint16_t	ack:1;
    uint16_t	psh:1;
    uint16_t	rst:1;
    uint16_t	syn:1;
    uint16_t	fin:1;
#endif
    n16_t	win;
    n16_t	cksum;
    n16_t	urg_ptr;
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

#endif/* _COMO_IPV4_H */
