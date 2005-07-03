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

#ifndef _COMO_STDWLAN_H
#define _COMO_STDWLAN_H

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#ifndef	__CYGWIN32__		/* file not present there */
#include <net/ethernet.h>       /* ETHERTYPE_IP */
#endif
#include <netinet/in.h>
#include <arpa/inet.h>          /* inet_ntop */

#ifdef __APPLE__
#include <stdint.h>
#endif

#include "stdpkt.h"

/* 
 * add a como packet type 
 */
#define COMOTYPE_PRISM 		0x0005  /* IEEE 802.11 w/Prism2 radio */

/*  
 * Prism2 header (also known as Hermes header) 
 * 
 * the content has been derived from /usr/include/dev/wi/if_wavelan_ieee.h
 * 
 */
struct _como_prismhdr { 
    uint16_t	status;
#define PRISM_BADCRC		0x0001

    uint16_t	ts0;
    uint16_t	ts1;
    uint8_t 	silence;
    uint8_t     signal;
    uint8_t     rate;
    uint8_t     rx_flow;
    uint16_t    rsvd0;
    uint16_t    rsvd1;
    uint16_t    frame_ctl;
#define WLAN_TYPE_MASK          0x0c
#define WLAN_MGMT               0x00
#define WLAN_CTL                0x04
#define WLAN_DATA               0x08
#define WLAN_WEP                0x40

#define WLAN_SUBTYPE_MASK	0xf0
#define WLAN_MGMT_BEACON	0x80

    uint16_t    id;
    char        addr1[6];
    char        addr2[6];
    char        addr3[6];
    uint16_t    seq;
    char	addr4[6];
    uint16_t    data_len;	/* frame length */
    char	dst[6];		/* same as addr1 */
    char	src[6];		/* same as addr2 */
    uint16_t    len;		/* same as data_len but big-endian */
};


/*
 * beacon packet format...
 */
struct _como_wlanbeacon {
    uint64_t ts;
    uint16_t ivl;
    uint16_t cap;
#define WLAN_CAPINFO_PRIVACY	0x0010

    char variable[0];
};


/* 
 * packet macros 
 * 
 * these are useful to access directly the relevant fields 
 * in the various packet headers 
 */
#define PRISM(field)            				\
    (((struct _como_prismhdr *) pkt->payload)->field)
#define WLANBEACON(field)					\
   (((struct _como_wlanbeacon *) 				\
	pkt->payload + sizeof(struct _como_prismhdr))->field)


/* 
 * packet-related frequently asked questions...
 */
#define WLANTYPE	(PRISM(frame_ctl) & WLAN_TYPE_MASK) 
#define WLANSUBTYPE	(PRISM(frame_ctl) & WLAN_SUBTYPE_MASK) 

#define isWLANDATA	(WLANTYPE == WLAN_DATA)
#define isWLANWEP	(isWLANDATA && (PRISM(frame_ctl) & WLAN_WEP))
#define isWLANMGMT	(WLANTYPE == WLAN_MGMT) 
#define isWLANCTL	(WLANTYPE == WLAN_CTL) 
#define isWLANBEACON	(isWLANMGMT && (WLANSUBTYPE == WLAN_MGMT_BEACON))

#endif /* _COMO_STDWLAN_H */
