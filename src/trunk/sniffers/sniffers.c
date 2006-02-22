/*
 * Copyright (c) 2005, Intel Corporation
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

#include <sys/types.h>
#include <assert.h>
#include "como.h"
#include "comofunc.h"
#include "stdpkt.h"

/* 
 * this file includes some inline helper functions to be 
 * shared among all sniffers. 
 */

int ieee80211_hdrlen(uint32_t fc);

/* 
 * figure out if a packet is ISL.
 * use the destination address to do this. 
 */
static __inline__ int 
isISL(pkt_t * pkt) 
{
    const char val[] = {0x01, 0x00, 0x0c, 0x00, 0x00}; 
    int i; 

    if (ISL(da)[0] != 0x01 && ISL(da)[0] != 0x03)
	return 0;

    for (i = 1; i < 5; i++)
	if (ISL(da)[i] != val[i])
	    return 0;

    return 1;
}


/* 
 * -- updatel4 
 * 
 * populates l4type and l4ofs values of a packet
 */
static void
updatel4(pkt_t * pkt)
{
    COMO(l4ofs) = COMO(l3ofs);
    COMO(l4type) = 0;

    if (COMO(l3type) == ETHERTYPE_IP
	&& COMO(caplen) > COMO(l3ofs) + sizeof(struct _como_iphdr)) {
	COMO(l4ofs) += ((IP(vhl) & 0x0f) << 2);
	COMO(l4type) = IP(proto);
    }
    /*
     * TODO: IPV6
     */
}

/*
 * -- updateofs 
 * 
 * updates type and offset information in the pkt_t data structure.
 * requires the type of interface as input. 
 */
void
updateofs(pkt_t * pkt, layer_t l, int type)
{
    uint32_t fc;
    assert(COMO(type) != 0);

    /*
     * update l2of
     */
    switch (COMO(type)) {
    case COMOTYPE_SFLOW:
	COMO(l2ofs) = sizeof(struct _como_sflow);
	break;
    case COMOTYPE_NF:
	COMO(l2ofs) = sizeof(struct _como_nf);
	break;
    case COMOTYPE_RADIO:
	COMO(l2ofs) = sizeof(struct _como_wlan_prism2hdr);
	break;
    case COMOTYPE_LINK:
    case COMOTYPE_COMO:
	COMO(l2ofs) = 0;
	break;
    default:
	assert_not_reached();
    }

    /*
     * initialise l2type, l3type and l3ofs
     */
    COMO(l2type) = 0;
    COMO(l3type) = 0;
    COMO(l3ofs) = COMO(l2ofs);

    if (l == L2) {

	/*
	 * update l2type, l3type, l3ofs
	 */
	switch (type) {
	case LINKTYPE_ETH:
	    if (H16(ETH(type)) == ETHERTYPE_VLAN) {
		COMO(l2type) = LINKTYPE_VLAN;
		COMO(l3type) = H16(VLAN(ethtype));
		COMO(l3ofs) += sizeof(struct _como_vlan);
	    } else if (isISL(pkt)) {
		COMO(l2type) = LINKTYPE_ISL;
		COMO(l3type) = H16(ISL(ethtype));
		COMO(l3ofs) += sizeof(struct _como_isl);
	    } else {
		COMO(l2type) = LINKTYPE_ETH;
		COMO(l3type) = H16(ETH(type));
		COMO(l3ofs) += sizeof(struct _como_eth);
	    }
	    break;
	case LINKTYPE_HDLC:
	    COMO(l2type) = LINKTYPE_HDLC;
	    COMO(l3type) = H16(HDLC(type));
	    COMO(l3ofs) += sizeof(struct _como_hdlc);
	    break;
	case LINKTYPE_80211:
	    COMO(l2type) = LINKTYPE_80211;

	    fc = H16(IEEE80211_HDR(fc));
	    COMO(l3ofs) += ieee80211_hdrlen(fc);

	    if (FCTRL_TYPE(fc) == WLANTYPE_DATA)
		COMO(l3type) = H16(LLC_HDR(type));

	    break;
	}
    } else {
	COMO(l3type) = type;
    }

    updatel4(pkt);
}
