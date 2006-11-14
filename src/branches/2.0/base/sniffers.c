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


#include <sys/types.h>
#include <string.h>
#include <assert.h>
#include "como.h"
#include "comofunc.h"
#include "stdpkt.h"

#include "sniffers-list.h"

sniffer_cb_t *
sniffer_cb_lookup(const char *name)
{
    int i;
    for (i = 0; g_como_builtin_sniffers[i] != NULL; i++) {
	if (strcmp(name, g_como_builtin_sniffers[i]->name) == 0) {
	    return g_como_builtin_sniffers[i];
	}
    }
    return NULL;
}

/* 
 * this file includes some inline helper functions to be 
 * shared among all sniffers. 
 */

int ieee80211_hdrlen(pkt_t * pkt);

static __inline__ uint32_t
comotype_lookup_len(int t)
{
    switch (t) {
    case COMOTYPE_ANY:
    case COMOTYPE_NONE:
    	return 0;
    case COMOTYPE_SFLOW:
	return sizeof(struct _como_sflow);
    case COMOTYPE_NF:
	return sizeof(struct _como_nf);
    case COMOTYPE_RADIO:
	return sizeof(struct _como_radio);
    case COMOTYPE_LINK:
    case COMOTYPE_COMO:
	return 0;
    }
    assert_not_reached();
    return 0;
}

static __inline__ uint32_t
linktype_lookup_len(int t)
{
    switch (t) {
    case LINKTYPE_ANY:
    case LINKTYPE_NONE:
	return 0;
    case LINKTYPE_ETH:
	return sizeof(struct _como_eth);
    case LINKTYPE_VLAN:
	return sizeof(struct _como_vlan);
    case LINKTYPE_ISL:
	return sizeof(struct _como_isl);
    case LINKTYPE_HDLC:
	return sizeof(struct _como_hdlc);
    /*case LINKTYPE_80211:*/
    /* FIXME: what to do here? */
    }
    assert_not_reached();
    return 0;
}

static __inline__ uint32_t
l3type_lookup_len(int t)
{
    switch (t) {
    case L3TYPE_ANY:
    case L3TYPE_NONE:
	return 0;
    case ETHERTYPE_IP:
	return sizeof(struct _como_iphdr);
    }
    assert_not_reached();
    return 0;
}

static __inline__ uint32_t
l4type_lookup_len(int t)
{
    switch (t) {
    case L4TYPE_ANY:
    case L4TYPE_NONE:
	return 0;
    case IPPROTO_TCP:
	return sizeof(struct _como_tcphdr);
    case IPPROTO_UDP:
	return sizeof(struct _como_udphdr);
    }
    return 0;
}

/* 
 * figure out if a packet is ISL.
 * use the destination address to do this. 
 */
static __inline__ int 
linktype_try_peek_ISL(pkt_t * pkt) 
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

static __inline__ int 
linktype_try_peek_VLAN(pkt_t * pkt) 
{
    return H16(ETH(type)) == ETHERTYPE_VLAN;
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
    COMO(l4type) = L4TYPE_NONE;

    if (COMO(l3type) == ETHERTYPE_IP
	&& COMO(caplen) > COMO(l3ofs) + sizeof(struct _como_iphdr)) {
	COMO(l4ofs) += (IP(ihl) << 2);
	COMO(l4type) = IP(proto);
    }
    /*
     * TODO: IPV6
     */
    COMO(l7ofs) = COMO(l4ofs);
    if (COMO(l4type) == IPPROTO_TCP && TCP(hlen) != 0) {
	COMO(l7ofs) += (TCP(hlen) << 2);
    } else {
	COMO(l7ofs) += l4type_lookup_len(COMO(l4type));
    }
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
    assert(COMO(type) != COMOTYPE_NONE);

    /*
     * update l2of
     */
    COMO(l2ofs) = comotype_lookup_len(COMO(type));

    /*
     * initialise l3ofs
     */
    COMO(l3ofs) = COMO(l2ofs);

    if (l == LALL) {
	COMO(l3ofs) += linktype_lookup_len(COMO(l2type));
	
	COMO(l4ofs) = COMO(l3ofs);
	
	if (COMO(l3type) == ETHERTYPE_IP) {
		COMO(l4ofs) += sizeof(struct _como_iphdr);
	}
	
	return;
    }

    /*
     * reset l2type and l3type
     */
    COMO(l2type) = LINKTYPE_NONE;
    COMO(l3type) = L3TYPE_NONE;

    if (l == L2) {

	/*
	 * update l2type, l3type, l3ofs
	 */
	switch (type) {
	case LINKTYPE_ETH:
	    if (linktype_try_peek_VLAN(pkt)) {
		COMO(l2type) = LINKTYPE_VLAN;
		COMO(l3type) = H16(VLAN(ethtype));
		COMO(l3ofs) += sizeof(struct _como_vlan);
	    } else if (linktype_try_peek_ISL(pkt)) {
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

	    COMO(l3ofs) += ieee80211_hdrlen(pkt);

	    if (IEEE80211_BASE(fc_type) == IEEE80211TYPE_DATA)
		COMO(l3type) = H16(LLC_HDR(type));

	    break;
	}
    } else if (l == L3) {
	COMO(l3type) = type;
    }

    updatel4(pkt);
}
