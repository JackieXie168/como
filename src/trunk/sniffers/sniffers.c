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
#include <net/ethernet.h> 
#include "como.h"
#include "comofunc.h"
#include "stdwlan.h"
#include "ieee80211.h"

/* 
 * this file includes some inline helper functions to be 
 * shared among all sniffers. 
 */

/* 
 * Layer 2 header lengths
 */
static size_t como_l2_len[] = {
    0,          // COMOTYPE_NONE
    14,         // COMOTYPE_ETH
    4,          // COMOTYPE_HDLC
    18,         // COMOTYPE_VLAN
    40,         // COMOTYPE_ISL
    0,          // COMOTYPE_NF
    0,		// COMOTYPE_80211     
    0 		// COMOTYPE_RADIO      
};



/* 
 * figure out if a packet is ISL.
 * use the destination address to do this. 
 */
static __inline__ int 
isISL(pkt_t * pkt) 
{
    const char val[] = {0x01, 0x00, 0x0c, 0x00, 0x00}; 
    int i; 
    struct _como_isl *islh = (struct _como_isl *)pkt->payload;
    if (islh->da[0] != 0x01 && islh->da[0] != 0x03) 
	return 0; 

    for (i = 1; i < 5; i++) 
	if (islh->da[i] != val[i])
	    return 0; 

    return 1; 
} 


/* 
 * -- updatel4 
 * 
 * populates l3ofs and l4ofs values of a packet
 */
static __inline__ void
updatel4(pkt_t * pkt)
{

    pkt->l4ofs = 0; 

    if (pkt->l3type == ETHERTYPE_IP) {
	pkt->l3ofs = pkt->l4ofs = como_l2_len[pkt->type];
	pkt->l4ofs += ((IP(vhl) & 0x0f) << 2);
	pkt->l4type = IP(proto);
    } else {
	switch(FCTRL_TYPE(pkt->l2type)) { /* determine 802.11 frame type */
	case WLANTYPE_MGMT:
	    pkt->l3ofs = pkt->l2ofs + MGMT_HDR_LEN;
	    pkt->l4ofs += pkt->l3ofs; 
	    break;
	case WLANTYPE_CTRL:
            pkt->l3ofs = pkt->l2ofs;
	    pkt->l4ofs += pkt->l3ofs; 
            break;
	case WLANTYPE_DATA:
	    if (FCTRL_TO_DS(pkt->l2type) && FCTRL_FROM_DS(pkt->l2type))
		pkt->l3ofs = pkt->l2ofs + 30 + LLC_HDR_LEN;
            else
		pkt->l3ofs = pkt->l2ofs + 24 + LLC_HDR_LEN;
	    pkt->l4ofs += pkt->l3ofs; 
            break;
         default:
            logmsg(LOGWARN, "ieee802.11 frame type unknown");
	    break;
	}
    }
}


/*
 * -- updateofs 
 * 
 * updates type and offset information in the pkt_t data structure. 
 * requires the type of interface as input. 
 */
__inline__ void 
updateofs(pkt_t * pkt, int type) 
{
    pkt->type = type; 
    pkt->l2type = 0xFFFF; /* implies field unused */ 
    switch (pkt->type) { 
    case COMOTYPE_ETH: 
        if (H16(ETH(type)) == ETHERTYPE_VLAN) {
            pkt->type = COMOTYPE_VLAN;
            pkt->l3type = H16(VLAN(ethtype));
        } else if (isISL(pkt)) { 
	    pkt->type = COMOTYPE_ISL; 
	    pkt->l3type = H16(ISL(ethtype)); 
	} else { 
            pkt->l3type = H16(ETH(type));
        }
	break; 

    case COMOTYPE_HDLC: 
	pkt->l3type = H16(HDLC(type)); 
        break; 
    
    case COMOTYPE_80211:
        pkt->l2type = H16(IEEE80211_HDR(fc));
        if (FCTRL_TYPE(pkt->l2type) == WLANTYPE_DATA)
	    pkt->l3type = H16(LLC_HDR(type));
	else
	    pkt->l3type = 0;
        break;
    case COMOTYPE_RADIO:
        pkt->l2type = H16(IEEE80211_HDR(fc)); /* 802.11 + XX byte capture hdr */
        if (FCTRL_TYPE(pkt->l2type) == WLANTYPE_DATA)
	    pkt->l3type = H16(LLC_HDR(type));
	else
	    pkt->l3type = 0;
        break;

    default: 
	pkt->l3type = 0; 
        break; 
    } 
    updatel4(pkt); 
}

