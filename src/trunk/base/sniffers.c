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
#include "stdpkt.h" 

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN  0x8100
#endif 

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
    18, 	// COMOTYPE_WLAN		// XXX fix this
    18		// COMOTYPE_WLANR		// XXX fix this
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

    if (ISL(da[0]) != 0x01 && ISL(da[0]) != 0x03) 
	return 0; 

    for (i = 1; i < 5; i++) 
	if (ISL(da[i]) != val[i])
	    return 0; 

    return 1; 
} 


/* 
 * -- update_ofs 
 * 
 * populates layer3ofs and layer4ofs values of a packet
 */
static __inline__ void
updatel4(pkt_t * pkt)
{
    pkt->layer3ofs = pkt->layer4ofs = como_l2_len[pkt->l2type];
    if (pkt->l3type ==  ETHERTYPE_IP)                                    
        pkt->layer4ofs += ((IP(vhl) & 0x0f) << 2);          
}


/*
 * -- update_l2_info 
 * 
 * updates type and offset information in the pkt_t data structure. 
 * requires the type of interface as input. 
 */
__inline__ void 
updateofs(pkt_t * pkt, int type) 
{
    pkt->l2type = type; 
    switch (pkt->l2type) { 
    case COMOTYPE_ETH: 
        if (H16(ETH(type)) == ETHERTYPE_VLAN) {
            pkt->l2type = COMOTYPE_VLAN;
            pkt->l3type = H16(VLAN(ethtype));
        } else if (isISL(pkt)) { 
	    pkt->l2type = COMOTYPE_ISL; 
	    pkt->l3type = H16(ISL(ethtype)); 
	} else { 
            pkt->l3type = H16(ETH(type));
        }
	break; 

    case COMOTYPE_HDLC: 
	pkt->l3type = H16(HDLC(type)); 
        break; 

    default: 
	pkt->l3type = 0; 
        break; 
    } 

    updatel4(pkt); 
}

