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


/*
 * 802.11 frame type/subtype combinations
 */

#define WLANTYPE_MGMT 0x0000
#define WLANTYPE_CTRL 0x4000
#define WLANTYPE_DATA 0x8000


#define MGMT_SUBTYPE_ASSOC_REQ   0x0000
#define MGMT_SUBTYPE_ASSOC_RES   0x1000
#define MGMT_SUBTYPE_REASSOC_REQ 0x2000  
#define MGMT_SUBTYPE_REASSOC_RES 0x3000   
#define MGMT_SUBTYPE_PROBE_REQ   0x4000   
#define MGMT_SUBTYPE_PROBE_RES   0x5000 
/* Reserved                      0x6000 */  
/* Reserved                      0x7000 */  
#define MGMT_SUBTYPE_BEACON      0x8000 
#define MGMT_SUBTYPE_ATIM        0x9000 
#define MGMT_SUBTYPE_DISASSOC    0xa000    
#define MGMT_SUBTYPE_AUTH        0xb000  
#define MGMT_SUBTYPE_DEAUTH      0xc000  
/* Reserved                      0xd000 */  
/* Reserved                      0xe000 */  
/* Reserved                      0xf000 */  


#define CTRL_SUBTYPE_PS_POLL  0xa000   
#define CTRL_SUBTYPE_RTS      0xb000   
#define CTRL_SUBTYPE_CTS      0xc000    
#define CTRL_SUBTYPE_ACK      0xd000   
#define CTRL_SUBTYPE_CF_END   0xe000  
#define CTRL_SUBTYPE_END_ACK  0xf000   


#define DATA_SUBTYPE_DATA          0x0000   
#define DATA_SUBTYPE_DATA_CFACK    0x1000  
#define DATA_SUBTYPE_DATA_CFPL     0x2000 
#define DATA_SUBTYPE_DATA_CFACKPL  0x3000  
#define DATA_SUBTYPE_NULL          0x4000  
#define DATA_SUBTYPE_CFACK         0x5000  
#define DATA_SUBTYPE_CFPL          0x6000 
#define DATA_SUBTYPE_CFACKPL       0x7000  

/*
 * information element IDs
 */
#define SSID_TYPE      0
#define RATES_TYPE     1
#define FH_TYPE        2
#define DS_TYPE        3
#define CF_TYPE        4
#define TIM_TYPE       5
#define IBSS_TYPE      6
/* Reserved         7- 15 */
#define CHALLENGE_TYPE 16

#if 0
static const char *mgmt_subtypes[] = {
  "association request",
  "association response",
  "reassociation request",
  "reassociation response",
  "probe request",
  "probe response",
  "reserved",
  "reserved",
  "beacon",
  "atim",
  "disassociation",
  "authentication",
  "deauthentication",
  "reserved",
  "reserved"
};
#endif
/* 
 * frame format derived from linux-wlan-ng codebase
 */
struct _como_wlan_prism2hdr {
  n32_t      version;
  n32_t      length;
  n64_t      mactime;
  n64_t      hosttime;
  n32_t      phytype;
  n32_t      channel;
  n32_t      datarate;
  n32_t      antenna;
  n32_t      priority;
  n32_t      ssi_type;
  n32_t      ssi_signal;
  n32_t      ssi_noise;
  n32_t      preamble;
  n32_t      encoding;
}; 
/*
 * prism header macro
 */ 
#define PRISM_HDR(field)        \
    (((struct _como_wlan_prism2hdr*)(pkt->payload))->field)
#define PRISM_HDR_LEN 64

/*
 * general 802.11 mac header
 */
struct __wlan_hdr {
        uint16_t       fc;
        uint16_t       duration;
        uint8_t        addr1[6];
        uint8_t        addr2[6];
        uint8_t        addr3[6];
        uint16_t       seq;
        uint8_t        addr4[6];
}; 
/*** not working ***/
#define WLAN(field)         \
    (((struct _wlan_hdr*)(pkt->payload + pkt->layer3ofs))->field)


/*
 * 802.11 management mac header
 */ 
struct _como_wlan_mgmt_hdr {
    n16_t	fc;
    uint16_t 	duration;
    uint8_t	da[6]; 
    uint8_t 	sa[6];
    uint8_t 	bssid[6]; 
    uint16_t 	seq_ctrl;
};
/*
 * 802.11 management header macro
 */
#define MGMT_HDR(field)         \
    (((struct _como_wlan_mgmt_hdr*) \
     (pkt->payload + PRISM_HDR_LEN))->field)
#define MGMT_HDR_LEN 24


/*
 * frame control bits
 */
#define FC_TYPE(fc)             (((fc) << 4) & 0xc000)
#define FC_SUBTYPE(fc)          ((fc) & 0xf000)

/*
 * capability information bits
 */

#define CAP_ESS(cap)     ((cap) & 0x0001)
#define CAP_PRIVACY(cap) ((cap) & 0x0010)

struct _como_wlan_mgmt_beacon {
    uint64_t   ts;
    uint16_t   ivl;
    uint16_t   cap;
    char variable[0];
}; 

/*
 * beacon frame macro
 */
#define MGMT_BEACON(field)      \
    (((struct _como_wlan_mgmt_beacon*) \
     (pkt->payload + sizeof(struct _como_wlan_mgmt_hdr) \
      + sizeof(struct _como_wlan_prism2hdr)))->field)
#define BEACON_SUBTYPE_LEN 12

/*
 * control frame mac headers
 */


/*  
 * request to send frame format
 */
struct _como_wlan_ctrl_rts {
        uint16_t       fc;
        uint16_t       duration;
        uint8_t        ra[6];
        uint8_t        ta[6];
        uint8_t        fcs[4];
}; 
#define CTRL_RTS(field)         \
    (((struct _como_wlan_ctrl_rts*) \
     (pkt->payload + sizeof(struct _como_wlan_prism2hdr)))->field)

/*
 * clear to send frame format
 */
struct _como_wlan_ctrl_cts {
        uint16_t       fc;
        uint16_t       duration;
        uint8_t        ra[6];
        uint8_t        fcs[4];
}; 

#define CTRL_CTS(field)         \
    (((struct _como_wlan_ctrl_cts*) \
     (pkt->payload + sizeof(struct _como_wlan_prism2hdr)))->field)

/*
 * acknowledgement frame format
 */
struct _como_wlan_ctrl_ack {
        uint16_t       fc;
        uint16_t       duration;
        uint8_t        ra[6];
        uint8_t        fcs[4];
}; 

#define CTRL_ACK(field)         \
    (((struct _como_wlan_ctrl_cts*) \
     (pkt->payload + sizeof(struct _como_wlan_prism2hdr)))->field)

/*
 * power save poll frame format
 */

struct _como_wlan_ctrl_ps_poll {
        uint16_t       fc;
        uint16_t       aid;
        uint8_t        bssid[6];
        uint8_t        ta[6];
        uint8_t        fcs[4];
};

#define CTRL_PS_POLL(field)         \
    (((struct _como_wlan_ctrl_ps_poll*) \
     (pkt->payload + sizeof(struct _como_wlan_prism2hdr)))->field)

/*
 * cf-end frame format 
 */
struct _como_wlan_ctrl_end {
        uint16_t       fc;
        uint16_t       duration;
        uint8_t        ra[6];
        uint8_t        bssid[6];
        uint8_t        fcs[4];
}; 

#define CTRL_END(field)         \
    (((struct _como_wlan_ctrl_end*) \
     (pkt->payload + sizeof(struct _como_wlan_prism2hdr)))->field)

/*
 * cf-end + cf-ack frame format
 */
struct _como_wlan_ctrl_end_ack {
        uint16_t       fc;
        uint16_t       duration;
        uint8_t        ra[6];
        uint8_t        bssid[6];
        uint8_t        fcs[4];
}; 

#define CTRL_END_ACK(field)         \
    (((struct _como_wlan_ctrl_end_ack*) \
     (pkt->payload + sizeof(struct _como_wlan_prism2hdr)))->field)
/*
 * 802.11 data mac header
 */
struct _como_wlan_data_hdr {
        uint16_t       fc;
        uint16_t       duration;
        uint8_t        addr1[6];
        uint8_t        addr2[6];
        uint8_t        addr3[6];
        uint16_t       seq;
        uint8_t        addr4[6];
};
 
#define DATA_HDR(field)         \
    (((struct _como_wlan_data_hdr*) \
     (pkt->payload + sizeof(struct _como_wlan_prism2hdr))->field)

/*
 * service set identity element
 */


struct _como_wlan_info_element {
        uint8_t        id;
        uint8_t        len;
}; 



struct _como_wlan_ssid {
        uint8_t        id;
        uint8_t        len;
        char           ssid[34];
};

/*
 * supported rates element
 */
struct _como_wlan_rates {
        uint8_t        id;
        uint8_t        len;
        uint8_t        rates[8]; /* ??? */
};

/*
 * fh parameter set element
 */
struct _como_wlan_fh {
        uint8_t        id;
        uint8_t        length;
        uint16_t       dwell_time;
        uint8_t        hop_set;
        uint8_t        hop_pattern;
        uint8_t        hop_index;
};
#define FH_IE_LEN 7


/*
 * ds parameter set element
 */
struct _como_wlan_ds {
        uint8_t        id;
        uint8_t        len;
        uint8_t        ch;
};
#define DS_IE_LEN 3

/*
 * cf parameter set element
 */
struct _como_wlan_cf {
        uint8_t        id;
        uint8_t        length;
        uint8_t        count;
        uint8_t        period;
        uint16_t       md;
        uint16_t       dr;
}; 
#define CF_IE_LEN 8

/* 
 * ibss parameter set element
 */
struct _wlan_ibss {
        uint8_t   id;
        uint8_t   len;
        uint16_t  atim;
};
#define IBSS_IE_LEN 4

/*
 * tim element format
 */
struct _como_wlan_tim {
        uint8_t        id;
        uint8_t        len;
        uint8_t        cnt;
        uint8_t        period;
        uint8_t        bc;
        uint8_t        bmap[252];
}; 

/*
 * challenge text element
 */
struct _como_wlan_challenge {
        uint8_t        id;
        uint8_t        length;
        uint8_t        text[254]; /* 1-253 + 1 for NULL */
};


/*
 * como management frame body components
 */
struct _como_wlan_mgmt_body {

        uint64_t       timestamp;
        uint16_t       beacon_ivl;
        uint16_t       cap;
        uint16_t       auth_algorithm;
        uint16_t       auth_trans_seq;
        uint8_t        ap_addr[6];
        uint16_t       listen_interval;
        uint16_t       reason_code;
        uint16_t       assoc_id;
        uint16_t       status_code;
       
        struct _como_wlan_ssid ssid;
        struct _como_wlan_rates rates; 
        struct _como_wlan_ds ds;
        struct _como_wlan_fh fh;
        struct _como_wlan_cf cf;
        struct _como_wlan_tim tim;
        struct _como_wlan_challenge challenge_info;

};

#define MGMT_BODY(field)        \
    (((struct _como_wlan_mgmt_body*) \
    (pkt->payload + PRISM_HDR_LEN + MGMT_HDR_LEN))->field) 


/* Prism2 header with 802.11 header tagged on
 *
 * frame format derived from linux-wlan-ng codebase
 * 
 */
struct _como_prismhdr_lnx {
  uint32_t 	version;
  uint32_t      length;
  uint64_t      mactime;
  uint64_t	hosttime;
  uint32_t	phytype;
  uint32_t	channel;
  uint32_t	datarate;
  uint32_t 	antenna;
  uint32_t 	priority;
  uint32_t	ssi_type;
  int32_t 	ssi_signal;
  int32_t	ssi_noise;
  uint32_t	preamble;
  uint32_t	encoding;

                                /* need support for control & data frames */ 
  n16_t  	fc;
  uint16_t 	duration;
  uint8_t	da[6];
  uint8_t 	sa[6];
  uint8_t 	bssid[6];
  uint16_t 	seq_ctrl;

};


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
/*#define WLAN_TYPE_MASK          0x0c00*/
#define WLAN_MGMT               0x00
#define WLAN_CTL                0x04
#define WLAN_DATA               0x08
#define WLAN_WEP                0x40

/*#define WLAN_SUBTYPE_MASK	0xf000*/
/*#define WLAN_MGMT_BEACON	0x80*/

    uint16_t    id;
    uint8_t     addr1[6];
    uint8_t    addr2[6];
    uint8_t     addr3[6];
    uint16_t    seq;
    uint8_t	addr4[6];
    uint16_t    data_len;	/* frame length */
    uint8_t	dst[6];		/* same as addr1 */
    uint8_t	src[6]; 	/* same as addr2 */
    uint16_t    len;	/* same as data_len but big-endian */
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
#define __EXTRACT_L2_FIELD(type, tag, field) \
    (pkt->l2type == type ? \
     (((struct tag *)pkt->payload)->field) : \
     (abort(), ((struct tag *)NULL)->field))
#define PRISM2(field) __EXTRACT_L2_FIELD(COMOTYPE_PRISM_LNX, _como_prismhdr_lnx, field)
*/

/*
 *   Macros are specific to 64 byte prism header
 *
 */

#define WLAN_TYPE_MASK          0x0c
#define WLAN_SUBTYPE_MASK	0xf0

#define WLAN_HDR(field) \
    (((struct _como_wlan_mgmt_hdr *) \
    (pkt->payload + sizeof(struct _como_wlan_prism2hdr)))->field)


#define WLANTYPE	(H16(WLAN_HDR(fc)) & WLAN_TYPE_MASK) 
#define WLANSUBTYPE	(H16(WLAN_HDR(fc)) & WLAN_SUBTYPE_MASK) 

#define isWLANDATA	(WLANTYPE == WLANTYPE_DATA)
#define isWLANWEP	(isWLANDATA && (H16(WLAN_HDR(fc)) & WLAN_WEP))
#define isWLANMGMT	(WLANTYPE == WLANTYPE_MGMT) 
#define isWLANBEACON	(isWLANMGMT && (WLANSUBTYPE == MGMT_SUBTYPE_BEACON))
/*
#define WLANBEACON(field)					\
   (((struct _como_wlanbeacon *) 				\
	pkt->payload + sizeof(struct _como_prism_hdr_lnx))->field)
*/
/*#define WLANTYPE	(PRISM_LNX(fc) & WLAN_TYPE_MASK) 
#define WLANSUBTYPE	(PRISM_LNX(fc) & WLAN_SUBTYPE_MASK) 
*/
/*#define isWLANDATA	(WLANTYPE == WLAN_DATA)*/
/*#define isWLANWEP	(isWLANDATA && (WLAN_HDR_PRISM2(fc) & 0x0040)*/
/*#define isWLANMGMT	(WLANTYPE == WLANTYPE_MGMT) */
/*#define isWLANCTL	(WLANTYPE == WLAN_CTL) */
/*#define isWLANBEACON	(isWLANMGMT && (WLANSUBTYPE == MGMT_SUBTYPE_BEACON))
*/


/* 
 * packet macros 
 * 
 * these are useful to access directly the relevant fields 
 * in the various packet headers 
 */
/*
#define PRISM(field)            				\
    (((struct _como_prismhdr *) pkt->payload)->field)

*/

/*
 *
 */



/*
static int 
parse_stype_beacon()
{
    panicx("BEACON");

    return 1;
}
*/
#endif /* _COMO_STDWLAN_H */

