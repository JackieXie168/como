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

#ifndef _COMO_IEEE80211_H
#define _COMO_IEEE80211_H

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#ifndef __CYGWIN32__            /* file not present there */
#include <net/ethernet.h>       /* ETHERTYPE_IP */
#endif
#include <netinet/in.h>
#include <arpa/inet.h>          /* inet_ntop */


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


/*
 * frame control bits
 */
#define FC_TYPE(fc)    	(((fc) << 4) & 0xc000)
#define FC_SUBTYPE(fc)	((fc) & 0xf000)


/*
 * capability information bits
 */
#define CAP_ESS(cap)     ((cap) & 0x0001)
#define CAP_PRIVACY(cap) ((cap) & 0x0010)



/*
 * snap header: subnetwork access protocol
 */
struct ieee80211_snap_hdr {
    uint8_t dsap;              
    uint8_t ssap;   
    uint8_t ctrl;    
    uint8_t oui[3]; /* organisation code */ 
}; 


/*
 * ieee802.11 general header frame format 
 */
struct _ieee80211_hdr {
    n16_t       fc;
    n16_t       duration;
    uint8_t     addr1[6];
    uint8_t     addr2[6];
    uint8_t     addr3[6];
    n16_t       seq;
};

#define IEEE80211_HDR(field)         \
    (((struct _ieee80211_hdr*)(pkt->payload + pkt->l3ofs))->field)


/*
 * management frames: fixed fields
 */
struct _ieee80211_beacon {
    uint64_t ts;
    uint16_t bi;
    uint16_t cap;
};

struct _ieee80211_disassoc {
    uint16_t rc;
};

struct _ieee80211_assoc_req {
    uint16_t cap;
    uint16_t li;
};

struct _ieee80211_assoc_res {
    uint16_t cap;
    uint16_t sc;
    uint16_t aid;
};

struct _ieee80211_reassoc_req {
    uint16_t cap;
    uint16_t li;
    uint8_t  addr[6]; /* current ap address */
};

struct _ieee80211_reassoc_res {
    uint16_t cap;
    uint16_t sc;
    uint16_t aid;
};

struct _ieee80211_probe_res {
    uint64_t ts;
    uint16_t bi;
    uint16_t cap;
};

struct _ieee80211_auth {
    uint16_t aan;   /* auth algorithm number */ 
    uint16_t atsn;  /* auth transaction seq number*/
    uint16_t sc;
};

struct _ieee80211_deauth {
    uint16_t rc;
};

/*
 * fixed field lengths
 */ 
#define BEACON_FIXED_LEN 12
#define DISASSOC_FIXED_LEN 2
#define ASSOC_REQ_FIXED_LEN 4
#define ASSOC_RES_FIXED_LEN 6
#define REASSOC_REQ_FIXED_LEN 10
#define REASSOC_RES_FIXED_LEN 6
#define PROBE_REQ_FIXED_LEN 0
#define PROBE_RES_FIXED_LEN 12
#define AUTH_FIXED_LEN 6 
#define DEAUTH_FIXED_LEN 2

/*
 * control frame mac headers
 */
struct _ieee80211_ctrl_rts {
    uint16_t       fc;
    uint16_t       duration;
    uint8_t        ra[6];
    uint8_t        ta[6];
    uint8_t        fcs[4];
};


struct _ieee80211_ctrl_cts {
    uint16_t       fc;
    uint16_t       duration;
    uint8_t        ra[6];
    uint8_t        fcs[4];
};


struct _ieee80211_ctrl_ack {
    uint16_t       fc;
    uint16_t       duration;
    uint8_t        ra[6];
    uint8_t        fcs[4];
};


struct _ieee80211_ctrl_ps_poll {
    uint16_t       fc;
    uint16_t       aid;
    uint8_t        bssid[6];
    uint8_t        ta[6];
    uint8_t        fcs[4];
};


struct _ieee80211_ctrl_end {
    uint16_t       fc;
    uint16_t       duration;
    uint8_t        ra[6];
    uint8_t        bssid[6];
    uint8_t        fcs[4];
};


struct _ieee80211_ctrl_end_ack {
    uint16_t       fc;
    uint16_t       duration;
    uint8_t        ra[6];
    uint8_t        bssid[6];
    uint8_t        fcs[4];
};


#define CTRL_RTS(field)         \
    (((struct _ieee80211_ctrl_rts*)(pkt->payload + pkt->l3ofs))->field)
#define CTRL_CTS(field)         \
    (((struct _ieee80211_ctrl_cts*)(pkt->payload + pkt->l3ofs))->field)
#define CTRL_ACK(field)         \
    (((struct _ieee80211_ctrl_cts*)(pkt->payload + pkt->l3ofs))->field)
#define CTRL_PS_POLL(field)     \
    (((struct _ieee80211_ctrl_ps_poll*)(pkt->payload + pkt->l3ofs))->field)
#define CTRL_END(field)         \
    (((struct _ieee80211_ctrl_end*)(pkt->payload + pkt->l3ofs))->field)
#define CTRL_END_ACK(field)     \
    (((struct _ieee80211_ctrl_end_ack*)(pkt->payload + pkt->l3ofs))->field)


/*
 * 802.11 data mac header
 */
struct _ieee80211_data_hdr {
    uint16_t       fc;
    uint16_t       duration;
    uint8_t        addr1[6];
    uint8_t        addr2[6];
    uint8_t        addr3[6];
    uint16_t       seq;
    uint8_t        addr4[6];
};

#define DATA_HDR(field)         \
    (((struct _ieee80211_data_hdr*)(pkt->payload + pkt->l3ofs))->field)

#define DATA_HDR_LEN 24


/*
 * 802.11 management mac header
 */
struct _ieee80211_mgmt_hdr {
    n16_t       fc;
    uint16_t    duration;
    uint8_t     da[6];
    uint8_t     sa[6];
    uint8_t     bssid[6];
    uint16_t    seq_ctrl;
};


/*
 * 802.11 management mac header
 */
struct _como_wlan_mgmt_hdr {
    n16_t       fc;
    uint16_t    duration;
    uint8_t     da[6];
    uint8_t     sa[6];
    uint8_t     bssid[6];
    uint16_t    seq_ctrl;
};


/*
 * 802.11 management header macro
 */
#define MGMT_HDR(field)         \
    (((struct _ieee80211_mgmt_hdr*)(pkt->payload + pkt->l3ofs))->field)

#define MGMT_HDR_LEN 24


/* service set identity element */
struct _ieee80211_info_element {
    uint8_t	id;
    uint8_t     len;
};

struct _ieee80211_ssid {
    uint8_t     id;
    uint8_t     len;
    char        ssid[34];
};

struct _ieee80211_rates {
    uint8_t     id;
    uint8_t     len;
    uint8_t     rates[8]; /* ??? */
};

struct _ieee80211_fh {
    uint8_t     id;
    uint8_t     length;
    uint16_t    dwell_time;
    uint8_t     hop_set;
    uint8_t     hop_pattern;
    uint8_t     hop_index;
};


struct _ieee80211_ds {
    uint8_t    id;
    uint8_t    len;
    uint8_t    ch;
};

struct _ieee80211_cf {
    uint8_t    id;
    uint8_t    length;
    uint8_t    count;
    uint8_t    period;
    uint16_t   md;
    uint16_t   dr;
};

struct _ieee80211_ibss {
    uint8_t    id;
    uint8_t    len;
    uint16_t   atim;
};

struct _ieee80211_tim {
    uint8_t    id;
    uint8_t    len;
    uint8_t    cnt;
    uint8_t    period;
    uint8_t    bc;
    uint8_t    bmap[252];
};

struct _ieee80211_challenge {
    uint8_t    id;
    uint8_t    length;
    uint8_t    text[254]; /* 1-253 + 1 for NULL */
};


#define FH_IE_LEN 7
#define DS_IE_LEN 3
#define CF_IE_LEN 8
#define IBSS_IE_LEN 4

/* useful macros ... */
#define isWLANBEACON (MGMT_SUBTYPE_BEACON | (WLANTYPE_MGMT >> 4))


#endif /* _COMO_IEEE80211_H */ 


