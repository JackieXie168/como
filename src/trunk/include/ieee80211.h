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

#ifndef _COMO_IEEE80211_H
#define _COMO_IEEE80211_H

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#ifndef __CYGWIN32__		/* file not present there */
#include <net/ethernet.h>	/* ETHERTYPE_IP */
#endif
#include <netinet/in.h>
#include <arpa/inet.h>		/* inet_ntop */

#include "comoendian.h"

/*
 * 802.11 frame type/subtype combinations
 */
enum IEEE80211TYPE {
    IEEE80211TYPE_MGMT = 0x0,
    IEEE80211TYPE_CTRL = 0x1,
    IEEE80211TYPE_DATA = 0x2
};

enum IEEE80211STYPE_MGMT {
    IEEE80211STYPE_MGMT_ASSOC_REQ = 0x0,
    IEEE80211STYPE_MGMT_ASSOC_RES = 0x1,
    IEEE80211STYPE_MGMT_REASSOC_REQ = 0x2,
    IEEE80211STYPE_MGMT_REASSOC_RES = 0x3,
    IEEE80211STYPE_MGMT_PROBE_REQ = 0x4,
    IEEE80211STYPE_MGMT_PROBE_RES = 0x5,
/* Reserved                      0x6 */
/* Reserved                      0x7 */
    IEEE80211STYPE_MGMT_BEACON = 0x8,
    IEEE80211STYPE_MGMT_ATIM = 0x9,
    IEEE80211STYPE_MGMT_DISASSOC = 0xa,
    IEEE80211STYPE_MGMT_AUTH = 0xb,
    IEEE80211STYPE_MGMT_DEAUTH = 0xc
/* Reserved                      0xd */
/* Reserved                      0xe */
/* Reserved                      0xf */
};

enum IEEE80211STYPE_CTRL {
    IEEE80211STYPE_CTRL_PS_POLL = 0xa,
    IEEE80211STYPE_CTRL_RTS = 0xb,
    IEEE80211STYPE_CTRL_CTS = 0xc,
    IEEE80211STYPE_CTRL_ACK = 0xd,
    IEEE80211STYPE_CTRL_CF_END = 0xe,
    IEEE80211STYPE_CTRL_END_ACK = 0xf
};

enum IEEE80211STYPE_DATA {
    IEEE80211STYPE_DATA_DATA = 0x0,
    IEEE80211STYPE_DATA_DATA_CFACK = 0x1,
    IEEE80211STYPE_DATA_DATA_CFPL = 0x2,
    IEEE80211STYPE_DATA_DATA_CFACKPL = 0x3,
    IEEE80211STYPE_DATA_NULL = 0x4,
    IEEE80211STYPE_DATA_CFACK = 0x5,
    IEEE80211STYPE_DATA_CFPL = 0x6,
    IEEE80211STYPE_DATA_CFACKPL = 0x7
};

#define MGMT_SUBTYPE_ASSOC_REQ   0x0
#define MGMT_SUBTYPE_ASSOC_RES   0x1
#define MGMT_SUBTYPE_REASSOC_REQ 0x2
#define MGMT_SUBTYPE_REASSOC_RES 0x3
#define MGMT_SUBTYPE_PROBE_REQ   0x4
#define MGMT_SUBTYPE_PROBE_RES   0x5
/* Reserved                      0x6 */
/* Reserved                      0x7 */
#define MGMT_SUBTYPE_BEACON      0x8
#define MGMT_SUBTYPE_ATIM        0x9
#define MGMT_SUBTYPE_DISASSOC    0xa
#define MGMT_SUBTYPE_AUTH        0xb
#define MGMT_SUBTYPE_DEAUTH      0xc
/* Reserved                      0xd */
/* Reserved                      0xe */
/* Reserved                      0xf */

#define CTRL_SUBTYPE_PS_POLL  0xa
#define CTRL_SUBTYPE_RTS      0xb
#define CTRL_SUBTYPE_CTS      0xc
#define CTRL_SUBTYPE_ACK      0xd
#define CTRL_SUBTYPE_CF_END   0xe
#define CTRL_SUBTYPE_END_ACK  0xf

#define DATA_SUBTYPE_DATA          0x0
#define DATA_SUBTYPE_DATA_CFACK    0x1
#define DATA_SUBTYPE_DATA_CFPL     0x2
#define DATA_SUBTYPE_DATA_CFACKPL  0x3
#define DATA_SUBTYPE_NULL          0x4
#define DATA_SUBTYPE_CFACK         0x5
#define DATA_SUBTYPE_CFPL          0x6
#define DATA_SUBTYPE_CFACKPL       0x7


/*
 * capability information bits
 */
#define CAPINFO_ESS(cap)     ((cap) & 0x0100)
#define CAPINFO_IBSS(cap)    ((cap) & 0x0200)
#define CAPINFO_CFP(cap)     ((cap) & 0x0400)
#define CAPINFO_CFP_REQ(cap) ((cap) & 0x0800)
#define CAPINFO_PRIVACY(cap) ((cap) & 0x1000)


/*
 * snap header: subnetwork access protocol
 * layer 2 encapsulation header
 */
struct _ieee80211_snap_hdr {
    uint8_t dsap;
    uint8_t ssap;
    uint8_t ctrl;
    uint8_t oui[3];		/* organisation code */
    n16_t type;
};

#define LLC_HDR_LEN 8
/* FIXME: what happens when data header is 30 bytes length? */
#define IEEE80211_LLC(field) \
    (((struct _ieee80211_snap_hdr*)(pkt->payload + pkt->l2ofs + \
    DATA_HDR_LEN))->field)

/* Deprecated */
#define LLC_HDR(field) \
    (((struct _ieee80211_snap_hdr*)(pkt->payload + pkt->l2ofs + \
    DATA_HDR_LEN))->field)


#ifdef COMO_LITTLE_ENDIAN
struct _ieee80211_frame_control {
    uint16_t version:2;
    uint16_t type:2;
    uint16_t subtype:4;

    uint16_t to_ds:1;
    uint16_t from_ds:1;
    uint16_t more_fragments:1;
    uint16_t retry:1;

    uint16_t power_management:1;
    uint16_t more_data:1;
    uint16_t wep:1;
    uint16_t order:1;
};
#endif

#ifdef COMO_BIG_ENDIAN
struct _ieee80211_frame_control {
    uint16_t subtype:4;
    uint16_t type:2;
    uint16_t version:2;

    uint16_t order:1;
    uint16_t wep:1;
    uint16_t more_data:1;
    uint16_t power_management:1;

    uint16_t retry:1;
    uint16_t more_fragments:1;
    uint16_t from_ds:1;
    uint16_t to_ds:1;
};
#endif

#define fc_version		fc.version
#define fc_type			fc.type
#define fc_subtype		fc.subtype
#define fc_to_ds		fc.to_ds
#define fc_from_ds		fc.from_ds
#define fc_more_fragments	fc.more_fragments
#define fc_retry		fc.retry
#define fc_power_management	fc.power_management
#define fc_more_data		fc.more_data
#define fc_wep			fc.wep
#define fc_order		fc.order

/*
 * ieee802.11 base header frame format 
 */
struct _ieee80211_base {
    struct _ieee80211_frame_control	fc;
    n16_t				duration;
    uint8_t				addr1[6];
    uint8_t				addr2[6];
    uint8_t				addr3[6];
    n16_t				seq;
};

#define IEEE80211_BASE(field)         \
    (((struct _ieee80211_base*)(pkt->payload + pkt->l2ofs))->field)


/*
 * control frame mac headers
 */
struct _ieee80211_ctrl_rts {
    struct _ieee80211_frame_control	fc;
    uint16_t				duration;
    uint8_t				ra[6];
    uint8_t				ta[6];
    uint8_t				fcs[4];
};

#define CTRL_RTS(field)         \
    (((struct _ieee80211_ctrl_rts*)(pkt->payload + pkt->l2ofs))->field)

struct _ieee80211_ctrl_cts {
    struct _ieee80211_frame_control	fc;
    uint16_t				duration;
    uint8_t				ra[6];
    uint8_t				fcs[4];
};

#define CTRL_CTS(field)         \
    (((struct _ieee80211_ctrl_cts*)(pkt->payload + pkt->l2ofs))->field)

struct _ieee80211_ctrl_ack {
    struct _ieee80211_frame_control	fc;
    uint16_t				duration;
    char				ra[6];
    uint8_t				fcs[4];
};

#define CTRL_ACK(field)         \
    (((struct _ieee80211_ctrl_cts*)(pkt->payload + pkt->l2ofs))->field)

struct _ieee80211_ctrl_ps_poll {
    struct _ieee80211_frame_control	fc;
    uint16_t				aid;
    uint8_t				bssid[6];
    uint8_t				ta[6];
    uint8_t				fcs[4];
};

#define CTRL_PS_POLL(field)     \
    (((struct _ieee80211_ctrl_ps_poll*)(pkt->payload + pkt->l2ofs))->field)

struct _ieee80211_ctrl_end {
    struct _ieee80211_frame_control	fc;
    uint16_t				duration;
    uint8_t				ra[6];
    uint8_t				bssid[6];
    uint8_t				fcs[4];
};

#define CTRL_END(field)         \
    (((struct _ieee80211_ctrl_end*)(pkt->payload + pkt->l2ofs))->field)

struct _ieee80211_ctrl_end_ack {
    struct _ieee80211_frame_control	fc;
    uint16_t				duration;
    uint8_t				ra[6];
    uint8_t				bssid[6];
    uint8_t				fcs[4];
};

#define CTRL_END_ACK(field)     \
    (((struct _ieee80211_ctrl_end_ack*)(pkt->payload + pkt->l2ofs))->field)


/*
 * 802.11 data mac header
 */
struct _ieee80211_data_hdr {
    struct _ieee80211_frame_control	fc;
    uint16_t				duration;
    uint8_t				addr1[6];
    uint8_t				addr2[6];
    uint8_t				addr3[6];
    uint16_t				seq;
    uint8_t				addr4[6];
};

#define DATA_HDR(field)         \
    (((struct _ieee80211_data_hdr*)(pkt->payload + pkt->l2ofs))->field)

#define DATA_HDR_LEN 24


/*
 * 802.11 management mac header
 */
struct _ieee80211_mgmt_hdr {
    struct _ieee80211_frame_control	fc;
    uint16_t				duration;
    uint8_t				da[6];
    uint8_t				sa[6];
    uint8_t				bssid[6];
    uint16_t				seq_ctrl;
};

/*
 * 802.11 management header macro
 */

#ifdef BUILD_FOR_ARM

#define MGMT_HDR(field)               \
    ((typeof(((struct _ieee80211_mgmt_hdr *)NULL)->field)) \
     get_field((char *)&(((struct _ieee80211_mgmt_hdr *) \
     (pkt->payload + pkt->l2ofs))->field), \
     sizeof(typeof(((struct _ieee80211_mgmt_hdr *)NULL)->field))))

#else

#define MGMT_HDR(field)         \
    (((struct _ieee80211_mgmt_hdr*)(pkt->payload + pkt->l2ofs))->field)

#endif

#define MGMT_HDR_LEN 24

#endif				/* _COMO_IEEE80211_H */
