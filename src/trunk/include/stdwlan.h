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
#include "ieee80211.h"

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
#define PRISM_HDR(field)        \
    (((struct _como_wlan_prism2hdr*)(pkt->payload))->field)

#define PRISM_HDR_LEN 64


/*
 * como management frame body components
 */
struct _como_wlan_mgmt_body {
    uint64_t       ts;
    uint16_t       bi;
    uint16_t       cap;
    uint16_t       aan;
    uint16_t       atsn;
    uint8_t        addr[6];
    uint16_t       li;
    uint16_t       rc;
    uint16_t       aid;
    uint16_t       sc;
   
    struct _ieee80211_ssid ssid;
    struct _ieee80211_rates rates; 
    struct _ieee80211_ds ds;
#if 0 
    /*
     * working with a minimum set of information elements 
     * to start with. For now, fh, cf, tim, & challenge 
     * not supported - kpmcgrath
     */
    struct _ieee80211_fh fh;
    struct _ieee80211_cf cf;
    struct _ieee80211_tim tim;
    struct _ieee80211_challenge challenge_info;
#endif
};
#define MGMT_BODY(field)        \
    (((struct _como_wlan_mgmt_body*)(pkt->payload + pkt->l3ofs))->field) 

typedef struct _como_wlan_mgmt_body        mgmt_body_t;


#define WLAN_CAPINFO_PRIVACY	0x0010



/* parsing  variables */
struct _p80211info {
    uint32_t  hdrlen;  /* header length */
    int  rl;           /* remaining packet length */
    int  n;
};


/* function used by sniffer-*.c to parse the 802.11 frames */
int
parse80211_info_elements(pkt_t *pkt, char * buf, char *pl,
                     struct _p80211info *pi, mgmt_body_t *mgmt_body);
int
parse80211_dataframe(pkt_t *pkt, char *buf, char *pl);
int
parse80211_ctrlframe(pkt_t *pkt, char *buf, char *pl);
int
parse80211_mgmtframe(pkt_t *pkt, char *buf, char *pl, struct _p80211info *pi);
int
ieee80211_hdrlen(pkt_t *pkt, uint32_t type);
int
parse80211_assoc_req(pkt_t *pkt, char * buf, char *pl, struct _p80211info *pi);
int
parse80211_assoc_res(pkt_t *pkt, char * buf, char *pl, struct _p80211info *pi);
int
parse80211_reassoc_req(pkt_t *pkt, char * buf, char *pl,
                                                    struct _p80211info *pi);
int
parse80211_reassoc_res(pkt_t *pkt, char * buf, char *pl,
                                                    struct _p80211info *pi);
int
parse80211_auth(pkt_t *pkt, char * buf, char *pl, struct _p80211info *pi);
int
parse80211_deauth(pkt_t *pkt, char * buf, char *pl, struct _p80211info *pi);
int
parse80211_probe_res(pkt_t *pkt, char * buf, char *pl, struct _p80211info *pi);
int
parse80211_probe_req(pkt_t *pkt, char * buf, char *pl, struct _p80211info *pi);
int
parse80211_disassoc(pkt_t *pkt, char * buf,
                                           char *pl, struct _p80211info *pi);
int
parse80211_beacon(pkt_t *pkt, char * buf, char *pl, struct _p80211info *pi);
void
update_parse_params(pkt_t *pkt, struct _p80211info *pi, int len);

#endif /* _COMO_STDWLAN_H */

