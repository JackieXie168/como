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

#ifndef _COMO_WLAN_H
#define _COMO_WLAN_H

#include "nettypes.h"
#include "ieee80211.h"

/* 
 * frame format derived from linux-wlan-ng codebase
 */
struct _como_wlan_avshdr {
    n32_t version;
    n32_t length;
    n64_t mactime;
    n64_t hosttime;
    n32_t phytype;
    n32_t channel;
    n32_t datarate;
    n32_t antenna;
    n32_t priority;
    n32_t ssi_type;
    n32_t ssi_signal;
    n32_t ssi_noise;
    n32_t preamble;
    n32_t encoding;
};
#define AVS_HDR(field)						\
    (((struct _como_wlan_avshdr*)(pkt->payload))->field)

#define AVS_HDR_LEN 64
#define AVS_MAGIC_COOKIE 0x80211001




/*
 * como management frame body components
 */
struct _como_wlan_mgmt_body {
    uint8_t ts[8];
    n16_t bivl;
    n16_t cap;
    n16_t aan;
    n16_t atsn;
    uint8_t ap_addr[6];
    n16_t li;
    n16_t rc;
    n16_t aid;
    n16_t sc;

    uint8_t ssid_len;
    char ssid[34];
    uint8_t rates_len;
    uint8_t rates[8];
    uint8_t ch;
    uint8_t padding;

    /*
     * working with a minimum set of information elements 
     * to start with. For now, fh, cf, tim, & challenge 
     * not supported - kpmcgrath
     */
};

typedef struct _como_wlan_mgmt_body mgmt_body_t;

#define MGMT_BODY(field)						\
    (((struct _como_wlan_mgmt_body*)(pkt->payload + pkt->l3ofs))->field)

#endif				/* _COMO_WLAN_H */
