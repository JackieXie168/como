/*
 * Copyright (c) 2006 Intel Corporation
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

#include "como.h"
#include "wlan.h"

typedef struct {
    uint32_t did;
    uint16_t status;
    uint16_t len;
    uint32_t data;
} p80211item_t;

#define WLAN_DEVNAMELEN_MAX 16

typedef struct {
    uint32_t msgcode;
    uint32_t msglen;
    uint8_t devname[WLAN_DEVNAMELEN_MAX];
    p80211item_t hosttime;
    p80211item_t mactime;
    p80211item_t channel;
    p80211item_t rssi;
    p80211item_t sq;
    p80211item_t signal;
    p80211item_t noise;
    p80211item_t rate;
    p80211item_t istx;
    p80211item_t frmlen;
} prism2_header;

typedef struct {
    uint32_t version;
    uint32_t length;
    uint64_t mactime;
    uint64_t hosttime;
    uint32_t phytype;
    uint32_t channel;
    uint32_t datarate;
    uint32_t antenna;
    uint32_t priority;
    uint32_t ssitype;
    int32_t ssisignal;
    int32_t ssinoise;
    uint32_t preamble;
    uint32_t encoding;
} avs_80211_1_header;

int
avs_header_to_como_radio(const char *buf, struct _como_radio *r)
{
    avs_80211_1_header *h;

    h = (avs_80211_1_header *) buf;

    if (ntohl(h->version) != 0x80211001)
	return 0;

    N64(r->mactime) = h->mactime;
    N64(r->hosttime) = h->hosttime;
    N32(r->phytype) = h->phytype;
    N32(r->channel) = h->channel;
    N32(r->datarate) = h->datarate;
    N32(r->antenna) = h->antenna;
    N32(r->priority) = h->priority;
    N32(r->ssitype) = h->ssitype;
    N32(r->ssisignal) = h->ssisignal;
    N32(r->ssinoise) = h->ssinoise;
    N32(r->preamble) = h->preamble;
    N32(r->encoding) = h->encoding;

    return sizeof(avs_80211_1_header);
}

int
prism2_header_to_como_radio(const char *buf, struct _como_radio *r)
{
    prism2_header *h;

    h = (prism2_header *) buf;

    N64(r->mactime) = h->mactime.data;
    N64(r->hosttime) = h->hosttime.data;
    N32(r->phytype) = 0;
    N32(r->channel) = h->channel.data;
    N32(r->datarate) = h->rate.data;
    N32(r->antenna) = 0;
    N32(r->priority) = 0;
    N32(r->ssitype) = RADIO_SSITYPE_DBM;
    N32(r->ssisignal) = h->signal.data;
    N32(r->ssinoise) = h->noise.data;
    N32(r->preamble) = 0;
    N32(r->encoding) = 0;

    return sizeof(prism2_header);
}
