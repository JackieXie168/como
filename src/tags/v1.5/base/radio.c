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

#include <string.h> /* memcpy */

#include "como.h"
#include "comoendian.h"
#include "wlan.h"
#include "radiotap.h"

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
#ifdef COMO_LITTLE_ENDIAN
    N32(r->ssisignal) = h->ssisignal + 0x00ffffff;
    N32(r->ssinoise) = h->ssinoise + 0x00ffffff;
#else
    N32(r->ssisignal) = h->ssisignal - 256;
    N32(r->ssinoise) = h->ssinoise - 256;
#endif
    N32(r->preamble) = h->preamble;
    N32(r->encoding) = h->encoding;

    return sizeof(avs_80211_1_header);
}

int
prism2_header_to_como_radio(const char *buf, struct _como_radio *r)
{
    prism2_header *h;

    h = (prism2_header *) buf;

    N64(r->mactime) = (uint64_t) htonl(h->mactime.data);
    N64(r->hosttime) = (uint64_t) htonl(h->hosttime.data);
    N32(r->phytype) = 0;
    N32(r->channel) = htonl(h->channel.data);
    N32(r->datarate) = htonl(h->rate.data);
    N32(r->antenna) = 0;
    N32(r->priority) = 0;
    N32(r->ssitype) = RADIO_SSITYPE_DBM;
    N32(r->ssisignal) = htonl((int32_t)h->signal.data - 256);
    N32(r->ssinoise) = htonl((int32_t)h->noise.data - 256);
    N32(r->preamble) = 0;
    N32(r->encoding) = 0;

    return sizeof(prism2_header);
}

int
avs_or_prism2_header_to_como_radio(const char *buf, struct _como_radio *r)
{
    int len;

    len = avs_header_to_como_radio(buf, r);
    if (len > 0)
	return len;

    return prism2_header_to_como_radio(buf, r);
}

inline static int
channel_lookup_80211abg(uint16_t freq)
{
    switch(freq) {
        /* b, g */
        case 2412: return 1;
        case 2417: return 2;
        case 2422: return 3;
        case 2427: return 4;
        case 2432: return 5;
        case 2437: return 6;
        case 2442: return 7;
        case 2447: return 8;
        case 2452: return 9;
        case 2457: return 10;
        case 2462: return 11;
        case 2467: return 12;
        case 2472: return 13;
        case 2477: return 14;
        /* a */
        case 5170: return 34;
        case 5180: return 36;
        case 5190: return 38;
        case 5200: return 40;
        case 5210: return 42;
        case 5220: return 44;
        case 5230: return 46;
        case 5240: return 48;
        case 5260: return 52;
        case 5280: return 56;
        case 5300: return 60;
        case 5320: return 64;
        case 5745: return 149;
        case 5765: return 153;
        case 5785: return 157;
        case 5805: return 161;
        /* unknown */
        default: return 0;
    }
}

int
radiotap_header_to_como_radio(const char *buf, struct _como_radio *r)
{
    struct ieee80211_radiotap_header *h;
    h = (struct ieee80211_radiotap_header *) buf;
    uint32_t *bitmap;
    char *unpack_ptr;
    uint16_t uint16_value;
    uint8_t uint8_value;
    int8_t int8_value;

#define BIT_PRESENT(value, x) (value & (1 << (x)))

#define unpack(var) { \
    memcpy(&(var), unpack_ptr, sizeof(var)); \
    unpack_ptr += sizeof(var); \
}

    /* values not provided: */
    N64(r->hosttime) = 0;
    N32(r->phytype) = 0;
    N32(r->priority) = 0;
    N32(r->encoding) = 0;

    /* TODO check that we have the full header */

    bitmap = &h->it_present; /* deal with extended bitmaps in header */
    while (BIT_PRESENT(h->it_present, IEEE80211_RADIOTAP_EXT))
        bitmap++;

    unpack_ptr = (char *)(bitmap + 1); /* data starts after the bitmap */
    if (BIT_PRESENT(h->it_present, IEEE80211_RADIOTAP_TSFT))
	unpack(N64(r->hosttime));

    if (BIT_PRESENT(h->it_present, IEEE80211_RADIOTAP_FLAGS)) {
	uint8_t flags;
        unpack(flags);

        if (flags & IEEE80211_RADIOTAP_F_SHORTPRE)
            N32(r->preamble) = RADIO_PREAMBLE_SHORT_PREAMBLE;
        else
            N32(r->preamble) = RADIO_PREAMBLE_LONG_PREAMBLE;
    }

    if (BIT_PRESENT(h->it_present, IEEE80211_RADIOTAP_RATE)) {
        unpack(uint8_value);
        N32(r->datarate) = 5 * uint8_value;
    }
    if (BIT_PRESENT(h->it_present, IEEE80211_RADIOTAP_CHANNEL)) {

        unpack(uint16_value);
        N32(r->channel) = channel_lookup_80211abg(uint16_value);

        unpack(uint16_value); /* ignored flags */

        /*logmsg(LOGUI, "FREQ %x, flags=0x%x (", freq, flags);
	if (flags & IEEE80211_CHAN_TURBO)
		logmsg(LOGUI, " chan_turbo");
	if (flags & IEEE80211_CHAN_CCK)
		logmsg(LOGUI, " cck");
	if (flags & IEEE80211_CHAN_OFDM)
		logmsg(LOGUI, " ofdm");
	if (flags & IEEE80211_CHAN_2GHZ)
		logmsg(LOGUI, " 2ghz");
	if (flags & IEEE80211_CHAN_5GHZ)
		logmsg(LOGUI, " 5ghz");
	if (flags & IEEE80211_CHAN_PASSIVE)
		logmsg(LOGUI, " passive");
	if (flags & IEEE80211_CHAN_DYN)
		logmsg(LOGUI, " dyn");
	if (flags & IEEE80211_CHAN_GFSK)
		logmsg(LOGUI, " gfsk");
	logmsg(LOGUI, " )\n");*/
    }

    if (BIT_PRESENT(h->it_present, IEEE80211_RADIOTAP_FHSS))
        unpack(uint16_value); /* ignored */

    if (BIT_PRESENT(h->it_present, IEEE80211_RADIOTAP_DBM_ANTSIGNAL)) {
        unpack(int8_value);
        N32(r->ssitype) = RADIO_SSITYPE_DBM;
        N32(r->ssisignal) =  htonl((int32_t) int8_value);
    }
    if (BIT_PRESENT(h->it_present, IEEE80211_RADIOTAP_DBM_ANTNOISE)) {
        unpack(int8_value);
        N32(r->ssitype) = RADIO_SSITYPE_DBM;
        N32(r->ssinoise) =  htonl((int32_t) int8_value);
    }

    if (BIT_PRESENT(h->it_present, IEEE80211_RADIOTAP_LOCK_QUALITY))
        unpack(uint16_value); /* ignored */
    if (BIT_PRESENT(h->it_present, IEEE80211_RADIOTAP_TX_ATTENUATION))
        unpack(uint16_value); /* ignored */
    if (BIT_PRESENT(h->it_present, IEEE80211_RADIOTAP_DB_TX_ATTENUATION))
        unpack(uint16_value); /* ignored */
    if (BIT_PRESENT(h->it_present, IEEE80211_RADIOTAP_DBM_TX_POWER))
        unpack(int8_value); /* ignored */

    if (BIT_PRESENT(h->it_present, IEEE80211_RADIOTAP_ANTENNA)) {
        unpack(uint8_value);
        N32(r->antenna) = uint8_value;
    }

    if (BIT_PRESENT(h->it_present, IEEE80211_RADIOTAP_DB_ANTSIGNAL))
        unpack(uint8_value); /* ignored */
    if (BIT_PRESENT(h->it_present, IEEE80211_RADIOTAP_DB_ANTNOISE))
        unpack(uint8_value); /* ignored */

    return h->it_len;
}

