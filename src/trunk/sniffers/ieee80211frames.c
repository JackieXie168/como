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

#include <string.h>
#include <assert.h>

#include "como.h"
#include "comofunc.h"
#include "sniffers.h"
#include "stdpkt.h"
#include "ieee80211.h"

/* parsing  variables */
struct _p80211info {
    int rl;			/* remaining packet length */
    const char *pkt_data;
    struct _como_wlan_mgmt *wlan_mgmt;
    uint32_t fc;
};

/*
 * management frames: fixed fields
 */
struct _ieee80211_beacon {
    uint8_t ts[8];
    uint16_t bi;
    uint16_t cap;
};
#define BEACON_FIXED_LEN 12

struct _ieee80211_disassoc {
    uint16_t rc;
};
#define DISASSOC_FIXED_LEN 2

struct _ieee80211_assoc_req {
    uint16_t cap;
    uint16_t li;
};
#define ASSOC_REQ_FIXED_LEN 4

struct _ieee80211_assoc_res {
    uint16_t cap;
    uint16_t sc;
    uint16_t aid;
};
#define ASSOC_RES_FIXED_LEN 6

struct _ieee80211_reassoc_req {
    uint16_t cap;
    uint16_t li;
    uint8_t addr[6];		/* current ap address */
};
#define REASSOC_REQ_FIXED_LEN 10

struct _ieee80211_reassoc_res {
    uint16_t cap;
    uint16_t sc;
    uint16_t aid;
};
#define REASSOC_RES_FIXED_LEN 6

/*
struct _ieee80211_probe_req {
};
*/
#define PROBE_REQ_FIXED_LEN 0

struct _ieee80211_probe_res {
    uint8_t ts[8];
    uint16_t bi;
    uint16_t cap;
};
#define PROBE_RES_FIXED_LEN 12

struct _ieee80211_auth {
    uint16_t aan;		/* auth algorithm number */
    uint16_t atsn;		/* auth transaction seq number */
    uint16_t sc;
};
#define AUTH_FIXED_LEN 6

struct _ieee80211_deauth {
    uint16_t rc;
};
#define DEAUTH_FIXED_LEN 2

/* service set identity element */
struct _ieee80211_info_element {
    uint8_t id;
    uint8_t len;
};

struct _ieee80211_ssid {
    uint8_t id;
    uint8_t len;
    char ssid[34];
};

struct _ieee80211_rates {
    uint8_t id;
    uint8_t len;
    uint8_t rates[8];
};

struct _ieee80211_fh {
    uint8_t id;
    uint8_t length;
    uint16_t dwell_time;
    uint8_t hop_set;
    uint8_t hop_pattern;
    uint8_t hop_index;
};

#define FH_IE_LEN 7

struct _ieee80211_ds {
    uint8_t id;
    uint8_t len;
    uint8_t ch;
};

#define DS_IE_LEN 3

struct _ieee80211_cf {
    uint8_t id;
    uint8_t length;
    uint8_t count;
    uint8_t period;
    uint16_t md;
    uint16_t dr;
};

#define CF_IE_LEN 8

struct _ieee80211_ibss {
    uint8_t id;
    uint8_t len;
    uint16_t atim;
};

#define IBSS_IE_LEN 4

struct _ieee80211_tim {
    uint8_t id;
    uint8_t len;
    uint8_t cnt;
    uint8_t period;
    uint8_t bc;
    uint8_t bmap[252];
};

struct _ieee80211_challenge {
    uint8_t id;
    uint8_t length;
    uint8_t text[254];		/* 1-253 + 1 for NULL */
};

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
 * -- ieee80211_hdrlen
 * return 802.11 header length 
 */
int
ieee80211_hdrlen(pkt_t * pkt)
{
    /* determine 802.11 frame type */
    switch (IEEE80211_BASE(fc_type)) {
    case IEEE80211TYPE_MGMT:
	return MGMT_HDR_LEN;
    case IEEE80211TYPE_CTRL:
	return 0;		/* TODO */
    case IEEE80211TYPE_DATA:
	if (IEEE80211_BASE(fc_to_ds) && IEEE80211_BASE(fc_from_ds))
	    return 30 + LLC_HDR_LEN;
	else
	    return 24 + LLC_HDR_LEN;
	break;
    default:
	logmsg(LOGWARN, "ieee802.11 frame type unknown\n");
	assert_not_reached();
	break;
    }
    return 0;			/* XXX */
}

/*
 * -- parse80211_info_elemeents
 *
 * fill managment body structure with 802.11 variable size fields, used to 
 * converge the ieee802.11 structures to a como defined structure
 */
static void
parse80211_info_elements(struct _p80211info *pi)
{
    /* information element types */
    struct _ieee80211_info_element *ie;
    struct _ieee80211_ssid *ssid_type;
    struct _ieee80211_rates *rates_type;
    struct _ieee80211_ds *ds_type;
    struct _ieee80211_tim *tim_type;
    struct _como_wlan_mgmt *wlan_mgmt = pi->wlan_mgmt;

    int wh;			/* buffer offset */

    /* generic information element with ID + LEN fields */
    ie = (struct _ieee80211_info_element *) pi->pkt_data;

    while (pi->rl >= (ie->len + 2)) {
	switch (ie->id) {
	case SSID_TYPE:
	    ssid_type = (struct _ieee80211_ssid *) pi->pkt_data;
	    wlan_mgmt->ssid_len = ssid_type->len;
	    memcpy(wlan_mgmt->ssid, ssid_type->ssid, wlan_mgmt->ssid_len);
	    wh = ssid_type->len + 2;
	    break;
	case RATES_TYPE:
	    rates_type = (struct _ieee80211_rates *) pi->pkt_data;
	    wlan_mgmt->rates_len = rates_type->len;
	    memcpy(wlan_mgmt->rates, rates_type->rates, wlan_mgmt->rates_len);
	    wh = rates_type->len + 2;
	    break;
	case FH_TYPE:
	    wh = FH_IE_LEN;	/* information element ignored */
	    break;
	case DS_TYPE:
	    ds_type = (struct _ieee80211_ds *) pi->pkt_data;
	    wlan_mgmt->ch = ds_type->ch;
	    wh = DS_IE_LEN;
	    break;
	case CF_TYPE:
	    wh = CF_IE_LEN;	/* information element ignored */
	    break;
	case IBSS_TYPE:
	    wh = IBSS_IE_LEN;	/* information element ignored */
	    break;
	case TIM_TYPE:
	    tim_type = (struct _ieee80211_tim *) pi->pkt_data;
	    wh = tim_type->len + 2;
	    break;
	default:
	    /* reserved information elements ignored */
	    ie = (struct _ieee80211_info_element *) pi->pkt_data;
	    wh = ie->len + 2;	/* fixed fields: element id + length field */
	    break;
	}
	pi->pkt_data += wh;
	/*
	 * remaining packet length to parse, when zero the packet
	 * parsing process is complete
	 */
	pi->rl -= wh;
	ie = (struct _ieee80211_info_element *) pi->pkt_data;
    }
}

/*
 * -- parse80211_assoc_req
 *
 * fill managment body structure, used to converge the ieee802.11 
 * management structures to a como defined structure
 */
static void
parse80211_assoc_req(struct _p80211info *pi)
{
    struct _ieee80211_assoc_req *stype;
    
    if (pi->rl < ASSOC_REQ_FIXED_LEN)
	return;

    stype = (struct _ieee80211_assoc_req *) pi->pkt_data;

    /*
     * fill management body structure with fixed fields
     */
    N16(pi->wlan_mgmt->cap) = stype->cap;
    N16(pi->wlan_mgmt->li) = stype->li;

    /*
     * remaining packet length to parse, when zero the packet
     * parsing process is complete
     */
    pi->rl -= ASSOC_REQ_FIXED_LEN;
    pi->pkt_data += ASSOC_REQ_FIXED_LEN;

    parse80211_info_elements(pi);
}


/*
 * -- parse80211_assoc_res
 *
 * fill managment body structure, used to converge the ieee802.11 
 * management structures to a como defined structure
 */
static void
parse80211_assoc_res(struct _p80211info *pi)
{
    struct _ieee80211_assoc_res *stype;

    if (pi->rl < ASSOC_RES_FIXED_LEN)
	return;

    stype = (struct _ieee80211_assoc_res *) pi->pkt_data;

    N16(pi->wlan_mgmt->cap) = stype->cap;
    N16(pi->wlan_mgmt->sc) = stype->sc;
    N16(pi->wlan_mgmt->aid) = stype->aid;

    pi->rl -= ASSOC_RES_FIXED_LEN;
    pi->pkt_data += ASSOC_RES_FIXED_LEN;

    parse80211_info_elements(pi);
}


/*
 * -- parse80211_reassoc_req
 *
 * fill managment body structure, used to converge the ieee802.11 
 * management structures to a como defined structure
 */
static void
parse80211_reassoc_req(struct _p80211info *pi)
{
    struct _ieee80211_reassoc_req *stype;

    if (pi->rl < REASSOC_REQ_FIXED_LEN)
	return;

    stype = (struct _ieee80211_reassoc_req *) pi->pkt_data;

    N16(pi->wlan_mgmt->cap) = stype->cap;
    N16(pi->wlan_mgmt->li) = stype->li;
    memcpy(pi->wlan_mgmt->ap_addr, stype->addr, 6);

    pi->rl -= REASSOC_REQ_FIXED_LEN;
    pi->pkt_data += REASSOC_REQ_FIXED_LEN;

    parse80211_info_elements(pi);
}


/*
 * -- parse80211_ressoc_res
 *
 * fill managment body structure, used to converge the ieee802.11 
 * management structures to a como defined structure
 */
static void
parse80211_reassoc_res(struct _p80211info *pi)
{
    struct _ieee80211_reassoc_res *stype;

    if (pi->rl < REASSOC_RES_FIXED_LEN)
	return;

    stype = (struct _ieee80211_reassoc_res *) pi->pkt_data;

    N16(pi->wlan_mgmt->cap) = stype->cap;
    N16(pi->wlan_mgmt->sc) = stype->sc;
    N16(pi->wlan_mgmt->aid) = stype->aid;

    pi->rl -= REASSOC_RES_FIXED_LEN;
    pi->pkt_data += REASSOC_RES_FIXED_LEN;

    parse80211_info_elements(pi);
}


/*
 * -- parse80211_auth
 *
 * fill managment body structure, used to converge the ieee802.11 
 * management structures to a como defined structure
 */
static void
parse80211_auth(struct _p80211info *pi)
{
    struct _ieee80211_auth *stype;

    if (pi->rl < AUTH_FIXED_LEN)
	return;

    stype = (struct _ieee80211_auth *) pi->pkt_data;
    /*
     * fill management body structure with fixed fields
     */
    N16(pi->wlan_mgmt->aan) = stype->aan;
    N16(pi->wlan_mgmt->atsn) = stype->atsn;

    pi->rl -= AUTH_FIXED_LEN;
    pi->pkt_data += AUTH_FIXED_LEN;

    parse80211_info_elements(pi);
}


/*
 * -- parse80211_deauth
 *
 * fill managment body structure, used to converge the ieee802.11 
 * management structures to a como defined structure
 */
static void
parse80211_deauth(struct _p80211info *pi)
{
    struct _ieee80211_deauth *stype;

    if (pi->rl < DEAUTH_FIXED_LEN)
	return;

    stype = (struct _ieee80211_deauth *) pi->pkt_data;
    /*
     * fill management body structure with fixed fields
     */
    N16(pi->wlan_mgmt->rc) = stype->rc;

    pi->rl -= DEAUTH_FIXED_LEN;
    pi->pkt_data += DEAUTH_FIXED_LEN;
}


/*
 * -- parse80211_probe_res
 *
 * fill managment body structur, used to converge the ieee802.11 
 * management structures to a como defined structure
 */
static void
parse80211_probe_res(struct _p80211info *pi)
{
    struct _ieee80211_probe_res *stype;

    if (pi->rl < PROBE_RES_FIXED_LEN)
	return;

    stype = (struct _ieee80211_probe_res *) pi->pkt_data;

    memcpy(pi->wlan_mgmt->ts, stype->ts, 8);
    N16(pi->wlan_mgmt->bivl) = stype->bi;
    N16(pi->wlan_mgmt->cap) = stype->cap;

    pi->rl -= PROBE_RES_FIXED_LEN;
    pi->pkt_data += PROBE_RES_FIXED_LEN;

    parse80211_info_elements(pi);
}


/*
 * -- parse80211_probe_req
 *
 * fill managment body structur, used to converge the ieee802.11 
 * management structures to a como defined structure
 */
static void
parse80211_probe_req(struct _p80211info *pi)
{
    /* PROBE_REQ_FIXED_LEN: fixed header is 0 lenght */
    parse80211_info_elements(pi);
}


/*
 * -- parse80211_disassoc
 *
 * fill managment body structur, used to converge the ieee802.11 
 * management structures to a como defined structure
 */
static void
parse80211_disassoc(struct _p80211info *pi)
{
    struct _ieee80211_disassoc *stype;

    if (pi->rl < DISASSOC_FIXED_LEN)
	return;

    stype = (struct _ieee80211_disassoc *) pi->pkt_data;

    N16(pi->wlan_mgmt->rc) = (stype->rc);

    pi->rl -= DISASSOC_FIXED_LEN;
    pi->pkt_data += DISASSOC_FIXED_LEN;
}


/*
 * -- parse80211_beacon
 *
 * fill managment body structur, used to converge the ieee802.11 
 * management structures to a como defined structure
 */
static void
parse80211_beacon(struct _p80211info *pi)
{
    struct _ieee80211_beacon *stype;

    if (pi->rl < BEACON_FIXED_LEN)
	return;

    stype = (struct _ieee80211_beacon *) pi->pkt_data;

    memcpy(pi->wlan_mgmt->ts, stype->ts, 8);
    N16(pi->wlan_mgmt->bivl) = stype->bi;
    N16(pi->wlan_mgmt->cap) = stype->cap;

    pi->rl -= BEACON_FIXED_LEN;
    pi->pkt_data += BEACON_FIXED_LEN;

    parse80211_info_elements(pi);
}


/*
 * -- parse80211_mgmt_frame
 *
 * determine the 802.11 management frame subtype
 * call parsing subtype routine to fill the management body structure with
 * 802.11 variable size fields, this is used to converge the iee802.11 
 * structures to a como defined structure
 *
 */
static int
parse80211_mgmt_frame(const char *buf, int buf_len, char *dest)
{
    struct _p80211info pi;
    struct _ieee80211_mgmt_hdr *h;

    if (buf_len < (int) sizeof(struct _ieee80211_mgmt_hdr)) {
    	/* The snaplen is too small: give up! */
    	return 0;
    }

    h = (struct _ieee80211_mgmt_hdr *) buf;

    /* copy the management header */
    memcpy(dest, buf, sizeof(struct _ieee80211_mgmt_hdr));
    buf += sizeof(struct _ieee80211_mgmt_hdr);
    dest += sizeof(struct _ieee80211_mgmt_hdr);
    buf_len -= sizeof(struct _ieee80211_mgmt_hdr);

    /* remaining packet length to parse, when zero the packet
     * parsing process is complete
     */
    pi.rl = buf_len;

    /* update capture buffer and processed packets buffer pointers */
    pi.pkt_data = buf;
    pi.wlan_mgmt = (struct _como_wlan_mgmt *) dest;

    switch (h->fc_subtype) {
    case MGMT_SUBTYPE_ASSOC_REQ:
	parse80211_assoc_req(&pi);
	break;
    case MGMT_SUBTYPE_ASSOC_RES:
	parse80211_assoc_res(&pi);
	break;
    case MGMT_SUBTYPE_REASSOC_REQ:
	parse80211_reassoc_req(&pi);
	break;
    case MGMT_SUBTYPE_REASSOC_RES:
	parse80211_reassoc_res(&pi);
	break;
    case MGMT_SUBTYPE_PROBE_REQ:
	parse80211_probe_req(&pi);
	break;
    case MGMT_SUBTYPE_PROBE_RES:
	parse80211_probe_res(&pi);
	break;
    case MGMT_SUBTYPE_BEACON:
	parse80211_beacon(&pi);
	break;
    case MGMT_SUBTYPE_ATIM:
	break;
    case MGMT_SUBTYPE_DISASSOC:
	parse80211_disassoc(&pi);
	break;
    case MGMT_SUBTYPE_AUTH:
	parse80211_auth(&pi);
	break;
    case MGMT_SUBTYPE_DEAUTH:
	parse80211_deauth(&pi);
	break;
    }

    return sizeof(struct _ieee80211_mgmt_hdr) + sizeof(struct _como_wlan_mgmt);
}


/*
 * -- ieee80211_capture_frame
 *
 * checks the frame type and in case of a management frame parses it
 * collecting all available header fields into a _como_wlan_mgmt
 * structure that is stored after the 802.11 header into memory pointed by
 * mgmt_buf.
 * returns the number of bytes written in dest
 */
int
ieee80211_capture_frame(const char *buf, int buf_len, char *dest)
{
    struct _ieee80211_base *h;

    h = (struct _ieee80211_base *) buf;

    switch (h->fc_type) {
    case IEEE80211TYPE_MGMT:
	/*
	 * remaining packet length to parse, when zero the packet
	 * parsing process is complete
	 */
	return parse80211_mgmt_frame(buf, buf_len, dest);
	break;
    case IEEE80211TYPE_CTRL:
    case IEEE80211TYPE_DATA:
	memcpy(dest, buf, buf_len);
	return buf_len;
    default:
	break;
    }
    return 0;
}
