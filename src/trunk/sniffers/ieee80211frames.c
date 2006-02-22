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

#include "como.h"
#include "comofunc.h"
#include "sniffers.h"
#include "stdpkt.h"
#include "ieee80211.h"

/* parsing  variables */
struct _p80211info {
    int rl;			/* remaining packet length */
    char *pkt_data;
    struct _como_wlan_mgmt_body *mgmt_body;
    uint32_t fc;
};

/*
 * -- ieee80211_hdrlen
 * return 802.11 header length 
 */
int
ieee80211_hdrlen(uint32_t fc)
{
    /* determine 802.11 frame type */
    switch (FCTRL_TYPE(fc)) {
    case WLANTYPE_MGMT:
	return MGMT_HDR_LEN;
    case WLANTYPE_CTRL:
	return 0;		/* TODO */
    case WLANTYPE_DATA:
	if (FCTRL_TO_DS(fc) && FCTRL_FROM_DS(fc))
	    return 30 + LLC_HDR_LEN;
	else
	    return 24 + LLC_HDR_LEN;
	break;
    default:
	logmsg(LOGWARN, "ieee802.11 frame type unknown\n");
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
    struct _como_wlan_mgmt_body *mgmt_body = pi->mgmt_body;

    int wh;			/* buffer offset */

    /* generic information element with ID + LEN fields */
    ie = (struct _ieee80211_info_element *) pi->pkt_data;

    while (pi->rl >= (ie->len + 2)) {
	switch (ie->id) {
	case SSID_TYPE:
	    ssid_type = (struct _ieee80211_ssid *) pi->pkt_data;
	    mgmt_body->ssid_len = ssid_type->len;
	    memcpy(mgmt_body->ssid, ssid_type->ssid, mgmt_body->ssid_len);
	    wh = ssid_type->len + 2;
	    break;
	case RATES_TYPE:
	    rates_type = (struct _ieee80211_rates *) pi->pkt_data;
	    mgmt_body->rates_len = rates_type->len;
	    memcpy(mgmt_body->rates, rates_type->rates, mgmt_body->rates_len);
	    wh = rates_type->len + 2;
	    break;
	case FH_TYPE:
	    wh = FH_IE_LEN;	/* information element ignored */
	    break;
	case DS_TYPE:
	    ds_type = (struct _ieee80211_ds *) pi->pkt_data;
	    mgmt_body->ch = ds_type->ch;
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

    stype = (struct _ieee80211_assoc_req *) pi->pkt_data;

    /*
     * fill management body structure with fixed fields
     */
    N16(pi->mgmt_body->cap) = stype->cap;
    N16(pi->mgmt_body->li) = stype->li;

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

    stype = (struct _ieee80211_assoc_res *) pi->pkt_data;

    N16(pi->mgmt_body->cap) = stype->cap;
    N16(pi->mgmt_body->sc) = stype->sc;
    N16(pi->mgmt_body->aid) = stype->aid;

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

    stype = (struct _ieee80211_reassoc_req *) pi->pkt_data;

    N16(pi->mgmt_body->cap) = stype->cap;
    N16(pi->mgmt_body->li) = stype->li;
    memcpy(pi->mgmt_body->ap_addr, stype->addr, 6);

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

    stype = (struct _ieee80211_reassoc_res *) pi->pkt_data;

    N16(pi->mgmt_body->cap) = stype->cap;
    N16(pi->mgmt_body->sc) = stype->sc;
    N16(pi->mgmt_body->aid) = stype->aid;

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

    stype = (struct _ieee80211_auth *) pi->pkt_data;
    /*
     * fill management body structure with fixed fields
     */
    N16(pi->mgmt_body->aan) = stype->aan;
    N16(pi->mgmt_body->atsn) = stype->atsn;

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

    stype = (struct _ieee80211_deauth *) pi->pkt_data;
    /*
     * fill management body structure with fixed fields
     */
    N16(pi->mgmt_body->rc) = stype->rc;

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

    stype = (struct _ieee80211_probe_res *) pi->pkt_data;

    memcpy(pi->mgmt_body->ts, stype->ts, 8);
    N16(pi->mgmt_body->bivl) = stype->bi;
    N16(pi->mgmt_body->cap) = stype->cap;

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

    stype = (struct _ieee80211_disassoc *) pi->pkt_data;

    N16(pi->mgmt_body->rc) = (stype->rc);

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

    stype = (struct _ieee80211_beacon *) pi->pkt_data;

    memcpy(pi->mgmt_body->ts, stype->ts, 8);
    N16(pi->mgmt_body->bivl) = stype->bi;
    N16(pi->mgmt_body->cap) = stype->cap;

    pi->rl -= BEACON_FIXED_LEN;
    pi->pkt_data += BEACON_FIXED_LEN;

    parse80211_info_elements(pi);
}


/*
 * -- parse80211_mgmtframe
 *
 * determine the 802.11 management frame subtype
 * call parsing subtype routine to fill the management body structure with
 * 802.11 variable size fields, this is used to converge the iee802.11 
 * structures to a como defined structure
 *
 */
static int
parse80211_mgmtframe(pkt_t * pkt, char *mgmt_buf, uint32_t fc)
{
    struct _p80211info pi;
    /*	FIXME: parser is not giving errors! */

    /*
     * copy the first packet bytes up to management header
     */
    memcpy(mgmt_buf, COMO(payload), COMO(l3ofs));

    /* remaining packet length to parse, when zero the packet
     * parsing process is complete
     */
    pi.rl = COMO(caplen) - COMO(l3ofs);

    /* update capture buffer and processed packets buffer pointers */
    pi.pkt_data = COMO(payload) + COMO(l3ofs);
    pi.mgmt_body = (struct _como_wlan_mgmt_body *) (mgmt_buf + COMO(l3ofs));

    switch (FCTRL_SUBTYPE(fc)) {
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
    COMO(caplen) = COMO(l3ofs) + sizeof(struct _como_wlan_mgmt_body);
    COMO(payload) = mgmt_buf;
    return COMO(caplen);
}


/*
 * -- ieee80211_parse_frame
 *
 * checks the frame type and in case of a management frame parses it
 * collecting all available header fields into a _como_wlan_mgmt_body
 * structure that is stored after the 802.11 header into memory pointed by
 * mgmt_buf.
 * returns the number of bytes used in the mgmt_buf
 */
int
ieee80211_parse_frame(pkt_t * pkt, char *mgmt_buf)
{
    uint32_t fc;

    fc = H16(IEEE80211_HDR(fc));

    switch (FCTRL_TYPE(fc)) {
    case WLANTYPE_MGMT:
	/*
	 * remaining packet length to parse, when zero the packet
	 * parsing process is complete
	 */
	return parse80211_mgmtframe(pkt, mgmt_buf, fc);
	break;
    case WLANTYPE_CTRL:
    case WLANTYPE_DATA:
    default:
	break;
    }
    return 0;
}
