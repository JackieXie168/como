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

#include <strings.h>

#include "como.h"
#include "comofunc.h"
#include "sniffers.h"
#include "stdwlan.h"
#include "ieee80211.h"

/*
 * PCAP header. It precedes every packet in the file.
 */
typedef struct {
    struct timeval ts;          /* time stamp */
    int caplen;                 /* length of portion present */
    int len;                    /* length this packet (on the wire) */
} pcap_hdr_t;


/*
 * -- ieee80211_hdrlen
 * to support different header types 
 */
int 
ieee80211_hdrlen(pkt_t *pkt, uint32_t type)
{
    /* determine header type */
    switch(type) { 
    case COMOTYPE_80211:
	pkt->l2ofs = 0;
	return 0;
	break;
    case COMOTYPE_RADIO: /* AVS wlan monitoring header ??? */
	pkt->l2ofs = PRISM_HDR_LEN;
	return PRISM_HDR_LEN;
	break;
    /* 
     * should support bsd 802.11 monitor header -- kpmcgrath 
     */
    default:
	break;
    }
    return 1;
}


/*
 * -- parse80211_frame
 *
 * determines the 802.11 frame type and the header length 
 * for the captured packet 
 */
int
parse80211_frame(pkt_t *pkt,char *buf,char *pl,uint32_t type)
{
    struct _p80211info pi;

    pi.hdrlen = ieee80211_hdrlen(pkt,type); /* capture header length */ 
    bcopy(buf,pl,pi.hdrlen+2);
    updateofs(pkt, type);

    switch(FC_TYPE(pkt->l2type)) {
    case WLANTYPE_MGMT:
	/*
	 * remaining packet length to parse, when zero the packet
	 * parsing process is complete
	 */
	pi.rl = pkt->caplen;
        return parse80211_mgmtframe(pkt,buf,pl,&pi);
	break;
    case WLANTYPE_CTRL:
	return parse80211_ctrlframe(pkt,buf,pl);
	break;
    case WLANTYPE_DATA:
	return parse80211_dataframe(pkt,buf,pl);
	break;
    default:
	break;
    }
    return 0;
}


/*
 * -- parse80211_dataframe
 */
int
parse80211_dataframe(pkt_t *pkt, char *buf, char *pl)
{
    bcopy(buf, pl, pkt->caplen);
    return pkt->caplen;
}


/*
 * -- parse80211_ctrlframe
 */
int
parse80211_ctrlframe(pkt_t *pkt, char *buf, char *pl)
{
    bcopy(buf, pl, pkt->caplen);
    return pkt->caplen;
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
int
parse80211_mgmtframe(pkt_t *pkt, char *buf, char *pl, struct _p80211info *pi)
{
    pi->hdrlen += MGMT_HDR_LEN; /* captured + 802.11 mgmt header length */
    /* remaining packet length to parse, when zero the packet
     * parsing process is complete
     */
    pi->rl -= pi->hdrlen; 
    bcopy(buf, pl, pi->hdrlen);
    pkt->caplen = pi->hdrlen; 
    
    /* update capture buffer and processed packets buffer pointers */
    buf += pi->hdrlen; pl += pi->hdrlen;

    switch(FC_SUBTYPE(pkt->l2type)) {
    case MGMT_SUBTYPE_ASSOC_REQ:
	return parse80211_assoc_req(pkt,buf,pl,pi);
	break;
    case MGMT_SUBTYPE_ASSOC_RES:
	return parse80211_assoc_res(pkt,buf,pl,pi);
	break;
    case MGMT_SUBTYPE_REASSOC_REQ:
	return parse80211_reassoc_req(pkt,buf,pl,pi);
	break;
    case MGMT_SUBTYPE_REASSOC_RES:
	return parse80211_reassoc_res(pkt,buf,pl,pi);
	break;
    case MGMT_SUBTYPE_PROBE_REQ:
	return parse80211_probe_req(pkt,buf,pl,pi);      
	break;
    case MGMT_SUBTYPE_PROBE_RES:
	return parse80211_probe_res(pkt,buf,pl,pi);
	break;
    case MGMT_SUBTYPE_BEACON:
	return parse80211_beacon(pkt,buf,pl,pi);
	break;
    case MGMT_SUBTYPE_ATIM:
	break;
    case MGMT_SUBTYPE_DISASSOC:
	return parse80211_disassoc(pkt,buf,pl,pi);
	break;
    case MGMT_SUBTYPE_AUTH:
	return parse80211_auth(pkt,buf,pl,pi);
	break;
    case MGMT_SUBTYPE_DEAUTH:
	return parse80211_deauth(pkt,buf,pl,pi);
	break;
    default:
	return 0;
    }
  return 0;
}


/*
 * -- parse80211_assoc_req
 *
 * fill managment body structure, used to converge the ieee802.11 
 * management structures to a como defined structure
 */ 
int
parse80211_assoc_req(pkt_t *pkt, char * buf, char *pl, struct _p80211info *pi) 
{
    struct _ieee80211_assoc_req *stype;
    struct _como_wlan_mgmt_body *mgmt_body;

    mgmt_body = (struct _como_wlan_mgmt_body *) pl;
    stype = (struct _ieee80211_assoc_req *) buf;
    /*
     * fill management body structure with fixed fields
     */
    mgmt_body->cap = stype->cap; 
    mgmt_body->li = stype->li;
    /* 
     * increment pointer for capture buffer and buffer 
     * for processed 802.11 packets 
     */ 
    buf += ASSOC_REQ_FIXED_LEN;
    pl += ASSOC_REQ_FIXED_LEN;
    /*
     * helper function
     */
    update_parse_params(pkt,pi,ASSOC_REQ_FIXED_LEN);
    return parse80211_info_elements(pkt,buf,pl,pi,mgmt_body);
}


/*
 * -- parse80211_assoc_res
 *
 * fill managment body structure, used to converge the ieee802.11 
 * management structures to a como defined structure
 */ 
int
parse80211_assoc_res(pkt_t *pkt, char * buf, char *pl, struct _p80211info *pi) 
{
    struct _ieee80211_assoc_res *stype;
    struct _como_wlan_mgmt_body *mgmt_body;
    int hdrlen; 

    switch(pkt->type) {
    case COMOTYPE_80211:
         hdrlen =  MGMT_HDR_LEN;
         break;
    case COMOTYPE_RADIO:
         hdrlen = PRISM_HDR_LEN + MGMT_HDR_LEN;
         break;
    default:
         break;
    }
    bcopy(buf, pkt->payload, hdrlen);

    /*
     * fill management body structure with fixed fields
     */
    mgmt_body->cap = stype->cap;
    mgmt_body->sc = stype->sc;
    mgmt_body->aid = stype->aid;
    /* 
     * increment pointer for capture buffer and buffer 
     * for processed 802.11 packets 
     */ 
    buf += ASSOC_RES_FIXED_LEN;
    pl += ASSOC_RES_FIXED_LEN;
    /*
     * helper function
     */ 
    update_parse_params(pkt,pi,ASSOC_RES_FIXED_LEN);
    return parse80211_info_elements(pkt,buf,pl,pi,mgmt_body);
}


/*
 * -- parse80211_reassoc_req
 *
 * fill managment body structure, used to converge the ieee802.11 
 * management structures to a como defined structure
 */ 
int
parse80211_reassoc_req(pkt_t *pkt, char * buf, char *pl, 
						    struct _p80211info *pi) 
{
    struct _ieee80211_reassoc_req *stype;
    struct _como_wlan_mgmt_body *mgmt_body;

    mgmt_body = (struct _como_wlan_mgmt_body *) pl;
    stype = (struct _ieee80211_reassoc_req *) buf;
    /*
     * fill management body structure with fixed fields
     */
    mgmt_body->cap = stype->cap;
    mgmt_body->li = stype->li;
    bcopy(stype->addr, mgmt_body->addr, 6);
    /* 
     * increment pointer for capture buffer and buffer 
     * for processed 802.11 packets 
     */ 
    buf += REASSOC_REQ_FIXED_LEN;
    pl += REASSOC_REQ_FIXED_LEN;
    /*
     * helper function
     */  
    update_parse_params(pkt,pi,REASSOC_REQ_FIXED_LEN);
    return parse80211_info_elements(pkt,buf,pl,pi,mgmt_body);
}


/*
 * -- parse80211_ressoc_res
 *
 * fill managment body structure, used to converge the ieee802.11 
 * management structures to a como defined structure
 */ 
int
parse80211_reassoc_res(pkt_t *pkt,char * buf,char *pl,struct _p80211info *pi) 
{
    struct _ieee80211_reassoc_res *stype;
    struct _como_wlan_mgmt_body *mgmt_body;

    mgmt_body = (struct _como_wlan_mgmt_body *) pl;
    stype = (struct _ieee80211_reassoc_res *) buf;
    /*
     * fill management body structure with fixed fields
     */
    mgmt_body->cap = stype->cap;
    mgmt_body->sc = stype->sc;
    mgmt_body->aid = stype->aid;
    /* 
     * increment pointer for capture buffer and buffer 
     * for processed 802.11 packets 
     */ 
    buf += REASSOC_RES_FIXED_LEN;
    pl += REASSOC_RES_FIXED_LEN;
    /*
     * helper function
     */
    update_parse_params(pkt,pi,REASSOC_RES_FIXED_LEN);
    return parse80211_info_elements(pkt,buf,pl,pi,mgmt_body);
}


/*
 * -- parse80211_auth
 *
 * fill managment body structure, used to converge the ieee802.11 
 * management structures to a como defined structure
 */ 
int
parse80211_auth(pkt_t *pkt, char * buf, char *pl, struct _p80211info *pi) 
{
    struct _ieee80211_auth *stype;
    struct _como_wlan_mgmt_body *mgmt_body;

    mgmt_body = (struct _como_wlan_mgmt_body *) pl;
    stype = (struct _ieee80211_auth *) buf;
    /*
     * fill management body structure with fixed fields
     */
    mgmt_body->aan = stype->aan;
    mgmt_body->atsn = stype->atsn;
    /* 
     * increment pointer for capture buffer and buffer 
     * for processed 802.11 packets 
     */ 
    buf += AUTH_FIXED_LEN;
    pl += AUTH_FIXED_LEN;
    /*
     * helper function
     */
    update_parse_params(pkt,pi,AUTH_FIXED_LEN);
    return parse80211_info_elements(pkt,buf,pl,pi,mgmt_body);
}

/*
 * -- parse80211_deauth
 *
 * fill managment body structure, used to converge the ieee802.11 
 * management structures to a como defined structure
 */ 
int
parse80211_deauth(pkt_t *pkt, char * buf, char *pl, struct _p80211info *pi) 
{
    struct _ieee80211_deauth *stype;
    struct _como_wlan_mgmt_body *mgmt_body;

    mgmt_body = (struct _como_wlan_mgmt_body *) pl;
    stype = (struct _ieee80211_deauth *) buf;
    /*
     * fill management body structure with fixed fields
     */
    mgmt_body->rc = stype->rc;
    /*
     * update counters
     */ 
    pkt->caplen += DEAUTH_FIXED_LEN;
    buf += DEAUTH_FIXED_LEN;
    return pi->hdrlen + sizeof(struct _como_wlan_mgmt_body);
}


/*
 * -- parse80211_probe_res
 *
 * fill managment body structur, used to converge the ieee802.11 
 * management structures to a como defined structure
 */ 
int
parse80211_probe_res(pkt_t *pkt, char * buf, char *pl, struct _p80211info *pi) 
{
    struct _ieee80211_probe_res *stype;
    struct _como_wlan_mgmt_body *mgmt_body;

    mgmt_body = (struct _como_wlan_mgmt_body *) pl;
    stype = (struct _ieee80211_probe_res *) buf;

    mgmt_body->ts = stype->ts; /* probe response fixed fields */
    mgmt_body->bi = stype->bi;
    mgmt_body->cap = stype->cap;
    /* 
     * increment pointer for capture buffer and buffer 
     * for processed 802.11 packets 
     */ 
    buf += PROBE_RES_FIXED_LEN;
    pl += PROBE_RES_FIXED_LEN;
    /*
     * helper function
     */
    update_parse_params(pkt,pi,PROBE_RES_FIXED_LEN);
    return parse80211_info_elements(pkt,buf,pl,pi,mgmt_body); 
}


/*
 * -- parse80211_probe_req
 *
 * fill managment body structur, used to converge the ieee802.11 
 * management structures to a como defined structure
 */ 
int
parse80211_probe_req(pkt_t *pkt, char * buf, 
                                           char *pl, struct _p80211info *pi) 
{
    struct _como_wlan_mgmt_body *mgmt_body;
    mgmt_body = (struct _como_wlan_mgmt_body *) pl;

    pi->n = PROBE_REQ_FIXED_LEN; 
    return parse80211_info_elements(pkt,buf,pl,pi,mgmt_body); 
}


/*
 * -- parse80211_disassoc
 *
 * fill managment body structur, used to converge the ieee802.11 
 * management structures to a como defined structure
 */ 
int
parse80211_disassoc(pkt_t *pkt, char * buf, char *pl, struct _p80211info *pi) 
{
    struct _ieee80211_disassoc *stype;
    struct _como_wlan_mgmt_body *mgmt_body;
  
    mgmt_body = (struct _como_wlan_mgmt_body *) pl;
    stype = (struct _ieee80211_disassoc *) buf;
    /*
     * fill management body structure with fixed fields
     */
    mgmt_body->rc = stype->rc;
    /*
     * update counters
     */
    pkt->caplen += DISASSOC_FIXED_LEN;
    buf += DISASSOC_FIXED_LEN;
    return pi->hdrlen + sizeof(struct _como_wlan_mgmt_body);
}


/*
 * -- parse80211_beacon
 *
 * fill managment body structur, used to converge the ieee802.11 
 * management structures to a como defined structure
 */ 
int
parse80211_beacon(pkt_t *pkt, char * buf, char *pl, struct _p80211info *pi) 
{
    struct _ieee80211_beacon *stype_bcn;
    struct _como_wlan_mgmt_body *mgmt_body;

    mgmt_body = (struct _como_wlan_mgmt_body *) pl;
    stype_bcn = (struct _ieee80211_beacon *) buf;

    mgmt_body->ts = stype_bcn->ts; /* beacon fixed fields */
    mgmt_body->bi = stype_bcn->bi;
    mgmt_body->cap = stype_bcn->cap;
    /* 
     * increment pointer for capture buffer and buffer 
     * for processed 802.11 packets 
     */ 
    buf += BEACON_FIXED_LEN;
    pl += BEACON_FIXED_LEN;
    /*
     * helper function
     */
    update_parse_params(pkt,pi,BEACON_FIXED_LEN);
    return parse80211_info_elements(pkt,buf,pl,pi,mgmt_body); 
}

/*
 * -- parse80211_info_elemeents
 *
 * fill managment body structure with 802.11 variable size fields, used to 
 * converge the ieee802.11 structures to a como defined structure
 */
int
parse80211_info_elements(pkt_t *pkt, char * buf, char *pl, 
				struct _p80211info *pi, mgmt_body_t *mgmt_body)
{
    struct _ieee80211_info_element *ie;
    struct _ieee80211_ssid *ssid_type;
    struct _ieee80211_rates *rates_type;
    struct _ieee80211_ds *ds_type;
    struct _ieee80211_tim *tim_type;

    int bptr = 0;       /* buffer pointer */
    int wh;

    ie = (struct _ieee80211_info_element *)buf;
    
    while(pi->rl >= (ie->len + 2)){
	switch(ie->id) {
	case SSID_TYPE:  
	    ssid_type = (struct _ieee80211_ssid *)buf;
	    mgmt_body->ssid.id = ssid_type->id;
	    mgmt_body->ssid.len = ssid_type->len;
	    bcopy(ssid_type->ssid, mgmt_body->ssid.ssid, mgmt_body->ssid.len);
	    wh = ssid_type->len + 2;
	    break;
	case RATES_TYPE: 
	    rates_type = (struct _ieee80211_rates *)buf;
	    mgmt_body->rates.id = rates_type->id;
	    mgmt_body->rates.len = rates_type->len;
	    bcopy(rates_type->rates, mgmt_body->rates.rates, 
							mgmt_body->rates.len);
	    wh = rates_type->len + 2;
	    break;
	case FH_TYPE:
	    wh = FH_IE_LEN; /* information element ignored */
	    break;
	case DS_TYPE:
	    ds_type = (struct _ieee80211_ds *)buf;
	    mgmt_body->ds.id = ds_type->id;
	    mgmt_body->ds.len = ds_type->len; 
	    mgmt_body->ds.ch = ds_type->ch;
	    wh = DS_IE_LEN;
	    break;
	case CF_TYPE:
	    wh = CF_IE_LEN; /* information element ignored */
	    break;
	case IBSS_TYPE:
	    wh = IBSS_IE_LEN; /* information element ignored */
	    break;
	case TIM_TYPE:
	/* information element ignored */
	    tim_type = (struct _ieee80211_tim *)buf;
	    wh = tim_type->len + 2;
	    break;
	default: 
	    /* reserved information elements ignored */
	    ie = (struct _ieee80211_info_element *)buf;
	    wh = ie->len + 2; /* fixed fields: element id + length field */
	    break;          
	}
	pkt->caplen += wh; 
	/* increment buffer + offset pointers */
	pl += wh; buf += wh; bptr += wh;
	/*
	 * remaining packet length to parse, when zero the packet
	 * parsing process is complete
	 */
	pi->rl -= wh;
	if (pi->rl == 0) 
	    return pi->hdrlen + sizeof(struct _como_wlan_mgmt_body);
	ie = (struct _ieee80211_info_element *)buf;
    }
    return pi->hdrlen + sizeof(struct _como_wlan_mgmt_body);
}


/*
 * update_parse_params
 */

void
update_parse_params(pkt_t *pkt, struct _p80211info *pi, int len)
{
    pkt->caplen += len;
    /*
     * store fixed fields length to structure
     */
    pi->n = len;
    /*
     * remaining packet length to parse, when zero the packet
     * parsing process is complete
     */
    pi->rl -= len;
}

