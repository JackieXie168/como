#include <strings.h>

#include "como.h"
#include "comofunc.h"
#include "sniffers.h"
#include "stdwlan.h"


/*
 * PCAP header. It precedes every packet in the file.
 */
typedef struct {
    struct timeval ts;          /* time stamp */
    int caplen;                 /* length of portion present */
    int len;                    /* length this packet (on the wire) */
} pcap_hdr_t;


/*
 * -- parse_80211_frame
 *
 * this function determines the 802.11 header tpye and calls
 * another function to parse the wlan management frames
 *
 */

int

parse_80211_frame(pkt_t *pkt, char *buf, uint32_t type)
{
    int n;
    int hdrlen;
    struct _como_wlan_mgmt_body * mgmt_body;


    pcap_hdr_t * ph = (pcap_hdr_t *) buf;
    pkt->ts = TIME2TS(ph->ts.tv_sec, ph->ts.tv_usec);
    pkt->len = ph->len;
    pkt->caplen = ph->caplen;


    /*
     * not interested in pcap_hdr_t structure, so move buf pointer
     */
    buf += sizeof(pcap_hdr_t);

    switch(type) {
      case COMOTYPE_WLAN:
         hdrlen =  MGMT_HDR_LEN;
         break;
      case COMOTYPE_WLAN_PRISM:
         hdrlen = PRISM_HDR_LEN + MGMT_HDR_LEN;
         break;
      default:
         break;
    }
    bcopy(buf, pkt->payload, hdrlen);
    /*
     * update offset information for ieee 802.11 frames
     */
    updateofs(pkt, type);
    mgmt_body = (struct _como_wlan_mgmt_body *)(pkt->payload + hdrlen);


    if ((FC_TYPE(pkt->l3type) == WLANTYPE_MGMT)
                     && (FC_SUBTYPE(pkt->l3type) == MGMT_SUBTYPE_BEACON)){
      /*
       * parse the 802.11 frame and store the data to a structure
       * of fixed size
       */
      n = parse_80211_mgmt_frame(pkt, buf);
    }
    return n;
}


/*
 * -- parse_80211_mgmt_frame
 *  
 * this function parses an 802.11 frame and produces a data
 * structure that is of fixed size and that can be easily
 * accessed by modules.
 */


int
parse_80211_mgmt_frame(pkt_t *pkt, char * buf)
{
    
    int wh;
    int rlen;           /* remaining packet length */
    int bptr = 0;       /* buffer pointer */
 
    struct _como_wlan_mgmt_beacon *stype_bcn;
    struct _como_wlan_mgmt_body *mgmt_body;
    struct _como_wlan_info_element *ie;
   
    struct _como_wlan_ssid *ssid_type;
    struct _como_wlan_rates *rates_type;
    struct _como_wlan_ds *ds_type;
    struct _como_wlan_tim *tim_type;



    rlen = pkt->caplen; 
    wh = PRISM_HDR_LEN + MGMT_HDR_LEN; 
    bcopy(buf, pkt->payload, wh);

 
    pkt->caplen = wh; /* wh = 96 ???, Maybe 88 ??? */ 
    buf += wh;
    pkt->payload += wh;

    /* management body section: converge ieee802.11 structures to a como
     * defined structure.
     *
     */
    
    mgmt_body = (struct _como_wlan_mgmt_body *)pkt->payload; 
    stype_bcn = (struct _como_wlan_mgmt_beacon *) buf;
    
    /* beacon fixed fields */ 
    mgmt_body->timestamp = stype_bcn->ts;
    mgmt_body->beacon_ivl = stype_bcn->ivl;
    mgmt_body->cap = stype_bcn->cap;

    /* correct to hear !! */  
    wh = BEACON_SUBTYPE_LEN;
  /*  bcopy(buf, pkt->payload, wh);  ??? */
    pkt->caplen += wh; 
    buf += wh;
    pkt->payload += wh;

/* check this may be incorrect */


    ie = (struct _como_wlan_info_element *)stype_bcn->variable;
    rlen = rlen - PRISM_HDR_LEN - MGMT_HDR_LEN - BEACON_SUBTYPE_LEN;

    while(rlen >= ie->len + 2){

    switch(ie->id) {
      case SSID_TYPE:  
          ssid_type = (struct _como_wlan_ssid *)(stype_bcn->variable + bptr);
          mgmt_body->ssid.id = ssid_type->id;
          mgmt_body->ssid.len = ssid_type->len;
          bcopy(ssid_type->ssid, mgmt_body->ssid.ssid, mgmt_body->ssid.len);
 
          wh = ssid_type->len + 2;
          break;

      case RATES_TYPE: 
          rates_type = (struct _como_wlan_rates *) 
                                        (stype_bcn->variable + bptr);
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
          ds_type = (struct _como_wlan_ds *) 
                                   (stype_bcn->variable + bptr);
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
          tim_type = (struct _como_wlan_tim *)(stype_bcn->variable + bptr);
          wh = tim_type->len + 2;
          break;
      default: 
          /* reserved information elements ignored */
          ie = (struct _como_wlan_info_element *)(stype_bcn->variable + bptr);
          wh = ie->len + 2; /* fixed fields: element id + length field */
          break;          
      }

      pkt->caplen += wh; 
      buf += wh;
      pkt->payload += wh;
      bptr += wh;
   
      rlen -= wh;
      ie = (struct _como_wlan_info_element *)(stype_bcn->variable + bptr);
    }

    return bptr + PRISM_HDR_LEN + MGMT_HDR_LEN + BEACON_SUBTYPE_LEN;
}



#if 0
static void
pmgmtframe(pkt_t *pkt, char *buf)
{
 
    switch(FC_SUBTYPE(COMO(l3type))) {
       case MGMT_SUBTYPE_ASSOC_REQ:
           break;
       case MGMT_SUBTYPE_ASSOC_RES:
           break;
       case MGMT_SUBTYPE_REASSOC_REQ:
           break;
       case MGMT_SUBTYPE_REASSOC_RES:
           break;
       case MGMT_SUBTYPE_PROBE_REQ:
           break;
       case MGMT_SUBTYPE_PROBE_RES:
           break;
       case MGMT_SUBTYPE_BEACON:
           break;
       case MGMT_SUBTYPE_ATIM:
           break;
       case MGMT_SUBTYPE_DISASSOC:
           break;
       case MGMT_SUBTYPE_AUTH:
           break;
       case MGMT_SUBTYPE_DEAUTH:
           break;
        default:
           fprintf(stderr, 
                      "*** ieee 802.11 management subtype not supported ***");
           break;
    }
}
    
static void 
pctrlframe(pkt_t *pkt, char *buf)
{

    switch(FC_SUBTYPE(COMO(l3type))) {
       case CTRL_SUBTYPE_PS_POLL:
           break;
       case CTRL_SUBTYPE_RTS:
           break;
       case CTRL_SUBTYPE_CTS:
           break;
       case CTRL_SUBTYPE_ACK:
           break;
       case CTRL_SUBTYPE_CF_END:
           break;
       case CTRL_SUBTYPE_END_ACK:
           break;
       default:
           fprintf(stderr,
                      "*** ieee 802.11 control subtype not supported***");
           break;
    }
}

static void
pdataframe(pkt_t *pkt, char *buf)
{
    switch(FC_SUBTYPE(COMO(l3type))) {
       case DATA_SUBTYPE_DATA:
           break;
       case DATA_SUBTYPE_DATA_CFACK:
           break;
 static void
pdataframe(pkt_t *pkt, char *buf)
{
    switch(FC_SUBTYPE(COMO(l3type))) {
       case DATA_SUBTYPE_DATA:
           break;
       case DATA_SUBTYPE_DATA_CFACK:
           break;
      case DATA_SUBTYPE_DATA_CFPL:
           break;
       case DATA_SUBTYPE_DATA_CFACKPL:
           break;
       case DATA_SUBTYPE_NULL:
           break;
       case DATA_SUBTYPE_CFACK:
           break;
       case DATA_SUBTYPE_CFPL:
           break;
       case DATA_SUBTYPE_CFACKPL:
           break;
       default:
           fprintf(stderr,
                      "*** ieee 802.11 data subtype not supported***");
        break;
    }
}
#endif


#if 0
    switch(FC_TYPE(COMO(l3type))) {
       case WLANTYPE_MGMT:
           pmgmtframe(pkt,buf);
           break;
       case WLANTYPE_CTRL:
           pctrlframe(pkt, buf);
           break;
       case WLANTYPE_DATA:
           pdataframe(pkt, buf);
           break;
       default:
           fprintf(stderr, "*** ieee 802.11 frame type not supported ***");
           break;
    }


    /*
     * copy the packet payload
     */
}

#endif 

