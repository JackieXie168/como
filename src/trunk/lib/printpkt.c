/*
 * Copyright (c) 2006, Intel Corporation
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

#include <sys/types.h>
#include <string.h>		/* bcopy */
#include <stdio.h>		/* fprintf, stderr */

#include "stdpkt.h"
#include "pcap.h"
#include "como.h"
#include "printpkt.h"

static const char *mgmt_subtypes[] = {
    "Association Request",
    "Association Response",
    "Reassociation Request",
    "Reassociation Response",
    "Probe Request",
    "Probe Response",
    "Reserved",
    "Reserved",
    "Beacon",
    "Atim",
    "Disassociation",
    "Authentication",
    "Deauthentication",
    "Reserved",
    "Reserved"
};

static const char *rc_text[] = {
    "Reserved",
    "Unspecified reason",
    "Previous authentication no longer valid",
    "Deauthenticated because sending STA is leaving (or has left) IBSS or ESS",
    "Disassociated due to inactivity",
    "Disassociated because AP is unable to handle all currently \
							    associated STAs",
    "Class 2 frame received from nonauthenticated STA",
    "Class 3 frame received from nonassociated STA",
    "Disassociated because sending STA is leaving (or has left) BSS",
    "STA requesting (re)association is not authenticated with responding STA"
};

static const char *sc_text[] = {
    "Successful",
    "Unspecified failure",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Cannot support all requested capabilities in the capability information \
									field",
    "Reassociation denied due to inability to confirm that association exists",
    "Association denied due to reason outside the scope of this standard",
    "Responding station does not support the specified authenticatoin \
								    algorithm",
    "Received an authentication frame with authentication transaction \
				    sequence number out of expected sequence",
    "Authentication rejected because of challenge failure",
    "Authentication rejected due to timeout waiting for next frame in sequence",
    "Association denied because AP is unable to handle additional associated \
								     stations",
    "Association denied due to requesting station not supporting all of the \
				data rates in the BSSBasicRateSet parameter"
};

#define RC_RESERVED_VALUES 10 /* 10 - 65535 */
#define SC_RESERVED_VALUES 19 /* 19 - 65535 */
#define MAC_ADDR_SIZE 6

/*
 * utility function used to pretty print tcp's control bits status
 */
static char*
print_tcp_flags(pkt_t *pkt) 
{
    static char s[7];
    size_t i;
    
    i = 0; 
    s[i] = '.'; 

    if (TCP(fin)) 
	s[i++] = 'F';

    if (TCP(syn)) 
	s[i++] = 'S';
	
    if (TCP(rst)) 
	s[i++] = 'R';
  	
    if (TCP(psh)) 
	s[i++] = 'P';

    if (TCP(ack)) 
	s[i++] = 'A';
  	
    if (TCP(urg)) 
	s[i++] = 'U';
  	
    if (TCP(ece)) 
	s[i++] = 'E';
  	
    if (TCP(cwr)) 
	s[i++] = 'C';
  	
    s[i] = '\0';
    return s;
}

/*
 * print_pkt_pretty
 *
 * pretty-prints a packet. Assumes that the input buffer will be
 * big enough. Returns the length of the string.
 */

int
print_pkt_pretty(pkt_t *pkt, char *str, int print_l2, int print_l3)
{
    int hh, mm, ss; 
    uint32_t addr; 
    int i, len;
    char ssid[34];
    
    len = 0;

    /* print timestamp (hh:mm:ss.us) */
    hh = (TS2SEC(COMO(ts)) % 86400) /3600; 
    mm = (TS2SEC(COMO(ts)) % 3600) / 60; 
    ss = TS2SEC(COMO(ts)) % 60; 
    len = sprintf(str, "%02d:%02d:%02d.%06u ",
		   hh, mm, ss, (uint) TS2USEC(COMO(ts))); 

    if (print_l2 == 0 )
        goto l2done;

    if (isETH) {
        /* TODO */
    } else if (isHDLC) {
        /* TODO */
    } else if (isVLAN) {
        /* TODO */
    } else if (isISL) {
        /* TODO */
    } else if (is80211) {
        switch (IEEE80211_BASE(fc_type)) {

            case IEEE80211TYPE_MGMT:
                snprintf(ssid, MGMT_BODY(ssid_len) + 1, MGMT_BODY(ssid));
                len += sprintf(str + len, "%s ",
                        mgmt_subtypes[IEEE80211_BASE(fc_subtype)]);
                switch (IEEE80211_BASE(fc_subtype)) {
                    case MGMT_SUBTYPE_BEACON:
                    case MGMT_SUBTYPE_PROBE_RES:
                        len += sprintf(str + len, "%s %s", ssid,"[");
                        for (i = 0; i < MGMT_BODY(rates_len); i++) {
                            len += sprintf(str + len, "%2.1f%s ",
                                    (0.5 * (MGMT_BODY(rates[i]) & 0x7f)), 
                                    (MGMT_BODY(rates[i]) & 0x80 ? "*" : "" ));
                        }
                        len += sprintf(str + len, "Mbit] ch: %d %s %s",
                                MGMT_BODY(ch),
                                CAPINFO_ESS(H16(MGMT_BODY(cap))) ? "ESS" :
                                "IBSS",
                                CAPINFO_PRIVACY(H16(MGMT_BODY(cap))) ? "PRIVACY"
                                : "");
                        break;
                    case MGMT_SUBTYPE_DISASSOC:
                    case MGMT_SUBTYPE_DEAUTH:
                        /* CHECKME: was using ntohs around rc */
                        len += sprintf(str + len, "%s", H16(MGMT_BODY(rc)) <
                                RC_RESERVED_VALUES ? rc_text[H16(MGMT_BODY(rc))]
                                : "RESERVED");
                        break;
                    case MGMT_SUBTYPE_ASSOC_REQ:
                    case MGMT_SUBTYPE_PROBE_REQ:
                        len += sprintf(str + len, "%s [", ssid);
                        for (i = 0; i < MGMT_BODY(rates_len); i++) {
                            len += sprintf(str + len, "%2.1f%s ",
                                    (0.5 * (MGMT_BODY(rates[i]) & 0x7f)),
                                    (MGMT_BODY(rates[i]) & 0x80 ? "*" : "" ));
                        }  
                        len += sprintf(str + len, "Mbit]");
                        break;
                    case MGMT_SUBTYPE_ASSOC_RES:
                    case MGMT_SUBTYPE_REASSOC_RES:
                        len += sprintf(str + len, "AID(%x) %s %s",
                                H16(MGMT_BODY(aid)),
                                CAPINFO_PRIVACY(H16(MGMT_BODY(cap))) ? "PRIVACY"
                                : "",
                                H16(MGMT_BODY(sc)) <
                                SC_RESERVED_VALUES ? sc_text[H16(MGMT_BODY(sc))]
                                : "RESERVED");
                        break;
                    case MGMT_SUBTYPE_REASSOC_REQ:
                        len += sprintf(str + len, "%s %s", ssid, "AP:");
                        for (i = 0; i < MAC_ADDR_SIZE; i++)
                            len += sprintf(str + len, "%02x%s", 
                                    MGMT_BODY(ap_addr[i]), 
                                    i < (MAC_ADDR_SIZE-1) ? ":": ""); 
                        break;
                    case MGMT_SUBTYPE_AUTH:
                        break;
                    default:
                        break;
                }	
                break;
            case IEEE80211TYPE_CTRL:
                switch (IEEE80211_BASE(fc_subtype)) {
                    case CTRL_SUBTYPE_PS_POLL:
                        len += sprintf(str + len, "Power Save-Poll AID(%02x)", 
                                H16(MGMT_BODY(aid)));
                        break;
                    case CTRL_SUBTYPE_RTS:
                        len += sprintf(str + len, "Request-To-Send TA:"); 
                        for (i = 0; i < MAC_ADDR_SIZE; i++)
                            len += sprintf(str + len, "%02x%s", 
                                    CTRL_RTS(ta[i]), 
                                    i < (MAC_ADDR_SIZE-1) ? ":": ""); 
                        break;
                    case CTRL_SUBTYPE_CTS:
                        len += sprintf(str + len, "Clear-To-Send RA:"); 
                        for (i = 0; i < MAC_ADDR_SIZE; i++)
                            len += sprintf(str + len, "%02x%s", 
                                    CTRL_CTS(ra[i]), 
                                    i < (MAC_ADDR_SIZE-1) ? ":": ""); 
                        break;
                    case CTRL_SUBTYPE_ACK:
                        len += sprintf(str + len, "Acknowledgment RA:"); 
                        for (i = 0; i < MAC_ADDR_SIZE; i++)
                            len += sprintf(str + len, "%02x%s", 
                                    CTRL_ACK(ra[i]), 
                                    i < (MAC_ADDR_SIZE-1) ? ":": ""); 
                        break;
                    case CTRL_SUBTYPE_CF_END:
                        len += sprintf(str + len, "CF-End RA:"); 
                        for (i = 0; i < MAC_ADDR_SIZE; i++)
                            len += sprintf(str + len, "%02x%s", 
                                    CTRL_END(ra[i]), 
                                    i < (MAC_ADDR_SIZE-1) ? ":" : ""); 
                        break;
                    case CTRL_SUBTYPE_END_ACK:
                        len += sprintf(str + len, "CF-End + CF-Ack RA:"); 
                        for (i = 0; i < MAC_ADDR_SIZE; i++)
                            len += sprintf(str + len, "%02x%s", 
                                    CTRL_END_ACK(ra[i]), 
                                    i < (MAC_ADDR_SIZE-1) ? ":" : ""); 
                        break;
                    default:
                        break;
                }
                break;
            case IEEE80211TYPE_DATA:
                switch (IEEE80211_BASE(fc_subtype)) {
                    case DATA_SUBTYPE_DATA:
                        len += sprintf(str + len, "Data Type NOT Supported"); 
                        break;
                    case DATA_SUBTYPE_DATA_CFACK: 
                        len += sprintf(str + len, "Data + CF-Ack"); 
                        break;
                    case DATA_SUBTYPE_DATA_CFPL:   
                        len += sprintf(str + len, "Data + CF-Poll"); 
                        break;
                    case DATA_SUBTYPE_DATA_CFACKPL: 
                        len += sprintf(str + len, "Data + CF-Ack + CF-Poll"); 
                        break;
                    case DATA_SUBTYPE_NULL:    
                        len += sprintf(str + len, "Null Function (no data)"); 
                        break;
                    case DATA_SUBTYPE_CFACK:    
                        len += sprintf(str + len, "CF-Ack (no data)"); 
                        break;
                    case DATA_SUBTYPE_CFPL:       
                        len += sprintf(str + len, "CF-Poll (no data)"); 
                        break;
                    case DATA_SUBTYPE_CFACKPL:   
                        len += sprintf(str + len,"CF-Ack + CF-Poll (no data)");
                        break;
                    default:
                        break;
                }
                break;
            default:
                len += sprintf(str + len, "Print Not Supported");
                break;
        }
    }

l2done:
    if (! print_l3)
        goto l3done;
    /* 
     * depending on the l3 type we print different 
     * information 
     */
    if(isIP) {
        /* 
         * print IP header information 
         */
	len += 
	    sprintf(str + len, "IP | %s - ", getprotoname(IP(proto))); 
        len += 
	    sprintf(str + len, "tos 0x%x ttl %d id %d length: %d - ", 
		    IP(tos), IP(ttl), H16(IP(id)), H16(IP(len)));   

	/* 
         * print IP addresses and port numbers (if any) 
         */
        addr = N32(IP(src_ip)); 
	len += sprintf(str + len, inet_ntoa(*(struct in_addr*) &addr));
	if (IP(proto) == IPPROTO_TCP || IP(proto) == IPPROTO_UDP)  
	    len += sprintf(str + len, ":%d", H16(UDP(src_port))); 

	len += sprintf(str + len, " > "); 

        addr = N32(IP(dst_ip)); 
	len += sprintf(str + len,inet_ntoa(*(struct in_addr *) &addr));
	if (IP(proto) == IPPROTO_TCP || IP(proto) == IPPROTO_UDP)  
	    len += sprintf(str + len, ":%d", H16(UDP(dst_port))); 

        /* 
	 * print TCP specific information 
         */
	if (IP(proto) == IPPROTO_TCP) { 
	    len += sprintf(str + len, 
			" %s seq %u ack %u win %u", 
			print_tcp_flags(pkt), 
			(uint) H32(TCP(seq)), 
			(uint) H32(TCP(ack_seq)), 
		 	(uint16_t) H16(TCP(win))); 
	}
    }

l3done:; /* done */
    return len;
}


/* 
 * some constants and structures needed to 
 * generate a pcap trace file 
 */
#define TCPDUMP_MAGIC   0xa1b2c3d4

struct pcap_timeval {
    bpf_int32 tv_sec;           /* seconds */
    bpf_int32 tv_usec;          /* microseconds */
};

struct pcap_packet {
    struct pcap_timeval ts;     /* time stamp */
    bpf_u_int32 caplen;         /* length of portion present */
    bpf_u_int32 len;            /* length of this packet (off wire) */
    char payload[0];            /* packet payload */
};

/*
 * print_pcap_file_header
 *
 * Outputs a pcap file header into the output buffer,
 * which is assumed to be big enough to hold this data.
 * Returns the output length.
 */
int
print_pcap_file_header(char *output)
{
    struct pcap_file_header *fhdr;
    fhdr = (struct pcap_file_header *) output;
    fhdr->magic = TCPDUMP_MAGIC;
    fhdr->version_major = PCAP_VERSION_MAJOR;
    fhdr->version_minor = PCAP_VERSION_MINOR;
    fhdr->thiszone = 0;
    fhdr->snaplen = 65535;
    fhdr->sigfigs = 0;
    fhdr->linktype = 1;
    return sizeof(struct pcap_file_header);
}

/*
 * print_pkt_pcap
 *
 * Outputs a packet in pcap format into an output string.
 * Assumes output string is large enough to contain the
 * packet. Returns the output length.
 */
int
print_pkt_pcap(pkt_t *pkt, char *output)
{
    struct pcap_packet *x;

    x = (struct pcap_packet *) output; 
    x->ts.tv_sec = TS2SEC(COMO(ts)); 
    x->ts.tv_usec = TS2USEC(COMO(ts)); 
    x->len = COMO(len); 
    x->caplen = COMO(caplen); 
    memcpy(x->payload, pkt->payload, COMO(caplen)); 
    return COMO(caplen) + sizeof(struct pcap_packet); 
}

