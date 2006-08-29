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

/*
 * Packet trace Module
 *
 * This module collects a packet level trace.
 * The packet is dumped as it is layed out in pkt_t. 
 *
 * The hash table has only one entry in order to preserve arrival order.
 *
 */

#include <sys/types.h>
#include <string.h>		/* bcopy */
#include <stdio.h>		/* fprintf, stderr */

#include "module.h"
#include "stdpkt.h"		/* ethernet headers, etc. */
#include "pcap.h"		/* bpf_int32, etc. */

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
 * FLOWDESC just contains one packet. 
 * We will always match the record in the table so that CAPTURE will 
 * create a nice queue of packets for us and EXPORT will process it in 
 * FIFO order. 
 */
#define FLOWDESC	struct _trace

FLOWDESC {
    int len; 
#define BUFSIZE	2048
    char buf[BUFSIZE];
};
#define SNAPLEN_MAX	(BUFSIZE - sizeof(pkt_t))


#define CONFIGDESC   struct _trace_config
CONFIGDESC {
    unsigned snaplen; 		/* bytes to capture in each packet */ 
    int fmt; 
};

static timestamp_t 
init(void * self, char * args[])
{
    CONFIGDESC *config;
    int i; 
    pkt_t *pkt;
    metadesc_t *inmd, *outmd;

    config = mem_mdl_malloc(self, sizeof(CONFIGDESC));
    config->snaplen = SNAPLEN_MAX;

    for (i = 0; args && args[i]; i++) {
	if (strstr(args[i], "snaplen=")) { 
	    char * len = index(args[i], '=') + 1; 
	    config->snaplen = atoi(len); 	    /* set the snaplen */
	    if (config->snaplen > SNAPLEN_MAX) {
		config->snaplen = SNAPLEN_MAX;
	    }
	} 
    }
    
    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = TIME2TS(1, 0);
    
    pkt = metadesc_tpl_add(inmd, "none:none:none:none");
    
    /* setup outdesc */
    outmd = metadesc_define_out(self, 0);
    
    pkt = metadesc_tpl_add(outmd, "any:any:any:any");
    COMO(caplen) = config->snaplen;

    CONFIG(self) = config; 
    return TIME2TS(1,0); 
}

static int
update(void * self, pkt_t *pkt, void *fh, __unused int isnew)
{
    CONFIGDESC * config = CONFIG(self); 
    FLOWDESC *x = F(fh);
    int len; 

    len = (COMO(caplen) > config->snaplen) ? config->snaplen : COMO(caplen);
    memcpy(x->buf, pkt, sizeof(pkt_t)); 
    ((pkt_t *) x->buf)->payload = NULL;
    ((pkt_t *) x->buf)->caplen = len;
    memcpy(x->buf + sizeof(pkt_t), COMO(payload), len);

    return 1;		/* records are always full */
}


static ssize_t
store(__unused void * self, void *fh, char *buf)
{
    FLOWDESC *x = F(fh);
    pkt_t * pkt; 
    size_t need;
    
    pkt = (pkt_t *) x->buf; 
    need = COMO(caplen) + sizeof(pkt_t);

    /* convert the CoMo header in network byte order */
#ifdef BUILD_FOR_ARM
    COMOX(ts, HTONLL(COMO(ts))); 
    COMOX(len, htonl(COMO(len))); 
    COMOX(caplen, htonl(COMO(caplen))); 
    COMOX(type, htons(COMO(type)));
    COMOX(dropped, htons(COMO(dropped)));
    COMOX(l2type, htons(COMO(l2type))); 
    COMOX(l3type, htons(COMO(l3type))); 
    COMOX(l4type, htons(COMO(l4type))); 
    COMOX(l2ofs, htons(COMO(l2ofs))); 
    COMOX(l3ofs, htons(COMO(l3ofs))); 
    COMOX(l4ofs, htons(COMO(l4ofs)));
#else
    COMO(ts) = HTONLL(COMO(ts)); 
    COMO(len) = htonl(COMO(len)); 
    COMO(caplen) = htonl(COMO(caplen)); 
    COMO(type) = htons(COMO(type));
    COMO(dropped) = htons(COMO(dropped));
    COMO(l2type) = htons(COMO(l2type)); 
    COMO(l3type) = htons(COMO(l3type)); 
    COMO(l4type) = htons(COMO(l4type)); 
    COMO(l2ofs) = htons(COMO(l2ofs)); 
    COMO(l3ofs) = htons(COMO(l3ofs)); 
    COMO(l4ofs) = htons(COMO(l4ofs)); 
#endif

    memcpy(buf, pkt, need); 
    return need; 
}


static size_t
load(__unused void * self, char * buf, size_t len, timestamp_t * ts)
{
    pkt_t * pkt; 

    if (len < sizeof(pkt_t)) {
        *ts = 0;
        return 0;
    }

    pkt = (pkt_t *) buf; 
    *ts = NTOHLL(COMO(ts));
    return (sizeof(pkt_t) + ntohl(COMO(caplen))); 
}



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
    char payload[0]; 		/* packet payload */
};


#define PRETTYFMT 		0
#define PCAPFMT			1


static char *
print(void * self, char *buf, size_t *len, char * const args[])
{
    CONFIGDESC * config = CONFIG(self); 
    static char str[65536];
    struct pcap_file_header * fhdr; 
    struct pcap_packet * x; 
    pkt_t p, pktbuf, *pkt; 
    int hh, mm, ss; 
    uint32_t addr; 
    int n; 
    int i;
    char ssid[34];

    if (buf == NULL && args != NULL) { 
	/* first call, process the arguments */
        for (n = 0; args[n]; n++) {
            if (!strcmp(args[n], "format=pcap")) {
		fhdr = (struct pcap_file_header *) str; 
		fhdr->magic = TCPDUMP_MAGIC;
		fhdr->version_major = PCAP_VERSION_MAJOR;
		fhdr->version_minor = PCAP_VERSION_MINOR;
		fhdr->thiszone = 0; 
		fhdr->snaplen = 65535; 		
		fhdr->sigfigs = 0; 
		fhdr->linktype = 1;
   
		*len = sizeof(struct pcap_file_header);
                config->fmt = PCAPFMT;
		return str; 
	    }
	}
        *len = 0;
	config->fmt = PRETTYFMT;
	return str;
    } 

    if (buf == NULL && args == NULL) { 
	/* last call, nothing to do */
        *len = 0; 
        return str; 
    } 

    /* copy the packet CoMo header, converting 
     * the fields in host-byte order 
     */
    bcopy(buf, &pktbuf, sizeof(pkt_t));
    pkt = &pktbuf;
    p.ts = NTOHLL(COMO(ts)); 
    p.len = ntohl(COMO(len)); 
    p.caplen = ntohl(COMO(caplen)); 
    p.type = ntohl(COMO(type));
    p.l2type = ntohs(COMO(l2type)); 
    p.l3type = ntohs(COMO(l3type)); 
    p.l4type = ntohs(COMO(l4type));
    p.l2ofs = ntohs(COMO(l2ofs)); 
    p.l3ofs = ntohs(COMO(l3ofs)); 
    p.l4ofs = ntohs(COMO(l4ofs)); 
    p.payload = buf + sizeof(pkt_t);

    /* now we are ready to process this packet */
    pkt = (pkt_t *) &p; 

    if (config->fmt == PCAPFMT) { 
        x = (struct pcap_packet *) str; 
	x->ts.tv_sec = TS2SEC(COMO(ts)); 
	x->ts.tv_usec = TS2USEC(COMO(ts)); 
	x->len = COMO(len); 
	x->caplen = COMO(caplen); 
	memcpy(x->payload, pkt->payload, COMO(caplen)); 
        *len = COMO(caplen) + sizeof(struct pcap_packet); 
	return str; 
    } 
	
    /* 
     * if not PCAP, the format is PRETTYFMT... 
     */
    
    /* print timestamp (hh:mm:ss.us) */
    hh = (TS2SEC(COMO(ts)) % 86400) /3600; 
    mm = (TS2SEC(COMO(ts)) % 3600) / 60; 
    ss = TS2SEC(COMO(ts)) % 60; 
    *len = sprintf(str, "%02d:%02d:%02d.%06u ",
		   hh, mm, ss, (uint) TS2USEC(COMO(ts))); 

    /* 
     * depending on the l3 type we print different 
     * information 
     */
    if(COMO(l3type) == ETHERTYPE_IP) { 
        /* 
         * print IP header information 
         */
	*len += 
	    sprintf(str + *len, "IP | %s - ", getprotoname(IP(proto))); 
        *len += 
	    sprintf(str + *len, "tos 0x%x ttl %d id %d length: %d - ", 
		    IP(tos), IP(ttl), H16(IP(id)), H16(IP(len)));   

	/* 
         * print IP addresses and port numbers (if any) 
         */
        addr = N32(IP(src_ip)); 
	*len += sprintf(str + *len, inet_ntoa(*(struct in_addr*) &addr));
	if (IP(proto) == IPPROTO_TCP || IP(proto) == IPPROTO_UDP)  
	    *len += sprintf(str + *len, ":%d", H16(UDP(src_port))); 

	*len += sprintf(str + *len, " > "); 

        addr = N32(IP(dst_ip)); 
	*len += sprintf(str + *len,inet_ntoa(*(struct in_addr *) &addr));
	if (IP(proto) == IPPROTO_TCP || IP(proto) == IPPROTO_UDP)  
	    *len += sprintf(str + *len, ":%d", H16(UDP(dst_port))); 

        /* 
	 * print TCP specific information 
         */
	if (IP(proto) == IPPROTO_TCP) { 
	    *len += sprintf(str + *len, 
			" %s seq %u ack %u win %u", 
			print_tcp_flags(pkt), 
			(uint) H32(TCP(seq)), 
			(uint) H32(TCP(ack_seq)), 
		 	(uint16_t) H16(TCP(win))); 
	}
    } else if (COMO(l2type) == LINKTYPE_80211) {
	switch (IEEE80211_BASE(fc_type)) {

	case IEEE80211TYPE_MGMT:
            snprintf(ssid, MGMT_BODY(ssid_len) + 1, MGMT_BODY(ssid));
	    *len += sprintf(str + *len, "%s ",
			    mgmt_subtypes[IEEE80211_BASE(fc_subtype)]);
	    switch (IEEE80211_BASE(fc_subtype)) {
	    case MGMT_SUBTYPE_BEACON:
	    case MGMT_SUBTYPE_PROBE_RES:
                *len += sprintf(str + *len, "%s %s", ssid,"[");
                for (i = 0; i < MGMT_BODY(rates_len); i++) {
                    *len += sprintf(str + *len, "%2.1f%s ",
                        (0.5 * (MGMT_BODY(rates[i]) & 0x7f)), 
                        (MGMT_BODY(rates[i]) & 0x80 ? "*" : "" ));
                }
		*len += sprintf(str + *len, "Mbit] ch: %d %s %s",
				MGMT_BODY(ch),
				CAPINFO_ESS(H16(MGMT_BODY(cap))) ? "ESS" :
				"IBSS",
				CAPINFO_PRIVACY(H16(MGMT_BODY(cap))) ? "PRIVACY"
				: "");
		break;
	    case MGMT_SUBTYPE_DISASSOC:
	    case MGMT_SUBTYPE_DEAUTH:
		/* CHECKME: was using ntohs around rc */
		*len += sprintf(str + *len, "%s", H16(MGMT_BODY(rc)) <
				RC_RESERVED_VALUES ? rc_text[H16(MGMT_BODY(rc))]
				: "RESERVED");
		break;
	    case MGMT_SUBTYPE_ASSOC_REQ:
	    case MGMT_SUBTYPE_PROBE_REQ:
                *len += sprintf(str + *len, "%s [", ssid);
                for (i = 0; i < MGMT_BODY(rates_len); i++) {
                    *len += sprintf(str + *len, "%2.1f%s ",
                        (0.5 * (MGMT_BODY(rates[i]) & 0x7f)),
                        (MGMT_BODY(rates[i]) & 0x80 ? "*" : "" ));
                }  
                *len += sprintf(str + *len, "Mbit]");
		break;
	    case MGMT_SUBTYPE_ASSOC_RES:
	    case MGMT_SUBTYPE_REASSOC_RES:
		*len += sprintf(str + *len, "AID(%x) %s %s",
				H16(MGMT_BODY(aid)),
				CAPINFO_PRIVACY(H16(MGMT_BODY(cap))) ? "PRIVACY"
				: "",
				H16(MGMT_BODY(sc)) <
				SC_RESERVED_VALUES ? sc_text[H16(MGMT_BODY(sc))]
				: "RESERVED");
		break;
	    case MGMT_SUBTYPE_REASSOC_REQ:
		*len += sprintf(str + *len, "%s %s", ssid, "AP:");
		for (i = 0; i < MAC_ADDR_SIZE; i++)
		    *len += sprintf(str + *len, "%02x%s", 
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
		*len += sprintf(str + *len, "Power Save-Poll AID(%02x)", 
				H16(MGMT_BODY(aid)));
		break;
	    case CTRL_SUBTYPE_RTS:
		*len += sprintf(str + *len, "Request-To-Send TA:"); 
		for (i = 0; i < MAC_ADDR_SIZE; i++)
		    *len += sprintf(str + *len, "%02x%s", 
				CTRL_RTS(ta[i]), 
				i < (MAC_ADDR_SIZE-1) ? ":": ""); 
		break;
	    case CTRL_SUBTYPE_CTS:
		*len += sprintf(str + *len, "Clear-To-Send RA:"); 
		for (i = 0; i < MAC_ADDR_SIZE; i++)
		    *len += sprintf(str + *len, "%02x%s", 
				CTRL_CTS(ra[i]), 
				i < (MAC_ADDR_SIZE-1) ? ":": ""); 
		break;
	    case CTRL_SUBTYPE_ACK:
		*len += sprintf(str + *len, "Acknowledgment RA:"); 
		for (i = 0; i < MAC_ADDR_SIZE; i++)
		    *len += sprintf(str + *len, "%02x%s", 
				CTRL_ACK(ra[i]), 
				i < (MAC_ADDR_SIZE-1) ? ":": ""); 
		break;
	    case CTRL_SUBTYPE_CF_END:
		*len += sprintf(str + *len, "CF-End RA:"); 
		for (i = 0; i < MAC_ADDR_SIZE; i++)
		    *len += sprintf(str + *len, "%02x%s", 
				CTRL_END(ra[i]), 
				i < (MAC_ADDR_SIZE-1) ? ":" : ""); 
		break;
	    case CTRL_SUBTYPE_END_ACK:
		*len += sprintf(str + *len, "CF-End + CF-Ack RA:"); 
		for (i = 0; i < MAC_ADDR_SIZE; i++)
		    *len += sprintf(str + *len, "%02x%s", 
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
		*len += sprintf(str + *len, "Data Type NOT Supported"); 
		break;
	    case DATA_SUBTYPE_DATA_CFACK: 
		*len += sprintf(str + *len, "Data + CF-Ack"); 
		break;
	    case DATA_SUBTYPE_DATA_CFPL:   
		*len += sprintf(str + *len, "Data + CF-Poll"); 
		break;
	    case DATA_SUBTYPE_DATA_CFACKPL: 
		*len += sprintf(str + *len, "Data + CF-Ack + CF-Poll"); 
	       break;
	    case DATA_SUBTYPE_NULL:    
		*len += sprintf(str + *len, "Null Function (no data)"); 
		break;
	    case DATA_SUBTYPE_CFACK:    
		*len += sprintf(str + *len, "CF-Ack (no data)"); 
		break;
	    case DATA_SUBTYPE_CFPL:       
		*len += sprintf(str + *len, "CF-Poll (no data)"); 
		break;
	    case DATA_SUBTYPE_CFACKPL:   
		*len += sprintf(str + *len,"CF-Ack + CF-Poll (no data)");
		break;
            default:
		break;
	    }
            break;
	default:
	    *len += sprintf(str + *len, "Print Not Supported");
	    break;
	}
    } else
	*len += sprintf(str + *len, "Print Not Supported");
    *len += sprintf(str + *len, "\n");
    return str; 
}

static int  
replay(__unused void * self, char *buf, char *out, size_t * len, 
       __unused int left)
{
    pkt_t * pkt; 
    size_t need; 

    if (buf == NULL) {
	/* this module does not buffer any records */
	*len = 0;
	return 0;
    }

    pkt = (pkt_t *) buf; 
    need = ntohl(COMO(caplen)) + sizeof(pkt_t);
    if (*len < need) 
	return -1; 

    bcopy(buf, out, need); 
    pkt = (pkt_t *) out;

    /* Convert the header data into host byte order */
#ifdef BUILD_FOR_ARM
    COMOX(ts, NTOHLL(COMO(ts))); 
    COMOX(len, ntohl(COMO(len))); 
    COMOX(caplen, ntohl(COMO(caplen))); 
    COMOX(type, ntohs(COMO(type)));
    COMOX(dropped, ntohs(COMO(dropped)));
    COMOX(l2type, ntohs(COMO(l2type))); 
    COMOX(l3type, ntohs(COMO(l3type))); 
    COMOX(l4type, ntohs(COMO(l4type))); 
    COMOX(l2ofs, ntohs(COMO(l2ofs))); 
    COMOX(l3ofs, ntohs(COMO(l3ofs))); 
    COMOX(l4ofs, ntohs(COMO(l4ofs))); 
    COMOX(l7ofs, ntohs(COMO(l7ofs))); 
#else
    COMO(ts) = NTOHLL(COMO(ts)); 
    COMO(len) = ntohl(COMO(len)); 
    COMO(caplen) = ntohl(COMO(caplen)); 
    COMO(type) = ntohs(COMO(type));
    COMO(dropped) = ntohs(COMO(dropped));
    COMO(l2type) = ntohs(COMO(l2type)); 
    COMO(l3type) = ntohs(COMO(l3type)); 
    COMO(l4type) = ntohs(COMO(l4type)); 
    COMO(l2ofs) = ntohs(COMO(l2ofs)); 
    COMO(l3ofs) = ntohs(COMO(l3ofs)); 
    COMO(l4ofs) = ntohs(COMO(l4ofs)); 
    COMO(l7ofs) = ntohs(COMO(l7ofs)); 
#endif

    COMO(payload) = out + sizeof(pkt_t);
    *len = need;
    return 0;	
}


MODULE(trace) = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0, 
    st_recordsize: sizeof(FLOWDESC),
    capabilities: {has_flexible_flush: 1, 0},
    init: init,
    check: NULL,
    hash: NULL,
    match: NULL,
    update: update,
    flush: NULL, 
    ematch: NULL,
    export: NULL,
    compare: NULL,
    action: NULL,
    store: store,
    load: load,
    print: print,
    replay: replay,
    formats: "pretty pcap"
};
