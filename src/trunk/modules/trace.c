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
    char buf[2048]; 
};


/*
 * bytes to capture in each packet. this includes layer2 header 
 * but does not include the CoMo header.  
 */
static unsigned snaplen = 65535;

/* 
 * description of the output trace for sniffer-como
 */
static pktdesc_t outdesc;


static timestamp_t 
init(__unused void *mem, __unused size_t msize, char * args[])
{
    int i; 

    for (i = 0; args && args[i]; i++) {
	if (strstr(args[i], "snaplen=")) { 
	    char * len = index(args[i], '=') + 1; 
	    snaplen = atoi(len); 		/* set the snaplen */
	} 
    }

    memset(&outdesc, 0xff, sizeof(pktdesc_t));
    outdesc.caplen = snaplen; 
    return TIME2TS(1,0); 
}


static int
update(pkt_t *pkt, void *fh, __unused int isnew)
{
    FLOWDESC *x = F(fh);
    int len; 

    len = (COMO(caplen) > snaplen) ? snaplen : COMO(caplen);
    memcpy(x->buf, pkt, sizeof(pkt_t)); 
    ((pkt_t *) x->buf)->payload = NULL;
    ((pkt_t *) x->buf)->caplen = len;
    memcpy(x->buf + sizeof(pkt_t), COMO(payload), len);

    return 1;		/* records are always full */
}


static ssize_t
store(void *fh, char *buf, size_t len)
{
    FLOWDESC *x = F(fh);
    pkt_t * pkt; 
    size_t need;
    
    pkt = (pkt_t *) x->buf; 
    need = COMO(caplen) + sizeof(pkt_t);

    if (len < need)
        return -1;

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
load(char * buf, size_t len, timestamp_t * ts)
{
    pkt_t * pkt; 

    if (len < sizeof(pkt_t)) {
        ts = 0;
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
print_tcp_flags(uint8_t flags) 
{
    static char s[7];
    size_t i;
    
    i = 0; 
    s[i] = '.'; 

    if (flags & 0x01) 
	s[i++] = 'F';

    if (flags & 0x02) 
	s[i++] = 'S';
	
    if (flags & 0x04) 
	s[i++] = 'R';
  	
    if (flags & 0x08) 
	s[i++] = 'P';

    if (flags & 0x10) 
	s[i++] = 'A';
  	
    if (flags & 0x20) 
	s[i++] = 'U';
  	
    if (flags & 0x40) 
	s[i++] = 'E';
  	
    if (flags & 0x80) 
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
print(char *buf, size_t *len, char * const args[])
{
    static char s[65536]; 
    char payload[65536];
    static int fmt; 
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
		fhdr = (struct pcap_file_header *) s; 
		fhdr->magic = TCPDUMP_MAGIC;
		fhdr->version_major = PCAP_VERSION_MAJOR;
		fhdr->version_minor = PCAP_VERSION_MINOR;
		fhdr->thiszone = 0; 
		fhdr->snaplen = 65535; 		
		fhdr->sigfigs = 0; 
		fhdr->linktype = 1;
   
		*len = sizeof(struct pcap_file_header);
                fmt = PCAPFMT;
		return s; 
            }
       }
        *len = 0;
	fmt = PRETTYFMT;
	return s;
    } 

    if (buf == NULL && args == NULL) { 
	/* last call, nothing to do */
        *len = 0; 
        return s; 
    } 

    /* copy the packet CoMo header, converting 
     * the fields in host-byte order 
     */
    //pkt = (pkt_t *) buf; 
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
    bcopy(buf + sizeof(pkt_t), payload, p.caplen);
    p.payload = payload;

    /* now we are ready to process this packet */
    pkt = (pkt_t *) &p; 

    if (fmt == PCAPFMT) { 
        x = (struct pcap_packet *) s; 
	x->ts.tv_sec = TS2SEC(COMO(ts)); 
	x->ts.tv_usec = TS2USEC(COMO(ts)); 
	x->len = COMO(len); 
	x->caplen = COMO(caplen); 
	memcpy(x->payload, pkt->payload, COMO(caplen)); 
        *len = COMO(caplen) + sizeof(struct pcap_packet); 
	return s; 
    } 
	
    /* 
     * if not PCAP, the format is PRETTYFMT... 
     */
    
    /* print timestamp (hh:mm:ss.us) */
    hh = (TS2SEC(COMO(ts)) % 86400) /3600; 
    mm = (TS2SEC(COMO(ts)) % 3600) / 60; 
    ss = TS2SEC(COMO(ts)) % 60; 
    *len = sprintf(s, "%02d:%02d:%02d.%06u ",
		   hh, mm, ss, (uint) TS2USEC(COMO(ts))); 

    /* 
     * depending on the l3 type we print different 
     * information 
     */
    if(COMO(l3type) == ETHERTYPE_IP) { 
        /* 
         * print IP header information 
         */
	*len += sprintf(s + *len, "IP | %s - ", getprotoname(IP(proto))); 
        *len += sprintf(s + *len, "tos 0x%x ttl %d id %d length: %d - ", 
		   IP(tos), IP(ttl), H16(IP(id)), H16(IP(len)));   

	/* 
         * print IP addresses and port numbers (if any) 
         */
        addr = N32(IP(src_ip)); 
	*len += sprintf(s + *len, inet_ntoa(*(struct in_addr*) &addr)); 
	if (IP(proto) == IPPROTO_TCP || IP(proto) == IPPROTO_UDP)  
	    *len += sprintf(s + *len, ":%d", H16(UDP(src_port))); 

	*len += sprintf(s + *len, " > "); 

        addr = N32(IP(dst_ip)); 
	*len += sprintf(s + *len, inet_ntoa(*(struct in_addr *) &addr)); 
	if (IP(proto) == IPPROTO_TCP || IP(proto) == IPPROTO_UDP)  
	    *len += sprintf(s + *len, ":%d", H16(UDP(dst_port))); 

        /* 
	 * print TCP specific information 
         */
	if (IP(proto) == IPPROTO_TCP) { 
	    *len += sprintf(s + *len, 
			" %s seq %u ack %u win %u", 
			print_tcp_flags(TCP(flags)), 
			(uint) H32(TCP(seq)), 
			(uint) H32(TCP(ack)), 
		 	(uint16_t) H16(TCP(win))); 
	}
    } else if (COMO(l2type) == LINKTYPE_80211) {
	uint32_t fc = H16(IEEE80211_HDR(fc));

	switch (WLANTYPE(fc)) {

	case WLANTYPE_MGMT:
            snprintf(ssid, MGMT_BODY(ssid_len) + 1, MGMT_BODY(ssid));
	    *len += sprintf(s + *len, "%s ",
			    mgmt_subtypes[WLANSUBTYPE(fc) >> 12]);
	    switch (WLANSUBTYPE(fc)) {
	    case MGMT_SUBTYPE_BEACON:
	    case MGMT_SUBTYPE_PROBE_RES:
                *len += sprintf(s + *len, "%s %s", ssid,"[");
                for (i = 0; i < MGMT_BODY(rates_len); i++) {
                    *len += sprintf(s + *len, "%2.1f%s ",
                        (0.5 * (MGMT_BODY(rates[i]) & 0x7f)), 
                        (MGMT_BODY(rates[i]) & 0x80 ? "*" : "" ));
                }
		*len += sprintf(s + *len, "%s %s %d %s %s", "Mbit]", "ch:",
				MGMT_BODY(ch),
				CAPINFO_ESS(H16(MGMT_BODY(cap))) ? "ESS" :
				"IBSS",
				CAPINFO_PRIVACY(H16(MGMT_BODY(cap))) ? "PRIVACY"
				: "");
		break;
	    case MGMT_SUBTYPE_DISASSOC:
	    case MGMT_SUBTYPE_DEAUTH:
		/* CHECKME: was using ntohs around rc */
		*len += sprintf(s + *len, "%s", H16(MGMT_BODY(rc)) <
				RC_RESERVED_VALUES ? rc_text[H16(MGMT_BODY(rc))]
				: "RESERVED");
		break;
	    case MGMT_SUBTYPE_ASSOC_REQ:
	    case MGMT_SUBTYPE_PROBE_REQ:
                *len += sprintf(s + *len, "%s %s", ssid,"[");
                for (i = 0; i < MGMT_BODY(rates_len); i++) {
                    *len += sprintf(s + *len, "%2.1f%s ",
                        (0.5 * (MGMT_BODY(rates[i]) & 0x7f)),
                        (MGMT_BODY(rates[i]) & 0x80 ? "*" : "" ));
                }  
                *len += sprintf(s + *len, "%s", "Mbit]");
		break;
	    case MGMT_SUBTYPE_ASSOC_RES:
	    case MGMT_SUBTYPE_REASSOC_RES:
		*len += sprintf(s + *len, "AID(%x) %s %s",
				H16(MGMT_BODY(aid)),
				CAPINFO_PRIVACY(H16(MGMT_BODY(cap))) ? "PRIVACY"
				: "",
				H16(MGMT_BODY(sc)) <
				SC_RESERVED_VALUES ? sc_text[H16(MGMT_BODY(sc))]
				: "RESERVED");
		break;
	    case MGMT_SUBTYPE_REASSOC_REQ:
		*len += sprintf(s + *len, "%s %s", ssid, "AP:");
		for (i = 0; i < MAC_ADDR_SIZE; i++)
		    *len += sprintf(s + *len, "%02x%s", MGMT_BODY(ap_addr[i]), 
			i < (MAC_ADDR_SIZE-1) ? ":": ""); 
		break;
	    case MGMT_SUBTYPE_AUTH:
		break;
	    default:
		break;
	    }	
	    break;
	case WLANTYPE_CTRL:
	    switch (WLANSUBTYPE(fc)) {
	    case CTRL_SUBTYPE_PS_POLL:
		*len += sprintf(s + *len, "%s %s%02x%s", "Power Save-Poll",
				"AID(", H16(MGMT_BODY(aid)), ")");
		break;
	    case CTRL_SUBTYPE_RTS:
		*len += sprintf(s + *len, "%s %s", "Request-To-Send", "TA:"); 
		for (i = 0; i < MAC_ADDR_SIZE; i++)
		    *len += sprintf(s + *len, "%02x%s", CTRL_RTS(ta[i]), 
			i < (MAC_ADDR_SIZE-1) ? ":": ""); 
		break;
	    case CTRL_SUBTYPE_CTS:
		*len += sprintf(s + *len, "%s %s", "Clear-To-Send", "RA:"); 
		for (i = 0; i < MAC_ADDR_SIZE; i++)
		    *len += sprintf(s + *len, "%02x%s", CTRL_CTS(ra[i]), 
			i < (MAC_ADDR_SIZE-1) ? ":": ""); 
		break;
	    case CTRL_SUBTYPE_ACK:
		*len += sprintf(s + *len, "%s %s", "Acknowledgment", "RA:"); 
		for (i = 0; i < MAC_ADDR_SIZE; i++)
		    *len += sprintf(s + *len, "%02x%s", CTRL_ACK(ra[i]), 
			i < (MAC_ADDR_SIZE-1) ? ":": ""); 
		break;
	    case CTRL_SUBTYPE_CF_END:
		*len += sprintf(s + *len, "%s %s", "CF-End", "RA:"); 
		for (i = 0; i < MAC_ADDR_SIZE; i++)
		    *len += sprintf(s + *len, "%02x%s", CTRL_END(ra[i]), 
			i < (MAC_ADDR_SIZE-1) ? ":" : ""); 
		break;
	    case CTRL_SUBTYPE_END_ACK:
		*len += sprintf(s + *len, "%s %s", "CF-End + CF-Ack", "RA:"); 
		for (i = 0; i < MAC_ADDR_SIZE; i++)
		    *len += sprintf(s + *len, "%02x%s", CTRL_END_ACK(ra[i]), 
			i < (MAC_ADDR_SIZE-1) ? ":" : ""); 
	       break;
	    default:
	       break;
	    }
	    break;
	case WLANTYPE_DATA:
	    switch (WLANSUBTYPE(fc)) {
	    case DATA_SUBTYPE_DATA:
		*len += sprintf(s + *len, "%s", "Data Type NOT Supported"); 
		break;
	    case DATA_SUBTYPE_DATA_CFACK: 
		*len += sprintf(s + *len, "%s", "Data + CF-Ack"); 
		break;
	    case DATA_SUBTYPE_DATA_CFPL:   
		*len += sprintf(s + *len, "%s", "Data + CF-Poll"); 
		break;
	    case DATA_SUBTYPE_DATA_CFACKPL: 
		*len += sprintf(s + *len, "%s", "Data + CF-Ack + CF-Poll"); 
	       break;
	    case DATA_SUBTYPE_NULL:    
		*len += sprintf(s + *len, "%s", "Null Function (no data)"); 
		break;
	    case DATA_SUBTYPE_CFACK:    
		*len += sprintf(s + *len, "%s", "CF-Ack (no data)"); 
		break;
	    case DATA_SUBTYPE_CFPL:       
		*len += sprintf(s + *len, "%s", "CF-Poll (no data)"); 
		break;
	    case DATA_SUBTYPE_CFACKPL:   
		*len += sprintf(s + *len, "%s", "CF-Ack + CF-Poll (no data)"); 
		break;
            default:
		break;
	    }
            break;
	default:
	    *len += sprintf(s + *len, "%s",  "Print Not Supported");
	    break;
	}
    }
    else
	*len += sprintf(s + *len, "%s", "Print Not Supported");
    *len += sprintf(s + *len, "\n");
    return s; 
}

static int  
replay(char *buf, char *out, size_t * len, int *count)
{
    pkt_t * pkt = (pkt_t *) buf; 
    size_t need = ntohl(COMO(caplen)) + sizeof(pkt_t);

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
#endif
    COMO(payload) = out + sizeof(pkt_t);
    *len = need;
    *count = 1;
    return 0;	
}


callbacks_t callbacks = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0, 
    st_recordsize: 65535,
    indesc: NULL, 
    outdesc: &outdesc, 
    init: init,
    check: NULL,
    hash: NULL,
    match: NULL,
    update: update,
    ematch: NULL,
    export: NULL,
    compare: NULL,
    action: NULL,
    store: store,
    load: load,
    print: print,
    replay: replay ,
    formats: "pretty pcap"
};
