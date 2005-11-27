/*
 * Copyright (c) 2004 Intel Corporation
 * All r ghts reserved.
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

#include <time.h>
#include <sys/types.h>
#include <string.h>		/* bcopy */
#include <stdio.h>		/* fprintf, stderr */
#include <net/ethernet.h>	/* ether_addr, ether_ntoa */
#ifdef BUILD_FOR_ARM
#include "pcap-stargate.h"
#else
#include <pcap.h>		/* bpf_int32, etc. */
#endif

#include "como.h"
#include "module.h"
#include "ieee80211.h"

static const char *mgmt_subtypes[] = {
  "association request",
  "association response",
  "reassociation request",
  "reassociation response",
  "probe request",
  "probe response",
  "reserved",
  "reserved",
  "beacon",
  "atim",
  "disassociation",
  "authentication",
  "deauthentication",
  "reserved",
  "reserved"
};


static const char *data_subtypes[] = {
"data",
"data + cf-ack",
"data + cf-poll",
"data + cf-ack + cf-poll",
"null function (no data)",
"cf-ack (no data)",
"cf-ack + cf-poll (no data)"
};

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

    len = (pkt->caplen > snaplen)? snaplen : pkt->caplen; 
    memcpy(x->buf, pkt, sizeof(pkt_t)); 
    ((pkt_t *) x->buf)->payload = NULL;
    ((pkt_t *) x->buf)->caplen = len;
    memcpy(x->buf + sizeof(pkt_t), pkt->payload, len); 

    return 1;		/* records are always full */
}


static ssize_t
store(void *fh, char *buf, size_t len)
{
    FLOWDESC *x = F(fh);
    pkt_t * pkt; 
    size_t need;
    
    pkt = (pkt_t *) x->buf; 
    need = pkt->caplen + sizeof(pkt_t) ; 

    if (len < need)
        return -1;

    /* convert the CoMo header in network byte order */
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
    *ts = NTOHLL(pkt->ts);
    return (sizeof(pkt_t) + ntohl(pkt->caplen)); 
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
    static int fmt; 
    struct pcap_file_header * fhdr; 
    struct pcap_packet * x; 
    pkt_t p, *pkt; 
    int hh, mm, ss; 
    uint32_t addr; 
    int n; 
    

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
    pkt = (pkt_t *) buf; 
    p.ts = NTOHLL(COMO(ts)); 
    p.len = ntohl(COMO(len)); 
    p.caplen = ntohl(COMO(caplen)); 
    p.type = ntohs(COMO(type));
    p.dropped = ntohs(COMO(dropped));
    p.l2type = ntohs(COMO(l2type)); 
    p.l3type = ntohs(COMO(l3type)); 
    p.l4type = ntohs(COMO(l4type)); 
    p.l2ofs = ntohs(COMO(l2ofs)); 
    p.l3ofs = ntohs(COMO(l3ofs)); 
    p.l4ofs = ntohs(COMO(l4ofs)); 
    p.payload = buf + sizeof(pkt_t);

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
    

    /* 
     * depending on the l3 type we print different 
     * information 
     */
    if(COMO(l3type) == ETHERTYPE_IP) { 

	/* print timestamp (hh:mm:ss.us) */
        hh = (TS2SEC(COMO(ts)) % 86400) /3600; 
        mm = (TS2SEC(COMO(ts)) % 3600) / 60; 
        ss = TS2SEC(COMO(ts)) % 60; 
        *len = sprintf(s, "%02d:%02d:%02d.%06d ", 
                                       hh, mm, ss, TS2USEC(COMO(ts))); 

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
			(uint32_t) H32(TCP(seq)), 
			(uint32_t) H32(TCP(ack)), 
		 	(uint16_t) H16(TCP(win))); 
	}
    } else if (FC_TYPE(COMO(l3type)) == WLANTYPE_MGMT || WLANTYPE_DATA || 
		WLANTYPE_CTRL){
	hh = (TS2SEC(COMO(ts)) % 86400) /3600; 
	mm = (TS2SEC(COMO(ts)) % 3600) / 60; 
	ss = TS2SEC(COMO(ts)) % 60; 
	    
	switch(FC_TYPE(COMO(l3type))) {
	case WLANTYPE_MGMT:
	    *len += sprintf(s + *len, 
		"%02d:%02d:%02d:%06d %s", hh, mm, ss, TS2USEC(COMO(ts)), 
		mgmt_subtypes[FC_SUBTYPE(COMO(l3type)) >> 12]); 
	    break;
	case WLANTYPE_CTRL:
	    switch(FC_SUBTYPE(COMO(l3type))) {
	    case CTRL_SUBTYPE_PS_POLL:
		*len += sprintf(s + *len, 
		    "%02d:%02d:%02d:%06d power save-poll", 
		    hh, mm, ss, TS2USEC(COMO(ts))); 
		break;
	    case CTRL_SUBTYPE_RTS:
		*len += sprintf(s + *len, 
		    "%02d:%02d:%02d:%06d request to send", 
		    hh, mm, ss, TS2USEC(COMO(ts))); 
		break;
	    case CTRL_SUBTYPE_CTS:
		*len += sprintf(s + *len, 
		    "%02d:%02d:%02d:%06d clear to send", 
		    hh, mm, ss, TS2USEC(COMO(ts))); 
		break;
	    case CTRL_SUBTYPE_ACK:
		*len += sprintf(s + *len, 
		    "%02d:%02d:%02d:%06d acknowledgment", 
		    hh, mm, ss, TS2USEC(COMO(ts)));
		break;
	    case CTRL_SUBTYPE_CF_END:
		*len += sprintf(s + *len, 
		    "%02d:%02d:%02d:%06d cf-end", 
		    hh, mm, ss, TS2USEC(COMO(ts))); 
		break;
	    case CTRL_SUBTYPE_END_ACK:
		*len += sprintf(s + *len, 
		    "%02d:%02d:%02d:%06d cf-end + cf-ack", 
		    hh, mm, ss, TS2USEC(COMO(ts))); 
	       break;
	    default:
	       break;
	    }
	    break;
	case WLANTYPE_DATA:
	    *len += sprintf(s + *len, 
		"%02d:%02d:%02d:%06d %s", hh, mm, ss, TS2USEC(COMO(ts)), 
		data_subtypes[FC_SUBTYPE(COMO(l3type)) >> 12]); 
	    break;
	default:
	    *len += sprintf(s + *len,
		"ieee802.11 type not supported - work in progress");
	    break;
	}
    }
    else
	*len += sprintf(s + *len, "print not supported");
    *len += sprintf(s + *len, "\n");
    return s; 
}

static int  
replay(char *buf, char *out, size_t * len, int *count)
{
    pkt_t * pkt = (pkt_t *) buf; 
    size_t need = ntohl(pkt->caplen) + sizeof(pkt_t); 

    if (*len < need) 
	return -1; 

    bcopy(buf, out, need); 
    pkt = (pkt_t *) out;
    /* Convert the header data into host byte order */
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
    pkt->payload = out + sizeof(pkt_t); 
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
    replay: replay 
};

