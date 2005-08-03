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

#include <time.h>
#include <sys/types.h>
#include <string.h>		/* bcopy */
#include <stdio.h>		/* fprintf, stderr */
#include <netdb.h>		/* getprotobynumber */
#include <net/ethernet.h>	/* ether_addr, ether_ntoa */

#include "como.h"
#include "module.h"


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
static unsigned snaplen = 56; 

/* 
 * description of the output trace for sniffer-como
 */
static pktdesc_t outdesc;


static int 
init(__unused void *mem, __unused size_t msize, char * args[])
{
    if (args == NULL) 
	return 0; 

    if (strstr(args[0], "snaplen=")) { 
	char * len; 

	len = index(args[0], '='); 
	len++; 	/* skip '=' */
	snaplen = atoi(len); 		/* set the snaplen */
    } 

    memset(&outdesc, 0xff, sizeof(pktdesc_t));
    outdesc.caplen = snaplen; 
    return 0; 
}


static int
update(pkt_t *pkt, void *fh, __unused int isnew, __unused unsigned drop_cntr)
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
    pkt->ts = HTONLL(pkt->ts); 
    pkt->caplen = htonl(pkt->caplen); 
    pkt->len = htonl(pkt->len); 
    pkt->l2type = htons(pkt->l2type); 
    pkt->l3type = htons(pkt->l3type); 
    pkt->layer3ofs = htons(pkt->layer3ofs); 
    pkt->layer4ofs = htons(pkt->layer4ofs); 

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
print_tcp_flags(uint8_t flags) {
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


static char *
print(char *buf, size_t *len, char * const args[])
{
    static char s[2048]; 
    pkt_t p, *pkt; 
    int hh, mm, ss; 
    uint32_t addr; 
    struct protoent * pe; 

    if (buf == NULL && args != NULL) { 
	/* first call, process the arguments */
	*len = 0; 
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
    p.l2type = ntohl(COMO(l2type)); 
    p.l3type = ntohs(COMO(l3type)); 
    p.l4type = ntohs(COMO(l4type)); 
    p.layer3ofs = ntohs(COMO(layer3ofs)); 
    p.layer4ofs = ntohs(COMO(layer4ofs)); 
    p.payload = buf + sizeof(pkt_t);

    /* now we are ready to process this packet */
    pkt = (pkt_t *) &p; 
    
    /* print timestamp (hh:mm:ss.us) */
    hh = (TS2SEC(COMO(ts)) % 86400) /3600; 
    mm = (TS2SEC(COMO(ts)) % 3600) / 60; 
    ss = TS2SEC(COMO(ts)) % 60; 
    *len = sprintf(s, "%02d:%02d:%02d.%06d ", hh, mm, ss, TS2USEC(COMO(ts))); 

    /* 
     * depending on the l3 type we print different 
     * information 
     */
    switch (COMO(l3type)) { 
    case ETHERTYPE_IP: 
        /* 
         * print IP header information 
         */
        pe = getprotobynumber(IP(proto)); 
	*len += sprintf(s + *len, "IP | %s - ", pe->p_name); 
        *len += sprintf(s + *len, "tos 0x%2x ttl %d id %d length: %d - ", 
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
			H32(TCP(seq)), H32(TCP(ack)), H16(TCP(win))); 
	} 

	break; 
 
    default: 
	*len += sprintf(s + *len, 
                    "ethertype: 0x%04x --- print not supported", 
		    COMO(l3type)); 
	break;
    }

    *len += sprintf(s + *len, "\n"); 
    return s; 
}


static int
replay(char *buf, char *out, size_t * len)
{
    pkt_t * pkt = (pkt_t *) buf; 
    size_t need = ntohl(pkt->caplen) + sizeof(pkt_t); 

    if (*len < need) 
	return -1; 

    bcopy(buf, out, need); 
    pkt = (pkt_t *) out; 
    pkt->payload = out + sizeof(pkt_t); 
    *len = need; 
    return 0;	
}

callbacks_t callbacks = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0, 
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

