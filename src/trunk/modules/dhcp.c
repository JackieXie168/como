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


/*
 * DHCP Module
 *
 * This module catches DHCPACK packets and store information about the
 * MAC to IP addresses associations.
 *
 */

#include <stdio.h>
#include <time.h>
#include "module.h"

#define FLOWDESC	struct _dhcp_desc
FLOWDESC {
    timestamp_t	ts;
    uint8_t	htype;		/* Hardware addr type (net/if_types.h) */
    uint8_t	hlen;		/* Hardware addr length */
    uint8_t	_res[2];	/* padding */
    uint8_t	chaddr[16];	/* Client hardware address */
    n32_t	yiaddr;		/* Client IP address */
};

static int dhcp_message_type(pkt_t *pkt);

static timestamp_t 
init(void * self, char *args[])
{
    pkt_t *pkt;
    metadesc_t *inmd;
    
    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    
    pkt = metadesc_tpl_add(inmd, "none:none:none:~udp");
    N16(UDP(src_port)) = 0xffff;
    N16(UDP(dst_port)) = 0xffff;
    
    return TIME2TS(1, 0);
}

static uint8_t cookie[4] = DHCP_OPTIONS_COOKIE;

static int
check(void * self, pkt_t * pkt)
{
    if (H16(UDP(src_port)) == DHCP_SERVER_PORT &&
	H16(UDP(dst_port)) == DHCP_CLIENT_PORT &&
	DHCP(op) == BOOTREPLY &&
	dhcp_message_type(pkt) == DHCPACK) {
	
	return 1;
    }
    return 0;
}

static uint8_t known_option_lens[] = {
/* DHO_PAD */				0,
/* DHO_SUBNET_MASK */			4,
/* DHO_TIME_OFFSET */			4,
/* DHO_ROUTERS */			4,
/* DHO_TIME_SERVERS */			4,
/* DHO_NAME_SERVERS */			4,
/* DHO_DOMAIN_NAME_SERVERS */		4,
/* DHO_LOG_SERVERS */			4,
/* DHO_COOKIE_SERVERS */		4,
/* DHO_LPR_SERVERS */			4,
/* DHO_IMPRESS_SERVERS */		4,
/* DHO_RESOURCE_LOCATION_SERVERS */	4,
/* DHO_HOST_NAME */			1,
/* DHO_BOOT_SIZE */			2,
/* DHO_MERIT_DUMP */			1,
/* DHO_DOMAIN_NAME */			1,
/* DHO_SWAP_SERVER */			4,
/* DHO_ROOT_PATH */			1,
/* DHO_EXTENSIONS_PATH */		1,
/* DHO_IP_FORWARDING */			1,
/* DHO_NON_LOCAL_SOURCE_ROUTING */	1,
/* DHO_POLICY_FILTER */			8,
/* DHO_MAX_DGRAM_REASSEMBLY */		2,
/* DHO_DEFAULT_IP_TTL */		1,
/* DHO_PATH_MTU_AGING_TIMEOUT */	4,
/* DHO_PATH_MTU_PLATEAU_TABLE */	2,
/* DHO_INTERFACE_MTU */			2,
/* DHO_ALL_SUBNETS_LOCAL */		1,
/* DHO_BROADCAST_ADDRESS */		4,
/* DHO_PERFORM_MASK_DISCOVERY */	1,
/* DHO_MASK_SUPPLIER */			1,
/* DHO_ROUTER_DISCOVERY */		1,
/* DHO_ROUTER_SOLICITATION_ADDRESS */	4,
/* DHO_STATIC_ROUTES */			8,
/* DHO_TRAILER_ENCAPSULATION */		1,
/* DHO_ARP_CACHE_TIMEOUT */		4,
/* DHO_IEEE802_3_ENCAPSULATION */	1,
/* DHO_DEFAULT_TCP_TTL */		1,
/* DHO_TCP_KEEPALIVE_INTERVAL */	4,
/* DHO_TCP_KEEPALIVE_GARBAGE */		1,
/* DHO_NIS_DOMAIN */			1,
/* DHO_NIS_SERVERS */			4,
/* DHO_NTP_SERVERS */			4,
/* DHO_VENDOR_ENCAPSULATED_OPTIONS */ 	1,
/* DHO_NETBIOS_NAME_SERVERS */		4,
/* DHO_NETBIOS_DD_SERVER */		4,
/* DHO_NETBIOS_NODE_TYPE */		1,
/* DHO_NETBIOS_SCOPE */			1,
/* DHO_FONT_SERVERS */			4,
/* DHO_X_DISPLAY_MANAGER */		4,
/* DHO_DHCP_REQUESTED_ADDRESS */	4,
/* DHO_DHCP_LEASE_TIME */		4,
/* DHO_DHCP_OPTION_OVERLOAD */		1,
/* DHO_DHCP_MESSAGE_TYPE */		1,
/* DHO_DHCP_SERVER_IDENTIFIER */	4,
/* DHO_DHCP_PARAMETER_REQUEST_LIST */ 	1,
/* DHO_DHCP_MESSAGE */			1,
/* DHO_DHCP_MAX_MESSAGE_SIZE */		2,
/* DHO_DHCP_RENEWAL_TIME */		4,
/* DHO_DHCP_REBINDING_TIME */		4,
/* DHO_VENDOR_CLASS_IDENTIFIER */	1,
/* DHO_DHCP_CLIENT_IDENTIFIER */	2
};

static int dhcp_message_type(pkt_t *pkt)
{
    uint8_t *options = DHCP(options) + sizeof(cookie);
    int i, limit;
    
    if (COMO(caplen) - COMO(l7ofs) <
	sizeof(struct _como_dhcp) + sizeof(cookie)) {
	return -1;
    }
    
    if (memcmp(DHCP(options), &cookie, sizeof(cookie)) != 0) {
	return -1;
    }
    
    limit = (int) ((uint32_t) COMO(payload) + COMO(caplen)) -
	    ((uint32_t) DHCP(options));
    
    for (i = 0; i < limit; ) {
	if (i + 2 > limit) {
	    return -1; /* bogus */
	}
	
	if (options[i] == DHO_PAD) {
	    i++;
	    continue;
	}
	
	if (options[i] == DHO_END) {
	    return -1; /* dhcp mt not found */
	}
	
	if (options[i] == DHO_DHCP_MESSAGE_TYPE) {
	    /* got it */
	    return (int) options[i + 2];
	}

	if (options[i] <= DHO_DHCP_CLIENT_IDENTIFIER) {
	    /* known option */
	    int len;
	    len = known_option_lens[options[i]];
	    i += len + 1;
	}
    }
    
    return -1;
}

static int
update(void * self, pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *d = F(fh);
    
    d->ts = COMO(ts);
    d->htype = DHCP(htype);
    d->hlen = DHCP(hlen);
    memcpy(d->chaddr, DHCP(chaddr), 16);
    N32(d->yiaddr) = N32(DHCP(yiaddr));
    
    return 1;
}

static ssize_t
store(void * self, void *efh, char *buf)
{
    FLOWDESC *d = F(efh);
    
    PUTH64(buf, d->ts);
    PUTH8(buf, d->htype);
    PUTH8(buf, d->hlen);
    PUTH8(buf, d->_res[0]); /* padding */
    PUTH8(buf, d->_res[1]); /* padding */
    memcpy(buf, d->chaddr, 16);
    buf += 16;
    PUTN32(buf, N32(d->yiaddr));
    
    return sizeof(FLOWDESC);
}

static size_t
load(void * self, char * buf, size_t len, timestamp_t * ts)
{
    if (len < sizeof(FLOWDESC)) {
        *ts = 0;
        return 0;
    }

    *ts = NTOHLL(((FLOWDESC *) buf)->ts);
    return sizeof(FLOWDESC);
}


#define PRETTYHDR \
  "Date                       Timestamp            Client IP      MAC Address\n"

static char prettyfmt[] = "%.24s %12d.%06d %15s %19s\n";

static char *
print(void * self, char *buf, size_t *len, char * const args[])
{
    static char s[512];
    char mac[48];
    static char *fmt; 
    struct in_addr yiaddr;
    FLOWDESC *x; 
    timestamp_t ts;
    time_t t; 

    if (buf == NULL && args != NULL) { 
	/* by default, pretty print */
	*len = sprintf(s, PRETTYHDR);  
	fmt = prettyfmt; 

	return s; 
    } 

    if (buf == NULL && args == NULL) { 
	*len = 0;
	
	return s; 
    } 
	
    x = (FLOWDESC *) buf; 
    ts = NTOHLL(x->ts);
    t = (time_t) TS2SEC(ts);
    
    yiaddr.s_addr = N32(x->yiaddr);
    
    mac[0] = '\0';
    if (x->htype == HTYPE_ETHER || x->htype == HTYPE_IEEE802) {
	sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
		x->chaddr[0], x->chaddr[1], x->chaddr[2],
		x->chaddr[3], x->chaddr[4], x->chaddr[5]);
    }
    
    /* print according to the requested format */
    if (fmt == prettyfmt) {
	*len = sprintf(s, fmt, 
	               asctime(localtime(&t)), TS2SEC(ts), TS2USEC(ts), 
		       inet_ntoa(yiaddr), mac);
    }
    
    return s;
}

MODULE(dhcp) = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0,
    st_recordsize: sizeof(FLOWDESC),
    capabilities: {has_flexible_flush: 0, 0},
    init: init,
    check: check,
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
    replay: NULL,
    formats: "pretty",
};
