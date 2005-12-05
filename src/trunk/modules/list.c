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
 * AP Neighbor List Module
 *
 * The neighbor list contains the list of 802.11 APs. The Module
 * utilises the beacon frames in order to determine which APs can 
 * be heard by sniffers in the service area.
 * 
 * Requirement: Measurment duration 1 second i.e
 * - http://localhost:44444/?module=list&time=-1s:0
 *
 */

#include <stdio.h>

#include "como.h"
#include "module.h"
#include "ieee80211.h"

/* phy types employed by ieee 802.11 devices */

#define PHYTYPE_FHSS_DOT11_97 	1
#define PHYTYPE_DSSS_DOT11_97  	2
#define PHYTYPE_IRBASEBAND    	3
#define PHYTYPE_DSSS_DOT11_B  	4
#define PHYTYPE_PBCC_DOT11_B 	5
#define PHYTYPE_OFDM_DOT11_G 	6
#define PHYTYPE_PBCC_DOT11_G 	7
#define PHYTYPE_OFDM_DOT11_A 	8

/* ieee 802.11 encoding types */

#define UNKNOWN_ENCODING 	0
#define CCK_ENCODING 		1
#define PBCC_ENCODING 		2
#define OFDM_ENCODING 		3


#define MAC_ADDR_SIZE 	6
#define SSID_SIZE     	34


#define FLOWDESC	struct _list
FLOWDESC {
    timestamp_t ts;
    uint32_t signal;   /* signal strength value */ 
    uint32_t noise;    /* noise value */
    uint32_t phytype;  /* identifies phy type employed by WLAN device */
    uint32_t encoding; /* specifies encoding of packet */
    uint16_t bivl;     /* beacon interval */  
    uint8_t  channel;  /* current channel number */
    uint8_t  len;
    uint8_t  addr[MAC_ADDR_SIZE];
    uint8_t  ssid[SSID_SIZE];
};


static uint32_t
hash(pkt_t *pkt) 
{
    uint32_t addr; 
    int i;
    for (i = 2, addr = 0; i < MAC_ADDR_SIZE; i++, addr <<= 8)
        addr |= MGMT_HDR(bssid[i]);
    return addr; 
}


static int
check(pkt_t * pkt)
{
    return ((COMO(type) == COMOTYPE_RADIO) && 
	((WLANTYPE(COMO(l2type)) == WLANTYPE_MGMT) && 
	(WLANSUBTYPE(COMO(l2type)) == MGMT_SUBTYPE_BEACON)));
}


static int
match(pkt_t * pkt, void * fh)
{
    FLOWDESC * x = F(fh);
    uint8_t addr;
    int i;
    
    /* Currently BUILD_FOR_ARM Macros don't support arrays properly, 
     * hence must access each byte individually. Preferred method 
     * would be to use the memcmp keyword. 
     */
    for (i = 0; i < MAC_ADDR_SIZE; i++) {
	addr = MGMT_HDR(bssid[i]);
	if (x->addr[i] != addr) 
	    return 0;
    }
    return 1;
}


static int
update(pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);
    uint8_t addr;
    int i;

    if (isnew) {
        x->ts = pkt->ts;

	x->signal = H32(PRISM_HDR(ssi_signal));
	x->noise = H32(PRISM_HDR(ssi_noise));
        x->phytype = H32(PRISM_HDR(phytype));
	x->encoding = H32(PRISM_HDR(encoding));    

        x->bivl = MGMT_BODY(bivl); 
	x->channel = MGMT_BODY(ch);
        
	/* get to the SSID information element */
        if (MGMT_BODY(ssid_len) > 0) {
            x->len = (MGMT_BODY(ssid_len));
            bcopy(MGMT_BODY(ssid), x->ssid, x->len);
        } else {
            x->len = 3;
            sprintf(x->ssid, "ANY");
        } 

	/* Currently BUILD_FOR_ARM Macros don't support arrays properly, 
	 * hence must access each byte individually. Preferred method 
	 * would be to use the bcopy keyword. 
	 */
        for (i = 0; i < MAC_ADDR_SIZE; i++) {
	    addr = MGMT_HDR(bssid[i]);
	    x->addr[i] = addr;
        }
    }
    return 0;		
}


static ssize_t
store(void *fh, char *buf, size_t len)
{
    FLOWDESC *x = F(fh);
    int i;
 
    if (len < sizeof(FLOWDESC))
	return -1;

    PUTH64(buf, x->ts);
    PUTH32(buf, x->signal);
    PUTH32(buf, x->noise);
    PUTH32(buf, x->phytype);
    PUTH32(buf, x->encoding);
    PUTH16(buf, x->bivl);
    PUTH8(buf, x->channel);
    PUTH8(buf, x->len);
    
    for(i = 0; i < MAC_ADDR_SIZE; i++)
	PUTH8(buf, x->addr[i]);

    for(i = 0; i < x->len; i++)
	PUTH8(buf, x->ssid[i]);

    return sizeof(FLOWDESC);
}


static size_t
load(char * buf, size_t len, timestamp_t * ts)
{
    if (len < sizeof(FLOWDESC)) {
        ts = 0;
        return 0;
    }
    *ts = NTOHLL(((FLOWDESC *)buf)->ts);
    return sizeof(FLOWDESC);
}


#define PRETTYHDR  "timestamp       s(dbm)  n(dbm)  mac address \
       channel band   encoding   interval    ch    ssid\n"
#define PRETTYFMT  "%02d:%02d:%02d:%06d %-7d %-7d "
#define PLAINFMT   "%ld %d %d %d %d %s"


static char *
print(char *buf, size_t *len, char * const args[])
{
    static char s[512];
    static char * fmt;
    FLOWDESC *x;
    timestamp_t ts;
    time_t t;
    char ssid[34];
    int hh, mm, ss;

    if (buf == NULL && args != NULL) {
        int n;

        /* first call of print, process the arguments and return */
        for (n = 0; args[n]; n++) {
            if (!strcmp(args[n], "format=plain")) {
                *len = 0;
                fmt = PLAINFMT;
                return s;
            }
        }

        /* by default, pretty print */
        *len = sprintf(s, PRETTYHDR);
        fmt = PRETTYFMT;
        return s;
    }

    if (buf == NULL && args == NULL) {
        *len = 0;
        return s;
    }

    x = (FLOWDESC *) buf;
    ts = NTOHLL(x->ts);

    hh = (TS2SEC(ts) % 86400) /3600;
    mm = (TS2SEC(ts) % 3600) / 60;
    ss = TS2SEC(ts) % 60;

    t = (time_t) TS2SEC(ts);
    snprintf(ssid, x->len+1, x->ssid);
  
    if (fmt == PRETTYFMT) {
	int n;
        *len = sprintf(s, fmt, hh, mm, ss, TS2USEC(ts), (ntohl(x->signal)-256),
		 (ntohl(x->noise)-256)); 
  
 
	for (n = 0; n < MAC_ADDR_SIZE; n++) 
	    *len += sprintf(s + *len, "%02x%s", x->addr[n],	
			n < (MAC_ADDR_SIZE-1) ? ":": "  ");

        switch (ntohl(x->phytype)) {
	case PHYTYPE_FHSS_DOT11_97:
	    *len += sprintf(s + *len, "%-15s", "FHSS 802.11 97");
	    break; 
	case PHYTYPE_DSSS_DOT11_97:
	    *len += sprintf(s + *len, "%-15s", "DSSS 802.11 97");
	    break;
	case PHYTYPE_IRBASEBAND:  
	    *len += sprintf(s + *len, "%-15s", "IR BASEBAND");
	    break;
	case PHYTYPE_DSSS_DOT11_B: 
	    *len += sprintf(s + *len, "%-15s", "DSSS 802.11b");
	    break;
	case PHYTYPE_PBCC_DOT11_B:
	    *len += sprintf(s + *len, "%-15s", "PBCC 802.11b");
	    break;
	case PHYTYPE_OFDM_DOT11_G:
	    *len += sprintf(s + *len, "%-15s", "OFDM 802.11g");
	    break;
	case PHYTYPE_PBCC_DOT11_G: 
	    *len += sprintf(s + *len, "%-15s", "PBCC 802.11g");
	    break;
	case PHYTYPE_OFDM_DOT11_A: 
	    *len += sprintf(s + *len, "%-15s", "OFDM 802.11a");
	    break;
	default:
	    *len += sprintf(s + *len, "%-15s", "FOREIGN");
	    break;
	}

	switch(ntohl(x->encoding)) {
	case UNKNOWN_ENCODING:
	    *len += sprintf(s + *len, "%-10s", "UNKNOWN");
	    break; 
	case CCK_ENCODING: 
	    *len += sprintf(s + *len, "%-10s", "CCK");
	    break; 
	case PBCC_ENCODING: 
	    *len += sprintf(s + *len, "%-10s", "PBCC");
	    break; 
	case OFDM_ENCODING: 
	    *len += sprintf(s + *len, "%-10s", "OFDM");
	    break; 
	default:
	    *len += sprintf(s + *len, "%-10s", "FOREIGN");
	    break;
	}	
	*len += sprintf(s + *len, " %-3d%-7s  %-5d %-32s", x->bivl, "ms", 
							    x->channel, ssid);
	*len += sprintf(s + *len, "\n");
    } else {
	*len = sprintf(s, fmt, (long int) t, (ntohl(x->signal)-256),
			    (ntohl(x->noise)-256), x->bivl, x->channel, ssid);
    }
    
    return s;
}


callbacks_t callbacks = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0, 
    st_recordsize: 65535,
    indesc: NULL, 
    outdesc: NULL, 
    init: NULL,
    check: check,
    hash: hash,
    match: match,
    update: update,
    ematch: NULL,
    export: NULL,
    compare: NULL,
    action: NULL,
    store: store,
    load: load,
    print: print,
    replay: NULL 
};

