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
 * 802.11 SSID 
 *
 * This module parses the 802.11 management frames to find beacon and stores 
 * all the SSIDs it observes together with the average signal strength 
 * value and noise value for the network.
 *
 */

#include <stdio.h>
#include <time.h>
#include "module.h"
#include "macutils.h"

#define MAC_ADDR_SIZE   6

/* 
 * the information we maintain in capture is just the 
 * ssid we have seen and the timestamp. 
 */
#define FLOWDESC    struct _ssid
FLOWDESC {
    timestamp_t ts;
    int32_t	signal; 
    int32_t	noise; 
    uint8_t	samples; 
    int8_t 	channel;
    uint8_t	wepmode;
    uint8_t     bssid[MAC_ADDR_SIZE];
    uint8_t	len; 
    char 	ssid[33];
    uint8_t     padding[1]; 
};

#define CONFIGDESC   struct _ssid_config
CONFIGDESC {
    int meas_ivl;     /* measurement interval */
};

static timestamp_t
init(void * self, char *args[])
{
    CONFIGDESC *config;
    int i;
    pkt_t *pkt;
    metadesc_t *inmd;

    config = mem_mdl_malloc(self, sizeof(CONFIGDESC)); 
    config->meas_ivl = 1;

    /* 
     * process input arguments 
     */
    for (i = 0; args && args[i]; i++) {
        if (strstr(args[i], "interval")) {
            char * val = index(args[i], '=') + 1;
            config->meas_ivl = atoi(val);
        }
    }
    
    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = TIME2TS(config->meas_ivl, 0);
    
    pkt = metadesc_tpl_add(inmd, "radio:802.11:none:none");
    
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = TIME2TS(config->meas_ivl, 0);
    
    pkt = metadesc_tpl_add(inmd, "none:802.11:none:none");
    
    CONFIG(self) = config; 
    return TIME2TS(config->meas_ivl, 0);
}


/* 
 * define a check() callback to filter out messages that are not 
 * beacons 
 */
static int
check(__unused void * self, pkt_t * pkt) 
{
    return ((IEEE80211_BASE(fc_type) == IEEE80211TYPE_MGMT) &&
	   (IEEE80211_BASE(fc_subtype) == MGMT_SUBTYPE_BEACON));
}


static int 
match(__unused void * self, pkt_t * pkt, void * fh) 
{
    FLOWDESC * x = F(fh); 
    
    if (!(strncmp(x->ssid, MGMT_BODY(ssid), x->len)) && 
            (!(bcmp(x->bssid, &IEEE80211_BASE(addr3), MAC_ADDR_SIZE))) &&
	    (x->channel == MGMT_BODY(ch)))
	return 1; 

    return 0; 
}


/*
 * update callback
 */
static int
update(void * self, pkt_t *pkt, void *fh, int isnew)
{
    CONFIGDESC * config = CONFIG(self);
    FLOWDESC *x = F(fh); 

    if (isnew) {
	x->ts = COMO(ts) - COMO(ts) % TIME2TS(config->meas_ivl, 0);
	x->channel = -1; 
	x->signal = x->noise = 0;
        x->samples = 0; 

	/* now find the information in the management frame.
	 * get privacy bit to determine if wep is enabled
	 */
	x->wepmode = CAPINFO_PRIVACY(H16(MGMT_BODY(cap))) ? 1 : 0;

	/* get to the SSID information element */
	if (MGMT_BODY(ssid_len) > 0) { 
	    x->len = (MGMT_BODY(ssid_len)); 
	    bcopy(MGMT_BODY(ssid), x->ssid, x->len);
	} else { 
	    x->len = 3; 
	    sprintf(x->ssid, "ANY"); 
	}
        bcopy(IEEE80211_BASE(addr3), x->bssid, MAC_ADDR_SIZE);
	x->channel = MGMT_BODY(ch); 	
    }
    x->samples++;
    if (COMO(type) == COMOTYPE_RADIO) {
        x->signal += H32(RADIO(ssisignal)); 
        x->noise += H32(RADIO(ssinoise)); 
    }
    
    return 0; /* records are never full */
}


static ssize_t
store(__unused void * self, void *rp, char *buf)
{
    FLOWDESC *x = F(rp);
    int i; 
    
    PUTH64(buf, x->ts);
    PUTH32(buf, x->signal);
    PUTH32(buf, x->noise);
    PUTH8(buf, x->samples); 
    PUTH8(buf, x->channel);
    PUTH8(buf, x->wepmode); 
    for (i = 0; i < MAC_ADDR_SIZE; i++)
	PUTH8(buf, x->bssid[i]); /* CHECKME: why not use memcpy? */
    PUTH8(buf, x->len); 
    for (i = 0; i < x->len; i++) 
	PUTH8(buf, x->ssid[i]); /* CHECKME: why not use memcpy? */
    
    return sizeof(FLOWDESC);
}


static size_t
load(__unused void * self, char * buf, size_t len, timestamp_t * ts)
{   
    if (len < sizeof(FLOWDESC)) {
        *ts = 0;
        return 0;
    }

    *ts = NTOHLL(((FLOWDESC *)buf)->ts);
    return sizeof(FLOWDESC);
}


#define PRETTYHDR		\
    "Date                     Signal (dbm)    Noise (dbm)     Channel \
   Samples    WEP   MAC               SSID\n"
#define PRETTYFMT	"%.24s %-15d %-15d %-10d %-10d %-5s %s %-32s\n"
#define PLAINFMT	"%12ld %1d %2d %2d %2d %2d\n" 

static char *
print(__unused void * self, char *buf, size_t *len, char * const args[])
{
    static char s[512];
    static char * fmt; 
    FLOWDESC *x; 
    timestamp_t ts;
    time_t t; 
    char ssid[34];
    int32_t sig, noise;
 
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
    t = (time_t) TS2SEC(ts); 
    snprintf(ssid, x->len+1, x->ssid);   
    sig = (int32_t)ntohl(x->signal) / x->samples; 
    noise = (int32_t)ntohl(x->noise) / x->samples; 
    
    /* print according to the requested format */
    if (fmt == PRETTYFMT) {
	char * wepmode = x->wepmode? "Y": "N"; 
        char bssid[64];

        pretty_mac(x->bssid, bssid, sizeof(bssid), 1);
	*len = sprintf(s, fmt, asctime(localtime(&t)), sig, noise,
                                    x->channel, x->samples, wepmode, bssid, ssid);
    } else {
	*len = sprintf(s, fmt, (long int) t, x->wepmode, 
		   x->channel, sig, noise, x->samples); 
    } 

    return s;
}


MODULE(ssid) = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0,
    st_recordsize: sizeof(FLOWDESC),
    capabilities: {has_flexible_flush: 0, 0},
    init: init,
    check: check,
    hash: NULL,
    match: match,
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
    formats: "pretty plain",
};
