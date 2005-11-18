/*
 * Copyright (c) 2005 Intel Corporation
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
 * 802.11 SSID 
 *
 * This module parses the 802.11 management frames to find beacon and probe
 * response messages and stores all the SSIDs it observes together with 
 * the signal strength value and noise value. 
 *
 */

#include <stdio.h>
#include <time.h>
#include "module.h"
#include "como.h"

/* 
 * the information we maintain in capture is just the 
 * ssid we have seen and the timestamp. 
 */
#define FLOWDESC    struct _ssid
FLOWDESC {
    timestamp_t ts;
    uint32_t	signal; 
    uint32_t	noise; 
    uint8_t	samples; 
    int8_t 	channel;
    uint8_t	wepmode;
    uint8_t	len; 
    char 	ssid[34]; 
};

#define WLAN_WEP 0x40

static int meas_ivl = 1;     /* measurement granularity */


static int
init(__unused void *mem, __unused size_t msize, char *args[])
{
    int i;

    if (args == NULL)
        return 0;

    for (i = 0; args[i]; i++) {
        if (strstr(args[i], "granularity")) {
            char * val = index(args[i], '=') + 1;
            meas_ivl = atoi(val);
        }
    }
    return 0;
}


/* 
 * define a check() callback to filter out messages that are not 
 * beacons and probe reponses  
 */
static int
check(pkt_t * pkt) 
{
    if ((COMO(type) == COMOTYPE_RADIO) && ((COMO(l3type) == isWLANBEACON) ||
	    (COMO(l3type) == isWLANPROBE_RESPONSE))) 
	return 1; 
    return 0; 
}


static int 
match(pkt_t * pkt, void * fh) 
{
    FLOWDESC * x = F(fh); 
    
    if (!(strncmp(x->ssid, MGMT_BODY(ssid.ssid), x->len)) && 
	    (x->channel == MGMT_BODY(ds.ch)))
	return 1; 

    return 0; 
}


/*
 * update callback
 */
static int
update(pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh); 

    if (isnew) {
	x->ts = pkt->ts - pkt->ts % TIME2TS(meas_ivl, 0);
	x->channel = -1; 
	x->signal = x->noise = 0;
        x->samples = 0; 

	/* now find the information in the management frame.
	 * get privacy bit to determine if wep is enabled
	 */
	x->wepmode = (MGMT_BODY(cap) & WLAN_CAPINFO_PRIVACY)? 1 : 0;

	/* get to the SSID information element */
	if (MGMT_BODY(ssid.len) > 0) { 
	    x->len = (MGMT_BODY(ssid.len)); 
	    bcopy(MGMT_BODY(ssid.ssid), x->ssid, x->len);
	} else { 
	    x->len = 3; 
	    sprintf(x->ssid, "ANY"); 
	}

	x->channel = MGMT_BODY(ds.ch); 	
    }
    x->samples++;
    x->signal += H32(PRISM_HDR(ssi_signal)); 
    x->noise += H32(PRISM_HDR(ssi_noise)); 
    
    return 0; /* records are never full */
}


static ssize_t
store(void *rp, char *buf, size_t len)
{
    FLOWDESC *x = F(rp);
    int i; 
    
    if (len < sizeof(FLOWDESC)) 
	return -1;   
    
    PUTH64(buf, x->ts);
    PUTH32(buf, x->signal);
    PUTH32(buf, x->noise);
    PUTH8(buf, x->samples); 
    PUTH8(buf, x->channel);
    PUTH8(buf, x->wepmode); 
    PUTH8(buf, x->len); 
    for (i = 0; i < x->len; i++) 
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


#define PRETTYHDR		\
    "date s(dbm) n(dbm) ch samples wep ssid\n"
#define PRETTYFMT	"%.24s %2d %2d %2d %2d %s %s\n"
#define PLAINFMT	"%12ld %1d %2d %2d %2d %2d\n" 

static char *
print(char *buf, size_t *len, char * const args[])
{
    static char s[512];
    static char * fmt; 
    FLOWDESC *x; 
    timestamp_t ts;
    time_t t; 
    char ssid[34];
    uint8_t sig, noise;
 
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
    sig = (uint8_t)(ntohl(x->signal) / x->samples); 
    noise = (uint8_t)(ntohl(x->noise) / x->samples); 
    
    /* print according to the requested format */
    if (fmt == PRETTYFMT) {
	char * wepmode = x->wepmode? "Y": "N"; 
	*len = sprintf(s, fmt, asctime(localtime(&t)), (sig-256), (noise-256),
					x->channel, x->samples, wepmode, ssid); 
    } else {
	*len = sprintf(s, fmt, (long int) t, x->wepmode, 
		   x->channel, (sig-256), (noise-256), x->samples); 
    } 

    return s;
}

callbacks_t callbacks = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0,
    indesc: NULL, 
    outdesc: NULL,
    init: init,
    check: check,
    hash: NULL,
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
