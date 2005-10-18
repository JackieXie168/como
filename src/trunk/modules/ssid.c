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
 * This module parses the 802.11 management frames to find beacon messages
 * and stores all the SSIDs it observes together with the SNR information. 
 *
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
    int32_t	signal; 
    int32_t	noise; 
    uint8_t	samples; 
    int8_t 	channel;
    uint8_t	wepmode;
    uint8_t	len; 
    char 	ssid[33]; 
};


/* 
 * beacon packet format... 
 */ 

struct wlanbeacon { 
    uint64_t ts; 
    uint16_t ivl; 
    uint16_t cap; 
    char variable[0];
};


struct wlanssid { 
    uint8_t id; 	/* must be 0 */
    uint8_t len; 	/* length of SSID */
    char ssid[33]; 	/* actual ssid */
};

struct wlands { 
    uint8_t id; 	/* must be 3 */
    uint8_t len; 	/* length of field (must be 1) */
    uint8_t ch; 	/* channel */
};

struct wlanrates { 
    uint8_t id; 	/* must be 1 */
    uint8_t len; 	/* no. of rates */
    uint8_t rates[7]; 	/* rates values */
};

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
 * beacons... we have to do it here because we don't have the right 
 * macros ready yet for the filter. 
 */
static int
check(pkt_t * pkt) 
{
    if ((pkt->l2type != COMOTYPE_PRISM_LNX) || isWLANWEP || !isWLANBEACON) 
	return 0; 
    return 1; 
}

static int 
match(pkt_t * pkt, void * fh) 
{
    struct wlanbeacon * bcn; 
    struct wlanssid * ssidinfo; 
    struct wlands * dsinfo; 
    FLOWDESC * x = F(fh); 
    int ch = -1; 
    int skip; 

    bcn = (struct wlanbeacon *) (pkt->payload + 
					sizeof(struct _como_prismhdr_lnx)); 

    ssidinfo = (struct wlanssid *) bcn->variable; 
    skip = x->len + 2;				/* skipping ssid info element */
    skip += bcn->variable[skip + 1] + 2; 	/* skipping rates info */
       
    /* look for the DS parameter set */
    dsinfo = (struct wlands *) (bcn->variable + skip); 
    if (dsinfo->id == 3) 
	ch = dsinfo->ch; 

    if (!(strncmp(x->ssid, ssidinfo->ssid, x->len)) && x->channel == ch)
	return 1; 

    return 0; 
}


static int
update(pkt_t *pkt, void *fh, int isnew, __unused unsigned drop_cntry)
{
    FLOWDESC *x = F(fh);

    if (isnew) {
	struct wlanbeacon * bcn; 
	struct wlanssid * ssidinfo; 
	struct wlands * dsinfo; 
	int skip;


	x->ts = pkt->ts - pkt->ts % TIME2TS(meas_ivl, 0);
	x->channel = -1; 
	x->signal = x->noise = x->samples = 0; 

        
	/* now find the information in the management frame */
	bcn = (struct wlanbeacon *) (pkt->payload + 
					sizeof(struct _como_prismhdr_lnx)); 

	/* get to the privacy bit to find out if wep is used */
	x->wepmode = (bcn->cap & WLAN_CAPINFO_PRIVACY)? 1 : 0;


	/* get to the SSID information element */
	ssidinfo = (struct wlanssid *) bcn->variable; 
	if (ssidinfo->len > 0) { 
	    x->len = ssidinfo->len; 
	    bcopy(ssidinfo->ssid, x->ssid, x->len); 
	} else { 
	    /* no SSID? */
	    x->len = 3; 
	    sprintf(x->ssid, "ANY"); 
	}

	/* find where the DS parameter set is */
	skip = x->len + 2;	/* skipping ssid info element */
	skip += bcn->variable[skip + 1] + 2; 
       
	/* look for the DS parameter set */
	dsinfo = (struct wlands *) (bcn->variable + skip); 
	if (dsinfo->id == 3) 
	    x->channel = dsinfo->ch; 
    } 

    x->samples++; 
    x->signal +=  PRISM_LNX(ssi_signal); 
    x->noise +=  PRISM_LNX(ssi_noise); 
    return 0;		/* records are never full */
}


static ssize_t
store(void *rp, char *buf, size_t len)
{
    FLOWDESC *x = F(rp);
    int i; 
    if (len < sizeof(FLOWDESC)) 
    
    PUTH64(buf, x->ts);
    PUTH32(buf, x->signal);
    PUTH32(buf, x->noise);
    PUTH8(buf, x->samples); 
    PUTH8(buf, x->channel);
    PUTH8(buf, x->wepmode); 
    PUTH8(buf, x->len); 
    for (i = 0; i < x->len; i++) 
	PUTH8(buf, x->ssid[i]); 

#if 1 
    /* XXX for debugging... */
    {
	time_t t; 
	char ssid[33]; 
	uint8_t sig, noise; 
	char * wepmode = x->wepmode? "yes": "no"; 

	t = (time_t) TS2SEC(x->ts); 
	snprintf(ssid, x->len + 1, x->ssid); 
	sig = (uint8_t) (x->signal / x->samples); 
	noise = (uint8_t) (x->noise / x->samples); 

#define PRETTYFMT	"%.24s %-32s %-3s %2d %2d %2d %2d\n"
	fprintf(stderr, PRETTYFMT, asctime(localtime(&t)), ssid, wepmode, 
	           x->channel, sig, noise, x->samples); 
#undef PRETTYFMT
    }
#endif 

    return 20 + x->len;
}

static size_t
load(char * buf, size_t len, timestamp_t * ts)
{

    if (len < sizeof(FLOWDESC)) {
        ts = 0;
        return 0;
    }

    *ts = NTOHLL(((FLOWDESC *)buf)->ts);
    return 20 + (((FLOWDESC *)buf)->len);
}


#define PRETTYHDR		\
    "Date                       SSID           WEP   Ch Signal Noise Samples\n"
#define PRETTYFMT	"%.24s %-32s %-3s %2d %2d %2d %2d\n"
#define PLAINFMT	"%12ld %-32s %1d %2d %2d %2d %2d\n" 

static char *
print(char *buf, size_t *len, char * const args[])
{
    static char s[512];
    static char * fmt; 
    FLOWDESC *x; 
    timestamp_t ts;
    time_t t; 
    char ssid[33]; 
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
    snprintf(ssid, x->len + 1, x->ssid); 
    sig = (uint8_t) (x->signal / x->samples); 
    noise = (uint8_t) (x->noise / x->samples); 

    /* print according to the requested format */
    if (fmt == PRETTYFMT) {
	char * wepmode = x->wepmode? "yes": "no"; 
	*len = sprintf(s, fmt, asctime(localtime(&t)), ssid, wepmode, 
	           x->channel, sig, noise, x->samples); 
    } else {
	*len = sprintf(s, fmt, (long int) t, ssid, x->wepmode, 
		   x->channel, sig, noise, x->samples); 
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
