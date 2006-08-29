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
 * IEEE 802.11 associations
 *
 * This module parses the 802.11 frames and builds a table of associations
 * between MAC addresses and Access Points.
 */
#include <stdio.h>
#include <strings.h>
#include <time.h>
#include <assert.h>
#include "module.h"

#define MAC_ADDR_SIZE   6

static void
mac_addr_to_ascii(uint8_t *mac, char *dest)
{
    char *ptr = dest;
    int i;

    for (i = 0; i < MAC_ADDR_SIZE; i++) {
        sprintf(ptr, "%02x:", mac[i]);
        ptr += 3;
    }

    dest[3 * MAC_ADDR_SIZE - 1] = '\0';
}


#define FLOWDESC    struct _ssid
FLOWDESC {
    timestamp_t ts;
    uint8_t ap[MAC_ADDR_SIZE];      /* MAC of AP */
    uint8_t client[MAC_ADDR_SIZE];  /* MAC of client or highest MAC */
    uint32_t pkts_upload;   /* pkts sent by client */
    uint32_t pkts_download; /* pkts sent by AP */
    int adhoc; /* set to 1 if the stations are talking in AP mode. 
                * if so, the lower MAC must be saved in ap, while the
                * higher in client.
                */
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

enum PKT_DIRECTIONS {
    BOGUS,
    TO_DS,   /* client -> AP */
    FROM_DS, /* AP -> client */
    ADHOC1,  /* higher MAC to lower MAC */
    ADHOC2   /* lower MAC to higher MAC */
};

static int
direction(pkt_t *pkt)
{
    if (IEEE80211_BASE(fc_from_ds) == 0 && IEEE80211_BASE(fc_to_ds) == 0) {
        int cmp = bcmp(DATA_HDR(addr3), DATA_HDR(addr4), MAC_ADDR_SIZE);
        if (cmp < 0)
            return ADHOC1;
        else
            return ADHOC2;
    }
    if (IEEE80211_BASE(fc_from_ds))
        return FROM_DS;
    if (IEEE80211_BASE(fc_to_ds))
        return TO_DS;
    return BOGUS; /* AP -> AP? */
}

static uint32_t
hash_mac_addr(uint8_t *addr)
{
    uint32_t mix = 0;
    int i;

    for (i = 0; i < MAC_ADDR_SIZE; i++)
        mix = (mix << 4) ^ (mix >> 28) ^ addr[i];
    return mix;
}

static uint32_t
hash(__unused void *self, pkt_t *pkt)
{
    int dir = direction(pkt);
    switch (dir) {
        case TO_DS:
        case FROM_DS:
            return hash_mac_addr(IEEE80211_BASE(addr1))
                 ^ hash_mac_addr(IEEE80211_BASE(addr2));
        case ADHOC1:
        case ADHOC2:
            return hash_mac_addr(DATA_HDR(addr3))
                 ^ hash_mac_addr(DATA_HDR(addr4));
    }

    return 0; /* not to be reached */
}

static int
check(__unused void *self, pkt_t *pkt)
{
    return IEEE80211_BASE(fc_type) == IEEE80211TYPE_DATA &&
        direction(pkt) != BOGUS;
}

static int 
match(__unused void * self, pkt_t * pkt, void * fh) 
{
    FLOWDESC * x = F(fh); 
    int dir = direction(pkt);

    switch (dir) {
        case TO_DS:
            return !x->adhoc &&
                0 == bcmp(x->ap,     IEEE80211_BASE(addr1), MAC_ADDR_SIZE) &&
                0 == bcmp(x->client, IEEE80211_BASE(addr2), MAC_ADDR_SIZE);
        case FROM_DS:
            return !x->adhoc &&
                0 == bcmp(x->ap,     IEEE80211_BASE(addr2), MAC_ADDR_SIZE) &&
                0 == bcmp(x->client, IEEE80211_BASE(addr1), MAC_ADDR_SIZE);
        case ADHOC1:
            return x->adhoc &&
                0 == bcmp(x->ap,     DATA_HDR(addr3), MAC_ADDR_SIZE) &&
                0 == bcmp(x->client, DATA_HDR(addr4), MAC_ADDR_SIZE);
        case ADHOC2:
            return x->adhoc &&
                0 == bcmp(x->ap,     DATA_HDR(addr4), MAC_ADDR_SIZE) &&
                0 == bcmp(x->client, DATA_HDR(addr3), MAC_ADDR_SIZE);
        default:
            return 0; /* should not be reached */
    } 
}


/*
 * update callback
 */
static int
update(void * self, pkt_t *pkt, void *fh, int isnew)
{
    CONFIGDESC * config = CONFIG(self);
    FLOWDESC *x = F(fh); 
    int dir = direction(pkt);

    if (isnew) {
	x->ts = COMO(ts) - COMO(ts) % TIME2TS(config->meas_ivl, 0);
        x->pkts_upload = 0;
        x->pkts_download = 0;
        switch (dir) {
            case TO_DS:
                x->adhoc = 0;
                memcpy(x->ap,     IEEE80211_BASE(addr1), MAC_ADDR_SIZE);
                memcpy(x->client, IEEE80211_BASE(addr2), MAC_ADDR_SIZE);
                break;
            case FROM_DS:
                x->adhoc = 0;
                memcpy(x->ap,     IEEE80211_BASE(addr2), MAC_ADDR_SIZE);
                memcpy(x->client, IEEE80211_BASE(addr1), MAC_ADDR_SIZE);
                break;
            case ADHOC1:
                x->adhoc = 1;
                memcpy(x->ap,     DATA_HDR(addr3), MAC_ADDR_SIZE);
                memcpy(x->client, DATA_HDR(addr4), MAC_ADDR_SIZE);
                break;
            case ADHOC2:
                x->adhoc = 1;
                memcpy(x->ap,     DATA_HDR(addr4), MAC_ADDR_SIZE);
                memcpy(x->client, DATA_HDR(addr3), MAC_ADDR_SIZE);
                break;
            default:
                return 1; /* should not be reached */
        }
    }

    switch(dir) {
        case TO_DS:
        case ADHOC1:
            x->pkts_upload++;
            break;
        case FROM_DS:
        case ADHOC2:
            x->pkts_download++;
            break;
    }
    return 0; /* records are never full */
}


static ssize_t
store(__unused void * self, void *rp, char *buf)
{
    FLOWDESC *x = F(rp);
    int i; 
    
    PUTH64(buf, x->ts);
    for (i = 0; i < MAC_ADDR_SIZE; i++) 
	PUTH8(buf, x->ap[i]);
    for (i = 0; i < MAC_ADDR_SIZE; i++) 
	PUTH8(buf, x->client[i]);
    PUTH32(buf, x->pkts_upload);
    PUTH32(buf, x->pkts_download);
    PUTH32(buf, x->adhoc);
    
    return sizeof(FLOWDESC);
}


static size_t
load(__unused void * self, char * buf, size_t len, timestamp_t * ts)
{   
    if (len < sizeof(FLOWDESC)) {
        ts = 0;
        return 0;
    }

    *ts = NTOHLL(((FLOWDESC *)buf)->ts);
    return sizeof(FLOWDESC);
}

#define PRETTYHDR		\
    "Date                     Mode           AP                pkts_down \
Client              pkts_up\n"
#define PRETTYFMT	"%.24s %14s %s %9u %s %9u\n"
#define PLAINFMT	"%d %s %s %u %s %u\n" 

static char *
print(__unused void * self, char *buf, size_t *len, char * const args[])
{
    static char s[512];
    static char * fmt;
    char buff1[64], buff2[64];
    int pkts_ul, pkts_dl;
    timestamp_t ts;
    FLOWDESC *x;
    time_t t;
 
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
    t = TS2SEC(ts);
    pkts_ul = ntohl(x->pkts_upload);
    pkts_dl = ntohl(x->pkts_download);

    mac_addr_to_ascii(x->ap, buff1);
    mac_addr_to_ascii(x->client, buff2);
    
    /* print according to the requested format */
    if (fmt == PRETTYFMT) {
	*len = sprintf(s, fmt, asctime(localtime(&t)), \
                    x->adhoc ? "Ad-Hoc" : "Infrastructure",
		    buff1, pkts_dl, buff2, pkts_ul);
    } else {
	*len = sprintf(s, fmt, (long int) t, x->adhoc ? "adhoc" : "infra",
		   buff1, pkts_dl, buff2, pkts_ul);
    }

    return s;
}


MODULE(assoc) = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0,
    st_recordsize: sizeof(FLOWDESC),
    capabilities: {has_flexible_flush: 0, 0},
    init: init,
    check: check,
    hash: hash,
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

