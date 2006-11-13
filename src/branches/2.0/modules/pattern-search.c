/*
 * Copyright (c) 2006, Intel Corporation
 * Copyright (c) 2006, Universitat Politecnica de Catalunya
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
 * $Id:pattern-search.c 978 2006-11-01 15:23:18 +0000 (Wed, 01 Nov 2006) m_canini $
 */

/*
 * Pattern search module
 *
 * This module collects a packet level trace, only with the packets
 * that contain a predefined pattern inside their data
 *
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
#include "printpkt.h"
#include "pattern_search.h"              /* Boyer-Moore pattern search */

/* 
 * FLOWDESC just contains one packet. 
 * We will always match the record in the table so that CAPTURE will 
 * create a nice queue of packets for us and EXPORT will process it in 
 * FIFO order. 
 */
#define FLOWDESC	struct _pattern_search_flowdesc

FLOWDESC {
    int len; 
#define BUFSIZE 2048
    char buf[BUFSIZE]; 
};

#define SNAPLEN_MAX (BUFSIZE - sizeof(pkt_t))

#define CONFIGDESC      struct _pattern_search_config
CONFIGDESC {
    unsigned snaplen; /* bytes to capture in each packet */
    pattern_search_t psearch; /* pattern search info */
    int fmt;          /* query format */
};

static timestamp_t 
init(void * self, char * args[])
{
    CONFIGDESC *config;
    metadesc_t *inmd, *outmd;
    pkt_t *pkt;
    int i;

    config = mem_mdl_malloc(self, sizeof(CONFIGDESC));
    config->snaplen = SNAPLEN_MAX;
    pattern_search_initialize(&config->psearch, "");

    for (i = 0; args && args[i]; i++) {
	if (strstr(args[i], "snaplen=")) { 
	    char * len = index(args[i], '=') + 1; 
	    config->snaplen = atoi(len);    /* set the snaplen */
	} 
	if (strstr(args[i], "pattern=")) { 
	    char * pat = index(args[i], '=') + 1;
            pattern_search_initialize(&config->psearch, pat);
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
check(void * self, pkt_t *pkt)
{
    CONFIGDESC *config = CONFIG(self);

    return pattern_search(&config->psearch, COMO(payload), COMO(caplen), NULL);
}

static int
update(void * self, pkt_t *pkt, void *fh, int isnew)
{
    CONFIGDESC *config = CONFIG(self);
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
store(void *self, void *fh, char *buf)
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
load(void *self, char * buf, size_t len, timestamp_t * ts)
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

#define PRETTYFMT 		0
#define PCAPFMT			1

static char *
print(void * self, char *buf, size_t *len, char * const args[])
{
    CONFIGDESC * config = CONFIG(self);
    static char s[65536]; 
    pkt_t p, pktbuf, *pkt;
    int n; 

    if (buf == NULL && args != NULL) { 
	/* first call, process the arguments */
        for (n = 0; args[n]; n++) {
            if (!strcmp(args[n], "format=pcap")) {
                *len = print_pcap_file_header(s);
                config->fmt = PCAPFMT;
		return s; 
            }
        }
        *len = 0;
        config->fmt = PRETTYFMT;
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

    if (config->fmt == PCAPFMT)
	*len = print_pkt_pcap(pkt, s);
    else {
	*len = print_pkt_pretty(pkt, s, PRINTPKT_L2 | PRINTPKT_L3);
        *len += sprintf(s + *len, "\n");
    }
    return s; 
}

static int  
replay(void * self, char *buf, char *out, size_t * len,
        int left)
{
    pkt_t * pkt = (pkt_t *) buf; 
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
    return 0;	
}


MODULE(pattern_search) = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0, 
    st_recordsize: sizeof(FLOWDESC),
    capabilities: {has_flexible_flush: 1, 0},
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
    replay: replay,
    formats: "pretty pcap"
};

