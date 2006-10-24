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
 * Traffic Matrix
 */

#include <stdio.h>
#include <time.h>
#include "module.h"
#include "uhash.h"
#include "macutils.h"

#define MAX_ADDRS 1024
#define MAX_ORG_LEN 16

#define FLOWDESC    struct _counter
FLOWDESC {
    timestamp_t ts;
    uint8_t     src_addr[MAC_ADDR_SIZE];
    uint8_t     dst_addr[MAC_ADDR_SIZE];
    uint64_t    bytes;
    uint64_t    pkts;
};


#define CONFIGDESC config_t
typedef struct {
    int meas_ivl;	/* measurement interval */
    int naddr;          /* number of configured addrs */
    uhash_t uhash;
    uint8_t addr_list[MAX_ADDRS][MAC_ADDR_SIZE];
    char orgs[MAX_ADDRS][MAX_ORG_LEN + 1];
} config_t;

static timestamp_t 
init(void * self, char *args[])
{
    config_t * config; 
    int i;
    pkt_t *pkt;
    metadesc_t *inmd;

    config = mem_mdl_malloc(self, sizeof(config_t)); 
    config->meas_ivl = 1;
    config->naddr = 0;
    uhash_initialize(&config->uhash);

    for (i = 0; args && args[i]; i++) {
	char * wh = index(args[i], '=') + 1;

        if (strstr(args[i], "interval"))
            config->meas_ivl = atoi(wh);

        if (strstr(args[i], "cfgfile")) {
            /*
             * XXX I am breaking the rules. Modules
             *     should never do syscalls. To be fixed.
             *     Do not take as an example.
             */
            FILE *fp = fopen(wh, "r");

            if (fp == NULL) { /* fail to open file */
                printf("warning: traffic-matrix fails to open config "
                    "file '%s'\n", wh);
                continue;
            }
            for (;;) {
                char addr[1024], org[1024];
                char *ptr;
                int ret, j;

                ret = fscanf(fp, "%1024s %1024s", addr, org);
                if (ret != 2) /* either parse error or eof */
                    break;
                if (config->naddr == MAX_ADDRS) {
                    printf("warning: too many definitions in file "
                        "'%s', max definitions set to %d\n", wh, MAX_ADDRS);
                    break; /* too many defs */
                }

                for (j = 0, ptr = addr; j < MAC_ADDR_SIZE; j++) {
                    unsigned int ui;
                    ret = sscanf(ptr, "%2x", &ui);
                    if (ret != 1 || ui & 0xffffff00)
                        break;
                    config->addr_list[config->naddr][j] = (uint8_t) ui;
                    ptr += 3;
                }

                if (j != MAC_ADDR_SIZE)
                    printf("warning: parse error. cannot parse MAC "
                            "address '%s'\n", addr);
                else {
                    strncpy(config->orgs[config->naddr], org, MAX_ORG_LEN);
                    config->naddr++;
                }
            }
            fclose(fp);
        }
    }
    
    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = TIME2TS(config->meas_ivl, 0);
    
    pkt = metadesc_tpl_add(inmd, "none:none:none:none");
    
    CONFIG(self) = config;
    return TIME2TS(config->meas_ivl, 0);
}

static int
match(__unused void *self, pkt_t *pkt, void *fh)
{
    FLOWDESC *x = F(fh);
    return memcmp(ETH(src), x->src_addr, MAC_ADDR_SIZE) == 0 &&
           memcmp(ETH(dst), x->dst_addr, MAC_ADDR_SIZE) == 0;
}

static uint32_t
hash(void *self, pkt_t *pkt)
{
    CONFIGDESC * config = CONFIG(self);
    uint32_t h;

    h = uhash(&config->uhash, (uint8_t*)&ETH(src), MAC_ADDR_SIZE, UHASH_NEW);
    h = uhash(&config->uhash, (uint8_t*)&ETH(dst), MAC_ADDR_SIZE, UHASH_APPEND);
    return h;
}


static int
update(__unused void * self, pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);

    if (isnew) {
	bzero(x, sizeof(FLOWDESC));
	x->ts = COMO(ts);
        memcpy(x->src_addr, &ETH(src), MAC_ADDR_SIZE);
        memcpy(x->dst_addr, &ETH(dst), MAC_ADDR_SIZE);
    }

    if (isNF) {
        x->bytes += H32(NF(pktcount)) * COMO(len) * H16(NF(sampling));
        x->pkts += H32(NF(pktcount)) * (uint32_t) H16(NF(sampling));
    } else if (isSFLOW) {
	x->bytes += (uint64_t) COMO(len) * 
		      (uint64_t) H32(SFLOW(sampling_rate));
	x->pkts += H32(SFLOW(sampling_rate));
    } else {
	x->bytes += COMO(len);
        x->pkts++;
    }

    return 0;
}


static ssize_t
store(__unused void * self, void *rp, char *buf)
{
    FLOWDESC *x = F(rp);
    int i;

    PUTH64(buf, x->ts);
    for (i = 0; i < MAC_ADDR_SIZE; i++)
        PUTH8(buf, x->src_addr[i]);
    for (i = 0; i < MAC_ADDR_SIZE; i++)
        PUTH8(buf, x->dst_addr[i]);
    PUTH64(buf, x->bytes);
    PUTH64(buf, x->pkts);

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


/*
 * locate_addr
 *
 * Auxiliary function to build the traffic matrix. It returns an index
 * for the address if found, otherwise -1.
 */
static int
locate_addr(config_t *cfg, uint8_t *addr)
{
    int pos;

    for (pos = 0; pos < cfg->naddr; pos++)
        if (memcmp(addr, cfg->addr_list[pos], MAC_ADDR_SIZE) == 0)
            break;

    return pos == cfg->naddr ? -1 : pos;
}

#define PLAINFMT	"%12ld %16llu %12llu %12u\n"
#define HTMLFMT         ""

static char *
print(__unused void * self, char *buf, size_t *len, char * const args[])
{
    static uint64_t matrix[MAX_ADDRS][MAX_ADDRS];
    static char s[512];
    static char * fmt; 
    static int use_bytes = 1; 
    static int64_t count = 0;
    config_t * config = CONFIG(self); 
    FLOWDESC rec; 
    int n, x, y;
    char b1[128], b2[128];

    if (buf == NULL && args != NULL) { 
	*len = 0;
	fmt = PLAINFMT; 
        use_bytes = 1;
        memset(matrix, '\0', sizeof(matrix));

	/* first call of print, process the arguments and return */
	for (n = 0; args[n]; n++) {
	    if (!strcmp(args[n], "format=plain")) {
                fmt = PLAINFMT;
	    } else if (!strcmp(args[n], "format=conversation_graph")) {
		fmt = PLAINFMT;
	    } else if (!strcmp(args[n], "format=html")) {
		fmt = HTMLFMT;
            } else if (!strcmp(args[n], "usebytes=yes")) {
                use_bytes = 1;
            } else if (!strcmp(args[n], "usebytes=no")) {
                use_bytes = 0;
	    }
	} 
	return s; 
    } 

    if (buf == NULL && args == NULL) { 
	*len = 0;
        char mac[128];

        for(x = 0; x < config->naddr; x++) {
            pretty_mac(config->addr_list[x], mac, 128, 0);
            *len += sprintf(s + *len, "%s,%s", config->orgs[x], mac);
            for (y = 0; y < config->naddr; y++) {
                *len += sprintf(s + *len, ",%lld", matrix[x][y]);
            }
            *len += sprintf(s + *len, "\n");
        }
	return s; 
    } 

    memcpy(&rec, buf, sizeof(FLOWDESC)); 
    rec.ts = NTOHLL(rec.ts);
    rec.bytes = NTOHLL(rec.bytes);
    rec.bytes = NTOHLL(rec.bytes);

    /* fill the matrix */

    pretty_mac(rec.src_addr, b1, 128, 0);
    pretty_mac(rec.dst_addr, b2, 128, 0);
    x = locate_addr(config, rec.src_addr);
    y = locate_addr(config, rec.dst_addr);
    count = use_bytes ? NTOHLL(rec.bytes) : ntohl(rec.pkts);

    if (x != -1 && y != -1 && x != y) /* fill the traffic matrix */
        matrix[x][y] += count;

    *len = 0;
    return s;
}

MODULE(traffic-matrix) = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0,
    st_recordsize: sizeof(FLOWDESC),
    capabilities: {has_flexible_flush: 0, 0},
    init: init,
    check: NULL,
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
    formats: "html plain conversation_graph"
};

