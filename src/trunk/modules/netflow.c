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
 * LIABILITY, OR TORT INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id$
 */

#include <stdio.h>      /* fprintf, stderr */
#include <time.h>	/* strftime, localtime */
#include <assert.h>

#include "como.h"
#include "module.h"
#include "rebuild.h"

/* XXX: keep this value low while work is in progress */
#define NETFLOW_TIMEOUT		3	/* timeout in seconds */

/*
 * This module has two goals:
 *   - to provide netflow information (emulating, to the extent where this
 *   is possible, the behaviour of an actual netflow-enabled router)
 *   - to save its data in flow-tools compliant files
 *
 * To read actual flow-tools files obtained elsewhere, please refer to
 * sniffer-flowtools.
 *
 * > Version information
 * Support is provided only for Netflow version 5 (basic 5-tuple
 * aggregation). The flow-tools file format is v3.
 *
 * XXX: TODO: to achieve flow-tools file format compliance without actually
 * linking libft in (which is a problem as it requires to be patched in
 * order to work on buffers instead of files), we have to print out a
 * pre-built compliant header. This is not currently done. Among the other
 * things, a new API should allow to close a storage file on a module's
 * request.
 *   Consequently, such header is not read as well.
 *
 * TODO: Support for zlib compression could be added to achieve better disk
 * space usage while remaining compliant with the flowtools format; it is
 * not required though and would require some changes in some of the
 * callbacks semantics (because you could not extract the timestamp of a
 * single record without buffering the ones before and possibly even
 * someone after).
 */

#define FLOWDESC        struct flow_desc
#define EFLOWDESC       FLOWDESC

static pktdesc_t reqs, bid;

/**
 * This structure is roughly the same as fts3rec_v5 from flow-tools.
 * The flow-tools software package is
 * Copyright (c) 2001 Mark Fullmer and The Ohio State University
 * All rights reserved.
 * See above for terms and conditions.
 * XXX: replication needed in order to avoid including "ftlib.h" which is a
 * very good thing as this module will compile and run even without having
 * libft from the flow-tools package installed
 */
struct fts3rec_v5 {
  uint32_t unix_secs;      /* Current seconds since 0000 UTC 1970 */
  uint32_t unix_nsecs;     /* Residual nanoseconds since 0000 UTC 1970 */
  uint32_t sysUpTime;      /* Current time in millisecs since router booted */
  uint32_t exaddr;         /* Exporter IP address */
  uint32_t srcaddr;        /* Source IP Address */
  uint32_t dstaddr;        /* Destination IP Address */
  uint32_t nexthop;        /* Next hop router's IP Address */
  uint16_t input;          /* Input interface index */
  uint16_t output;         /* Output interface index */
  uint32_t dPkts;          /* Packets sent in Duration */
  uint32_t dOctets;        /* Octets sent in Duration. */
  uint32_t First;          /* SysUptime at start of flow */
  uint32_t Last;           /* and of last packet of flow */
  uint16_t srcport;        /* TCP/UDP source port number or equivalent */
  uint16_t dstport;        /* TCP/UDP destination port number or equiv */
  uint8_t  prot;           /* IP protocol, e.g., 6=TCP, 17=UDP, ... */
  uint8_t  tos;            /* IP Type-of-Service */
  uint8_t  tcp_flags;      /* OR of TCP header bits */
  uint8_t  pad;
  uint8_t  engine_type;    /* Type of flow switching engine (RP,VIP,etc.) */
  uint8_t  engine_id;      /* Slot number of the flow switching engine */
  uint8_t  src_mask;       /* mask length of source address */
  uint8_t  dst_mask;       /* mask length of destination address */
  uint16_t src_as;         /* AS of source address */
  uint16_t dst_as;         /* AS of destination address */
};

pkt_t netflow_gen_template(void *s);

struct flow_desc {
    rec_t rec;
    struct fts3rec_v5 nf5;
};

/* storeable records before a forced emission (possibly in the wrong order) */
#define LOC_BUF_SIZE    10000

/*
 * allow packet emission when the maximum timestamp seen so far minus the
 * lowest is greater than TIME_WINDOW
 */
#define TIME_WINDOW     TIME2TS(2 * NETFLOW_TIMEOUT,0)

static reb_t *f;

__inline static uint32_t
get_uptime(timestamp_t ts)
{
    /* XXX: arbitrary start */
    return ((ts - TIME2TS(1109696337,0)) * 1000) >> 32;
}

static int
init(__unused void *mem, __unused size_t msize, __unused char **args)
{
    f = reb_init(TIME_WINDOW, LOC_BUF_SIZE, netflow_gen_template,
                sizeof(struct fts3rec_v5));
    if (f == NULL)
        return -1;
    
    memset(&reqs, 0, sizeof(reqs));
    
    N32(reqs.bm.ih.src_ip) = 0xffffffff;
    N32(reqs.bm.ih.dst_ip) = 0xffffffff;
    reqs.bm.ih.proto = 0xff;
    N16(reqs.bm.tcph.src_port) = 0xffff;
    N16(reqs.bm.tcph.dst_port) = 0xffff;
    reqs.bm.tcph.flags = 0xff;
    N16(reqs.bm.udph.src_port) = 0xffff;
    N16(reqs.bm.udph.dst_port) = 0xffff;
    reqs.bm.icmph.type = 0xff; /* XXX ?!? */
    reqs.bm.icmph.code = 0xff;
    
    bid = reqs;
    N16(bid.bm.ih.len) = 0xffff;
    bid.ts = TIME2TS(NETFLOW_TIMEOUT, 0);
    
    return 0;
}

/*
 * This hash function is roughly based on the djb2 algorithm
 * TODO: performance analysis
 */
static uint32_t
hash(pkt_t *pkt)
{
    uint32_t hashv = 5381;
    if (pkt->l3type == ETH_P_IP) {
	hashv = (hashv << 5) + hashv + H32(IP(src_ip));
	hashv = (hashv << 5) + hashv + H32(IP(dst_ip));
	hashv = (hashv << 5)+ hashv + IP(proto);
	switch (IP(proto)) {
	case IPPROTO_TCP:
	    hashv = (hashv << 5) + hashv + H16(TCP(src_port));
	    hashv = (hashv << 5) + hashv + H16(TCP(dst_port));
	    break;
	case IPPROTO_UDP:
	    hashv = (hashv << 5) + hashv + H16(UDP(src_port));
	    hashv = (hashv << 5) + hashv + H16(UDP(dst_port));
	    break;
	case IPPROTO_ICMP:
	    hashv = (hashv << 5) + hashv + ICMP(type);
	    hashv = (hashv << 5) + hashv + ICMP(code);
	    break;
	}
    } else
	hashv = 0;
    return hashv;
}

/*
 * The match is performed on the 5-tuple for TCP and UDP, only protocol and
 * IP addresses are checked otherwise
 */
static int
match(pkt_t *pkt, rec_t *fh)
{
    FLOWDESC *xx = F(fh);
    struct fts3rec_v5 *x = &xx->nf5;

    if (pkt->l3type == ETH_P_IP)
	return H32(IP(src_ip)) == x->srcaddr &&
	    H32(IP(dst_ip)) == x->dstaddr &&
	    IP(proto) == x->prot &&
	    ( (x->prot == IPPROTO_UDP || x->prot == IPPROTO_TCP) &&
	      H16(TCPUDP(src_port)) == x->srcport &&
	      H16(TCPUDP(dst_port)) == x->dstport) ||
	    (x->prot != IPPROTO_UDP && x->prot != IPPROTO_TCP);
    else
	return x->dstaddr == 0;
}

static int
update(pkt_t *pkt, rec_t *fh, int is_new, __unused unsigned drop_cntr)
{
    FLOWDESC *xx = F(fh);
    struct fts3rec_v5 *x = &xx->nf5;
    
    if (is_new) {
	if (pkt->l3type == ETH_P_IP) {
	    x->srcaddr = H32(IP(src_ip));
	    x->dstaddr = H32(IP(dst_ip));
	    switch (x->prot = IP(proto)) {
	    case IPPROTO_TCP:
		x->tcp_flags = TCP(flags);
	    case IPPROTO_UDP:
		x->srcport = H16(TCPUDP(src_port));
		x->dstport = H16(TCPUDP(dst_port));
		break;
	    }
	    x->tos = IP(tos);
        }

        x->dPkts = x->dOctets = 0;
        x->First = get_uptime(pkt->ts);

	/*
	 * Please note that right now we cannot provide meaningful values
	 * for those fields involving data known only to routers, such as
	 * information on autonomous systems, masks, snmp indexes, etc.
	 */
    }
    
    /* 
     * here I am sure that every ts is >= than the preceding one
     * because I assume that the packets arrive in order
     * XXX: TODO: program defensively
     */
    x->unix_secs = TS2SEC(pkt->ts);
    x->unix_nsecs = TS2USEC(pkt->ts);
    x->Last = x->sysUpTime = get_uptime(pkt->ts);
    /*
     * it is *not* useless to update sysUpTime (as previously stated here)
     * because it is needed to compute the actual flow start and end time
     */
    
    x->dPkts++;
    if (pkt->l3type == ETH_P_IP)
	x->dOctets += H16(IP(len));
    
    return 0;
    /*
     * We could return 1 if we detected that the tcp flow is closing, but
     * even then the records would be merged again by export
     */
}

static int
ematch(rec_t *eh, rec_t *fh)
{
    FLOWDESC *xx = F(fh);
    struct fts3rec_v5 *x = &xx->nf5;
    EFLOWDESC *exx = EF(eh);
    struct fts3rec_v5 *ex = &exx->nf5;
    
    return ex->srcaddr == x->srcaddr &&
        ex->dstaddr == x->dstaddr &&
        ex->prot == x->prot &&
        ex->srcport == x->srcport &&
        ex->dstport == x->dstport;
}

static int
export(rec_t *efh, rec_t *fh, int is_new)
{
    FLOWDESC *xx = F(fh);
    struct fts3rec_v5 *x = &xx->nf5;
    EFLOWDESC *exx = EF(efh);
    struct fts3rec_v5 *ex = &exx->nf5;
    
    if (is_new) {
        ex->srcaddr = x->srcaddr;
        ex->dstaddr = x->dstaddr;
        ex->prot = x->prot;
        ex->srcport = x->srcport;
        ex->dstport = x->dstport;
        ex->tcp_flags = x->tcp_flags;
        ex->tos = x->tos;
        
        ex->dPkts = 0;
        ex->dOctets = 0;
        
        ex->First = x->First;
        
        ex->unix_secs = ex->unix_nsecs = 0;
    }
    
    if (TIMEVAL2TS(x) > TIMEVAL2TS(ex)) {
        ex->unix_secs = x->unix_secs;
        ex->unix_nsecs = x->unix_nsecs;
        ex->Last = ex->sysUpTime = x->sysUpTime;
        assert(x->sysUpTime == x->Last);
    }
    ex->dPkts += x->dPkts;
    ex->dOctets += x->dOctets;
    
    return 0;
}

/*
 * We have to sort the records with respect to their time in order to allow
 * action() to handle their timeout.
 */
static int
compare(const void *efh1, const void *efh2)
{
    EFLOWDESC *ex1 = CMPEF(efh1);
    EFLOWDESC *ex2 = CMPEF(efh2);

    return ((ex1->nf5.Last > ex2->nf5.Last)? 1 : -1);
}

static int
action(rec_t *fh, timestamp_t t, __unused int count)
{
    EFLOWDESC *ex = EF(fh);
    
    if (fh == NULL)
        return ACT_GO;
    
    if (t - TIMEVAL2TS(&ex->nf5) > NETFLOW_TIMEOUT)
        return ACT_STORE | ACT_DISCARD;
    
    return ACT_STOP;
}

static int
store(rec_t *efh, char *buf, size_t len)
{
    EFLOWDESC *ex = EF(efh);
    struct fts3rec_v5 *rec = &ex->nf5;
    
    if (len < sizeof(struct fts3rec_v5))
        return -1; /* configuration error */
    
    /*
     * XXX: this is not flowtools format yet
     */
    PUTH32(buf, rec->unix_secs);
    PUTH32(buf + 4, rec->unix_nsecs);
    PUTH32(buf + 8, rec->sysUpTime);
    PUTH32(buf + 12, rec->exaddr);      /* not used */
    PUTH32(buf + 16, rec->srcaddr);
    PUTH32(buf + 20, rec->dstaddr);
    PUTH32(buf + 24, rec->nexthop);
    PUTH16(buf + 28, rec->input);
    PUTH16(buf + 30, rec->output);
    PUTH32(buf + 32, rec->dPkts);
    PUTH32(buf + 36, rec->dOctets);
    PUTH32(buf + 40, rec->First);
    PUTH32(buf + 44, rec->Last);
    PUTH16(buf + 48, rec->srcport);
    PUTH16(buf + 50, rec->dstport);
    PUTH8(buf + 52, rec->prot);
    PUTH8(buf + 53, rec->tos);
    PUTH8(buf + 54, rec->tcp_flags);
    PUTH8(buf + 55, rec->pad);          /* not used */
    PUTH8(buf + 56, rec->engine_type);  /* not used */
    PUTH8(buf + 57, rec->engine_id);    /* not used */
    PUTH8(buf + 58, rec->src_mask);     /* not used */
    PUTH8(buf + 59, rec->dst_mask);     /* not used */
    PUTH16(buf + 60, rec->src_as);      /* not used */
    PUTH16(buf + 62, rec->dst_as);      /* not used */
    
    return sizeof(struct fts3rec_v5);
}

static size_t
load(char *buf, size_t len, timestamp_t *ts)
{    
    if (len < sizeof(struct fts3rec_v5))
        return 0; /* configuration error | lost sync */
    
    *ts = TIME2TS(ntohl(*(uint32_t*)buf), ntohl(*(uint32_t*)(buf + 4)));
    
    return sizeof(struct fts3rec_v5);
}

/**
 * revert_fields
 * revert back a struct fts3rec_v5's fields from network to host byte order
 */
#define NTOH32(a)       (a=ntohl(a))
#define NTOH16(a)       (a=ntohs(a))

__inline static void
revert_fields(struct fts3rec_v5 *rec) {
    NTOH32(rec->unix_secs);
    NTOH32(rec->unix_nsecs);
    NTOH32(rec->sysUpTime);
    NTOH32(rec->exaddr);        /* not used */
    NTOH32(rec->srcaddr);
    NTOH32(rec->dstaddr);
    NTOH32(rec->nexthop);
    NTOH16(rec->input);
    NTOH16(rec->output);
    NTOH32(rec->dPkts);
    NTOH32(rec->dOctets);
    NTOH32(rec->First);
    NTOH32(rec->Last);
    NTOH16(rec->srcport);
    NTOH16(rec->dstport);
    NTOH16(rec->src_as);        /* not used */
    NTOH16(rec->dst_as);        /* not used */
}

/* 
 * XXX: the print function is just an outline and should be regarded as
 * 	provisional
 */
static char*
print(char *buf, size_t *len, __unused char * const args[])
{
    static char s[2048];     /* XXX really ugly... */ 
    char *out = s;
    static char tss[20];
    typedef char ipaddr[16];
    char* protstr;
    ipaddr src, dst;
    static uint32_t up_since = 0;
    uint32_t us_time;
    struct fts3rec_v5 rec;

    rec = *(struct fts3rec_v5*)buf;
    
    /* call inet_ntoa *before* reverting fields back to host byte order */
    strncpy(src, inet_ntoa(*(struct in_addr*)&rec.srcaddr), 16);
    strncpy(dst, inet_ntoa(*(struct in_addr*)&rec.dstaddr), 16);
    
    revert_fields(&rec);
    
    strftime(tss, 20, "%b %e %T", localtime((time_t*)&rec.unix_secs));
    us_time = rec.unix_secs - rec.sysUpTime/1000;
    if (us_time != up_since) {
        static char tsr[30];
        up_since = us_time;
        strftime(tsr, 30, "%Y %b %e %T", localtime((time_t*)&up_since));
        printf("Router running since %s\n", tsr );
    }
    
    asprintf(&protstr, "%d", rec.prot);
    
    out += sprintf(out, "%s:%03u "
        "(%5dp:%6dB) "
        "[%3s] "
        "%15s:%5d > %15s:%5d"
        "\n",
        tss, rec.unix_nsecs,
        rec.dPkts, rec.dOctets,
        rec.prot == 6 ? "TCP" : rec.prot == 17 ? "UDP" : protstr,
        src, rec.srcport, dst, rec.dstport
    );
    
    *len = strlen(s);

    return s;
}

static int
dump(char *buf, pkt_t *out, uint maxpkts) {
    struct fts3rec_v5 *rec, arec;
    timestamp_t min_time;
    uint npkts = 0;

    /* get the current flow record in host byte order */
    arec = *(struct fts3rec_v5*)buf;
    rec = &arec;
    revert_fields(rec);
    
    if (reb_is_full(f))
        npkts += reb_emit_pkts(f, out, 1, maxpkts);
    
    min_time = TIMEVAL2TS(rec) - TIME2TS(0, (rec->sysUpTime - rec->First) * 1000);
    reb_add_flow(f, rec, min_time, TIMEVAL2TS(rec), rec->dPkts);
    
    /*
     * XXX: we need a way to allow flushing of old data
     * this necessarily imposes changes in the dump definition
     */
    
    return npkts += reb_emit_pkts(f, out + npkts, 0, maxpkts - npkts);
}

callbacks_t callbacks = {
    sizeof(FLOWDESC), 
    sizeof(EFLOWDESC), 

    &reqs,
    &bid,
    
    init,
    NULL,	/* check() */
    hash,
    match,
    update,

    ematch,
    export,
    compare,
    action,
    store,

    load,
    print,
    dump
};

