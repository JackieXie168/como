/*
 * Copyright (c) 2007 Universitat Politecnica de Catalunya
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
 */

/*
 * Port-scanner Detection Module.
 *
 * Author: Derek Hossack Lopez (UPC, Barcelona)
 *
 * This module detects potentially malicious hosts by tracking the TCP 3-way 
 * handshake at the beggining of a TCP connection.
 *
 * If a source IP sends SYNs without any answer to more than 's_thresh' 
 * destinations, it is considered to be a scanner. From that moment on, all 
 * traffic from this IP is stored onto disk.
 *
 * If the input stream is undirectional, it checks instead if the packet 
 * with the initial sequence number + 1 is sent.
 *
 * This module is inspired on the method described in "Autograph: Toward
 * Automated, Distributed Worm Signature Detection" by Hyang-Ak Kim and Brad
 * Karp.
 *
 */
        
#include <stdio.h>
#include <time.h>

#include "module.h"
#include "hash.h"
#include "printpkt.h"

#define FLOWDESC    struct _scanner_detect_cap
#define EFLOWDESC   struct _scanner_detect_exp
#define CONFIGDESC  struct _scanner_config

#define SYN         0x02
#define SYN_ACK     0x12

/* possible status for EFLOWDESC->tcp_status */
/* EFLOWDESC contains a packet that is not a connection initiation packet */
#define NON_SYN     0
/* EFLOWDESC contains a SYN waiting for the corresponding ACK */
#define SYN_SENT    1
/* EFLOWDESC contains a SYN already answered */
#define SYN_ACK_SENT    2

/* possible status for EFLOWDESC->pkt_status */
/* EFLOWDESC contains a suspicious packet - will be stored */
#define SUSPICIOUS  3
/* EFLOWDESC contains a normal packet - will be discarded */
#define NON_SUSPICIOUS  4 

/* print formats */
#define PRETTYFMT       0
#define PCAPFMT         1

struct _suspicious_ip
{
    /* ip address */
    uint32_t ip;
    
    /* number of failed connections until the moment */
    uint32_t num;
    
    /* timestamp of last failed connection */
    timestamp_t last;   
    
    /* list of ips to which this ip has made failed connections */
    hash_t *fail_list;  
};
typedef struct _suspicious_ip suspicious_ip;

struct _fail
{
    uint32_t ip;
    uint16_t port;
};
typedef struct _fail fail;

FLOWDESC 
{
    int len; 
    char buf[2000];
};

EFLOWDESC
{
    timestamp_t ts;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    
    int tcp_status;
    int pkt_status;  
    
    /*
     * sequence number of the SYN, for checking scanners without bidirectional
     * traffic
     */
    uint32_t syn_seq;
    
    char buf[2000];
};

CONFIGDESC
{
    /* 
     * minimum number of failed connections (SYN's without SYN-ACK) for a
     * src_ip to be considered a scanner.
     */
    uint32_t s_thresh;

    /* timeout to consider a SYN unanswered */
    timestamp_t syn_timeout;    

    /* timeout to consider a suspicious IP non-suspicious again */
    timestamp_t ip_timeout;

    /* hash table containing of suspicious ips */
    hash_t *suspicious_ip_list; 

    int format;
    int discard_incomplete_pkt;

    /* internal network information */
    uint32_t network;
    uint32_t netmask;

    /* use uni-directional traffic to detect scanners */
    int unidirectional;
};

static uint 
hash_function(const void *key)
{
    return (uint)((uint32_t)key);
}

static int
key_cmp_function(const void *key1, const void *key2)
{
    if ((uint32_t)key1 == (uint32_t)key2)
    {
        return 0;
    }
    
    return 1;
}

/* Determine if IP is inside or outside network */
static int
isInternalIP(uint32_t ip, CONFIGDESC *config)
{
    int ret = 0;
    struct in_addr addr;
    
    addr.s_addr = 0;
    addr.s_addr = ip;
    
    if ((ip & config->netmask) == config->network)
        ret = 1;

    return ret;
}

/* Functions to manage de suspicious IP list */

static suspicious_ip*
get_suspicious (uint32_t ip, CONFIGDESC *config)
{
    return  (suspicious_ip *)hash_lookup_ulong(config->suspicious_ip_list, ip);
}

static int
remove_suspicious(suspicious_ip *elem, CONFIGDESC *config)
{
    return  hash_remove_ulong(config->suspicious_ip_list, elem->ip);
}

static int
is_suspicious (uint32_t ip, timestamp_t now, void * self)
{
    struct in_addr addr;
    
    CONFIGDESC *config = CONFIG(self);
    
    suspicious_ip *elem;
    elem = get_suspicious(ip, config);
    
    if (elem == NULL || (elem->num < config->s_thresh)) {
        return 0;
    }
    else {
        if ((TS2SEC(now) - TS2SEC(elem->last)) > TS2SEC(config->ip_timeout)) {
            /* the IP was suspicious, but not any more */
            addr.s_addr = elem->ip;
            remove_suspicious(elem, config);
            hash_destroy(elem->fail_list);
            
            mem_mdl_free(self, elem);
            return 0;
        }
        else {
            return 1;
        }
    }
}

static void
add_fail (uint32_t ip, uint32_t dst_ip, timestamp_t ts, void * self)
{
    
    CONFIGDESC *config = CONFIG(self);
    
    suspicious_ip *elem;
    
    module_t * mdl = self;
    
    struct in_addr addr;
    
    elem = get_suspicious(ip, config);
    
    if (elem != NULL) {
        uint32_t * aux;
        aux = (uint32_t *) hash_lookup_ulong(elem->fail_list, dst_ip);

        if (aux == NULL) {
            /*
             * this IP has not been scanned yet, so add to list, 
             * and increment NUM
             */
            
            elem->num++;
            hash_insert_ulong(elem->fail_list, dst_ip, &dst_ip);
            
        }
        
        /* in any case, the 'last' timestamp must be updated to current time */
        elem->last = ts;
    }
    else {
        elem = (suspicious_ip *)mem_mdl_malloc(self, sizeof(suspicious_ip));

        elem->ip = ip;
        elem->last = ts;
        elem->num = 1;
        
        elem->fail_list = hash_new(&(mdl->alc), HASHKEYS_ULONG, hash_function,
        key_cmp_function);
        
        /* add to this suspicious IP list of scanned ips */
        hash_insert_ulong(elem->fail_list, dst_ip, &dst_ip);
        
        /* its a new suspicious_ip item -> add to main suspicious IP list */
        hash_insert_ulong(config->suspicious_ip_list, elem->ip, elem);
    }
}

static timestamp_t
init(void *self, char *args[])
{
    CONFIGDESC *config;
    metadesc_t *inmd, *outmd;
    pkt_t *pkt;
    int i;
    
    module_t * mdl = self;
    
    struct in_addr addr;
    
    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    
    pkt = metadesc_tpl_add(inmd, "any:any:~ip:~tcp");
    N16(TCP(src_port)) = 0xffff;
    N16(TCP(dst_port)) = 0xffff;
    IP(proto) = IPPROTO_TCP;
    N16(IP(len)) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    
    /* setup outdesc */
    outmd = metadesc_define_out(self, 0);
    
    pkt = metadesc_tpl_add(outmd, "any:any:any:any");
    
    config = (CONFIGDESC *)mem_mdl_malloc(self, sizeof(CONFIGDESC));
    
    /* default values for config parameters */
    config->s_thresh = 3;
    config->ip_timeout = TIME2TS(86400, 0);
    config->syn_timeout = TIME2TS(300, 0);
    config->discard_incomplete_pkt = 0;
    config->network = 0;
    config->netmask = 0;
    config->unidirectional = 0;
    
    config->suspicious_ip_list = hash_new(&(mdl->alc), HASHKEYS_ULONG,
                                hash_function, key_cmp_function);
    
    for (i = 0; args && args[i]; i++) {
        if (strstr(args[i], "s_thresh=")) {
            char * s_t = index(args[i], '=') + 1; 
            config->s_thresh = atoi(s_t);   
        }
        if (strstr(args[i], "ip_timeout=")) { 
            char * ip_t = index(args[i], '=') + 1; 
            config->ip_timeout = TIME2TS(atoi(ip_t), 0);
        }
        if (strstr(args[i], "syn_timeout=")) {
            char * syn_t = index(args[i], '=') + 1; 
            config->syn_timeout = TIME2TS(atoi(syn_t),0);
        }
        if (strstr(args[i], "discard_incomplete_pkt=")) {
            char * d_pkt = index(args[i], '=') + 1; 
            config->discard_incomplete_pkt = atoi(d_pkt);   
        }
        if (strstr(args[i], "network=")) {
            char * nw = index(args[i], '=') + 1; 
            inet_aton(nw, &addr);
            config->network = addr.s_addr;
        }
        if (strstr(args[i], "netmask=")) {
            char * nm = index(args[i], '=') + 1; 
            inet_aton(nm, &addr);
            config->netmask = addr.s_addr;
        }
        if (strstr(args[i], "unidirectional=")) {
            char * ud = index(args[i], '=') + 1; 
            config->unidirectional = atoi(ud);
        }
    }
    
    CONFIG(self) = config;
    return TIME2TS(1,0);
}

static int
check(void * self, pkt_t *pkt)
{
    CONFIGDESC *config = CONFIG(self);
    uint16_t syn, ack;
    int inbound;
    struct in_addr addr1, addr2;
    
    /* Check for truncated packets */
    if (config->discard_incomplete_pkt && (COMO(caplen) < COMO(len)))
        return 0;
    
    /* 
     * Check that the packet is from an inbound connection (unless it is a 
     * syn/ack)
     */

    syn = TCP(syn);
    ack = TCP(ack);
    
    if (config->network && config->netmask) {
        addr1.s_addr=N32(IP(src_ip));
        addr2.s_addr=N32(IP(dst_ip));

        if (syn && ack) {  
            /*
             * if its a syn/ack, only analyze if source IP is internal, and
             * destination IP is external (syn/ack response comes from inside)
             */
            
            if (!isInternalIP(addr1.s_addr, config) ||
                isInternalIP(addr2.s_addr, config))
                return 0;
        }
        else { 
            /* 
             * if its not a syn/ack, only analyze if source IP is external, and
             * destination IP is internal (only inbound traffic)
             */
            if (!isInternalIP(addr2.s_addr, config) ||
                isInternalIP(addr1.s_addr, config))
                return 0;
        }
    }
    
    return 1;
}

static uint32_t
hash(void * self, pkt_t *pkt)
{
    uint sport;
    uint dport;
    
    
    if (pkt->l3type != ETHERTYPE_IP) 
        return 0; 
    
    sport = N16(TCP(src_port));
    dport = N16(TCP(dst_port));

    return (N32(IP(src_ip)) ^ N32(IP(dst_ip)) ^ (sport << 3) ^ (dport << 3));
}

static int
update(void * self, pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);
    x->len = sizeof(pkt_t) + pkt->caplen;
    
    /* copy the whole packet + como header */
    memcpy(x->buf, pkt, sizeof(pkt_t)); 
    memcpy(x->buf + sizeof(pkt_t), pkt->payload, pkt->caplen); 
    ((pkt_t *) x->buf)->payload = x->buf + sizeof(pkt_t);

    /* records are always full */
    return 1;
}


static int
ematch(void * self, void *efh, void *fh)
{
    pkt_t *pkt;
    uint16_t syn;
    uint16_t ack;
    
    struct in_addr addr;
    
    CONFIGDESC *config = CONFIG(self);
    
    FLOWDESC  *x  = F(fh);
    EFLOWDESC *ex = EF(efh);

    pkt = (pkt_t *)x->buf;
    
    syn = TCP(syn);
    ack = TCP(ack);
    
    if (!config->unidirectional) {
        if (syn) {
            /* it is a SYN or SYN_ACK */
            if (syn && ack) {
                /* 
                 * packet is a SYN-ACK - must match the src_ip as dst_ip, and 
                 * dst_ip as src_ip, to match it with the corresponding SYN.
                 */ 
                return  (
                        ex->src_ip == N32(IP(dst_ip)) && 
                        ex->dst_ip == N32(IP(src_ip)) && 
                        ex->src_port == H16(TCP(dst_port)) && 
                        ex->dst_port == H16(TCP(src_port))
                    );
            }
            else {
                /* packet is a SYN - must match normally */
                return ( 
                        ex->src_ip == N32(IP(src_ip)) && 
                        ex->dst_ip == N32(IP(dst_ip)) && 
                        ex->src_port == H16(TCP(src_port)) && 
                        ex->dst_port == H16(TCP(dst_port))
                       );
            }
        }
    }
    else {
        if((ex->tcp_status == SYN_SENT) && ack) {
            if (ex->src_ip == N32(IP(src_ip)) && 
                ex->dst_ip == N32(IP(dst_ip)) && 
                ex->src_port == H16(TCP(src_port)) && 
                ex->dst_port == H16(TCP(dst_port))) {
                return 1;
            }
            else {
                return 0;
            }
        }
        else {
            return 0;
        }
    }

    return 0;
}

static int
export(void * self, void *efh, void *fh, int isnew)
{
    pkt_t *pkt;
    uint16_t syn;
    uint16_t ack;
    
    int suspicious = 0;
    
    struct in_addr addr;    
    
    suspicious_ip *elem;
    
    FLOWDESC  *x  = F(fh);
    EFLOWDESC *ex = EF(efh);

    CONFIGDESC *config = CONFIG(self);
    
    pkt = (pkt_t *)x->buf;
    syn = TCP(syn);
    ack = TCP(ack);

    if (isnew) {
        ex->pkt_status = NON_SUSPICIOUS;
        ex->tcp_status = NON_SYN;
        
        /* first check if the IP is suspicious */
        suspicious = is_suspicious(N32(IP(src_ip)), pkt->ts, self);
        
        if (suspicious) {
            ex->pkt_status = SUSPICIOUS;
            /* save the whole packet */
            ex->src_ip = N32(IP(src_ip));
            ex->dst_ip = N32(IP(dst_ip));
            ex->src_port = H16(TCP(src_port));
            ex->dst_port = H16(TCP(dst_port));
            ex->ts = pkt->ts;
            
            bzero(ex->buf, 2000);
            memcpy(ex->buf, pkt, sizeof(pkt_t)); 
            memcpy(ex->buf + sizeof(pkt_t), pkt->payload, pkt->caplen); 
            ((pkt_t *)ex->buf)->payload = ex->buf + sizeof(pkt_t);
            
            ex->ts = pkt->ts;
            
            /* dont return yet, as it can be suspicious too (checked now) */
        }
        
        if (syn && !ack) {
            /* save information about the SYN */
            ex->tcp_status = SYN_SENT;
            
            ex->src_ip = N32(IP(src_ip));
            ex->dst_ip = N32(IP(dst_ip));
            ex->src_port = H16(TCP(src_port));
            ex->dst_port = H16(TCP(dst_port));
            ex->syn_seq = H32(TCP(seq));
            
            ex->ts = pkt->ts;
            return 0;
        }
        else {
            /* will be discarded */
            return 1;
        }
    }
    else {
        /* 
         * packet is not new. this should only be possible when the packet is 
         * a SYN/ACK, its the only case that ematch actually matches anything.
         */
        if (!config->unidirectional) {
            if (syn && ack) {
                /* packet is a SYN-ACK - if status is 1, change back to 0 */
                if (ex->tcp_status == SYN_SENT) {
                    /* correct connection */
                    ex->tcp_status = SYN_ACK_SENT;
                    return 1;
                }
                else {
                    return 0;
                }
            }
        }
        else {
            if ((ex->tcp_status == SYN_SENT) && ack && ((ex->syn_seq +1) ==
                H32(TCP(seq)))) {
                /* correct connection */
                ex->tcp_status = SYN_ACK_SENT;
            
                return 1;
            }
            else {
                return 0;
            }
        }
        
        ex->pkt_status = NON_SUSPICIOUS;
        ex->tcp_status = NON_SYN;
            
        return 1;
    }
}

static int
compare(const void *efh1, const void *efh2)
{
    EFLOWDESC *ex1 = CMPEF(efh1);
    EFLOWDESC *ex2 = CMPEF(efh2);
    
    if (ex1->ts > ex2->ts) 
        return 1;
   
    return -1;
}

static int
action(void * self, void *efh, timestamp_t ivl, timestamp_t current_time, 
       int count)
{
    EFLOWDESC *ex = EF(efh);
    CONFIGDESC *config = CONFIG(self);
    
    struct in_addr addr;
    
    uint32_t ret = 0;
    
    if (efh == NULL) {
        timestamp_t now = current_time;
        return ACT_GO;
    }
    
    if ((ex->pkt_status != SUSPICIOUS) && (ex->tcp_status != SYN_SENT)) {
        /* 
         * its a non suspicious packet, and not a connection, so can be
         * discarded
         */
        
        return ACT_DISCARD;
    }
    
    if (ex->pkt_status == SUSPICIOUS) {
        /* Its a suspicious packet, so must be stored */
        ret = ACT_STORE; 
        
        if (ex->tcp_status == SYN_SENT) {
            /*
             * its a SYN packet, so dont discard, just unset the suspicious
             * packet flag since its already been saved
             */
            ex->pkt_status = NON_SUSPICIOUS;
        }
        else {
            /* its not a connection establishment, so discard after storing */
            ret |= ACT_DISCARD;
        }
    }
    
    if (ex->tcp_status == SYN_SENT) {
        if ((TS2SEC(current_time) - TS2SEC(ex->ts)) >
             TS2SEC(config->syn_timeout)) {
            /* SYN has timed out - add a failed connection to this src_ip */
                        
            add_fail(ex->src_ip, ex->dst_ip, ex->ts, self);
            ret |= ACT_DISCARD;
        }
        else {
            /* SYN is still waiting for SYN/ACK, dont discard */
            ;
        }
    }

    return ret;
}

static ssize_t
store(void * self, void *efh, char *buf)
{
    EFLOWDESC *ex = EF(efh);
    size_t size;
    pkt_t *pkt;
    pkt = (pkt_t *)ex->buf;
    size = COMO(caplen) + sizeof(pkt_t);

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
        COMOX(l7ofs, htons(COMO(l7ofs)));
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
        COMO(l7ofs) = htons(COMO(l7ofs));  
    #endif
    memcpy(buf, pkt, size); 
    
    return size;
}

static size_t
load(void * self, char * buf, size_t len, timestamp_t * ts)
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

static char *
print(void * self, char *buf, size_t *len, char * const args[])
{
    CONFIGDESC * config = CONFIG(self); 
    static char str[65536];
    pkt_t p, pktbuf, *pkt; 
    int n; 

    if (buf == NULL && args != NULL) {
        /* first call, process the arguments */
        *len = 0;
        config->format = PRETTYFMT;
        
        for (n = 0; args[n]; n++) {
            if (!strcmp(args[n], "format=pcap")) {
                *len = print_pcap_file_header(str);
                config->format = PCAPFMT;
                return str; 
            }
        }
        return str;
    }

    if (buf == NULL && args == NULL) {
        /* last call, nothing to do */
        *len = 0; 
        return str; 
    } 
    
    /* 
     * copy the packet CoMo header, converting 
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
    p.l7ofs = ntohs(COMO(l7ofs));  
    p.payload = buf + sizeof(pkt_t);
    
    /* now we are ready to process this packet */
    pkt = (pkt_t *) &p; 
    
    if (config->format == PCAPFMT) {
        *len = print_pkt_pcap(pkt, str);
    }
    else {
        *len = print_pkt_pretty(pkt, str, PRINTPKT_L2 | PRINTPKT_L3);
        *len += sprintf(str + *len, "\n");
    }
    return str; 
}

static int
replay(void * self, char *buf, char *out, size_t * len, int left)
{
    pkt_t * pkt; 
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
    COMOX(l7ofs, ntohs(COMO(l7ofs))); 
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
    COMO(l7ofs) = ntohs(COMO(l7ofs)); 
#endif

    COMO(payload) = out + sizeof(pkt_t);
 
    *len = need;
    return 0;   
}

MODULE(scanner_detect) = 
{
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: sizeof(EFLOWDESC),
    st_recordsize: sizeof(pkt_t) + 2000,
    init: init,
    check: check,
    hash: hash,
    match: NULL,
    update: update,
    ematch: ematch,
    export: export,
    compare: compare,
    action: action,
    store: store,
    load: load,
    print: print,
    replay: replay
};

