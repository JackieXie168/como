/*
 * Copyright (c) 2004 Universitat Politecnica de Catalunya
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
 * Author: Diego Amores Lopez (damores@ac.upc.edu)
 * 
 * Description:
 * ------------
 *  
 * Snort module for CoMo - main file
 *
 * This module tries to offer part of the functionality of the Snort
 * IDS software, using the CoMo infrastructure as a base. 
 * No Snort code has been directly used though, due to license restrictions 
 * (Snort is GPL licensed and CoMo will have a BSD-style license).
 * 
 * This version (0.3) of the Snort module has a new design.
 * It is better structured and probably also faster.
 * It runs on Ethernet links (only place where I can test it for now).
 *
 * How does it work?
 * -----------------
 *  
 * The module reads a file that contains rules in Snort syntax (one rule per line).
 * This file is called snort.rules and is located in the modules directory. Please
 * see the comments there to know details about the kind of rules supported and
 * their syntax. The info parsed from the rules file has the following structure:
 *
 * Rule header 1 ----> Rule header 2 ----> Rule header 3 ----> ...
 *      |                   |
 *      |                   > Options chain 1 ---> Options chain 2 ---> ...
 *      |
 *      > Options chain 1 ---> Options chain 2 ---> Options chain 3 ---> ...
 * 
 * This is because two rules can have the same header but different options.
 * This way everything is stored in a more or less efficient manner, and we don't do
 * unnecessary checks (for example, checking the same rule header more than once
 * for the same packet).
 * 
 * Once the rules have been parsed, the module waits for CAPTURE to get packets
 * from the sniffer and call its check() callback. In the check callback the info in
 * the packet is compared with the rule headers until a match is found. If there
 * is no match, the packet is discarded.
 *
 * If the packet matched any of the rule headers, it is passed to EXPORT along with
 * some additional info.
 * In the action() callback, the module decides if the packet
 * has to be written to disk, after considering the rule options that apply.
 *
 * The flow followed by incoming packets can be represented this way:
 *
 * incoming packet -> check()                    -> update()                  ->
 *                    match against rule headers    update capture hash table
 *                              |
 *                              > discard if no match
 *                              
 * -> export()              -> action()           -> store()
 *    copy packet to export    match against rule    store the packet on disk
 *    hash table               options
 *                              |
 *                              > discard if no match
 *
 * The most expensive calculations (searches in the payload, etc) are done in the
 * action() callback (EXPORT process). This way, there is a smaller possibility of
 * CAPTURE dropping packets due to the activation of the Snort module. The drawback
 * of this method is that sometimes a packet will be copied from CAPTURE to EXPORT
 * to be discarded later (when the packet matches a rule header but it does not match
 * any of the associated option chains).
 *
 * When a query is received, the packets that fired any rule during the requested
 * interval are read from disk via the load() callback, and the output is written.
 * It is possible to choose from different outputs using the "format" argument in the
 * query:
 *  - a pkt_t stream (format=como, this is also activated by default)
 *  - a libpcap file (format=log)
 *  - text output similar to Snort's fast alert format (format=alert)
 *  - a unified log file (format=ulog)
 *  - a unified alert file (format=ualert)
 *  - gnuplot info for CoMo-Live! (format=gnuplot)
 *  - debug format (similar to Snort packet-logger mode, only included for debug
 *    purposes)
 *
 * Unified files are readable with the Barnyard software, that can store the data
 * in a database or in other formats for its further analysis.
 * The alert outputs only write the packets that fired alert rules.
 * 
 * It's also possible to select only the packets that fired a specific rule
 * (p.e. rule=4). The rules are identified by their position in the rules file.
 */

#include <time.h>       /* gmtime */
#include <stdio.h>      /* snprintf, fopen, fclose */
#include <errno.h>      /* ENOMEM */
#include <ctype.h>      /* isalpha, tolower */
#include <pcap.h>       /* libpcap data types */

#include "como.h"       /* needed by all CoMo modules */
#include "module.h"     /* needed by all CoMo modules */
#include "snort.h"      /* prv_alloc, prv_free */

#define MAX_SIMULT_HDRS 10

 /* Structure for the data that CoMo will save on disk */
struct _pktinfo {
    ruleinfo_t *rules[MAX_SIMULT_HDRS]; /* pointers to the rule headers that matched the packet */
    opt_t *opt;       /* pointer to the options header that matched the packet */
    pkt_t pkt;        /* packet data */
};
typedef struct _pktinfo pktinfo_t;

/* Structures needed to save libpcap-formatted files */

#define TCPDUMP_MAGIC   0xa1b2c3d4

struct pcap_timeval {
    bpf_int32 tv_sec;           /* seconds */
    bpf_int32 tv_usec;          /* microseconds */
};

struct pcap_sf_pkthdr {
    struct pcap_timeval ts;     /* time stamp */
    bpf_u_int32 caplen;         /* length of portion present */
    bpf_u_int32 len;            /* length of this packet (off wire) */
};

/* Structures needed for Snort unified output */

#define ALERT_MAGIC     0xDEAD4137  /* unified alert file magic number */
#define LOG_MAGIC       0xDEAD1080  /* unified log file magic number */
#define SNORT_VERSION_MAJOR   1
#define SNORT_VERSION_MINOR   2

/* File header for Snort unified format alert files */

typedef struct UnifiedAlertFileHeader
{
    u_int32_t magic;
    u_int32_t version_major;
    u_int32_t version_minor;
    u_int32_t timezone;
} UnifiedAlertFileHeader_t;

typedef struct Event
{
    u_int32_t sig_generator;   /* which part of snort generated the alert? */
    u_int32_t sig_id;          /* sig id for this generator */
    u_int32_t sig_rev;         /* sig revision for this id */
    u_int32_t classification;  /* event classification */
    u_int32_t priority;        /* event priority */
    u_int32_t event_id;        /* event ID */
    u_int32_t event_reference; /* reference to other events that have gone off,
                                * such as in the case of tagged packets...
                                */
    struct timeval ref_time;   /* reference time for the event reference */
} Event_t;

/* Unified alert message format
 *
 * One per event notification, all the important data for people to know
 */
typedef struct UnifiedAlert
{
    Event_t event;
    struct timeval ts;         /* event timestamp */
    u_int32_t sip;             /* src ip */
    u_int32_t dip;             /* dest ip */
    u_int16_t sp;              /* src port */
    u_int16_t dp;              /* dest port */
    u_int32_t protocol;        /* protocol id */
    u_int32_t flags;           /* any other flags (fragmented, etc) */
} UnifiedAlert_t;

/* File header for Snort unified format log files */
typedef struct UnifiedLogFileHeader
{
    u_int32_t magic;
    u_int16_t version_major;
    u_int16_t version_minor;
    u_int32_t timezone;
    u_int32_t sigfigs;
    u_int32_t snaplen;
    u_int32_t linktype;
} UnifiedLogFileHeader_t;

/* Unified log packet header format 
 *
 * One of these per packet in the log file, the packets are appended in the 
 * file after each UnifiedLog header (in extended pcap format) 
 */
typedef struct UnifiedLog
{
    Event_t event;
    u_int32_t flags;                /* bitmap for interesting flags */
    struct pcap_sf_pkthdr pkth;
} UnifiedLog_t;

/* Maximum Transfer Unit of an Ethernet link */
#define ETH_MTU 1514
/* Maximum size of the info that gets saved on disk for each packet
 * Ethernet Maximum Transfer Unit + size of pktinfo_t struct */
#define MAX_PKTINFOSIZE (ETH_MTU + sizeof(pktinfo_t))

/* FLOWDESC just contains the info for one packet. 
 * We let CAPTURE handle the packet queue and send them to EXPORT in order,
 * using a variable size record */
#define FLOWDESC struct _snort
#define EFLOWDESC FLOWDESC
FLOWDESC {
    char    buf[MAX_PKTINFOSIZE];
};

/* Maximum length of the rules file name */
#define MAX_FILENAMELEN 255
/* Maximum length of a line inside the rules file */
#define MAX_RULELEN 1024

/* Size of the hash table used to store variable information */
#define VAR_HASHSIZE 26
/* We save the info that we get from the Snort rules file
 * into these structures */
unsigned int nrules = 0;        /* number of rules */
ruleinfo_t *ri = NULL;          /* rules info */
varinfo_t *vi[VAR_HASHSIZE];    /* variables info */
dyn_t *dr[MAX_RULES];           /* dynamic rules info */

#define IP_ADDR_LEN     15      /* strlen("XXX.XXX.XXX.XXX") */

/* Pointers to the rule headers that match with a packet */
ruleinfo_t *rule_match[MAX_SIMULT_HDRS];

/* Needed to manage the module's private memory region */
void *prv_mem;
size_t prv_actualsize = 0;
size_t prv_memsize;

/* Declaration of the Bison-generated parsing routine */
int parse_rules(char *rules, void *mem, size_t msize);
    
/**
 * -- check_proto
 *
 * Match the protocol type in a packet 
 * with the one obtained from a Snort rule header
 *
 */
unsigned int 
check_proto(ruleinfo_t *info, pkt_t *pkt)
{
    if (info->proto == IPPROTO_IP) {
        /* If the rule header is for the IP protocol,
         * check the Ethernet type field */
        /* XXX TODO: Only works for Ethernet... add more link types? */
        return (H16(ETH(type)) == 0x0800);
    }
    else if (pkt->l3type == ETHERTYPE_IP) {
        /* If the rule header is for TCP, UDP or ICMP,
         * check the IP proto field */
        return (IP(proto) == info->proto);
    }
    else return 0;
}

/**
 * -- check_xxx_ip
 *
 * Match the src/dst IP address in a packet 
 * with the one(s) obtained from a Snort rule header
 *
 */    
unsigned int
check_src_ip(ruleinfo_t *info, pkt_t *pkt)
{
    unsigned int r = 0; 
    ipnode_t *aux;
    
    aux = info->src_ips.ipnode;
    while (aux != NULL && !r) {
        /* Turn the rule's netmask into network byte order
         * before comparing */
        r = (aux->ipaddr == (N32(IP(src_ip)) & htonl(aux->netmask)));
        aux = aux->next;
    }
    if (info->src_ips.negation) r ^= 1;
    return r;
}
    
unsigned int
check_dst_ip(ruleinfo_t *info, pkt_t *pkt)
{
    unsigned int r = 0; 
    ipnode_t *aux;
    aux = info->dst_ips.ipnode;
    while (aux != NULL && !r) {
        /* Turn the rule's netmask into network byte order
         * before comparing */
        r = (aux->ipaddr == (N32(IP(dst_ip)) & htonl(aux->netmask)));
        aux = aux->next;
    }
    if (info->dst_ips.negation) r ^= 1;
    return r;
}

/**
 * -- check_xxx_xxx_port
 *
 * Match the tcp/udp source/destination port in a packet 
 * against a set of ports obtained from a Snort rule header
 *
 */    
unsigned int 
check_tcp_src_port(ruleinfo_t *info, pkt_t *pkt)
{
    unsigned int r = 0;
    r = ( info->src_ports.lowport <= H16(TCP(src_port)) &&
          info->src_ports.highport >= H16(TCP(src_port)) );
    if (info->src_ports.negation) r ^= 1;
    return r;
}

unsigned int 
check_tcp_dst_port(ruleinfo_t *info, pkt_t *pkt)
{
    unsigned int r = 0;
    r = ( info->dst_ports.lowport <= H16(TCP(dst_port)) &&
          info->dst_ports.highport >= H16(TCP(dst_port)) );
    if (info->dst_ports.negation) r ^= 1;
    return r;
}

unsigned int 
check_udp_src_port(ruleinfo_t *info, pkt_t *pkt)
{
    unsigned int r = 0;
    r = ( info->src_ports.lowport <= H16(UDP(src_port)) &&
          info->src_ports.highport >= H16(UDP(src_port)) );
    if (info->src_ports.negation) r ^= 1;
    return r;
}

unsigned int 
check_udp_dst_port(ruleinfo_t *info, pkt_t *pkt)
{
    unsigned int r = 0;
    r = ( info->dst_ports.lowport <= H16(UDP(dst_port)) &&
          info->dst_ports.highport >= H16(UDP(dst_port)) );
    if (info->dst_ports.negation) r ^= 1;
    return r;
}
    
/*
 * -- lowercase
 *  Transforms a string into lowercase
 *
 */
void
lowercase(char *string, unsigned int length)
{
    unsigned int i;
    for(i = 0; i < length; i++) {
        if (isalpha(string[i])) string[i] = tolower(string[i]);
    }
}

/*
 * -- get_bytes
 *  Gets a number of bytes from a packet payload and returns their
 *  integer value
 *
 */
int
get_bytes(char *pl, unsigned int nbytes, uint8_t endian)
{
    int ret;
    
    switch(nbytes) {
        case 1:
            ret = (*pl) & 0xFF;
            break;
        case 2:
            switch(endian) {
                case BIGENDIAN:
                    ret = (((*pl) & 0xFF) << 8);
                    ret |= (*(pl + 1) & 0xFF);
                    break;
                case LILENDIAN:
                    ret = ((*pl) & 0xFF);
                    ret |= ((*(pl + 1) & 0xFF) << 8);
                    break;
            }
            break;
        case 4:
            switch(endian) {
                case BIGENDIAN:
                    ret = (((*pl) & 0xFF) << 24);
                    ret |= ((*(pl + 1) & 0xFF) << 16);
                    ret |= (((*pl + 2) & 0xFF) << 8);
                    ret |= ((*pl + 3) & 0xFF); 
                    break;
                case LILENDIAN:
                    ret = ((*pl) & 0xFF);
                    ret |= ((*(pl + 1) & 0xFF) << 8);
                    ret |= (((*pl + 2) & 0xFF) << 16);
                    ret |= (((*pl + 3) & 0xFF) << 24);
                    break;
            }
            break;
    }
    return ret;
}

/*
 * -- get_ip_option
 *
 *
 */
uint16_t get_ip_option(char *option) {
    uint16_t ret = 0;
    switch(atoi(option)) {
        case 7:
            ret = IPOPT_RR;
            break;
        case 0:
            ret = IPOPT_EOL;
            break;
        case 1:
            ret = IPOPT_NOP;
            break;
        case 68:
            ret = IPOPT_TS;
            break;
        case 130:
            ret = IPOPT_SEC;
            break;
        case 131:
            ret = IPOPT_LSRR;
            break;
        case 137:
            ret = IPOPT_SSRR;
            break;
        case 136:
            ret = IPOPT_SATID;
            break;
    }
    return ret;
}

/*
 * -- get_ip_options
 *  Gets the ip option codes from a packet
 *
 */
uint16_t get_ip_options(pkt_t *pkt)
{
    int i = 0;
    uint16_t ipopt = 0, ipopts = 0;
    char *options = IP(options);
    
    while (i < (((IP(vhl) & 0x0F) << 2) - 20)) {
        ipopt = get_ip_option(options + i);
        ipopts |= ipopt;
        if (ipopt == IPOPT_SEC || ipopt == IPOPT_LSRR ||
            ipopt == IPOPT_TS || ipopt == IPOPT_RR ||
            ipopt == IPOPT_SATID || ipopt == IPOPT_SSRR)
            /* If the option's length is greater than 1 byte,
             * jump the necessary bytes ahead */
            i += atoi(options + i + 1);
        else i++;
    }
    
    return ipopts;
}

#define OVECCOUNT 30 /* needed for pcre matching, multiple of 3 */

#define ICMP_ECHO 8
#define ICMP_ECHOREPLY 0

/**
 * -- check_options
 *
 * Given a packet and the rule header that matched against it,
 * go through all the options headers and determine which one
 * matches the packet (if any).
 * A pointer to the matching option header (or NULL if there is no match)
 * is returned through the opt parameter
 * 
 */
unsigned int
check_options(ruleinfo_t *info, pkt_t *pkt, opt_t **opt)
{
    opt_t *oaux;
    optnode_t *onode;
    unsigned int ok;
    unsigned int pl_start = 0, pl_size = 0, last_found = 0, layer4jmp = 0;
    char *pl;
#ifdef HAVE_PCRE
    int rc;
    int ovector[OVECCOUNT];
    int pcre_startoffset;
#endif
    int byte_value;
    uint8_t ipopts;
    
    for (oaux = info->opts; oaux; oaux = oaux->next) {
        ok = 1;
        for (onode = oaux->options; onode && ok; onode = onode->next) {
            if (onode->keyword == SNTOK_CONTENT || onode->keyword == SNTOK_PCRE) {
                switch(IP(proto)) {
                    case IPPROTO_IP:
                        /* If we have a generic IP packet, consider all the
                         * layer4 content as payload */
                        layer4jmp = 0;
                        break;
                    case IPPROTO_TCP:
                        /* We don't use the size of struct _como_tcphdr
                         * because there can be TCP options in the packet */
                        layer4jmp = ((TCP(hlen) >> 4) << 2);
                        break;
                    case IPPROTO_UDP:
                        layer4jmp = sizeof(struct _como_udphdr);
                        break;
                    case IPPROTO_ICMP:
                        layer4jmp = sizeof(struct _como_icmphdr);
                        break;
                }
            }
            switch(onode->keyword) {
                case SNTOK_CONTENT:
                    if (onode->has_distance || onode->has_within)
                        pl_start = pkt->layer4ofs + onode->offset + last_found + onode->distance;
                    else pl_start = pkt->layer4ofs + onode->offset;

                    /* Jump the layer 4 header */
                    pl_start += layer4jmp;
                    
                    /* Check that the scope of the search
                     * is not beyond the payload limits */
                    if (pl_start > pkt->caplen) {
                        logmsg(LOGWARN, "SNORT: payload search out of limits: %d > %d\n",
                               pl_start, pkt->caplen);
                        /* XXX debug
                        logmsg(LOGWARN, "last_found = %d, pkt->layer4ofs = %d, pl_start = %d\n",
                               last_found, pkt->layer4ofs, pl_start); */
                        continue;
                    }
                    
                    if (onode->has_within) {
                        if ((pkt->caplen - pl_start) < onode->within)
                            pl_size = pkt->caplen - pl_start;
                        else pl_size = onode->within;
                    }
                    else {
                        /* If the depth option is larger than the actual payload, limit the
                         * search to the payload length */
                        if (((pkt->caplen - pl_start) < onode->depth) || !(onode->has_depth))
                            pl_size = pkt->caplen - pl_start;
                        else pl_size = onode->depth;
                    }

                    /* Copy the part of the payload in which we are interested */
                    pl = (char *)prv_alloc(pl_size);
                    memcpy(pl, pkt->payload + pl_start, pl_size);
                    if (onode->nocase) {
                        /* Turn the payload string into lower case */
                        lowercase(pl, pl_size);
                    }
                    ok &= BM(onode->cnt, onode->cntlen, pl, pl_size,
                             onode->bmBc, onode->bmGs, &last_found);
                    if (ok) last_found = last_found + (pl_start - pkt->layer4ofs - layer4jmp) + onode->cntlen;
                    prv_free(pl);
                    
                    if (onode->neg) ok ^= 1;
                    break;
                case SNTOK_ISDATAAT:
                    if (onode->relative) {
                        ok &= ((pkt->caplen - pkt->layer4ofs - layer4jmp) > (onode->isdataat + last_found));
                    }
                    else ok &= ((pkt->caplen - pkt->layer4ofs - layer4jmp) > onode->isdataat);
                    break;
                case SNTOK_PCRE:
#ifdef HAVE_PCRE
                    pl_size = pkt->caplen - pkt->layer4ofs - layer4jmp;
                    pl = (char *)prv_alloc(pl_size);
                    memcpy(pl, pkt->payload + pkt->layer4ofs + layer4jmp, pl_size);
                    
                    if (onode->relative) pcre_startoffset = last_found;
                    else pcre_startoffset = 0;
                    
                    /* Evaluate PCRE */
                    rc = pcre_exec(onode->regexp, NULL, pl, pl_size, pcre_startoffset, 0,
                                   ovector, OVECCOUNT);
                    prv_free(pl);
                    if (rc < 0) {
                        switch(rc) {
                            case PCRE_ERROR_NOMATCH: 
                                ok = 0;
                                break;
                            default:
                                logmsg(LOGWARN, "SNORT: error while matching pcre\n");
                                break;
                        }
                    }
                    else last_found = ovector[1];
                    if (onode->neg) ok ^= 1;
#endif
                    break;
                case SNTOK_BYTETEST:
                    pl = (char *)prv_alloc(onode->byte_number);
                    pl_start = pkt->layer4ofs + layer4jmp + onode->byte_offset;
                    if (onode->relative) pl_start += last_found;
                    memcpy(pl, pkt->payload + pl_start, onode->byte_number);
                    if (!(onode->byte_isstring))
                        byte_value = get_bytes(pl, onode->byte_number, onode->byte_endian);
                    else byte_value = strtol(pl, NULL, onode->byte_base);
                    prv_free(pl);
                    switch (onode->byte_op) {
                        case SNTOK_LT:
                            ok &= (byte_value < onode->byte_value);
                            break;
                        case SNTOK_EQ:
                            ok &= (byte_value == onode->byte_value);
                            break;
                        case SNTOK_GT:
                            ok &= (byte_value > onode->byte_value);
                            break;
                        case SNTOK_BWAND:
                            ok &= (byte_value & onode->byte_value);
                            break;
                        case SNTOK_BWOR:
                            ok &= (byte_value & onode->byte_value);
                            break;
                    }
                    if (ok) last_found = pl_start - pkt->layer4ofs - layer4jmp + onode->byte_number;
                    break;
                case SNTOK_BYTEJUMP:
                    pl = (char *)prv_alloc(onode->byte_number);
                    pl_start = pkt->layer4ofs + layer4jmp + onode->byte_offset;
                    if (onode->relative) pl_start += last_found;
                    memcpy(pl, pkt->payload + pl_start, onode->byte_number);
                    if (!(onode->byte_isstring)) {
                        last_found = get_bytes(pl, onode->byte_number, onode->byte_endian) * onode->byte_multi;
                    }
                    else last_found = strtol(pl, NULL, onode->byte_base) * onode->byte_multi;
                    prv_free(pl);
                    break;
                case SNTOK_FROFFSET:
                    switch (oaux->fragoffcmp) {
                        case SNTOK_EQ:
                            ok &= ((H16(IP(ofs)) & 0x1fff) == oaux->fragoffset);
                            break;
                        case SNTOK_GT:
                            ok &= ((H16(IP(ofs)) & 0x1fff) > oaux->fragoffset);
                            break;
                        case SNTOK_LT:
                            ok &= ((H16(IP(ofs)) & 0x1fff) < oaux->fragoffset);
                            break;
                    }
                    break;
                case SNTOK_TTL:
                    switch(oaux->ttlcmp) {
                        case SNTOK_EQ:
                            ok &= (IP(ttl) == oaux->ttllow);
                            break;
                        case SNTOK_LT:
                            ok &= (IP(ttl) < oaux->ttllow);
                            break;
                        case SNTOK_GT:
                            ok &= (IP(ttl) > oaux->ttllow);
                            break;
                        case SNTOK_BETWEEN:
                            ok &= (IP(ttl) >= oaux->ttllow && IP(ttl) <= oaux->ttlhigh);
                            break;
                    }
                    break;
                case SNTOK_TOS:
                    if (onode->neg)
                        ok &= (IP(tos) != oaux->tos);
                    else
                        ok &= (IP(tos) == oaux->tos);
                    break;
                case SNTOK_IPID:
                    ok &= (H16(IP(id)) == oaux->ipid);
                    break;
                case SNTOK_IPOPTS:
                    if (((IP(vhl) & 0x0F) << 2) == 20) {
                        /* There are no IP options in the packet */
                        ok = 0;
                    }
                    else if (!(oaux->ipopts_any)) {
                        /* Check if the required IP options are present */
                        ipopts = get_ip_options(pkt);
                        ok &= ((oaux->ipopts & ipopts) == ipopts);
                    }
                    break;
                case SNTOK_FRAGBITS:
                    switch (oaux->fragbitscmp) {
                        case 0:
                            /* No comparison modifier specified */
                            ok &= (H16(IP(ofs)) == oaux->fragbits);
                            break;
                        case FB_NOT:
                            /* Match if the specified bits are not set */
                            ok &= ((H16(IP(ofs)) & oaux->fragbits) == 0x0000);
                            break;
                        case FB_ALL:
                            /* Match on the specified bits plus any others */
                            ok &= ((H16(IP(ofs)) & oaux->fragbits) == oaux->fragbits);
                            break;
                        case FB_ANY:
                            /* Match if any of the specified bits are set */
                            ok &= ((H16(IP(ofs)) & oaux->fragbits) != 0x0000);
                            break;
                    }
                    break;
                case SNTOK_DSIZE:
                    pl_size = pkt->caplen - pkt->layer4ofs - layer4jmp;
                    switch (oaux->dsizecmp) {
                        case SNTOK_EQ:
                            ok &= (pl_size == oaux->dsizelow);
                            break;
                        case SNTOK_GT:
                            ok &= (pl_size > oaux->dsizelow);
                            break;
                        case SNTOK_LT:
                            ok &= (pl_size < oaux->dsizelow);
                            break;
                        case SNTOK_BETWEEN:
                            ok &= (pl_size >= oaux->dsizelow &&
                                   pl_size <= oaux->dsizehigh);
                            break;
                    }                
                    break;
                case SNTOK_FLAGS:
                    if (oaux->flagsnone) {
                        /* Match if no TCP flags are set */
                        ok &= (TCP(flags) == 0x00);
                    }
                    else {
                        switch(oaux->flagscmp) {
                            case 0:
                                /* No comparison modifier specified */
                                ok &= (TCP(flags) == oaux->flags);
                                break;
                            case FLG_NOT:
                                /* Match if the specified bits are not set */
                                ok &= ((TCP(flags) & oaux->flags) == 0x00);
                                break;
                            case FLG_ALL:
                                /* Match on the specified bits plus any others */
                                ok &= ((TCP(flags) & oaux->flags) == oaux->flags);
                                break;
                            case FLG_ANY:
                                /* Match if any of the specified bits are set */
                                ok &= ((TCP(flags) & oaux->flags) != 0x00);
                                break;
                        }
                    }
                    break;
                case SNTOK_SEQ:
                    ok &= (H32(TCP(seq)) == oaux->seq);
                    break;
                case SNTOK_ACK:
                    ok &= (H32(TCP(ack)) == oaux->ack);
                    break;
                case SNTOK_WINDOW:
                    if (onode->neg)
                        ok &= (H16(TCP(win)) != oaux->window);
                    else
                        ok &= (H16(TCP(win)) == oaux->window);
                    break;
                case SNTOK_ITYPE:
                    switch (oaux->itypecmp) {
                        case SNTOK_EQ:
                            ok &= (ICMP(type) == oaux->itypelow);
                            break;
                        case SNTOK_GT:
                            ok &= (ICMP(type) > oaux->itypelow);
                            break;
                        case SNTOK_LT:
                            ok &= (ICMP(type) < oaux->itypelow);
                            break;
                        case SNTOK_BETWEEN:
                            ok &= (ICMP(type) >= oaux->itypelow &&
                                   ICMP(type) <= oaux->itypehigh);
                            break;
                    }                
                    break;                    
                case SNTOK_ICODE:
                    switch (oaux->icodecmp) {
                        case SNTOK_EQ:
                            ok &= (ICMP(code) == oaux->icodelow);
                            break;
                        case SNTOK_GT:
                            ok &= (ICMP(code) > oaux->icodelow);
                            break;
                        case SNTOK_LT:
                            ok &= (ICMP(code) < oaux->icodelow);
                            break;
                        case SNTOK_BETWEEN:
                            ok &= (ICMP(code) >= oaux->icodelow &&
                                   ICMP(code) <= oaux->icodehigh);
                            break;
                    }                
                    break;
                case SNTOK_ICMPID:
                    /* XXX There could be problems with endianness
                     * in some architectures */
                    if (ICMP(type) == ICMP_ECHO || ICMP(type) == ICMP_ECHOREPLY) {
                        ok &= (get_bytes(ICMP(payload), 2, BIGENDIAN) == oaux->icmpid);
                    }
                    else {
                        /* The match is not possible 
                         * (not an echo or echo reply packet) */
                        ok = 0;
                    }
                    break;
                case SNTOK_ICMPSEQ:
                    /* XXX There could be problems with endianness
                     * in some architectures */
                    if (ICMP(type) == ICMP_ECHO || ICMP(type) == ICMP_ECHOREPLY) {
                        ok &= (get_bytes(ICMP(payload) + 2, 2, BIGENDIAN) == oaux->icmpseq);
                    }
                    else {
                        /* The match is not possible 
                         * (not an echo or echo reply packet) */
                        ok = 0;
                    }
                    break;
                case SNTOK_IPPROTO:
                    switch (oaux->ipprotocmp) {
                        case SNTOK_EQ:
                            ok &= (IP(proto) == oaux->ipproto);
                            break;
                        case SNTOK_NOTEQ:
                            ok &= (IP(proto) != oaux->ipproto);
                            break;
                        case SNTOK_GT:
                            ok &= (IP(proto) > oaux->ipproto);
                            break;
                        case SNTOK_LT:
                            ok &= (IP(proto) < oaux->ipproto);
                            break;
                    }                    
                    break;
                case SNTOK_SAMEIP:
                    ok &= (H32(IP(src_ip)) == H32(IP(dst_ip)));
                    break;
            }
        }
        if (ok) {
            *opt = oaux;
            return 1;
        }
    }
    *opt = NULL;
    return 0;
}
    
/**
 * -- init
 *
 * The init callback
 * Here we check and initialize the module's private memory region,
 * parse the arguments received via como.conf, and call the rules parsing
 * routine generated by Bison.
 *
 * Regarding the private memory region, a simple system to allocate and
 * free memory chunks in this region has been implemented. This makes us
 * able to use external software like Flex, Bison and libpcre without
 * calls to the C language malloc() or free() routines, as this is not
 * allowed in CoMo modules.
 *
 */   
static int
init(void *mem, size_t msize, char *args[])
{
    char *line;
    
    /* Check and initialize the module's private memory region
     * where the info from the rules will be stored */
    if (msize < 100000) {
	logmsg(LOGWARN, "SNORT: need 100 Kbytes of private memory, have just %d\n", msize);
	return ENOMEM; 
    } 
    memset(mem, 0, msize);
    prv_mem = mem;
    prv_memsize = msize;
    
    /* Check whether we have rules */
    if (!args[0]) {
        logmsg(LOGWARN, "SNORT: no rules specified in base/como.conf");
        return 1;
    }
    
    /* Read the rules line by line and parse them,
     * saving their info in the module's private memory region */
    line = strtok(args[0], "\n");
    while(line != NULL) {
        if (parse_rules(line, mem, msize) == 1)
            return 1;
        line = strtok(NULL, "\n");
    }
    
    if (nrules == 0)
        logmsg(LOGWARN, "SNORT: parsing rules: empty rules file\n");
    
    return 0;
}

/**
 * -- check
 *
 * The check callback
 * This callback is used to do the matching between the info in Snort
 * rule headers and the packets. If a packet does not match any of the
 * rule headers, it won't be further processed.
 */
static int
check(pkt_t *pkt)
{
    ruleinfo_t *i;
    unsigned int ok;
    fpnode_t *fp;
    unsigned int idx = 0, found = 0;
    
    /* Initialize the rule_match array */
    for(idx = 0; idx < MAX_SIMULT_HDRS; idx++)
        rule_match[idx] = NULL;
    
    /* See if the incoming packet matches any of the
     * rules' headers */    
    idx = 0;
    for (i = ri; i; i = i->next) {
        ok = 1;
        /* Go through the list of pointers to check functions */
        for (fp = i->funcs; fp != NULL && ok; fp = fp->next)
            ok &= fp->function(i, pkt);
        if (ok) {
            /* Save which rule headers matched the packet */
            found = 1;
            rule_match[idx] = i;
            idx++;
            /* If we have reached the max number of simultaneous rule
             * headers than a packet can match, stop the check */
            if (idx == MAX_SIMULT_HDRS) return found; 
        }
    }
    return found;
}
    
/**
 * -- update
 *
 * The update callback
 * Each packet is stored in a different record in capture
 * (actually all of them are part of the same variable-size record)
 *
 */ 
static int
update(pkt_t *pkt, void *fh, __unused int isnew, __unused unsigned drop_cntr)
{
    unsigned int idx;
    
    FLOWDESC *f = F(fh);
    
    pktinfo_t *p = (pktinfo_t *)(f->buf);
    
    for (idx = 0; idx < MAX_SIMULT_HDRS; idx++)
        p->rules[idx] = rule_match[idx];
    
    memcpy(&(p->pkt), pkt, sizeof(pkt_t));
    /* Modify the packet caplen if needed */
    p->pkt.caplen = pkt->caplen;
    memcpy(p + 1, pkt->payload, pkt->caplen);
    p->pkt.payload = (char *)(p + 1);
    
    return 1; /* Only one packet per record, so records are always full */
}

/*
 * -- ematch
 *
 * The ematch callback
 * In export, each packet is stored also in a different record,
 * so we always return 0
 *
 */
static int
ematch(__unused void *efh, __unused void *fh)
{
    return 0;
}
    
/*
 * -- export
 *
 * The export callback
 * We just need to copy the data from the capture hash table
 * 
 */
static int
export(void *efh, void *fh, __unused int isnew)
{
    FLOWDESC  *f  = F(fh);
    EFLOWDESC *ef = EF(efh);

    pktinfo_t *p = (pktinfo_t *)(f->buf);
    pktinfo_t *ep = (pktinfo_t *)(ef->buf);
    
    memcpy(ep, p, sizeof(pktinfo_t));
    memcpy(ep + 1, p->pkt.payload, p->pkt.caplen);
    ep->pkt.payload = (char *)(ep + 1);

    return 0;
}
    
/*
 * -- action
 *
 * The action callback
 * Check if any of the rules matches the packet, and act accordingly
 * (discard it, or store it on disk and then discard it)
 *
 */
static int
action(void *efh, __unused timestamp_t current_time, __unused int count)
{
    FLOWDESC *ef;
    pktinfo_t *ep;
    ruleinfo_t *i;
    pkt_t *pkt;
    dyn_t *d;
    opt_t *opt;
    unsigned int active, idx;

    if (efh == NULL) 
	return ACT_GO;

    ef = EF(efh);
    ep = (pktinfo_t *)(ef->buf);

    pkt = &(ep->pkt);
    
    idx = 0;
    i = ep->rules[idx];
    while(i && idx < MAX_SIMULT_HDRS) {
        /* First check whether the rule is active */
        active = 0;
        for (opt = i->opts; opt && !active; opt = opt->next)
            active |= opt->active;
        if (!active) return ACT_DISCARD;
    
        /* Check the rule options against the packet
         * to decide what to do with it (discard or store)
         */
        if (check_options(i, pkt, &opt)) {
            switch(opt->action) {
                case SNTOK_PASS:
                    return ACT_DISCARD;
                case SNTOK_ACTIV:
                    for(d = dr[opt->activates]; d; d = d->next) {
                        if (d->activates->active == 0) {
                            d->activates->curr_count = d->activates->count;
                            d->activates->active = 1;
                        }
                    }
                    break;
                case SNTOK_DYN:
                    opt->curr_count--;
                    if (opt->curr_count == 0) opt->active = 0;
                    break;
            }        
            ep->opt = opt;
            return (ACT_STORE | ACT_DISCARD);
        }

        idx++;
        i = ep->rules[idx];
    }
    
    /* The packet didn't match */
    return ACT_DISCARD;
}

/*
 * -- store
 *
 * The store callback
 * Store a packet and its related info on disk
 *
 */
static ssize_t
store(void *rp, char *buf, size_t len)
{
    EFLOWDESC *ef = EF(rp);
    pktinfo_t *p, *bp;
    
    if (len < sizeof(EFLOWDESC)) 
	return -1; 

    p = (pktinfo_t *)(ef->buf);
    bp = (pktinfo_t *)buf;
    
    memcpy(bp, p, sizeof(pktinfo_t));
    memcpy(bp + 1, p->pkt.payload, p->pkt.caplen);
    
    return sizeof(pktinfo_t) + p->pkt.caplen;
}

/*
 * -- load
 *
 * The load callback
 * Read a packet and its related info from disk
 *
 */
static size_t
load(char *buf, size_t len, timestamp_t *ts)
{
    pktinfo_t *p;
    
    if (len < sizeof(pktinfo_t)) {
        ts = 0;
        return 0;
    } 
    
    p = (pktinfo_t *)buf;

    *ts = p->pkt.ts;
    return sizeof(pktinfo_t) + p->pkt.caplen;
}

#define TIMEBUF_SIZE 26

/*
 * -- ts_print
 *
 * Converts a timeval structure into a readable string
 * Taken from tcpdump code and modified
 */
void ts_print(register const struct timeval *tvp, char *timebuf)
{
    register int s;
    int    localzone;
    time_t Time;
    struct timeval tv;
    struct timezone tz;
    struct tm *lt;    /* place to stick the adjusted clock data */

    /* if null was passed, we use current time */
    if(!tvp)
    {
        /* manual page (for linux) says tz is never used, so.. */
        bzero((char *) &tz, sizeof(tz));
        gettimeofday(&tv, &tz);
        tvp = &tv;
    }

    /* We're doing UTC */
    localzone = 0;

    s = (tvp->tv_sec + localzone) % 86400;
    Time = (tvp->tv_sec + localzone) - s;

    lt = gmtime(&Time);

    /* Do not include the year */
    (void) snprintf(timebuf, TIMEBUF_SIZE,
                    "%02d/%02d-%02d:%02d:%02d.%06u ", lt->tm_mon + 1,
                    lt->tm_mday, s / 3600, (s % 3600) / 60, s % 60,
                    (u_int) tvp->tv_usec);
}
    
/* Macros to access packet fields from print() */
#define IPS(field)               \
    (((struct _como_iphdr *) ((char *)(pkt + 1) + pkt->layer3ofs))->field)
#define TCPS(field)              \
    (((struct _como_tcphdr *) ((char *)(pkt + 1) + pkt->layer4ofs))->field)
#define UDPS(field)              \
    (((struct _como_udphdr *) ((char *)(pkt + 1) + pkt->layer4ofs))->field)
#define ICMPS(field)              \
    (((struct _como_icmphdr *) ((char *)(pkt + 1) + pkt->layer4ofs))->field)

/*
 * -- create_alert_str
 *
 * utility function used to print a Snort alert
 */
static void 
create_alert_str(struct timeval *t, pkt_t *pkt, opt_t *opt, char *s)
{
    char srcip[IP_ADDR_LEN];
    char dstip[IP_ADDR_LEN];
    char srcport[5];
    char dstport[5];
    char proto[5];
    char timebuf[TIMEBUF_SIZE];
    struct in_addr addr;
    
    ts_print(t, timebuf);
    addr.s_addr = N32(IPS(src_ip));
    snprintf(srcip, IP_ADDR_LEN, "%s", inet_ntoa(addr));
    addr.s_addr = N32(IPS(dst_ip));
    snprintf(dstip, IP_ADDR_LEN, "%s", inet_ntoa(addr));
    
    switch (IPS(proto)) {
        case IPPROTO_TCP:
            sprintf(proto, "tcp");
            sprintf(srcport, "%d", H16(TCPS(src_port)));
            sprintf(dstport, "%d", H16(TCPS(dst_port)));
            break;
        case IPPROTO_UDP:
            sprintf(proto, "udp");
            sprintf(srcport, "%d", H16(UDPS(src_port)));
            sprintf(dstport, "%d", H16(UDPS(dst_port))); 
            break;
        case IPPROTO_ICMP:
            sprintf(proto, "icmp");
            sprintf(srcport, "N/A");
            sprintf(dstport, "N/A");
            break;
        case IPPROTO_IP:
            sprintf(proto, "ip");
            sprintf(srcport, "N/A");
            sprintf(dstport, "N/A");
            break;
        default:
            sprintf(proto, "other");
            sprintf(srcport, "N/A");
            sprintf(dstport, "N/A");            
            break;
    }
    
    sprintf(s, "%s [**] [%d,%d] rule no. %d: %s [**] [Classification: %s] [Priority: %d] {%s} %s:%s -> %s:%s\n",
                timebuf, opt->sid, opt->rev, opt->rule_id, opt->msg, 
                opt->ctype, opt->prio, proto, srcip, srcport, 
                dstip, dstport);
}

#define LINE_SEPARATOR \
    "=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n"

#define PCAPLOGFMT      1
#define FALERTFMT       2
#define ULOGFMT         3
#define UALERTFMT       4
#define COMOFMT         5
#define GNUPLOTFMT1     6
#define GNUPLOTFMT2     7
#define DEBUGFMT      8

/* GNUPLOT_PERCENT: 
 * If this is defined, the gnuplot output is the percentage of packets
 * per rule over the total packets that match any rule.
 * If not, the gnuplot output is the total of packets per rule */
// #define GNUPLOT_PERCENT
    
#define GNUPLOTHDR1     						\
    "set terminal postscript eps color solid lw 1 \"Helvetica\" 14;"	\
    "set grid;"								\
    "set ylabel \"Percentage\";"					\
    "set xlabel \"Time (HH:MM UTC)\";"					\
    "set yrange [0:100];"						\
    "set autoscale xfix;"						\
    "set key outside;"							\
    "set xdata time;"							\
    "set timefmt \"%%s\";"						\
    "set format x \"%%H:%%M\";"                                         \
    "plot "

#define GNUPLOTHDR2     						\
    "set terminal postscript eps color solid lw 1 \"Helvetica\" 14;"	\
    "set grid;"								\
    "set ylabel \"Packets\";"				                \
    "set xlabel \"Time (HH:MM UTC)\";"					\
    "set ytics nomirror;"						\
    "set autoscale ymax;"						\
    "set autoscale xfix;"						\
    "set key outside;"                                                  \
    "set xdata time;"							\
    "set timefmt \"%%s\";"						\
    "set format x \"%%H:%%M\";"						\
    "plot "

#define GNUPLOTFOOTER	"e\n"

static char *
print(char *buf, size_t *len, char * const args[])
{
    /* Options parsing */
    int n, fmt_found = 0;
    static unsigned int fmt, rule, rule_found = 0;
    char *rulestr;
    
    /* CoMo-Live! counters */
    unsigned int i;
    static int count = 0;
    static uint64_t pktssum[100];
    ruleinfo_t *ruleptr;
    opt_t *optptr;
    
    /* Output file structs */
    /* file headers */
    static struct pcap_file_header fhdr;
    static UnifiedAlertFileHeader_t uafhdr;
    static UnifiedLogFileHeader_t ulfhdr;
    /* packet headers */
    static struct pcap_sf_pkthdr *pcaphdr;
    static UnifiedAlert_t *uat;
    static UnifiedLog_t *ult;
   
    static uint64_t event_id = 0;
    
    pktinfo_t *pktinfo;
    pkt_t *pkt;
    static char s[4096];
    char timebuf[TIMEBUF_SIZE];
    struct timeval tv;
    uint32_t addr;
    ref_t *ref;
    unsigned int pl_start;
    
    if (buf == NULL && args != NULL) { 
	/* First print callback, process the arguments.
         * Return a file header if necessary */
        for (n = 0; args[n]; n++) {
            if (!strcmp(args[n], "format=log")) {
                fmt = PCAPLOGFMT;
                fmt_found = 1;
            }
            else if (!strcmp(args[n], "format=alert")) {
                fmt = FALERTFMT;
                fmt_found = 1;
            }
            else if (!strcmp(args[n], "format=ulog")) {
                fmt = ULOGFMT;
                fmt_found = 1;
            }
            else if (!strcmp(args[n], "format=ualert")) {
                fmt = UALERTFMT;
                fmt_found = 1;
            }
            else if (!strcmp(args[n], "format=como")) {
                fmt = COMOFMT;
                fmt_found = 1;
            }
            else if (!strcmp(args[n], "format=gnuplot")) {
#ifdef GNUPLOT_PERCENT
                fmt = GNUPLOTFMT1;
#else
                fmt = GNUPLOTFMT2;
#endif
                fmt_found = 1;
            }
            else if (!strcmp(args[n], "format=debug")) {
                fmt = DEBUGFMT;
                fmt_found = 1;
            }
        }        
        
        /* If no format argument has been specified in the query, 
        * the default is to output a stream of pkt_t structs 
        */
        if (!fmt_found) {
            logmsg(LOGQUERY, "SNORT: missing query argument \"format=xxx\"\n");
            fmt = COMOFMT;
        }
        
        /* Check if the user has specified a rule number
         * in the query */
        for (n = 0; args[n]; n++) {
            if ((rulestr = strstr(args[n], "rule="))) {
                rule_found = 1;
                rule = atoi(rulestr + 5);
            }
        }
        
        if (fmt == PCAPLOGFMT) { /* libpcap file format */
            /* XXX TODO: snaplen and linktype should depend on 
             * the sniffer used:
             * - snaplen can be passed as an init parameter 
             * - linktype can be gathered from pkt->l2type
             */
            fhdr.magic = TCPDUMP_MAGIC;
            fhdr.version_major = PCAP_VERSION_MAJOR;
            fhdr.version_minor = PCAP_VERSION_MINOR;
            fhdr.thiszone = 0;    // Time Zone Offset - gmt to local correction
            fhdr.snaplen = 65535; /* Maximum number of captured bytes per packet
                                   * By default we capture entire packets, so we put
                                   * here the maximum IPv4 MTU */
            fhdr.sigfigs = 0;     // Time Stamp Accuracy
            fhdr.linktype = 1;    // Ethernet link type (default)
    
            *len = sizeof(fhdr);
            return (char *)&fhdr; // return a libpcap file header
        }
        else if (fmt == ULOGFMT) { /* Unified Log format */
            /* XXX TODO: snaplen and linktype should depend on the sniffer used */
            ulfhdr.magic = LOG_MAGIC;
            ulfhdr.version_major = SNORT_VERSION_MAJOR;
            ulfhdr.version_minor = SNORT_VERSION_MINOR;
            ulfhdr.timezone = 0;    // Time Zone Offset - gmt to local correction
            ulfhdr.snaplen = 65535; /* Maximum number of captured bytes per packet
                                     * By default we capture entire packets, so we put
                                     * here the maximum IPv4 MTU */
            ulfhdr.sigfigs = 0;     // Time Stamp Accuracy
            ulfhdr.linktype = 1;    // Ethernet link type (default)
            *len = sizeof(ulfhdr);
            return (char *)&ulfhdr; // return a unified log file header
        }
        else if (fmt == UALERTFMT) { /* Unified Alert format */
            uafhdr.magic = ALERT_MAGIC;
            uafhdr.version_major = 1;
            uafhdr.version_minor = 81;
            uafhdr.timezone = 0;
            *len = sizeof(uafhdr);
            return (char *)&uafhdr;
        }
        else if (fmt == GNUPLOTFMT1) { /* CoMo-Live! format (percentage of packets per rule) */
            for (i = 0; i < nrules; i++) pktssum[i] = 0;

            *len = sprintf(s, GNUPLOTHDR1);
            for (ruleptr = ri; ruleptr->next; ruleptr = ruleptr->next) {
                for (optptr = ruleptr->opts; optptr; optptr = optptr->next) {
                    *len += sprintf(s + *len, "\"-\" using 1:%d with filledcurve x1 title \"%s\",   ",
                                    nrules - optptr->rule_id + 1, optptr->msg);
                }
            }
            /* Last rule header */
            for (optptr = ruleptr->opts; optptr->next; optptr = optptr->next) {
                *len += sprintf(s + *len, "\"-\" using 1:%d with filledcurve x1 title \"%s\",   ",
                                nrules - optptr->rule_id + 1, optptr->msg);
            }
            /* Last option header */
            *len += sprintf(s + *len, "\"-\" using 1:%d with filledcurve x1 title \"%s\";\n",
                            nrules - optptr->rule_id + 1, optptr->msg); 
            return s;
        }        
        else if (fmt == GNUPLOTFMT2) { /* CoMo-Live! format (number of packets per rule) */
            for (i = 0; i < nrules; i++) pktssum[i] = 0;
            
            *len = sprintf(s, GNUPLOTHDR2);
            for (ruleptr = ri; ruleptr->next; ruleptr = ruleptr->next) {
                for (optptr = ruleptr->opts; optptr; optptr = optptr->next) {
                    *len += sprintf(s + *len, "\"-\" using 1:%d with lines title \"%s\",    ",
                                    optptr->rule_id + 2, optptr->msg);
                }
            }            
            /* Last rule header */
            for (optptr = ruleptr->opts; optptr->next; optptr = optptr->next) {
                *len += sprintf(s + *len, "\"-\" using 1:%d with lines title \"%s\",    ",
                                optptr->rule_id + 2, optptr->msg);
            }            
            /* Last option header */
            *len += sprintf(s + *len, "\"-\" using 1:%d with lines title \"%s\";\n",
                            optptr->rule_id + 2, optptr->msg);
            return s;
        }
        else { /* Snort Fast Alert format / pkt_t format */
            /* Return an empty string because no headers are needed for these formats */
            *len = 0;
            return s;
        }
    }
        
    if (buf == NULL && args == NULL) { 
	/* Last print callback */
        if (fmt == GNUPLOTFMT1 || fmt == GNUPLOTFMT2)
            /* CoMo-Live! needs a footer at the end */
            *len = sprintf(s, GNUPLOTFOOTER);
        else {
            /* The other formats don't need a footer at the end */
            *len = 0;
        }
        return s;    
    } 
    
    /* Rest of print callbacks (all except first and last one) */    
    
    pktinfo = (pktinfo_t *)buf; 
    pkt = &(pktinfo->pkt);
    
    /* If we selected a Snort rule in the query, make sure that
     * the packet to output matches that rule. If it doesn't, return an
     * empty string
     */
    if (rule_found && pktinfo->opt->rule_id != rule) {
        *len = 0;
        return s;
    }
    
    /* Get the packet timestamp */
    tv.tv_sec = TS2SEC(pkt->ts);
    tv.tv_usec = TS2USEC(pkt->ts);
    
    if (fmt == GNUPLOTFMT1) { /* CoMo-Live! format (percentage of packets per rule) */
	/* 
	 * Plot the percentage of packets matched by each rule. 
	 * Compute them here and then output. 
	 */
	static uint64_t pktstotalsum = 0;
        static uint64_t pkts = 0; 

        *len = sprintf(s, "%12ld ", tv.tv_sec);
        
        pktssum[pktinfo->opt->rule_id]++;
        pktstotalsum++;
        
        /* Only output every 100 alerts */
        if (count++ < 100) {
	    *len = 0; 
	    return s;
        }
	
	/* Now print the values */
	for (i = 0; i < nrules; i++) { 
            pkts += (100 * pktssum[i])/pktstotalsum; 
            *len += sprintf(s + *len, "%8llu ", pkts);
            pktssum[i] = 0;
	}

        *len += sprintf(s + *len, "\n");
        
        count = 0;
        pkts = 0;
        pktstotalsum = 0;
        
        return s;
    }
    else if (fmt == GNUPLOTFMT2) { /* CoMo-Live! format (number of packets per rule) */
        *len = sprintf(s, "%12ld ", tv.tv_sec);

        pktssum[pktinfo->opt->rule_id]++;
        
        /* Now print the values */
        for (i = 0; i < nrules; i++) {
            *len += sprintf(s + *len, "%8llu ", pktssum[i]);
        }

        *len += sprintf(s + *len, "\n");
        
        return s;
    }    

    else if (fmt == COMOFMT) { /* pkt_t format (default) */
        *len = sizeof(pkt_t) + pkt->caplen;
        return (char *)pkt;
    }
    else if (fmt == FALERTFMT) { /* Fast alert format */
        /* if the packet did not match against an alert rule,
         * do not print it (return an empty string) */
        if (pktinfo->opt->action != SNTOK_ALERT) {
            *len = 0;
            return s;
        }
        /* create the alert string and return it */
        create_alert_str(&tv, pkt, pktinfo->opt, s);
        *len = strlen(s);
        return s;
    }
    else if (fmt == PCAPLOGFMT) { /* pcap packet logging */
        /* Return a libpcap-formatted packet */
        if (pcaphdr) prv_free(pcaphdr);
        pcaphdr = (struct pcap_sf_pkthdr *)prv_alloc(sizeof(*pcaphdr) + pkt->caplen);
        pcaphdr->ts.tv_sec = tv.tv_sec;
        pcaphdr->ts.tv_usec = tv.tv_usec;
        pcaphdr->caplen = pkt->caplen;
        pcaphdr->len = pkt->len;
        memcpy(pcaphdr + 1, pkt + 1, pkt->caplen);
            
        *len = sizeof(*pcaphdr) + pkt->caplen;
        return (char *)pcaphdr;
    }
    else if (fmt == UALERTFMT) { /* Unified alert format */
        if (pktinfo->opt->action != SNTOK_ALERT) {
            *len = 0;
            return s;
        }
        event_id++;
        if (uat) prv_free(uat);
        uat = (UnifiedAlert_t *)prv_alloc(sizeof(*uat));
        uat->event.sig_generator = 1; // All events are generated by Snort rules
        uat->event.sig_id = pktinfo->opt->sid;
        uat->event.sig_rev = pktinfo->opt->rev;
        uat->event.classification = 0; // XXX ???
        uat->event.priority = pktinfo->opt->prio;
        uat->event.event_id = event_id;
        uat->event.event_reference = 0; // no tagged packets or other event references
        uat->event.ref_time.tv_sec = 0;
        uat->event.ref_time.tv_usec = 0;
        
        uat->ts.tv_sec = tv.tv_sec;
        uat->ts.tv_usec = tv.tv_usec;
        uat->sip = H32(IPS(src_ip));
        uat->dip = H32(IPS(dst_ip));
        switch (IPS(proto)) {
            case IPPROTO_TCP:
                uat->sp = H16(TCPS(src_port));
                uat->dp = H16(TCPS(dst_port));
                break;
            case IPPROTO_UDP:
                uat->sp = H16(UDPS(src_port));
                uat->dp = H16(UDPS(dst_port));
                break;
            case IPPROTO_ICMP: // For ICMP packets, save ICMP type instead of ports
                uat->sp = ICMPS(type);
                uat->dp = uat->sp;
                break;
            default:
                uat->sp = 0;
                uat->dp = 0;
                break;
        }
        uat->protocol = IPS(proto);
        uat->flags = 0; // XXX ???
        *len = sizeof(*uat);
        return (char *)uat;
    }
    else if (fmt == ULOGFMT) { /* Unified Log format */
        event_id++;
        if (ult) prv_free(ult);
        ult = (UnifiedLog_t *)prv_alloc(sizeof(*ult) + pkt->caplen);
        ult->event.sig_generator = 1; // All events are generated by Snort rules
        ult->event.sig_id = pktinfo->opt->sid;
        ult->event.sig_rev = pktinfo->opt->rev;
        ult->event.classification = 0; // XXX ???
        ult->event.priority = pktinfo->opt->prio;
        ult->event.event_id = event_id;
        ult->event.event_reference = event_id; /* no tagged packets or other event references,
                                                * so the event reference id is the same as the
                                                * event id */
        ult->event.ref_time.tv_sec = 0;
        ult->event.ref_time.tv_usec = 0;
        
        ult->flags = 0; // XXX ???
        ult->pkth.ts.tv_sec = tv.tv_sec;
        ult->pkth.ts.tv_usec = tv.tv_usec;
        ult->pkth.caplen = pkt->caplen;
        ult->pkth.len = pkt->len;
        
        memcpy(ult + 1, pkt + 1, pkt->caplen);
            
        *len = sizeof(*ult) + pkt->caplen;
        return (char *)ult;
    }
    else { /* debug format (print some info about the packets, in a similar
              way to Snort packet-logger mode */
        /* Print timestamp */
        ts_print(&tv, timebuf);
        *len = sprintf(s, "%s", timebuf);

        /* Print info about the rule that matched the packet */
        *len += sprintf(s + *len, "msg:%s", pktinfo->opt->msg); 
        for (ref = pktinfo->opt->refs; ref; ref = ref->next)
            *len += sprintf(s + *len, " ref:%s,%s", ref->systemid, ref->id);
        *len += sprintf(s + *len, "\n");
        *len += sprintf(s + *len, "sid:%d, rev:%d\n", pktinfo->opt->sid, pktinfo->opt->rev);
        *len += sprintf(s + *len, "classtype:%s, prio:%d\n", pktinfo->opt->ctype, pktinfo->opt->prio);
    
        /* Print IP addresses and port numbers (if any) */
        addr = N32(IPS(src_ip)); 
        *len += sprintf(s + *len, inet_ntoa(*(struct in_addr*) &addr)); 
        if (IPS(proto) == IPPROTO_TCP)  
            *len += sprintf(s + *len, ":%d", H16(TCPS(src_port)));
        else if (IPS(proto) == IPPROTO_UDP)
            *len += sprintf(s + *len, ":%d", H16(UDPS(src_port)));

        *len += sprintf(s + *len, " -> "); 

        addr = N32(IPS(dst_ip)); 
        *len += sprintf(s + *len, inet_ntoa(*(struct in_addr *) &addr)); 
        if (IPS(proto) == IPPROTO_TCP)  
            *len += sprintf(s + *len, ":%d", H16(TCPS(dst_port)));
        else if (IPS(proto) == IPPROTO_UDP)
            *len += sprintf(s + *len, ":%d", H16(UDPS(dst_port)));    
    
        *len += sprintf(s + *len, "\n"); 
    
        /* Print protocol type */
        switch(IPS(proto)) {
            case IPPROTO_TCP:
                *len += sprintf(s + *len, "TCP ");
                break;
            case IPPROTO_UDP:
                *len += sprintf(s + *len, "UDP ");
                break;
            case IPPROTO_ICMP:
                *len += sprintf(s + *len, "ICMP ");
                break;
            default:
                *len += sprintf(s + *len, "IP ");
                break;
        }
    
        /* Print layer3 info */
        *len += sprintf(s + *len, "TTL:%d TOS:0x%x ID:%d IpLen:%d DgmLen:%d\n",
                        IPS(ttl), IPS(tos), H16(IPS(id)), (IPS(vhl) & 0x0f) << 2,
                        H16(IPS(len)));
    
        /* Print layer4 info */
        switch(IPS(proto)) {
            case IPPROTO_TCP:
                *len += sprintf(s + *len, "Seq: 0x%x Ack: 0x%x Win: 0x%x TcpLen: %d\n",
                                H32(TCPS(seq)), H32(TCPS(ack)), H16(TCPS(win)),
                                (TCPS(hlen) >> 4) << 2);
                break;
            case IPPROTO_UDP:
                *len += sprintf(s + *len, "Len: %d\n", H16(UDPS(len)));
                break;
            case IPPROTO_ICMP:
                *len += sprintf(s + *len, "Type: %d Code: %d\n",
                                ICMPS(type), ICMPS(code));
                break;
        }
    
        /* Print payload info */
        switch(IPS(proto)) {
            case IPPROTO_IP:
                pl_start = pkt->layer4ofs;
                break;
            case IPPROTO_TCP:
                pl_start = pkt->layer4ofs + ((TCPS(hlen) >> 4) << 2);
                break;
            case IPPROTO_UDP:
                pl_start = pkt->layer4ofs + sizeof(struct _como_udphdr);
                break;
            case IPPROTO_ICMP:
                pl_start = pkt->layer4ofs + sizeof(struct _como_icmphdr);
                break;
        }
        *len += snprintf(s + *len, pkt->caplen - pl_start, "%s", (char *)(pkt + 1) + pl_start);
        
        /* End of packet info */
        *len += sprintf(s + *len, LINE_SEPARATOR);
    
        return s;
    }
}

callbacks_t callbacks = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: sizeof(EFLOWDESC),
    indesc:     NULL, 
    outdesc:    NULL,
    init:       init,
    check:      check,
    hash:       NULL,
    match:      NULL,
    update:     update,
    ematch:     ematch,
    export:     export,
    compare:    NULL,
    action:     action,
    store:      store,
    load:       load,
    print:      print,
    replay:     NULL
};
