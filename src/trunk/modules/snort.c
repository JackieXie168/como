/*
 * Copyright (c) 2005 Universitat Politecnica de Catalunya 
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
 * Snort Module
 *
 * This module interprets and runs Snort rules passed as arguments from the
 * config file
 * Possible outputs: 
 * - logs in libpcap format, alerts in Snort's fast-alert format
 * - packet trace formed by pkt_t structures
 * - unified log or alert files (readable with Barnyard)
 * - data for gnuplot to create a chart
 */

#include <errno.h>          /* ENOMEM */
#include <time.h>           /* gmtime ... */
#include <string.h>         /* bcopy */
#include <sys/types.h>
#include <pcap.h>           /* libpcap data types */
#include <ctype.h>          /* isalpha, tolower */

#include "como.h"
#include "module.h"
#include "snort.h"

#define BUF_SIZE        65535   // Maximum total size of an IPv4 packet
#define RECSIZE         BUF_SIZE + sizeof(struct snort_hdr)
                        // Actual max size of a record on disk

#define FLOWDESC        struct _snort

#define TIMEBUF_SIZE    26

#define IP_ADDR_LEN     15      /* strlen("XXX.XXX.XXX.XXX") */
#define OUTPUT_LEN      4096    /* size of the strings returned by the
                                   print() callback */

#define CMP_EQ          0       /* Used for some options of Snort rules */
#define CMP_GT          1
#define CMP_LT          -1
#define CMP_BTW         2

FLOWDESC {
    rec_t   r;
    uint    bytes_used;
    uint8_t bytes[BUF_SIZE];
};

struct snort_hdr {
    uint8_t isalert;    /* 0 = non-alert rule, 1 = alert rule */
    int rulenum;        /* Snort rule number that fired the alert 
                           (-1 if the packet was logged by a non-alert rule) */
    pkt_t pkt;          /* CoMo packet info */
};

/* Input and output packet description, needed to use dump()
   XXX this is not supported yet!
static pktdesc_t indesc;
static pktdesc_t outdesc; */

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

/* Here we save the info that we get from Snort rules */
ruleinfo_t ri[MAX_RULES];

/* Number of Snort rules in the config file */
int nrules = 0;

/* Number of the rule that matches with a packet */
int rule_match;

/* Declaration of the Bison-generated parsing routine */
int parse_rules(char *rules, void *mem, size_t msize);

/*
 * -- hextochar
 *  Parses a string and translates the hexadecimal content parts
 *  (p.ex. |0a 75 f5 22|) to normal characters
 *
 */
static uint 
hextochar(unsigned char *string)
{
    uint i = 0, j = 0;
    unsigned char c[4] = {'0', 'x', '0', '0'};

    while (i < strlen(string)) {
        if (string[i] == '|') {
            i++;
            while (string[i] != '|') {
                if (string[i] == ' ') i++;
                else {
                    strncpy(&c[2], &string[i], 2);
                    string[j] = (unsigned char)strtol(c, NULL, 16);
                    i += 2; j++;
                }
            }
            i++;
        }
        else {
            string[j] = string[i];
            i++; j++;
        }
    }
    
    return j;
}
    
/*
 * -- lowercase
 *  Transforms a string into lowercase
 *
 */

static void lowercase(char *string, unsigned int length) {
    unsigned int i;
    for(i = 0; i < length; i++) {
        if (isalpha(string[i])) string[i] = tolower(string[i]);
    }
}
    
static int
init(void *mem, size_t msize, char **args)
{
    int i;
    optnode_t *opt, *optaux;
    int has_sid;
    int has_prio;
    int has_content;
    int classtype;
    /* Needed for pcre expression compiling */
    pcre *regexp_aux;
    const char *error;
    int erroffset;
    char *straux;
    
    /* Check and initialize the module's private memory region */
    if (msize < 10000) {
	logmsg(LOGWARN, "need 10Kbytes of private memory, have just %d\n", msize);
	return ENOMEM; 
    } 
    memset(mem, 0, msize);
    
    /* Call the parsing routine generated by Bison.
     * It reads Snort rules info and fills the ri
     * structure with it.
     */
    for(i = 0; args[i] != NULL; i++) {
        if (parse_rules(args[i], mem, msize) == 1) {
            return 1;
        }
    }
    
    /* Rules options preprocessing */
    for (i = 0; i < nrules; i++) {
        /* Initialization */
        has_sid = 0;
        has_prio = 0;
        has_content = 0;
        ri[i].nocase = 0;
        ri[i].activates = -1;
        ri[i].actvby = -1;
        ri[i].count = -1;
        ri[i].offset = 0;
        ri[i].depth = 0;
        
        /* First pass through the rule's options */
        opt = ri[i].opts;
        while (opt != NULL) {
            switch(opt->keyword) {
                case SNTOK_SID:
                    has_sid = 1;
                    break;
            }
            opt = opt->next;
        }
        /* Second pass */
        opt = ri[i].opts;
        while (opt != NULL) {
            switch(opt->keyword) {
                case SNTOK_NULL:
                    break;
                case SNTOK_MSG:
                    strncpy(ri[i].msg, opt->content, MAX_STR_SIZE);
                    break;
                case SNTOK_SID:
                    ri[i].sid = atoi(opt->content);
                    break;
                case SNTOK_REV:
                    if (!has_sid) {
                        logmsg(LOGWARN, "SNORT: rule %d: rev option without sid\n", i);
                        return 1;
                    }
                    ri[i].rev = atoi(opt->content);
                    break;
                case SNTOK_CTYPE:
                    strncpy(ri[i].ctype, opt->content, MAX_STR_SIZE);
                    classtype = translate_kw(opt->content);
                    switch(classtype) {
                        case SNTOK_HIGHPRIO:
                            if (!has_prio) ri[i].priority = 1;
                            break;
                        case SNTOK_MEDPRIO:
                            if (!has_prio) ri[i].priority = 2;
                            break;
                        case SNTOK_LOWPRIO:
                            if (!has_prio) ri[i].priority = 3;
                            break;                            
                        case SNTOK_NULL:
                            logmsg(LOGWARN, "SNORT: rule %d: Wrong classtype\n", i);
                            return 1;
                    }
                    break;
                case SNTOK_PRIO:
                    ri[i].priority = atoi(opt->content);
                    has_prio = 1;
                    break;
                case SNTOK_NOCASE:
                    if (!has_content) {
                        logmsg(LOGWARN, "SNORT: rule %d: nocase option without content\n", i);
                        return 1;
                    }
                    ri[i].nocase = 1;
                    for (optaux = ri[i].opts; optaux != NULL; optaux = optaux->next) {
                        if (optaux->keyword == SNTOK_CONTENT)
                            lowercase(optaux->content, optaux->cntlen);
                    }                        
                    break;
                case SNTOK_OFFSET:
                    if (!has_content) {
                        logmsg(LOGWARN, "SNORT: rule %d: offset option without content\n", i);
                        return 1;                        
                    }
                    ri[i].offset = atoi(opt->content);
                    break;
                case SNTOK_DEPTH:
                    if (!has_content) {
                        logmsg(LOGWARN, "SNORT: rule %d: depth option without content\n", i);
                        return 1;                        
                    }                        
                    ri[i].depth = atoi(opt->content);
                    break;
                case SNTOK_FROFFSET:
                    if (strstr(opt->content, ">") == opt->content) {
                        ri[i].fragoffset = atoi(opt->content + 1);
                        ri[i].fragoffcmp = CMP_GT;
                    }
                    else if (strstr(opt->content, "<") == opt->content) {
                        ri[i].fragoffset = atoi(opt->content + 1);
                        ri[i].fragoffcmp = CMP_LT;
                    }
                    else {
                        ri[i].fragoffset = atoi(opt->content);
                        ri[i].fragoffcmp = CMP_EQ;
                    }
                    break;
                case SNTOK_TTL:
                    if (strstr(opt->content, ">") == opt->content) {
                        ri[i].ttllow = atoi(opt->content + 1);
                        ri[i].ttlcmp = CMP_GT;
                    }
                    else if (strstr(opt->content, "<") == opt->content) {
                        ri[i].ttllow = atoi(opt->content + 1);
                        ri[i].ttlcmp = CMP_LT;
                    }
                    else if ((straux = strstr(opt->content, "-")) != NULL) {
                        ri[i].ttllow = atoi(opt->content);
                        ri[i].ttlhigh = atoi(straux + 1);
                        ri[i].ttlcmp = CMP_BTW;
                    }
                    else {
                        ri[i].ttllow = atoi(opt->content);
                        ri[i].ttlcmp = CMP_EQ;
                    }
                    break;
                case SNTOK_TOS:
                    if (strstr(opt->content, "!") == opt->content) {
                        opt->neg = 1;
                        ri[i].tos = atoi(opt->content + 1);
                    }
                    else {
                        opt->neg = 0;
                        ri[i].tos = atoi(opt->content);
                    }
                    break;
                case SNTOK_IPID:
                    ri[i].ipid = atoi(opt->content);
                    break;
                case SNTOK_DSIZE:
                    if (strstr(opt->content, ">") == opt->content) {
                        ri[i].dsizelow = atoi(opt->content + 1);
                        ri[i].dsizecmp = CMP_GT;
                    }
                    else if (strstr(opt->content, "<") == opt->content) {
                        ri[i].dsizelow = atoi(opt->content + 1);
                        ri[i].dsizecmp = CMP_LT;                        
                    }
                    else if ((straux = strstr(opt->content, "<>")) != NULL) {
                        ri[i].dsizelow = atoi(opt->content);
                        ri[i].dsizehigh = atoi(straux + 2);
                        ri[i].dsizecmp = CMP_BTW;
                    }
                    else {
                        ri[i].dsizelow = atoi(opt->content);
                        ri[i].dsizecmp = CMP_EQ;
                    }                    
                    break;
                case SNTOK_ACTIVATES:
                    ri[i].activates = atoi(opt->content);
                    break;                
                case SNTOK_ACTVBY:
                    ri[i].actvby = atoi(opt->content);
                    break;
                case SNTOK_COUNT:
                    ri[i].count = atoi(opt->content);
                    break;
                case SNTOK_CONTENT:
                    /* search pattern preprocessing */
                    opt->cntlen = hextochar(opt->content);
                    preBmBc(opt->content, opt->cntlen, opt->bmBc);
                    opt->bmGs = (int *)prv_alloc(opt->cntlen * sizeof(int));
                    preBmGs(opt->content, opt->cntlen, opt->bmGs);
                    has_content = 1;
                    break;
                case SNTOK_PCRE:
                    /* Compile the regexp found in the rule */
                    pcre_malloc = prv_alloc;
                    pcre_free = prv_free;
                    regexp_aux = pcre_compile(opt->content, 0, &error, &erroffset, NULL);                    
                    if (regexp_aux == NULL) {
                        logmsg(LOGWARN, "SNORT: rule %d: wrong pcre expression\n", i);
                        return 1;
                    } 
                    ri[i].regexp = regexp_aux;
                    break;
                default:
                    break;
            }
            opt = opt->next;
        }

        /* Check that all the mandatory rule options are present */
        if (ri[i].action == SNTOK_ACTIV && ri[i].activates < 0) {
            logmsg(LOGWARN, "SNORT: rule %d: activate rule without activates option\n", i);
            return 1;
        }
        if (ri[i].action == SNTOK_DYN && ri[i].count < 0) {
            logmsg(LOGWARN, "SNORT: rule %d: dynamic rule without count option\n", i);
            return 1;
        }
    }

    /* Fill the input and output packet description.
     * We need and provide entire packet headers 
     * so we fill all the bitmasks with ones.
     */
    /* XXX this is not supported yet!
    memset(&indesc, 0, sizeof(pktdesc_t));
    memset(&(indesc.bm), 0xff, sizeof(struct _como_eth) + sizeof(struct _como_hdlc) + 
                            sizeof(struct _como_iphdr) + sizeof(struct _como_tcphdr) + 
                            sizeof(struct _como_udphdr) + sizeof(struct _como_icmphdr));
    memset(&outdesc, 0, sizeof(pktdesc_t));
    memset(&(outdesc.bm), 0xff, sizeof(struct _como_eth) + sizeof(struct _como_hdlc) + 
                            sizeof(struct _como_iphdr) + sizeof(struct _como_tcphdr) + 
                            sizeof(struct _como_udphdr) + sizeof(struct _como_icmphdr)); */
    return 0;
}
    
/**
 * -- check_proto
 *
 * matches the protocol type in a packet 
 * with the one obtained from a Snort rule
 *
 */
unsigned int 
check_proto(ruleinfo_t *info, pkt_t *pkt)
{
    if (info->proto == IPPROTO_IP) {
        /* XXX TODO: Only works for Ethernet... add more link types? */
        return (H16(ETH(type)) == 0x0800);
    }
    else if (pkt->l3type == ETHERTYPE_IP) {
        return (IP(proto) == info->proto);
    }
    else return 0;
}

/**
 * -- check_xxx_xxx_port
 *
 * match the tcp/udp port in a packet 
 * against a set of ports obtained from a Snort rule
 *
 */    
unsigned int 
check_tcp_src_port(ruleinfo_t *info, pkt_t *pkt)
{
    unsigned int r = 0;
    r = ( info->src_ports.lowport <= H16(TCP(src_port)) &&
          info->src_ports.highport >= H16(TCP(src_port))    );
    if (info->src_ports.negation) r ^= 1;
    return r;
}

unsigned int 
check_tcp_dst_port(ruleinfo_t *info, pkt_t *pkt)
{
    unsigned int r = 0;
    r = ( info->dst_ports.lowport <= H16(TCP(dst_port)) &&
          info->dst_ports.highport >= H16(TCP(dst_port))    );
    if (info->dst_ports.negation) r ^= 1;
    return r;
}

unsigned int 
check_udp_src_port(ruleinfo_t *info, pkt_t *pkt)
{
    unsigned int r = 0;
    r = ( info->src_ports.lowport <= H16(UDP(src_port)) &&
          info->src_ports.highport >= H16(UDP(src_port))    );
    if (info->src_ports.negation) r ^= 1;
    return r;
}

unsigned int 
check_udp_dst_port(ruleinfo_t *info, pkt_t *pkt)
{
    unsigned int r = 0;
    r = ( info->dst_ports.lowport <= H16(UDP(dst_port)) &&
          info->dst_ports.highport >= H16(UDP(dst_port))    );
    if (info->dst_ports.negation) r ^= 1;
    return r;
}

/**
 * -- check_xxx_ip
 *
 * match the src/dst IP address in a packet 
 * with the one(s) obtained from a Snort rule
 *
 */    
unsigned int
check_src_ip(ruleinfo_t *info, pkt_t *pkt)
{
    unsigned int r = 0; 
    ipnode_t *aux;
    aux = info->src_ips.ipnode;
    while (aux != NULL && !r) {
        r = (aux->ipaddr == (N32(IP(src_ip)) & aux->netmask));
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
        r = (aux->ipaddr == (N32(IP(dst_ip)) & aux->netmask));
        aux = aux->next;
    }
    if (info->dst_ips.negation) r ^= 1;
    return r;
}

#define OVECCOUNT 30 /* needed for pcre matching, multiple of 3 */

/**
 * -- check_options
 *
 * processes the options found in a Snort rule's body
 * against the info in a packet
 * 
 */
unsigned int
check_options(ruleinfo_t *info, pkt_t *pkt)
{
    uint plsize;
    optnode_t *opt;
    /* Variables needed for pcre-matching */
    int rc;
    int ovector[OVECCOUNT];
    
    switch(IP(proto)) {
        case IPPROTO_TCP:
            /* We don't use sizeof(struct _como_tcphdr) because it's possible
             * that the packet contains TCP options, making the header larger */
            plsize = pkt->caplen - pkt->layer4ofs + ((TCP(hlen) >> 4) << 2);
            break;
        case IPPROTO_UDP:
            plsize = pkt->caplen - pkt->layer4ofs + sizeof(struct _como_udphdr);
            break;
        case IPPROTO_ICMP:
            plsize = pkt->caplen - pkt->layer4ofs + sizeof(struct _como_icmphdr);
            break;            
        default:
            logmsg(LOGWARN, "SNORT: Unsupported protocol\n");
            plsize = pkt->caplen - pkt->layer4ofs;
            break;
    }
    
    unsigned char pl[plsize];

    opt = info->opts;
    while (opt != NULL) {
        switch(opt->keyword) {
            case SNTOK_NULL:
                /* There are no options in the rule */
                return 1;
            case SNTOK_MSG: 
                break;
            case SNTOK_SID:
                break;
            case SNTOK_REV:
                break;
            case SNTOK_CTYPE:
                break;
            case SNTOK_PRIO:
                break;
            case SNTOK_NOCASE:
                break;
            case SNTOK_OFFSET:
                break;
            case SNTOK_DEPTH:
                break;
            case SNTOK_FROFFSET:
                switch (info->fragoffcmp) {
                    case CMP_EQ:
                        if (info->fragoffset != (H16(IP(ofs)) & 0x1fff)) return 0;
                        break;
                    case CMP_GT:
                        if (info->fragoffset >= (H16(IP(ofs)) & 0x1fff)) return 0;
                        break;
                    case CMP_LT:
                        if (info->fragoffset <= (H16(IP(ofs)) & 0x1fff)) return 0;
                        break;
                }
                break;
            case SNTOK_TTL:
                switch (info->ttlcmp) {
                    case CMP_EQ:
                        if (info->ttllow != IP(ttl)) return 0;
                        break;
                    case CMP_GT:
                        if (info->ttllow >= IP(ttl)) return 0;
                        break;
                    case CMP_LT:
                        if (info->ttllow <= IP(ttl)) return 0;
                        break;
                    case CMP_BTW:
                        if (info->ttllow > IP(ttl) ||
                            info->ttlhigh < IP(ttl)) return 0;
                        break;
                }
                break;
            case SNTOK_TOS:
                if ((info->tos != IP(tos) && !opt->neg) ||
                    (info->tos == IP(tos) && opt->neg)) return 0;
                break;
            case SNTOK_IPID:
                if (info->ipid != H16(IP(id))) return 0;
                break;
            case SNTOK_DSIZE:
                switch (info->dsizecmp) {
                    case CMP_EQ:
                        if (info->dsizelow != plsize) return 0;
                        break;
                    case CMP_GT:
                        if (info->dsizelow >= plsize) return 0;
                        break;
                    case CMP_LT:
                        if (info->dsizelow <= plsize) return 0;
                        break;
                    case CMP_BTW:
                        if (info->dsizelow > plsize ||
                            info->dsizehigh < plsize) return 0;
                        break;
                }                
                break;
            case SNTOK_ACTIVATES:
                break;
            case SNTOK_ACTVBY:
                break;
            case SNTOK_COUNT:
                break;
            case SNTOK_CONTENT:
                if (info->offset > (plsize)) {
                    logmsg(LOGWARN, "SNORT: offset option larger than payload\n");
                    return 0;
                }
                if (info->depth > 0)
                    plsize = MIN(plsize - info->offset, info->depth);
                else plsize = plsize - info->offset;
                if (IP(proto) == IPPROTO_TCP)
                    bcopy(TCP(payload) + info->offset, pl, plsize);
                else if (IP(proto) == IPPROTO_UDP)
                    bcopy(UDP(payload) + info->offset, pl, plsize);
                else if (IP(proto) == IPPROTO_ICMP)
                    bcopy(ICMP(payload) + info->offset, pl, plsize);
                else {
                    logmsg(LOGWARN, "SNORT: Unsupported protocol\n");
                    bcopy((pkt->payload + pkt->layer4ofs) + info->offset, pl, plsize);
                }
                if (info->nocase) lowercase(pl, plsize);
                if (!BM(opt->content, opt->cntlen, pl, plsize, opt->bmBc, opt->bmGs))
                    return 0;
                break;
            case SNTOK_PCRE:
                if (IP(proto) == IPPROTO_TCP)
                    bcopy(TCP(payload), pl, plsize);
                else if (IP(proto) == IPPROTO_UDP)
                    bcopy(UDP(payload), pl, plsize);
                else if (IP(proto) == IPPROTO_ICMP)
                    bcopy(ICMP(payload), pl, plsize);
                else {
                    logmsg(LOGWARN, "SNORT: Unsupported protocol\n");
                    bcopy((pkt->payload + pkt->layer4ofs), pl, plsize);
                }
                rc = pcre_exec(info->regexp, NULL, pl, plsize, 0, 0,
                               ovector, OVECCOUNT);
                if (rc < 0) {
                    switch(rc) {
                        case PCRE_ERROR_NOMATCH: 
                            return 0;
                        default:
                            logmsg(LOGWARN, "SNORT: error while matching pcre\n");
                            return 0;
                    }
                }                
                break;
            default:
                logmsg(LOGWARN, "SNORT: unknown Snort option\n");
                break;
        }
        opt = opt->next;
    }
    return 1;
}
    
/*
 * -- swap_ip_list
 * -- swap_port_list
 *
 * Auxiliar functions used by check() for bidirectional rules 
 *
 */
    
static void
swap_ip_list(ip_t *src, ip_t *dst)
{
    ip_t aux;
    
    aux = *src;
    *src = *dst;
    *dst = aux;
    
    return;
}
    
static void
swap_port_list(portset_t *src, portset_t *dst)
{
    portset_t aux;

    aux = *src;
    *src = *dst;
    *dst = aux;
    
    return;
}
    
static int
check(pkt_t *pkt)
{
    /* compare the incoming packet with the info
     * obtained from the Snort rules
     */    
    
    int i;
    unsigned int ok;
    fpnode_t *fp;
    
    for (i = 0; i < nrules; i++) {
        /* First check whether the rule is active */
        if (!ri[i].active) continue;
        
        /* Check whether the rule matches the packet in the -> direction */
        ok = 1;
        for (fp = ri[i].funcs; fp != NULL && ok; fp = fp->next) {
            ok &= fp->function(&ri[i], pkt);
        }
        if (ok) {
            /* The rule matched the packet in the -> direction
             * If it's a pass rule, we drop the packet 
             */
            if (ri[i].action == SNTOK_PASS) {
                rule_match = -1;
                return 0;
            }
            /* If it's not a pass rule, we accept the packet, 
             * save the rule no. that matched against it,
             * and activate another rule if necessary 
             */
            else {
                rule_match = i;
                if (ri[i].action == SNTOK_ACTIV) {
                    ri[ri[i].activates].active = 1;
                    ri[ri[i].activates].act_count = ri[ri[i].activates].count;
                }
                if (ri[i].action == SNTOK_DYN) {
                    ri[i].act_count--;
                    if (ri[i].act_count <= 0) ri[i].active = 0;
                }
                return 1;
            }
        }
        else if (ri[i].bidirectional) {
            /* Swap the source and destination ip's and ports 
             * It's not a problem if we directly modify the ri structure 
             */
            swap_ip_list(&(ri[i].src_ips), &(ri[i].dst_ips));
            swap_port_list(&(ri[i].src_ports), &(ri[i].dst_ports));
            
            /* Modify the list of pointers to check functions */
            for (fp = ri[i].funcs; fp != NULL; fp = fp->next) {
                if (fp->function == check_tcp_src_port)
                    fp->function = check_tcp_dst_port;
                else if (fp->function == check_tcp_dst_port)
                    fp->function = check_tcp_src_port;
                else if (fp->function == check_udp_src_port)
                    fp->function = check_udp_dst_port;
                else if (fp->function == check_udp_dst_port)
                    fp->function = check_udp_src_port;
                else if (fp->function == check_src_ip)
                    fp->function = check_dst_ip;
                else if (fp->function == check_dst_ip)
                    fp->function = check_src_ip;
            }
            
            /* Check whether the rule matches the packet in the <- direction */ 
            ok = 1;
            for (fp = ri[i].funcs; fp != NULL && ok != 0; fp = fp->next) {
                ok &= fp->function(&(ri[i]), pkt);
            }
            if (ok) {
                /* The rule matched the packet in the <- direction
                 * If it's a pass rule, we drop the packet 
                 */
                if (ri[i].action == SNTOK_PASS) {
                    rule_match = -1;
                    return 0;
                }
                /* If it's not a pass rule, we accept the packet, 
                 * save the rule no. that matched against it,
                 * and activate another rule if necessary 
                 */
                else {
                    rule_match = i;
                    if (ri[i].action == SNTOK_ACTIV) {
                        ri[ri[i].activates].act_count = ri[ri[i].activates].count;
                        ri[ri[i].activates].active = 1;
                    }
                    if (ri[i].action == SNTOK_DYN) {
                        ri[i].act_count--;
                        if (ri[i].act_count <= 0) ri[i].active = 0;
                    }                    
                    return 1;
                }
            }
        }
    }
    // None of the rules matched the packet
    rule_match = -1;
    return 0;
}

static int
update(pkt_t *pkt, void *fh, int new_rec, __unused unsigned drop_cntr)
{
    FLOWDESC *x;
    struct snort_hdr *shdr;
    int max_pktsize;
    
    x = (FLOWDESC *)(fh);
            
    if (new_rec)
        x->bytes_used = 0;
    
    shdr = (struct snort_hdr *)(x->bytes + x->bytes_used);
    
    if ( rule_match >= 0 && 
         (ri[rule_match].action == SNTOK_ALERT 
          || ri[rule_match].action == SNTOK_ACTIV) )
        shdr->isalert = 1;
    else shdr->isalert = 0;
    
    shdr->rulenum = rule_match;
    
    bcopy(pkt, &shdr->pkt, sizeof(pkt_t));
    bcopy(pkt->payload, shdr + 1, pkt->caplen);
    
    x->bytes_used += sizeof(struct snort_hdr) + pkt->caplen;
    
    /* XXX TODO: This value should vary according to the sniffer used */
    switch (pkt->l2type) {
        case COMOTYPE_ETH:
            max_pktsize = 1514; // Ethernet MTU (1500 bytes) + Ethernet header (14 bytes)
            break;
        default:
            /* Default is Ethernet */
            max_pktsize = 1514;
            break;
    }
    if (x->bytes_used + sizeof(struct snort_hdr) + max_pktsize >= BUF_SIZE)
        return 1; /* The record might overflow next time we try to use it */
    return 0;
}

static ssize_t
store(void *fh, char *buf, size_t len)
{
    FLOWDESC *x;
    
    x = (FLOWDESC *)(fh);
        
    if (len < RECSIZE)
        return -1;
    memcpy(buf, x->bytes, x->bytes_used);
    return x->bytes_used;
}

static size_t
load(char * buf, size_t len, timestamp_t * ts)
{
    struct snort_hdr *shdr;
    
    /* The buffer that we receive must contain at least the
     * snort_hdr structure, even if it has no packet info 
     */
    if (len < sizeof(struct snort_hdr)) {
        ts = 0;
	return 0;
    }
    shdr = (struct snort_hdr *)buf;
    *ts = shdr->pkt.ts;
    return sizeof(struct snort_hdr) + shdr->pkt.caplen;
}

/*
 * -- ts_print
 *
 * Converts a timeval structure into a readable string
 * Taken from tcpdump code and modified
 */
static char * 
ts_print(const struct timeval *tvp)
{
    register int s;
    int    localzone;
    time_t Time;
    struct timeval tv;
    struct timezone tz;
    struct tm *lt;    /* place to stick the adjusted clock data */
    static char timebuf[25];

    /* if null was passed, we use current time */
    if(!tvp)
    {
        /* manual page (for linux) says tz is never used, so.. */
        bzero((char *) &tz, sizeof(tz));
        gettimeofday(&tv, &tz);
        tvp = &tv;
    }

    /* Assume we are using UTC */
    localzone = 0;
        
    s = (tvp->tv_sec + localzone) % 86400;
    Time = (tvp->tv_sec + localzone) - s;
    
    lt = gmtime(&Time);
    
    /* We do not include the year in the string */
    (void) snprintf(timebuf, TIMEBUF_SIZE,
                        "%02d/%02d-%02d:%02d:%02d.%06u ", lt->tm_mon + 1,
                        lt->tm_mday, s / 3600, (s % 3600) / 60, s % 60,
                        (u_int) tvp->tv_usec);
    return timebuf;
}

#define SNORTIP(packet,field)  ((struct _como_iphdr *) ((char *)(packet + 1) + packet->layer3ofs))->field
#define SNORTTCP(packet,field) ((struct _como_tcphdr *) ((char *)(packet + 1) + packet->layer4ofs))->field
#define SNORTUDP(packet,field) ((struct _como_udphdr *) ((char *)(packet + 1) + packet->layer4ofs))->field
#define SNORTICMP(packet,field) ((struct _como_icmphdr *) ((char *)(packet + 1) + packet->layer4ofs))->field

/*
 * -- create_alert_str
 *
 * utility function used to print a Snort alert
 */
static void 
create_alert_str(struct timeval *t, pkt_t *pkt, int rule, char *s)
{
    char srcip[IP_ADDR_LEN];
    char dstip[IP_ADDR_LEN];
    char srcport[5];
    char dstport[5];
    char proto[5];
    char *timestr;
    struct in_addr addr;
    
    timestr = ts_print(t);
    addr.s_addr = N32(SNORTIP(pkt,src_ip));
    snprintf(srcip, IP_ADDR_LEN, "%s", inet_ntoa(addr));
    addr.s_addr = N32(SNORTIP(pkt,dst_ip));
    snprintf(dstip, IP_ADDR_LEN, "%s", inet_ntoa(addr));
    
    switch (SNORTIP(pkt,proto)) {
        case IPPROTO_TCP:
            sprintf(proto, "tcp");
            sprintf(srcport, "%d", H16(SNORTTCP(pkt,src_port)));
            sprintf(dstport, "%d", H16(SNORTTCP(pkt,dst_port)));
            break;
        case IPPROTO_UDP:
            sprintf(proto, "udp");
            sprintf(srcport, "%d", H16(SNORTUDP(pkt,src_port)));
            sprintf(dstport, "%d", H16(SNORTUDP(pkt,dst_port))); 
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
                timestr, ri[rule].sid, ri[rule].rev, rule, ri[rule].msg, 
                ri[rule].ctype, ri[rule].priority, proto, srcip, srcport, 
                dstip, dstport);
}
    
#define MAXARGLEN   20

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
/* GNUPLOT_PERCENT: 
 * If this is defined, the gnuplot output is the percentage of packets
 * per rule over the total packets that match any rule.
 * If not, the gnuplot output is the total of packets per rule */
// #define GNUPLOT_PERCENT

#define PCAPLOGFMT      1
#define FALERTFMT       2
#define ULOGFMT         3
#define UALERTFMT       4
#define COMOFMT         5
#define GNUPLOTFMT1     6
#define GNUPLOTFMT2     7

static char *
print(char *buf, size_t *len, char * const args[])
{
    static struct pcap_file_header fhdr;
    static UnifiedAlertFileHeader_t uafhdr;
    static UnifiedLogFileHeader_t ulfhdr;
    static char s[OUTPUT_LEN];
    struct snort_hdr *shdr;
    pkt_t *pkt;
    static struct pcap_sf_pkthdr *pcaphdr;
    static UnifiedAlert_t *uat;
    static UnifiedLog_t *ult;
    static uint64_t event_id = 0;
    struct timeval t;

    int n;
    int fmt_found = 0;
    static int rule_found = 0;
    static int fmt;
    char *ruletxt;
    static int rule;
    
    int i;
    static int count = 0;
    static uint64_t pktssum[100];

    /* First print callback. Process the arguments and return a libpcap file
     * header if necessary.
     */
    if (buf == NULL && args != NULL) {
        /* Parse the optional arguments passed in the query string */
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
        }
        /* If no format argument has been specified in the query, 
        * the default is to output a stream of pkt_t structs 
        */
        if (!fmt_found) {
            logmsg(LOGQUERY, "SNORT: missing query argument \"format=xxx\"\n");
            fmt = COMOFMT;
        }

        for (n = 0; args[n]; n++) {
            if ((ruletxt = strstr(args[n], "rule="))) {
                rule_found = 1;
                rule = atoi(ruletxt + 5);
            }
        }
    
        if (fmt == PCAPLOGFMT) { /* libpcap file format */
            /* XXX TODO: snaplen and linktype should vary depending on 
             * the sniffer we use (pass them as init parameters?)
             * linktype could be gathered from pkt->l2type
             */
            fhdr.magic = TCPDUMP_MAGIC;
            fhdr.version_major = PCAP_VERSION_MAJOR;
            fhdr.version_minor = PCAP_VERSION_MINOR;
            fhdr.thiszone = 0;    // Time Zone Offset - gmt to local correction
            fhdr.snaplen = 65535; /* Maximum number of captured bytes per packet
                                   * We are capturing entire packets, so we put
                                   * here the maximum IPv4 MTU */
            fhdr.sigfigs = 0;     // Time Stamp Accuracy
            fhdr.linktype = 1;    // Ethernet
    
            *len = sizeof(fhdr);
            return (char *)&fhdr;
        }
        else if (fmt == ULOGFMT) { /* Unified Log format */
            /* XXX TODO: snaplen and linktype should depend on the sniffer used */
            ulfhdr.magic = LOG_MAGIC;
            ulfhdr.version_major = SNORT_VERSION_MAJOR;
            ulfhdr.version_minor = SNORT_VERSION_MINOR;
            ulfhdr.timezone = 0;    // Time Zone Offset - gmt to local correction
            ulfhdr.snaplen = 65535; /* Maximum number of captured bytes per packet
                                     * We are capturing entire packets, so we put
                                     * here the maximum IPv4 MTU */
            ulfhdr.sigfigs = 0;     // Time Stamp Accuracy
            ulfhdr.linktype = 1;    // Ethernet
            *len = sizeof(ulfhdr);
            return (char *)&ulfhdr;
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
            for (i = 0; i < nrules - 1; i++) {
                *len += sprintf(s + *len, "\"-\" using 1:%d with filledcurve x1 title \"%s\",   ",
                                nrules - i + 1, ri[nrules - i - 1].msg);
            }
            *len += sprintf(s + *len, "\"-\" using 1:%d with filledcurve x1 title \"%s\";\n",
                            nrules -i + 1, ri[nrules - i - 1].msg);
            return s;
        }        
        else if (fmt == GNUPLOTFMT2) { /* CoMo-Live! format (number of packets per rule) */
            for (i = 0; i < nrules; i++) pktssum[i] = 0;
            
            *len = sprintf(s, GNUPLOTHDR2);
            for (i = 0; i < nrules - 1; i++) {
                *len += sprintf(s + *len, "\"-\" using 1:%d with lines title \"%s\",    ",
                                i + 2, ri[i].msg);
            }
            *len += sprintf(s + *len, "\"-\" using 1:%d with lines title \"%s\";\n",
                            i + 2, ri[i].msg);
            return s;
        }
        else { /* Snort Fast Alert format / pkt_t format */
            /* Return an empty string because no headers are needed for this format */
            *len = 0;
            return s;
        }
    }
    
    /* Last print callback */
    if (buf == NULL && args == NULL) {
        if (fmt == GNUPLOTFMT1 || fmt == GNUPLOTFMT2) /* CoMo-Live! format */
            *len = sprintf(s, GNUPLOTFOOTER);
        else {
            /* The other formats don't need a footer at the end */
            *len = 0;
        }
        return s;
    }
    
    /* Rest of print callbacks (all except first and last one) */
    
    shdr = (struct snort_hdr *)buf;
    pkt = &(shdr->pkt);
    
    /* If we have selected a Snort rule in the query, make sure that
     * the packet to output matches that rule. If it doesn't, return an
     * empty string
     */
    if (rule_found && shdr->rulenum != rule) {
        *len = 0;
        return s;
    }
    
    t.tv_sec = TS2SEC(shdr->pkt.ts);
    t.tv_usec = TS2USEC(shdr->pkt.ts);
    
    if (fmt == GNUPLOTFMT1) { /* CoMo-Live! format (percentage of packets per rule */
	/* 
	 * Plot the percentage of packets matched by each rule. 
	 * Compute them here and then output. 
	 */
	static uint64_t pktstotalsum = 0;
        static uint64_t pkts = 0; 

        *len = sprintf(s, "%12ld ", t.tv_sec);
        
        pktssum[shdr->rulenum]++;
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
        *len = sprintf(s, "%12ld ", t.tv_sec);

        pktssum[shdr->rulenum]++;
        
        /* Now print the values */
        for (i = 0; i < nrules; i++) {
            *len += sprintf(s + *len, "%8llu ", pktssum[i]);
        }

        *len += sprintf(s + *len, "\n");
        
        return s;
    }
    else if (fmt == COMOFMT) { /* pkt_t format (default) */
        *len = sizeof(pkt_t) + shdr->pkt.caplen;
        return buf + sizeof(int);
    }
    else if (fmt == FALERTFMT) { /* Fast alert format */
        /* if the packet did not match against an alert rule,
         * do not print it (return an empty string) */
        if (!shdr->isalert) {
            *len = 0;
            return s;
        }
        /* create the alert string and return it */
        create_alert_str(&t, &(shdr->pkt), shdr->rulenum, s);
        *len = strlen(s);
        return s;
    }
    else if (fmt == PCAPLOGFMT) { /* pcap packet logging */
        /* Return a libpcap-formatted packet */
        if (pcaphdr) prv_free(pcaphdr);
        pcaphdr = (struct pcap_sf_pkthdr *)prv_alloc(sizeof(*pcaphdr) + shdr->pkt.caplen);
        pcaphdr->ts.tv_sec = TS2SEC(shdr->pkt.ts);
        pcaphdr->ts.tv_usec = TS2USEC(shdr->pkt.ts);
        pcaphdr->caplen = shdr->pkt.caplen;
        pcaphdr->len = shdr->pkt.len;
        bcopy(&(shdr->pkt) + 1, pcaphdr + 1, shdr->pkt.caplen);
            
        *len = sizeof(*pcaphdr) + shdr->pkt.caplen;
        return (char *)pcaphdr;
    }
    else if (fmt == UALERTFMT) { /* Unified alert format */
        if (!shdr->isalert) {
            *len = 0;
            return s;
        }
        event_id++;
        if (uat) prv_free(uat);
        uat = (UnifiedAlert_t *)prv_alloc(sizeof(*uat));
        uat->event.sig_generator = 1; // All events are generated by Snort rules
        uat->event.sig_id = ri[shdr->rulenum].sid;
        uat->event.sig_rev = ri[shdr->rulenum].rev;
        uat->event.classification = 0; // XXX ???
        uat->event.priority = ri[shdr->rulenum].priority;
        uat->event.event_id = event_id;
        uat->event.event_reference = 0; // no tagged packets or other event references
        uat->event.ref_time.tv_sec = 0;
        uat->event.ref_time.tv_usec = 0;
        
        uat->ts.tv_sec = TS2SEC(shdr->pkt.ts);
        uat->ts.tv_usec = TS2USEC(shdr->pkt.ts);
        uat->sip = H32(SNORTIP(pkt,src_ip));
        uat->dip = H32(SNORTIP(pkt,dst_ip));
        switch (SNORTIP(pkt,proto)) {
            case IPPROTO_TCP:
                uat->sp = H16(SNORTTCP(pkt,src_port));
                uat->dp = H16(SNORTTCP(pkt,dst_port));
                break;
            case IPPROTO_UDP:
                uat->sp = H16(SNORTUDP(pkt,src_port));
                uat->dp = H16(SNORTUDP(pkt,dst_port));
                break;
            case IPPROTO_ICMP: // For ICMP packets, save ICMP type instead of port
                uat->sp = SNORTICMP(pkt,type);
                uat->dp = uat->sp;
                break;
            default:
                uat->sp = 0;
                uat->dp = 0;
                break;
        }
        uat->protocol = SNORTIP(pkt,proto);
        uat->flags = 0; // XXX ???
        *len = sizeof(*uat);
        return (char *)uat;
    }
    else { /* Unified Log format */
        event_id++;
        if (ult) prv_free(ult);
        ult = (UnifiedLog_t *)prv_alloc(sizeof(*ult) + shdr->pkt.caplen);
        ult->event.sig_generator = 1; // All events are generated by Snort rules
        ult->event.sig_id = ri[shdr->rulenum].sid;
        ult->event.sig_rev = ri[shdr->rulenum].rev;
        ult->event.classification = 0; // XXX ???
        ult->event.priority = ri[shdr->rulenum].priority;
        ult->event.event_id = event_id;
        ult->event.event_reference = event_id; /* no tagged packets or other event references,
                                                * so the event reference id is the same as the
                                                * event id */
        ult->event.ref_time.tv_sec = 0;
        ult->event.ref_time.tv_usec = 0;
        
        ult->flags = 0; // XXX ???
        ult->pkth.ts.tv_sec = TS2SEC(shdr->pkt.ts);
        ult->pkth.ts.tv_usec = TS2USEC(shdr->pkt.ts);
        ult->pkth.caplen = shdr->pkt.caplen;
        ult->pkth.len = shdr->pkt.len;
        
        bcopy(&(shdr->pkt) + 1, ult + 1, shdr->pkt.caplen);
            
        *len = sizeof(*ult) + shdr->pkt.caplen;
        return (char *)ult;
    }
}

callbacks_t callbacks = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0, 
    indesc: NULL,
    outdesc: NULL,
    init: init,
    check: check,
    hash: NULL,
    match: NULL,
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

