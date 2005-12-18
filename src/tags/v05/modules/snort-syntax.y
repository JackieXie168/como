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
 * Author: Diego Amores Lopez (damores@ac.upc.edu)
 * 
 * Description:
 * ------------
 *  
 * Snort module for CoMo - syntax file
 * 
 * Here we define the syntax of a Snort rule, and the specific actions to be
 * done when a part of a rule is recognised.
 * GNU Bison turns this file into a C program that can parse a rules file and
 * save the information contained in them.
 */
 
%{

/* C Declarations */

#include <string.h>     /* strlen... */
#include <stdio.h>      /* sprintf */
#include <ctype.h>      /* isdigit */
#include <stdarg.h> 	/* va_start */
#include "como.h"       /* logmsg */
#include "snort.h"      /* data types */

#define YYMALLOC prv_alloc
#define YYFREE prv_free

#define YYERROR_VERBOSE

/* These variables are declared in modules/snort.c
 * We fill the info from here while parsing the Snort rules file
 */
extern unsigned int nrules;
extern unsigned int nrules_read;
extern ruleinfo_t *ri;
extern varinfo_t *vi[];
extern dyn_t *dr[];

int linenum = 0;
int rule_is_valid = 0;

/*
 * -- translate_proto
 *
 * Translates a string representing a network protocol into its
 * corresponding integer constant 
 *
 */
static int
translate_proto(char *proto, uint8_t *p)
{
    if (!strcmp(proto, "ip")) *p = IPPROTO_IP;
    else if (!strcmp(proto, "tcp")) *p = IPPROTO_TCP;
    else if (!strcmp(proto, "udp")) *p = IPPROTO_UDP;
    else if (!strcmp(proto, "icmp")) *p = IPPROTO_ICMP;
    else {
        yserror("Invalid protocol: %s", proto);
        return -1;
    }
    return 0;
}

/*
 * -- translate_ip
 *
 * Dots and numbers notation -> Binary representation of an IP address
 *
 */

static int
translate_ip(char *ipstring, uint32_t *ip)
{
    struct in_addr inp;
    if (inet_aton(ipstring, &inp) == 0) {
        yserror("Invalid IP address: %s", ipstring);
        return -1;
    }
    *ip = inp.s_addr;
    return 0;
}

uint32_t netmasks[33] = 
    { 
      0x0,
      0x80000000,
      0xC0000000,
      0xE0000000,
      0xF0000000,
      0xF8000000,
      0xFC000000,
      0xFE000000,
      0xFF000000,
      0xFF800000,
      0xFFC00000,
      0xFFE00000,
      0xFFF00000,
      0xFFF80000,
      0xFFFC0000,
      0xFFFE0000,
      0xFFFF0000,
      0xFFFF8000,
      0xFFFFC000,
      0xFFFFE000,
      0xFFFFF000,
      0xFFFFF800,
      0xFFFFFC00,
      0xFFFFFE00,
      0xFFFFFF00,
      0xFFFFFF80,
      0xFFFFFFC0,
      0xFFFFFFE0,
      0xFFFFFFF0,
      0xFFFFFFF8,
      0xFFFFFFFC,
      0xFFFFFFFE,
      0xFFFFFFFF 
    };

/*
 * -- translate_nm
 *
 * CIDR notation -> integer representing the network mask
 *
 */

static int
translate_nm(char *nmstring, uint32_t *nm)
{
    int i = atoi(nmstring);
    
    if (i >= 0 && i <= 32) *nm = netmasks[i];
    else {
        yserror("Invalid CIDR netmask: %s", nmstring);
        return -1;
    }
    return 0;
}

struct _snortkw {
    char const *str;    /* keyword */
    int token;          /* related token */
};

typedef struct _snortkw snortkw_t;

snortkw_t snortkwds[] = {
    /* Rule actions */
    { "alert",      SNTOK_ALERT },
    { "log",        SNTOK_LOG },
    { "pass",       SNTOK_PASS },
    { "activate",   SNTOK_ACTIV },
    { "dynamic",    SNTOK_DYN },
    /* Rule options */
    { "content",        SNTOK_CONTENT },
    { "pcre",           SNTOK_PCRE },
    { "msg",            SNTOK_MSG },
    { "reference",      SNTOK_REF },
    { "sid",            SNTOK_SID },
    { "rev",            SNTOK_REV },
    { "classtype",      SNTOK_CTYPE },
    { "priority",       SNTOK_PRIO },
    { "nocase",         SNTOK_NOCASE },
    { "offset",         SNTOK_OFFSET },
    { "depth",          SNTOK_DEPTH },
    { "distance",       SNTOK_DISTANCE },
    { "within",         SNTOK_WITHIN },
    { "isdataat",       SNTOK_ISDATAAT },
    { "byte_test",      SNTOK_BYTETEST },
    { "byte_jump",      SNTOK_BYTEJUMP },
    { "fragoffset",     SNTOK_FROFFSET },
    { "ttl",            SNTOK_TTL },
    { "tos",            SNTOK_TOS },
    { "id",             SNTOK_IPID },
    { "ipopts",         SNTOK_IPOPTS },
    { "fragbits",       SNTOK_FRAGBITS },
    { "dsize",          SNTOK_DSIZE },
    { "flags",          SNTOK_FLAGS },
    { "seq",            SNTOK_SEQ },
    { "ack",            SNTOK_ACK },
    { "window",         SNTOK_WINDOW },
    { "itype",          SNTOK_ITYPE },
    { "icode",          SNTOK_ICODE },
    { "icmp_id",        SNTOK_ICMPID },
    { "icmp_seq",       SNTOK_ICMPSEQ },
    { "ip_proto",       SNTOK_IPPROTO },
    { "sameip",         SNTOK_SAMEIP },
    { "activates",      SNTOK_ACTIVATES },
    { "activated-by",   SNTOK_ACTVBY },
    { "count",          SNTOK_COUNT },
    /* Unsupported rule options */
    { "rawbytes",       SNTOK_RAWBYTES },
    { "uricontent",     SNTOK_URICNT },
    { "ftpbounce",      SNTOK_FTPBOUNCE },
    { "regex",          SNTOK_REGEX },
    { "content-list",   SNTOK_CNTLIST },
    { "flow",           SNTOK_FLOW },
    { "flowbits",       SNTOK_FLOWBITS },
    { "logto",          SNTOK_LOGTO },
    { "session",        SNTOK_SESSION },
    { "resp",           SNTOK_RESP },
    { "react",          SNTOK_REACT },
    { "tag",            SNTOK_TAG },
    { "threshold",      SNTOK_THRESHOLD },
    /* Rule options content */
    /* classtype */
    { "attempted-admin",                SNTOK_HIGHPRIO },
    { "attempted-user",                 SNTOK_HIGHPRIO },
    { "shellcode-detect",               SNTOK_HIGHPRIO },
    { "successful-admin",               SNTOK_HIGHPRIO },
    { "successful-user",                SNTOK_HIGHPRIO },
    { "trojan-activity",                SNTOK_MEDPRIO },
    { "unsuccessful-user",              SNTOK_MEDPRIO },
    { "web-application-attack",         SNTOK_MEDPRIO },
    { "attempted-dos",                  SNTOK_MEDPRIO },
    { "attempted-recon",                SNTOK_MEDPRIO },
    { "bad-unknown",                    SNTOK_MEDPRIO },
    { "denial-of-service",              SNTOK_MEDPRIO },
    { "misc-attack",                    SNTOK_MEDPRIO },
    { "non-standard-protocol",          SNTOK_MEDPRIO },
    { "rpc-portmap-decode",             SNTOK_MEDPRIO },
    { "successful-dos",                 SNTOK_MEDPRIO },
    { "successful-recon-largescale",    SNTOK_MEDPRIO },
    { "successful-recon-limited",       SNTOK_MEDPRIO },
    { "suspicious-filename-detect",     SNTOK_MEDPRIO },
    { "suspicious-login",               SNTOK_MEDPRIO },
    { "system-call-detect",             SNTOK_MEDPRIO },
    { "unusual-client-port-connection", SNTOK_MEDPRIO },
    { "web-application-activity",       SNTOK_MEDPRIO },
    { "icmp-event",                     SNTOK_LOWPRIO },
    { "misc-activity",                  SNTOK_LOWPRIO },
    { "network-scan",                   SNTOK_LOWPRIO },
    { "not-suspicious",                 SNTOK_LOWPRIO },
    { "protocol-command-decode",        SNTOK_LOWPRIO },
    { "string-detect",                  SNTOK_LOWPRIO },
    { "policy-violation",               SNTOK_LOWPRIO },
    { "unknown",                        SNTOK_LOWPRIO },
    /* bytetest, bytejump */
    { "<",  SNTOK_LT },
    { "=",  SNTOK_EQ },
    { "!",  SNTOK_NOTEQ },
    { ">",  SNTOK_GT },
    { "&",  SNTOK_BWAND },
    { "^",  SNTOK_BWOR },
    /* ip_proto */
    { "ip",         0 },
    { "icmp",       1 },
    { "igmp",       2 },
    { "ggp",        3 },
    { "ipencap",    4 },
    { "st",         5 },
    { "tcp",        6 },
    { "egp",        8 },
    { "pup",        12 },
    { "udp",        17 },
    { "hmp",        20 },
    { "xns-idp",    22 },
    { "rdp",        27 },
    { "iso-tp4",    29 },
    { "xtp",        36 },
    { "ddp",        37 },
    { "idpr-cmtp",  38 },
    { "ipv6",       41 },
    { "ipv6-route", 43 },
    { "ipv6-frag",  44 },
    { "idrp",       45 },
    { "rsvp",       46 },
    { "gre",        47 },
    { "esp",        50 },
    { "ah",         51 },
    { "skip",       57 },
    { "ipv6-icmp",  58 },
    { "ipv6-nonxt", 59 },
    { "ipv6-opts",  60 },
    { "rspf",       73 },
    { "vmtp",       81 },
    { "ospf",       89 },
    { "ipip",       94 },
    { "encap",      98 },
    { "pim",        103 },
    /* terminator */
    { NULL,          	                0 }
};

/*
 * -- translate_kw
 *
 * Translates a keyword string to an integer constant 
 *
 */

static int
translate_kw(char *string)
{
    uint i = strlen(string);
    snortkw_t *pt;

    for (pt = snortkwds; i && pt->str != NULL ; pt++)
        if (strlen(pt->str) == i && !bcmp(string, pt->str, i))
            return pt->token;
    
    yserror("Incorrect keyword: %s", string);
    return -1;
}

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
 * -- add_func
 *
 * Adds a function to a rule's list of check functions
 *
 */

static int 
add_func(fpnode_t **list, unsigned int (*function)(ruleinfo_t *, pkt_t *))
{
    fpnode_t *aux, *i;
    
    aux = (fpnode_t *)prv_alloc(sizeof(fpnode_t));
    if (aux == NULL) return -1;
    
    aux->function = function;
    aux->next = NULL;
    if (*list == NULL) *list = aux;
    else {
        /* Add the new function at the end of the list */
        for (i = *list; i->next; i = i->next);
        i->next = aux;
    }
    return 0;
}

/*
 * -- add_var
 *
 * Adds a variable to the hash table vi[]
 *
 */

static int
add_var(char *varname, varinfo_t var)
{
    char c;
    int p;
    varinfo_t *v;
    
    c = *varname;
    p = c - 65;
    
    if (!vi[p]) {
        vi[p] = (varinfo_t *)prv_alloc(sizeof(varinfo_t)); 
        if (vi[p] == NULL) return -1;
        vi[p]->next = NULL;
        vi[p]->namelen = strlen(varname);
        vi[p]->name = (char *)prv_alloc(strlen(varname));
        if (vi[p]->name == NULL) return -1;
        strncpy(vi[p]->name, varname, strlen(varname));
        vi[p]->type = var.type;
        if (!var.type)
            vi[p]->value.ip = var.value.ip;
        else vi[p]->value.port = var.value.port;
    }
    
    else {
        for (v = vi[p]; v; v = v->next) {
            if (!strcmp(v->name, varname)) {
                yserror("Variable %s already exists", varname);
                return -1;
            }
        }
        v = (varinfo_t *)prv_alloc(sizeof(varinfo_t));
        if (v == NULL) return -1;
        v->next = vi[p];
        v->namelen = strlen(varname);
        v->name = (char *)prv_alloc(strlen(varname));
        if (v->name == NULL) return -1;
        strncpy(v->name, varname, strlen(varname));
        v->type = var.type;
        if (!var.type)
            v->value.ip = var.value.ip;
        else v->value.port = var.value.port;
        vi[p] = v;
    }
    
    return 0;
}

/*
 * -- get_var
 *
 * Gets a variable value from the hash table vi[]
 *
 */
 
static int
get_var(char *varname, varinfo_t *varinfo)
{
    char c;
    int p;
    varinfo_t *var;

    c = *varname;
    p = c - 65;

    for (var = vi[p]; var; var = var->next) {
        if (!strncmp(var->name, varname, var->namelen)) {
            *varinfo = *var;
            return 0;
        }
    }
    yserror("Variable %s not found", varname);
    return -1;
}

/*
 * -- add_dynamic_rule
 *
 * Adds the info of a dynamic rule
 *
 */

static int
add_dynamic_rule(opt_t *o)
{
    dyn_t *aux, *d;
    int n;
    
    d = (dyn_t *)prv_alloc(sizeof(dyn_t));
    if (d == NULL) return -1;
    
    d->activates = o;
    d->next = NULL;
    
    n = o->actvby;
    
    if (!dr[n]) dr[n] = d;
    else {
        for (aux = dr[n]; aux->next; aux = aux->next);
        aux->next = d;
    }

    return 0;
}

static int
compare_portset(portset_t a, portset_t b)
{
    /* If none of the portsets is valid, we consider them equal */
    if (!a.valid && !b.valid) return 1;
    if (a.valid != b.valid) return 0;
    if (a.negation == b.negation &&
        a.lowport == b.lowport &&
        a.highport == b.highport)
        return 1;
    else return 0;
}

static int
compare_ipset(ip_t a, ip_t b)
{
    ipnode_t *ipa, *ipb;
    
    if (a.negation != b.negation) return 0;
    for (ipa = a.ipnode, ipb = b.ipnode; ipa && ipb; ipa = ipa->next, ipb = ipb->next) {
        if (ipa->valid != ipb->valid ||
            ipa->ipaddr != ipb->ipaddr ||
            ipa->netmask != ipb->netmask)
            return 0;
    }
    if (!ipa && !ipb) return 1;
    else return 0;
}

static int
compare_rule_header(ruleinfo_t *a, ruleinfo_t *b)
{
    if ( a->proto == b->proto &&
         compare_ipset(a->src_ips, b->src_ips) &&
         compare_ipset(a->dst_ips, b->dst_ips) &&
         compare_portset(a->src_ports, b->src_ports) &&
         compare_portset(a->dst_ports, b->dst_ports) )
        return 1;
    else return 0;
}

/*
 * -- find_pm_option
 *
 * Find the nearest pattern match option to a given option
 *
 */
static optnode_t *
find_pm_option(optnode_t *opts, optnode_t *optnode)
{
    optnode_t *onode_cand, *onode_aux;
    
    onode_cand = NULL;
    for(onode_aux = opts; onode_aux && onode_aux != optnode; onode_aux = onode_aux->next) {
        if (onode_aux->keyword == SNTOK_CONTENT || onode_aux->keyword == SNTOK_PCRE ||
            onode_aux->keyword == SNTOK_BYTETEST || onode_aux->keyword == SNTOK_BYTEJUMP)
            onode_cand = onode_aux;
    }
    return onode_cand;
}

/*
 * -- add_rule
 *
 * Adds a rule's information to ri
 * The rule's options preprocessing is also done here.
 *
 */

static int
add_rule(uint8_t action, unsigned int proto,
         ip_t src_ips, portset_t src_ports, ip_t dst_ips, portset_t dst_ports,
         optnode_t *opts)
{
    ruleinfo_t *info, *ricur, *riprev;
    unsigned int header_found = 0;
    optnode_t *optnode, *onode_cand, *onode_cand_2;
    opt_t *opt, *oaux;
    fpnode_t **fp;

    unsigned int has_actv = 0, has_actvby = 0, has_count = 0, has_sid = 0;
    unsigned int has_prio = 0;
    char *saux, *saux_2, *tmpcnt;
    char caux;
    ref_t *ref, *raux;
    unsigned int idx;
    
    /* Needed for pcre expression compiling */
#ifdef HAVE_PCRE
    pcre *regexp_aux;
    const char *pcre_error;
    int erroffset;
    int pcre_opts = 0;
    int end = 0;
#endif
    
    if (nrules >= MAX_RULES) {
        yserror("Too many rules in the file");
        return -1;
    }

    info = (ruleinfo_t *)prv_alloc(sizeof(ruleinfo_t));
    if (info == NULL) return -1;
    
    opt = (opt_t *)prv_alloc(sizeof(opt_t));
    if (opt == NULL) return -1;
    
    opt->action = action;
    if (opt->action != SNTOK_DYN)
        opt->active = 1;
    else opt->active = 0;
            
    fp = &(info->funcs);
    *fp = NULL;
    
    info->proto = proto;
    if (add_func(fp, check_proto) == -1)
        return -1;
    
    info->src_ips = src_ips;
    if (info->src_ips.ipnode->valid) {
        if (add_func(fp, check_src_ip) == -1)
            return -1;
    }
            
    info->src_ports = src_ports;
    if (info->src_ports.valid) {
        switch(proto) {
            case IPPROTO_TCP:
                if (add_func(fp, check_tcp_src_port) == -1)
                    return -1;
                break;
            case IPPROTO_UDP:
                if (add_func(fp, check_udp_src_port) == -1)
                    return -1;
                break;
        }
    }            
            
    info->dst_ips = dst_ips;
    if (info->dst_ips.ipnode->valid) {
        if (add_func(fp, check_dst_ip) == -1)
            return -1;
    }
            
    info->dst_ports = dst_ports;
    if (info->dst_ports.valid) {
        switch(proto) {
            case IPPROTO_TCP:
                if (add_func(fp, check_tcp_dst_port) == -1)
                    return -1;
                break;
            case IPPROTO_UDP:
                if (add_func(fp, check_udp_dst_port) == -1)
                    return -1;
                break;
        }
    }            

    /* Preprocess rule's options */
    opt->rule_id = nrules;
    opt->refs = NULL;
    opt->next = NULL;
    opt->options = opts;
    
    /* First pass: check if some options are present */
    optnode = opts;
    while (optnode != NULL) {
        switch(optnode->keyword) {
            case SNTOK_PRIO:
                has_prio = 1;
                break;
        }
        optnode = optnode->next;
    }
    
    /* Second pass: actual preprocessing */
    optnode = opts;
    while (optnode != NULL) {
        switch(optnode->keyword) {                   
            case SNTOK_ACTIVATES:
                /* Save which number to activate
                   when a packet matches this rule */
                has_actv = 1;
                opt->activates = atoi(optnode->content);
                break; 
            case SNTOK_ACTVBY:
                /* Add a pointer to this rule 
                   to the correspondent list of dynamic rules
                   (only for a dynamic rule) */
                has_actvby = 1;
                if (opt->action != SNTOK_DYN) {
                    yserror("rule %d: activated-by option in non-dynamic rule",
                            nrules);
                    return 0;
                }
                opt->actvby = atoi(optnode->content);
                if (add_dynamic_rule(opt) == -1)
                    return -1;
                break;
            case SNTOK_COUNT:
                /* Save the counter (only for a dynamic rule) */
                has_count = 1;
                if (opt->action != SNTOK_DYN) {
                    yserror("rule %d: count option in non-dynamic rule",
                            nrules);
                    return 0;
                }
                opt->count = atoi(optnode->content);
                break;
            case SNTOK_MSG:
                /* Save the message associated with this rule */
                opt->msg = optnode->content;
                break;
            case SNTOK_REF:
                /* Save the reference system id and the reference id */
                ref = (ref_t *)prv_alloc(sizeof(ref_t));
                if (ref == NULL) return -1;
                
                saux = index(optnode->content, ',');
                if (saux == NULL) {
                    yserror("rule %d: wrong reference option", nrules);
                    return 0;
                }
                ref->id = saux + 1;
                ref->systemid =
                    (char *)prv_alloc(strlen(optnode->content) - strlen(saux));
                if (ref->systemid == NULL) return -1;
                strncpy(ref->systemid, optnode->content,
                        strlen(optnode->content) - strlen(saux));
                ref->next = NULL;
                
                if (!opt->refs) opt->refs = ref;
                else {
                    for (raux = opt->refs; raux->next; raux = raux->next);
                    raux->next = ref;
                }
                break;
            case SNTOK_SID:
                /* Save the rule unique identifier */
                has_sid = 1;
                opt->sid = atoi(optnode->content);
                break;
            case SNTOK_REV:
                /* Save the revision of the rule */
                if (!has_sid) {
                    yserror("rule %d: rev option without previous sid option",
                            nrules);
                    return 0;
                }
                opt->rev = atoi(optnode->content);
                break;
            case SNTOK_CTYPE:
                /* Save the rule's classtype and set the default priority
                   (high priority = 1, med priority = 2, low priority = 3) */
                opt->ctype = optnode->content;
                switch(translate_kw(optnode->content)) {
                    case SNTOK_HIGHPRIO:
                        if (!has_prio) opt->prio = 1;
                        break;
                    case SNTOK_MEDPRIO:
                        if (!has_prio) opt->prio = 2;
                        break;
                    case SNTOK_LOWPRIO:
                        if (!has_prio) opt->prio = 3;
                        break;                            
                    case SNTOK_NULL:
                        yserror("rule %d: wrong classtype", nrules);
                        return 0;
                }
                break;
            case SNTOK_PRIO:
                /* Save the rule priority */
                opt->prio = atoi(optnode->content);
                break;
            case SNTOK_CONTENT:
                /* Initialize content modifier variables */
                optnode->nocase = 0;
                optnode->depth = 0;
                optnode->offset = 0;
                optnode->has_distance = 0;
                optnode->distance = 0;
                optnode->has_within = 0;
                optnode->within = 0;
                optnode->relative = 0;
                optnode->neg = 0;
                
                /* Preprocess the pattern to search */
                caux = optnode->content[0];
                if (caux == '!') {
                    optnode->neg = 1;
                    optnode->cnt = optnode->content + 1;
                }
                else optnode->cnt = optnode->content;
                optnode->cntlen = hextochar(optnode->cnt);
                preBmBc(optnode->cnt, optnode->cntlen, optnode->bmBc);
                optnode->bmGs =
                    (int *)prv_alloc(optnode->cntlen * sizeof(int));
                if (!(optnode->bmGs)) return -1;
                preBmGs(optnode->cnt, optnode->cntlen, optnode->bmGs);
                break;
            case SNTOK_NOCASE:
                onode_cand = find_pm_option(opts, optnode);
                if (!onode_cand) {
                    yserror("rule %d: nocase option without previous "
                            "pattern-matching option", nrules);
                    return 0;                    
                }
                onode_cand->nocase = 1;
                lowercase(onode_cand->cnt, strlen(onode_cand->cnt));
                break;
            case SNTOK_DEPTH:
                onode_cand = find_pm_option(opts, optnode);
                if (!onode_cand) {
                    yserror("rule %d: depth option without previous "
                            "pattern-matching option", nrules);
                    return 0;                
                }
                onode_cand->has_depth = 1;
                onode_cand->depth = atoi(optnode->content);
                break;
            case SNTOK_OFFSET:
                onode_cand = find_pm_option(opts, optnode);
                if (!onode_cand) {
                    yserror("rule %d: offset option without previous "
                            "pattern_matching option", nrules);
                    return 0;
                }
                onode_cand->offset = atoi(optnode->content);
                break;
            case SNTOK_DISTANCE:
                onode_cand = find_pm_option(opts, optnode);
                if (onode_cand) {
                    onode_cand_2 = find_pm_option(opts, onode_cand);
                    if (!onode_cand_2) {
                        yserror("rule %d: distance option requires at least "
                                "two previous pattern_matching options",
                                nrules);
                        return 0;
                    }
                    else {
                        onode_cand->has_distance = 1;
                        onode_cand->distance = atoi(optnode->content);
                    }
                }
                else {
                    yserror("rule %d: distance option requires at least two "
                            "previous pattern-matching options", nrules);
                    return 0;
                }
                break;
            case SNTOK_WITHIN:
                onode_cand = find_pm_option(opts, optnode);
                if (onode_cand) {
                    onode_cand->has_within = 1;
                    onode_cand->within = atoi(optnode->content);                    
                }
                else {
                    yserror("rule %d: within option without "
                            "previous pattern-matching option", nrules);
                    return 0;
                }
                break;
            case SNTOK_ISDATAAT:
                optnode->isdataat = 0;
                optnode->relative = 0;
                saux = index(optnode->content, ',');
                if (saux == NULL) {
                    optnode->isdataat = atoi(optnode->content);
                }
                else if (!strcmp(saux + 1, "relative")) {
                    onode_cand = find_pm_option(opts, optnode);
                    if (!onode_cand) {
                        yserror("rule %d: isdataat relative option without "
                                "previous pattern-matching option", nrules);
                        return 0;                        
                    }
                    else {
                        optnode->isdataat = atoi(optnode->content);
                        optnode->relative = 1;
                    }
                }
                else {
                    yserror("rule %d: wrong isdataat option", nrules);
                    return 0;                    
                }
                break;
            case SNTOK_PCRE:
#ifdef HAVE_PCRE
                optnode->relative = 0;
                optnode->neg = 0;
                /* Parse the option's content string */
                caux = optnode->content[0];
                if (caux == '!') optnode->neg = 1;
                /* Find the perl-compatible regular expression */
                saux = index(optnode->content, '/');
                saux_2 = saux;
                end = 0;
                while (!end) {
                    saux_2 = index(saux_2 + 1, '/');
                    if (!saux_2)
                        end = 1;
                    else if (strncmp(saux_2 - 1, "\\", 1))
                        end = 1;
                }
                if (!saux || !saux_2) {
                    /* The pcre was not found */
                    yserror("rule %d: wrong pcre option", nrules);
                    return 0;                    
                }
                optnode->cnt = (char *)prv_alloc(saux_2 - saux - 1);
                strncpy(optnode->cnt, saux + 1, saux_2 - saux - 1);
                
                if (strlen(saux_2) > 1) {
                    /* There are pcre modifiers after the expression */
                    /* Perl-compatible modifiers */
                    saux = index(saux_2 + 1, 'i');
                    if (saux != NULL) pcre_opts |= PCRE_CASELESS;
                    saux = index(saux_2 + 1, 's');
                    if (saux != NULL) pcre_opts |= PCRE_DOTALL;
                    saux = index(saux_2 + 1, 'm');
                    if (saux != NULL) pcre_opts |= PCRE_MULTILINE;
                    saux = index(saux_2 + 1, 'x');
                    if (saux != NULL) pcre_opts |= PCRE_EXTENDED;
                    /* PCRE-compatible modifiers */
                    saux = index(saux_2 + 1, 'A');
                    if (saux != NULL) pcre_opts |= PCRE_ANCHORED;
                    saux = index(saux_2 + 1, 'E');
                    if (saux != NULL) pcre_opts |= PCRE_DOLLAR_ENDONLY;
                    saux = index(saux_2 + 1, 'G');
                    if (saux != NULL) pcre_opts |= PCRE_UNGREEDY;
                    /* Snort-only modifiers */
                    saux = index(saux_2 + 1, 'R');
                    if (saux != NULL) {
                        /* Match relative to the end of the last pattern match */
                        onode_cand = find_pm_option(opts, optnode);
                        if (!onode_cand) {
                            yserror("rule %d: pcre relative option without "
                                    "previous pattern-matching option",
                                    nrules);
                            return 0;
                        }
                        else optnode->relative = 1;
                    }
                }
                
                /* Compile the pcre found in the rule */                
                pcre_malloc = prv_alloc;
                pcre_free = prv_free;
                regexp_aux = pcre_compile(optnode->cnt, pcre_opts,
                                          &pcre_error, &erroffset, NULL);
                if (regexp_aux == NULL) {
                    yserror("rule %d: wrong pcre expression, offset = %d, "
                            "error = %s", nrules, erroffset, pcre_error);
                    return 0;
                } 
                prv_free(optnode->cnt);
                optnode->regexp = regexp_aux;
#else
                yserror("rule %d: pcre option found, but pcre support is "
                        "disabled. please install libpcre and edit "
                        "config_vars.local", nrules);
                return 0;
#endif
                break;

            case SNTOK_BYTETEST:
                optnode->relative = 0;
                optnode->byte_base = 0;
                optnode->byte_isstring = 0;
                /* We consider bytes in big-endian order by default */
                optnode->byte_endian = BIGENDIAN;
                optnode->byte_number = atoi(optnode->content);
                if (optnode->byte_number != 1 && optnode->byte_number != 2 &&
                    optnode->byte_number != 4) {
                    yserror("rule %d: the number of bytes in a byte_test "
                            "option must be 1, 2 or 4", nrules);
                    return 0;                    
                }
                saux = index(optnode->content, ',');
                if (saux != NULL) {
                    tmpcnt = (char *)prv_alloc(1);
                    strncpy(tmpcnt, saux + 1, 1);
                    optnode->byte_op = translate_kw(tmpcnt);
                    prv_free(tmpcnt);

                    saux = index(optnode->content, ',');
                    if (saux != NULL) {
                        optnode->byte_value = atoi(saux + 1);
                        saux = index(saux + 1, ',');
                        if (saux != NULL) {
                            optnode->byte_offset = atoi(saux + 1);
                            saux = index(saux + 1, ',');
                            if (saux != NULL) {
                                if (strstr(saux + 1, "relative") != NULL) {
                                    onode_cand = find_pm_option(opts, optnode);
                                    if (!onode_cand) {
                                        yserror("rule %d: byte_test relative "
                                                "option without previous "
                                                "pattern-matching option",
                                                nrules);
                                        return 0;
                                    }                                    
                                    else optnode->relative = 1;
                                }
                                if (strstr(saux + 1, "string") != NULL)
                                    optnode->byte_isstring = 1;
                                if (strstr(saux + 1, "hex") != NULL)
                                    optnode->byte_base = 16;
                                if (strstr(saux + 1, "dec") != NULL)
                                    optnode->byte_base = 10;
                                if (strstr(saux + 1, "oct") != NULL)
                                    optnode->byte_base = 8;
                                if (strstr(saux + 1, "big") != NULL)
                                    optnode->byte_endian = BIGENDIAN;
                                if (strstr(saux + 1, "little") != NULL)
                                    optnode->byte_endian = LILENDIAN;
                            }
                        }
                        else {
                            yserror("rule %d: insufficient parameters "
                                    "in byte_test option", nrules);
                            return 0;                            
                        }
                    }
                    else {
                        yserror("rule %d: insufficient parameters in "
                                "byte_test option", nrules);
                        return 0;
                    }
                }
                else {
                    yserror("rule %d: insufficient parameters "
                            "in byte_test option", nrules);
                    return 0;
                }
                break;
            case SNTOK_BYTEJUMP:
                optnode->relative = 0;
                optnode->byte_base = 0;
                optnode->byte_isstring = 0;
                /* We consider bytes in big-endian order by default */
                optnode->byte_endian = BIGENDIAN;
                optnode->byte_number = atoi(optnode->content);
                if (optnode->byte_number != 1 && optnode->byte_number != 2 &&
                    optnode->byte_number != 4) {
                    yserror("rule %d: the number of bytes in a byte_test "
                            "option must be 1, 2 or 4", nrules);
                    return 0;                    
                }
                saux = index(optnode->content, ',');
                if (saux != NULL) {
                    optnode->byte_offset = atoi(saux + 1);
                    saux = index(saux + 1, ',');
                    if (saux != NULL) {
                        if (strstr(saux + 1, "relative") != NULL) {
                            onode_cand = find_pm_option(opts, optnode);
                            if (!onode_cand) {
                                yserror("rule %d: byte_test relative option "
                                        "without previous pattern-matching "
                                        "option", nrules);
                                return 0;
                            }                                    
                            else optnode->relative = 1;                        
                        }
                        if ((saux_2 = strstr(saux + 1, "multiplier")) != NULL) {
                            optnode->byte_multi = atoi(saux_2 + 12);
                        }
                        if (strstr(saux + 1, "string") != NULL)
                            optnode->byte_isstring = 1;
                        if (strstr(saux + 1, "hex") != NULL)
                            optnode->byte_base = 16;
                        if (strstr(saux + 1, "dec") != NULL)
                            optnode->byte_base = 10;
                        if (strstr(saux + 1, "oct") != NULL)
                            optnode->byte_base = 8;
                        if (strstr(saux + 1, "big") != NULL)
                            optnode->byte_endian = BIGENDIAN;
                        if (strstr(saux + 1, "little") != NULL)
                            optnode->byte_endian = LILENDIAN;
                    }
                }
                else {
                    yserror("rule %d: insufficient parameters in byte_jump "
                            "option", nrules);
                    return 0;
                }
                break;
            case SNTOK_FROFFSET:
                opt->fragoffcmp = 0;
                opt->fragoffset = 0;
                if (optnode->content[0] == '<' || optnode->content[0] == '>') { 
                    tmpcnt = (char *)prv_alloc(1);
                    strncpy(tmpcnt, optnode->content, 1);
                    opt->fragoffcmp = translate_kw(tmpcnt);
                    prv_free(tmpcnt);
                    opt->fragoffset = atoi(optnode->content + 1);
                }
                else {
                    opt->fragoffcmp = SNTOK_EQ;
                    opt->fragoffset = atoi(optnode->content);
                }
                break;
            case SNTOK_TTL:
                opt->ttllow = 0;
                opt->ttlhigh = 0;
                opt->ttlcmp = 0;
                if (optnode->content[0] == '<' || optnode->content[0] == '>' ||
                    optnode->content[0] == '=') {
                    tmpcnt = (char *)prv_alloc(1);
                    strncpy(tmpcnt, optnode->content, 1);
                    opt->ttlcmp = translate_kw(tmpcnt);
                    prv_free(tmpcnt);
                    opt->ttllow = atoi(optnode->content + 1);
                }
                else {
                    saux = index(optnode->content, '-');
                    if (saux == NULL) {
                        opt->ttlcmp = SNTOK_EQ;
                        opt->ttllow = atoi(optnode->content);
                    }
                    else {
                        opt->ttlcmp = SNTOK_BETWEEN;
                        opt->ttllow = atoi(optnode->content);
                        opt->ttlhigh = atoi(saux + 1);
                    }
                }
                break;
            case SNTOK_TOS:
                optnode->neg = 0;
                opt->tos = 0;
                if (optnode->content[0] == '!') {
                    optnode->neg = 1;
                    opt->tos = atoi(optnode->content + 1);
                }
                else
                    opt->tos = atoi(optnode->content);
                break;
            case SNTOK_IPID:
                opt->ipid = atoi(optnode->content);
                break;
            case SNTOK_IPOPTS:
                opt->ipopts = 0;
                opt->ipopts_any = 0;
                saux_2 = (char *)prv_alloc(MAX_STR_SIZE);
                saux = strtok_r(optnode->content, "|", &saux_2);
                while (saux != NULL) {
                    if (strstr(saux, "rr") != NULL)
                        opt->ipopts |= IPOPT_RR;
                    if (strstr(saux, "eol") != NULL)
                        opt->ipopts |= IPOPT_EOL;
                    if (strstr(saux, "nop") != NULL)
                        opt->ipopts |= IPOPT_NOP;
                    if (strstr(saux, "ts") != NULL)
                        opt->ipopts |= IPOPT_TS;
                    if (strstr(saux, "sec") != NULL)
                        opt->ipopts |= IPOPT_SEC;
                    if (strstr(saux, "lsrr") != NULL)
                        opt->ipopts |= IPOPT_LSRR;
                    if (strstr(saux, "ssrr") != NULL)
                        opt->ipopts |= IPOPT_SSRR;
                    if (strstr(saux, "satid") != NULL)
                        opt->ipopts |= IPOPT_SATID;
                    if (strstr(saux, "any") != NULL)
                        opt->ipopts_any = 1;
                    saux = strtok_r(NULL, "|", &saux_2);
                }
                if (!(opt->ipopts)) {
                    yserror("rule %d: empty or wrong ipopts option", nrules);
                    return 0;                
                }
                break;
            case SNTOK_FRAGBITS:
                opt->fragbits = 0;
                opt->fragbitscmp = 0;
                for (idx = 0; idx < strlen(optnode->content); idx++) {
                    switch (optnode->content[idx]) {
                        case 'M':
                            opt->fragbits |= FB_MF;
                            break;
                        case 'D':
                            opt->fragbits |= FB_DF;
                            break;
                        case 'R':
                            opt->fragbits |= FB_RSV;
                            break;
                        case '+':
                            opt->fragbitscmp = FB_ALL;
                            break;
                        case '*':
                            opt->fragbitscmp = FB_ANY;
                            break;
                        case '!':
                            opt->fragbitscmp = FB_NOT;
                            break;
                    }
                }
                break;
            case SNTOK_DSIZE:
                opt->dsizelow = 0;
                opt->dsizehigh = 0;
                opt->dsizecmp = 0;
                if (optnode->content[0] == '>') {
                    opt->dsizelow = atoi(optnode->content + 1);
                    opt->dsizecmp = SNTOK_GT;
                }
                else if (optnode->content[0] == '<') {
                    opt->dsizelow = atoi(optnode->content + 1);
                    opt->dsizecmp = SNTOK_LT;                        
                }
                else if ((saux = strstr(optnode->content, "<>")) != NULL) {
                    opt->dsizelow = atoi(optnode->content);
                    opt->dsizehigh = atoi(saux + 2);
                    opt->dsizecmp = SNTOK_BETWEEN;
                }
                else {
                    opt->dsizelow = atoi(optnode->content);
                    opt->dsizecmp = SNTOK_EQ;
                }                    
                break;                
            case SNTOK_FLAGS:
                if (info->proto != IPPROTO_TCP) {
                    yserror("rule %d: flags option not compatible with "
                            "non-tcp rule", nrules);
                    return 0;                
                }
                opt->flags = 0;
                opt->flagsnone = 0;
                opt->flagscmp = 0;
                for (idx = 0; idx < strlen(optnode->content); idx++) {
                    switch (optnode->content[idx]) {
                        case 'F':
                            opt->flags |= FLG_FIN;
                            break;
                        case 'S':
                            opt->flags |= FLG_SYN;
                            break;
                        case 'R':
                            opt->flags |= FLG_RST;
                            break;
                        case 'P':
                            opt->flags |= FLG_PSH;
                            break;
                        case 'A':
                            opt->flags |= FLG_ACK;
                            break;
                        case 'U':
                            opt->flags |= FLG_URG;
                            break;
                        case '1':
                            opt->flags |= FLG_RSV1;
                            break;
                        case '2':
                            opt->flags |= FLG_RSV2;
                            break;
                        case '0':
                            opt->flagsnone = 1;
                            break;
                        case '+':
                            opt->flagscmp = FLG_ALL;
                            break;
                        case '*':
                            opt->flagscmp = FLG_ANY;
                            break;
                        case '!':
                            opt->flagscmp = FLG_NOT;
                            break;
                    }
                }
                break;
            case SNTOK_SEQ:
                if (info->proto != IPPROTO_TCP) {
                    yserror("rule %d: seq option not compatible "
                            "with non-tcp rule", nrules);
                    return 0;                
                }                
                opt->seq = atoi(optnode->content);
                break;
            case SNTOK_ACK:
                if (info->proto != IPPROTO_TCP) {
                    yserror("rule %d: ack option not compatible "
                            "with non-tcp rule", nrules);
                    return 0;                
                }
                opt->ack = atoi(optnode->content);
                break;
            case SNTOK_WINDOW:
                if (info->proto != IPPROTO_TCP) {
                    yserror("rule %d: window option not compatible "
                            "with non-tcp rule", nrules);
                    return 0;                
                }
                optnode->neg = 0;
                if (optnode->content[0] == '!') {
                    optnode->neg = 1;
                    opt->window = atoi(optnode->content + 1);
                }
                else
                    opt->window = atoi(optnode->content);
                break;
            case SNTOK_ITYPE:
                if (info->proto != IPPROTO_ICMP) {
                    yserror("rule %d: itype option not compatible "
                            "with non-icmp rule", nrules);
                    return 0;                
                }                
                opt->itypelow = 0;
                opt->itypehigh = 0;
                opt->itypecmp = 0;
                if (optnode->content[0] == '>') {
                    opt->itypelow = atoi(optnode->content + 1);
                    opt->itypecmp = SNTOK_GT;
                }
                else if (optnode->content[0] == '<') {
                    opt->itypelow = atoi(optnode->content + 1);
                    opt->itypecmp = SNTOK_LT;                        
                }
                else if ((saux = strstr(optnode->content, "<>")) != NULL) {
                    opt->itypelow = atoi(optnode->content);
                    opt->itypehigh = atoi(saux + 2);
                    opt->itypecmp = SNTOK_BETWEEN;
                }
                else {
                    opt->itypelow = atoi(optnode->content);
                    opt->itypecmp = SNTOK_EQ;
                }                    
                break;                
            case SNTOK_ICODE:
                if (info->proto != IPPROTO_ICMP) {
                    yserror("rule %d: icode option not compatible "
                            "with non-icmp rule", nrules);
                    return 0;                
                }                
                opt->icodelow = 0;
                opt->icodehigh = 0;
                opt->icodecmp = 0;
                if (optnode->content[0] == '>') {
                    opt->icodelow = atoi(optnode->content + 1);
                    opt->icodecmp = SNTOK_GT;
                }
                else if (optnode->content[0] == '<') {
                    opt->icodelow = atoi(optnode->content + 1);
                    opt->icodecmp = SNTOK_LT;                        
                }
                else if ((saux = strstr(optnode->content, "<>")) != NULL) {
                    opt->icodelow = atoi(optnode->content);
                    opt->icodehigh = atoi(saux + 2);
                    opt->icodecmp = SNTOK_BETWEEN;
                }
                else {
                    opt->icodelow = atoi(optnode->content);
                    opt->icodecmp = SNTOK_EQ;
                }                    
                break;
            case SNTOK_ICMPID:
                if (info->proto != IPPROTO_ICMP) {
                    yserror("rule %d: icmp_id option not compatible "
                            "with non-icmp rule", nrules);
                    return 0;                
                }                
                opt->icmpid = atoi(optnode->content);
                break;
            case SNTOK_ICMPSEQ:
                if (info->proto != IPPROTO_ICMP) {
                    yserror("rule %d: icmp_seq option not compatible "
                            "with non-icmp rule", nrules);
                    return 0;                
                }                
                opt->icmpseq = atoi(optnode->content);
                break;
            case SNTOK_IPPROTO:
                opt->ipprotocmp = 0;
                opt->ipproto = 0;
                if (optnode->content[0] == '<' || optnode->content[0] == '>' ||
                    optnode->content[0] == '!') { 
                    tmpcnt = (char *)prv_alloc(1);
                    strncpy(tmpcnt, optnode->content, 1);
                    opt->ipprotocmp = translate_kw(tmpcnt);
                    prv_free(tmpcnt);
                    if (isdigit(optnode->content[1]))
                        opt->ipproto = atoi(optnode->content + 1);
                    else
                        opt->ipproto = translate_kw(optnode->content + 1);
                }
                else {
                    opt->ipprotocmp = SNTOK_EQ;
                    if (isdigit(optnode->content[0]))
                        opt->ipproto = atoi(optnode->content);
                    else
                        opt->ipproto = translate_kw(optnode->content);                    
                }
                break;
        }
        optnode = optnode->next;
    }

    /* Check that all mandatory options are present */
    if (opt->action == SNTOK_ACTIV) {
        if (!has_actv) {
            yserror("activate rule %d without activates option", nrules);
            return 0;
        }
    }
    if (opt->action == SNTOK_DYN) {
        if (!has_count || !has_actvby) {
            yserror("dynamic rule %d lacks required options "
                    "(activated_by,count)", nrules);
            return 0;
        }
    }
    
    info->next = NULL;
    
    /* Add the new rule at the end of the list */
    if (rule_is_valid) {
        if (!ri) {
            ri = info;
            opt->rule = ri;
            ri->opts = opt;
        }
        else {
            ricur = ri;
            riprev = NULL;
            do {
                if (compare_rule_header(ricur, info)) {
                    header_found = 1;
                    /* Add the options to the end of the options list */
                    for(oaux = ricur->opts; oaux->next; oaux = oaux->next);
                    opt->rule = ricur;
                    oaux->next = opt;
                }
                riprev = ricur;
                ricur = ricur->next;
            } while (ricur && !header_found);
        
            if (!header_found) {
                opt->rule = info;
                info->opts = opt;
                riprev->next = info;
            }
        }    
        nrules++;
    } else
        // XXX We should free more structures here
        prv_free(info);
    
    return 0;
}

ipnode_t *ipaux;
optnode_t *optaux;
varinfo_t vaux;

int yslex();

%}

/* Data types and tokens used by the parser */

%union {
    char            *text;
    ipnode_t        *ipnode;
    ip_t            ip;
    portset_t       port;
    varinfo_t       varinfo;
    uint8_t         uint;
    int             integer;
    optnode_t       *optnode;
}
%token <text> ACTION
%token <text> IPTOK 
%token <text> NETMASK
%token <text> PORT
%token <text> DIRECTION
%token <text> VARNAME
%token <text> VARREF
%token <text> PROTO
%token <text> CONTENT
%token <text> QUOTEDCONTENT
%token <text> KEYWORD
%token <text> BADKEYWORD
%token ANY
%token COLON
%token NEGATION
%token OPENSQBR
%token CLOSESQBR
%token COMMA
%token VAR
%token OPENBR
%token CLOSEBR
%token SEMICOLON
%token COMMENT
%type <ip>          ip
%type <ip>          ipvar
%type <ipnode>      ipdesc
%type <ipnode>      ipdescvar
%type <ipnode>      ipset
%type <ipnode>      ipaddr
%type <port>        port
%type <port>        portvar
%type <port>        portdesc
%type <port>        portdescvar
%type <varinfo>     var
%type <integer>     action
%type <uint>        proto
%type <uint>        direction
%type <optnode>     options
%type <optnode>     optset
%type <optnode>     option
%start expression

%%

/* Snort rules grammar */

expression : variable
           | rule
           | COMMENT

variable : VAR VARNAME var { 
                                if (add_var($2, $3) == -1)
                                    YYABORT;
                           }

var : ipvar {
                $$.value = (varvalue_t)$1;
                $$.type = 0;
            }
    | portvar {
                $$.value = (varvalue_t)$1;
                $$.type = 1;
              }
    | VARREF {
                if (get_var($1, &$$) == -1)
                    YYABORT;
             }

ipvar : NEGATION ipdescvar {
                            $$.ipnode = $2;
                            $$.negation = 1;
                           }
      | ipdescvar {
                    $$.ipnode = $1;
                    $$.negation = 0;
                  }

portvar : NEGATION portdescvar {
                                $$ = $2; 
                                $$.negation = 1;
                               }
        | portdescvar {
                        $$ = $1;
                        $$.negation = 0;
                      }

rule : action proto ip port direction ip port options
       { 
            nrules_read++;
            
            if (add_rule($1, $2, $3, $4, $6, $7, $8) == -1)
                YYABORT;

            if ($5) { 
                /* Bidirectional rule
                 * Add another rule with swapped IP addresses and ports
                 */
                if (add_rule($1, $2, $6, $7, $3, $4, $8) == -1)
                    YYABORT;
            }
       }

action: ACTION {
                    $$ = translate_kw($1);
                    if ($$ == -1) YYABORT;
               }

proto : PROTO { 
                if (translate_proto($1, &$$) == -1)
                    YYABORT;
              }

ip : NEGATION ipdesc {
                        $$.ipnode = $2;
                        $$.negation = 1;
                     }
   | ipdesc {
                $$.ipnode = $1;
                $$.negation = 0;
            }
   | VARREF {
                if (get_var($1, &vaux) == -1)
                    YYABORT;
                if (vaux.type != 0) {
                    yserror("Wrong variable type: %s", $1);
                    YYABORT;
                }
                $$ = vaux.value.ip;
            }

ipdesc : ipdescvar {
                    $$ = $1
                   }
       | ANY   {
                    $$ = (ipnode_t *)prv_alloc(sizeof(ipnode_t));
                    if ($$ == NULL) YYABORT;
                    if (translate_ip("0.0.0.0", &($$->ipaddr)) == -1)
                        YYABORT;
                    if (translate_nm("0", &($$->netmask)) == -1)
                        YYABORT; 
                    $$->next = NULL;
                    $$->valid = 0;
               }

ipdescvar : ipaddr {
                    $$ = $1; 
                    $$->next = NULL;
                    $$->valid = 1;
                   } 
          | OPENSQBR ipset CLOSESQBR {
                                        $$ = $2; 
                                        $$->valid = 1;
                                     }

ipaddr : IPTOK NETMASK {
                            $$ = (ipnode_t *)prv_alloc(sizeof(ipnode_t));
                            if ($$ == NULL) YYABORT;
                            if (translate_ip($1, &($$->ipaddr)) == -1)
                                YYABORT;
                            if (translate_nm($2, &($$->netmask)) == -1)
                                YYABORT;
                       }

ipset : ipaddr {
                    $$ = $1;
                    $$->next = NULL;
               }
      | ipaddr COMMA ipset {
                                $$ = $1; 
                                ipaux = (ipnode_t *)prv_alloc(sizeof(ipnode_t));
                                if ($$ == NULL) YYABORT;
                                ipaux->ipaddr = $3->ipaddr;
                                ipaux->netmask = $3->netmask;
                                ipaux->next = $3->next;
                                $$->next = ipaux;
                           }

port : NEGATION portdesc {
                            $$ = $2;
                            $$.negation = 1;
                         }
     | portdesc {
                    $$ = $1;
                    $$.negation = 0;
                }
     | VARREF {
                if (get_var($1, &vaux) == -1)
                    YYABORT;
                if (vaux.type != 1) {
                    yserror("Wrong variable type: %s", $1);
                    YYABORT;
                }
                $$ = vaux.value.port;
              }

portdesc : portdescvar {
                        $$ = $1;
                       }
         | ANY {
                    $$.lowport = 1;
                    $$.highport = MAX_PORT;
                    $$.valid = 0;
               }

portdescvar : PORT {
                    $$.lowport = atoi($1);
                    $$.highport = atoi($1);
                    $$.valid = 1;
                   }
            | PORT COLON {
                            $$.lowport = atoi($1);
                            $$.highport = MAX_PORT;
                            $$.valid = 1;
                         }
            | COLON PORT {
                            $$.lowport = 1;
                            $$.highport = atoi($2);
                            $$.valid = 1;
                         }
            | PORT COLON PORT {
                                $$.lowport = atoi($1);
                                $$.highport = atoi($3);
                                $$.valid = 1;
                              }

direction : DIRECTION {
                        if (strncmp($1, "-", 1)) $$ = 1;
                        else $$ = 0;
                      }     

options : OPENBR optset CLOSEBR {
                                    $$ = $2;
                                }
        | {
            $$ = NULL;
          }

optset : option {
                    $$ = $1;
                    if ($$ != NULL)
                        $$->next = NULL;
                }
       | option optset {
                            if ($1 != NULL) {
                                $$ = $1;
                                optaux =
                                    (optnode_t *)prv_alloc(sizeof(optnode_t));
                                if (optaux == NULL) YYABORT;
                                optaux->keyword = $2->keyword;
                                if ($2->content != NULL) {
                                    optaux->content =
                                        (char *)prv_alloc(strlen($2->content)+1);                            
                                    if (optaux->content == NULL) YYABORT;
                                    strncpy(optaux->content, $2->content,
                                            strlen($2->content)+1);
                                } else
                                    optaux->content = NULL;
                                optaux->next = $2->next;
                                $$->next = optaux;
                            } else
                                $$ = $2;
                       }

option : KEYWORD CONTENT {
                            $$ = (optnode_t *)prv_alloc(sizeof(optnode_t));
                            if ($$ == NULL) YYABORT;
                            $$->keyword = translate_kw($1);
                            if ($$->keyword == -1) YYABORT;
                            $$->content = (char *)prv_alloc(strlen($2)+1);
                            if ($$->content == NULL) YYABORT;
                            strncpy($$->content, $2, strlen($2)+1);
                            $$->next = NULL;
                         }
       | KEYWORD SEMICOLON {
                            $$ = (optnode_t *)prv_alloc(sizeof(optnode_t));
                            if ($$ == NULL) YYABORT;
                            $$->keyword = translate_kw($1);
                            if ($$->keyword == -1) YYABORT;
                            $$->content = NULL;
                            $$->next = NULL;
                           }
       | BADKEYWORD CONTENT  {
                                $$ = NULL;
                                yserror("Unsupported option: %s", $1);
                             }
       | BADKEYWORD SEMICOLON {
                                $$ = NULL;
                                yserror("Unsupported option: %s", $1);
                              }           
                             
%%

#include "snort-lexic.c"

void yserror(char *fmt, ...)
{ 
    va_list ap;
    char error[255];
    
    va_start(ap, fmt);
    vsnprintf(error, sizeof(error), fmt, ap);
    logmsg(LOGWARN, "SNORT module error: line %d: %s\n", linenum, error);
    va_end(ap);
    rule_is_valid = 0;
}

int 
parse_rules(char *rules)
{
    linenum++;
    rule_is_valid = 1;
    ys_scan_string(rules);
    return ysparse();
}
