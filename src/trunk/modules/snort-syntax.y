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

%{

/* C Declarations */
#include <string.h>     /* strcpy, strncmp, strcat */
#include <stdlib.h>     /* atoi */
#include <stdint.h>     /* uint8_t, etc. */
#include <sys/socket.h> /* inet_aton */
#include <arpa/inet.h>  /* inet_aton */
#include <netinet/in.h> /* inet_aton, some inet macros (IPPROTO_X ...) */
#include <ctype.h>      /* toupper */
#include <assert.h>     /* assert */
#include "snort.h"
#include "como.h"       /* logmsg */

#define YYMALLOC prv_alloc
#define YYFREE prv_free

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
    { "sid",            SNTOK_SID },
    { "rev",            SNTOK_REV },
    { "classtype",      SNTOK_CTYPE },
    { "priority",       SNTOK_PRIO },
    { "nocase",         SNTOK_NOCASE },
    { "offset",         SNTOK_OFFSET },
    { "depth",          SNTOK_DEPTH },
    { "fragoffset",     SNTOK_FROFFSET },
    { "ttl",            SNTOK_TTL },
    { "tos",            SNTOK_TOS },
    { "id",             SNTOK_IPID },
    { "dsize",          SNTOK_DSIZE },
    { "activates",      SNTOK_ACTIVATES },
    { "activated-by",   SNTOK_ACTVBY },
    { "count",          SNTOK_COUNT },
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
    { "unknown",                        SNTOK_LOWPRIO },
    /* terminator */
    { NULL,          	    0 }
};

/* These variables are declared in modules/snort.c
 * We fill the info from here while parsing Snort rules
 */
extern ruleinfo_t ri[];
extern int nrules;

/* Needed to manage the module's private memory region */
void *prv_mem;
size_t prv_actualsize = 0;
size_t prv_memsize;

ipnode_t *ipaux;
optnode_t *optaux;
fpnode_t *fpaux;

int yslex();
void yserror(char *error);

typedef long align_t;

union header {
    struct {
        union header *ptr;
        unsigned int size;
    } s;
    align_t x;
};

typedef union header header_t;

static header_t *freep = NULL; /* start of free list */
static header_t membase; /* empty list to get started */

/* 
 * -- prv_free
 *
 * Put block ap in free list
 *
 */
void prv_free(void *ap)
{
    header_t *bp, *p;
    bp = (header_t *)ap - 1; /* point to block header */
    for (p = freep; !(bp > p && bp < p->s.ptr); p = p->s.ptr)
        if (p >= p->s.ptr && (bp > p || bp < p->s.ptr))
            break; /* freed block at start or end of arena */
    if (bp + bp->s.size == p->s.ptr) { /* join to upper nbr */
        bp->s.size += p->s.ptr->s.size;
        bp->s.ptr = p->s.ptr->s.ptr;
    } else
        bp->s.ptr = p->s.ptr;
    if (p + p->s.size == bp) { /* join to lower nbr */
            p->s.size += bp->s.size;
            p->s.ptr = bp->s.ptr;
    } else
        p->s.ptr = bp;
    freep = p;
}

static header_t *morecore(unsigned nunits)
{
    header_t *up;
    size_t nbytes;
    
    nbytes = nunits * sizeof(header_t);
    prv_actualsize += nbytes;
    if (prv_actualsize > prv_memsize) {
        yserror("Not enough private memory\n");
        return NULL;
    }
    prv_mem += nbytes;
    up = (header_t *)(prv_mem - nbytes);
    up->s.size = nunits;
    prv_free((void *)(up + 1));
    return freep;
}

/*
 * -- prv_alloc
 *
 * Allocate nbytes of memory in the private memory
 * space of the module
 *
 */

void *
prv_alloc(unsigned int nbytes)
{
    header_t *p, *prevp;
    unsigned int nunits;
    
    nunits = (nbytes + sizeof(header_t) - 1) / sizeof(header_t) + 1;
    if ((prevp = freep) == NULL) { /* no free list yet */
        membase.s.ptr = freep = prevp = &membase;
        membase.s.size = 0;
    }
    for (p = prevp->s.ptr; ; prevp = p, p = p->s.ptr) {
        if (p->s.size >= nunits) { /* big enough */
            if (p->s.size == nunits) /* exact size */
                prevp->s.ptr = p->s.ptr;
            else {
                p->s.size -= nunits;
                p += p->s.size;
                p->s.size = nunits;
            }
            freep = prevp;
            return (void *)(p + 1);
        }
        if (p == freep) /* wrapped around free list */
            if ((p = morecore(nunits)) == NULL)
                return NULL;
    }
}

/*
 * -- prv_realloc
 *
 */

void *
prv_realloc(void *ptr, unsigned int nbytes)
{
    header_t *bp;
    void *p;
    unsigned int size;
    
    bp = (header_t *)ptr - 1;
    size = MIN(((bp->s.size - 1) * sizeof(header_t)), nbytes); 
    p = prv_alloc(nbytes);
    memcpy(p, ptr, size);
    prv_free(ptr);
    return p; 
}

/*
 * -- translate_kw
 *
 * Translates a keyword string to an integer constant 
 *
 */

int
translate_kw(char *string)
{
    uint i = strlen(string);
    snortkw_t *pt;

    for (pt = snortkwds; i && pt->str != NULL ; pt++)
        if (strlen(pt->str) == i && !bcmp(string, pt->str, i))
            return pt->token;
    return 0;
}

/*
 * -- translate_proto
 *
 * Translates a string representing a network protocol into its
 * corresponding integer constant 
 *
 */
static uint8_t 
translate_proto(char *proto)
{
    uint8_t p = 0;
    if (!strcmp(proto, "ip")) p = IPPROTO_IP;
    else if (!strcmp(proto, "tcp")) p = IPPROTO_TCP;
    else if (!strcmp(proto, "udp")) p = IPPROTO_UDP;
    else if (!strcmp(proto, "icmp")) p = IPPROTO_ICMP;
    return p;
}

/*
 * -- translate_ip
 *
 * Dots and numbers notation -> Binary representation of an IP address
 *
 */

static uint32_t
translate_ip(char *ipstring)
{
    struct in_addr inp;
    if (inet_aton(ipstring, &inp) == 0)
        yserror("Invalid IP address in Snort rule");
    return inp.s_addr;
}

/*
 * -- translate_nm
 *
 * CIDR notation -> integer representing the network mask
 *
 */

static uint32_t
translate_nm(char *nmstring)
{
    uint32_t r = 0;
    int i = atoi(nmstring);
    if (i >= 0 && i <= 32) r = netmasks[i];
    else yserror("Invalid CIDR netmask in Snort rule");
    return r;
}

/*
 * -- add_func
 *
 * Adds a function to a rule's list of check functions
 *
 */

static fpnode_t * 
add_func(fpnode_t **list, unsigned int (*function)(ruleinfo_t *, pkt_t *))
{
    fpnode_t *aux;
    
    /* Add a new function to the list */
    aux = (fpnode_t *)prv_alloc(sizeof(fpnode_t));
    if (aux != NULL) {
        aux->function = function;
        aux->next = NULL;
        if (*list == NULL) *list = aux;
        else (*list)->next = aux;
    }
    
    return aux;
}

%}

/* Data types and tokens used by the parser */

%union {
    char *text;
    uint8_t action;
    uint8_t proto;
    ipnode_t *ipnode;
    ip_t ip;
    portset_t port;
    unsigned int direction;
    optnode_t *optnode;
}
%token <text> ACTION 
%token <text> PROTO 
%token <text> IPTOK 
%token <text> NETMASK
%token <text> PORT
%token <text> DIRECTION
%token <text> ANY
%token <text> CONTENT
%token <text> QUOTEDCONTENT
%token <text> KEYWORD
%token QUOTE
%token COLON
%token NEGATION
%token OPENSQBR
%token CLOSESQBR
%token COMMA
%token OPENBR
%token CLOSEBR
%token SEMICOLON
%type <action> action
%type <proto> proto
%type <ip> ip
%type <ipnode> ipdesc
%type <ipnode> ipset
%type <ipnode> ipaddr
%type <port> port
%type <port> portdesc
%type <direction> direction
%type <optnode> options
%type <optnode> optset
%type <optnode> option
%start rule

%%

/* Snort rules grammar */

rule : action proto ip port direction ip port options
       {
            if (nrules < MAX_RULES) {
                
                ri[nrules].funcs = NULL;
                
                ri[nrules].id = nrules;
                
                ri[nrules].action = $1;
                if (ri[nrules].action != SNTOK_DYN)
                    ri[nrules].active = 1;
                else ri[nrules].active = 0;
                
                ri[nrules].proto = $2;
                fpaux = add_func(&(ri[nrules].funcs), check_proto);
                if (fpaux == NULL) YYABORT;
                
                ri[nrules].src_ips = $3;
                if (ri[nrules].src_ips.ipnode->valid) {
                    fpaux = add_func(&fpaux, check_src_ip);
                    if (fpaux == NULL) YYABORT;
                }
                
                ri[nrules].src_ports = $4;
                if (ri[nrules].src_ports.valid) {
                    switch(ri[nrules].proto) {
                        case IPPROTO_TCP:
                            fpaux = add_func(&fpaux, check_tcp_src_port);
                            if (fpaux == NULL) YYABORT;
                            break;
                        case IPPROTO_UDP:
                            fpaux = add_func(&fpaux, check_udp_src_port);
                            if (fpaux == NULL) YYABORT;
                            break;
                    }
                }
                
                ri[nrules].bidirectional = $5;
                
                ri[nrules].dst_ips = $6;
                if (ri[nrules].dst_ips.ipnode->valid) {
                    fpaux = add_func(&fpaux, check_dst_ip);
                    if (fpaux == NULL) YYABORT;
                }
                
                ri[nrules].dst_ports = $7;
                if (ri[nrules].dst_ports.valid) {
                    switch(ri[nrules].proto) {
                        case IPPROTO_TCP:
                            fpaux = add_func(&fpaux, check_tcp_dst_port);
                            if (fpaux == NULL) YYABORT;
                            break;
                        case IPPROTO_UDP:
                            fpaux = add_func(&fpaux, check_udp_dst_port);
                            if (fpaux == NULL) YYABORT;
                            break;
                    }
                }
                
                ri[nrules].opts = $8;
                if (ri[nrules].opts->keyword) {
                    fpaux = add_func(&fpaux, check_options);
                    if (fpaux == NULL) YYABORT;
                }

                nrules++;

            }
            else {
                yserror("Too many rules in config file");
                YYABORT;
            }
       }

action: ACTION { $$ = translate_kw($1); }

proto: PROTO { $$ = translate_proto($1); }

ip: NEGATION ipdesc { $$.ipnode = $2; $$.negation = 1; }
    | ipdesc { $$.ipnode = $1; $$.negation = 0; }

ipdesc : ipaddr { $$ = $1; 
                  $$->next = NULL;
                  $$->valid = 1; }
       | OPENSQBR ipset CLOSESQBR { $$ = $2; 
                                    $$->valid = 1; }
       | ANY { $$ = (ipnode_t *)prv_alloc(sizeof(ipnode_t));
               if ($$ == NULL) YYABORT;
               $$->ipaddr = translate_ip("0.0.0.0");
               $$->netmask = translate_nm("0"); 
               $$->next = NULL;
               $$->valid = 0; }

ipaddr : IPTOK NETMASK { $$ = (ipnode_t *)prv_alloc(sizeof(ipnode_t));
                         if ($$ == NULL) YYABORT;
                         $$->ipaddr = translate_ip($1);
                         $$->netmask = translate_nm($2); }

ipset : ipaddr { $$ = $1; $$->next = NULL; }
      | ipaddr COMMA ipset { $$ = $1; 
                             ipaux = (ipnode_t *)prv_alloc(sizeof(ipnode_t));
                             if ($$ == NULL) YYABORT;
                             ipaux->ipaddr = $3->ipaddr;
                             ipaux->netmask = $3->netmask;
                             ipaux->next = $3->next;
                             $$->next = ipaux; }

port : NEGATION portdesc { $$ = $2; $$.negation = 1; }
     | portdesc { $$ = $1; $$.negation = 0; }

portdesc : PORT { $$.lowport = atoi($1); $$.highport = atoi($1); $$.valid = 1; }
         | PORT COLON { $$.lowport = atoi($1); $$.highport = MAX_PORT; $$.valid = 1; }
         | COLON PORT { $$.lowport = 1; $$.highport = atoi($2); $$.valid = 1; }
         | PORT COLON PORT { $$.lowport = atoi($1); $$.highport = atoi($3); $$.valid = 1; }
         | ANY { $$.lowport = 1; $$.highport = MAX_PORT; $$.valid = 0; }
     
direction : DIRECTION { if (strncmp($1, "-", 1)) $$ = 1;
                        else $$ = 0; }

options : OPENBR optset CLOSEBR { $$ = $2; }
        | { $$ = (optnode_t *)prv_alloc(sizeof(optnode_t));
            if ($$ == NULL) YYABORT;
            $$->keyword = 0;
            $$->content = NULL;
            $$->next = NULL; }

optset : option { $$ = $1; $$->next = NULL; }
       | option optset { $$ = $1;
                         optaux = (optnode_t *)prv_alloc(sizeof(optnode_t));
                         if ($$ == NULL) YYABORT;
                         optaux->keyword = $2->keyword;
                         if ($2->content != NULL) {
                            optaux->content = (char *)prv_alloc(strlen($2->content)+1);                            
                            if (optaux->content == NULL) YYABORT;
                            strncpy(optaux->content, $2->content, strlen($2->content)+1);
                         }
                         else optaux->content = NULL;
                         optaux->next = $2->next;
                         $$->next = optaux; }

option : KEYWORD CONTENT { $$ = (optnode_t *)prv_alloc(sizeof(optnode_t));
                           if ($$ == NULL) YYABORT;
                           $$->keyword = translate_kw($1);
                           $$->content = (char *)prv_alloc(strlen($2)+1);
                           if ($$->content == NULL) YYABORT;
                           strncpy($$->content, $2, strlen($2)+1);
                           $$->next = NULL; }
       | KEYWORD SEMICOLON { $$ = (optnode_t *)prv_alloc(sizeof(optnode_t));
                             if ($$ == NULL) YYABORT;
                             $$->keyword = translate_kw($1);
                             $$->content = NULL;
                             $$->next = NULL; }
%%

#include "snort-lexic.c"

void yserror(char *error)
{ 
    logmsg(LOGWARN, "SNORT: Error parsing rules: %s\n", error);
}

int 
parse_rules(char *rules, void *mem, size_t msize)
{
    if (!prv_mem) {
        prv_mem = mem;
        prv_memsize = msize;
    }
    ys_scan_string(rules);
    return ysparse();
}
