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
 */

%{

/* C Declarations */
#include <stdio.h>      /* printf */
#include <string.h>     /* strcpy, strncmp, strcat */
#include <stdlib.h>     /* atoi */
#include <stdint.h>     /* uint8_t, etc. */
#include <sys/socket.h> /* inet_aton */
#include <arpa/inet.h>  /* inet_aton */
#include <netinet/in.h> /* inet_aton, some inet macros (IPPROTO_X ...) */
#include <ctype.h>      /* toupper */
#include "snort.h"
#include "como.h"       /* logmsg */

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
    { "alert",          SNTOK_ALERT },
    { "log",            SNTOK_LOG },
    { "pass",           SNTOK_PASS },
    { "content",        SNTOK_CONTENT },
    { NULL,          	0 }    /* terminator */
};

/* These variables are declared in modules/snort.c
 * We fill the info from here while parsing Snort rules
 */
extern ruleinfo_t ri[];
extern int nrules;

ipnode_t *ipaux;
optnode_t *optaux;
fpnode_t *fpaux;

int yylex();
int yyerror(char *error);

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
        yyerror("Invalid IP address in Snort rule");
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
    else yyerror("Invalid CIDR netmask in Snort rule");
    return r;
}

/*
 * -- add_func
 *
 * Adds a function to a rule's list of check functions
 *
 */

static fpnode_t * 
add_func(fpnode_t *list, unsigned int (*function)(ruleinfo_t *, pkt_t *))
{
    /* Add a new function to the list */
    fpnode_t *aux;
    
    aux = (fpnode_t *)safe_calloc(1, sizeof(fpnode_t));
    aux->function = function;
    aux->next = list;
    
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
	ri[nrules].active = 1;
	ri[nrules].action = $1;
	
	ri[nrules].proto = $2;
	ri[nrules].funcs = add_func(ri[nrules].funcs, check_proto);
	
	ri[nrules].src_ips = $3;
	if (ri[nrules].src_ips.ipnode->valid)
	    ri[nrules].funcs = add_func(ri[nrules].funcs, check_src_ip);
	ri[nrules].src_ports = $4;
	if (ri[nrules].src_ports.valid) {
	    switch(ri[nrules].proto) {
	    case IPPROTO_TCP:
		ri[nrules].funcs = add_func(ri[nrules].funcs, check_tcp_src_port);
	    case IPPROTO_UDP:
		ri[nrules].funcs = add_func(ri[nrules].funcs, check_udp_src_port);
	    }
	}
	
	ri[nrules].bidirectional = $5;
	
	ri[nrules].dst_ips = $6;
	if (ri[nrules].dst_ips.ipnode->valid)
	    ri[nrules].funcs = add_func(ri[nrules].funcs, check_dst_ip);
	ri[nrules].dst_ports = $7;
	if (ri[nrules].dst_ports.valid) {
	    switch(ri[nrules].proto) {
	    case IPPROTO_TCP:
		ri[nrules].funcs = add_func(ri[nrules].funcs, check_tcp_dst_port);
	    case IPPROTO_UDP:
		ri[nrules].funcs = add_func(ri[nrules].funcs, check_udp_dst_port);
	    }
	}
	
	ri[nrules].opts = $8;
	ri[nrules].funcs = add_func(ri[nrules].funcs, check_options);

	nrules++;

    } else 
	logmsg(LOGWARN, "SNORT: too many rules in config file");
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
       | ANY { $$ = (ipnode_t *)safe_calloc(1, sizeof(ipnode_t));
               $$->ipaddr = translate_ip("0.0.0.0");
               $$->netmask = translate_nm("0"); 
               $$->next = NULL;
               $$->valid = 0; }

ipaddr : IPTOK NETMASK { $$ = (ipnode_t *)safe_calloc(1, sizeof(ipnode_t));
                         $$->ipaddr = translate_ip($1);
                         $$->netmask = translate_nm($2); }

ipset : ipaddr { $$ = $1; $$->next = NULL; }
      | ipaddr COMMA ipset { $$ = $1; 
                             ipaux = (ipnode_t *)safe_calloc(1, sizeof(ipnode_t));
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
        | { $$ = (optnode_t *)safe_calloc(1, sizeof(optnode_t));
            $$->keyword = 0; }

optset : option { $$ = $1; $$->next = NULL; }
       | option optset { $$ = $1;
                         optaux = (optnode_t *)safe_calloc(1, sizeof(optnode_t));
                         optaux->keyword = $2->keyword;
                         optaux->content = strdup($2->content);
                         optaux->next = $2->next;
                         $$->next = optaux; }

option : KEYWORD CONTENT { $$ = (optnode_t *)safe_calloc(1, sizeof(optnode_t));
                           $$->keyword = translate_kw($1);
                           $$->content = strdup($2);
                           $$->next = NULL; }
       | KEYWORD QUOTEDCONTENT { $$ = (optnode_t *)safe_calloc(1, sizeof(optnode_t));
                                 $$->keyword = translate_kw($1);
                                 $$->content = strdup($2);
                                 $$->next = NULL; }
       | KEYWORD SEMICOLON { $$ = (optnode_t *)safe_calloc(1, sizeof(optnode_t));
                             $$->keyword = translate_kw($1);
                             $$->content = NULL;
                             $$->next = NULL; }
%%

#include "snort-lexic.c"

int yyerror(char *error) 
{ 
    logmsg(LOGWARN, "SNORT: Error parsing rules: %s\n", error);
    return 0; 
}

void 
snort_parse_rules(char *rules)
{
    yy_scan_string(rules);
    yyparse();
}
