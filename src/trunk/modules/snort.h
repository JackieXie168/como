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

#ifdef __FreeBSD__ 
#include <pcre.h>
#else
#include <pcre/pcre.h>       /* pcre library headers */
#endif 

#include "stdpkt.h"     /* pkt_t */

#define MAX(a,b) (a > b) ? a : b
#define MIN(a,b) (a < b) ? a : b

#define MAX_PORT        65535
#define MAX_RULES       50
#define MAX_STR_SIZE    255 

#define ASIZE 256    /* anything that can be represented with a char 
                      * needed for Boyer-Moore pattern matching 
                      */

enum snort_tokens {
    SNTOK_NULL = 0,
    // Tokens for rule actions
    SNTOK_ALERT,
    SNTOK_LOG,
    SNTOK_PASS,
    SNTOK_ACTIV,
    SNTOK_DYN,
    // Tokens for rule options
    SNTOK_MSG,
    SNTOK_CONTENT,
    SNTOK_PCRE,
    SNTOK_SID,
    SNTOK_REV,
    SNTOK_CTYPE,
    SNTOK_PRIO,
    SNTOK_NOCASE,
    SNTOK_OFFSET,
    SNTOK_DEPTH,
    SNTOK_FROFFSET,
    SNTOK_TTL,
    SNTOK_TOS,
    SNTOK_IPID,
    SNTOK_DSIZE,
    SNTOK_ACTIVATES,
    SNTOK_ACTVBY,
    SNTOK_COUNT,
    // Tokens for rule options' content
    SNTOK_HIGHPRIO,
    SNTOK_MEDPRIO,
    SNTOK_LOWPRIO,
};

struct _ruleinfo;
typedef struct _ruleinfo ruleinfo_t;

struct _fpnode {
    unsigned int (*function)(ruleinfo_t *, pkt_t *);
    struct _fpnode *next;
};

typedef struct _fpnode fpnode_t;

struct _optnode {
    int keyword;
    char *content;
    uint cntlen;
    int bmBc[ASIZE];
    int *bmGs;
    uint8_t neg;    /* 0 -> normal, 1 -> negated */
    struct _optnode *next;
};

typedef struct _optnode optnode_t;

struct _ipnode {
    unsigned int valid;
    uint32_t ipaddr;
    uint32_t netmask;
    struct _ipnode *next;
};

typedef struct _ipnode ipnode_t;

struct _ip {
    unsigned int negation;
    ipnode_t *ipnode;
};

typedef struct _ip ip_t;

struct _portset {
    unsigned int valid;
    unsigned int negation;
    uint16_t lowport;
    uint16_t highport;
};

typedef struct _portset portset_t;

struct _ruleinfo {
    int         id;
    uint8_t     active;
    int         activates;
    int         actvby;
    int         count;
    int         act_count;
    uint8_t     action;
    uint8_t	proto;
    ip_t        src_ips;
    ip_t    	dst_ips;
    portset_t   src_ports;
    portset_t	dst_ports;
    int         bidirectional;  /* 0 -> normal, 1 -> bidirectional */
    fpnode_t    *funcs;         /* list of pointers to check functions */
    optnode_t   *opts;          /* information about the rule's options */
    char        msg[MAX_STR_SIZE];
    uint        sid;
    uint8_t     rev;
    char        ctype[MAX_STR_SIZE];
    uint        priority;
    uint8_t     nocase;
    uint        offset;
    uint        depth;
    uint16_t    fragoffset;
    int8_t      fragoffcmp;     /* 0 -> equal, 1 -> gt, -1 -> lt */
    uint8_t     ttllow;
    uint8_t     ttlhigh;
    int8_t      ttlcmp;         /* 0 -> equal, 1 -> gt, -1 -> lt, 2 -> between */
    uint8_t     tos;
    uint16_t    ipid;
    uint16_t    dsizelow;
    uint16_t    dsizehigh;
    int8_t      dsizecmp;
    pcre        *regexp;
};

/* Check function declarations */
unsigned int check_proto(ruleinfo_t *, pkt_t *);
unsigned int check_tcp_src_port(ruleinfo_t *, pkt_t *);
unsigned int check_tcp_dst_port(ruleinfo_t *, pkt_t *);
unsigned int check_udp_src_port(ruleinfo_t *, pkt_t *);
unsigned int check_udp_dst_port(ruleinfo_t *, pkt_t *);
unsigned int check_src_ip(ruleinfo_t *, pkt_t *);
unsigned int check_dst_ip(ruleinfo_t *, pkt_t *);
unsigned int check_options(ruleinfo_t *, pkt_t *);

/* Used to allocate memory in the module's private region */
void *prv_alloc(unsigned int nbytes);
void prv_free(void *);

/* String matching function (Boyer-Moore algorithm) */
void preBmBc(char *, int, int[]);
void preBmGs(char *, int, int[]);
int BM(char *, int, char *, int, int[], int[]);

/* Translates a keyword string into an integer constant */
int translate_kw(char *);
