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

#include "stdpkt.h"     /* pkt_t */

#define MAX_PORT    65535

#define MAX_RULES   50

enum snort_tokens {
    SNTOK_NULL = 0,
    // Tokens for rule actions
    SNTOK_ALERT,
    SNTOK_LOG,
    SNTOK_PASS,
    // Tokens in the rules' options
    SNTOK_CONTENT,
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
    int         active;
    uint8_t     action;
    uint8_t	proto;
    ip_t        src_ips;
    ip_t    	dst_ips;
    portset_t   src_ports;
    portset_t	dst_ports;
    int         bidirectional;  /* 0 -> normal, 1 -> bidirectional */
    fpnode_t    *funcs;         /* list of pointers to check functions */
    optnode_t   *opts;          /* information about the rule's options */
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
