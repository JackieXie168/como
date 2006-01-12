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
 * Snort module for CoMo - header file
 * 
 */

#ifdef __FreeBSD__ 
#include <pcre.h>
#else
#include <pcre/pcre.h>       /* pcre library headers (Fedora Core location)
                                The location may be <pcre.h> in other 
                                Linux distributions */
#endif

#include "stdpkt.h" /* pkt_t */

#define MAX_RULES       2000
#define MAX_PORT        65535
#define MAX_STR_SIZE    255

#define ASIZE 256    /* anything that can be represented with a char 
                      * needed for Boyer-Moore pattern matching 
                      */

/* Constants for byte_test and byte_jump options */
#define BIGENDIAN 0
#define LILENDIAN 1

/* Constants for ipopts option */
#define IPOPT_RR        1
#define IPOPT_EOL       2
#define IPOPT_NOP       4
#define IPOPT_TS        8
#define IPOPT_SEC       16
#define IPOPT_LSRR      32
#define IPOPT_SSRR      64
#define IPOPT_SATID     128

/* Constants for fragbits option */
#define FB_MF   0x2000
#define FB_DF   0x4000
#define FB_RSV  0x8000

#define FB_NOT  1
#define FB_ALL  2
#define FB_ANY  3

/* Constants for flags option */
#define FLG_FIN     0x01
#define FLG_SYN     0x02
#define FLG_RST     0x04
#define FLG_PSH     0x08
#define FLG_ACK     0x10
#define FLG_URG     0x20
#define FLG_RSV1    0x80
#define FLG_RSV2    0x40

#define FLG_NOT 1
#define FLG_ALL 2
#define FLG_ANY 3

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
    SNTOK_REF,
    SNTOK_CONTENT,
    SNTOK_PCRE,
    SNTOK_SID,
    SNTOK_REV,
    SNTOK_CTYPE,
    SNTOK_PRIO,
    SNTOK_NOCASE,
    SNTOK_OFFSET,
    SNTOK_DEPTH,
    SNTOK_DISTANCE,
    SNTOK_WITHIN,
    SNTOK_ISDATAAT,
    SNTOK_BYTETEST,
    SNTOK_BYTEJUMP,
    SNTOK_FROFFSET,
    SNTOK_TTL,
    SNTOK_TOS,
    SNTOK_IPID,
    SNTOK_IPOPTS,
    SNTOK_FRAGBITS,
    SNTOK_DSIZE,
    SNTOK_FLAGS,
    SNTOK_SEQ,
    SNTOK_ACK,
    SNTOK_WINDOW,
    SNTOK_ITYPE,
    SNTOK_ICODE,
    SNTOK_ICMPID,
    SNTOK_ICMPSEQ,
    SNTOK_IPPROTO,
    SNTOK_SAMEIP,
    SNTOK_ACTIVATES,
    SNTOK_ACTVBY,
    SNTOK_COUNT,
    // Tokens for unsupported rule options
    SNTOK_RAWBYTES,
    SNTOK_URICNT,
    SNTOK_FTPBOUNCE,
    SNTOK_REGEX,
    SNTOK_CNTLIST,
    SNTOK_FLOW,
    SNTOK_FLOWBITS,
    SNTOK_LOGTO,
    SNTOK_SESSION,
    SNTOK_RESP,
    SNTOK_REACT,
    SNTOK_TAG,    
    SNTOK_THRESHOLD,
    // Tokens for rule options' content
    SNTOK_HIGHPRIO,
    SNTOK_MEDPRIO,
    SNTOK_LOWPRIO,
    SNTOK_LT,
    SNTOK_GT,
    SNTOK_EQ,
    SNTOK_NOTEQ,
    SNTOK_BETWEEN,
    SNTOK_BWAND,
    SNTOK_BWOR,    
};

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

/* Forward declaration */
typedef struct _ruleinfo ruleinfo_t;

struct _fpnode {
    unsigned int (*function)(ruleinfo_t *, pkt_t *);
    struct _fpnode *next;
};
typedef struct _fpnode fpnode_t;

struct _ref {
    char *systemid;
    char *id;
    struct _ref *next;
};

typedef struct _ref ref_t;

struct _optnode {
    struct _optnode *next;
    int keyword;
    char *content;
    uint8_t neg;    /* 0 -> normal, 1 -> negated */
    char *cnt;
    unsigned int cntlen;
    int bmBc[ASIZE];
    int *bmGs;
    uint8_t nocase;
    uint8_t has_depth;
    unsigned int depth;
    unsigned int offset;
    uint8_t has_distance;
    unsigned int distance;
    uint8_t has_within;
    unsigned int within;
    unsigned int isdataat;
    uint8_t relative;
    pcre *regexp;
    unsigned int byte_number;
    uint8_t byte_op;
    unsigned int byte_offset;
    int byte_value;
    uint8_t byte_base;
    uint8_t byte_isstring;
    uint8_t byte_endian;
    unsigned int byte_multi;
};

typedef struct _optnode optnode_t;

struct _opt {
    struct _opt *next;
    uint8_t action;
    optnode_t *options;
    ruleinfo_t *rule;
    unsigned int rule_id;
    uint8_t active;
    unsigned int activates;
    unsigned int actvby;
    unsigned int count;
    unsigned int curr_count;
    ref_t *refs;
    unsigned int sid;
    unsigned int rev;
    char *ctype;
    unsigned int prio;
    char *msg;
    uint8_t fragoffcmp;
    uint16_t fragoffset;
    uint8_t ttlcmp;
    uint8_t ttllow;
    uint8_t ttlhigh;
    uint8_t tos;
    uint16_t ipid;
    uint8_t ipopts;
    uint8_t ipopts_any;
    uint16_t fragbits;
    uint8_t fragbitscmp;
    uint8_t dsizecmp;
    uint16_t dsizelow;
    uint16_t dsizehigh;
    uint8_t flags;
    uint8_t flagscmp;
    uint8_t flagsnone;
    uint32_t seq;
    uint32_t ack;
    uint16_t window;
    uint8_t itypecmp;
    uint8_t itypelow;
    uint8_t itypehigh;
    uint8_t icodecmp;
    uint8_t icodelow;
    uint8_t icodehigh;
    uint16_t icmpid;
    uint16_t icmpseq;
    uint8_t ipprotocmp;
    uint8_t ipproto;
};

typedef struct _opt opt_t;

struct _ruleinfo {
    struct _ruleinfo    *next;
    uint16_t	        proto;
    ip_t                src_ips;
    ip_t    	        dst_ips;
    portset_t           src_ports;
    portset_t	        dst_ports;
    fpnode_t            *funcs;     /* list of pointers to check functions */
    opt_t               *opts;      /* list of rule options */
};

union _varvalue {
    ip_t ip;
    portset_t port;
};
typedef union _varvalue varvalue_t;

struct _varinfo {
    struct _varinfo *next;
    char *name;
    unsigned int namelen;
    uint8_t type; /* 0 = ip, 1 = port */
    varvalue_t value;
};
typedef struct _varinfo varinfo_t;

struct _dyn {
    struct _dyn *next;
    opt_t *activates;
};
typedef struct _dyn dyn_t;

void yserror(char *, ...);

/* Used to allocate memory in the module's private region */
void *prv_alloc(unsigned int);
void prv_free(void *);
void *prv_realloc(void *, unsigned int);

/* String matching functions (Boyer-Moore algorithm) */
void lowercase(char *, unsigned int);
void preBmBc(char *, int, int[]);
void preBmGs(char *, int, int[]);
int BM(char *, int, char *, int, int[], int[], unsigned int *);

/* Check functions */
unsigned int check_proto(ruleinfo_t *, pkt_t *);
unsigned int check_src_ip(ruleinfo_t *, pkt_t *);
unsigned int check_dst_ip(ruleinfo_t *, pkt_t *);
unsigned int check_tcp_src_port(ruleinfo_t *, pkt_t *);
unsigned int check_tcp_dst_port(ruleinfo_t *, pkt_t *);
unsigned int check_udp_src_port(ruleinfo_t *, pkt_t *);
unsigned int check_udp_dst_port(ruleinfo_t *, pkt_t *);
unsigned int check_options(ruleinfo_t *, pkt_t *, opt_t **);
