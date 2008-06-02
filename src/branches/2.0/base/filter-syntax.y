/*
 * Copyright (c) 2005-2006, Intel Corporation
 * Copyright (c) 2005-2006, Universitat Politecnica de Catalunya
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the distribution.
 * * Neither the name of Intel Corporation nor the names of its contributors
 *   may be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id$
 */

/*
 * Filter parsing for CoMo - syntax file
 * 
 * Here we define the syntax of a CoMo filter, and the specific actions to be
 * done when a part of a filter is recognised.
 * 
 * GNU Bison turns this file into a C program that can parse a filter string
 * and return a semantically equivalent and normalized string, that can be
 * compared with others.
 *
 * The following process is used to normalize a filter:
 * 
 * 1. Read the filter string and create a tree that represents the logical
 *    expression obtained from it. This tree can be evaluated when packets
 *    arrive to see if they match the corresponding filter.
 *
 * 2. Transform the tree to Conjunctive Normal Form:
 *      - Propagate negations inward the tree, until only literals
 *        (leaves of the tree) are negated.
 *      - Propagate conjunctions outward, using the logical rules that apply.
 *
 * 3. Traverse the tree and transform it into a string, using lexicographical
 *    order to assure that two semantically equivalent filters always produce
 *    the same string.
 *
 *
 * How to add new keywords to the filter parser:
 * ---------------------------------------------
 *
 * 1. base/filter-lexic.l: add new tokens and their corresponding actions.
 *    
 *      - You can add variables at the beginning of the file, and use regular
 *        expressions to define the new tokens.
 *
 * 2. base/filter-syntax.y: add new token declarations, and new data types
 *    to the %union section
 *
 * 3. base/filter-syntax.y: extend the "expr" rule of the grammar as needed.
 *
 *      - You should always finish with a call to tree_make:
 *          Example:
 *          $$ = tree_make(Tpred, Tproto, NULL, NULL, (nodedata_t *)&$1);
 *        where $1 is a structure containing the data related to the new
 *        keyword.
 *
 * 4. base/filter-syntax.y: modify the tree_make function accordingly.
 *
 */
 
%{

/* C Declarations */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h> 	/* va_start */

#define LOG_DOMAIN "FILTER"
#include "como.h"
#include "comopriv.h"

#define YYERROR_VERBOSE

/* Node types */
#define Tnone  0
#define Tand   1
#define Tor    2
#define Tnot   3
#define Tpred  4
#define Tip    5
#define Tport  6
#define Tproto 7
#define Tiface 8
#define Texporter 9
#define Tfromds   10
#define Ttods     11
#define Tasn      12
#define Tether    13
#define Tall      14

struct _listnode
{
    char *string;
    struct _listnode *next;
    struct _listnode *prev;
};
typedef struct _listnode listnode_t;

int yflex(void);
void yferror(char *fmt, ...);

/* Variables where the results will be stored after parsing the filter */
treenode_t **filter_tree;
char **filter_cmp;


/*
 * -- parse_ip
 *
 * Dots and numbers notation -> Binary representation of an IP address
 *
 */
static int
parse_ip(char *ipstring, uint32_t *ip)
{
    struct in_addr inp;
    
    if (!inet_aton(ipstring, &inp)) {
        yferror("Invalid IP address: %s", ipstring);
        return -1;
    }
    *ip = inp.s_addr;
    return 0;
}

static int
parse_mac(char *macstring, uint8_t *mac)
{
    struct ether_addr *a;
    a = ether_aton(macstring);
    if (a == NULL) {
        yferror("Invalid MAC address: %s", macstring);
        return -1;
    }
    memcpy(mac, a, sizeof(struct ether_addr));
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
 * -- parse_nm
 *
 * CIDR notation -> integer representing the network mask
 *
 */
static int
parse_nm(int i, uint32_t *nm)
{
    if (i >= 0 && i <= 32) *nm = htonl(netmasks[i]);
    else {
        yferror("Invalid CIDR netmask: %d", i);
        return -1;
    }
    return 0;
}

/*
 * -- append_string
 *
 */
char *
append_string(char *dest, char *src)
{
    dest = (char *)safe_realloc(dest, strlen(dest) + strlen(src) + 1);
    strcat(dest, src);
    return dest;
}

/* 
 * -- tree_make
 * 
 * Create a new expression tree node
 *
 */
treenode_t *
tree_make(uint8_t type, uint8_t pred_type, treenode_t *left,
          treenode_t *right, nodedata_t *data)
{
    treenode_t *t;
    
    t = (treenode_t *)safe_malloc(sizeof(treenode_t));
    t->type = type;
    if (t->type == Tpred) {
        t->pred_type = pred_type;
        t->data = (nodedata_t *)safe_malloc(sizeof(nodedata_t));
        switch(t->pred_type) {
        case Tip:
            asprintf(&(t->string), "%d ip %d/%d",
                     data->ipaddr.direction,
                     data->ipaddr.ip,
                     data->ipaddr.nm);
            t->data->ipaddr.direction = data->ipaddr.direction;
            t->data->ipaddr.ip = data->ipaddr.ip & data->ipaddr.nm;
            t->data->ipaddr.nm = data->ipaddr.nm;
            break;
        case Tasn:
            asprintf(&(t->string), "%d ASN %d",
                     data->asn.direction,
                     data->asn.asn);
            t->data->asn.direction = data->asn.direction;
            t->data->asn.asn = data->asn.asn;
            break;
        case Tether:
            asprintf(&(t->string), "ETHER %d %s",
                     data->ether.direction,
                     ether_ntoa((struct ether_addr *) data->ether.mac));
            t->data->ether.direction = data->ether.direction;
            memcpy(t->data->ether.mac, data->ether.mac, 6);
            break;
        case Tport:
            asprintf(&(t->string), "%d port %d:%d",
                     data->ports.direction,
                     data->ports.lowport,
                     data->ports.highport);
            t->data->ports.direction = data->ports.direction;
            t->data->ports.lowport = data->ports.lowport;
            t->data->ports.highport = data->ports.highport;
            break;
        case Tproto:
            asprintf(&(t->string), "proto %d", data->proto);
            t->data->proto = data->proto;
            break;
        case Tiface:
            asprintf(&(t->string), "iface %d %d", 
		    data->iface.direction, data->iface.index);
            t->data->iface.direction = data->iface.direction;
            t->data->iface.index = data->iface.index;
            break;
	case Texporter:
            asprintf(&(t->string), "exporter %d",
                     data->exaddr.ip);
            t->data->exaddr.ip = data->exaddr.ip;
            break;
        case Tfromds:
            asprintf(&(t->string), "from_ds");
            t->data = NULL;
        case Ttods:
            asprintf(&(t->string), "to_ds");
            t->data = NULL;
        case Tall:
            asprintf(&(t->string), "all");
            t->data = NULL;
        }
    }
    t->right = right;
    t->left = left;
    
    return(t);
}

/*
 * -- list_add
 *
 * Add an element to a sorted list
 * XXX Insertion sort, quite inefficient
 *
 */
listnode_t *
list_add(listnode_t *list, char *s)
{
    listnode_t *laux;
    
    if (!list) {
        list = (listnode_t *)safe_malloc(sizeof(listnode_t));
        list->next = NULL;
        list->prev = NULL;
        list->string = safe_strdup(s);
    }
    else {
        if (strcmp(s, list->string) <= 0) {
            laux = (listnode_t *)safe_malloc(sizeof(listnode_t));
            laux->string = safe_strdup(s);
            laux->next = list;
            laux->prev = list->prev;
            list->prev = laux;
            list = laux;
        }
        else {
            laux = list_add(list->next, s);
            list->next = laux;
            laux->prev = list;
        }
    }

    return list;
}

/*
 * -- list_merge
 *
 * Insert the elements of a list into another list
 *
 */
listnode_t *list_merge(listnode_t *l1, listnode_t *l2)
{
    listnode_t *laux;

    for (laux = l2; laux; laux = laux->next)
        l1 = list_add(l1, laux->string);
    
    return l1;
}

char *tree_to_string(treenode_t *);

/*
 * -- list_make
 *
 * Create a sorted list from an expression tree
 *
 */
listnode_t *
list_make(listnode_t *list, uint8_t type, treenode_t *tree)
{
    char *s;
    
    if (!tree) return NULL;

    switch (tree->type) {
    case Tnot:
    case Tpred:
        s = tree_to_string(tree);
        list = list_add(list, s);
        free(s);
        break;
    case Tand:
    case Tor:
        if (tree->type == type) {
            list = list_make(list, type, tree->left);
            list = list_make(list, type, tree->right);
        } else {
            s = tree_to_string(tree);
            list = list_add(list, s);
            free(s);
        }
        break;
    }

    return list;
}

/*
 * -- tree_to_string
 *
 */
char *
tree_to_string(treenode_t *tree)
{
    char *s = NULL;
    listnode_t *list, *laux;
    
    if (!tree) return NULL;
    
    switch (tree->type) {
    case Tand:
        list = list_make(NULL, Tand, tree->left);
        list = list_merge(list, list_make(NULL, Tand, tree->right));
        s = safe_strdup("(");
        for (laux = list; laux->next; laux = laux->next) {
            s = append_string(s, laux->string);
            s = append_string(s, " && ");
        }
        s = append_string(s, laux->string);
        s = append_string(s, ")");
        /* free the list */
        do {
            laux = list->next;
            free(list->string);
            free(list);
            list = laux;
        } while (laux);
        break;
	case Tor:
        list = list_make(NULL, Tor, tree->left);
        list = list_merge(list, list_make(NULL, Tor, tree->right));
        s = safe_strdup("(");
        for (laux = list; laux->next; laux = laux->next) {
            s = append_string(s, laux->string);
            s = append_string(s, " || ");
        }
        s = append_string(s, laux->string);
        s = append_string(s, ")");
        /* free the list */
        do {
            laux = list->next;
            free(list->string);
            free(list);
            list = laux;
        } while (laux);
        break;
	case Tnot:
        s = safe_strdup("!");
        s = append_string(s, tree_to_string(tree->left));
        break;
    case Tpred:
        s = safe_strdup(tree->string);
        break;
    }
    
    return s;
}

/*
 * -- tree_print_indent
 *
 * Print an expression tree with indentation
 * (only used for debug purposes)
 *
 */
void
tree_print_indent(treenode_t *tree, int indent)
{
    int i;

    if (!tree) return;
    printf("\n");
    printf("     ");
    for (i = 1; i <= indent; i++) printf("   ");
    switch (tree->type) {
    case Tand:
        printf("and");
        break;
	case Tor:
        printf("or");
        break;
	case Tnot:
        printf("not");
        break;
    case Tpred:
        printf("%s", tree->string);
        break;
    }
    tree_print_indent(tree->left, indent + 1);
    tree_print_indent(tree->right, indent + 1);
}

/*
 * -- tree_print
 *
 * Print an expression tree
 * (only used for debug purposes)
 *
 */
void
tree_print(treenode_t *tree)
{
    if (tree) {
        printf("\n\n\nLogical Expression Tree: \n\n");
        tree_print_indent(tree, 0);
        printf("\n\n\n\n");
    } else
        printf("\n\n\nLogical Expression Tree is empty!\n\n");
}

treenode_t *negate(treenode_t *);

/*
 * -- prop_negs
 *
 * Propagate the negations of a tree inward with the following rules:
 *      not(not(A)) => A
 *      not(A and B) => not(A) or not(B)
 *      not(A or B) => not(A) and not(B)
 *
 */
treenode_t *
prop_negs(treenode_t *t)
{
    switch(t->type) {
    case Tnot:
        t = negate(t->left);
        break;
    case Tand:
    case Tor:
        prop_negs(t->left);
        prop_negs(t->right);
        break;
    }

    return t;
}

/*
 * -- negate
 *
 * Negate a node of a tree
 *
 */
treenode_t *
negate(treenode_t *t)
{
    switch(t->type) {
    case Tpred:
        /* Negate the node */
        t = tree_make(Tnot, Tnone, t, NULL, NULL);
        break;
    case Tnot:
        /* Double negation, get rid of it */
        t = prop_negs(t->left);
        break;
    case Tand:
        /* not(A and B) => not(A) or not(B) */
        t->type = Tor;
        t->left = negate(t->left);
        t->right = negate(t->right);
        break;
    case Tor:
        /* not(A or B) => not(A) and not(B) */
        t->type = Tand;
        t->left = negate(t->left);
        t->right = negate(t->right);
        break;
    }

    return t;
}

/*
 * -- tree_copy
 *
 * Duplicate a tree and return a pointer to the new copy
 *
 */
treenode_t *
tree_copy(treenode_t *t)
{
    treenode_t *taux, *taux_left, *taux_right;

    if (!t)
        return NULL;
    
    taux_left = tree_copy(t->left);
    taux_right = tree_copy(t->right);
    taux = tree_make(t->type, t->pred_type, taux_left, taux_right, t->data);

    return taux;
}

/*
 * -- or_and
 *
 * Propagate conjunctions outward with the following rule:
 *      A or (B and C) => (A or B) and (A or C)
 *
 */
treenode_t *
or_and(treenode_t *t)
{
    treenode_t *taux;
    uint8_t type;
    
    switch(t->left->type) {
        case Tor:
            type = t->left->type;
            t->left = or_and(t->left);
            if (t->left->type != type) {
                t = or_and(t);
                /* No need to check the right child */
                return t;
            }
            break;
        case Tand:
            /* Apply the rule ... */
            t->type = Tand;
            t->left->type = Tor;
            taux = t->left->right;
            t->left->right = t->right;
            t->right = tree_make(Tor, Tnone, taux,
                                 tree_copy(t->left->right), NULL);
            
            t->left = or_and(t->left);
            t->right = or_and(t->right);
            
            /* No need to check the right child */
            return t;
            
            break;
    }

    switch(t->right->type) {
        case Tor:
            type = t->right->type;
            t->right = or_and(t->right);
            if (t->right->type != type)
                t = or_and(t);
            break;
        case Tand:
            /* Apply the rule ... */
            t->type = Tand;
            t->right->type = Tor;
            taux = t->right->left;
            t->right->left = t->left;
            t->left = tree_make(Tor, Tnone, tree_copy(t->right->left),
                                taux, NULL);
            
            t->left = or_and(t->left);
            t->right = or_and(t->right);
            
            break;
    }    
    
    return t;
}

/*
 * -- prop_conjs
 *
 * Propagate conjunctions outward with the following rule:
 *      A or (B and C) => (A or B) and (A or C)
 *
 */
treenode_t *
prop_conjs(treenode_t *t)
{
    switch(t->type) {
    case Tnot:
        prop_conjs(t->left);
        break;
    case Tand:
        prop_conjs(t->left);
        prop_conjs(t->right);
        break;
    case Tor:
        t = or_and(t);
        break;
    }

    return t;
}

/*
 * -- cnf
 *
 * Transform an expression tree to Conjunctive Normal Form
 *
 */
treenode_t *
cnf(treenode_t *t)
{
    /* 1. Propagate negations inward */
    t = prop_negs(t);
    /* 2. Propagate conjunctions outward */
    t = prop_conjs(t);
    
    return t;
}

/*
 * -- evaluate_pred
 *
 * Evaluate a predicate expression
 *
 */
int evaluate_pred(treenode_t *t, pkt_t *pkt)
{
    int z = 0;

    if (t != NULL) {
        switch(t->pred_type) {
        case Tip:
            if (!isIP) 
		return 0;
            if (t->data->ipaddr.direction == 0)			/* src */
                z = ((N32(IP(src_ip)) & t->data->ipaddr.nm) ==
                     t->data->ipaddr.ip);
            else if (t->data->ipaddr.direction == 1)		/* dst */
                z = ((N32(IP(dst_ip)) & t->data->ipaddr.nm) ==
                     t->data->ipaddr.ip);
            else 						/* addr */
                z = ((N32(IP(dst_ip)) & t->data->ipaddr.nm) ==
                     t->data->ipaddr.ip) || 
                    ((N32(IP(src_ip)) & t->data->ipaddr.nm) ==
                     t->data->ipaddr.ip);
            break;
        case Tasn:
            if (!isIP) 
		return 0;
            if (t->data->asn.direction == 0)			/* src */
                z = asn_test((H32(IP(src_ip))), t->data->asn.asn);
            else if (t->data->ipaddr.direction == 1)		/* dst */
                z = asn_test((H32(IP(dst_ip))), t->data->asn.asn);
            else 						/* addr */
                z = asn_test((H32(IP(src_ip))), t->data->asn.asn) ||
		    asn_test((H32(IP(dst_ip))), t->data->asn.asn);
            break;
        case Tether:
            if (!isETH && !isVLAN) 
		return 0;
            if (t->data->ether.direction == 0)			/* src */
                z = (memcmp(ETH(src), t->data->ether.mac, 6) == 0);
            else if (t->data->ipaddr.direction == 1)		/* dst */
                z = (memcmp(ETH(dst), t->data->ether.mac, 6) == 0);
            else 						/* addr */
                z = (memcmp(ETH(src), t->data->ether.mac, 6) == 0) ||
		    (memcmp(ETH(dst), t->data->ether.mac, 6) == 0);
            break;
        case Tport:
            if (!isTCP && !isUDP)
                return 0;
            if (t->data->ports.direction == 0) {
                if (isTCP)
                    z = (H16(TCP(src_port)) >= t->data->ports.lowport &&
                         H16(TCP(src_port)) <= t->data->ports.highport);
                else /* udp */
                    z = (H16(UDP(src_port)) >= t->data->ports.lowport &&
                         H16(UDP(src_port)) <= t->data->ports.highport);
            } else {
                if (isTCP)
                    z = (H16(TCP(dst_port)) >= t->data->ports.lowport &&
                         H16(TCP(dst_port)) <= t->data->ports.highport);
                else /* udp */
                    z = (H16(UDP(dst_port)) >= t->data->ports.lowport &&
                         H16(UDP(dst_port)) <= t->data->ports.highport);
            }
            break;
   	case Tiface: 
	    if (COMO(type) != COMOTYPE_NF) 
		return 0; 
	    if (t->data->iface.direction == 0) 
		z = (H16(NF(input)) == t->data->iface.index); 
	    else 
		z = (H16(NF(output)) == t->data->iface.index); 
            break;
	case Texporter:
	    if (COMO(type) != COMOTYPE_NF) 
		return 0; 
	    z = (N32(NF(exaddr)) == t->data->exaddr.ip);
            break;
        case Tproto:
            switch(t->data->proto) {
            case ETHERTYPE_IP:
                z = isIP;
                break;
            case IPPROTO_TCP:
                z = isTCP;
                break;
            case IPPROTO_UDP:
                z = isUDP;
                break;
            case IPPROTO_ICMP:
                z = isICMP;
                break;
            }
            break;
        case Tfromds:
            if (COMO(type) == COMOTYPE_RADIO) {
                if (IEEE80211_BASE(fc_from_ds))
                    z = 1;
            }
            break;
        case Ttods:
            if (COMO(type) == COMOTYPE_RADIO) {
                if (IEEE80211_BASE(fc_to_ds))
                    z = 1;
            }
            break;
        case Tall:
            z = 1;
            break;
        }
    }

    return z;
}

/*
 * -- evaluate
 *
 * Evaluate an expression tree
 *
 */
int evaluate(treenode_t *t, pkt_t *pkt)
{
    int x,y,z = 0;
    
    if (t == NULL) return 1;
    else {
        if (t->type != Tpred) {
            x = evaluate(t->left, pkt);
            /* Shortcuts */
            if ((!x && t->type == Tand) || (x && t->type == Tor))
                return x;
            y = evaluate(t->right, pkt);
            switch(t->type) {
            case Tand:
                z = x && y;
                break;
            case Tor:
                z = x || y;
                break;
            case Tnot:
                z = (x == 0)? 1 : 0;
                break;
            }
        } else {
            z = evaluate_pred(t, pkt);
        }
    }

    return z;
}

%}

%union {
    char *string;
    uint8_t byte;
    uint16_t word;
    uint32_t dword;
    treenode_t *tree;
    ipaddr_t ipaddr;
    portrange_t portrange;
    iface_t iface;
    ipaddr_t exaddr;
    asnfilt_t asn;
    etherfilt_t ether;
}

/* Data types and tokens used by the parser */

%token NOT AND OR OPENBR CLOSEBR COLON ALL EXPORTER FROMDS TODS ASN ETHER
%left NOT AND OR /* Order of precedence */
%token <byte> DIR PORTDIR IFACE
%token <word> LEVEL3 LEVEL4 NUMBER
%token <dword> NETMASK
%token <string> IPADDR MACADDR
%type <tree> expr
%type <ipaddr> ip
%type <asn> asnfilt
%type <ether> etherfilt
%type <portrange> port
%type <word> proto 
%type <iface> iface
%type <exaddr> exporter
%start filter

%%

/* Grammar rules and actions */

filter: expr
        {
        if (filter_tree != NULL)
            *filter_tree = tree_copy($1);
        $1 = cnf($1);
        if (filter_cmp != NULL)
	    *filter_cmp = tree_to_string($1);
        }
      | ALL
        {
        if (filter_tree != NULL)
            *filter_tree = NULL;
        if (filter_cmp != NULL)
	    asprintf(filter_cmp, "all");
        }
;
expr: expr AND expr
      {
        $$ = tree_make(Tand, Tnone, $1, $3, NULL);
      }
    | expr OR expr
      {
        $$ = tree_make(Tor, Tnone, $1, $3, NULL);
      }
    | NOT expr
      {
        $$ = tree_make(Tnot, Tnone, $2, NULL, NULL);
        
      }
    | OPENBR expr CLOSEBR
      {
        $$ = tree_copy($2);
      }
    | ip
      {
        $$ = tree_make(Tpred, Tip, NULL, NULL, (nodedata_t *)&$1);
      }
    | asnfilt
      {
        $$ = tree_make(Tpred, Tasn, NULL, NULL, (nodedata_t *)&$1);
      }
    | etherfilt
      {
        $$ = tree_make(Tpred, Tether, NULL, NULL, (nodedata_t *)&$1);
      }
    | port
      {
        $$ = tree_make(Tpred, Tport, NULL, NULL, (nodedata_t *)&$1);
      }
    | proto
      {
        $$ = tree_make(Tpred, Tproto, NULL, NULL, (nodedata_t *)&$1);
      }
    | iface
      {
        $$ = tree_make(Tpred, Tiface, NULL, NULL, (nodedata_t *)&$1);
      }
    | exporter
      {
        $$ = tree_make(Tpred, Texporter, NULL, NULL, (nodedata_t *)&$1);
      }
    | FROMDS
      {
        $$ = tree_make(Tpred, Tfromds, NULL, NULL, NULL);
      }
    | TODS
      {
        $$ = tree_make(Tpred, Ttods, NULL, NULL, NULL);
      }
    | ALL
      {
        $$ = tree_make(Tpred, Tall, NULL, NULL, NULL);
      }
;
ip: DIR IPADDR
    {
        $$.direction = $1;
        if (parse_ip($2, &($$.ip)) == -1)
            YYABORT;
        /* Assume it's a host IP address if we don't have a netmask */
        $$.nm = htonl(netmasks[32]);
    }
  | DIR IPADDR NETMASK
    {
        $$.direction = $1;
        if (parse_ip($2, &($$.ip)) == -1)
            YYABORT;
        if (parse_nm($3, &($$.nm)) == -1)
            YYABORT;
    }
;
etherfilt: ETHER DIR MACADDR
    {
	$$.direction = $2;
	if (parse_mac($3, $$.mac) == -1)
	    YYABORT;
    }
;
asnfilt: DIR ASN NUMBER
    {
        $$.direction = $1;
        $$.asn       = $3;
    }
;
port: PORTDIR NUMBER
      {
        $$.direction = $1;
        $$.lowport = $2;
        $$.highport = $2;
      } 
    | PORTDIR NUMBER COLON
      {
        $$.direction = $1;
        $$.lowport = $2;
        $$.highport = 65535;
      }
    | PORTDIR COLON NUMBER
      {
        $$.direction = $1;
        $$.lowport = 1;
        $$.highport = $3;
      }
    | PORTDIR NUMBER COLON NUMBER
      {
        $$.direction = $1;
        $$.lowport = $2;
        $$.highport = $4;
      }
;
proto: LEVEL3
       {
        $$ = $1;
       }
     | LEVEL4
       {
        $$ = $1;
       }
;
iface: IFACE NUMBER
       {
        $$.direction = $1;
	$$.index = $2;
       }
;
exporter: EXPORTER IPADDR
          {
           if (parse_ip($2, &($$.ip)) == -1)
               YYABORT;
          }
;
%%

#include "filter-lexic.c"

void yferror(char *fmt, ...)
{ 
    va_list ap;
    char error[255];
    
    va_start(ap, fmt);
    vsnprintf(error, sizeof(error), fmt, ap);
    warn("Filter parser error: %s\n", error);
    va_end(ap);
}

int 
parse_filter(char *f, treenode_t **result_tree, char **result_cmp)
{
    filter_tree = result_tree;
    filter_cmp = result_cmp;
    yf_scan_string(f);
    return yfparse();
}
