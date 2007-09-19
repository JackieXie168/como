/*
 * Copyright (c) 2006-2007 Universitat Politecnica de Catalunya
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
 * Volume reports. Inspired on "Automatically Inferring Patterns of Resource
 * Consumption in Network Traffic", by Cristian Estan et al.
 */

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <time.h>

#include "module.h"
#include "stdpkt.h"

typedef struct autofocus_record autofocus_rec_t;
struct autofocus_record {
    uint32_t ip_addr;
    int mask;
    uint64_t bytes;
};

typedef struct _vtnode vtnode_t;
struct _vtnode {
    vtnode_t *left;
    vtnode_t *right;
    uint64_t bytes;
    char interest;
};

/* fixed amount of nodes, stored in an array. */
#define MAX_VTNODES 640000

typedef struct _vtstruct vt_t;
struct _vtstruct {
    vtnode_t *root;
};

/* to allocate a node, get it from the array and bzero it */

static vtnode_t *
allocate_vtnode(void * self)
{
    return mem_mdl_malloc(self, sizeof(vtnode_t));

}

/* return the ascii representation of an IP address in host byte order */
#if 0
static char *
ip_to_ascii(uint32_t ip_host_order)
{
    struct in_addr addr;
    addr.s_addr = htonl(ip_host_order);
    return inet_ntoa(addr);
}
#endif

/*
 * functions to deal with ip address clustering.
 */
static void 
initialize_tree_iptraffic(vt_t *t)
{
    t->root = NULL;
}

/* update the tree with an <ipaddr,bytes> pair */
static void 
update_tree_iptraffic(vt_t *t, uint32_t ipaddr, uint64_t bytes, void * self)
{
    vtnode_t *tree, **_child;
    int shift, bit;

    if (t->root == NULL)
        t->root = allocate_vtnode(self);
    tree = t->root;

    for (shift = 31; shift >= 0; shift--) { /* traverse or build path to node */
        bit = ipaddr & (1 << shift);
        _child = bit ? &tree->right : &tree->left;

        if (*_child == NULL)
            *_child = allocate_vtnode(self);
        tree = *_child;
    }

    tree->bytes += bytes; /* update the node */
}

#if 0
static void
dump_tree_iptraffic(vtnode_t *tree, int depth, uint32_t carry_ip)
{
    int i;
    for (i = 0; i < depth; i++) printf(" ");
    if (tree == NULL) {
        printf("NULL\n");
        return;
    }

    if (depth == 32) {
        char *str = ip_to_ascii(carry_ip);
        printf("addr = %s, bytes = %llu\n", str, tree->bytes);
        return;
    }
    printf("+\n");

    depth++;
    dump_tree_iptraffic(tree->left, depth, carry_ip << 1);
    dump_tree_iptraffic(tree->right, depth, (carry_ip << 1) | 1);
}
#endif

/*
 * -- calc_sum
 *
 * Recursively calculate the aggregate traffic for each node.
 */
static uint64_t 
calc_sum(vtnode_t *tree, int depth)
{
    if (tree == NULL)
        return 0;

    depth++;
    tree->bytes += calc_sum(tree->left, depth) + calc_sum(tree->right, depth);
    return tree->bytes;
}


/*
 * -- compress
 *
 * Decides what nodes are to be reported. It filters out all the
 * nodes (clusters) whose aggregate traffic is either below the
 * thres, or whose traffic can be explained from data
 * which is included in the report, within a margin defined by 
 * REDUNDANCY_THRES.
 */
static uint64_t 
compress(vtnode_t *tree, uint64_t inter_thres, uint32_t red_thres, int depth)
{
    uint64_t rep_bytes;

    if (tree == NULL) /* nothing to do */
        return 0;

    /*
     * amount of traffic below the interest threshold. this means that neither
     * this node nor its children will be.
     */
    if (tree->bytes < inter_thres) {
        tree->interest = 0;
        return 0;
    }

    /*
     * first visit the children, and get the already reported bytes
     * for the current tree
     */
    rep_bytes = compress(tree->left, inter_thres, red_thres, depth + 1) +
        compress(tree->right, inter_thres, red_thres, depth + 1);

    if ((rep_bytes + rep_bytes * red_thres/100) >= tree->bytes) {
        /*
         * this node's data is largely explained by data which will
         * be in the report, so it is not interesting.
         */
        tree->interest = 0;
        return rep_bytes; /* the reported bytes from children */
    }

    /*
     * both above the absolute threshold and the redundancy threshold
     */
    tree->interest = 1;
    return tree->bytes; /* the reported bytes are this node's */
}

/*
 * -- _report_iptraffic
 *
 * Copies into a report string the nodes considered to be of interest.
 * Traverses the tree in postorder.
 */
static void 
_report_iptraffic(vtnode_t *tree, autofocus_rec_t *afr, int *count, int depth,
        uint32_t addr)
{
    int j;

    if (tree == NULL)
        return;

    if (tree->interest) {
        j = *count;
        /* save the node information */ 
        afr[j].mask = depth;
        afr[j].ip_addr = addr;
        afr[j].bytes = tree->bytes;
    
        /* mantain the count */
        (*count)++;
    }

    _report_iptraffic(tree->left, afr, count, depth + 1, addr);
    _report_iptraffic(tree->right, afr, count, depth + 1, addr | 
            (1<<(31-depth)));
}

/*
 * -- report_iptraffic
 *
 * Simpler wrapper to _report_iptraffic
 */
static void 
report_iptraffic(vt_t *t, autofocus_rec_t *afr, int *count,
        uint32_t inter_thres, uint32_t red_thres)
{
    uint64_t min_bytes;
    uint64_t total = calc_sum(t->root, 0);
    *count = 0;
    /* apply the user config threshold */
    min_bytes = total * inter_thres / 100;
    compress(t->root, min_bytes,  red_thres, 0);
    _report_iptraffic(t->root, afr, count, 0, 0);
}

#define NUM_REPORTS 100000

#define FLOWDESC    struct _af_fd

FLOWDESC {
    uint32_t ts;
};

#define EFLOWDESC   struct _af_efd

EFLOWDESC {
    uint32_t ts;
    int nelems;
    autofocus_rec_t report[NUM_REPORTS];
};

#define CONFIGDESC   struct _af_config

CONFIGDESC{
    timestamp_t meas_ivl;       /* interval (secs) */
    uint32_t interest_thres;	/* minimum volume to be reported */
    uint32_t redundancy_thres;	/* ?? */
    int use_dst; 		/* set if we should use destination address */ 
    uint32_t last_export;       /* last export time */
};

#define STATE struct _state
STATE {
    vt_t voltree;   /* tree used to  save each IP with its traffic volume */
};


/*
 * -- init
 */
static timestamp_t
init(void *self, char *args[])
{
    int i;
    pkt_t * pkt; 
    metadesc_t *inmd;
    CONFIGDESC * config;
    
    config = mem_mdl_calloc(self, 1, sizeof(CONFIGDESC));
    config->meas_ivl = TIME2TS(1, 0);
    config->use_dst = 1;
    config->interest_thres = 5; // 5%
    config->redundancy_thres = 5; // 5%
    config->last_export = 0;

    for (i = 0; args && args[i]; i++) {  
	char *x;
	
        if (strstr(args[i], "use_src")) {
	    config->use_dst = 0;
        } else if (strstr(args[i], "use_dst")) {
	    config->use_dst = 1;
        } else if (strstr(args[i], "inter_thres")) {
	    x = index(args[i], '=') + 1;
            if (atoi(x) <= 100)
    	        config->interest_thres = atoi(x);
        } else if (strstr(args[i], "red_thres")) {
	    x = index(args[i], '=') + 1; 
            if (atoi(x) <= 100)
	        config->redundancy_thres = atoi(x);
	} else if (strstr(args[i], "interval")) {
	    x = index(args[i], '=') + 1; 
	    config->meas_ivl = TIME2TS(atoi(x),0);
	}
    }
    
    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = config->meas_ivl;
    
    pkt = metadesc_tpl_add(inmd, "none:none:~ip:none");
    N16(IP(len)) = 0xffff;
    IP(proto) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;

    pkt = metadesc_tpl_add(inmd, "none:none:~ip:~tcp");
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;

    pkt = metadesc_tpl_add(inmd, "none:none:~ip:~udp");
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;

    CONFIG(self) = config; 
    
    return config->meas_ivl;
}


/*
 * -- update
 *
 * Instead of updating records, it updates a private memory region
 * and, when an interval change is detected, it copies a report to
 * the current record and tells the system it is full.
 */
static int
update(void *self, pkt_t *pkt, void *fh, int isnew)
{

    FLOWDESC *fd = F(fh);
    CONFIGDESC * config = CONFIG(self);
    static timestamp_t last_ivl = 0;
    timestamp_t ivl;
    STATE * state = FSTATE(self);
    uint32_t src,dst; 
    uint64_t len;

    len = COMO(len);
    src = H32(IP(src_ip));
    dst = H32(IP(dst_ip));

    if (isnew)
        fd->ts = COMO(ts);

    if (config->use_dst)
        update_tree_iptraffic(&state->voltree, dst, len, self);
    else
        update_tree_iptraffic(&state->voltree, src, len, self);

    return 0;
}


/*
 * -- flush
 */
static void *
flush(void *self)
{
    CONFIGDESC * config = CONFIG(self);
    STATE *state;

    state = mem_mdl_malloc(self, sizeof(STATE));
    initialize_tree_iptraffic(&state->voltree);
    return state;
}


/*
 * -- export
 */
static int
export(void * self, void *efh, void *fh, int isnew)
{
    FLOWDESC *fd = F(fh);
    EFLOWDESC *efd = EF(efh);
    STATE * state = FSTATE(self);
    CONFIGDESC * config = CONFIG(self);

    if(isnew){
        bzero(efd, sizeof(EFLOWDESC));
        efd->ts = fd->ts;
    }

    /* dump the voltree to the eflowdesc */    
    report_iptraffic(&state->voltree, efd->report, &efd->nelems,
            config->interest_thres, config->redundancy_thres);

    if (efd->nelems >= NUM_REPORTS)
        panic("report length %d too large, increase REPORT_LEN\n", efd->nelems);

    return 1;
}


/*
 * -- action
 */
static int
action(void *self, void *efh, timestamp_t ivl,
        timestamp_t current_time, int count)
{
    CONFIGDESC * config = CONFIG(self);

    if (efh == NULL) {
        /* 
         * this is the action for the entire table. 
         * check if it is time to export the table. 
         * if not stop. 
         */
        if (TS2SEC(current_time) < config->last_export +
                TS2SEC(config->meas_ivl)){
            return ACT_STOP;}            /* too early */

        config->last_export = TS2SEC(ivl);
        return ACT_GO;          /* dump the records */
    }

    return (ACT_STORE | ACT_DISCARD); /* store the records */
}


/*
 * -- store
 */
static ssize_t
store(void *self, void *efh, char *buf)
{
    EFLOWDESC *efd = EF(efh);
    CONFIGDESC * config = CONFIG(self);
    int i;

    if (efd->ts == 0) /* this record contains no info */
        return 0;

    //PUTH32(buf, efd->ts);
    PUTH32(buf, config->last_export);
    PUTH32(buf, (uint32_t)efd->nelems);

    for (i = 0; i < efd->nelems; i++) {
        PUTH32(buf, efd->report[i].ip_addr);
        PUTH32(buf, efd->report[i].mask);
        PUTH64(buf, efd->report[i].bytes);
    }

    return sizeof(EFLOWDESC);
}


/*
 * -- load
 */
static size_t
load(void * self, char * buf, size_t len, timestamp_t * ts)
{

    if (len < sizeof(EFLOWDESC)) {
        *ts = 0;
        return 0;
    }

    *ts = TIME2TS(ntohl(((EFLOWDESC *)buf)->ts),0);
    return sizeof(EFLOWDESC);
}

#define PRETTY_HDR_SRCS                                                     \
    "\tTimestamp\t\t\t\tSource IP\t\t\t\tTraffic\n"

#define PRETTY_HDR_DSTS                                                     \
    "\tTimestamp\t\t\t\tDestination IP\t\t\t\tTraffic\n"

#define PRETTY_FMT                                                          \
    "\t%u\t\t\t\t%s/%d\t\t\t\t%llu\n"

#define PLAIN_FMT                                                           \
    "\t%u\t\t\t\t%s/%d\t\t\t\t%llu\n"

#define HTML_HDR							    \
"<html>\n"							            \
"<head>\n"                                                                  \
"  <style type=\"text/css\">\n"                                             \
"   body { font-family: \"lucida sans unicode\", verdana, arial;\n"         \
"          font-size: 9pt; margin: 0; padding: 0;}\n"	                    \
"   table, tr, td {background-color: #DDD;\n"		                    \
"     font-family: \"lucida sans unicode\", verdana, arial;\n"              \
"     font-size: 9pt;}\n"				                    \
"   a, a:visited { color: #475677; text-decoration: none;}\n"               \
"   .netviewbar{ \n"                                                        \
"     color :#FFF; width :100%%; padding :2px; text-align:center;}\n"       \
"   .netview {\n"                                                           \
"     top: 0px; width: 100%%; vertical-align:top;\n"                        \
"     margin: 2; padding-left: 5px;\n"                                      \
"     padding-right: 5px; text-align:left;}\n"                              \
"   .nvtitle {\n"                                                           \
"     font-weight: bold; font-size: 9pt; padding-bottom: 3px;\n"            \
"     color: #475677;}\n"                                                   \
"  </style>\n"                                                              \
"</head>\n"                                                                 \
"<body>\n"

#define HTML_TITLE 						            \
"<div class=nvtitle style=\"border-top: 1px solid;\">"	                    \
"Top volume report</div>\n"                                                 \
"<table class=netview>\n"					            \
"  <tr class=nvtitle>\n"					            \
"    <td>Position</td>\n" 	                			    \
"    <td>%s</td>\n"					                    \
"    <td>Traffic (bytes)</td>\n"					    \
"  </tr>\n"

#define HTML_FOOTER						            \
"</table>\n"						                    \
"</body></html>\n"

#define HTML_FMT						            \
"<tr><td>%d</td>"                                                           \
"<td>%s/%d</td>"                                                            \
"<td>%llu</td></tr>\n"

#define HTML_FMT2						            \
"<tr><tr><td><br></td></tr>"                                                \
"<td>%d</td>"                                                               \
"<td>%s/%d</td>"                               	                            \
"<td>%llu</td></tr>\n"

#define SIDEBOX_TITLE 						            \
"<table class=netview>\n"					            \
"  <tr class=nvtitle>\n"					            \
"    <td>Pos</td>\n"						            \
"    <td>%s</td>\n"					                    \
"    <td>Traffic (bytes)</td>\n"				            \
"  </tr>\n"							

    
/*
 * -- print
 */
static char *
print(void *self, char *buf, size_t *len, char * const args[])
{
    
    EFLOWDESC * efd = (EFLOWDESC *) buf;
    CONFIGDESC * config = CONFIG(self);
    static char s[64*1024];
    char * header;
    struct in_addr addr;
    time_t ts;
    static time_t last_ts = 0;
    char *t;
    static char * fmt; 
    static int count = 0; 
    uint64_t bytes;
    int mask;
    uint32_t nelems;
    uint i;
    autofocus_rec_t * record;
    int j;


    /* first call to print */
    if (buf == NULL && args != NULL) {

        char * what[] = {"Source IP", "Destination IP"};
        int n;

        /* by default, pretty print */
        if (config->use_dst)
            *len = sprintf(s, PRETTY_HDR_DSTS); 
        else
            *len = sprintf(s, PRETTY_HDR_SRCS); 

        fmt = PRETTY_FMT; 

        /* first call of print, process the arguments and return */
        for (n = 0; args[n]; n++) {
            if (!strcmp(args[n], "format=plain")) {
                *len = 0; 
                fmt = PLAIN_FMT;
            } else if (!strcmp(args[n], "format=html")) {
                *len = sprintf(s, HTML_HDR); 
                *len += sprintf(s + *len, HTML_TITLE, what[config->use_dst]);
                fmt = HTML_FMT;
            } else if (!strcmp(args[n], "format=sidebox")) {
                *len = sprintf(s, HTML_HDR); 
                *len += sprintf(s + *len, SIDEBOX_TITLE,
                                    what[config->use_dst]);
                fmt = HTML_FMT;
            }
        } 
        count = 0; 	/* reset count */ 
        return s; 
    }

    /* last call of print */
    if (buf == NULL && args == NULL) { 
        *len = 0;
        if (fmt == HTML_FMT) 
            *len = sprintf(s, HTML_FOOTER);
        count = 0;      /* reset count */
        last_ts = 0; 	/* reset timestamp */ 
        return s; 
    } 

    /* get data from buffer */
    ts = (time_t)ntohl(efd->ts);
    t = asctime(localtime(&ts));
    nelems = ntohl(efd->nelems);
    *len = 0;

    if (ts != last_ts)
        count = 0; /* reset count */
    last_ts = ts; 
    count++;

    for (i = 0; i < nelems; i++){
        /* get the i-report from the buffer*/
        record = &efd->report[i];
        addr.s_addr = record->ip_addr;
        mask = ntohl(record->mask);
        bytes = NTOHLL(record->bytes);

        /* fill up each type of output */
        if (fmt == PLAIN_FMT)
            *len += sprintf(s + *len, fmt, ts, inet_ntoa(addr), mask, bytes);
        else if (fmt == PRETTY_FMT)
            *len += sprintf(s + *len, fmt, ts, inet_ntoa(addr), mask, bytes);
        else if (fmt == HTML_FMT) { 
            if (count == 1)
                *len += sprintf(s + *len, HTML_FMT2, count, inet_ntoa(addr),
                        mask, bytes);
            else
                *len += sprintf(s + *len, fmt, count, inet_ntoa(addr), mask,
                        bytes);
        }
        count++;
    }

    return s;
}

MODULE(autofocus) = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: sizeof(EFLOWDESC),
    st_recordsize: sizeof(EFLOWDESC),
    capabilities: {has_flexible_flush: 0, 0},
    init: init,
    check: NULL,
    hash: NULL,  
    match: NULL,
    update: update,
    flush:flush,
    ematch: NULL,
    export: export,
    compare: NULL,
    action: action,
    store: store,
    load: load,
    print: print,
    replay: NULL,
    formats: "plain pretty html sidebox"
};

