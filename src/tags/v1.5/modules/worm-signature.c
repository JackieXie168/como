/*
 * Copyright (c) 2007 Universitat Politecnica de Catalunya
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

/*
 * Worm Signature Generation Module.
 *
 * This module generates signatures from the traffic it receives. The traffic 
 * normally comes from the 'scanner_detect' module and the 'flow_reassembly' 
 * module, so the captured traffic is actually reassembled TCP flows coming 
 * from suspicious IPs.
 * 
 * The flows are stored in the export hash table, grouped by destination port.
 * 
 * Periodically, the module does content-based partitioning of the suspicious 
 * flows with the same destination port, and measures the prevalence of each 
 * content block that results from the partitioning. The most prevalent blocks 
 * are then chosen as signatures.
 *
 * This module is based on the method described in "Autograph: Toward
 * Automated, Distributed Worm Signature Detection" by Hyang-Ak Kim and Brad
 * Karp.
 *
 */
 
#include <stdio.h>
#include <time.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>        
        
#include "module.h"
#include "hash.h"
#include <openssl/md5.h>

/* CoMo module structures */
#define FLOWDESC    struct _signature_cap
#define EFLOWDESC   struct _signature_exp
#define CONFIGDESC  struct _signature_config

/* defines for fingerprinting */
#define POLY 0xbfe6b8a5bf378d83LL
#define WINDOW_SIZE 16
#define BREAKPOINT 0x07

#define MAX_STORE 10000



/*
 * Polynomial fingerprinting library
 *
 * Library necessary for generating Rabin string fingerprints
 */

struct _window
{
    uint64_t polynomial;
    uint64_t fingerprint;
    int winpos;
    uint64_t U[256];
    unsigned char *buffer;
    int winsize;
    int shiftvalue;
    uint64_t T[256];
};
typedef struct _window window;


void init_window(window *this_w, uint64_t poly, int size, void *);
uint64_t appendbyte (window *w, uint64_t polyact, unsigned char byte);
uint64_t slidebyte (window *w, unsigned char byte);

uint64_t mod (uint64_t xh, uint64_t xl, uint64_t divd);
void mult (uint64_t *resh, uint64_t *resl, uint64_t x, uint64_t y);
int degree (uint64_t p);    
int hbs (uint64_t p);

void precalculateT(window *);


void init_window(window *this_w, uint64_t poly, int size, void *this_mod)
{
    uint64_t sizeshift=1;
    uint64_t auxh, auxl;
    int i;
    
    this_w->shiftvalue = degree(poly) - 8;
    this_w->polynomial = poly;
    this_w->winsize = size;
    this_w->buffer = (unsigned char *)mem_mdl_malloc(this_mod, sizeof(unsigned
                    char) * (size+1));
    bzero(this_w->buffer, sizeof(unsigned char) * (size+1));

    this_w->winpos = -1;

    for (i = 1; i < size; i++) {
        sizeshift = appendbyte(this_w, sizeshift, 0);
    }

    for (i = 0; i < 256; i++) {
        mult(&auxh, &auxl, i, sizeshift);
        this_w->U[i] = mod(auxh, auxl, poly);
    }
    
    precalculateT(this_w);
}

uint64_t appendbyte (window *w, uint64_t polyact, unsigned char byte)
{
    return ((polyact << 8) | byte) ^ w->T[polyact >> w->shiftvalue];
}

uint64_t slidebyte (window *w, unsigned char byte)
{
    unsigned char oldbyte;
    if (w->winpos++ >= w->winsize) {
        w->winpos = 0;
    }
    oldbyte = w->buffer[w->winpos];
    w->buffer[w->winpos] = byte;
    w->fingerprint = appendbyte(w, w->fingerprint ^ w->U[oldbyte], byte);
    
    return w->fingerprint;
}

uint64_t mod (uint64_t xh, uint64_t xl, uint64_t divd)
{
    /*
     * calculates x % div where xh are the 64 highest bits of x, and xl are the
     * lowest 64.
     */
    int i;
    int k = degree(divd);   /* degree of div */
    divd <<= 63 - k;
    
    if (xh) {
        if (xh & 0x8000000000000000LL) {
            xh ^= divd;
        }

        for (i = 62; i >= 0; i--) {
            if (xh & ((uint64_t) 1) << i) {
                xh ^= divd >> (63 - i);
                xl ^= divd << (i + 1);
            }
        }
    }
    
    for (i = 63; i >= k; i--) {  
        if (xl & 1LL << i) {
            xl ^= divd >> (63 - i);
        }
    }
    return xl;
}

void mult (uint64_t *resh, uint64_t *resl, uint64_t x, uint64_t y)
{
    int i;
    uint64_t rh = 0, rl = 0;
    if (x & 1) {
        rl = y;
    }
    for (i = 1; i < 64; i++) {
        if (x & (1LL << i)) {
            rh ^= y >> (64 - i);
            rl ^= y << i;
        }
    }
    if (resh) {
        *resh = rh;
    }
    if (resl) {
        *resl = rl;
    }
}

int degree (uint64_t p)
{
    return hbs(p) -1;
}

int hbs (uint64_t p)     /* highest bit set */
{
    int i = 0;
    uint64_t mask = 0x8000000000000000LL;
    
    if (p) {
        for (i=64; i>0; i--) {
            if (p & mask) {
                break;
            }
            mask >>= 1;
        }
    }
    
    return i;
}

void precalculateT(window *w)
{
    int i;
    int kp = degree(w->polynomial);

    uint64_t auxh, auxl;
    uint64_t T_1;
    
    T_1 = mod (0, 1LL << kp, w->polynomial);
    
    for (i = 0; i < 256; i++) {
        mult(&auxh, &auxl, i, T_1);
        w->T[i] = mod(auxh, auxl, w->polynomial) | (uint64_t) i << kp;
    }
}

/*
 * List
 *
 * Very basic list implementation
 *
 */

struct _list
{
    struct _item *first;
};

struct _item
{
    void *content;
    struct _item *next;
    struct _item *prev;

};

typedef struct _item item;
typedef struct _list list;

void list_new(list *l);
item* list_insert(list *l, void *cont, void *mdl);
void* list_get_content(item *i);
item* list_get_item(list *l, void *c);
void list_remove(list *l, item *i, void *mdl);

struct _list_iterator
{
    struct _item *current;
};

typedef struct _list_iterator list_iterator;

void ite_reset(list* l, list_iterator *i);
item* ite_next(list_iterator *i);
void destroy_list(void *mdl, list *l);

void list_new(list *l)
{
    l->first = NULL;
}


item* list_insert(list *l, void *cont, void* mdl)
{
    item* aux_item;
    
    aux_item = (item *)mem_mdl_malloc(mdl, sizeof(item));
    
    aux_item->content = cont;
    
    aux_item->next = l->first;
    aux_item->prev = NULL;
    
    if (l->first != NULL)
        l->first->prev = aux_item;
    
    l->first = aux_item;
    
    return l->first;
    
}

void* list_get_content(item *i)
{
    if (i != NULL) {
        return i->content;
    }
    else {
        return NULL;
    }
}

item* list_get_item(list *l, void *c)
{
    item *i;
    i = l->first;
    if (c != NULL) {
        while (i != NULL && c != i->content) {
            i = i->next;
        }
        if (i != NULL) {
            return i;
        }
    }

    return NULL;
}

void list_remove(list *l, item *i, void *mod_p)
{
    if (i == NULL) {
        return;
    }
    
    if (i->next != NULL) {
        i->next->prev = i->prev;
    }
    
    if (i->prev != NULL) {
        i->prev->next = i->next;
    }
    
    if (l->first == i) {
        l->first = i->next;
    }
    
    mem_mdl_free(mod_p, i);
}

void ite_reset(list* l, list_iterator *i)
{
    i->current = l->first;
}

item* ite_next(list_iterator *i)
{
    item *aux;
    
    if (i->current == NULL) {
        return NULL;
    }
    aux = i->current;

    i->current = i->current->next;

    return aux;
}

void destroy_list(void *mdl, list *l)
{
    item *i;
    item *aux;
    i = l->first;
    while (i != NULL) {
        aux = i->next;
        mem_mdl_free(mdl, i);
        i = aux;
    }
    l->first = NULL;
}



/* info of suspcious flow */
struct _flowitem
{
    struct _flowitem* prev;
    struct _flowitem* next;
    
    /* list of content blocks in this flow.*/
    list * content_blocks; 
    int num_blocks;
    
    /* timestamp of this flow */
    timestamp_t ts;
    
    /* pointer to real content, and length of data */
    char *flow_content;
    uint32_t flow_content_len;
    
    /*
     * pointer to entry in EXPORT hash table - when this flow is removed from
     * the flow pool, i must decrement the number of flows in this entry
     */
    EFLOWDESC* ex_desc;
    int expire;
};
typedef struct _flowitem flowitem;

/* info of content block */
struct _content_block 
{
    /* MD5 of the content */
    char *md5digest;
    
    /* content (maybe not necessary) and length of data */
    char *content;
    size_t len;
    
    /* list of pointer to flows that contain this block */
    list flows;
    
    /*
     * number of flows in which this block appears (so, amount of flows in
     * previous list)
     */
    int orig_num_flows;
    int num_flows;
    
    /* 
     * auxiliar list of content blocks that have maximum number of flows
     * containing it 
     */
    struct _content_block *max_next;
};
typedef struct _content_block content_block;

void init_cb(content_block *cb)
{
    cb->md5digest = 0;
    cb->content = NULL;
    cb->len = 0;
    
    list_new(&(cb->flows));
    cb->num_flows = 0;
    cb->orig_num_flows = 0;
    
    cb->max_next = NULL;
}
        
struct _signature
{
    /* destination port attacked by the worm that caused this signature */
    uint16_t dst_port;
    
    /* byte-pattern selected as signature */
    char * pattern;
    
    /* length of the pattern */
    uint32_t len;
    
    /* the signatures prevalence */
    uint16_t prevalence;
};
typedef struct _signature signature;

uint hash_function(const void *key)
{
    return (uint) (*((uint64_t*)key));
}

int key_cmp_function(const void *key1, const void *key2)
{
    if (*(uint64_t*)key1 == *(uint64_t*)key2) {
        return 0;
    }
    else {
        return -1;
    }
}

FLOWDESC 
{
    int len; 
    char * buf; 
};

EFLOWDESC
{
    /* timestamp of this export table entry */
    timestamp_t ts;
    
    /* destination port of the flows in this export record */
    uint16_t dst_port;
    
    /* number of flows for this destination port */
    int32_t num;
    
    /* list of all suspicious flows with this destination port */
    flowitem* flowlist;
    
    /* histogram of content blocks */
    hash_t *htable;
    
    /* list of content blocks that currently appear in most flows */
    content_block *max;
};

CONFIGDESC
{
    /* interval for checking if it should generate signatures(secs) */
    timestamp_t gen_ivl;
    
    /* threshold of flows per port, to start signature generation */
    int gen_thresh;
    
    /* minimum prevalence for a content block to be accepted */
    int min_prevalence;
    
    /* timestamp of last attempt to generate signatures */
    timestamp_t last_gen;
    
    /* timeout to remove flows from the flow pool */
    timestamp_t flow_timeout;
    
    /* percentage of flows to be covered by sig generation before it ends */
    double percentage;
    
    /* total number of flows in the pool */
    int total_flows;
    
    /*
     * blacklist containing character strings. when a content block is a
     * substring of any of these items, it can not be chosen as a content block
     */
    hash_t * blacklist;
    
    /* average content block size */
    uint32_t avg_cb_size;
    
    /* minimum content block size */
    uint32_t min_cb_size;
    
    /* maximum content block size */
    uint32_t max_cb_size;
    
    /* hash table containing the signatures */
    list * signatures;
    
    /*
     * boolean to control if we have already stored signatures at each action 
     * callback
     */
    int stored;
    
    /* format for print callback */
    char * format;
    
    /* total signatures */
    int total_sig;
    
};


void generate_signature(void * mod_p, char * pattern, uint32_t len, uint16_t
dst_port, uint16_t prevalence)
{
    CONFIGDESC *config = CONFIG(mod_p);
    signature * sig;
    
    /* create the signature and all its fields */
    sig = (signature *)mem_mdl_malloc(mod_p, sizeof(signature));
    sig->pattern = (char *)mem_mdl_malloc(mod_p, len);
    memcpy(sig->pattern, pattern, len);
    sig->dst_port = dst_port;
    sig->len = len;
    sig->prevalence = prevalence;
    
    /*
     * insert it in the list of signatures, and set the 'stored' flag to 0, 
     * indicating that not all signatures have been stored
     */
    
    list_insert(config->signatures, (void *)sig, mod_p);
    config->stored = 0;
}

int check_blacklist(CONFIGDESC *config, content_block * cb)
{
    hash_t * blacklist;
    char * bl_item;
    size_t bl_item_len;
    
    size_t idx=0;
    size_t idx2=0;

            
    blacklist = config->blacklist;
    
    hash_iter_t iterator;   
    hash_iter_init(blacklist, &iterator);
    
    if (cb == NULL) {
        return 0;
    }
    
    while (hash_iter_next (&iterator)) {
        bl_item = (char *)hash_iter_get_key (&iterator);
        bl_item_len = strlen(bl_item);
        
        if (cb->len <= bl_item_len) {
            for (idx = 0; (bl_item_len - idx) >= cb->len; idx++) {
                for (idx2=0; idx2<cb->len; idx2++) {
                    if (cb->content[idx2] != bl_item[idx + idx2]) {
                        break;
                    }
                }
                if (idx2 == cb->len) { /* blacklisted */
                    return 1;
                }
            }
        }
    }
    
    return 0;
}

int analyze_histogram(void *mod_p, EFLOWDESC* ex, int min_prevalence)
{
    
    list_iterator ite_flows;
    list_iterator ite_cbs;
    item *aux_cb;
    item *aux_flow;
    
    CONFIGDESC *config = CONFIG(mod_p);
    
    content_block *curr_cb, *cb_in_flow, *remove_cb, *debugcb;
    flowitem *curr_flow;
    int total_flows;
    
    /* only use the content blocks of maximum prevalence each time */
    curr_cb = ex->max;
    total_flows = 0;    
    
    /* hash iterator to search for new CB of max prevalence */
    hash_iter_t iterator;
    int max_value = 0;

    if (curr_cb->orig_num_flows < min_prevalence) {
        return -1;
    }
    
        
    while (curr_cb != NULL) { /* loop of all CBs of MAX PREVALENCE */
                    
        /* 0. Check the blacklist, in case the content block is there */

        if (check_blacklist(config, curr_cb) == 0) {
            
            /* 1. Generate signature with current content block */
            generate_signature(mod_p, curr_cb->content, curr_cb->len,
            ex->dst_port, curr_cb->orig_num_flows);
        }
        
        /*
         * 2. MAINTAIN HASH, EXPORT HASH - Remove all flows that contain this
         * content block from the flow pool
         * At the same time, modify all content blocks in the hash that were
         * in any of these flows (decrement flow counter / remove from the CB
         * flow list) 
         */
        
        ite_reset(&(curr_cb->flows), &ite_flows);
        
        while ((aux_flow = ite_next(&ite_flows)) != NULL) {
            /* 
             * loop of all flows containing this MAX-PREV CB - they must be
             * removed from the flowlist!!!
             */

            curr_flow = (flowitem *)list_get_content(aux_flow);
            
            if (curr_flow->expire == 0) {
                ite_reset(curr_flow->content_blocks, &ite_cbs);
                    
                while ((aux_cb = ite_next(&ite_cbs)) != NULL) {
                    cb_in_flow = (content_block *) list_get_content(aux_cb);

                    if (curr_cb != cb_in_flow) {
                        /* remove the current flow from this CB */
                        list_remove(&(cb_in_flow->flows),
                        list_get_item(&(cb_in_flow->flows), curr_flow),mod_p); 
                        
                        cb_in_flow->num_flows--;
                
                    }
                }
                
                /* remove this flow from suspicious flow pool */
                curr_flow->expire = 1;
                
                /* decrement number of flows in the export table entry */
                ex->num--; 
                
                /* increment the amount of flows used in the signatures */
                total_flows++;
            }
        }
        
        /* 
         * 3. Next CB
         * store a pointer to the content block that should be removed
         */
        remove_cb = curr_cb;
        
        /* should not be selected ever again */
        curr_cb->num_flows = 0; 
        curr_cb->orig_num_flows = 0;
        curr_cb = curr_cb->max_next;

        /* destroy the CB */
        /* first remove from hash table */
        hash_remove_string(ex->htable, (char *)remove_cb->md5digest);
        
        /* then destroy object */
        destroy_list(mod_p, &(remove_cb->flows));
        mem_mdl_free(mod_p, remove_cb);
    }
    
    /* regenerate sg->max (CB with highest prevalence) */
    hash_iter_init(ex->htable, &iterator);
    max_value = 0;
    ex->max = NULL;
    
    while (hash_iter_next (&iterator)) {
        
        curr_cb = (content_block *)hash_iter_get_value (&iterator);
        curr_cb->max_next = NULL;
        if (curr_cb->orig_num_flows > max_value) {
            ex->max = curr_cb;
            curr_cb->max_next = NULL;
            max_value = curr_cb->orig_num_flows;    
        }
        else if(curr_cb->orig_num_flows == max_value) {
            curr_cb->max_next = ex->max;
            ex->max = curr_cb;
        }
    }
    return total_flows;
}


void analyze_flows(EFLOWDESC *ex, double percentage, int min_prevalence, void
*mod_p)
{
    /*
     * generate signatures iteratively while the minimum percentage of the
     * suspicious flow pool has not been used.
     */
    
    /* fingerprint */
    uint64_t fp;    
    /* sliding window for calculating fingerprints */
    window polyWindow;
    /* index of the content of current flow being analysed */
    uint32_t idx;
    /* last breakpoint, current breakpoint, size of partition */
    uint32_t last, size;            
    /* current flow in loop */
    flowitem *curr_flow;
    /* content block */
    content_block *cb;
    /* content of flow */
    char *curr_content;
    /* key for hash (md5 of content block) */
    char *key;
    /* flows used so far for signature generation */
    int num_flows, total_flows = 0;     
    
    curr_content = NULL;
    
    CONFIGDESC *config = CONFIG(mod_p);
    
    module_t *mdl = mod_p;
    
    init_window(&polyWindow, POLY, WINDOW_SIZE, mod_p);
    
    curr_flow = ex->flowlist;
    ex->htable = hash_new(&(mdl->alc), HASHKEYS_STRING, hash_function, NULL);
    
    while (curr_flow != NULL) {
        
        if (curr_flow->expire == 1) {
            /* this should never happen */
            continue;
        }
        
        /*
         * loop of signature generations: create the hash table with all the
         * content blocks
         */
        last = 0;
        
        /* initialize the list of this flows content blocks.*/
        curr_flow->content_blocks = (list *) mem_mdl_malloc(mod_p,
        sizeof(list));
        list_new(curr_flow->content_blocks);
        
        for(idx=0; idx<(curr_flow->flow_content_len); idx++) {

            size = (idx - last)+1;

            fp = slidebyte(&polyWindow, curr_flow->flow_content[idx]);

            if (((fp % config->avg_cb_size) == BREAKPOINT && size >
                config->min_cb_size)  /* normal breakpoint */
                || size >= config->max_cb_size  /* block is getting too big */
                || ((curr_flow->flow_content_len - last) < config->min_cb_size)
                || idx+1 == curr_flow->flow_content_len) /* not enough */
            {
                if ((curr_flow->flow_content_len - last) < config->min_cb_size)
                {
                    /*
                     * if it is this case, skip calculating rabin until the end
                     * - just take the last piece as a content block.
                     */
                    
                    idx = (curr_flow->flow_content_len-1);
                    size = (idx-last)+1;
                    if (size <= 0) {
                        break;
                    }
                }
                
                /* create a new content block */
                curr_content = (char *)mem_mdl_malloc(mod_p, size);
                memcpy(curr_content, &(curr_flow->flow_content[last]), size);

                key = (char *) mem_mdl_malloc(mod_p, 16);
                
                MD5((unsigned char *)curr_content, size, (unsigned char *)key);

                cb = (content_block *)hash_lookup_string(ex->htable, key);
                
                /* check if this content block already exists */
                if(cb == NULL) {
                    /* not already in hash table, so create new entry */
                    
                    cb = (content_block *)mem_mdl_malloc(mod_p,
                    sizeof(content_block));
                    
                    init_cb(cb);
                    
                    cb->content = curr_content;
                    cb->len = size;
                    cb->md5digest = key;

                    hash_insert_string(ex->htable, (char *)key, cb);
                }
                else {
                    /*
                     * the content block is already in the hash table, so no
                     * need to keep it in memory
                     */
                    mem_mdl_free(mod_p, curr_content);
                    mem_mdl_free(mod_p, key);
                }

                if ((flowitem **)list_get_content(cb->flows.first) !=
                    &curr_flow)
                /* 
                 * only add information about the flow if it has not already
                 * been added
                 * (this happens if the same content block is twice in the same
                 * flow)
                 */
                {
                    /* 
                     * the content block has a list of pointer to the flows 
                     * that contain it - insert curr_flow
                     */
                    
                    list_insert(&(cb->flows), (void*)curr_flow, mod_p);
                    cb->num_flows++;
                    cb->orig_num_flows++;
                    
                    /*
                     * the flow has a list of pointers to the content blocks
                     * that it contains - insert cb
                     */
                    list_insert(curr_flow->content_blocks, (void *)cb, mod_p);
                    curr_flow->num_blocks++;
                    
                    if (ex->max == NULL || ex->max == cb) {
                        ex->max = cb;
                        cb->max_next = NULL;
                    }
                    else {
                        if (cb->num_flows >= ex->max->num_flows) {
                            if (cb->num_flows == ex->max->num_flows) {
                                cb->max_next = ex->max;
                                ex->max = cb;
                            }
                            else {
                                ex->max = cb;
                                cb->max_next = NULL;
                            }
                        }
                    }
                }
                
                last = idx+1;
            }
        }

        curr_flow = curr_flow->next;
    }
        
    /*
     * successively choose the CB of highest prevalence as signature, until
     * 'percentage'% of flows have been covered.
     */
    
    int num_initial_flows = ex->num;
    total_flows = 0;

    while ((num_initial_flows * percentage > total_flows)) {       
        if((num_flows = analyze_histogram(mod_p, ex, min_prevalence))<0) {
            break;
        }
        else {
            total_flows += num_flows;
        }
    }
    
    hash_destroy(ex->htable);
    ex->max = NULL;

}

void expire_flows(EFLOWDESC *ex, timestamp_t current_time, timestamp_t
flow_timeout, void * mod_p)
        
{
    
    int n=0;
    flowitem *curr_flow, *aux_flow;
    
    curr_flow = ex->flowlist;
    
    while (curr_flow != NULL) {
        
        if (curr_flow->expire == 1 || TS2SEC(current_time) >=
        TS2SEC(curr_flow->ts) + TS2SEC(flow_timeout)) {
            /* current flow has expired! delete it from the list */
            
            n++;
            
            if (curr_flow->next != NULL)
                curr_flow->next->prev = curr_flow->prev;
            if (curr_flow->prev != NULL)
                curr_flow->prev->next = curr_flow->next;
            if (curr_flow == ex->flowlist)
                ex->flowlist = curr_flow->next;
            
            aux_flow = curr_flow->next;

            curr_flow->prev = NULL;
            curr_flow->next = NULL;
            
            if (curr_flow->expire == 0) { 
              /*
               * only decrement number of flows if the flow was expired by time
               * (not by previous signature generation, which would already 
               * have decremented this counter)
               */
                ex->num--;  
            }
            
            /* 
             * delete the flow information forever - only pointers + content 
             * space reserved
             */
            mem_mdl_free(mod_p, curr_flow->flow_content);  
            
            if (curr_flow->content_blocks != NULL) {
                destroy_list(mod_p, curr_flow->content_blocks);
                mem_mdl_free(mod_p, curr_flow->content_blocks);
            }
            curr_flow->num_blocks=0;
            mem_mdl_free(mod_p, curr_flow);
            
            curr_flow = aux_flow;
        }
        else {
            curr_flow = curr_flow->next;
        }
    }
    
}

static timestamp_t init(void * self, char *args[])
{
    CONFIGDESC *config;
    int i;
    metadesc_t *inmd;
    pkt_t *pkt;
    flowitem *aux_test;
    
    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    
    pkt = metadesc_tpl_add(inmd, "any:any:~ip:~tcp");
    N16(TCP(src_port)) = 0xffff;
    N16(TCP(dst_port)) = 0xffff;
    IP(proto) = 0xff;
    N16(IP(len)) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    
    config = (CONFIGDESC *)mem_mdl_malloc(self, sizeof(CONFIGDESC));

    /* create empty blacklist hash table */
    config->blacklist = hash_new(&(((module_t *)self)->alc), HASHKEYS_STRING,
    NULL, NULL); 
    
    
    config->signatures = (list *) mem_mdl_malloc(self, sizeof(list));
    list_new(config->signatures);
    
    config->stored = 1;
    config->total_sig = 0;
        
    /* default values for config parameters */
    
    config->gen_ivl = TIME2TS(600, 0);
    config->gen_thresh = 10;
    config->flow_timeout = TIME2TS(86400, 0);
    config->min_prevalence = 5;
    config->percentage = 0.5;
    config->avg_cb_size = 64;
    config->min_cb_size = 32;
    config->max_cb_size = 1024;
    
    config->last_gen = TIME2TS(0,0);
    config->total_flows = 0;
    
    for (i = 0; args && args[i]; i++) {
        if (strstr(args[i], "#") != args[i]) {
            /* Its not a comment */
            
            if (strstr(args[i], "gen-interval")) {
                char * val = index(args[i], '=') + 1;
                config->gen_ivl = TIME2TS(atoi(val), 0);
            }
            else if (strstr(args[i], "gen-threshold")) {
                char * val = index(args[i], '=') + 1;
                config->gen_thresh = atoi(val);
            }
            else if (strstr(args[i], "flow-timeout")) {
                char * val = index(args[i], '=') + 1;
                config->flow_timeout = TIME2TS(atoi(val), 0);
            }
            else if (strstr(args[i], "min-prevalence")) {
                char * val = index(args[i], '=') + 1;
                config->min_prevalence = atoi(val);
            }
            else if (strstr(args[i], "percentage")) {
                char * val = index(args[i], '=') + 1;
                config->percentage = atof(val);
            }
            else if (strstr(args[i], "blacklist")) {
                /* Blacklist item */
                char * val = index(args[i], '=') + 1;
                int size = strlen(val);
                if (size > 0) {
                    char * blitem = (char *)mem_mdl_malloc(self, size+1);
                    blitem[size]='\0';
                    memcpy(blitem, val, size+1);
                    hash_insert_string(config->blacklist, blitem, NULL);
                }
            }
            else if (strstr(args[i], "avg_cb_size")) {
                char * val = index(args[i], '=') + 1;
                config->avg_cb_size = atoi(val);
            }
            else if (strstr(args[i], "min_cb_size")) {
                char * val = index(args[i], '=') + 1;
                config->min_cb_size = atoi(val);
            }
            else if (strstr(args[i], "max_cb_size")) {
                char * val = index(args[i], '=') + 1;
                config->max_cb_size = atoi(val);
            }
        }
    }

    CONFIG(self) = config;
    
    return TIME2TS(1,0);
}

static int check(void * self, pkt_t *pkt)
{
    CONFIGDESC *config = CONFIG(self);
    /* Only accept packets with payload */
    
    if (config->last_gen == 0) {
        /* Initializing last generation time to the time of first packet */
        config->last_gen = pkt->ts;
    }
    
    
    if (H16(IP(len)) == (IP(ihl)*4 + TCP(hlen)*4) || pkt->caplen == pkt->l7ofs)
    {
        /* captured length is equal to the data offset, so no data. */

        return 0;
    }


    return 1;
}

static uint32_t hash(void * self, pkt_t *pkt)
{
    if (pkt->l3type != ETHERTYPE_IP) {
        return 0; 
    }
    
    /* group flows by destination port */
    return (H16(TCP(dst_port)));
}

static int update(void * self, pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);
    x->len = sizeof(pkt_t) + pkt->caplen;

    x->buf = (char *)mem_mdl_malloc(self, x->len);
    
    memcpy(x->buf, pkt, sizeof(pkt_t)); 
    memcpy(x->buf + sizeof(pkt_t), pkt->payload, pkt->caplen); 
    ((pkt_t *) x->buf)->payload = x->buf + sizeof(pkt_t);

    return 1;
}

static int ematch(void * self, void *efh, void *fh)
{
    pkt_t* pkt;
    FLOWDESC *x = F(fh);
    EFLOWDESC *ex = EF(efh);

    pkt = (pkt_t *)x->buf;

    /* group flows by destination port */
    return (ex->dst_port == H16(TCP(dst_port)));
}

static int export(void * self, void *efh, void *fh, int isnew)
{   
    pkt_t* pkt;
    FLOWDESC *x = F(fh);
    EFLOWDESC *ex = EF(efh);
    CONFIGDESC *config;
    config = CONFIG(self);

    flowitem* flow;
    pkt = (pkt_t *)x->buf;

    if (isnew == 1) {
        ex->num = 0;
        ex->dst_port = H16(TCP(dst_port));
        ex->flowlist = NULL;
        ex->max = NULL;
        ex->htable = NULL;
        ex->ts = COMO(ts);
    }
    
    /* new flowlist item in the state memory */
    flow = (flowitem *)mem_mdl_malloc(self, sizeof(flowitem));
    
    flow->flow_content_len = pkt->caplen - pkt->l7ofs; /* ONLY content! */
            
    flow->flow_content = 0;
    flow->expire = 0;
    flow->content_blocks = NULL;
    flow->num_blocks=0;

    flow->flow_content = (char *)mem_mdl_malloc(self, flow->flow_content_len);
    
    memcpy(flow->flow_content, pkt->payload + pkt->l7ofs,
           flow->flow_content_len); 
    

    
    /* insert into flowlist */
    flow->next = ex->flowlist;
    flow->prev = NULL;
    if (ex->flowlist != NULL) {
        ex->flowlist->prev = flow;
    }
    ex->flowlist = flow;
    
    
    /* timestamp of this flow */
    flow->ts = pkt->ts;
    
    /* 
     * point to ex entry, to be able to decrease the number of flows when this
     * flow is removed
     */
    flow->ex_desc = ex;
    
    /* increment the number of flows with this destination port */
    ex->num++;
    config->total_flows++;

    return 0;
}


static int action(void * self, void *efh, timestamp_t ivl, timestamp_t
current_time, int count)
{
    EFLOWDESC *ex = EF(efh);
    CONFIGDESC *config;

    flowitem* aux_test;
    
    int num_flows, total_flows;
    
    num_flows = 0;
    total_flows = 0;
    
    config = CONFIG(self);
    
    if (efh == NULL) {
        timestamp_t now = current_time;
            
        if (TS2SEC(current_time) >= TS2SEC(config->last_gen) +
            TS2SEC(config->gen_ivl)) {
            config->last_gen = current_time;
            return ACT_GO;
        }
        else {
            return ACT_STOP;
        }
    }
    else {
        expire_flows(ex, current_time, config->flow_timeout, self);
        
        /* check if there are enough flows to begin signature generation */
        if (ex->num > config->gen_thresh) {
            /* generate signatures */
            analyze_flows(ex, config->percentage, config->min_prevalence, self);
            
            /* expire flows that where removed while generating signatures */
            expire_flows(ex, current_time, config->flow_timeout, self);
            
            if (config->stored == 0) {
                config->stored = 1;
                return ACT_STORE;
            }
        }
        else if (ex->num == 0) {
            /* flows were used in signature creation, or were expired */
            return ACT_DISCARD;
        }
    }
    return 0;
}

static ssize_t store(void * self, void *efh, char *buf)
{
    CONFIGDESC * config = CONFIG(self);
    int mem_offset = 0;
    int num = 0;
    
    timestamp_t ts = TIME2TS(time(0), 0);
    
    EFLOWDESC *ex = EF(efh);
    
    /*
     * i will first store a int variable indicating the amount of signatures i
     * have stored, and the timestamp
     */
    mem_offset = sizeof(int) + sizeof(timestamp_t);
    
    signature * sig;
    
    item * aux_item;
    list_iterator l_ite;
    ite_reset(config->signatures, &l_ite);
    
    while ((aux_item = ite_next(&l_ite)) != NULL) {
        sig = (signature *) list_get_content(aux_item);
        
        /* is there enough space for the next signature? */
        if (mem_offset + sizeof(signature) + sig->len <= MAX_STORE) {
            num++;      
            
            /* copy the signature header */
            memcpy(buf + mem_offset, sig, sizeof(signature));
            mem_offset += sizeof(signature);
            
            /* copy the signature data */
            memcpy(buf + mem_offset, sig->pattern, sig->len);
            mem_offset += sig->len;
            
            /* remove the signature as it has already been stored */
            list_remove(config->signatures, aux_item, self);

            /* start the list again (as we have removed the item) */
            ite_reset(config->signatures, &l_ite);
        }
        else {
            /* we have stored MAXIMUM already */
            /* indicate that more must be stored next time */
            config->stored = 0;
            break;
        }
    }
    
    /*
     * copy the amount of signatures, so the load callback knows how many
     * signatures to look for
     */
    memcpy(buf, &num, sizeof(int));
    
    /* copy the timestamp */
    memcpy(buf + sizeof(int), &(ex->ts), sizeof(timestamp_t));
        
    return mem_offset;
}

static size_t load(void * self, char * buf, size_t len, timestamp_t * ts)
{
    if (len == 0) {
        /* its a case where no signatures were stored */
        return 0;
    }
    
    signature * sig;
    
    /* retrieve the amount of signatures that this block of memory contains */
    int num = *((int *)buf);
    
    /* where the next signature is */
    int memory_offset = sizeof(int);
    *ts = *((timestamp_t *)(buf + memory_offset));
    
    memory_offset += sizeof(timestamp_t);
    
    while (num > 0) {
        /* get the next signature */
        sig = (signature *)(buf + memory_offset);
        memory_offset += sizeof(signature);
        memory_offset += sig->len;
        num--;
    }

    return memory_offset;
}

/* Print MACROS */

#define DATAHEX "0"
#define DATABIN "1"
#define DATASNORT "2"
#define GNUPLOTFMT "3"

#define GNUPLOTHDR                                                      \
    "set terminal postscript eps color solid lw 1 \"Helvetica\" 14;"    \
    "set grid;"                                                         \
    "set ylabel \"Signatures\";"                                        \
    "set xlabel \"Time (H:M UTC)\";"                                    \
    "set yrange [0:*];"                                                 \
    "set autoscale xfix;"                                               \
    "unset key;"                                                        \
    "set xdata time;"                                                   \
    "set timefmt \"%%s\";"                                              \
    "set format x \"%%H:%%M\";"                                         \
    "plot \"-\" using 1:2 with lines lt 3\n"


#define GNUPLOTLINE      "%"PRIu32" %u\n"

#define GNUPLOTFOOTER   "e\n"

static char * print(void * self, char *buf, size_t *len, char * const args[])
{
    CONFIGDESC * config = CONFIG(self); 
    
    static char str[65536];
    int n;

    if (buf == NULL && args != NULL) {
        /* first call, process the arguments */
        config->format = DATASNORT;
        config->total_sig = 0;
        
        for (n = 0; args[n]; n++) {
            if (!strcmp(args[n], "format=gnuplot")) {
                config->format = GNUPLOTFMT;
            }
            if (!strcmp(args[n], "format=hex")) {
                config->format = DATAHEX;
            }
            if (!strcmp(args[n], "format=bin")) {
                config->format = DATABIN;
            }
            if (!strcmp(args[n], "format=snort")) {
                config->format = DATASNORT;
            }
        }
        
        if (config->format == GNUPLOTFMT) {
            *len = sprintf(str, GNUPLOTHDR);
            return str;
        }
        
        *len = 0;

        return str;
    } 

    if (buf == NULL && args == NULL) {
        *len = 0; 
        if (config->format == GNUPLOTFMT) 
            *len = sprintf(str, GNUPLOTFOOTER);
        return str; 
    }

    /* obtain all the signatures that are in the buffer, and print them out */

    int num = *((int *)buf);
    
    config->total_sig += num;
    
    signature * sig;
    int memory_offset = sizeof(int) + sizeof(timestamp_t);
    char * data;
    uint32_t idx;
    *len = 0;
    
    if (config->format == GNUPLOTFMT) {
        timestamp_t ts = *((timestamp_t *)(buf + sizeof(int)));
        *len = sprintf(str, GNUPLOTLINE, TS2SEC(ts), config->total_sig);
        return str; 
    }

    while (num > 0) {
        sig = (signature *)(buf + memory_offset);

        memory_offset += sizeof(signature);
        data = (char *)(buf + memory_offset);
        memory_offset += sig->len;
        
        if (config->format == DATABIN || config->format == DATAHEX) {
            *len += sprintf(str + *len,
            "-----------------------------------------------\nDest \
            Port:%"PRIu16" Length: %"PRIu32" - Prevalence: %"PRIu16" \nPattern:\
            ", sig->dst_port, sig->len, sig->prevalence);
        }
        else if (config->format == DATASNORT) {
            *len += sprintf(str + *len,
            "-----------------------------------------------\n");
            *len += sprintf(str + *len, "alert any any -> any %"PRIu16"\
            (content:\"|", sig->dst_port);
        }
        
        
        for (idx = 0; idx < sig->len; idx++) {

            if (config->format == DATABIN || config->format == DATAHEX ||
            config->format == DATASNORT ) {
                if (config->format == DATAHEX || config->format == DATASNORT)
                    *len += sprintf(str + *len, "%.2x", data[idx]);
                else if (config->format == DATABIN)
                    *len += sprintf(str + *len, "%c", data[idx]);
            }
        }
        
        if (config->format == DATABIN || config->format == DATAHEX) {
            *len += sprintf(str + *len,
            "\n-----------------------------------------------\n");
        }
        else if(config->format == DATASNORT) {
            *len += sprintf(str + *len, "|\";)\n");
        }
        
        num--;
    }

    return str; 
}

MODULE(worm-signature) = 
{
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: sizeof(EFLOWDESC),
    st_recordsize: MAX_STORE,
    init: init,
    check: check,
    hash: hash,
    match: NULL,
    update: update,
    ematch: ematch,
    export: export,
    compare: NULL,
    action: action,
    store: store,
    load: load,
    print: print,
    replay: NULL,
    formats: "gnuplot hex bin snort",
};

