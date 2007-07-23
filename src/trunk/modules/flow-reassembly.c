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
 * $Id: tuple.c 976 2006-10-30 19:01:52Z xxxx $
 */

/*
 * TCP Flow Reassembly Module.
 *
 * Author: Derek Hossack Lopez (UPC, Barcelona)
 *
 * This module reassembles all TCP flows contained in the incoming traffic. 
 * It checks for the initial SYN to get the initial sequence number, then 
 * reassembles all ordered packets or buffers the unordered. Finally, when 
 * the TCP flow finishes, it outputs the reassembled TCP flow.
 */

#include <stdio.h>
#include <time.h>
#include "module.h"
#include "hash.h"
#include "printpkt.h"       
        
#define FLOWDESC    struct _reass_cap
#define EFLOWDESC   struct _reass_exp
#define CONFIGDESC  struct _reass_conf

/* posisble status for flows */
enum flow_status {
    IN_PROCESS,     /* currently being captured, action does nothing */
    COMPLETE,       /* all blocks in correct order, and FIN/RST has arrived, 
                       action stores */
    COMPLETE_BUFFER /* FIN/RST has arrived, but blocks are all in the buffer 
                       (so SYN missing). action sorts blocks and then stores */
};

/* 
 * Maximum size of flow that we can store (when this limit is reached, the next
 * part of the flow will be captured and reassembled in a separate record
 */
#define MAX_FLOW_SIZE 100000

/* Maximum size of the packet header (COMO + ETHERNET + IP + TCP) */
#define MAX_HDR 186 /* (52+14+60+60) */

/* print formats */
#define PRETTYFMT   0
#define PCAPFMT     1

/* struct to save each block of data that is already saved in order */
struct _reass_block
{
    /* pointer to previous and next block in the ordered list of blocks */
    struct _reass_block * next; 
    struct _reass_block * prev;
    
    /* actual payload */
    unsigned char * data;
    
    /* length of the payload */
    uint32_t len;
    
    /* 
     * sequence number of this block, also the key for the hash table when the
     * block is out of order
     */
    uint32_t seq;
    
    /* FIN and RST flags, to know if the flow has ended */
    uint16_t fin;
    uint16_t rst;
};
        
typedef struct _reass_block block_t;

FLOWDESC {
    /* full packet */
    int len; 
    char buf[2048]; 
};

EFLOWDESC {
    /* 
     * timestamp of this TCP flow - if it timesout, delete the whole flow / or
     * build what has been captured??
     */
    timestamp_t ts;
    
    /* info of this TCP flow */
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t dst_port;
    uint16_t src_port;
    
    /* expected and initial sequence numbers */
    uint32_t next_seq;
    uint32_t base_seq;
    
    /* 
     * hash table with packets out of order, waiting for the missing sequence
     * numbers
     */
    hash_t *htable;
    
    /* length of buffered data */
    uint32_t buffer_len;
    
    /*
     * current reassembled flow (length should always be next_seq - base_seq ?)
     */
    block_t * data;
    uint32_t len;
    
    /*
     * CoMo header + l2, l3, l4 headers of the first packet of the flow. Will
     * be modified later to store a CoMo pkt with the reassembled data.
     */
    char comohdr[MAX_HDR + 1];  /* CoMo + ETH + IP + TCP */
    
    int full_flow;
    int status;
};

CONFIGDESC {
    timestamp_t flow_timeout;   /* timeout to expire an idle flow */
    uint32_t wait_fin;          /* time to wait for TCP flow finalization after
                                   detecting FIN / RST */
    int format;
};


/* block_t constructor */
static void
init_block(block_t *block)
{
    block->next = NULL;
    block->prev = NULL;
    
    block->data = NULL;
    block->len = 0;

    block->seq = 0;
}

static void 
buffer_block(EFLOWDESC *ex, block_t *block)
{
    /* just insert in the hash */
    hash_insert_ulong(ex->htable, block->seq, block);
    ex->buffer_len += block->len;
}

static int
unbuffer_block(EFLOWDESC *ex, uint32_t seq, uint32_t len)
{
    /* just remove from the hash */
    int ret;
    
    ret = hash_remove_ulong(ex->htable, seq);
    ex->buffer_len -= len;
    
    return ret;
}

static void
add_block(EFLOWDESC *ex, block_t *block, void *mdl)
{
    /* aux variables necesary in case there is overlapping */
    unsigned char * aux_data;   /* previous data (with overlapping) */
    uint32_t aux_old_len;       /* size of old data */

    CONFIGDESC *config = CONFIG(mdl);
    
    /*
     * at this point, block->next and block->prev are both NULL (should be)
     * ex->data is a circular doubled-linked list. always add next block at 
     * the end. to get the reassembled flow, just follow the list in order
     */
    if (ex->data == NULL) {
        /* special case: first element, just add element and point both 
         * pointers to itself
         */
        ex->data = block;
        block->next = block;
        block->prev = block;
    } else {
        /* 
         * first check if the blocks sequence number is the expected, or less 
         * than the expected (overlapped packet)
         */
        if (block->seq < ex->next_seq) {
            /* if so, trim the data to only the necessary */
            if (block->seq + block->len <= ex->next_seq)
                return; /* its old data, do nothing with it */
            else {
                /* modify block so its the next expected block */
                aux_data = block->data;
                aux_old_len = ex->next_seq - block->seq; /* size of OLD data */
                
                block->len -=  aux_old_len;
                block->seq = ex->next_seq;
                
                block->data = (unsigned char *)mem_mdl_malloc(mdl, block->len);
                memcpy(block->data, aux_data+aux_old_len, block->len);
                
                mem_mdl_free(mdl, aux_data);
            }
        }
        
        /* check if it was the last block */
        if (block->fin || block->rst) {
            ex->status = COMPLETE;
            ex->next_seq++;
        }
        
        /* add block to the data, only if len > 0 */
        if (block->len > 0) {
            /* normal case: add block at the end (the end = ex->data->prev) */
            block->next = ex->data;
            block->prev = ex->data->prev;
            
            ex->data->prev->next = block;
            ex->data->prev = block;
        } else 
            /* free block info (no data to free, should be null) */
            mem_mdl_free(mdl, block);
    }
    
    /* 
     * update the information in export entry - next sequence number expected, 
     * and total data length
     */
    if (block != NULL) {
        ex->next_seq += block->len;
        ex->len += block->len;
    }
}

static void
check_buffer(EFLOWDESC *ex, void *mdl)
{
    /* 
     * lookup for a item in the hash table with sequence number = ex->next_seq.
     * if found, repeat until not found
     */
    block_t * block;
    hash_iter_t iterator;
    
    block = (block_t *)hash_lookup_ulong(ex->htable, ex->next_seq);
    
    while (block != NULL) {
        if (block->seq == ex->next_seq) {   /* must ALWAYS be true :) */
            add_block(ex, block, mdl);
            unbuffer_block(ex, block->seq, block->len);
        }
        block = (block_t *)hash_lookup_ulong(ex->htable, ex->next_seq);
    }
    
    /* 
     * in case there are overlapped packets, iterate on the hash table to look 
     * for sequence numbers < ex->next_seq
     */
    hash_iter_init(ex->htable, &iterator);
    
    while (hash_iter_next (&iterator)) {
        block = (block_t *)hash_iter_get_value(&iterator);
        
        if (block->seq <= ex->next_seq) {
            add_block(ex, block, mdl);
            
            /*
             * remove from hash with current key value, because the sequence 
             * number could have changed (in case of overlap with valid data), 
             * so no longer would coincide with the hash key
             */
            unbuffer_block(ex, hash_iter_get_ulong_key(&iterator), block->len);
            
            /* start again */
            hash_iter_init(ex->htable, &iterator);
        }
    }
}

static void 
sort_buffer(EFLOWDESC *ex, void *mdl)
{
    /* 
     * this only happens when FIN / RST arrives for a flow that was already 
     * established when sniffing started. so SYN was not captured (initial
     * sequence number). in this case, just sort what we have captured.
     */
    hash_iter_t iterator;
    block_t * block, * min_block;
    
    min_block = NULL;
    hash_iter_init(ex->htable, &iterator);
    
    while (hash_iter_next(&iterator)) {
        block = (block_t *)hash_iter_get_value (&iterator);
        
        if (min_block == NULL || block->seq < min_block->seq)
            min_block = block;
    }
    
    /* 
     * min_block is now the 'first' block of all. so set it as the first block,
     * then call check_buffer to put everything in place.
     */
    if (min_block != NULL) {
        ex->base_seq = min_block->seq;
        ex->next_seq = min_block->seq;
        
        add_block(ex, min_block, mdl);
        unbuffer_block(ex, min_block->seq, min_block->len);
        
        check_buffer(ex, mdl);
    }
    
    /* now all possible blocks to be ordered (if any) should be in order */
}

/* hash function for the hash table containing out of order packets */
static uint
hash_function(const void *key)
{
    return (uint)((uint32_t)key);
}

static int
key_cmp_function(const void *key1, const void *key2)
{
    if ((uint32_t)key1 == (uint32_t)key2)
        return 0;
    
    return 1;
}

static void
finalize_flow(EFLOWDESC *ex, void *mdl)
{
    if ((ex->next_seq == 0) &&  (ex->base_seq == 0))
        sort_buffer(ex, mdl); /* didnt receive SYN, so sort the buffer */
    else {
        /* 
         * did receive SYN, so just reassemble as many packets as possible in 
         * the buffer
         */
        check_buffer(ex, mdl);
    }
}

static timestamp_t
init(void *self, char *args[])
{
    CONFIGDESC *config;
    metadesc_t *inmd, *outmd;
    pkt_t * pkt;
    int i;
    
    inmd = metadesc_define_in(self, 0);
    
    pkt = metadesc_tpl_add(inmd, "any:any:~ip:~tcp");
    N16(TCP(src_port)) = 0xffff;
    N16(TCP(dst_port)) = 0xffff;
    IP(proto) = 0xff;
    N16(IP(len)) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    
    outmd = metadesc_define_out(self, 0);
    
    pkt = metadesc_tpl_add(outmd, "any:any:any:any");
    
    config = (CONFIGDESC *)mem_mdl_malloc(self, sizeof(CONFIGDESC));

    /* default values for config parameters */
    config->flow_timeout = TIME2TS(60, 0);
    config->wait_fin = 60;
    
    for (i = 0; args && args[i]; i++) {
        if (strstr(args[i], "flow_timeout=")) {
            char * f_t = index(args[i], '=') + 1; 
            config->flow_timeout = TIME2TS(atoi(f_t), 0);
        }
        if (strstr(args[i], "wait_fin=")) {
            char * w_f = index(args[i], '=') + 1; 
            config->wait_fin = atoi(w_f);
        }
    }

    CONFIG(self) = config;
    
    return TIME2TS(1,0);
}

static int
check(void *self, pkt_t *pkt)
{
    CONFIGDESC *config = CONFIG(self);

    if (TCP(syn) == 0) {
        if (H16(IP(len)) == (IP(ihl)*4 + TCP(hlen)*4) || 
            pkt->caplen == pkt->l7ofs) {
            /* captured length is equal to the data offset, so no data. */
            return 0;
        }
    }
    
    return 1;
}

static uint32_t
hash(void *self, pkt_t *pkt)
{
    if (pkt->l3type != ETHERTYPE_IP) 
        return 0; 

    /* must be the same source ip, dest ip, source port, dest port */
    return (H32(IP(src_ip)) ^ H32(IP(dst_ip)) ^ (H16(TCP(dst_port)) << 3) ^ 
           (H16(TCP(dst_port)) << 3));
}

static int
update(void *self, pkt_t *pkt, void *fh, int isnew)
{
    CONFIGDESC *config = CONFIG(self);
        
    FLOWDESC *x = F(fh);
    x->len = sizeof(pkt_t) + pkt->caplen;

    memcpy(x->buf, pkt, sizeof(pkt_t));
    memcpy(x->buf + sizeof(pkt_t), pkt->payload, pkt->caplen);
    ((pkt_t *) x->buf)->payload = x->buf + sizeof(pkt_t);
    
    return 1;   /* records are always full */
}

static int
ematch(void *self, void *efh, void *fh)
{
    pkt_t* pkt;
    int ret = 0;
    FLOWDESC *x = F(fh);
    EFLOWDESC *ex = EF(efh);

    pkt = (pkt_t *)x->buf;
    
    if (ex->full_flow == 0) { /* if its full, go to next export record */
        ret = ((ex->dst_port == H16(TCP(dst_port))) && 
               (ex->src_port == H16(TCP(src_port))) &&
               (ex->src_ip == H32(IP(src_ip))) && 
               (ex->dst_ip == H32(IP(dst_ip))));
    }

    return ret;
}

static int
export(void *self, void *efh, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);
    EFLOWDESC *ex = EF(efh);
    pkt_t* pkt;
    pkt_t* pktaux;
    
    CONFIGDESC *config = CONFIG(self);
    
    block_t * block;
    
    module_t * mdl = self;
    pkt = (pkt_t *)x->buf;
    
    if (isnew) {
        ex->full_flow = 0;
        
        ex->next_seq = 0;
        ex->base_seq = 0;
        
        ex->src_ip = H32(IP(src_ip));
        ex->dst_ip = H32(IP(dst_ip));
        ex->src_port = H16(TCP(src_port));
        ex->dst_port = H16(TCP(dst_port));
        
        /* copy como header */
        bzero(ex->comohdr, MAX_HDR+1);
        memcpy(ex->comohdr, pkt, sizeof(pkt_t));
        /* copy payload headers */
        memcpy(ex->comohdr + sizeof(pkt_t), pkt->payload, pkt->l7ofs);

        /* point payload pointer to correct place */
        ((pkt_t *) ex->comohdr)->payload = ex->comohdr + sizeof(pkt_t);
        /* captured length is only the size of the headers */
        ((pkt_t *) ex->comohdr)->caplen = pkt->l7ofs;
        ((pkt_t *) ex->comohdr)->len = pkt->l7ofs;
        
        ex->data = NULL;
        ex->len = 0;
        
        ex->htable = hash_new(&(mdl->alc), HASHKEYS_ULONG, hash_function, 
                              key_cmp_function);
        ex->buffer_len = 0;

        ex->status = IN_PROCESS;
    }
    
    ex->ts = COMO(ts);
    
    if ((ex->next_seq == 0) &&  (ex->base_seq == 0) && (TCP(syn) == 1)) { 
        /* SYN has arrived, can start assembling */
        
        /* 
         * syn is always in order as it's the first packet.
         * the next seq number after SYN is always ISN + 1 -> i'm using 
         * relative numbers
         */
        ex->base_seq = H32(TCP(seq));
        ex->next_seq = 1;  
       
        /* 
         * check the list of out-of-order in case something arrived before 
         * the SYN
         */
        check_buffer(ex, self);
    } 
    else {
        if (ex->full_flow == 0) { 
            /*
             * other cases: create the block, then decide what to do with it 
             * (assemble it or buffer it)
             */
            block = (block_t *)mem_mdl_malloc(self, sizeof(block_t));
            init_block(block);
            
            /* 
             * length of real data is IP:total_length - IP:header_size - 
             * TCP:header_size
             */
            block->len = H16(IP(len)) - 4*(IP(ihl)) - 4*(TCP(hlen));
            
            if (block->len > 0) {
                /* reserve space and memcpy the data */
                block->data = (unsigned char *)mem_mdl_malloc(self, block->len);
                memcpy(block->data, (pkt->payload + pkt->l7ofs), block->len); 
            }
                
            /* set the TCP sequence number and flags */
            block->seq = H32(TCP(seq)) - ex->base_seq;
            block->fin = TCP(fin);
            block->rst = TCP(rst);
                
            if ((ex->next_seq == 0) && (ex->base_seq == 0)) {
                /* pkt has arrived before syn */
                if (block->fin || block->rst) 
                    ex->status = COMPLETE_BUFFER;
                
                /* add to the buffer */
                if(block->len > 0)
                    buffer_block(ex, block);
                else
                    mem_mdl_free(self, block);
            }
            else { 
                /* 
                 * not waiting for SYN - check if packet is the next one in the
                 * flow, if not just add to buffer
                 */
                if(block->seq <= ex->next_seq) {
                    add_block(ex, block, mdl);
                   /* 
                    * check the list of out-of-order in case something arrived 
                    * before the SYN
                    */
                    check_buffer(ex, self);
                } else
                    buffer_block(ex, block);
            }
        }
        
        if ((ex->len + ex->buffer_len + MAX_HDR + 2000) >= MAX_FLOW_SIZE) {
            ex->full_flow = 1;
            return 1;
        }
    }

    return 0;
}

static int
action(void *self, void *efh, timestamp_t ivl, timestamp_t current_time, 
       int count)
{
    EFLOWDESC *ex = EF(efh);
    CONFIGDESC *config = CONFIG(self);

    if (efh == NULL) 
        return ACT_GO;
    else {
        switch(ex->status) {
            case IN_PROCESS:
                if ((TS2SEC(current_time) - TS2SEC(ex->ts) >
                     TS2SEC(config->flow_timeout)) || ex->full_flow) {
                    /*
                     * flow has expired (no new packets for more than 
                     * flow_timeout) or 
                     * flow is too big to be stored - this part will be stored 
                     * now and next part will be put in a separate export
                     * record
                     */
                    finalize_flow(ex, self);
                    check_buffer(ex, self);
                    return ACT_STORE | ACT_DISCARD;
                }
                return 0;
                
            case COMPLETE:
                if (current_time - ex->ts < config->wait_fin)
                    return 0;
                else
                    return ACT_STORE | ACT_DISCARD;
                
           case COMPLETE_BUFFER:
                sort_buffer(ex, self);
                return ACT_STORE | ACT_DISCARD;
                
            default:
                return 0;
        }
    }
}

static ssize_t
store(void * self, void *efh, char *buf)
{
    EFLOWDESC *ex = EF(efh);
    pkt_t * pkt;
    uint32_t size;
        
    CONFIGDESC *config = CONFIG(self);
    
    uint32_t maxsize = MAX_FLOW_SIZE - sizeof(pkt_t) - MAX_HDR;
    
    /* 
     * save space for the CoMo header and the reassembled data.
     * size > MAX_FLOW_SIZE is controlled in ematch/export
     */
    size = sizeof(pkt_t) + ((pkt_t *) ex->comohdr)->caplen + ex->len; 
    
    pkt = (pkt_t *)ex->comohdr;
    
    memcpy(buf, ex->comohdr, sizeof(pkt_t) + ((pkt_t *) ex->comohdr)->caplen);
    
    /* loop to copy all the blocks of this flow */
    block_t * block, * remove_block;
    uint32_t current_total_len = 0;
    
    if (ex->data != NULL) {
        block = ex->data;
        
        do {
            memcpy(buf + sizeof(pkt_t) + ((pkt_t *) ex->comohdr)->caplen + 
                   current_total_len, block->data, block->len);
            current_total_len += block->len;
            /* 
             * Once it's already stored, free the memory reserved for the 
             * reassembled data. Check if data is empty first!
             */
            remove_block = block;
            block = block->next;
            
            if (remove_block != ex->data) {
                /* 
                 * free all blocks except the first one (to check when we have
                 * finished the loop)
                 */
                mem_mdl_free(self, remove_block->data);
                mem_mdl_free(self, remove_block);
            }
        } while (block != ex->data);
        
        /* now we can free the first block */
        if (ex->data->data != NULL) 
            mem_mdl_free(self, ex->data->data);

        mem_mdl_free(self, ex->data);
    }
    
    /* payload pointer */
    ((pkt_t *)buf)->payload = buf + sizeof(pkt_t);
    
    pkt = (pkt_t *)buf;
    
    COMO(ts) = ex->ts;      /* latest timestamp */
    COMO(len) += ex->len;   /* length was only the headers - add the data */
    COMO(caplen) += ex->len;
    
    /* 
     * change IP header accordingly.
     * ip datagram total length = total length - como header - ethernet header
     */
    N16(IP(len)) = htons(COMO(caplen) - 14);     
    
    /* TCP header */
    TCP(syn) = htons(0);    
    
    COMO(ts) = HTONLL(COMO(ts)); 
    COMO(len) = htonl(COMO(len)); 
    COMO(caplen) = htonl(COMO(caplen)); 
    COMO(type) = htons(COMO(type));
    COMO(dropped) = htons(COMO(dropped));
    COMO(l2type) = htons(COMO(l2type)); 
    COMO(l3type) = htons(COMO(l3type)); 
    COMO(l4type) = htons(COMO(l4type)); 
    COMO(l2ofs) = htons(COMO(l2ofs)); 
    COMO(l3ofs) = htons(COMO(l3ofs)); 
    COMO(l4ofs) = htons(COMO(l4ofs));
    COMO(l7ofs) = htons(COMO(l7ofs));  
    
    return size;
}

static size_t
load(void * self, char * buf, size_t len, timestamp_t * ts)
{
    pkt_t * pkt; 
    
    if (len < sizeof(pkt_t)) {
        *ts = 0;
        return 0;
    }
    pkt = (pkt_t *) buf; 
    
    *ts = NTOHLL(COMO(ts));

    return (sizeof(pkt_t) + ntohl(COMO(caplen))); 
}

static char * 
print(void * self, char *buf, size_t *len, char * const args[])
{
    CONFIGDESC * config = CONFIG(self); 
    static char str[65536];
    pkt_t p, pktbuf, *pkt; 
    int n; 
    
    if (buf == NULL && args != NULL) { 
        /* first call, process the arguments */
        for (n = 0; args[n]; n++) {
            if (!strcmp(args[n], "format=pcap")) {
                *len = print_pcap_file_header(str);
                config->format = PCAPFMT;
                return str; 
            }
        }
        *len = 0;
        config->format = PRETTYFMT;
        return str;
    } 

    if (buf == NULL && args == NULL) { 
        /* last call, nothing to do */
        *len = 0; 
        return str; 
    } 

    /* copy the packet CoMo header, converting 
     * the fields in host-byte order 
     */
    bcopy(buf, &pktbuf, sizeof(pkt_t));
    pkt = &pktbuf;
    p.ts = NTOHLL(COMO(ts)); 
    p.len = ntohl(COMO(len)); 
    p.caplen = ntohl(COMO(caplen)); 
    p.type = ntohl(COMO(type));
    p.l2type = ntohs(COMO(l2type)); 
    p.l3type = ntohs(COMO(l3type)); 
    p.l4type = ntohs(COMO(l4type));
    p.l2ofs = ntohs(COMO(l2ofs)); 
    p.l3ofs = ntohs(COMO(l3ofs)); 
    p.l4ofs = ntohs(COMO(l4ofs));
    p.l7ofs = ntohs(COMO(l7ofs));  
    p.payload = buf + sizeof(pkt_t);

    /* now we are ready to process this packet */
    pkt = (pkt_t *) &p; 

    if (config->format == PCAPFMT)
        *len = print_pkt_pcap(pkt, str);
    else {
        *len = print_pkt_pretty(pkt, str, PRINTPKT_L2 | PRINTPKT_L3);
        *len += sprintf(str + *len, "\n");
    }
    return str; 
}

static int 
replay(void * self, char *buf, char *out, size_t * len, int left)
{
    pkt_t * pkt; 
    size_t need; 

    if (buf == NULL) {
        /* this module does not buffer any records */
        *len = 0;
        return 0;
    }

    pkt = (pkt_t *) buf; 
    need = ntohl(COMO(caplen)) + sizeof(pkt_t);
    if (*len < need) 
        return -1; 

    bcopy(buf, out, need); 
    pkt = (pkt_t *) out;

    /* Convert the header data into host byte order */
#ifdef BUILD_FOR_ARM
    COMOX(ts, NTOHLL(COMO(ts))); 
    COMOX(len, ntohl(COMO(len))); 
    COMOX(caplen, ntohl(COMO(caplen))); 
    COMOX(type, ntohs(COMO(type)));
    COMOX(dropped, ntohs(COMO(dropped)));
    COMOX(l2type, ntohs(COMO(l2type))); 
    COMOX(l3type, ntohs(COMO(l3type))); 
    COMOX(l4type, ntohs(COMO(l4type))); 
    COMOX(l2ofs, ntohs(COMO(l2ofs))); 
    COMOX(l3ofs, ntohs(COMO(l3ofs))); 
    COMOX(l4ofs, ntohs(COMO(l4ofs))); 
    COMOX(l7ofs, ntohs(COMO(l7ofs))); 
#else
    COMO(ts) = NTOHLL(COMO(ts)); 
    COMO(len) = ntohl(COMO(len)); 
    COMO(caplen) = ntohl(COMO(caplen)); 
    COMO(type) = ntohs(COMO(type));
    COMO(dropped) = ntohs(COMO(dropped));
    COMO(l2type) = ntohs(COMO(l2type)); 
    COMO(l3type) = ntohs(COMO(l3type)); 
    COMO(l4type) = ntohs(COMO(l4type)); 
    COMO(l2ofs) = ntohs(COMO(l2ofs)); 
    COMO(l3ofs) = ntohs(COMO(l3ofs)); 
    COMO(l4ofs) = ntohs(COMO(l4ofs)); 
    COMO(l7ofs) = ntohs(COMO(l7ofs)); 
#endif

    COMO(payload) = out + sizeof(pkt_t);
    *len = need;
    return 0;   
}

MODULE(flow-reassembly) = 
{
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: sizeof(EFLOWDESC),
    st_recordsize: MAX_FLOW_SIZE,
    init: init,
    check: NULL,
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
    replay: replay
};

