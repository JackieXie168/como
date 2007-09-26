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
 * $Id$
 */

#include "como.h"
#include "comopriv.h"
#include "comotypes.h"
#include "feats.h"

/*
 * -- feat_extr
 *
 * Extract the traffic features for a module from a batch of packets
 *
 */
void
feat_extr(batch_t *batch, char *which, mdl_t *mdl)
{
    static bitmap_t *bitmaps[NUM_BITMAPS]; /* per-batch bitmaps */
    static int initialized = 0;
    uint32_t h0, h1, h2, h3, h4;
    pkt_t **pktptr;
    int i, c, l, j;
    timestamp_t curr_ivl;
    mdl_icapture_t *ic;
    mdl_ls_t *mdl_ls;

    ic = mdl_get_icapture(mdl);
    mdl_ls = &ic->ls;

    /* initialize feature values */
    for (i = 0; i < NUM_FEATS; i++) {
        mdl_ls->fextr.feats[i].value = 0;
    }

    /* initialize bitmaps */
    if (!initialized) {
        initialized = 1;
        for(i = 0; i < NUM_BITMAPS; i++)
            bitmaps[i] = new_bitmap(NUM_KEYS);
    }

    /* initialize module's bitmaps */
    if (!mdl_ls->fextr.bitmaps) {
        mdl_ls->fextr.bitmaps = como_calloc(NUM_BITMAPS, sizeof(bitmap_t *));
        for (i = 0; i < NUM_BITMAPS; i++)
            mdl_ls->fextr.bitmaps[i] = new_bitmap(NUM_KEYS);
    }

    /* initialize hash functions */
    if (!mdl_ls->fextr.hash) {
        mdl_ls->fextr.last_ivl = 0;
        mdl_ls->fextr.hash = como_calloc(NUM_HASH, sizeof(uhash_t *));
        for (i = 0; i < NUM_HASH; i++)
            mdl_ls->fextr.hash[i] = como_malloc(sizeof(uhash_t));
    }

    /* calculate current interval */
    pktptr = batch->pkts0;
    curr_ivl = (*pktptr)->ts - ((*pktptr)->ts % mdl->flush_ivl);

    if (curr_ivl != mdl_ls->fextr.last_ivl) {
        /* new capture interval: clean aggregated bitmaps and
         * generate new hash functions */
        mdl_ls->fextr.last_ivl = curr_ivl;
        for (i = 0; i < NUM_HASH; i++)
            uhash_initialize(mdl_ls->fextr.hash[i]);
        for (i = 0; i < NUM_BITMAPS; i++)
            reset_bitmap(mdl_ls->fextr.bitmaps[i]);
    }

    /* 
     * initialize output to -estimations of aggregated bitmaps,
     * so that later we can estimate the amount of new flows
     * in a batch
     */
    for (i = 0; i < NUM_BITMAPS; i++)
        mdl_ls->fextr.feats[NO_BM_FEATS + i + NUM_BITMAPS].value =
            -estimate_unique_keys(mdl_ls->fextr.bitmaps[i]);

    /* reset per-batch bitmaps */
    for (i = 0; i < NUM_BITMAPS; i++)
        reset_bitmap(bitmaps[i]);

    /* go through the packets in the batch and compute the features */
    for (c = 0, pktptr = batch->pkts0, l = MIN(batch->pkts0_len, batch->count);
	 c < batch->count;
	 pktptr = batch->pkts1, l = batch->pkts1_len)
    {
	for (i = 0; i < l; i++, pktptr++, c++, which++) {
            pkt_t *pkt = *pktptr;

            if (*which == 0)
                continue; /* no interest in this packet */

            mdl_ls->fextr.feats[0].value++;
            mdl_ls->fextr.feats[1].value += pkt->caplen;

            if (!isIP)
                continue; /* no need to calculate the remaining features */

            /* calculate hashes for src_ip, dst_ip and proto */
            h0 = uhash(mdl_ls->fextr.hash[0], (uint8_t *)&IP(src_ip), 4,
                       UHASH_NEW);
            h1 = uhash(mdl_ls->fextr.hash[1], (uint8_t *)&IP(dst_ip), 4,
                       UHASH_NEW);
            h2 = uhash(mdl_ls->fextr.hash[2], (uint8_t *)&IP(proto), 1,
                       UHASH_NEW);

            set_bit(bitmaps[0],      h0); /* src_ip */
            set_bit(bitmaps[1], h1     ); /* dst_ip */
            set_bit(bitmaps[2], h1 ^ h0); /* src_ip + dst_ip */

            /* calculate hashes for src and dst network */
            h3 = uhash(mdl_ls->fextr.hash[0], (uint8_t *)&IP(src_ip), 3,
                       UHASH_NEW);
            h4 = uhash(mdl_ls->fextr.hash[1], (uint8_t *)&IP(dst_ip), 3,
                       UHASH_NEW);

            set_bit(bitmaps[ 9], h3); /* src_net */
            set_bit(bitmaps[10], h4); /* dst_net */
            set_bit(bitmaps[11], h3 ^ h4); /* src_net + dst_net */
            set_bit(bitmaps[12], (int)IP(proto));

            switch(IP(proto)) {
                case IPPROTO_TCP:
                    h3 = uhash(mdl_ls->fextr.hash[3],
                               (uint8_t *)&TCP(src_port), 2, UHASH_NEW);
                    h4 = uhash(mdl_ls->fextr.hash[4],
                               (uint8_t *)&TCP(dst_port), 2, UHASH_NEW);
                    break;
                case IPPROTO_UDP:
                    h3 = uhash(mdl_ls->fextr.hash[3],
                               (uint8_t *)&UDP(src_port), 2, UHASH_NEW);
                    h4 = uhash(mdl_ls->fextr.hash[4],
                               (uint8_t *)&UDP(dst_port), 2, UHASH_NEW);
                    break;
                default:
                    continue; /* not TCP nor UDP, next packet */            
            }

            set_bit(bitmaps[ 3], h2 ^ h3); /* proto + src_port */
            set_bit(bitmaps[ 4], h2 ^ h4); /* proto + dst_port */
            set_bit(bitmaps[ 5], h2 ^ h3 ^ h0); /* proto + src_port + src_ip */
            set_bit(bitmaps[ 6], h2 ^ h4 ^ h1); /* proto + dst_port + dst_ip */
            set_bit(bitmaps[ 7], h2 ^ h3 ^ h4); /* proto + src_port + dst_port */
            set_bit(bitmaps[ 8], h0 ^ h1 ^ h2 ^ h3 ^ h4); /* 5-tuple */
        }
    }

    /* Update aggregated bitmaps */
    for (j = 0; j < NUM_BITMAPS; j++)
        or_bitmaps(mdl_ls->fextr.bitmaps[j], bitmaps[j]);

#if NUM_FEATS != NO_BM_FEATS + NUM_BITMAPS * 4
#error NUM_FEATS inconsistent with NUM_BITMAPS, need to fix that
#endif

    /* Update module's features */
    for (j = 0; j < NUM_BITMAPS; j++) {
        mdl_ls->fextr.feats[NO_BM_FEATS + j].value =
            estimate_unique_keys(bitmaps[j]); /* unique */
        mdl_ls->fextr.feats[NO_BM_FEATS + j + NUM_BITMAPS].value +=
            estimate_unique_keys(mdl_ls->fextr.bitmaps[j]); /* new */
        /* batch repeated */
        mdl_ls->fextr.feats[NO_BM_FEATS + j + 2 * NUM_BITMAPS].value =
            batch->count - mdl_ls->fextr.feats[NO_BM_FEATS + j].value;
        /* aggregated repeated */
        mdl_ls->fextr.feats[NO_BM_FEATS + j + 3 * NUM_BITMAPS].value =
            batch->count -
            mdl_ls->fextr.feats[NO_BM_FEATS + j + NUM_BITMAPS].value;
    }
}
