/* 
 * Copyright (c) 2006, Intel Corporation 
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

#ifndef CAPTURE_SOURCE
#error "ppbuf.c must be included by capture.c"
#endif

#include "ppbuf_list.h"

struct ppbuf {
    int		woff;		/* offset for the next pkt to capture */
    int		roff;		/* offset for the next pkt to read */
    pkt_t *	last_rpkt;	/* last pkt pointed by roff */
    int		count;		/* number of valid items in pp array */
    int		captured;	/* number of captured pkts since the last
				   call to ppbuf_begin() */
    int		size;		/* number of allocated items in pp array */
    pkt_t **	pp;
    timestamp_t	last_pkt_ts;
    timestamp_t	first_pkt_ts;
    int		id;		/* sniffer id */
    ppbuf_list_entry_t	next;
};


/**
 * -- ppbuf_new
 * 
 * Allocates a new ppbuf with size many packet pointers.
 */
static ppbuf_t *
ppbuf_new(int size, int id)
{
    ppbuf_t *ppbuf;
    
    ppbuf = como_new0(ppbuf_t);
    ppbuf->size = size;
    ppbuf->pp = como_calloc(size, sizeof(pkt_t *));
    ppbuf->id = id;
    
    return ppbuf;
}


/**
 * -- ppbuf_destroy
 * 
 * Destroys a ppbuf.
 */
static void
ppbuf_destroy(ppbuf_t * ppbuf)
{
    if (ppbuf) {
	free(ppbuf->pp);
	free(ppbuf);
    }
}


/**
 * -- ppbuf_capture
 * 
 * Captures a pkt into the ppbuf.
 * This is the only exported function that will be called by sniffers to
 * link a captured packet into the ppbuf.
 * Returns 1 if the packet was inserted in the buffer, 0 if it has been
 * dropped.
 */
int
ppbuf_capture(ppbuf_t * ppbuf, pkt_t * pkt, sniffer_t * sniff)
{
    if (pkt->ts == 0) {
	warn("dropping pkt no. %d: invalid timestamp\n",
	       ppbuf->woff);
	return 0;
    }

    if (pkt->ts < sniff->last_ts) {
        timestamp_t skew = sniff->last_ts - pkt->ts;

        if (skew > sniff->max_ts_skew) {
            sniff->max_ts_skew = skew;
            warn("sniffer %s (%s): timestamps not increasing!\n",
                    sniff->cb->name, sniff->device);
            warn("max skew so far is %u.%06u seconds\n",
                    TS2SEC(skew), TS2USEC(skew));
        }
    }
    sniff->last_ts = pkt->ts;

    ppbuf->captured++;
    assert(ppbuf->captured <= ppbuf->size);

    ppbuf->last_pkt_ts = pkt->ts;
    if (ppbuf->first_pkt_ts == 0)
        ppbuf->first_pkt_ts = pkt->ts;

    pkt->input = ppbuf->id;
    
    ppbuf->pp[ppbuf->woff] = pkt;
    ppbuf->woff = (ppbuf->woff + 1) % ppbuf->size;

    return 1;
}


/**
 * -- ppbuf_get_count
 * 
 * Returns number of valid item in the ppbuf.
 */
int
ppbuf_get_count(ppbuf_t * ppbuf)
{
    return ppbuf->count;
}


/**
 * -- ppbuf_begin
 * 
 * Initializes the ppbuf for capture mode. The roff field is moved to the first
 * valid entry in pp. The captured field is reset.
 * Returns the number of free items in the pp array.
 */
static int
ppbuf_begin(ppbuf_t * ppbuf)
{
    ppbuf->roff = ppbuf->woff - ppbuf->count;
    if (ppbuf->roff < 0) {
	ppbuf->roff += ppbuf->size;
    }
    ppbuf->captured = 0;
    return ppbuf->size - ppbuf->count;
}


/**
 * -- ppbuf_end
 * 
 * Completes the initialization of the ppbuf. If at least a packet has been
 * captured the field last_pkt_ts is updated with the timestamp of the last
 * captured packet and the field captured is added to the field count.
 */
static void
ppbuf_end(ppbuf_t * ppbuf)
{
    if (ppbuf->captured) {
	ppbuf->count += ppbuf->captured;
    }
}


/**
 *-- ppbuf_get
 * 
 * Returns the packet at the offset roff
 */
static pkt_t *
ppbuf_get(ppbuf_t * ppbuf)
{
    ppbuf->last_rpkt = ppbuf->pp[ppbuf->roff];
    return ppbuf->last_rpkt;
}


/**
 *-- ppbuf_next
 * 
 * Decrements count and advances roff.
 */
static void
ppbuf_next(ppbuf_t * ppbuf)
{
    ppbuf->count--;
    assert(ppbuf->count >= 0);
    ppbuf->roff = (ppbuf->roff + 1) % ppbuf->size;
}


#ifdef DEBUG_PPBUF
int
ppbuf_is_ordered(ppbuf_t * ppbuf)
{
    int i, roff;
    timestamp_t ts = 0;

    if (ppbuf->count == 0)
	return 1;

    roff = ppbuf->roff;
    for (i = 0; i < ppbuf->count; i++) {
	pkt_t *pkt;
	pkt = ppbuf->pp[roff];
	if (pkt->ts < ts)
	    return 0;
	ts = pkt->ts;
	roff = (roff + 1) % ppbuf->size;
    }
    
    return 1;
}
#endif
