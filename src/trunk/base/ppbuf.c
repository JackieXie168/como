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

struct ppbuf {
    int		woff;		/* offset for the next pkt to capture */
    int		roff;		/* offset for the next pkt to read */
    int		count;		/* number of valid items in pp array */
    int		captured;	/* number of captured pkts since the last
				   call to ppbuf_begin() */
    int		size;		/* number of allocated items in pp array */
    pkt_t **	pp;
    timestamp_t	last_pkt_ts;
};


/**
 * -- ppbuf_new
 * 
 * Allocates a new ppbuf with size many packet pointers.
 */
static ppbuf_t *
ppbuf_new(int size)
{
    ppbuf_t *ppbuf;
    
    ppbuf = safe_calloc(1, sizeof(ppbuf_t));
    ppbuf->size = size;
    ppbuf->pp = safe_calloc(size, sizeof(pkt_t *));
    
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
 */
void
ppbuf_capture(ppbuf_t * ppbuf, pkt_t * pkt)
{
    ppbuf->captured++;
    assert(ppbuf->captured <= ppbuf->size);
    ppbuf->pp[ppbuf->woff] = pkt;
    ppbuf->woff = (ppbuf->woff + 1) % ppbuf->size;
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
	int last;
	last = ppbuf->woff - 1;
	if (last < 0) {
	    last = ppbuf->size - 1;
	}
	/* save the last packet's timestamp */
	ppbuf->last_pkt_ts = (ppbuf->pp[last])->ts;
	
	ppbuf->count += ppbuf->captured;
    }
}


/**
 *-- ppbuf_get_next
 * 
 * Returns the packet pointed by roff, decrements count and advances roff.
 */
static pkt_t *
ppbuf_get_next(ppbuf_t * ppbuf)
{
    pkt_t *pkt;
    ppbuf->count--;
    assert(ppbuf->count >= 0);
    pkt = ppbuf->pp[ppbuf->roff];
    ppbuf->roff = (ppbuf->roff + 1) % ppbuf->size;
    return pkt;
}
