/*
 * Copyright (c) 2004 Intel Corporation
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

#ifndef _COMO_SNIFFERS_H
#define _COMO_SNIFFERS_H

#include "stdpkt.h"

/* sniffer-related typedefs */
typedef struct _source          source_t;
typedef struct _sniffer 	sniffer_t;

/*
 * A sniffer is in charge of delivering packets to CoMo from a given
 * input source. Each sniffer must implement three callbacks:
 *
 * start()	to start the sniffer and do whatever is needed to
 *		necessary to start operations, e.g. open files etc.
 *		The first argument is the file or device name,
 *		the rest is a pointer to an opaque argument with
 *		extra configuration info XXX may go away in the future.
 *		The following return values are
 *		It is supposed to return -1 on error, otherwise
 *		a file descriptor on which we can select().
 *		The fd is in turn passed down, so it could be used
 *		as an object id for sniffers that have local information.
 *		XXX TODO: provide a fake fd which will always
 *		return as ready for sniffers that cannot return
 *		a valid descriptor.
 *
 * next()	Fill the structure passed as argument with a copy of
 *		the next packet(s) and associated metadata.
 *		Return -1 on error, the number of packets otherwise.
 *		XXX TODO: implement checks on the number of packets returned;
 *		currently there are no checks and we hope that the caller
 *		gives us a block sufficiently large to avoid overflows.
 *		
 * stop()	Terminate the activity of the sniffer.
 *		This usually involves closing the descriptor, but
 *		maybe also freeing memory etc.
 */

/* sniffer callbacks */
typedef int (start_fn)(source_t *src);
typedef int (next_fn)(source_t *src, pkt_t *pkts, int max_no); 
typedef void (stop_fn)(source_t *src);

struct _sniffer {
    char const * name;
    start_fn * sniffer_start;   /* start the sniffer */
    next_fn * sniffer_next;     /* get next packet */
    stop_fn * sniffer_stop;     /* stop the sniffer */
};

/*
 * Description of the active data sources (i.e., packet information
 * coming sniffers). This structure is populated at config time and
 * used to keep state between successive calls of the sniffer
 * callbacks.
 */
struct _source {
    struct _source *next;
    sniffer_t *cb;              /* callbacks */
    int fd;                     /* file descriptor we are using */
    char *device;		/* device name */
    char *args;			/* optional arguments */
    pktdesc_t *output;		/* packet stream description */
    void *ptr;			/* sniffer-dependent information */ 
    uint32_t flags;		/* sniffer flags */
};

#define	SNIFF_SELECT	0x0001	/* device must be polled */
#define	SNIFF_POLL	0x0002	/* device must be polled */
#define	SNIFF_FILE	0x0004	/* device reads from file */
#define SNIFF_INACTIVE	0x0008	/* sniffer is inactive */


/* some functions and variables */
void updateofs(pkt_t * pkt, int type);

 
#endif /* _COMO_SNIFFERS_H */
