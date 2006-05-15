/*
 * Copyright (c) 2004-2006, Intel Corporation
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


#ifndef _COMO_SNIFFERS_H
#define _COMO_SNIFFERS_H

#include "comotypes.h"

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
typedef int (next_fn)(source_t *src, pkt_t *pkts, int max_no,
		      timestamp_t max_ivl);
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
    metadesc_t *outdesc;	/* offered output metadesc list */
    void *ptr;			/* sniffer-dependent information */ 
    uint32_t flags;		/* sniffer flags */
    timestamp_t polling; 	/* polling interval, if needed */
    uint32_t drops;		/* packets dropped by sniffer */
};

#define SNIFF_TOUCHED	0x8000	/* set if the the flags have changed */
#define	SNIFF_SELECT	0x0001	/* device supports select() */
#define	SNIFF_POLL	0x0002	/* device must be polled */
#define	SNIFF_FILE	0x0004	/* device reads from file */
#define SNIFF_INACTIVE	0x0008	/* inactive, i.e. do not select() */
#define SNIFF_FROZEN	0x0010	/* frozen to slow down (only for SNIFF_FILE) */
#define SNIFF_COMPLETE  0x0020  /* complete, i.e. finish the buffer */

/* generic function used by sniffer-*.c */
void updateofs(pkt_t * pkt, layer_t l, int type);

/* function used by sniffer-*.c to parse the 802.11 frames */
int ieee80211_capture_frame(const char *buf, int buf_len, char *dest);

typedef int (*to_como_radio_fn)(const char *, struct _como_radio *);

int avs_header_to_como_radio(const char *buf, struct _como_radio *r);

int prism2_header_to_como_radio(const char *buf, struct _como_radio *r);

int avs_or_prism2_header_to_como_radio(const char *buf, struct _como_radio *r);

/*
 * metadesc.c
 */
metadesc_t * metadesc_define_sniffer_out(source_t *src, int pktopt_count, ...);

#endif /* _COMO_SNIFFERS_H */
