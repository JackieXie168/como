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
typedef struct source		source_t;
typedef struct sniffer_cb	sniffer_cb_t;
typedef struct sniffer		sniffer_t;

#define SNIFFER(name) sniffer_cb_t como_ ## name ## _sniffer

typedef struct ppbuf ppbuf_t;

int ppbuf_capture   (ppbuf_t * ppbuf, pkt_t * pkt);
int ppbuf_get_count (ppbuf_t * ppbuf);

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
typedef sniffer_t * (*sniffer_init_fn)    (const char * device,
					   const char * args);
typedef void (*sniffer_finish_fn)         (sniffer_t * s);
typedef void (*sniffer_setup_metadesc_fn) (sniffer_t * s);
typedef int  (*sniffer_start_fn)          (sniffer_t * s);
typedef int  (*sniffer_next_fn)           (sniffer_t * s,
					   int max_pkts, timestamp_t max_ivl,
					   int * dropped_pkts);
typedef void (*sniffer_stop_fn)           (sniffer_t * s);

struct sniffer_cb {
    char const *		name;
    sniffer_init_fn		init;     /* initialize the sniffer */
    sniffer_finish_fn		finish;   /* finalize the sniffer */
    sniffer_setup_metadesc_fn	setup_metadesc; /* setup the out metadesc */
    sniffer_start_fn		start;    /* start the sniffer */
    sniffer_next_fn		next;     /* get next packet */
    sniffer_stop_fn		stop;     /* stop the sniffer */
};

struct sniffer {
    int		fd;		/* file descriptor we are using */
    uint32_t	flags;		/* sniffer flags */
    int		max_pkts;	/* maximum number of pkts captured for each
				   call to sniffer_next_fn() */
    timestamp_t	polling;	/* polling interval, if needed */
    ppbuf_t *	ppbuf;		/* ring buffer of pkt pointers */
};

/*
 * Description of the active data sources (i.e., packet information
 * coming sniffers). This structure is populated at config time and
 * used to keep state between successive calls of the sniffer
 * callbacks.
 */
struct source {
    source_t *	next;
    sniffer_cb_t *cb;		/* callbacks */
    sniffer_t *	sniff;		/* sniffer state */
    char *	device;		/* device name */
    char *	args;		/* optional arguments */
    metadesc_t *outdesc;	/* offered output metadesc list */
    uint64_t	tot_cap_pkts;	/* packets captured by the sniffer */
    uint64_t	tot_dropped_pkts; /* packets dropped by the sniffer */
};


#define SNIFF_TOUCHED	0x8000	/* set if the the flags have changed */
#define	SNIFF_SELECT	0x0001	/* device supports select() */
#define	SNIFF_POLL	0x0002	/* device must be polled */
#define	SNIFF_FILE	0x0004	/* device reads from file */
#define SNIFF_INACTIVE	0x0008	/* inactive, i.e. do not select() */
#define SNIFF_FROZEN	0x0010	/* frozen to slow down (only for SNIFF_FILE) */
#define SNIFF_COMPLETE  0x0020  /* complete, i.e. finish the buffer */

sniffer_cb_t * sniffer_cb_lookup(const char *name);

/* generic function used by sniffer-*.c */
void updateofs(pkt_t * pkt, layer_t l, int type);

/* function used by sniffer-*.c to parse the 802.11 frames */
int ieee80211_process_mgmt_frame(const char *buf, int buf_len, char *dest);

typedef int (*to_como_radio_fn)(const char *, struct _como_radio *);

int avs_header_to_como_radio(const char *buf, struct _como_radio *r);

int prism2_header_to_como_radio(const char *buf, struct _como_radio *r);

int avs_or_prism2_header_to_como_radio(const char *buf, struct _como_radio *r);

int radiotap_header_to_como_radio(const char *buf, struct _como_radio *r);

/*
 * metadesc.c
 */
metadesc_t * metadesc_define_sniffer_out(sniffer_t *s, int pktopt_count, ...);

#endif /* _COMO_SNIFFERS_H */
