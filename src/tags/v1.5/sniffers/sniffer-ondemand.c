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

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h> /* socket */
#include <netinet/in.h> /* struct sockaddr_in */
#include <string.h>     /* strerror */
#include <errno.h>
#include <assert.h>

#include "como.h" 
#include "sniffers.h" 
#include "comopriv.h"
#include "storage.h"
#include "ipc.h"

#include "capbuf.c"

/*
 * SNIFFER  ---	ondemand
 * 
 * Use the local database to replay records for a given module.
 *
 */

/* sniffer-specific information */
#define ONDEMAND_MIN_BUFSIZE	(1024*1024)
#define ONDEMAND_MAX_BUFSIZE	(4*ONDEMAND_MIN_BUFSIZE)

struct ondemand_me {
    sniffer_t		sniff;		/* common fields, must be the first */
    const char *	device;		/* source module name */
    int			fd;		/* cs file descriptor */
    module_t *		mdl;		/* source module */
    int			node;		/* node id */
    timestamp_t		start;		/* start timestamp */
    timestamp_t		end;		/* end timestamp */
    int			has_end;	/* end timestamp valid flag */
    off_t		resume_ofs;	/* offset to resume at */
    int			done;		/* done flag */
    capbuf_t		capbuf;
};


/*
 * -- sniffer_init
 * 
 */
static sniffer_t *
sniffer_init(const char * device, const char * args)
{
    struct ondemand_me *me;
    
    me = safe_calloc(1, sizeof(struct ondemand_me));
    me->sniff.fd = -1; 
    me->sniff.max_pkts = 8192;
    me->sniff.flags = SNIFF_POLL | SNIFF_FILE;
    me->device = device;

    if (me->device == NULL || strlen(me->device) == 0) {
	logmsg(LOGWARN, "sniffer-ondemand: "
	       "device must contain a valid module\n");
	goto error;
    }
    
    if (args) { 
	/* process input arguments */
	char *p;

	/*
	 * "node".
	 * sets the node to which the module belongs.
	 */
	if ((p = strstr(args, "node=")) != NULL) {
	    me->node = atoi(p + 5);
	}
	/*
	 * "start".
	 * sets the start timestamp.
	 */
	if ((p = strstr(args, "start=")) != NULL) {
	    me->start = strtoll(p + 6, (char **) NULL, 10);
	}
	/*
	 * "start".
	 * sets the end timestamp.
	 */
	if ((p = strstr(args, "end=")) != NULL) {
	    me->end = strtoll(p + 4, (char **) NULL, 10);
	    me->has_end = 1;
	}
    }


    /* create the capture buffer */
    if (capbuf_init(&me->capbuf, args, NULL, ONDEMAND_MIN_BUFSIZE,
		    ONDEMAND_MAX_BUFSIZE) < 0)
	goto error;

    return (sniffer_t *) me;
error:
    free(me);
    return NULL;
}


static void
sniffer_setup_metadesc(__attribute__((__unused__)) sniffer_t * s)
{
}


/**
 * -- sniffer_start
 * 
 * This function connects to storage and creates a storage client for the
 * module used as data source. 
 *
 */
static int
sniffer_start(sniffer_t * s) 
{
    struct ondemand_me *me = (struct ondemand_me *) s;
    
    /* 
     * connect to the storage process, open the module output file 
     * and then start reading the file and send the data back 
     */
    if (ipc_connect(STORAGE) == IPC_ERR) 
	goto error;
    
    /* find the module */
    me->mdl = module_lookup(me->device, me->node);
    if (me->mdl == NULL) {
	logmsg(LOGWARN, "sniffer-ondemand: "
	       "module \"%s\" [%d] not found\n", me->device, me->node);
	goto error;
    }
    
    logmsg(V_LOGSNIFFER, "opening file for reading (%s)\n", me->mdl->output);
    me->sniff.fd = csopen(me->mdl->output, CS_READER, 0); 
    if (me->sniff.fd < 0) {
	logmsg(LOGWARN, "sniffer-ondemand: "
	       "error while opening file %s\n", me->mdl->output);
	goto error;
    }
    
    /* seek on the first record */
    me->resume_ofs = module_db_seek_by_ts(me->mdl, me->sniff.fd, me->start);
    if (me->resume_ofs < 0) {
	logmsg(LOGWARN, "sniffer-ondemand: "
	       "error while seeking file %s\n", me->mdl->output);
	goto error;
    }
       
    return 0;
    
error:
    if (me->sniff.fd != -1) {
	csclose(me->sniff.fd, 0);
    }
    return -1;
}


/**
 * -- sniffer_next
 *
 * Copies sizeof(pkt_t) bytes from the stream in a pkt_t struct 
 * Returns how many packets were read or -1 if an unrecoverable
 * error occurred.
 * 
 */
static int
sniffer_next(sniffer_t * s, int max_pkts, timestamp_t max_ivl,
	     __attribute__((__unused__)) pkt_t * first_ref_pkt, int * dropped_pkts) 
{
    struct ondemand_me *me = (struct ondemand_me *) s;
    
    int npkts;			/* processed pkts */
    timestamp_t first_seen = 0;
    off_t ofs;
    ssize_t len;
    size_t replayed_size = 0, max_size;
    void * ptr;
    int left = 0;
    const size_t max_pkt_sz = sizeof(pkt_t) + 65536;

    if (me->done)
	return -1;
    
    max_size = (me->capbuf.size - max_pkt_sz);
    
    ofs = me->resume_ofs;
    
    npkts = 0;
    
    capbuf_begin(&me->capbuf, NULL);
    
    while (npkts < max_pkts && replayed_size < max_size) {
	timestamp_t ts;
	
	len = me->mdl->callbacks.st_recordsize;
	
	ptr = module_db_record_get(me->fd, &ofs, me->mdl, &len, &ts);
	if (ptr == NULL) {
	    if (len != 0) {
		logmsg(LOGWARN, "error reading file %s: %s\n",
		       me->mdl->output, strerror(errno));
		/* error */
		return -1;
	    }
	    /* we're finished */
	    me->done = 1;
	    return (npkts > 0) ? 0 : -1;
	}
	/*
	 * Now we have either good data or GR_LOSTSYNC.
	 * If lost sync, move to the next file and try again. 
	 */
	if (ptr == GR_LOSTSYNC) {
	    ofs = csseek(me->fd, CS_SEEK_FILE_NEXT);
	    logmsg(LOGSNIFFER, "lost sync, trying next file %s/%016llx\n", 
		   me->mdl->output, ofs);
	    continue;
	}
	if (ts >= me->end) {
	    /* we're finished */
	    me->done = 1;
	    return (npkts > 0) ? npkts : -1;
	}
	
	if (npkts > 0) {
	    if (ts > first_seen && ts - first_seen > max_ivl) {
		/* Never returns more than max_ivl of traffic */
		/* NOTE: need to restart from this record */
		ofs -= len;
		break;
	    }
	} else {
	    first_seen = ts;
	}
	
	left = 0;
	do {
	    size_t l = max_pkt_sz;
	    pkt_t *pkt;
	    
	    /* reserve the space in the buffer for the pkt_t */
	    pkt = (pkt_t *) capbuf_reserve_space(&me->capbuf, l);
	    
	    left = me->mdl->callbacks.replay(me->mdl, ptr, (char *) pkt,
					     &l, left);
	    capbuf_truncate(&me->capbuf, ((void *) pkt) + l);
	    if (left < 0) {
		errno = ENODATA;
		return -1;
	    }
	    
	    if (l == 0)
		break; /* done with this record */

	    replayed_size += l;
	    npkts++;
	    ppbuf_capture(me->sniff.ppbuf, pkt);
	} while (left > 0 && npkts < max_pkts && replayed_size < max_size);
    }

    *dropped_pkts = left;
    me->resume_ofs = ofs;

    return 0;
}

/*
 * -- sniffer_stop
 *
 * just close the storage file
 */
static void
sniffer_stop(sniffer_t * s)
{
    struct ondemand_me *me = (struct ondemand_me *) s;
    
    csclose(me->sniff.fd, 0);
}


static void
sniffer_finish(sniffer_t * s)
{
    struct ondemand_me *me = (struct ondemand_me *) s;

    capbuf_finish(&me->capbuf);
    free(me);
}


SNIFFER(ondemand) = {
    name: "ondemand",
    init: sniffer_init,
    finish: sniffer_finish,
    setup_metadesc: sniffer_setup_metadesc,
    start: sniffer_start,
    next: sniffer_next,
    stop: sniffer_stop,
};
