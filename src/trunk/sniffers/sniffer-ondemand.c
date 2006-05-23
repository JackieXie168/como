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


/*
 * SNIFFER  ---	ondemand
 * 
 * Use the local database to replay records for a given module.
 *
 */

/* sniffer-specific information */
#define BUFSIZE		(1024*1024)
struct _snifferinfo { 
    char buf[BUFSIZE];	/* the capture buffer */
    int fd;		/* storage file descriptor */
    int storage_fd;
    module_t *mdl;
    int node;
    timestamp_t start;
    timestamp_t end;
    int has_end;
    off_t resume_ofs;
    int done;
};

/**
 * -- sniffer_config
 * 
 * process config parameters 
 *
 */
static void
sniffer_config(char *args, struct _snifferinfo *info)
{
    char *wh;

    if (args == NULL)
	return;

    /*
     * "node". 
     * sets the node to which the module belongs.
     */
    wh = strstr(args, "node");
    if (wh != NULL) {
	char *x = index(wh, '=');

	if (x == NULL)
	    logmsg(LOGWARN, "sniffer-ondemand: invalid argument %s\n", wh);
	else
	    info->node = atoi(x + 1);
    }

    /*
     * "start". 
     * sets the start timestamp.
     */
    wh = strstr(args, "start");
    if (wh != NULL) {
	char *x = index(wh, '=');

	if (x == NULL)
	    logmsg(LOGWARN, "sniffer-ondemand: invalid argument %s\n", wh);
	else
	    info->start = atoll(x + 1);
    }

    /*
     * "end". 
     * sets the start timestamp.
     */
    wh = strstr(args, "end");
    if (wh != NULL) {
	char *x = index(wh, '=');

	if (x == NULL)
	    logmsg(LOGWARN, "sniffer-ondemand: invalid argument %s\n", wh);
	else {
	    info->end = atoll(x + 1);
	    info->has_end = 1;
	}
    }
}

/**
 * -- sniffer_start
 * 
 * This function sends the query (via HTTP) to the destination 
 * and receives back the packet description. 
 *
 */
static int
sniffer_start(source_t * src) 
{
    struct _snifferinfo *info;
    off_t ofs;
    
    if (src->device == NULL) {
	logmsg(LOGWARN, "sniffer-ondemand: "
	       "device must contain a valid module\n");
    }
    
    src->flags = SNIFF_FILE;
    
    /* 
     * populate the sniffer specific information
     */
    src->ptr = safe_calloc(1, sizeof(struct _snifferinfo));
    info = (struct _snifferinfo *) src->ptr;
    src->fd = info->fd = -1;
    
    sniffer_config(src->args, info);
    
    /* 
     * connect to the storage process, open the module output file 
     * and then start reading the file and send the data back 
     */
    info->storage_fd = ipc_connect(STORAGE);
    if (info->storage_fd == IPC_ERR)
	goto error;
    
    /* find the module */
    info->mdl = module_lookup_with_name_and_node(src->device, info->node);
    if (info->mdl == NULL) {
	logmsg(LOGWARN, "sniffer-ondemand: "
	       "module \"%s\" not found\n", src->device);
	goto error;
    }
    
    logmsg(V_LOGSNIFFER, "opening file for reading (%s)\n", info->mdl->output);
    info->fd = csopen(info->mdl->output, CS_READER_NOBLOCK, 0, info->storage_fd); 
    if (info->fd < 0) {
	logmsg(LOGWARN, "sniffer-ondemand: "
	       "error while opening file %s\n", info->mdl->output);
	goto error;
    }
    
    /* quickly seek the file from which to start the search */
    if (module_db_seek_by_ts(info->mdl, info->fd, info->start) < 0) {
	logmsg(LOGWARN, "sniffer-ondemand: "
	       "error while seeking file %s\n", info->mdl->output);
	goto error;
    }
    
    /* seek the first interesting record */
    ofs = csgetofs(info->fd);
    
    for (;;) {
	void * ptr;
	timestamp_t ts;
	ssize_t len;
	
	len = info->mdl->callbacks.st_recordsize;
	
	ptr = module_db_record_get(info->fd, &ofs, info->mdl, &len, &ts);
	if (ptr == NULL) {
	    if (len != 0) {
		logmsg(LOGWARN, "error reading file %s: %s\n",
		       info->mdl->output, strerror(errno));
	    }
	    /* there's no data */
	    goto error;
	}
	/*
	 * Now we have either good data or GR_LOSTSYNC.
	 * If lost sync, move to the next file and try again. 
	 */
	if (ptr == GR_LOSTSYNC) {
	    ofs = csseek(info->fd, CS_SEEK_FILE_NEXT);
	    logmsg(LOGSNIFFER, "lost sync, trying next file %s/%016llx\n", 
		   info->mdl->output, ofs);
	    continue;
	}
	
	if (ts >= info->start) {
	    info->resume_ofs = ofs - len;
	    break;
	}
    }
    
    return 0;
    
error:
    if (info->fd != -1) {
	csclose(info->fd, 0);
    }
    if (info->storage_fd) {
    	close(info->storage_fd);
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
sniffer_next(source_t * src, pkt_t * out, int max_no, timestamp_t max_ivl)
{
    struct _snifferinfo * info;
    pkt_t * pkt;
    char * base;		/* current position in input buffer */
    int npkts;			/* processed pkts */
    timestamp_t first_seen = 0;
    off_t ofs;
    ssize_t len, buf_size;
    void * ptr;

    assert(src->ptr != NULL);

    info = (struct _snifferinfo *) src->ptr;
    base = info->buf;
    buf_size = BUFSIZE;
    
    if (info->done)
	return -1;

    ofs = csgetofs(info->fd);
    
    for (npkts = 0, pkt = out; npkts < max_no && buf_size > 65535; ) {
	int left = 0;
	timestamp_t ts;
	
	len = info->mdl->callbacks.st_recordsize;
	if (info->resume_ofs != 0) {
	    ofs = info->resume_ofs;
	    info->resume_ofs = 0;
	}
	
	ptr = module_db_record_get(info->fd, &ofs, info->mdl, &len, &ts);
	if (ptr == NULL) {
	    if (len != 0) {
		logmsg(LOGWARN, "error reading file %s: %s\n",
		       info->mdl->output, strerror(errno));
		/* error */
		return -1;
	    }
	    /* we're finished */
	    info->done = 1;
	    return (npkts > 0) ? npkts : -1;
	}
	/*
	 * Now we have either good data or GR_LOSTSYNC.
	 * If lost sync, move to the next file and try again. 
	 */
	if (ptr == GR_LOSTSYNC) {
	    ofs = csseek(info->fd, CS_SEEK_FILE_NEXT);
	    logmsg(LOGSNIFFER, "lost sync, trying next file %s/%016llx\n", 
		   info->mdl->output, ofs);
	    continue;
	}
	if (ts > info->end) {
	    /* we're finished */
	    info->done = 1;
	    return (npkts > 0) ? npkts : -1;
	}
	
	if (npkts > 0) {
	    if (ts - first_seen > max_ivl) {
		/* Never returns more than max_ivl of traffic */
		/* NOTE: need to restart from this record */
		info->resume_ofs = ofs - len;
		break;
	    }
	} else {
	    first_seen = ts;
	}
	
	do {
	    size_t l = buf_size;
	    left = info->mdl->callbacks.replay(info->mdl, ptr, base, &l, left);
	    if (left < 0) {
		errno = ENODATA;
		return -1;
	    }
	    if (len == 0)
		break; /* done with this record */
	    buf_size -= l;
	    /* ok, copy the packet header */
	    bcopy(base, pkt, sizeof(pkt_t));
	    /* the payload is just after the packet. update 
	     * the payload pointer. 
	     */
	    COMO(payload) = base + sizeof(pkt_t);
	    
	    /* move forward */
	    base += COMO(caplen) + sizeof(pkt_t);
	    npkts++;
	    if (npkts == max_no) {
	    	/* out of pkt_ts, simplest solution drop left packets */
		src->drops = left;
		break;
	    }
	    pkt++;
	} while (left > 0 && buf_size > 65535);
    }

    return npkts;
}

/*
 * -- sniffer_stop
 *
 * just close the storage file
 */
static void
sniffer_stop(source_t * src) 
{
    if (src->ptr) {
	struct _snifferinfo * info;
	info = (struct _snifferinfo *) src->ptr;
	if (info->fd != -1) {
	    csclose(info->fd, 0);
	}
    }
    free(src->ptr);
}

struct _sniffer ondemand_sniffer = { 
    "ondemand", sniffer_start, sniffer_next, sniffer_stop
};
