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

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h> /* socket */
#include <netinet/in.h> /* struct sockaddr_in */
#include <string.h>     /* strerror */
#include <sys/mman.h>
#include <errno.h>
#include <assert.h>

#include "como.h" 
#include "sniffers.h" 

#include "capbuf.c"


/*
 * SNIFFER  ---		CoMo systems
 * 
 * Connects to live CoMo nodes through the query interface and receives
 * the output data of a given module. It then generates a packet stream 
 * out of the module data. 
 *
 */

/* sniffer-specific information */
#define COMO_DEFAULT_BUFSIZE	(1024 * 1024)
#define COMO_MIN_BUFSIZE	(COMO_DEFAULT_BUFSIZE / 2)
#define COMO_MAX_BUFSIZE	(COMO_DEFAULT_BUFSIZE * 2)
#define COMO_DEFAULT_MIN_PROC_SIZE	(65536 * 2)
#define COMO_DEFAULT_READ_SIZE	(me->capbuf.size / 2)

struct como_me {
    sniffer_t		sniff;		/* common fields, must be the first */
    const char *	device;
    size_t		min_proc_size;
    size_t		read_size;
    size_t		avn;
    char *		cur;
    capbuf_t		capbuf;
};

/*
 * -- sniffer_init
 * 
 */
static sniffer_t *
sniffer_init(const char * device, const char * args)
{
    struct como_me *me;
    
    me = safe_calloc(1, sizeof(struct como_me));

    me->sniff.max_pkts = 8192;
    me->sniff.flags = SNIFF_SELECT;
    me->device = device;
    
    /* create the capture buffer */
    if (capbuf_init(&me->capbuf, args, COMO_MIN_BUFSIZE, COMO_MAX_BUFSIZE) < 0)
	goto error;

    me->read_size = me->capbuf.size / 2;
    me->min_proc_size = COMO_DEFAULT_MIN_PROC_SIZE;
    me->cur = me->capbuf.base;
    
    return (sniffer_t *) me;
error:
    free(me);
    return NULL; 
}


static void
sniffer_setup_metadesc(__unused sniffer_t * s)
{
}


/**
 * -- sniffer_start
 * 
 * This function sends the query (via HTTP) to the destination 
 * and receives back the packet description. 
 *
 */
static int
sniffer_start(sniffer_t * s) 
{
    struct como_me *me = (struct como_me *) s;
    int ret;
    char *msg, *path = NULL;
    
    me->sniff.fd = create_socket(me->device, &path);
    if (me->sniff.fd < 0) { 
        logmsg(LOGWARN, "sniffer-como: cannot create socket: %s\n", 
	    strerror(errno)); 
	goto error;
    } 
    
    /* build the HTTP request */
    asprintf(&msg, "GET %s HTTP/1.0\r\n\r\n", path);
    ret = como_writen(me->sniff.fd, msg, strlen(msg));
    free(msg);
    free(path);
    if (ret < 0) {
        logmsg(LOGWARN, "sniffer-como: write error: %s\n", strerror(errno));
	goto error;
    } 

#if 0
    /* FIXME: sniffer-como can't get pktdesc anymore */
    /*
     * a pktdesc_t for the stream is the first data to be received
     */
    ret = como_readn(sd, (char *) &src->output, sizeof(pktdesc_t));
    if (ret < 0) {
        logmsg(LOGWARN, "sniffer-como: read error: %s\n", strerror(errno));
	return -1; 
    } 
#endif

   return 0;
error:
    close(me->sniff.fd);
    free(path);
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
	     int * dropped_pkts) 
{
    struct como_me *me = (struct como_me *) s;
    char * base;                /* current position in input buffer */
    int npkts;                  /* processed pkts */
    size_t avn;
    timestamp_t first_seen = 0;

    *dropped_pkts = 0;
    
    avn = me->avn;
    
    if (avn >= me->min_proc_size) {
	base = me->cur;
    } else {
	ssize_t rdn;
	base = capbuf_reserve_space(&me->capbuf, me->read_size);
	if (base == me->capbuf.base && avn > 0) {
	    memmove(base, me->cur, avn);
	}
	/* read CoMo packets from stream */
	rdn = read(me->sniff.fd, base + avn, me->read_size);
	if (rdn < 0) {
	    return -1;
	}
	avn += (size_t) rdn;
	if (avn == 0) {
	    return -1;
	}
    }

    for (npkts = 0; npkts < max_pkts; npkts++) {
	size_t sz;
	/* TODO: handle different endianness */
	pkt_t *pkt = (pkt_t *) base;
	
	/* check if we have enough for a new packet record */
	if (sizeof(pkt_t) > avn)
	    break;

	/* check if we have the payload as well */
        if (sizeof(pkt_t) + COMO(caplen) > avn)
            break;

	if (npkts > 0) {
	    if (COMO(ts) - first_seen > max_ivl) {
		/* Never returns more than max_ivl of traffic */
		break;
	    }
	} else {
	    first_seen = COMO(ts);
	}

	/* the payload is just after the packet */
	COMO(payload) = base + sizeof(pkt_t);

	ppbuf_capture(me->sniff.ppbuf, pkt);
	
	/* move forward */
	sz = sizeof(pkt_t) + COMO(caplen) /* + TODO padding */;
	base += sz;
	avn -= sz;
    }
    /* save the state */
    me->avn = avn;
    me->cur = base;

    return 0;
}


/*
 * -- sniffer_stop
 *
 * just close the socket
 */
static void
sniffer_stop(sniffer_t * s) 
{
    struct como_me *me = (struct como_me *) s;
    
    close(me->sniff.fd);
}


static void
sniffer_finish(sniffer_t * s)
{
    struct como_me *me = (struct como_me *) s;

    capbuf_finish(&me->capbuf);
    free(me);
}


SNIFFER(como) = {
    name: "como",
    init: sniffer_init,
    finish: sniffer_finish,
    setup_metadesc: sniffer_setup_metadesc,
    start: sniffer_start,
    next: sniffer_next,
    stop: sniffer_stop,
};
