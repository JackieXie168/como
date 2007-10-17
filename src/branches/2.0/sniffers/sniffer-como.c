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
#include "comopriv.h"
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
#define COMO_MIN_BUFSIZE	(1024 * 1024)
#define COMO_MAX_BUFSIZE	(COMO_MIN_BUFSIZE * 2)
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
sniffer_init(const char * device, const char * args, alc_t *alc)
{
    struct como_me *me;
    
    me = alc_calloc(alc, 1, sizeof(struct como_me));

    me->sniff.max_pkts = 8192;
    me->sniff.flags = SNIFF_SELECT | SNIFF_SHBUF;
    me->device = device;
    
    /* create the capture buffer */
    if (capbuf_init(&me->capbuf, args, NULL, COMO_MIN_BUFSIZE,
		    COMO_MAX_BUFSIZE) < 0)
	goto error;

    me->read_size = me->capbuf.size / 8;
    me->min_proc_size = COMO_DEFAULT_MIN_PROC_SIZE;
    me->cur = me->capbuf.base;
    
    return (sniffer_t *) me;
error:
    alc_free(alc, me);
    return NULL; 
}


static metadesc_t *
sniffer_setup_metadesc(UNUSED sniffer_t * s, UNUSED alc_t *alc)
{
    return NULL; /* TODO !? */
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
    char *http_res = NULL; /* HTTP response */
    char *res_end, *msg;
    const char *path;
    size_t http_res_sz;
    size_t rdn, cpn;

    me->sniff.fd = create_socket(me->device, 0);
    if (me->sniff.fd < 0) { 
	warn("sniffer-como: cannot create socket: %s\n", strerror(errno)); 
	goto error;
    } 
    
    /* build the HTTP request */
    path = me->device + strlen("http://");
    path = strchr(path, '/');
    asprintf(&msg, "GET %s HTTP/1.0\r\n\r\n", path);
    ret = como_write(me->sniff.fd, msg, strlen(msg));
    free(msg);
    if (ret < 0) {
	warn("sniffer-como: write error: %s\n", strerror(errno));
	goto error;
    } 

    /* receives the HTTP response if present */
    http_res_sz = 32;
    http_res = como_malloc(http_res_sz);
    ret = como_read(me->sniff.fd, http_res, http_res_sz);
    if (ret < 0) {
	warn("sniffer-como: read error: %s\n", strerror(errno));
	goto error;
    }
    rdn = (size_t) ret;
    if (strncmp(http_res, "HTTP", 4) == 0) {
	for (;;) {
	    res_end = strstr(http_res, "\r\n\r\n"); /* TODO: use a function
						       that doesn't go further
						       than http_res + rdn */
	    if (res_end != NULL) {
		res_end += 4;
		cpn = rdn - (res_end - http_res);
		break;
	    }
	    http_res_sz = http_res_sz * 2;
	    http_res = como_realloc(http_res, http_res_sz);
	    ret = como_read(me->sniff.fd, http_res + rdn, http_res_sz - rdn);
	    if (ret < 0) {
		warn("sniffer-como: read error: %s\n", strerror(errno));
		goto error;
	    }
	    rdn += (size_t) ret;
	}
	if (strncmp(http_res + 9, "200 OK", 6) != 0) {
	    warn("sniffer-como: unsuccessful HTTP request: %s\n", me->device);
	    goto error;
	}
    } else {
	cpn = rdn;
	res_end = http_res;
    }
    
    if (cpn > 0) {
	char *x;
	x = capbuf_reserve_space(&me->capbuf, cpn);
	memcpy(x, res_end, cpn);
	me->avn = cpn;
    }

    free(http_res);

    /* FIXME: sniffer-como can't get pktdesc anymore */

   return 0;
error:
    close(me->sniff.fd);
    free(http_res);
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
	     pkt_t * first_ref_pkt, int * dropped_pkts) 
{
    struct como_me *me = (struct como_me *) s;
    char * base;                /* current position in input buffer */
    int npkts;                  /* processed pkts */
    size_t avn;
    timestamp_t first_seen = 0;

    *dropped_pkts = 0;
    
    capbuf_begin(&me->capbuf, first_ref_pkt);
    
    avn = me->avn;
    
    if (avn < me->min_proc_size) {
	ssize_t rdn;
	size_t rd_sz = me->read_size;
	base = capbuf_reserve_space(&me->capbuf, rd_sz);
        if (base == NULL) { /* buffer is full */
            s->priv->full = 1;
            return 0;
        }

	if (base == me->capbuf.base) {
	    /* handle the wrapping: me->cur points to avn previously read
	     * bytes, move them to base and decrement rd_sz */
	    if (avn > 0) {
		memmove(base, me->cur, avn);
	    }
	    me->cur = base;
	    rd_sz -= avn;
	    base += avn;
	}
	/* read CoMo packets from stream */
	rdn = read(me->sniff.fd, base, rd_sz);
	if (rdn < 0) {
	    return -1;
	}
	avn += (size_t) rdn;
	if (avn == 0) {
	    return -1;
	}
	capbuf_truncate(&me->capbuf, base + rdn);
    }
    /* start to capture packets from the current position saved in the state */
    base = me->cur;

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

	ppbuf_capture(me->sniff.ppbuf, pkt, s);
	
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


static float
sniffer_usage(sniffer_t * s, pkt_t * first, pkt_t * last)
{
    struct como_me *me = (struct como_me *) s;
    size_t sz;
    void * y;
    
    y = ((void *) last) + sizeof(pkt_t) + last->caplen;
    sz = capbuf_region_size(&me->capbuf, first, y);
    return (float) sz / (float) me->capbuf.size;
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
sniffer_finish(sniffer_t * s, alc_t *alc)
{
    struct como_me *me = (struct como_me *) s;

    capbuf_finish(&me->capbuf);
    alc_free(alc, me);
}


SNIFFER(como) = {
    name: "como",
    init: sniffer_init,
    finish: sniffer_finish,
    setup_metadesc: sniffer_setup_metadesc,
    start: sniffer_start,
    next: sniffer_next,
    stop: sniffer_stop,
    usage: sniffer_usage
};
