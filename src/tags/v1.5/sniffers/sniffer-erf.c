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


#include <fcntl.h>
#include <dagapi.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <glob.h>	/* glob */
#include <errno.h>
#include <string.h>     /* bcopy */

#include "como.h"
#include "sniffers.h"

#include "capbuf.c"

/*
 * SNIFFER  ---    Endace ERF file 
 *
 * Endace ERF trace format. 
 *
 */


/* sniffer specific information */
#define ERF_MIN_BUFSIZE		(me->sniff.max_pkts * sizeof(pkt_t))
#define ERF_MAX_BUFSIZE		(ERF_MIN_BUFSIZE + (2*1024*1024))
#define ERF_DEFAULT_MAPSIZE	(16*1024*1024)	// 16 MB
#define ERF_MIN_MAPSIZE		(1*1024*1024)	// 1 MB
#define ERF_MAX_MAPSIZE		(32*1024*1024)	// 32 MB

struct erf_me {
    sniffer_t		sniff;		/* common fields, must be the first */
    glob_t		files;		/* result of device pattern */
    size_t		file_idx;	/* index of current file in
					   files.gl_pathv */
    off_t		file_size;	/* size fo trace file */
    off_t		nread;
    size_t		map_size;	/* size of mmap */
    char *		base;		/* mmap addres */
    off_t		off;
    off_t		remap_sz;
    off_t		remap;
    capbuf_t		capbuf;
};


static int
open_next_file(struct erf_me * me)
{
    char *device;
    struct stat trace_stat;

    if (me->sniff.fd >= 0) {
	me->sniff.flags |= SNIFF_TOUCHED;
	me->file_idx++;
	if (me->file_idx >= me->files.gl_pathc)
	    goto error;
	close(me->sniff.fd);
    }

    /* open the trace file */
    device = me->files.gl_pathv[me->file_idx];
    me->sniff.fd = open(device, O_RDONLY);
    if (me->sniff.fd < 0) {
	logmsg(LOGWARN, "sniffer-erf: error while opening file %s: %s\n",
	       device, strerror(errno));
	goto error;
    }
    
    /* get the trace file size */
    if (fstat(me->sniff.fd, &trace_stat) < 0) {
	logmsg(LOGWARN, "sniffer-erf: failed to stat file %s: %s\n",
	       device, strerror(errno));
	goto error;
    }

    if (me->base) {
	munmap(me->base, me->map_size);
    }

    me->base = NULL;
    me->nread = me->off = 0;
    me->remap = 0;
    me->file_size = trace_stat.st_size;

    return 0;

error:
    return -1;
}


/*
 * -- sniffer_init
 * 
 */
static sniffer_t *
sniffer_init(const char * device, const char * args)
{
    struct erf_me *me;
    
    me = safe_calloc(1, sizeof(struct erf_me));

    me->sniff.max_pkts = 8192;
    me->sniff.flags = SNIFF_FILE | SNIFF_SELECT;
    me->map_size = ERF_DEFAULT_MAPSIZE;

    if (args) { 
	/* process input arguments */
	char *p;

	if ((p = strstr(args, "mapsize=")) != NULL) {
	    me->map_size = atoi(p + 8);
	    me->map_size = ROUND_32(me->map_size);
	    if (me->map_size < ERF_MIN_MAPSIZE) {
	    	me->map_size = ERF_MIN_MAPSIZE;
	    }
	    if (me->map_size > ERF_MAX_MAPSIZE) {
		me->map_size = ERF_MAX_MAPSIZE;
	    }
	}
    }

    /* 
     * list all files that match the given pattern. 
     */
    if (glob(device, GLOB_ERR | GLOB_TILDE, NULL, &me->files) < 0) {
	logmsg(LOGWARN, "sniffer-erf: error matching %s: %s\n",
	       device, strerror(errno));
	goto error;
    }
	
    if (me->files.gl_pathc == 0) { 
	logmsg(LOGWARN, "sniffer-erf: no files match %s\n", device);
	goto error;
    }
    
    /* create the capture buffer */
    if (capbuf_init(&me->capbuf, args, NULL, ERF_MIN_BUFSIZE,
		    ERF_MAX_BUFSIZE) < 0)
	goto error;

    return (sniffer_t *) me;
error:
    free(me);
    return NULL;
}


static void
sniffer_setup_metadesc(sniffer_t * s)
{
    metadesc_t *outmd;
    pkt_t *pkt;

    /* setup output descriptor */
    outmd = metadesc_define_sniffer_out(s, 0);
    
    pkt = metadesc_tpl_add(outmd, "link:eth:any:any");
    pkt = metadesc_tpl_add(outmd, "link:vlan:any:any");
    pkt = metadesc_tpl_add(outmd, "link:isl:any:any");
    pkt = metadesc_tpl_add(outmd, "link:hdlc:any:any");
}


static int
mmap_next_region(struct erf_me * me)
{
    if (me->base != NULL) {
	munmap(me->base, me->map_size);
    }
    /* mmap the trace file */
    me->base = (char *) mmap(NULL, me->map_size, PROT_READ, MAP_PRIVATE,
			     me->sniff.fd, me->remap);
    if (me->base == MAP_FAILED) {
	logmsg(LOGWARN, "sniffer-erf: mmap failed: %s\n",
	       strerror(errno));
	return -1;
    }
    return 0;
}


/*
 * -- sniffer_start
 * 
 * open the trace file and return the file descriptors. 
 * No arguments are supported so far. It returns 0 in case 
 * of success, -1 in case of failure.
 */
static int
sniffer_start(sniffer_t * s) 
{
    struct erf_me *me = (struct erf_me *) s;
    int ps, mp; /* page size, maximum packet size */
    int r;
    
    me->sniff.fd = -1;
    me->file_idx = 0;
    if (open_next_file(me) < 0)
	return -1;

    if (mmap_next_region(me) < 0)
	return -1;

    /*
     * compute remap offset using the system pagesize and the maximum
     * packet length.
     */
    ps = getpagesize();
    mp = 65535;
    r = (mp / ps) * ps;
    if (mp % ps > 0) {
	r += ps;
    }
    me->remap_sz = (off_t) (me->map_size - r);
    me->remap = me->remap_sz;
    
    return 0;
}


/*
 * -- sniffer_next
 * 
 * Reads one chunk of the file (BUFSIZE) and fill the out_buf 
 * with packets in the _como_pkt format. Return the number of 
 * packets read. 
 *
 */
static int
sniffer_next(sniffer_t * s, int max_pkts, timestamp_t max_ivl,
	     __attribute__((__unused__)) pkt_t * first_ref_pkt, int * dropped_pkts) 
{
    struct erf_me *me = (struct erf_me *) s;
    pkt_t *pkt;                 /* packet records */
    int npkts;                  /* processed pkts */
    timestamp_t first_seen = 0;

    /* TODO: handle truncated traces */
    if (me->nread >= me->file_size) {
	if (ppbuf_get_count(me->sniff.ppbuf) > 0) {
	    /* we've finished with this file but the ppbuf is not empty */
	    return 0;
	}
	if (open_next_file(me) < 0) {
	    return -1; /* end of file, nothing left to do */
	}
    }

    if (me->nread >= me->remap) {
	if (ppbuf_get_count(me->sniff.ppbuf) > 0) {
	    /* can't call munmap while the ppbuf contains some valid packets
	     * pointing to the currently mmaped memory */
	    return 0;
	}
	/* we've read all the packets that fit in the mmaped memory, now
	 * mmap the next area of the trace file */
	if (mmap_next_region(me) < 0)
	    return -1;
	me->off = me->nread - me->remap;
	me->remap += me->remap_sz;
    }

    *dropped_pkts = 0;
    
    npkts = 0;
    
    capbuf_begin(&me->capbuf, NULL);

    while (npkts < max_pkts) {
	dag_record_t *rec;	/* DAG record structure */
	int len;		/* total record length */
	int l2type;		/* interface type */
	size_t rs;
	off_t left = me->file_size - me->nread;
	char *base = me->base + me->off;

	if (me->nread > me->remap) {
	    break;
	}

	/* see if we have a record */
	if (left < dag_record_size)  
	    break; 

        /* access to packet record */
        rec = (dag_record_t *) base;
        len = ntohs(rec->rlen);
        
        rs = len;

        /* check if entire record is available */
        if (left < (size_t) len) 
	    break; 

	if (npkts > 0 && (rec->ts - first_seen) >= max_ivl) {
	    /* Never returns more than max_ivl of traffic */
	    break;
	} else {
	    first_seen = rec->ts;
	}

	/* skip DAG header */
	base += dag_record_size; 
        len -= dag_record_size;
        
        /*
         * we need to figure out what interface we are monitoring.
         * some information is in the DAG record but for example Cisco
         * ISL is not reported.
         */
        switch (rec->type) {
        case TYPE_LEGACY:
            /* we consider legacy to be only packet-over-sonet. this
             * is just pass through.
             */   
  
        case TYPE_HDLC_POS:
            l2type = LINKTYPE_HDLC;
            break;

        case TYPE_ETH:
            l2type = LINKTYPE_ETH;
	    base += 2; /* ethernet frames have padding */
	    len -= 2;
            break;

        default:
            /* other types are not supported */
            me->off += len;
            me->nread += len;
            continue;
        }
        
        /* reserve the space in the buffer for the pkt_t */
	pkt = (pkt_t *) capbuf_reserve_space(&me->capbuf, sizeof(pkt_t));
        
        /* 
	 * ok, data is good now, copy the packet over 
	 */
	COMO(ts) = rec->ts;
	COMO(len) = (uint32_t) ntohs(rec->wlen);
	COMO(type) = COMOTYPE_LINK;

	/*
	 * point to the packet payload
	 */
	COMO(caplen) = len;
	COMO(payload) = base;

	/*
	 * update layer2 information and offsets of layer 3 and above.
	 * this sniffer only runs on ethernet frames.
	 */
	updateofs(pkt, L2, l2type);
	
        /* increment the number of processed packets */
	npkts++;
	ppbuf_capture(me->sniff.ppbuf, pkt);
	
	me->off += rs;
	me->nread += rs;
    }

    return 0;
}


/*
 * -- sniffer_stop
 * 
 * close the file descriptor. 
 */
static void
sniffer_stop(sniffer_t * s)
{
    struct erf_me *me = (struct erf_me *) s;
    
    if (me->base) {
    	munmap(me->base, me->map_size);
    }
    close(me->sniff.fd);
}


static void
sniffer_finish(sniffer_t * s)
{
    struct erf_me *me = (struct erf_me *) s;

    capbuf_finish(&me->capbuf);
    free(me);
}


SNIFFER(erf) = {
    name: "erf",
    init: sniffer_init,
    finish: sniffer_finish,
    setup_metadesc: sniffer_setup_metadesc,
    start: sniffer_start,
    next: sniffer_next,
    stop: sniffer_stop,
};
