/*-
 * Copyright (c) 2005, Intel Corporation
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

#include <stdlib.h>     /* malloc */
#include <fcntl.h>      /* open */
#include <unistd.h>     /* close */
#include <string.h>     /* memset, memcpy */
#include <glob.h>	/* glob */
#include <errno.h>	/* errno values */
#include <ftlib.h>      /* flow-tools stuff */
//#include <sys/types.h>
//#include <sys/stat.h>

#include "sniffers.h"
#include "como.h"
#include "comotypes.h"
#include "heap.h"

/*
 * SNIFFER  ---    Flow-tools files
 *
 * Flow-tools files. It requires the flow-tools and zlib library to be 
 * installed (i.e., HAVE_FTLIB_AND_ZLIB must be set to 1). 
 *
 * It produces a packet stream that resembles the original packet 
 * stream. All information that cannot find space in the pkt_t data 
 * structure is dropped. 
 * 
 * XXX This sniffer assumes NetFlow v5
 *
 */


/*
 * This data structure will be stored in the source_t structure and 
 * used for successive callbacks.
 */
struct _snifferinfo {
    glob_t in; 			/* result of src->device pattern */
    int curfile; 		/* index of current file in in.gl_pathv */
    heap_t * heap; 		/* heap with flow records read so far */
    timestamp_t min_ts; 	/* min start time in the heap (root) */
    timestamp_t max_ts; 	/* max start time in the heap */
    timestamp_t window; 	/* min diff between max_ts and min_ts */
    struct ftio ftio;		/* flow-tools I/O data structure */
}; 


/* 
 * This data structure is saved in the heap and contains the flow 
 * information as derived by the flow-tools record. 
 */
struct _flowinfo { 
    pkt_t pkt;			/* next packet that will be generated */
    uint32_t length_last;	/* length of last packet */
    timestamp_t increment; 	/* timestamp increment at each packet */
    timestamp_t end_ts;		/* timestamp of last packet */
};


/* 
 * this macro is used to convert a timestamp in netflow (given by the
 * sysuptime) into a timestamp_t 
 */
static __inline__ timestamp_t 
netflow2ts(struct fts3rec_v5 * f, uint32_t ms)
{
    int64_t curtime; 
    int64_t uptime; 
    int64_t mstime; 

    curtime = (int64_t) TIME2TS(f->unix_secs, f->unix_nsecs/1000); 
    uptime = (int64_t) TIME2TS(f->sysUpTime/1000, (f->sysUpTime%1000)*1000);  
    mstime = (int64_t) TIME2TS(ms/1000, (ms%1000)*1000);
 
    return (timestamp_t) (curtime + mstime - uptime); 
}


/*
 * -- pkt_fillin
 * 
 * A flow record defines all pkt_t fields but the timestamp. We fill 
 * in one template to speed up things later on. We put the timestamp of 
 * the beginning of the flow and it will then be modified during the 
 * replay of the flow record. 
 */
static pkt_t
pkt_fillin(struct fts3rec_v5 * f) 
{
    pkt_t p; 
    pkt_t * pkt = &p;
    
    /* clear the packet */
    bzero(pkt, sizeof(pkt_t)); 		/* XXX just for now. */

    /* CoMo header */
    pkt->ts = netflow2ts(f, f->First); 
    pkt->len = f->dOctets / f->dPkts;
    pkt->caplen = sizeof(struct _como_iphdr);
    pkt->type = COMO_L2_NONE; 

    /* IP header */
    IP(vhl) = 0x45; 
    IP(tos) = f->tos; 
    N16(IP(len)) = htons(f->dOctets / f->dPkts);
    IP(proto) = f->prot; 
    N32(IP(src_ip)) = htonl(f->srcaddr);
    N32(IP(dst_ip)) = htonl(f->dstaddr);
    
    switch (f->prot) {
    case IPPROTO_TCP:
        N16(TCP(src_port)) = htons(f->srcport);
        N16(TCP(dst_port)) = htons(f->dstport);
	pkt->caplen += sizeof(struct _como_tcphdr);
        break;

    case IPPROTO_UDP:
        N16(UDP(src_port)) = htons(f->srcport);
        N16(UDP(dst_port)) = htons(f->dstport);
	pkt->caplen += sizeof(struct _como_udphdr);
        break;

    default:
        break;
    }
    
    return p;
}


/* 
 * -- flowtools_next 
 * 
 * this function goes to the next file in the list
 * of flowtools files. It returns the new file descriptor or 
 * -1 in case of failures. 
 *
 */
int 
flowtools_next(int ofd, struct _snifferinfo * info) 
{
    int fd; 
    int ret; 

    if (ofd >= 0) {
	ftio_close(&info->ftio); 
	close(ofd);
    } 
  
    logmsg(LOGSNIFFER, "opening file %s\n", info->in.gl_pathv[info->curfile]);
    fd = open(info->in.gl_pathv[info->curfile], O_RDONLY);
    if (fd < 0) 
        return -1;
 
    /* init flowtools library */
    ret = ftio_init(&info->ftio, fd, FT_IO_FLAG_READ);
    if (ret < 0) 
        return -1;

    return fd; 
}


/* 
 * -- flowtools_read
 * 
 * Read from next flow record from flowtools files and
 * store the flow record in the heap. 
 * Returns the start timestsamp of the flow or 0 if no 
 * more flows are available.
 * 
 */ 
timestamp_t 
flowtools_read(source_t * src) 
{ 
    struct _snifferinfo * info; 
    struct fts3rec_v5 * fr;
    struct _flowinfo * flow; 

    info = (struct _snifferinfo *) src->ptr; 
    if (info->curfile == info->in.gl_pathc) 
	return 0;		/* all files have been processed */

    /* get next flow record */
    fr = (struct fts3rec_v5 *) ftio_read(&info->ftio);
    if (fr == NULL) {
	/* end of file. go to next if any. */
	info->curfile++;
	if (info->curfile == info->in.gl_pathc)
	    return 0; 		/* no files left */

	src->fd = flowtools_next(src->fd, info); 
	if (src->fd < 0) {		/* XXX errors are ignored here... */
	    logmsg(LOGWARN, "sniffer-flowtools: opening %s: %s\n",
		info->in.gl_pathv[info->curfile], strerror(errno));
	    return 0; 
        } 

	fr = (struct fts3rec_v5 *) ftio_read(&info->ftio);  
    }

    /* build a new flow record */
    flow = safe_calloc(1, sizeof(struct _flowinfo));
    flow->end_ts = netflow2ts(fr, fr->Last);
    flow->pkt = pkt_fillin(fr);
    flow->increment = (flow->end_ts - flow->pkt.ts) / fr->dPkts;
    flow->length_last = fr->dOctets % fr->dPkts;

    /* insert in the heap */
    heap_insert(info->heap, flow);

    return flow->pkt.ts; 
}


/* 
 * -- flow_cmp
 * 
 * This is the sorting callback required by the heap service. 
 * It compare the timestamps of the next packets for two flows, a and b, 
 * and returns (a < b).  
 */
static int
flow_cmp(const void * fa, const void * fb) 
{
    return (((struct _flowinfo*)fa)->pkt.ts < ((struct _flowinfo*)fb)->pkt.ts); 
}



/*
 * -- sniffer_start
 * 
 * this sniffer opens the directory as asked and opens 
 * sequentially all files that src->device resolves to. 
 * It assumes that the ASCII order of the filenames
 * respect the time order of the trace. 
 * It returns 0 in case of success, -1 in case of failure.
 */
static int
sniffer_start(source_t * src) 
{
    struct _snifferinfo * info;
    int ret;

    /* 
     * populate the sniffer specific information
     */
    src->ptr = safe_calloc(1, sizeof(struct _snifferinfo)); 
    info = (struct _snifferinfo *) src->ptr; 
    info->window = 300; 		/* default window is 5 minutes */

    /* 
     * list all files that match the given pattern. 
     */
    ret = glob(src->device, GLOB_ERR|GLOB_TILDE, NULL, &info->in); 
    if (ret != 0) {
	logmsg(LOGWARN, "sniffer-flowtools: error matching %s: %s\n",
	    src->device, strerror(errno)); 
	free(src->ptr);
	return -1; 
    } 
	
    if (info->in.gl_pathc == 0) { 
	logmsg(LOGWARN, "sniffer-flowtools: no files match %s\n", src->device); 
	free(src->ptr);
	return -1; 
    } 
	
    /* open the first file */
    src->fd = flowtools_next(-1, info); 
    if (src->fd < 0) {
        logmsg(LOGWARN, "sniffer-flowtools: opening %s: %s\n", 
	    info->in.gl_pathv[info->curfile], strerror(errno)); 
	globfree(&info->in);
	free(src->ptr);
	return -1; 
    } 

    /* 
     * set the window size, i.e., how much ahead in the flow records 
     * we need to read before replaying packets to make sure that no 
     * out-of-order packets will be sent. 
     */
    if (src->args && strstr(src->args, "window=") != NULL) {
	char * wh; 

	wh = index(src->args, '=') + 1; 
	info->window = TIME2TS(atoi(wh), 0); 
    }

    /* initialize the heap */
    info->heap = heap_init(flow_cmp);

    /* 
     * read a full window of netflow records and populate the heap. 
     * We do this now so that the first time sniffer_next will be
     * called there will be something in the heap to process right away. 
     */
    info->min_ts = (timestamp_t) ~0; 
    info->max_ts = (timestamp_t) 0; 
    do { 
	timestamp_t ts; 

	ts = flowtools_read(src); 
	if (ts == 0) 
	    break; 		/* EOF */
	if (ts > info->max_ts) 
	    info->max_ts = ts; 
	else if (ts < info->min_ts) 
	    info->min_ts = ts; 
    } while (info->max_ts - info->min_ts > info->window);

#if 0 		/* XXX this is not supported yet!! */
    /*  
     * given that the output stream is not a plain packet 
     * stream, describe it in the source_t data structure 
     */ 
    p = src->output = safe_calloc(1, sizeof(pktdesc_t));
    p->ts = TIME2TS(120, 0);
    N16(p->bm.ih.len) = 0xffff;
    outdesc.bm.ih.proto = 0xff;
    N32(outdesc.bm.ih.src_ip) = 0xffffffff;
    N32(outdesc.bm.ih.dst_ip) = 0xffffffff;
    N16(outdesc.bm.tcph.src_port) = 0xffff;
    N16(outdesc.bm.tcph.dst_port) = 0xffff;
    outdesc.bm.tcph.flags = 0xff;
    N16(outdesc.bm.udph.src_port) = 0xffff;
    N16(outdesc.bm.udph.dst_port) = 0xffff;
#endif
    
    return 0; 
}


/*
 * -- sniffer_next
 *
 * Fills the outbuf with packets and returns the number of 
 * packet present in the buffer. It returns -1 in case of error. 
 *
 */
static int
sniffer_next(source_t * src, void *out_buf, size_t out_buf_size)
{
    struct _snifferinfo * info; 
    struct _flowinfo * flow; 
    uint npkts;                 /* processed pkts */
    uint out_buf_used;          /* bytes in output buffer */
    
    info = (struct _snifferinfo *) src->ptr; 

    /* update the minimum timestamp from the root of the heap */
    flow = heap_root(info->heap);
    if (flow == NULL) 
	return -1; 		/* heap is empty, we are done! */

    npkts = out_buf_used = 0; 
    while (out_buf_used + sizeof(pkt_t) < out_buf_size) {
	pkt_t * pkt; 

	/* 
	 * read from flow-tools file so that we have a full info->window 
 	 * of flows in the heap. 
	 */ 
	while (info->max_ts - info->min_ts < info->window) { 
	    timestamp_t ts; 

	    ts = flowtools_read(src);
	    if (ts == 0) 
		break; 		/* EOF */
	    if (ts > info->max_ts) 
		info->max_ts = ts;
	    else if (ts < info->min_ts) 
		info->min_ts = ts;
        } 

	/* get the first flow from the heap */
	heap_extract(info->heap, (void **) &flow); 

	/* generate the first packet and update the pkt template */
	pkt = (pkt_t *) ((char *)out_buf + out_buf_used); 
	*pkt = flow->pkt; 
	out_buf_used += STDPKT_LEN(pkt); 

	/* 
	 * check if this flow has more packets. If so, update the 
	 * timestamp and insert it into the heap again. Otherwise, 
	 * update the lenght of the packet and free this data 
	 * structure 
	 */
	if (flow->pkt.ts >= flow->end_ts) { 
	    pkt->ts = flow->end_ts; 
	    pkt->len = flow->length_last; 
	    N16(IP(len)) = htons((uint16_t) flow->length_last);
	    free(flow); 
	} else {  
	    flow->pkt.ts += flow->increment; 
	    heap_insert(info->heap, flow); 
	} 

	/* increment packet count */
	npkts++; 

	/* update the minimum timestamp from the root of the heap */
	flow = heap_root(info->heap);
	if (flow == NULL) 
	    break; 		/* we are done; next time we will stop */
	info->min_ts = flow->pkt.ts;
    }

    return npkts;
}

/*
 * sniffer_stop
 */
static void
sniffer_stop(source_t * src)
{
    struct _snifferinfo * info; 

    info = (struct _snifferinfo *) src->ptr; 

    ftio_close(&info->ftio);
    heap_close(info->heap); 
    close(src->fd); 
    free(src->ptr); 
}


sniffer_t flowtools_sniffer = { 
    "flowtools", sniffer_start, sniffer_next, sniffer_stop, SNIFF_FILE 
};
