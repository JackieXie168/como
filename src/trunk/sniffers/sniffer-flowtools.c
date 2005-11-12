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
#include <assert.h>

#include "sniffers.h"
#include "como.h"
#include "comotypes.h"
#include "heap.h"

/*
 * SNIFFER  ---    Flow-tools files
 *
 * Flow-tools files. It requires the flow-tools and zlib library to be 
 * installed.
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
#define BUFSIZE		(1024*1024)
struct _snifferinfo {
    glob_t in; 			/* result of src->device pattern */
    int curfile; 		/* index of current file in in.gl_pathv */
    heap_t * heap; 		/* heap with flow records read so far */
    timestamp_t last_ts; 	/* last packet timestamp */
    timestamp_t min_ts; 	/* min start time in the heap (root) */
    timestamp_t max_ts; 	/* max start time in the heap */
    timestamp_t window; 	/* min diff between max_ts and min_ts */
    struct ftio ftio;		/* flow-tools I/O data structure */
    char buf[BUFSIZE];		/* buffer used between sniffer-next calls */
    uint nbytes; 		/* bytes used in the buffer */
    int scale; 			/* scaling pkts/bytes for sampled Netflow */
    int iface; 			/* interface of interest (SNMP index) */
    int flags; 			/* options */
}; 


/* sniffer options */
#define FLOWTOOLS_STREAM 	0x01	/* always wait for more files */

/* 
 * This data structure is saved in the heap and contains the flow 
 * information as derived by the flow-tools record. 
 */
struct _flowinfo { 
    pkt_t pkt;			/* next packet that will be generated */
    char payload[48]; 		/* payload (NF + IP + TCP header) */
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
 * -- cookpkt
 * 
 * A flow record defines all pkt_t fields but the timestamp. We fill 
 * in one template to speed up things later on. We put the timestamp of 
 * the beginning of the flow and it will then be modified during the 
 * replay of the flow record. 
 */
static void
cookpkt(struct fts3rec_v5 * f, struct _flowinfo * flow) 
{
    pkt_t * pkt = &flow->pkt; 
    
    pkt->ts = netflow2ts(f, f->First); 
    pkt->len = f->dOctets / f->dPkts;
    pkt->caplen = sizeof(struct _como_nf) + 
		  sizeof(struct _como_iphdr) + 
		  sizeof(struct _como_udphdr);
    pkt->type = COMOTYPE_NF; 
    pkt->l3type = ETHERTYPE_IP; 
    pkt->l4type = f->prot;
    pkt->l3ofs = sizeof(struct _como_nf); 
    pkt->l4ofs = pkt->l3ofs + sizeof(struct _como_iphdr); 
    pkt->payload = flow->payload; 

    /* NetFlow header */
    NF(src_mask) = f->src_mask;
    NF(dst_mask) = f->dst_mask;
    N16(NF(src_as)) = htons(f->src_as);
    N16(NF(dst_as)) = htons(f->dst_as);
    N32(NF(exaddr)) = htonl(f->exaddr);
    N32(NF(nexthop)) = htonl(f->nexthop);
    NF(engine_type) = f->engine_type;
    NF(engine_id) = f->engine_id;
    NF(tcp_flags) = f->tcp_flags;
    N16(NF(input)) = htons(f->input);
    N16(NF(output)) = htons(f->output);


    /* IP header */
    IP(vhl) = 0x45; 
    IP(tos) = f->tos; 
    N16(IP(len)) = htons(f->dOctets / f->dPkts);
    IP(proto) = f->prot; 
    N32(IP(src_ip)) = htonl(f->srcaddr);
    N32(IP(dst_ip)) = htonl(f->dstaddr);

    /* fill the port numbers even if the protocol 
     * is not UDP or TCP... just for simplicity 
     */
    N16(UDP(src_port)) = htons(f->srcport);
    N16(UDP(dst_port)) = htons(f->dstport);
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
flowtools_next(int ofd, char * device, struct _snifferinfo * info) 
{
    int fd; 
    int ret; 

    if (ofd >= 0) {
	/* close current file */
	ftio_close(&info->ftio); 
	close(ofd); 

	/* move to next file */
	info->curfile++;  
    } 
  
    if (info->curfile == (int) info->in.gl_pathc) {
	/*
	 * no files left. check again the input directory to
	 * see if new files are there. if not return 0.
	 */
	ret = glob(device, GLOB_ERR|GLOB_TILDE, NULL, &info->in);
	if (ret != 0) 
	    logmsg(LOGWARN, "sniffer-flowtools: error matching %s: %s\n",
		device, strerror(errno));
	
	return -1;           /* no files to process */
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

    assert(src != NULL); 
    assert(src->ptr != NULL); 

    info = (struct _snifferinfo *) src->ptr; 

    /* get next flow record */
    fr = NULL; 
    if (src->fd >= 0) 
	fr = (struct fts3rec_v5 *) ftio_read(&info->ftio);
    while (fr == NULL) {
	src->fd = flowtools_next(src->fd, src->device, info); 
	if (src->fd < 0) { 
	    /* file is not ready, yet. this is normal if we are streaming
	     * flowtools files. if not it could be an error. in both cases
	     * we return 0 and have sniffer_next() deal with it. 
	     */
	    return 0; 
	} 

	fr = (struct fts3rec_v5 *) ftio_read(&info->ftio);  
	if (fr == NULL) {
	    logmsg(LOGWARN, "error reading flowtools file: %s\n", 
		   strerror(errno));
	    logmsg(0, "moving to next file in the directory\n"); 
	}
    }

    /* 
     * filter out flows that do not cross the interface 
     * of interest. if iface is 0, all flows are of interest. 
     */
    if (info->iface && (info->iface != fr->input && info->iface != fr->output))
	return (netflow2ts(fr, fr->Last));

    /* 
     * scale the bytes/pkts of this record 
     */
    fr->dPkts *= info->scale; 
    fr->dOctets *= info->scale; 

    /* build a new flow record */
    flow = safe_calloc(1, sizeof(struct _flowinfo));
    flow->end_ts = netflow2ts(fr, fr->Last);
    cookpkt(fr, flow); 
    flow->increment = (flow->end_ts - flow->pkt.ts) / fr->dPkts;
    flow->length_last = fr->dOctets % fr->dPkts;

    /* insert in the heap */
    heap_insert(info->heap, flow);

    /* update the max and min timestamps in the heap */
    if (flow->pkt.ts > info->max_ts) 
	info->max_ts = flow->pkt.ts; 
    if (flow->pkt.ts < info->min_ts) 
	info->min_ts = flow->pkt.ts; 

    return flow->pkt.ts; 
}


/* 
 * -- flow_cmp
 * 
 * This is the sorting callback required by the heap service. 
 * It compare the timestamps of the next packets for two Flows, a and b, 
 * and returns (a < b).  
 */
static int
flow_cmp(const void * fa, const void * fb) 
{
    return (((struct _flowinfo*)fa)->pkt.ts < ((struct _flowinfo*)fb)->pkt.ts); 
}


/* 
 * -- configsniffer
 * 
 * process config parameters 
 *
 */
static void 
configsniffer(char * args, struct _snifferinfo * info) 
{
    char * wh; 

    if (args == NULL) 
	return; 

    /*
     * "window". 
     * sets how much ahead in the flow records we need to read 
     * before replaying packets to make sure that no out-of-order 
     * packets will be sent.
     */
    wh = strstr(args, "window");
    if (wh != NULL) {
	char * x = index(wh, '=');      
	if (x == NULL)
	    logmsg(LOGWARN, "sniffer-flowtools: invalid argument %s\n", wh);
	info->window = TIME2TS(atoi(x + 1), 0);
    }

    /* 
     * "scale". 
     * for sampled netflow set the scaling factor we need to apply
     * to the packet and byte count present in the flow record.
     */
    wh = strstr(args, "scale");
    if (wh != NULL) {
	char * x = index(wh, '=');
	if (x == NULL) 
	    logmsg(LOGWARN, "sniffer-flowtools: invalid argument %s\n", wh);
	info->scale = atoi(x + 1);
    }

    /*
     * "iface".
     * for sampled netflow set the scaling factor we need to apply
     * to the packet and byte count present in the flow record.
     */
    wh = strstr(args, "iface");
    if (wh != NULL) {
	char * x = index(wh, '=');
	if (x == NULL)
	    logmsg(LOGWARN, "sniffer-flowtools: invalid argument %s\n", wh);
	info->iface = atoi(x + 1);
    }

    /* 
     * "stream" 
     * streaming mode. the sniffer will wait for more files once done.  
     */
    wh = strstr(args, "stream");
    if (wh != NULL) 
	info->flags |= FLOWTOOLS_STREAM; 
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
    pktdesc_t * p; 
    int ret;

    /* 
     * populate the sniffer specific information
     */
    src->ptr = safe_calloc(1, sizeof(struct _snifferinfo)); 
    info = (struct _snifferinfo *) src->ptr; 
    info->window = TIME2TS(300,0) ; 	/* default window is 5 minutes */
    info->scale = 1;			/* default no scaling */

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
    info->curfile = 0;
    src->fd = flowtools_next(-1, src->device, info); 
    if (src->fd < 0) {
        logmsg(LOGWARN, "sniffer-flowtools: opening %s: %s\n", 
	    info->in.gl_pathv[info->curfile], strerror(errno)); 
	globfree(&info->in);
	free(src->ptr);
	return -1; 
    } 

    /* 
     * set the config values 
     */
    configsniffer(src->args, info);

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
	if (!flowtools_read(src)) 
	    break; 		/* EOF */
    } while (info->max_ts - info->min_ts < info->window);

    info->last_ts = info->min_ts; 

    /*  
     * given that the output stream is not a plain packet 
     * stream, describe it in the source_t data structure 
     */ 
    p = src->output = safe_calloc(1, sizeof(pktdesc_t));
    p->ts = TIME2TS(120, 0);
    p->caplen = sizeof(struct _como_iphdr) + sizeof(struct _como_tcphdr); 
    p->flags = COMO_AVG_PKTLEN; 
    N16(p->ih.len) = 0xffff;
    p->ih.proto = 0xff;
    N32(p->ih.src_ip) = 0xffffffff;
    N32(p->ih.dst_ip) = 0xffffffff;
    N16(p->tcph.src_port) = 0xffff;
    N16(p->tcph.dst_port) = 0xffff;
    p->tcph.flags = 0xff;
    N16(p->udph.src_port) = 0xffff;
    N16(p->udph.dst_port) = 0xffff;
    
    /* this sniffer operates on file and uses a select()able descriptor */
    src->flags = SNIFF_TOUCHED|SNIFF_FILE|SNIFF_SELECT; 
    src->polling = 0; 
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
sniffer_next(source_t * src, pkt_t *out, int max_no) 
{
    struct _snifferinfo * info; 
    pkt_t * pkt; 
    int npkts;                 /* processed pkts */
    
    assert(src != NULL);
    assert(src->ptr != NULL); 
    assert(out != NULL); 

    info = (struct _snifferinfo *) src->ptr; 
    info->nbytes = 0; 

    /* first check if the heap is empty, 
     * if so we are done. 
     */
    if (heap_root(info->heap) == NULL && !(info->flags & FLOWTOOLS_STREAM))
	return -1;  

    for (npkts = 0, pkt = out; npkts < max_no; npkts++, pkt++) {
	struct _flowinfo * flow; 

	/* 
	 * read from flow-tools file so that we have a full info->window 
 	 * of flows in the heap. 
	 */ 
	while (info->max_ts - info->min_ts < info->window) {
	    if (!flowtools_read(src)) { 
		/* 
		 * no more flow records to be read. if we are 
		 * in stream mode, give to CAPTURE whatever we have
	 	 * got so far and try again later. otherwise, process 
		 * the flow records left in the heap. 
		 */
		if (info->flags & FLOWTOOLS_STREAM) { 
		    /* we don't have files to process anymore. write a 
		     * message and sleep for 10 mins. 
		     */
		    assert(src->fd == -1); 
		    logmsg(V_LOGWARN, "sniffing from %s\n", src->device);
		    logmsg(0, "   no more files to read, but want more\n");
		    logmsg(0, "   going to sleed for 10minutes\n");
		    src->polling = TIME2TS(600, 0);
		    src->flags = SNIFF_TOUCHED|SNIFF_FILE|SNIFF_POLL; 
		    return npkts;	
		} 
		break;
	    } else if (src->flags & SNIFF_POLL) { 
		/* 
		 * we have a new file but still in polling mode. 
		 * switch to select() mode to run faster. 
		 */
	        src->flags = SNIFF_TOUCHED|SNIFF_FILE|SNIFF_SELECT; 
	    } 
	}

	/* get the first flow from the heap */
	heap_extract(info->heap, (void **) &flow); 

	/* 
	 * check if we have enough space in the packet buffer 
	 */
	if (BUFSIZE - info->nbytes < flow->pkt.caplen) 
	    break; 

	/* copy the first packet of the flow and update 
	 * the pkt template. note that we cannot just point to the 
	 * packet template because that is due to change (e.g., the 
	 * length of the last packet may be different from all the 
	 * others. 
	 */
	*pkt = flow->pkt; 
	bcopy(pkt->payload, info->buf + info->nbytes, pkt->caplen); 
	pkt->payload = info->buf + info->nbytes; 
	info->nbytes += pkt->caplen; 
	info->last_ts = pkt->ts; 

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

	/* update the minimum timestamp from the root of the heap */
	flow = heap_root(info->heap);
	if (flow == NULL) 
	    break; 		/* we are done; next time we will stop */
	info->min_ts = flow->pkt.ts;

	/* if we have processed more than one second worth of
	 * packets stop and return to CAPTURE so that it can 
 	 * process EXPORT messages, etc. 
	 */
	if (pkt->ts - info->last_ts > TIME2TS(1,0))
	    break; 
    }

    return npkts;
}

/*
 * sniffer_stop
 */
static void
sniffer_stop(source_t * src)
{
    struct _snifferinfo * info = (struct _snifferinfo *) src->ptr; 

    assert(src->ptr != NULL); 
    assert(info->heap != NULL); 

    heap_close(info->heap); 
    if (src->fd > 0) { 
	ftio_close(&info->ftio);
	close(src->fd); 
    } 
    free(src->ptr); 
}


sniffer_t flowtools_sniffer = { 
    "flowtools", sniffer_start, sniffer_next, sniffer_stop
};
