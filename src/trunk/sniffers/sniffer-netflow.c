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

#include <stdlib.h>     /* malloc */
#include <fcntl.h>      /* open */
#include <unistd.h>     /* close */
#include <string.h>     /* memset, memcpy */
#include <errno.h>	/* errno values */
#include <assert.h>
#undef __unused			/* __unused is used in netdb.h */
#include <netdb.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "sniffers.h"
#include "como.h"
#include "comoendian.h"
#include "comotypes.h"
#include "comopriv.h"
#include "corlib.h"

#include "capbuf.c"

#include <ftlib.h>      /* flow-tools stuff 
			 * NOTE: this .h must be included last 
			 */

/*
 * SNIFFER  ---    NetFlow
 *
 * NetFlow datagrams. It requires the flow-tools and zlib library to be 
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

#define NETFLOW_MIN_BUFSIZE	(1024 * 1024)
#define NETFLOW_MAX_BUFSIZE	(NETFLOW_MIN_BUFSIZE * 2)

struct netflow_me {
    sniffer_t		sniff;		/* common fields, must be the first */
    const char *	device;
    timestamp_t		window;		/* lookahead window */
    timestamp_t		timescale;	/* timestamp resolution */ 
    uint16_t		port;		/* socket port */
    uint16_t		sampling;	/* scaling pkts/bytes for sampled
					   Netflow */
    uint16_t		iface;		/* interface of interest (SNMP
					   index) */
    uint32_t		exporter;	/* exporter address to be processed */
    int			flags;		/* options */
    hash_t *		ftch;		/* hash table for demuxing exporters */
    capbuf_t		capbuf;
};


/* sniffer options */
#define NETFLOW_COMPACT	0x02	/* just one packet per flow */

#define NF_PAYLOAD			\
    (sizeof(struct _como_nf) + 		\
     sizeof(struct _como_iphdr) +	\
     sizeof(struct _como_tcphdr)) 
/* 
 * This data structure is saved in the heap and contains the flow 
 * information as derived by the flow-tools record. 
 */
struct _flowinfo { 
    pkt_t pkt;			/* next packet that will be generated */
    char payload[NF_PAYLOAD]; 	/* payload (NF + IP + TCP header) */
    timestamp_t increment; 	/* timestamp increment at each packet */
    uint pkts_left; 		/* packets to be generated */
    uint bytes_left; 		/* bytes to be generated */ 
};

typedef struct ftche_t {
    heap_t *heap;		/* heap with flow records read so far */
    timestamp_t min_ts; 	/* min start time in the heap (root) */
    timestamp_t max_ts; 	/* max start time in the heap */
    struct ftseq ftseq;		/* sequence numbers for this exporter */
} ftche_t;

/* 
 * this macro is used to convert a timestamp in netflow (given by the
 * sysuptime) into a timestamp_t 
 */
static inline timestamp_t 
netflow2ts(struct fts3rec_v5 * f, uint32_t ms)
{
    timestamp_t curtime, uptime, mstime; 

    curtime = TIME2TS(f->unix_secs, f->unix_nsecs/1000); 
    uptime = TIME2TS(f->sysUpTime/1000, (f->sysUpTime%1000)*1000);  
    mstime = TIME2TS(ms/1000, (ms%1000)*1000);
 
    return (curtime + mstime - uptime); 
}


/* 
 * -- update_flowvalues
 * 
 * set the timestamp for the next packet. this function is called
 * only when running in NETFLOW_COMPACT mode for which we need to 
 * split a flow in multiple pieces according to the value of 
 * info->timescale (i.e. if the flow is 5 minute long but the timescale
 * is just 60secs we will split it in 5 flows 60 second long and assume
 * an equal number of packets and bytes in each flow).  
 *
 */
static void
update_flowvalues(pkt_t * pkt, struct _flowinfo * flow, timestamp_t timescale) 
{
    timestamp_t duration; 
    timestamp_t length; 
    uint pkts; 

    length = timescale - COMO(ts) % timescale; 
    length = MIN(length, flow->increment * (flow->pkts_left - 1));
    pkts = flow->increment? (length / flow->increment + 1) : 1; 

    
    /*
     * check if this is the last packet we generate to 
     * make sure it contains all bytes left. 
     * 
     * if this is not possible because the number of bytes left is not 
     * a multiple of the packet count we are forced to reduce the 
     * pktcount in this packet (when in compact mode) or to increase 
     * the packet length in packet mode. 
     *  
     */
    if (flow->pkts_left == pkts) { 
        if (flow->pkts_left * COMO(len) < flow->bytes_left) { 
	    if (flow->pkts_left == 1) 
		COMO(len) = flow->bytes_left; 
	    else 
	        pkts--; 
	} else if (flow->pkts_left * COMO(len) > flow->bytes_left) { 
	    panicx("incorrect flow - pkts: %d, len: %d, bytes: %d < %d", 
		flow->pkts_left, COMO(len), flow->bytes_left, 
		flow->pkts_left * COMO(len)); 
	} 
    } 

    N32(NF(pktcount)) = htonl(pkts); 
    duration = (pkts - 1) * flow->increment; 
    N32(NF(duration)) = htonl(TS2SEC(duration) * 1000 + TS2MSEC(duration)); 
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
cookpkt(struct fts3rec_v5 * f, struct _flowinfo * flow, uint16_t sampling) 
{
    pkt_t * pkt = &flow->pkt; 
    
    COMO(ts) = netflow2ts(f, f->First); 
    COMO(len) = f->dOctets / f->dPkts;
    COMO(caplen) = sizeof(struct _como_nf) + 
		  sizeof(struct _como_iphdr) + 
		  sizeof(struct _como_udphdr);
    COMO(type) = COMOTYPE_NF;
    COMO(l2type) = 0;
    COMO(l3type) = ETHERTYPE_IP; 
    COMO(l4type) = f->prot;
    COMO(l2ofs) = COMO(l3ofs) = sizeof(struct _como_nf); 
    COMO(l4ofs) = COMO(l3ofs) + sizeof(struct _como_iphdr); 
    COMO(payload) = flow->payload; 

    /* NetFlow header */
    NF(src_mask) = f->src_mask;
    NF(dst_mask) = f->dst_mask;
    N16(NF(src_as)) = htons(f->src_as);
    N16(NF(dst_as)) = htons(f->dst_as);
//#define LIBFT_BUGGY
#ifdef LIBFT_BUGGY
    N32(NF(exaddr)) = f->exaddr;
#else
    N32(NF(exaddr)) = htonl(f->exaddr);
#endif
    N32(NF(nexthop)) = htonl(f->nexthop);
    NF(engine_type) = f->engine_type;
    NF(engine_id) = f->engine_id;
    NF(tcp_flags) = f->tcp_flags;		/* OR of TCP flags */
    N16(NF(input)) = htons(f->input);
    N16(NF(output)) = htons(f->output);
    N16(NF(sampling)) = htons(sampling); 
    N32(NF(pktcount)) = htonl(1);  
    N32(NF(duration)) = 0; 

    /* IP header */
    IP(version) = 4;	/* version 4 */
    IP(ihl) = 5;	/* header len 20 bytes */
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
 * -- update_pkt
 * 
 * Update the pkt template in the flow record. If this flow
 * has no more packets to send just free the _flowinfo data 
 * structure. Otherwise, insert it back into the heap. 
 * 
 */ 
static void
update_pkt(struct _flowinfo * flow, struct netflow_me * me,
	   ftche_t * ftche) 
{
    pkt_t *pkt = &flow->pkt;

    /* 
     * update the flow counters and destroy this 
     * flow if there are no packets left 
     */
    flow->pkts_left -= H32(NF(pktcount));
    flow->bytes_left -= (H32(NF(pktcount)) * COMO(len));
    if (flow->pkts_left == 0) {
	assert(flow->bytes_left == 0);
	free(flow);
	return; 	/* we are done! */
    } 

    COMO(ts) += H32(NF(pktcount)) * flow->increment;
    COMO(len) = flow->bytes_left / flow->pkts_left;
    if (me->flags & NETFLOW_COMPACT) {
	update_flowvalues(pkt, flow, me->timescale);
    }
    
    heap_insert(ftche->heap, flow);
} 


/* 
 * -- process_record
 * 
 * Store the flow record in the heap. 
 * Returns the start timestsamp of the flow or 0 if no 
 * more flows are available.
 * 
 */ 
timestamp_t 
process_record(struct fts3rec_v5 * fr, struct netflow_me * me,
	       ftche_t * ftche)
{ 
    struct _flowinfo *flow; 

    /* 
     * filter out flows that do not cross the interface 
     * of interest. if iface is 0, all flows are of interest. 
     */
    if (me->iface && (me->iface != fr->input && me->iface != fr->output))
	return netflow2ts(fr, fr->Last);

    /* 
     * check that the information in the flow record is valid 
     */ 
    if (fr->dPkts == 0 || fr->dOctets == 0) { 
	logmsg(V_LOGSNIFFER, "invalid flow record (pkts: %d, bytes: %d)\n", 
	       fr->dPkts, fr->dOctets); 
	return netflow2ts(fr, fr->Last);
    }

    /* build a new flow record */
    flow = safe_calloc(1, sizeof(struct _flowinfo));
    flow->pkts_left = fr->dPkts; 
    flow->bytes_left = fr->dOctets; 
    flow->increment = netflow2ts(fr, fr->Last) - netflow2ts(fr, fr->First);
    flow->increment /= flow->pkts_left; 
    cookpkt(fr, flow, me->sampling); 
    if (me->flags & NETFLOW_COMPACT) {
	update_flowvalues(&flow->pkt, flow, me->timescale);
    }

    /* insert in the heap */
    heap_insert(ftche->heap, flow);

    /* update the max and min timestamps in the heap */
    if (flow->pkt.ts > ftche->max_ts) {
	ftche->max_ts = flow->pkt.ts;
    }
    if (flow->pkt.ts < ftche->min_ts) {
	ftche->min_ts = flow->pkt.ts;
    }

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

static inline ftche_t *
ftche_new()
{
    ftche_t *ftche;
    
    ftche = safe_calloc(1, sizeof(ftche_t));
    ftche->heap = heap_init(flow_cmp, 32);
    ftche->min_ts = ~0;
    ftche->max_ts = 0;
    
    return ftche;
}

static void
ftche_destroy(ftche_t * ftche)
{
    heap_close(ftche->heap);
    free(ftche);
}

/* 
 * -- process_ftpdu
 * 
 * Receive and process a NetFlow PDU. 
 */
static int
process_ftpdu(struct netflow_me * me, ftche_t ** ftche_out)
{
    struct sockaddr_in agent;
    socklen_t addr_len;
    struct ftpdu ftpdu;		/* NetFlow PDU */
    struct fts3rec_v5 *fr;
    ftche_t *ftche;
    int i, n, offset;
    
    *ftche_out = NULL;
    
    addr_len = sizeof(agent);
    memset(&agent, 0, sizeof(agent));
    ftpdu.bused = recvfrom(me->sniff.fd, ftpdu.buf, sizeof(ftpdu.buf),
			   MSG_DONTWAIT,
			   (struct sockaddr *) &agent, &addr_len);
    if (ftpdu.bused <= 0) {
    	if (errno != EAGAIN) {
	    logmsg(LOGWARN, "sniffer-netflow: recvfrom: %s\n",
		   strerror(errno));
    	}
	return -1;
    }

    /* verify integrity, get version */
    if (ftpdu_verify(&ftpdu) < 0) {
	logmsg(LOGWARN, "sniffer-netflow: PDU corrupted\n");
	return 0;
    }
    
    if (ftpdu.ftv.d_version != 5) {
    	logmsg(LOGWARN, "sniffer-netflow: NetFlow V5 required!\n");
	return 0;
    }

    /* if exporter src IP has been configured then make sure it matches */
    if (me->exporter && (me->exporter != agent.sin_addr.s_addr)) {
	/* ignore PDU */
	return 0;
    }
    
    ftche = hash_lookup_ulong(me->ftch, agent.sin_addr.s_addr);
    if (ftche == NULL) {
	ftche = ftche_new();
    	hash_insert_ulong(me->ftch, agent.sin_addr.s_addr, ftche);
    }

    /* verify sequence number */
    if (ftpdu_check_seq(&ftpdu, &ftche->ftseq) < 0) {
	logmsg(LOGSNIFFER, "sniffer-netflow: PDU with wrong sequence number:"
	       "expected: %lu got: %lu lost %lu\n",
	       ftche->ftseq.seq_exp, ftche->ftseq.seq_rcv,
	       ftche->ftseq.seq_lost);
    }

    /* decode */
#ifdef COMO_LITTLE_ENDIAN
    ftpdu.ftd.byte_order = FT_HEADER_LITTLE_ENDIAN;
#else
    ftpdu.ftd.byte_order = FT_HEADER_BIG_ENDIAN;
#endif
    ftpdu.ftd.exporter_ip = agent.sin_addr.s_addr;
    n = fts3rec_pdu_decode(&ftpdu);
    
    /* write decoded flows */
    for (i = 0, offset = 0; i < n; ++i, offset += ftpdu.ftd.rec_size) {
	fr = (struct fts3rec_v5 *) (ftpdu.ftd.buf + offset);
	process_record(fr, me, ftche);
    }
    
    *ftche_out = ftche;
    return 1;
}


/*
 * -- sniffer_init
 * 
 */
static sniffer_t *
sniffer_init(const char * device, const char * args)
{
    struct netflow_me *me;

    me = safe_calloc(1, sizeof(struct netflow_me));

    me->sniff.max_pkts = 8192;
    me->sniff.flags = SNIFF_SELECT;
    me->device = device;
    me->window = TIME2TS(300,0); 	/* default window is 5 minutes */
    me->timescale = me->window; 	/* default timescale is window */
    me->sampling = 1;			/* default no sampling */
    me->port = FT_PORT;

    if (args) { 
	/* process input arguments */
	char *p;

	/*
	 * "port". 
	 * sets the port to which the UDP socket will be bound.
	 */
	if ((p = strstr(args, "port=")) != NULL) {
	    me->port = atoi(p + 5);
	}
	/*
	 * "window". 
	 * sets how much ahead in the flow records we need to read 
	 * before replaying packets to make sure that no out-of-order 
	 * packets will be sent.
	 */
	if ((p = strstr(args, "window=")) != NULL) {
	    me->window = TIME2TS(atoi(p + 7), 0);
	}
	/*
	 * "timescale". 
	 * resolution for timestamps in packets. flows with longer durations
	 * are split with an equal number of packets in each "timescale"
	 * interval. 
	 */
	if ((p = strstr(args, "timescale=")) != NULL) {
	    me->timescale = TIME2TS(atoi(p + 10), 0);
	}
	/* 
	 * "sampling". 
	 * for sampled netflow we need to know the sampling rate applied 
	 * in order to include this information on the packet headers. 
	 * we expect a number that is actually the inverse of the sampling 
	 * rate (i.e., if sampling 1/1000, the value should be 1000). 
	 */
	if ((p = strstr(args, "sampling=")) != NULL) {
	    me->sampling = atoi(p + 9);
	}
	/*
	 * "iface".
	 * select the interface we are interested to process.
	 */
	if ((p = strstr(args, "iface=")) != NULL) {
	    me->iface = atoi(p + 6);
	}
	 /* 
	 * "compact" 
	 * compact mode. generate just the first packet of each flow. 
	 */
	if ((p = strstr(args, "compact")) != NULL) {
	    me->flags |= NETFLOW_COMPACT;
	}
	/* 
	 * "exporter"
	 * select the NetFlow exporter we are listening to. 
	 */ 
	if ((p = strstr(args, "exporter=")) != NULL) {
	    me->exporter = inet_addr(p + 9);
	}
    }

    /* create the capture buffer */
    if (capbuf_init(&me->capbuf, args, NULL, NETFLOW_MIN_BUFSIZE,
		    NETFLOW_MAX_BUFSIZE) < 0)
	goto error;

    return (sniffer_t *) me;
error:
    free(me);
    return NULL;
}


static void
sniffer_setup_metadesc(sniffer_t * s)
{
    struct netflow_me *me = (struct netflow_me *) s;
    metadesc_t *outmd;
    pkt_t *pkt;

    /* setup output descriptor */
    outmd = metadesc_define_sniffer_out(s, 0);
    //outmd = metadesc_define_sniffer_out(src, 1, "sampling_rate");
    
    outmd->ts_resolution = TIME2TS(me->timescale, 0);
    outmd->flags = META_PKT_LENS_ARE_AVERAGED;
    if (me->flags & NETFLOW_COMPACT) 
	outmd->flags |= META_PKTS_ARE_FLOWS;
    
    /* NOTE: templates defined from more generic to more restrictive */
    pkt = metadesc_tpl_add(outmd, "nf:none:~ip:none");
    COMO(caplen) = sizeof(struct _como_nf) +
		   sizeof(struct _como_iphdr);
    N16(IP(len)) = 0xffff;
    IP(proto) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    
    pkt = metadesc_tpl_add(outmd, "nf:none:~ip:~tcp");
    COMO(caplen) = sizeof(struct _como_nf) +
		   sizeof(struct _como_iphdr) +
		   sizeof(struct _como_tcphdr);
    N16(IP(len)) = 0xffff;
    IP(proto) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    N16(TCP(src_port)) = 0xffff;
    N16(TCP(dst_port)) = 0xffff;
    
    pkt = metadesc_tpl_add(outmd, "nf:none:~ip:~udp");
    COMO(caplen) = sizeof(struct _como_nf) +
		   sizeof(struct _como_iphdr) +
		   sizeof(struct _como_udphdr);
    N16(IP(len)) = 0xffff;
    IP(proto) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    N16(UDP(src_port)) = 0xffff;
    N16(UDP(dst_port)) = 0xffff;
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
sniffer_start(sniffer_t * s) 
{
    struct netflow_me *me = (struct netflow_me *) s;
    struct sockaddr_in loc_addr;

    /* create a socket */
    me->sniff.fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (me->sniff.fd < 0) {
	logmsg(LOGWARN, "sniffer-netflow: can't create socket: %s\n",
	       strerror(errno));
	goto error;
    }

    memset((char *) &loc_addr, 0, sizeof(loc_addr));
    loc_addr.sin_family = AF_INET;
    loc_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    loc_addr.sin_port = htons(me->port);

    if (me->device && strlen(me->device) > 0) {
	struct hostent *bindinfo;
	bindinfo = gethostbyname(me->device);
	if (bindinfo) {
	    loc_addr.sin_addr = *((struct in_addr *) bindinfo->h_addr);
	} else {
	    logmsg(LOGWARN,
		   "sniffer-netflow: unresolved ip address %s: %s\n",
		   me->device, strerror(h_errno));
	    goto error;
	}
    }

    /* unicast bind -- no multicast support */
    if (bind(me->sniff.fd, (struct sockaddr *) &loc_addr,
	sizeof(loc_addr)) < 0) {
	logmsg(LOGWARN, "sniffer-netflow: can't bind socket: %s\n",
	       strerror(errno));
	goto error;
    }
    
    /* initialize the hash table for demuxing exporters */
    me->ftch = hash_new_full(allocator_safe(), HASHKEYS_ULONG, NULL, NULL,
			     NULL, (destroy_notify_fn) ftche_destroy);

    return 0;
error:
    if (me->sniff.fd >= 0) {
	close(me->sniff.fd);
    }
    return -1;
}


/*
 * -- sniffer_next
 *
 * Fills the outbuf with packets and returns the number of 
 * packet present in the buffer. It returns -1 in case of error. 
 *
 */
static int
sniffer_next(sniffer_t * s, int max_pkts, timestamp_t max_ivl,
	     int * dropped_pkts)
{
    struct netflow_me *me = (struct netflow_me *) s;
    int npkts;                 /* processed pkts */
    int r;
    timestamp_t first_seen;
    ftche_t *ftche;
    
    /* receive and process a NetFlow PDU */
    r = process_ftpdu(me, &ftche);
    if (r <= 0) {
    	return r;
    }

    *dropped_pkts = 0;

    npkts = 0;

    while (npkts < max_pkts) {
	struct _flowinfo *flow; 
	pkt_t *pkt; 

	/* 
	 * check if we have a full info->window of flows in the heap.
	 */ 
	if (ftche == NULL || (ftche->max_ts - ftche->min_ts < me->window)) {
	    /* try to get more data if available */
	    if (process_ftpdu(me, &ftche) == -1) {
		/* break on error, probably EAGAIN */
		break;
	    }
	    /*
	     * a pdu has been either received or discarded, perform the check
	     * again.
	     */
	    continue;
	}

	/* get the first flow from the heap */
	heap_extract(ftche->heap, (void **) &flow); 

	/* reserve the space in the buffer for the packet */
	pkt = (pkt_t *) capbuf_reserve_space(&me->capbuf,
				      sizeof(pkt_t) + flow->pkt.caplen);
	
	/* copy the first packet of the flow and update 
	 * the pkt template. note that we cannot just point to the 
	 * packet template because that is due to change (e.g., the 
	 * length of the last packet may be different from all the 
	 * others. 
	 */
	*pkt = flow->pkt;
	COMO(payload) = (char *) (pkt + 1);
	memcpy(COMO(payload), flow->pkt.payload, COMO(caplen));

	update_pkt(flow, me, ftche);
	
	ppbuf_capture(me->sniff.ppbuf, pkt);

	/* update the minimum timestamp from the root of the heap */
	flow = heap_root(ftche->heap);
	if (flow == NULL) 
	    break; 		/* we are done; next time we will stop */
	ftche->min_ts = flow->pkt.ts;

	/* if we have processed more than max_ivl worth of
	 * packets stop and return to CAPTURE so that it can 
 	 * process EXPORT messages, etc. 
	 */
	if (npkts > 0) {
	    if (COMO(ts) - first_seen > max_ivl) {
		break;
	    }
	} else {
	    first_seen = COMO(ts);
	}

	npkts++;
    }

    return 0;
}


/*
 * sniffer_stop
 * 
 * free the heap structure and all sniffer data structure. 
 */
static void
sniffer_stop(sniffer_t * s)
{
    struct netflow_me *me = (struct netflow_me *) s;
    
    hash_destroy(me->ftch);
    close(me->sniff.fd); 
}


static void
sniffer_finish(sniffer_t * s)
{
    struct netflow_me *me = (struct netflow_me *) s;

    capbuf_finish(&me->capbuf);
    free(me);
}


SNIFFER(netflow) = {
    name: "netflow",
    init: sniffer_init,
    finish: sniffer_finish,
    setup_metadesc: sniffer_setup_metadesc,
    start: sniffer_start,
    next: sniffer_next,
    stop: sniffer_stop,
};
