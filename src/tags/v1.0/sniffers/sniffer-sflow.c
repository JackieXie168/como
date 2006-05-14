/*
 * Copyright (c) 2006 Intel Corporation
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


/* 
 * This sniffer support sFlow(R) datagrams for Version 4 and 5 as 
 * specified in IETF RFC 3176 or in http://www.sflow.org/sflow_version_5.txt. 
 * 
 * sFlow is a trademark of InMon Corporation.
 * 
 * For sFlow(R) licensing details please refer to 
 * http://www.inmon.com/technology/sflowlicense.txt
 *
 */

#include <stdlib.h>		/* malloc */
#include <fcntl.h>		/* open */
#include <unistd.h>		/* close */
#include <string.h>		/* memset, memcpy */
#include <errno.h>		/* errno values */
#include <assert.h>
#include <sys/types.h>
#include <time.h>
#include <stdio.h>
#undef __unused			/* __unused is used in netdb.h */
#include <netdb.h>

#ifdef WIN32
#include "winsock2.h"
#else
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#endif

#include "sniffers.h"
#include "como.h"
#include "comotypes.h"

#include "sflow.h"		/* sFlow v5 */

enum sf_err {
    SF_OK = 0,
    SF_ABORT_EOS = 1,
    SF_ABORT_DECODE_ERROR = 2,
    SF_ABORT_LENGTH_ERROR = 3,
    SF_ABORT_RECV_ERROR = 4
};

typedef struct _SFCursor {
    u_char *buf;
    u_char *end;
    uint32_t *cur;
    uint32_t len;
    int err;
} SFCursor;

typedef struct _SFDatagram {
    SFCursor sc;
    uint32_t buf_length;
    SFLSample_datagram_hdr hdr;
} SFDatagram;

typedef struct _SFTag {
    SFCursor sc;
    uint32_t type;
    SFDatagram *dg;
} SFTag;

/* 
 * define SNIFFER_SFLOW_DEBUG to enable debug information
 */
/* #define SNIFFER_SFLOW_DEBUG */
#ifdef SNIFFER_SFLOW_DEBUG
#define sf_log(format...)	logmsg(LOGDEBUG, format)
#else
#define sf_log(format...)
#endif
#define sf_warning(format...)	logmsg(LOGWARN, format)


static __inline__ uint32_t
sf_read32(SFCursor * c)
{
    return ntohl(*(c->cur)++);
}

static __inline__ void
sf_copy(SFCursor * c, void *dest, size_t n)
{
    memcpy(dest, c->cur, n);
    c->cur = (uint32_t *) ((u_char *) c->cur + n);
}

static __inline__ void
sf_skip_bytes(SFCursor * c, int skip)
{
    int quads = (skip + 3) / 4;

    c->cur += quads;
}

static __inline__ int
sf_check(SFCursor * c)
{
    if ((u_char *) c->cur > c->end)
	c->err = SF_ABORT_EOS;
    return c->err;
}

static int
sflow_datagram_read(int fd, SFDatagram * dg)
{
    struct sockaddr_in agent;
    socklen_t addr_len;
    int bytes;
    SFCursor *sc = (SFCursor *) dg;

    addr_len = sizeof(agent);
    memset(&agent, 0, sizeof(agent));
    bytes = recvfrom(fd, sc->buf, (size_t) dg->buf_length, 0,
		     (struct sockaddr *) &agent, &addr_len);
    if (bytes <= 0) {
	sf_warning("sniffer-sflow: recvfrom() failed: %s\n", strerror(errno));
	sc->err = SF_ABORT_RECV_ERROR;
	return SF_ABORT_RECV_ERROR;
    }
    sc->len = bytes;
    sc->cur = (uint32_t *) sc->buf;
    sc->end = ((u_char *) sc->cur) + sc->len;
    sc->err = SF_OK;

    return SF_OK;
}

static int
sflow_datagram_decode_hdr(SFDatagram * dg)
{
    /* check the version */
    dg->hdr.datagram_version = sf_read32((SFCursor *) dg);
    sf_log("datagramVersion %d\n", dg->hdr.datagram_version);

    if (dg->hdr.datagram_version != 2 &&
	dg->hdr.datagram_version != 4 && dg->hdr.datagram_version != 5) {
	sf_warning("unexpected datagram version number\n");
	dg->sc.err = SF_ABORT_DECODE_ERROR;
	return SF_ABORT_DECODE_ERROR;
    }

    /* get the agent address */
    dg->hdr.agent_address.type = sf_read32((SFCursor *) dg);
    if (dg->hdr.agent_address.type == SFLADDRESSTYPE_IP_V4) {
	sf_copy((SFCursor *) dg,
		&dg->hdr.agent_address.address.ip_v4.s_addr, 4);
    } else {
	sf_copy((SFCursor *) dg,
		&dg->hdr.agent_address.address.ip_v6.s6_addr, 16);
    }

    /* version 5 has an agent sub-id as well */
    if (dg->hdr.datagram_version == 5) {
	dg->hdr.sub_agent_id = sf_read32((SFCursor *) dg);
    }

    /* this is the packet sequence number */
    dg->hdr.sequence_number = sf_read32((SFCursor *) dg);
    dg->hdr.uptime = sf_read32((SFCursor *) dg);
    dg->hdr.num_records = sf_read32((SFCursor *) dg);

    return sf_check((SFCursor *) dg);
}

static int
sflow_datagram_next_tag(SFDatagram * dg, SFTag * tag)
{
    tag->sc.buf = (u_char *) dg->sc.cur;
    tag->type = sf_read32((SFCursor *) dg);
    tag->sc.len = sf_read32((SFCursor *) dg);
    tag->sc.cur = dg->sc.cur;	/* actually tag->sc.buf + 2*sizeof(uint32_t) */
    tag->sc.end = ((u_char *) tag->sc.cur) + tag->sc.len;
    tag->dg = dg;
    sf_skip_bytes((SFCursor *) dg, tag->sc.len);

    return sf_check((SFCursor *) dg);
}

static int
sflow_tag_decode_flow_sample(SFTag * tag, SFLFlow_sample * fs)
{
    fs->sequence_number = sf_read32((SFCursor *) tag);
    fs->source_id = sf_read32((SFCursor *) tag);
    fs->sampling_rate = sf_read32((SFCursor *) tag);
    sf_log("sampling_rate %d\n", fs->sampling_rate);
    fs->sample_pool = sf_read32((SFCursor *) tag);
    sf_log("sample_pool %d\n", fs->sample_pool);
    fs->drops = sf_read32((SFCursor *) tag);
    fs->input = sf_read32((SFCursor *) tag);
    fs->output = sf_read32((SFCursor *) tag);
    fs->num_elements = sf_read32((SFCursor *) tag);
    fs->elements = NULL;	/* not used as no memory is allocated here */

    return sf_check((SFCursor *) tag);
}

static int
sflow_tag_decode_flow_sample_expanded(SFTag * tag,
				      SFLFlow_sample_expanded * fse)
{
    fse->sequence_number = sf_read32((SFCursor *) tag);
    fse->ds_class = sf_read32((SFCursor *) tag);
    fse->ds_index = sf_read32((SFCursor *) tag);
    fse->sampling_rate = sf_read32((SFCursor *) tag);
    fse->sample_pool = sf_read32((SFCursor *) tag);
    fse->drops = sf_read32((SFCursor *) tag);
    fse->inputFormat = sf_read32((SFCursor *) tag);
    fse->input = sf_read32((SFCursor *) tag);
    fse->outputFormat = sf_read32((SFCursor *) tag);
    fse->output = sf_read32((SFCursor *) tag);
    fse->num_elements = sf_read32((SFCursor *) tag);
    fse->elements = NULL;	/* not used as no memory is allocated here */

    return sf_check((SFCursor *) tag);
}

static int
sflow_read_flow_sample_header(SFTag * tag, SFLFlow_sample_element * el)
{
    sf_log("flowSampleType HEADER\n");
    el->flowType.header.header_protocol = sf_read32((SFCursor *) tag);
    sf_log("headerProtocol %lu\n", el->flowType.header.header_protocol);
    el->flowType.header.frame_length = sf_read32((SFCursor *) tag);
    sf_log("sampledPacketSize %lu\n", el->flowType.header.frame_length);
    if (tag->dg->hdr.datagram_version > 4) {
	/* stripped count introduced in sFlow version 5 */
	el->flowType.header.stripped = sf_read32((SFCursor *) tag);
	sf_log("strippedBytes %lu\n", el->flowType.header.stripped);
    }
    el->flowType.header.header_length = sf_read32((SFCursor *) tag);
    sf_log("headerLen %lu\n", el->flowType.header.header_length);

    /* just point at the header */
    el->flowType.header.header_bytes = (u_int8_t *) tag->sc.cur;
    sf_skip_bytes((SFCursor *) tag, el->flowType.header.header_length);

    return sf_check((SFCursor *) tag);
}

static int
sflow_read_flow_sample_ethernet(SFTag * tag, SFLFlow_sample_element * el)
{
    sf_log("flowSampleType ETHERNET\n");
    el->flowType.ethernet.eth_len = sf_read32((SFCursor *) tag);
    sf_copy((SFCursor *) tag, el->flowType.ethernet.src_mac, 6);
    sf_copy((SFCursor *) tag, el->flowType.ethernet.dst_mac, 6);
    el->flowType.ethernet.eth_type = sf_read32((SFCursor *) tag);

    sf_log("ethernet_type %lu\n", el->flowType.ethernet.eth_type);
    sf_log("ethernet_len %lu\n", el->flowType.ethernet.eth_len);

#ifdef SNIFFER_SFLOW_DEBUG
    {
	char *p;

	p = el->flowType.ethernet.src_mac;
	sf_log("ethernet_src %02x%02x%02x%02x%02x%02x\n", p[0], p[1],
	       p[2], p[3], p[4], p[5]);
	p = el->flowType.ethernet.dst_mac;
	sf_log("ethernet_dst %02x%02x%02x%02x%02x%02x\n", p[0], p[1],
	       p[2], p[3], p[4], p[5]);
    }
#endif

    return sf_check((SFCursor *) tag);
}

static int
sflow_read_flow_sample_ipv4(SFTag * tag, SFLFlow_sample_element * el)
{
    sf_log("flowSampleType IPV4\n");
    el->flowType.ipv4.length = sf_read32((SFCursor *) tag);
    el->flowType.ipv4.protocol = sf_read32((SFCursor *) tag);
    sf_copy((SFCursor *) tag, &el->flowType.ipv4.src_ip,	/* 4 */
	    sizeof(el->flowType.ipv4.src_ip));
    sf_copy((SFCursor *) tag, &el->flowType.ipv4.dst_ip,	/* 4 */
	    sizeof(el->flowType.ipv4.dst_ip));
    el->flowType.ipv4.src_port = sf_read32((SFCursor *) tag);
    el->flowType.ipv4.dst_port = sf_read32((SFCursor *) tag);
    el->flowType.ipv4.tcp_flags = sf_read32((SFCursor *) tag);
    el->flowType.ipv4.tos = sf_read32((SFCursor *) tag);

    return sf_check((SFCursor *) tag);
}

static int
sflow_read_flow_sample_ipv6(SFTag * tag, SFLFlow_sample_element * el)
{
    sf_log("flowSampleType IPV6\n");
    el->flowType.ipv6.length = sf_read32((SFCursor *) tag);
    el->flowType.ipv6.protocol = sf_read32((SFCursor *) tag);
    sf_copy((SFCursor *) tag, &el->flowType.ipv6.src_ip,	/* 16 */
	    sizeof(el->flowType.ipv6.src_ip));
    sf_copy((SFCursor *) tag, &el->flowType.ipv4.dst_ip,	/* 16 */
	    sizeof(el->flowType.ipv6.dst_ip));
    el->flowType.ipv6.src_port = sf_read32((SFCursor *) tag);
    el->flowType.ipv6.dst_port = sf_read32((SFCursor *) tag);
    el->flowType.ipv6.tcp_flags = sf_read32((SFCursor *) tag);
    el->flowType.ipv6.priority = sf_read32((SFCursor *) tag);

    return sf_check((SFCursor *) tag);
}

static int
sflow_tag_next_flow_sample(SFTag * tag, SFLFlow_sample_element * el)
{
    el->tag = sf_read32((SFCursor *) tag);
    el->length = sf_read32((SFCursor *) tag);
    switch (el->tag) {
    case SFLFLOW_HEADER:
	return sflow_read_flow_sample_header(tag, el);
    case SFLFLOW_ETHERNET:
	return sflow_read_flow_sample_ethernet(tag, el);
    case SFLFLOW_IPV4:
	return sflow_read_flow_sample_ipv4(tag, el);
    case SFLFLOW_IPV6:
	return sflow_read_flow_sample_ipv6(tag, el);
	/*case SFLFLOW_EX_SWITCH:
	   case SFLFLOW_EX_ROUTER:
	   case SFLFLOW_EX_GATEWAY:
	   case SFLFLOW_EX_USER:
	   case SFLFLOW_EX_URL:
	   case SFLFLOW_EX_MPLS:
	   case SFLFLOW_EX_NAT:
	   case SFLFLOW_EX_MPLS_TUNNEL:
	   case SFLFLOW_EX_MPLS_VC:
	   case SFLFLOW_EX_MPLS_FTN:
	   case SFLFLOW_EX_MPLS_LDP_FEC:
	   case SFLFLOW_EX_VLAN_TUNNEL:
	   case SFLFLOW_EX_PROCESS: */
    default:
	sf_skip_bytes((SFCursor *) tag, el->length);
	break;
    }

    return sf_check((SFCursor *) tag);
}

 /*
  * This data structure will be stored in the source_t structure and 
  * used for successive callbacks.
  */
struct _snifferinfo {
    uint16_t port;		/* socket port */
    uint32_t last_sn;		/* last sample packet sequence number */
    uint32_t first_sn;		/* first sample packet sequence number */
    timestamp_t last_ts;	/* last datagram timestamp */
    u_int32_t flow_type_tag;	/* SFLFlow_type_tag */
#define BUFSIZE		65536	/* sflow is not going to give us more bytes
				 * than 65K
				 */
    char pktbuf[BUFSIZE];	/* packet buffer */
};

/* 
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
     * "port". 
     * sets the port to which the UDP socket will be bound.
     */
    wh = strstr(args, "port");
    if (wh != NULL) {
	char *x = index(wh, '=');

	if (x == NULL)
	    logmsg(LOGWARN, "sniffer-sflow: invalid argument %s\n", wh);
	else
	    info->port = atoi(x + 1);
    }

    /*
     * "flow_type_tag". 
     * sets the flow type tag the sflow agent is configured to send
     */
    wh = strstr(args, "flow_type_tag");
    if (wh != NULL) {
	char *x = index(wh, '=');

	if (x == NULL)
	    logmsg(LOGWARN, "sniffer-sflow: invalid argument %s\n", wh);
	else {
	    if (strcasecmp("HEADER", x + 1) == 0) {
		info->flow_type_tag = SFLFLOW_HEADER;
	    } else if (strcasecmp("ETHERNET", x + 1) == 0) {
		info->flow_type_tag = SFLFLOW_ETHERNET;
	    } else if (strcasecmp("IPV4", x + 1) == 0) {
		info->flow_type_tag = SFLFLOW_IPV4;
	    } else if (strcasecmp("IPV6", x + 1) == 0) {
		info->flow_type_tag = SFLFLOW_IPV6;
	    }
	}

    }
}

/*
 * -- sniffer_start
 * 
 * this sniffer opens a UDP socket and expects to receive
 * sflow sample datagrams over it.
 * It returns 0 in case of success, -1 in case of failure.
 */
static int
sniffer_start(source_t * src)
{
    struct _snifferinfo *info;
    int fd;
    struct sockaddr_in addr_in;
    struct hostent *bindinfo;
    metadesc_t *outmd;
    pkt_t *pkt;

    sf_log("sflow start\n");

    assert(src->ptr == NULL);

    /* 
     * populate the sniffer specific information
     */
    src->ptr = safe_calloc(1, sizeof(struct _snifferinfo));
    info = (struct _snifferinfo *) src->ptr;
    src->fd = -1;
    /* defult port as assigned by IANA */
    info->port = SFL_DEFAULT_COLLECTOR_PORT;
    info->first_sn = 0;
    info->last_sn = 0xFFFFFFFF;
    info->last_ts = 0;
    info->flow_type_tag = SFLFLOW_HEADER;

    sniffer_config(src->args, info);

    /* this sniffer operates on socket and uses a select()able descriptor */
    src->flags = SNIFF_TOUCHED | SNIFF_SELECT;
    src->polling = 0;

    /* create a socket */
    if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
	logmsg(LOGWARN, "sniffer-sflow: can't create socket: %s\n",
	       strerror(errno));
	goto error;
    }

    memset((char *) &addr_in, 0, sizeof(struct sockaddr_in));
    addr_in.sin_family = AF_INET;
    addr_in.sin_addr.s_addr = INADDR_ANY;
    addr_in.sin_port = htons(info->port);

    if (src->device && strlen(src->device) > 0) {
	bindinfo = gethostbyname(src->device);
	if (bindinfo) {
	    addr_in.sin_addr = *((struct in_addr *) bindinfo->h_addr);
	} else {
	    logmsg(LOGWARN,
		   "sniffer-sflow: unresolved ip address: %s: %s\n",
		   src->device, strerror(h_errno));
	    goto error;
	}
    }

    /* CHECKME: do we need to set some socket options? */

    /* bind the socket */
    if (bind(fd, (struct sockaddr *) &addr_in, sizeof(struct sockaddr_in))
	== -1) {
	logmsg(LOGWARN, "sniffer-sflow: can't bind socket: %s\n",
	       strerror(errno));
	goto error;
    }

    src->fd = fd;

    /* setup output descriptor */
    outmd = metadesc_define_sniffer_out(src, 1, "sampling_rate");
    
    outmd->ts_resolution = TIME2TS(1, 0);
    
    switch (info->flow_type_tag) {
    case SFLFLOW_HEADER:
	pkt = metadesc_tpl_add(outmd, "sflow:any:any:any");
	COMO(caplen) = 0xffff;
	break;
    case SFLFLOW_ETHERNET:
	pkt = metadesc_tpl_add(outmd, "sflow:eth:none:none");
	COMO(caplen) = sizeof(struct _como_eth);
	break;
    case SFLFLOW_IPV4:
	/* NOTE: templates defined from more generic to more restrictive */
	pkt = metadesc_tpl_add(outmd, "sflow:none:~ip:none");
	COMO(caplen) = sizeof(struct _como_iphdr);
	IP(tos) = 0xff;
	N16(IP(len)) = 0xffff;
	IP(proto) = 0xff;
	N32(IP(src_ip)) = 0xffffffff;
	N32(IP(dst_ip)) = 0xffffffff;
	
	pkt = metadesc_tpl_add(outmd, "sflow:none:~ip:~tcp");
	COMO(caplen) = sizeof(struct _como_iphdr) +
		       sizeof(struct _como_tcphdr);
	IP(tos) = 0xff;
	N16(IP(len)) = 0xffff;
	IP(proto) = 0xff;
	N32(IP(src_ip)) = 0xffffffff;
	N32(IP(dst_ip)) = 0xffffffff;
	N16(TCP(src_port)) = 0xffff;
	N16(TCP(dst_port)) = 0xffff;
	TCP(cwr) = 1;
	TCP(ece) = 1;
	TCP(urg) = 1;
	TCP(ack) = 1;
	TCP(psh) = 1;
	TCP(rst) = 1;
	TCP(syn) = 1;
	TCP(fin) = 1;
	
	pkt = metadesc_tpl_add(outmd, "sflow:none:~ip:~udp");
	COMO(caplen) = sizeof(struct _como_iphdr) +
		       sizeof(struct _como_udphdr);
	IP(tos) = 0xff;
	N16(IP(len)) = 0xffff;
	IP(proto) = 0xff;
	N32(IP(src_ip)) = 0xffffffff;
	N32(IP(dst_ip)) = 0xffffffff;
	N16(UDP(src_port)) = 0xffff;
	N16(UDP(dst_port)) = 0xffff;
	break;
    case SFLFLOW_IPV6:
	/* TODO */
	logmsg(LOGWARN, "IPV6 not supported\n");
	goto error;
    }

    return 0;
  error:
    free(src->ptr);
    src->ptr = NULL;

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
sniffer_next(source_t * src, pkt_t * out, int max_no)
{
/*
 * CHECKME: To be sure no packet loss happens max_no should be >= 2350.
 * Can we assume max_no is always greater than that?
 * Otherwise we need to keep packets in sniffer's pktbuf but that involves
 * more work and I don't believe it's necessary to have a pkt buffer manager
 * here that could anyway loss packets.
 * Plus capture is not going to call sniffer next unless a datagram is
 * received, so either the local pkt buffer becomes full and we lose packets or
 * we delay the new datagram avoiding the call to recvfrom. In the latter case
 * however it's the OS buffer that becomes full and the kernel start dropping
 * datagrams.
 * In the end it's better to process more packets and at the moment capture can
 * receive up to 8192 packets every sniffer.
 * So what's the need to keep packets here?
 * Obviously this must be retought if another design that involves different
 * packet consumption times is implemented.
 */
    struct _snifferinfo *info;
    pkt_t *pkt;
    int npkts;			/* processed pkts */

#define MAX_PKT_SIZ 65536
    u_char buf[MAX_PKT_SIZ];
    int nbytes = 0;
    uint32_t t;			/* index for sflow samples */
    struct timeval now;

    SFDatagram dg;
    SFTag tag;

    struct _como_sflow como_sflow_hdr;

    assert(src != NULL);
    assert(src->ptr != NULL);
    assert(out != NULL);

    sf_log("sflow next\n");

    info = (struct _snifferinfo *) src->ptr;

    memset(&dg, 0, sizeof(dg));
    dg.sc.buf = buf;
    dg.buf_length = MAX_PKT_SIZ;

    if (sflow_datagram_read(src->fd, &dg) != SF_OK) {
	/* an error here cannot be ignored, return with -1 */
	return -1;
    }

    if (sflow_datagram_decode_hdr(&dg) != SF_OK) {
	/* received a bad sflow datagram: ignoring */
	return 0;
    }

    /* NOTE: only IPv4 address is considered */
    N32(como_sflow_hdr.agent_address) =
	dg.hdr.agent_address.address.ip_v4.s_addr;
    N32(como_sflow_hdr.sub_agent_id) = htonl(dg.hdr.sub_agent_id);

    /*
     * timestamp handling
     * sFlow is real time traffic reporting protocol so we just assume the flow
     * sample elements contained in the datagram have been sampled within the
     * last second and we set all packet timestamps to current system time
     */
    gettimeofday(&now, NULL);
    info->last_ts = TIME2TS(now.tv_sec, now.tv_usec);

    if (info->first_sn == 0 && info->last_sn == 0xFFFFFFFF) {
	info->first_sn = dg.hdr.sequence_number;
    } else if (info->last_sn >= dg.hdr.sequence_number
	       && dg.hdr.sequence_number > info->first_sn) {
	logmsg(LOGWARN,
	       "sniffer-sflow: received sflow datagram with a lower sequence "
	       "number than expected\n");
	return 0;
    }

    /* remember datagram sequence number */
    info->last_sn = dg.hdr.sequence_number;

    if (info->last_sn < info->first_sn)
	info->first_sn = info->last_sn;

    for (t = 0, npkts = 0, pkt = out;
	 t < dg.hdr.num_records && npkts < max_no; t++) {
	uint32_t num_elements;

	if (sflow_datagram_next_tag(&dg, &tag) != SF_OK)
	    break;

	if (tag.type == SFLFLOW_SAMPLE) {
	    SFLFlow_sample fs;

	    if (sflow_tag_decode_flow_sample(&tag, &fs) != SF_OK)
		break;
	    num_elements = fs.num_elements;

	    N32(como_sflow_hdr.ds_class) = htonl(fs.source_id >> 24);
	    N32(como_sflow_hdr.ds_index) = htonl(fs.source_id & 0x00ffffff);
	    N32(como_sflow_hdr.sampling_rate) = htonl(fs.sampling_rate);
	    N32(como_sflow_hdr.sample_pool) = htonl(fs.sample_pool);
	    N32(como_sflow_hdr.inputFormat) = htonl(fs.input >> 30);
	    N32(como_sflow_hdr.input) = htonl(fs.input & 0x3fffffff);
	    N32(como_sflow_hdr.outputFormat) = htonl(fs.output >> 30);
	    N32(como_sflow_hdr.output) = htonl(fs.output & 0x3fffffff);
	}

	if (tag.type == SFLFLOW_SAMPLE_EXPANDED) {
	    SFLFlow_sample_expanded fse;

	    if (sflow_tag_decode_flow_sample_expanded(&tag, &fse) != SF_OK)
		break;
	    num_elements = fse.num_elements;

	    N32(como_sflow_hdr.ds_class) = htonl(fse.ds_class);
	    N32(como_sflow_hdr.ds_index) = htonl(fse.ds_index);
	    N32(como_sflow_hdr.sampling_rate) = htonl(fse.sampling_rate);
	    N32(como_sflow_hdr.sample_pool) = htonl(fse.sample_pool);
	    N32(como_sflow_hdr.inputFormat) = htonl(fse.inputFormat);
	    N32(como_sflow_hdr.input) = htonl(fse.input);
	    N32(como_sflow_hdr.outputFormat) = htonl(fse.outputFormat);
	    N32(como_sflow_hdr.output) = htonl(fse.output);
	}

	/*
	 * FLOW samples are elaborated while COUNTERS samples are ignored
	 */
	if (tag.type == SFLFLOW_SAMPLE || tag.type == SFLFLOW_SAMPLE_EXPANDED) {
	    SFLFlow_sample_element el;
	    uint32_t eli;

	    for (eli = 0; eli < num_elements; eli++) {
		if (sflow_tag_next_flow_sample(&tag, &el) != SF_OK)
		    break;

		/*
		 * only consider full packet headers or ethernet or ipv4 or
		 * ipv6 headers
		 */
		if (el.tag != SFLFLOW_HEADER &&
		    el.tag != SFLFLOW_ETHERNET &&
		    el.tag != SFLFLOW_IPV4 && el.tag != SFLFLOW_IPV6)
		    continue;

		/* point the packet payload to next packet */
		COMO(payload) = info->pktbuf + nbytes;

		/* set the timestamp */
		COMO(ts) = info->last_ts;

		/* set packet type */
		COMO(type) = COMOTYPE_SFLOW;

		/* add sflow header to packet */
		memcpy(COMO(payload), &como_sflow_hdr,
		       sizeof(struct _como_sflow));
		COMO(caplen) = sizeof(struct _como_sflow);
		
		/* no options since here */
		COMO(pktmetaslen) = 0;

		/* set layer 2 and 3 to start after sflow header */
		COMO(l2ofs) = sizeof(struct _como_sflow);
		COMO(l3ofs) = sizeof(struct _como_sflow);

		switch (el.tag) {
		case SFLFLOW_HEADER:
		    /*
		     * have got a full header, now copy it into pktbuf and set
		     * cap_len and len properly
		     */
		    COMO(caplen) += el.flowType.header.header_length;

		    /* CHECKME: should stripped bytes be summed to this */
		    COMO(len) = el.flowType.header.frame_length;
		    memcpy(COMO(payload) + COMO(l2ofs),
			   el.flowType.header.header_bytes,
			   el.flowType.header.header_length);
		    switch (el.flowType.header.header_protocol) {
		    case SFLHEADER_ETHERNET_ISO8023:
			/*
			 * update layer 2 information and offsets of layer 3
			 * and above.
			 */
			updateofs(pkt, L2, LINKTYPE_ETH);
			break;
		    case SFLHEADER_IPv4:
			/*
			 * there's nothing at layer 2, the packet starts with
			 * ip header
			 */
			updateofs(pkt, L3, ETHERTYPE_IP);
			break;
		    case SFLHEADER_IPv6:
			/*
			 * there's nothing at layer 2, the packet starts with
			 * ip v6 header
			 */
			updateofs(pkt, L3, ETHERTYPE_IPV6);
			break;
		    default:
			/*
			 * FIXME: what to do here?
			 */
			COMO(l2type) = 0;
			break;
		    }
		    break;
		case SFLFLOW_ETHERNET:
		    /*
		     * only the ethernet header is available in a
		     * SFLSampled_ethernet structure need to copy structure
		     * fields into pktbuf to make it a valid ethernet header
		     */
		    COMO(caplen) += sizeof(struct _como_eth);
		    /*
		     * CHECKME: eth_len doesn't contain MAC encapsulation
		     * (does it include ethernet header?)
		     */
		    COMO(len) = el.flowType.ethernet.eth_len;
		    memcpy(COMO(payload) + COMO(l2ofs),
			   el.flowType.ethernet.dst_mac, 6);
		    memcpy(COMO(payload) + COMO(l2ofs) + 6,
			   el.flowType.ethernet.src_mac, 6);
		    N16(ETH(type)) = htons(el.flowType.ethernet.eth_type);
		    updateofs(pkt, L2, LINKTYPE_ETH);
		    break;
		case SFLFLOW_IPV4:
		    /*
		     * only some ipv4 header fields are available in a
		     * SFLSampled_ipv4 structure need to copy structure fields
		     * into pktbuf to make it a valid ipv4 header
		     */
		    COMO(caplen) += sizeof(struct _como_iphdr);
		    /*
		     * CHECKME: We don't know the lower layer, can we assume a
		     * minimum encapsulation length?
		     */
		    COMO(len) = el.flowType.ipv4.length;
		    IP(version) = 4;	/* version 4 */
		    IP(ihl) = 5;	/* header len 20 bytes */
		    IP(tos) = (uint8_t) el.flowType.ipv4.tos;
		    N16(IP(len)) = htons((uint16_t) el.flowType.ipv4.length);
		    IP(proto) = (uint8_t) el.flowType.ipv4.protocol;
		    N32(IP(src_ip)) = el.flowType.ipv4.src_ip.s_addr;
		    N32(IP(dst_ip)) = el.flowType.ipv4.dst_ip.s_addr;
		    COMO(l4ofs) = COMO(l3ofs) + sizeof(struct _como_iphdr);
		    switch (el.flowType.ipv4.protocol) {
		    case IPPROTO_TCP:
			COMO(caplen) += sizeof(struct _como_tcphdr);
			N16(TCP(src_port)) =
			    htons((uint16_t) el.flowType.ipv4.src_port);
			N16(TCP(dst_port)) =
			    htons((uint16_t) el.flowType.ipv4.dst_port);
			/* TCP(flags) */
			*(COMO(payload) + COMO(l4ofs) + 13) = el.flowType.ipv4.tcp_flags;
			break;
		    case IPPROTO_UDP:
			COMO(caplen) += sizeof(struct _como_udphdr);
			N16(UDP(src_port)) =
			    htons((uint16_t) el.flowType.ipv4.src_port);
			N16(UDP(dst_port)) =
			    htons((uint16_t) el.flowType.ipv4.dst_port);
			break;
		    }
		    updateofs(pkt, L3, ETHERTYPE_IP);
		    break;
		case SFLFLOW_IPV6:
		    /*
		     * only some ipv6 header are available in a SFLSampled_ipv6
		     * structure need to copy structure fields into pktbuf to
		     * make it a valid ipv6 header
		     */
		    COMO(caplen) += 40;	/* IPv6 header length */
		    /*
		     * CHECKME: We don't know the lower layer, can we assume a
		     * minimum encapsulation length?
		     */
		    COMO(len) = el.flowType.ipv6.length + 40;
		    IPV6(base.vtcfl) =
			htonl((6 << 28) | (el.flowType.ipv6.priority << 20));
		    N16(IPV6(base.len)) = htons(el.flowType.ipv6.length);
		    IPV6(base.nxthdr) = (uint8_t) el.flowType.ipv6.protocol;
		    memcpy(&IPV6(base.src_addr), &el.flowType.ipv6.src_ip, 16);
		    memcpy(&IPV6(base.dst_addr), &el.flowType.ipv6.dst_ip, 16);
		    COMO(l4ofs) = COMO(l3ofs) + 40; /* IPv6 header length */
		    switch (el.flowType.ipv6.protocol) {
		    case IPPROTO_TCP:
			COMO(caplen) += sizeof(struct _como_tcphdr);
			N16(TCP(src_port)) =
			    htons((uint16_t) el.flowType.ipv6.src_port);
			N16(TCP(dst_port)) =
			    htons((uint16_t) el.flowType.ipv6.dst_port);
			/* TCP(flags) */
			*(COMO(payload) + COMO(l4ofs) + 13) = el.flowType.ipv6.tcp_flags;
			break;
		    case IPPROTO_UDP:
			COMO(caplen) += sizeof(struct _como_udphdr);
			N16(UDP(src_port)) =
			    htons((uint16_t) el.flowType.ipv6.src_port);
			N16(UDP(dst_port)) =
			    htons((uint16_t) el.flowType.ipv6.dst_port);
			break;
		    }
		    break;
		    updateofs(pkt, L3, ETHERTYPE_IPV6);
		}
		COMO(pktmetas) = COMO(payload) + COMO(caplen);
		pktmeta_set(pkt, "sampling_rate", &como_sflow_hdr.sampling_rate,
			    sizeof(uint32_t));
		
		nbytes += COMO(caplen) + COMO(pktmetaslen);
		npkts++;
		pkt++;
	    }
	    /* unless every element was processed will add a positive number */
	    src->drops += num_elements - eli;
	}
    }

    if (t < dg.hdr.num_records && npkts == max_no) {
	/*
	 * the count is not really accurate
	 */
	src->drops += dg.hdr.num_records - t;
    }

    return npkts;
}

/*
 * sniffer_stop
 */
static void
sniffer_stop(source_t * src)
{
    struct _snifferinfo *info;

    assert(src->ptr != NULL);

    sf_log("sflow stop\n");

    info = (struct _snifferinfo *) src->ptr;

    if (src->fd > 0) {
	/* close the socket */
	close(src->fd);
    }

    free(src->ptr);
}

sniffer_t sflow_sniffer = {
    "sflow", sniffer_start, sniffer_next, sniffer_stop
};
