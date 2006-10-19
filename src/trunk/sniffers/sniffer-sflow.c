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


/* 
 * This sniffer support sFlow(R) datagrams for Version 2, 4 and 5 as 
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
#include <sys/mman.h>
#include <errno.h>		/* errno values */
#include <assert.h>
#include <sys/types.h>
#include <time.h>
#include <stdio.h>
#undef __unused			/* __unused is used in netdb.h */
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "sniffers.h"
#include "como.h"
#include "comotypes.h"

#include "sflow.h"		/* sFlow */

#include "capbuf.c"

enum sf_err {
    SF_OK = 0,
    SF_ABORT_EOS = 1,
    SF_ABORT_DECODE_ERROR = 2,
    SF_ABORT_LENGTH_ERROR = 3,
    SF_ABORT_RECV_ERROR = 4
};

typedef struct _SFDatagram {
    u_char *buf;
    u_char *end;
    uint32_t *cur;
    uint32_t len;
    int err;
    uint32_t buf_length;
    SFLSample_datagram_hdr hdr;
} SFDatagram;

typedef struct _SFTag {
    uint32_t type;
    uint32_t len;
    SFDatagram *dg;
} SFTag;

/* 
 * define SNIFFER_SFLOW_DEBUG to enable debug information
 */
/* #define SNIFFER_SFLOW_DEBUG */
#ifdef SNIFFER_SFLOW_DEBUG
#define sf_log(format...)	logmsg(LOGWARN, format)
#else
#define sf_log(format...)
#endif
#define sf_warning(format...)	logmsg(LOGWARN, format)


static inline uint32_t
sf_read32(SFDatagram * dg)
{
    return ntohl(*(dg->cur)++);
}

static inline void
sf_copy(SFDatagram * dg, void *dest, size_t n)
{
    memcpy(dest, dg->cur, n);
    dg->cur = (uint32_t *) ((u_char *) dg->cur + n);
}

static inline void
sf_skip_bytes(SFDatagram * dg, int skip)
{
    int quads = (skip + 3) / 4;

    dg->cur += quads;
}

static inline int
sf_check(SFDatagram * dg)
{
    if ((u_char *) dg->cur > dg->end)
	dg->err = SF_ABORT_EOS;
    return dg->err;
}

static int
sflow_datagram_read(SFDatagram * dg, int fd)
{
    struct sockaddr_in agent;
    socklen_t addr_len;
    int bytes;

    addr_len = sizeof(agent);
    memset(&agent, 0, sizeof(agent));
    bytes = recvfrom(fd, dg->buf, (size_t) dg->buf_length, 0,
		     (struct sockaddr *) &agent, &addr_len);
    if (bytes <= 0) {
	sf_warning("sniffer-sflow: recvfrom() failed: %s\n", strerror(errno));
	dg->err = SF_ABORT_RECV_ERROR;
	return SF_ABORT_RECV_ERROR;
    }
    dg->len = bytes;
    dg->cur = (uint32_t *) dg->buf;
    dg->end = ((u_char *) dg->cur) + dg->len;
    dg->err = SF_OK;

    return SF_OK;
}

static int
sflow_read_address(SFDatagram * dg, SFLAddress * a)
{
    a->type = sf_read32(dg);
    if (a->type == SFLADDRESSTYPE_IP_V4) {
	sf_copy(dg, &a->address.ip_v4.s_addr, 4);
    } else {
	sf_copy(dg, &a->address.ip_v6.s6_addr, 16);
    }
    return sf_check(dg);
}

static int
sflow_read_string(SFDatagram * dg, SFLString * s)
{
    s->len = sf_read32(dg);
    s->str = (char *) dg->cur;
    sf_skip_bytes(dg, s->len);
    return sf_check(dg);
}

static int
sflow_datagram_decode_hdr(SFDatagram * dg)
{
    /* check the version */
    dg->hdr.datagram_version = sf_read32(dg);
    sf_log("datagramVersion %d\n", dg->hdr.datagram_version);

    if (dg->hdr.datagram_version != 2 &&
	dg->hdr.datagram_version != 4 && dg->hdr.datagram_version != 5) {
	sf_warning("unexpected datagram version number\n");
	dg->err = SF_ABORT_DECODE_ERROR;
	return SF_ABORT_DECODE_ERROR;
    }

    /* get the agent address */
    sflow_read_address(dg, &dg->hdr.agent_address);

    /* version 5 has an agent sub-id as well */
    if (dg->hdr.datagram_version == 5) {
	dg->hdr.sub_agent_id = sf_read32(dg);
    }

    /* this is the packet sequence number */
    dg->hdr.sequence_number = sf_read32(dg);
    dg->hdr.uptime = sf_read32(dg);
    dg->hdr.num_records = sf_read32(dg);

    return sf_check(dg);
}

static int
sflow_datagram_next_tag(SFDatagram * dg, SFTag * tag)
{
    tag->type = sf_read32(dg);
    if (dg->hdr.datagram_version == 5) {
	tag->len = sf_read32(dg);
    } else {
	tag->len = 0;
    }
    tag->dg = dg;

    return sf_check(dg);
}

static int
sflow_tag_decode_flow_sample(SFTag * tag, SFLFlow_sample * fs)
{
    fs->sequence_number = sf_read32(tag->dg);
    fs->source_id = sf_read32(tag->dg);
    fs->sampling_rate = sf_read32(tag->dg);
    fs->sample_pool = sf_read32(tag->dg);
    fs->drops = sf_read32(tag->dg);
    fs->input = sf_read32(tag->dg);
    fs->output = sf_read32(tag->dg);
    if (tag->dg->hdr.datagram_version == 5) {
	fs->num_elements = sf_read32(tag->dg);
    } else {
	fs->num_elements = 1;
    }
    fs->elements = NULL;	/* not used as no memory is allocated here */

    return sf_check(tag->dg);
}

static int
sflow_tag_decode_flow_sample_expanded(SFTag * tag,
				      SFLFlow_sample_expanded * fse)
{
    fse->sequence_number = sf_read32(tag->dg);
    fse->ds_class = sf_read32(tag->dg);
    fse->ds_index = sf_read32(tag->dg);
    fse->sampling_rate = sf_read32(tag->dg);
    fse->sample_pool = sf_read32(tag->dg);
    fse->drops = sf_read32(tag->dg);
    fse->inputFormat = sf_read32(tag->dg);
    fse->input = sf_read32(tag->dg);
    fse->outputFormat = sf_read32(tag->dg);
    fse->output = sf_read32(tag->dg);
    fse->num_elements = sf_read32(tag->dg);
    fse->elements = NULL;	/* not used as no memory is allocated here */

    return sf_check(tag->dg);
}

static int
sflow_read_flow_sample_header(SFTag * tag, SFLFlow_sample_element * el)
{
    sf_log("flowSampleType HEADER\n");
    el->flowType.header.header_protocol = sf_read32(tag->dg);
    sf_log("headerProtocol %lu\n", el->flowType.header.header_protocol);
    el->flowType.header.frame_length = sf_read32(tag->dg);
    sf_log("sampledPacketSize %lu\n", el->flowType.header.frame_length);
    if (tag->dg->hdr.datagram_version > 4) {
	/* stripped count introduced in sFlow version 5 */
	el->flowType.header.stripped = sf_read32(tag->dg);
	sf_log("strippedBytes %lu\n", el->flowType.header.stripped);
    }
    el->flowType.header.header_length = sf_read32(tag->dg);
    sf_log("headerLen %lu\n", el->flowType.header.header_length);

    /* just point at the header */
    el->flowType.header.header_bytes = (u_int8_t *) tag->dg->cur;
    sf_skip_bytes(tag->dg, el->flowType.header.header_length);

    return sf_check(tag->dg);
}

static int
sflow_read_flow_sample_ethernet(SFTag * tag, SFLFlow_sample_element * el)
{
    sf_log("flowSampleType ETHERNET\n");
    el->flowType.ethernet.eth_len = sf_read32(tag->dg);
    sf_copy(tag->dg, el->flowType.ethernet.src_mac, 6);
    sf_copy(tag->dg, el->flowType.ethernet.dst_mac, 6);
    el->flowType.ethernet.eth_type = sf_read32(tag->dg);

    sf_log("ethernet_type %lu\n", el->flowType.ethernet.eth_type);
    sf_log("ethernet_len %lu\n", el->flowType.ethernet.eth_len);

#ifdef SNIFFER_SFLOW_DEBUG
    {
	unsigned char *p;

	p = el->flowType.ethernet.src_mac;
	sf_log("ethernet_src %02x%02x%02x%02x%02x%02x\n", p[0], p[1],
	       p[2], p[3], p[4], p[5]);
	p = el->flowType.ethernet.dst_mac;
	sf_log("ethernet_dst %02x%02x%02x%02x%02x%02x\n", p[0], p[1],
	       p[2], p[3], p[4], p[5]);
    }
#endif

    return sf_check(tag->dg);
}

static int
sflow_read_flow_sample_ipv4(SFTag * tag, SFLFlow_sample_element * el)
{
    sf_log("flowSampleType IPV4\n");
    el->flowType.ipv4.length = sf_read32(tag->dg);
    el->flowType.ipv4.protocol = sf_read32(tag->dg);
    sf_copy(tag->dg, &el->flowType.ipv4.src_ip, 4);
    sf_copy(tag->dg, &el->flowType.ipv4.dst_ip, 4);
    el->flowType.ipv4.src_port = sf_read32(tag->dg);
    el->flowType.ipv4.dst_port = sf_read32(tag->dg);
    el->flowType.ipv4.tcp_flags = sf_read32(tag->dg);
    el->flowType.ipv4.tos = sf_read32(tag->dg);

    return sf_check(tag->dg);
}

static int
sflow_read_flow_sample_ipv6(SFTag * tag, SFLFlow_sample_element * el)
{
    sf_log("flowSampleType IPV6\n");
    el->flowType.ipv6.length = sf_read32(tag->dg);
    el->flowType.ipv6.protocol = sf_read32(tag->dg);
    sf_copy(tag->dg, &el->flowType.ipv6.src_ip, 16);
    sf_copy(tag->dg, &el->flowType.ipv6.dst_ip, 16);
    el->flowType.ipv6.src_port = sf_read32(tag->dg);
    el->flowType.ipv6.dst_port = sf_read32(tag->dg);
    el->flowType.ipv6.tcp_flags = sf_read32(tag->dg);
    el->flowType.ipv6.priority = sf_read32(tag->dg);

    return sf_check(tag->dg);
}

static int
sflow_read_extended_switch(SFTag * tag, SFLExtended_switch * r)
{
    sf_log("extendedType SWITCH\n");
    r->src_vlan = sf_read32(tag->dg);
    r->src_priority = sf_read32(tag->dg);
    r->dst_vlan = sf_read32(tag->dg);
    r->dst_priority = sf_read32(tag->dg);

    return sf_check(tag->dg);
}

static int
sflow_read_extended_router(SFTag * tag, SFLExtended_router * r)
{
    sf_log("extendedType ROUTER\n");
    sflow_read_address(tag->dg, &r->nexthop);
    r->src_mask = sf_read32(tag->dg);
    r->dst_mask = sf_read32(tag->dg);

    return sf_check(tag->dg);
}

static int
sflow_read_extended_gateway(SFTag * tag, SFLExtended_gateway * r)
{
    uint32_t seg;

    sf_log("extendedType GATEWAY\n");

    if (tag->dg->hdr.datagram_version == 5) {
	sflow_read_address(tag->dg, &r->nexthop);
    }

    r->as = sf_read32(tag->dg);
    r->src_as = sf_read32(tag->dg);
    r->src_peer_as = sf_read32(tag->dg);
    if (tag->dg->hdr.datagram_version != 2) {
	r->dst_as_path_segments = sf_read32(tag->dg);
	if (r->dst_as_path_segments > 0) {
	    for (seg = 0; seg < r->dst_as_path_segments; seg++) {
		uint32_t seg_type;
		uint32_t seg_len;
		seg_type = sf_read32(tag->dg);
		seg_len = sf_read32(tag->dg);
		sf_skip_bytes(tag->dg, seg_len * 4);
	    }
	}
	r->communities_length = sf_read32(tag->dg);
	sf_skip_bytes(tag->dg, r->communities_length * 4);
	r->localpref = sf_read32(tag->dg);
    } else {
	uint32_t seg_len;
	seg_len = sf_read32(tag->dg);
	sf_skip_bytes(tag->dg, seg_len * 4);
    }

    return sf_check(tag->dg);
}

static int
sflow_read_extended_user(SFTag * tag, SFLExtended_user * r)
{
    sf_log("extendedType USER\n");

    if (tag->dg->hdr.datagram_version == 5) {
	r->src_charset = sf_read32(tag->dg);
    }
    sflow_read_string(tag->dg, &r->src_user);

    if (tag->dg->hdr.datagram_version == 5) {
	r->dst_charset = sf_read32(tag->dg);
    }
    sflow_read_string(tag->dg, &r->dst_user);

    return sf_check(tag->dg);
}

static int
sflow_read_extended_url(SFTag * tag, SFLExtended_url * r)
{
    sf_log("extendedType URL\n");

    r->direction = sf_read32(tag->dg);
    sflow_read_string(tag->dg, &r->url);
    if (tag->dg->hdr.datagram_version == 5) {
	sflow_read_string(tag->dg, &r->host);
    }
    return sf_check(tag->dg);
}

enum INMExtended_information_type {
    INMEXTENDED_SWITCH = 1,	/* Extended switch information */
    INMEXTENDED_ROUTER = 2,	/* Extended router information */
    INMEXTENDED_GATEWAY = 3,	/* Extended gateway router information */
    INMEXTENDED_USER = 4,	/* Extended TACAS/RADIUS user information */
    INMEXTENDED_URL = 5		/* Extended URL information */
};

static int
sflow_tag_next_flow_sample(SFTag * tag, SFLFlow_sample_element * el)
{
    int res;

    el->tag = sf_read32(tag->dg);
    if (tag->dg->hdr.datagram_version == 5) {
	el->length = sf_read32(tag->dg);
    }
    switch (el->tag) {
    case SFLFLOW_HEADER:
	res = sflow_read_flow_sample_header(tag, el);
	break;
    case SFLFLOW_ETHERNET:
	res = sflow_read_flow_sample_ethernet(tag, el);
	break;
    case SFLFLOW_IPV4:
	res = sflow_read_flow_sample_ipv4(tag, el);
	break;
    case SFLFLOW_IPV6:
	res = sflow_read_flow_sample_ipv6(tag, el);
	break;
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
	if (tag->dg->hdr.datagram_version != 5) {
	    tag->dg->err = SF_ABORT_DECODE_ERROR;
	    return tag->dg->err;
	}
	/* NOTE: el->length exists only in v5 */
	sf_skip_bytes(tag->dg, el->length);
	break;
    }

    if (res != SF_OK)
	return res;

    if (tag->dg->hdr.datagram_version != 5) {
	uint32_t num_extended, x;

	num_extended = sf_read32(tag->dg);

	for (x = 0; x < num_extended; x++) {
	    uint32_t ext_type;
	    ext_type = sf_read32(tag->dg);
	    switch (ext_type) {
	    case INMEXTENDED_SWITCH:
		{
		    SFLExtended_switch r;
		    sflow_read_extended_switch(tag, &r);
		}
		break;
	    case INMEXTENDED_ROUTER:
		{
		    SFLExtended_router r;
		    sflow_read_extended_router(tag, &r);
		}
		break;
	    case INMEXTENDED_GATEWAY:
		{
		    SFLExtended_gateway r;
		    sflow_read_extended_gateway(tag, &r);
		}
		break;
	    case INMEXTENDED_USER:
		{
		    SFLExtended_user r;
		    sflow_read_extended_user(tag, &r);
		}
		break;
	    case INMEXTENDED_URL:
		{
		    SFLExtended_url r;
		    sflow_read_extended_url(tag, &r);
		}
		break;
	    }
	}
    }

    return sf_check(tag->dg);
}

static int
sflow_tag_ignore(SFTag * tag)
{
    if (tag->dg->hdr.datagram_version == 5) {
	sf_skip_bytes(tag->dg, tag->len);
    } else {
	uint32_t counters_type;
	if (tag->type != SFLCOUNTERS_SAMPLE) {
	    sf_warning("Unexpected sample type %u... ignoring.\n", tag->type);
	    tag->dg->err = SF_ABORT_DECODE_ERROR;
	    return tag->dg->err;
	}
	/* skip sequence_number, source_id, sampling_interval */
	sf_skip_bytes(tag->dg, 12);
	counters_type = sf_read32(tag->dg);
	switch (counters_type) {
	case 1: /* GENERIC */
	case 4: /* FDDI */
	case 6: /* WAN */
	    sf_skip_bytes(tag->dg, sizeof(SFLIf_counters));
	    break;
	case 2: /* ETHERNET */
	    sf_skip_bytes(tag->dg, sizeof(SFLIf_counters) +
			  sizeof(SFLEthernet_counters));
	    break;
	case 3: /* TOKENRING */
	    sf_skip_bytes(tag->dg, sizeof(SFLIf_counters) +
			  sizeof(SFLTokenring_counters));
	    break;
	case 5: /* VG */
	    sf_skip_bytes(tag->dg, sizeof(SFLIf_counters) +
			  sizeof(SFLVg_counters));
	    break;
	case 7: /* VLAN */
	    sf_skip_bytes(tag->dg, sizeof(SFLVlan_counters));
	    break;
	default:
	    sf_warning("Unexpected counters type %u... ignoring.\n",
		       counters_type);
	    tag->dg->err = SF_ABORT_DECODE_ERROR;
	    return tag->dg->err;
	}
    }

    return sf_check(tag->dg);
}


/* sniffer-specific information */
#define SFLOW_MIN_BUFSIZE	(1024 * 1024)
#define SFLOW_MAX_BUFSIZE	(SFLOW_MIN_BUFSIZE * 2)


struct sflow_me {
    sniffer_t		sniff;		/* common fields, must be the first */
    uint16_t		port;		/* socket port */
    const char *	device;
    uint16_t		_reserved;	/* padding */
    uint32_t		last_sn;	/* last sample packet seq number */
    uint32_t		first_sn;	/* first sample packet seq number */
    timestamp_t		last_ts;	/* last datagram timestamp */
    u_int32_t		flow_type_tag;	/* SFLFlow_type_tag */
    capbuf_t		capbuf;
};


/*
 * -- sniffer_init
 * 
 */
static sniffer_t *
sniffer_init(const char * device, const char * args)
{
    struct sflow_me *me;
    
    me = safe_calloc(1, sizeof(struct sflow_me));

    me->sniff.max_pkts = 2400;
    me->sniff.flags = SNIFF_SELECT;
    me->device = device;
    /* defult port as assigned by IANA */
    me->port = SFL_DEFAULT_COLLECTOR_PORT;
    me->first_sn = 0;
    me->last_sn = 0xFFFFFFFF;
    me->last_ts = 0;
    me->flow_type_tag = SFLFLOW_HEADER;

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
	 * "flow_type_tag". 
	 * sets the flow type tag the sflow agent is configured to send
	 */
	if ((p = strstr(args, "flow_type_tag=")) != NULL) {
	    p += 14;
	    if (strcasecmp("HEADER", p) == 0) {
		me->flow_type_tag = SFLFLOW_HEADER;
	    } else if (strcasecmp("ETHERNET", p) == 0) {
		me->flow_type_tag = SFLFLOW_ETHERNET;
	    } else if (strcasecmp("IPV4", p) == 0) {
		me->flow_type_tag = SFLFLOW_IPV4;
	    /* IPv6 not supported
	    } else if (strcasecmp("IPV6", p) == 0) {
		me->flow_type_tag = SFLFLOW_IPV6;
	    */
	    }
	}
    }

    /* create the capture buffer */
    if (capbuf_init(&me->capbuf, args, NULL, SFLOW_MIN_BUFSIZE,
		    SFLOW_MAX_BUFSIZE) < 0)
	goto error;

    return (sniffer_t *) me;
error:
    free(me);
    return NULL;
}

static void
sniffer_setup_metadesc(sniffer_t * s)
{
    struct sflow_me *me = (struct sflow_me *) s;
    metadesc_t *outmd;
    pkt_t *pkt;

    /* setup output descriptor */
    outmd = metadesc_define_sniffer_out(s, 1, "sampling_rate");

    outmd->ts_resolution = TIME2TS(1, 0);

    switch (me->flow_type_tag) {
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
	/* IPv6 not supported*/
	assert_not_reached();
	break;
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
sniffer_start(sniffer_t * s)
{
    struct sflow_me *me = (struct sflow_me *) s;
    struct sockaddr_in addr_in;

    sf_log("sflow start\n");

    /* create a socket */
    me->sniff.fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (me->sniff.fd == -1) {
	logmsg(LOGWARN, "sniffer-sflow: can't create socket: %s\n",
	       strerror(errno));
	return -1;
    }

    memset((char *) &addr_in, 0, sizeof(struct sockaddr_in));
    addr_in.sin_family = AF_INET;
    addr_in.sin_addr.s_addr = htonl(INADDR_ANY);
    addr_in.sin_port = htons(me->port);

    if (me->device && strlen(me->device) > 0) {
	struct hostent *bindinfo;
	bindinfo = gethostbyname(me->device);
	if (bindinfo) {
	    addr_in.sin_addr = *((struct in_addr *) bindinfo->h_addr);
	} else {
	    logmsg(LOGWARN,
		   "sniffer-sflow: unresolved ip address %s: %s\n",
		   me->device, strerror(h_errno));
	    return -1;
	}
    }

    /* CHECKME: do we need to set some socket options? */

    /* bind the socket */
    if (bind(me->sniff.fd, (struct sockaddr *) &addr_in, sizeof(addr_in))
	== -1) {
	logmsg(LOGWARN, "sniffer-sflow: can't bind socket: %s\n",
	       strerror(errno));
	return -1;
    }

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
sniffer_next(sniffer_t * s, int max_pkts, timestamp_t max_ivl,
	     pkt_t * first_ref_pkt, int * dropped_pkts)
{
    struct sflow_me *me = (struct sflow_me *) s;
    int npkts;			/* processed pkts */

#define MAX_PKT_SIZE 65536
    u_char buf[MAX_PKT_SIZE];
    uint32_t t;			/* index for sflow samples */
    struct timeval now;

    SFDatagram dg;
    SFTag tag;

    struct _como_sflow como_sflow_hdr;

    max_ivl = 0; /* just to avoid warning on unused max_ivl */

    sf_log("sflow next\n");


    memset(&tag, 0, sizeof(tag));
    memset(&dg, 0, sizeof(dg));
    dg.buf = buf;
    dg.buf_length = MAX_PKT_SIZE;

    if (sflow_datagram_read(&dg, me->sniff.fd) != SF_OK) {
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
    me->last_ts = TIME2TS(now.tv_sec, now.tv_usec);

    if (me->first_sn == 0 && me->last_sn == 0xFFFFFFFF) {
	me->first_sn = dg.hdr.sequence_number;
    } else if (me->last_sn >= dg.hdr.sequence_number
	       && dg.hdr.sequence_number > me->first_sn) {
	logmsg(LOGWARN,
	       "sniffer-sflow: received sflow datagram with a lower sequence "
	       "number than expected\n");
	return 0;
    }

    /* remember datagram sequence number */
    me->last_sn = dg.hdr.sequence_number;

    if (me->last_sn < me->first_sn)
	me->first_sn = me->last_sn;

    *dropped_pkts = 0;
    
    capbuf_begin(&me->capbuf, first_ref_pkt);
    
    for (t = 0, npkts = 0;
	 t < dg.hdr.num_records && npkts < max_pkts; t++) {
	uint32_t num_elements = 0;

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
		pkt_t *pkt;
		size_t sz;
		
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

		/* compute packet size */
		sz = sizeof(pkt_t) + sizeof(struct _como_sflow);
		switch (el.tag) {
		case SFLFLOW_HEADER:
		    sz += el.flowType.header.header_length;
		    break;
		case SFLFLOW_ETHERNET:
		    sz += sizeof(struct _como_eth);
		    break;
		case SFLFLOW_IPV4:
		    sz += sizeof(struct _como_iphdr);
		    break;
		case SFLFLOW_IPV6:
		    sz += 40;	/* IPv6 header length */
		    break;
		}
		/* reserve the space in the buffer for the packet */
		pkt = (pkt_t *) capbuf_reserve_space(&me->capbuf, sz);
		
		/* point the packet payload to next packet */
		COMO(payload) = (char *) (pkt + 1);

		/* set the timestamp */
		COMO(ts) = me->last_ts;

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
		/* TODO
		COMO(pktmetas) = COMO(payload) + COMO(caplen);
		pktmeta_set(pkt, "sampling_rate", &como_sflow_hdr.sampling_rate,
			    sizeof(uint32_t));
		*/
		npkts++;
		
		ppbuf_capture(me->sniff.ppbuf, pkt);
	    }
	    /* unless every element was processed will add a positive number */
	    *dropped_pkts += num_elements - eli;
	} else {
	    if (sflow_tag_ignore(&tag) != SF_OK)
		break;
	}
    }

    if (t < dg.hdr.num_records && npkts == max_pkts) {
	/*
	 * the count is not really accurate
	 */
	*dropped_pkts += dg.hdr.num_records - t;
    }

    return 0;
}

/*
 * sniffer_usage
 *
 * return the current usage of this sniffer's internal buffers
 */
static float
sniffer_usage(sniffer_t * s, pkt_t * first, pkt_t * last)
{
    struct sflow_me *me = (struct sflow_me *) s;
    size_t sz;
    void * y;
    
    y = ((void *) last) + sizeof(pkt_t) + last->caplen;
    sz = capbuf_region_size(&me->capbuf, first, y);
    return (float) sz / (float) me->capbuf.size;
}

/*
 * sniffer_stop
 */
static void
sniffer_stop(sniffer_t * s)
{
    struct sflow_me *me = (struct sflow_me *) s;

    sf_log("sflow stop\n");

    /* close the socket */
    close(me->sniff.fd);
}

static void
sniffer_finish(sniffer_t * s)
{
    struct sflow_me *me = (struct sflow_me *) s;

    capbuf_finish(&me->capbuf);
    free(me);
}


SNIFFER(sflow) = {
    name: "sflow",
    init: sniffer_init,
    finish: sniffer_finish,
    setup_metadesc: sniffer_setup_metadesc,
    start: sniffer_start,
    next: sniffer_next,
    usage: sniffer_usage,
    stop: sniffer_stop,
};
