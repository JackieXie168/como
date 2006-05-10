/*
 * Copyright (c) 2004 Intel Corporation
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

#ifndef _COMO_LINKLAYER_H
#define _COMO_LINKLAYER_H


/* 
 * Ethernet framing 
 */
struct _como_eth {
    char dst[6];
    char src[6];
    n16_t type;
};


/*
 * VLAN header 
 */
struct _como_vlan {
    char dst[6];
    char src[6];
    n16_t type;			/* 0x8100 for 802.1q */
    n16_t vlan;
    n16_t ethtype;
};


/* 
 * Cisco HDLC framing (used for POS point-to-point links) 
 */
struct _como_hdlc {
    uint8_t address;		/* 0x0F unicast, 0x8F broadcast */
    uint8_t control;		/* always 0 */
    n16_t type;			/* Ethernet-like type codes */
};


/* 
 * Cisco ISL framing (used for VLAN trunking) 
 */
struct _como_isl {
    char da[5];			/* dst address 0x01000c0000 or 0x03000c0000 */
    uint8_t type:4;		/* 0 for ethernet */
    uint8_t user:4;		/* priority */
    char sa[6];			/* source address */
    n16_t len;			/* packet length (excluding ISL) */
    char snap[3];		/* SNAP, constant 0xaaaa03 */
    char hsa[3];		/* source address, 0x00000c */
    n16_t vlan;			/* vlan ID (15bit), last bit is BPDU */
    n16_t index;		/* index, ignored */
    n16_t res;			/* reserved */

    char dst[6];		/* ethernet frame, dst address */
    char src[6];		/* ethernet frame, src address */
    n16_t ethtype;		/* ethernet frame, type field */
};


/* 
 * NetFlow-like record 
 * It contains some information that can be derived from 
 * NetFlow or cflowd records...
 * Currently the fields reflect V5 NetFlow
 * 
 */
struct _como_nf {
    n32_t exaddr;		/* exporter IP Address */
    n32_t nexthop;		/* next hop router's IP Address */
    n16_t src_as;		/* source AS */
    n16_t dst_as;		/* destination AS for dst IP */
    n16_t input;		/* input interface index */
    n16_t output;		/* output interface index */
    uint8_t tcp_flags;		/* OR'ed TCP header bits */
    uint8_t src_mask;		/* source prefix mask */
    uint8_t dst_mask;		/* destination prefix mask */
    uint8_t engine_type;	/* type of switching engine (RP,VIP,etc.) */
    uint8_t engine_id;		/* slot number of the flow switching engine */
    n16_t sampling;		/* sampling rate */
    n32_t pktcount;		/* no. pkts represented (compact mode) */
    n32_t duration;		/* flow duration (in milliseconds) */
};


/*
 * sFlow record
 */
struct _como_sflow {
    n32_t agent_address;	/* IP address of sampling agent */
    n32_t sub_agent_id;		/* Used to distinguishing between datagram
				   streams from separate agent sub entities
				   within an device */
    n32_t ds_class;		/* fsSourceId */
    n32_t ds_index;		/* fsSourceId */
    n32_t sampling_rate;	/* fsPacketSamplingRate */
    n32_t sample_pool;		/* Total number of packets that could have been
				   sampled (i.e. packets skipped by sampling
				   process + total number of samples) */
    n32_t inputFormat;		/* SNMP ifIndex of input interface */
    n32_t input;		/* 0 if interface is not known. */
    n32_t outputFormat;		/* SNMP ifIndex of output interface */
    n32_t output;		/* 0 if interface is not known */
};

#endif				/* _COMO_LINKLAYER_H */
