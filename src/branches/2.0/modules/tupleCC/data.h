/*
 * Copyright (c) 2004-2007, Intel Corporation
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
 * $Id: tuple.c 1012 2006-11-13 15:04:31Z jsanjuas $
 */

#include "module.h"

como_tuple como_record struct record {
    timestamp_t start_ts; 
    timestamp_t last_ts; 
    uint32_t src_ip; /* XXX should be n32_t and n16_t's */
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
    uint8_t padding;
    uint16_t sampling;
    uint64_t bytes;
    uint64_t pkts;
};

como_config struct config {
    /*
     * packet description and templates for the
     * replay() callback or to know if we can process
     * the packets from given sniffer
     */    
    int compact;
    uint32_t mask;
    uint32_t last_export;
    uint32_t meas_ivl;
};

typedef struct record record_t;
typedef struct config config_t;

static void
get_pkt_info(pkt_t *pkt, uint32_t *src, uint32_t *dst, uint16_t *sport,
    uint16_t *dport, uint8_t *proto)
{
    *src = N32(IP(src_ip));
    *dst = N32(IP(dst_ip));
    *proto = IP(proto);

    switch (*proto) {
        case IPPROTO_TCP:
            *sport = N16(TCP(src_port));
            *dport = N16(TCP(dst_port));
            break;
        case IPPROTO_UDP:
            *sport = N16(UDP(src_port));
            *dport = N16(UDP(dst_port));
            break;
        default:
            *sport = *dport = 0;
    }
}

