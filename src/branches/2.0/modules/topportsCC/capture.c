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
 * $Id$
 */

/*
 * Top-N ports module.
 *
 * This module finds the top N port numbers (source or destination) with the 
 * largest number of bytes sent during a given interval. 
 *
 */

#include "module.h"
#include "data.h"

tuple_t *
ca_init(mdl_t *self, timestamp_t ivl)
{
    tuple_t *t = mdl_alloc_tuple(self, tuple_t);

    bzero(t, sizeof(tuple_t));
    t->ts = ivl;

    return t;
}

void
capture(mdl_t * self, pkt_t *pkt, tuple_t *t)
{
    uint64_t newbytes = H16(IP(len));
    uint32_t newpkts = 1;
    config_t *config = mdl_get_config(self, config_t);

    if (COMO(type) == COMOTYPE_NF) {
        newbytes = H32(NF(pktcount)) * COMO(len) * H16(NF(sampling));
        newpkts = H32(NF(pktcount)) * (uint32_t) H16(NF(sampling));
    } else if (COMO(type) == COMOTYPE_SFLOW) {
	newbytes = (uint64_t) COMO(len) * (uint64_t) H32(SFLOW(sampling_rate));
	newpkts = H32(SFLOW(sampling_rate));
    } 

    if (isTCP) {
	uint16_t sport = H16(TCP(src_port));
	uint16_t dport = H16(TCP(dst_port));

	t->tcpbytes[sport] += newbytes;
	t->tcpbytes[dport] += newbytes;
	t->tcppkts[sport] += newpkts;
	t->tcppkts[dport] += newpkts;

        t->maxtcpport = GETMAX(t->maxtcpport, GETMAX(sport, dport));
    } else if (isUDP) {
	uint16_t sport = H16(UDP(src_port));
	uint16_t dport = H16(UDP(dst_port));

	t->udpbytes[sport] += newbytes;
	t->udpbytes[dport] += newbytes;
	t->udppkts[sport] += newpkts;
	t->udppkts[dport] += newpkts;

        t->maxudpport = GETMAX(t->maxudpport, GETMAX(sport, dport));
    } 
}

