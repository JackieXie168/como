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

#include <string.h>

#include "como.h"

static const headerinfo_t s_known_headers[] = {
    /* CoMo layer */
    {"any", LCOMO, COMOTYPE_ANY, 0},
    {"none", LCOMO, COMOTYPE_NONE, 0},
    {"como", LCOMO, COMOTYPE_COMO, 0},
    {"link", LCOMO, COMOTYPE_LINK, 0},
    {"radio", LCOMO, COMOTYPE_RADIO, sizeof(struct _como_radio)},
    {"nf", LCOMO, COMOTYPE_NF, sizeof(struct _como_nf)},
    {"sflow", LCOMO, COMOTYPE_SFLOW, sizeof(struct _como_sflow)},
    /* Link layer */
    {"any", L2, LINKTYPE_ANY, 0},
    {"none", L2, LINKTYPE_NONE, 0},
    {"eth", L2, LINKTYPE_ETH, sizeof(struct _como_eth)},
    {"vlan", L2, LINKTYPE_VLAN, sizeof(struct _como_vlan)},
    {"isl", L2, LINKTYPE_ISL, sizeof(struct _como_isl)},
    {"hdlc", L2, LINKTYPE_HDLC, sizeof(struct _como_hdlc)},
    {"802.11", L2, LINKTYPE_80211, 0}, /* TODO: variable size */
    /* Layer 3 */
    {"any", L3, L3TYPE_ANY, 0},
    {"none", L3, L3TYPE_NONE, 0},
    {"ip", L3, ETHERTYPE_IP, sizeof(struct _como_iphdr)},
    /* Layer 4 */
    {"any", L4, L4TYPE_ANY, 0},
    {"none", L4, L4TYPE_NONE, 0},
    {"tcp", L4, IPPROTO_TCP, sizeof(struct _como_tcphdr)},
    {"udp", L4, IPPROTO_UDP, sizeof(struct _como_udphdr)},
    {NULL, 0, 0, 0}
};

const headerinfo_t *
headerinfo_lookup_with_name_and_layer(const char *name, layer_t l)
{
    const headerinfo_t *hi = s_known_headers;

    while (hi->name) {
	if (hi->layer == l) break;
	hi++;
    }
    if (!hi->name) return NULL;
    
    while (hi->name && strcmp(name, hi->name) != 0) {
	hi++;
    }
    if (!hi->name) return NULL;
    
    return hi;
}

const headerinfo_t *
headerinfo_lookup_with_type_and_layer(uint32_t type, layer_t l)
{
    const headerinfo_t *hi = s_known_headers;

    while (hi->name) {
	if (hi->layer == l) break;
	hi++;
    }
    if (!hi->name) return NULL;
    
    while (hi->name && type != hi->type) {
	hi++;
    }
    if (!hi->name) return NULL;
    
    return hi;
}
