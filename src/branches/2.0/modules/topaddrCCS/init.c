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

/*
 * This module ranks addresses in terms of bytes.
 * The IP addresses can be destination or sources. 
 */

#include "como.h"
#include "data.h"

topaddr_config_t *
init(mdl_t * self, hash_t * args)
{
    topaddr_config_t *config;
    int i;
    pkt_t *pkt;
    metadesc_t *inmd;
    char *val;
    
    config = mdl_alloc_config(self, topaddr_config_t);
    config->use_dst = 1; 
    config->meas_ivl = 5;
    config->topn = 20;
    config->mask = ~0;
    /* config->last_export = 0;  */
    
    /* 
     * process input arguments 
     */
    if ((val = hash_lookup_string(args, "interval")))
        config->meas_ivl = atoi(val);
    if ((val = hash_lookup_string(args, "topn")))
        config->topn = atoi(val);
    if ((val = hash_lookup_string(args, "mask")))
        config->mask = atoi(val);
    /*if ((val = hash_lookup_string(args, "align-to")))
        config->last_export = atoi(val);*/
    if ((val = hash_lookup_string(args, "use-dst")))
        config->use_dst = 1;
    if ((val = hash_lookup_string(args, "use-src")))
        config->use_dst = 0;

    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = TIME2TS(config->meas_ivl, 0);
    
    pkt = metadesc_tpl_add(inmd, "none:none:~ip:none");
    IP(proto) = 0xff;
    N16(IP(len)) = 0xffff;
    if (config->use_dst) 
	N32(IP(dst_ip)) = 0xffffffff;
    else 
	N32(IP(src_ip)) = 0xffffffff;

    self->flush_ivl = TIME2TS(config->meas_ivl, 0);
    return config;
}

