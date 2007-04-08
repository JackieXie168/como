/*
 * Copyright (c) 2006-2007, Intel Corporation
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
 * $Id: flowcount.c 1012 2006-11-13 15:04:31Z jsanjuas $
 */

#include "module.h"
#include "data.h"

config_t *
init(mdl_t * self, hash_t *args)
{
    config_t *config;
    /*metadesc_t *inmd;
    pkt_t *pkt;*/
    char *val;
    int i;

    config = mdl_alloc_config(self, config_t);
    config->meas_ivl = 1;
    config->max_keys = 2000000;  	/* by default expect max 2M keys */
    config->flow_fields = 0;
    //uhash_initialize(&config->hfunc);

    /*
     * parse input arguments
     */
    if ((val = hash_lookup_string(args, "interval")))
        config->meas_ivl = atoi(val);
    if ((val = hash_lookup_string(args, "flowdef"))) {
        config->flow_fields |= strstr(val, "src_ip") ? USE_SRC : 0;
        config->flow_fields |= strstr(val, "dst_ip") ? USE_DST : 0;
        config->flow_fields |= strstr(val, "src_port") ? USE_SPORT : 0;
        config->flow_fields |= strstr(val, "dst_port") ? USE_DPORT : 0;
        config->flow_fields |= strstr(val, "proto") ? USE_PROTO : 0;
    }
    if ((val = hash_lookup_string(args, "maxflows")))
        config->max_keys = strtoul(val, NULL, 0);

    /*
     * if the user did not define the concept of flow then
     * pick the 5-tuple as a safe default.
     */
    if (config->flow_fields == 0)
        config->flow_fields = USE_ALL; 

    /* setup indesc */
    /*inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = TIME2TS(cf->meas_ivl, 0);

    pkt = metadesc_tpl_add(inmd, "none:none:~ip:none");
    IP(proto) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;

    pkt = metadesc_tpl_add(inmd, "none:none:~ip:~tcp");
    IP(proto) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    N16(TCP(src_port)) = 0xffff;
    N16(TCP(dst_port)) = 0xffff;
    
    pkt = metadesc_tpl_add(inmd, "none:none:~ip:~udp");
    IP(proto) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    N16(UDP(src_port)) = 0xffff;
    N16(UDP(dst_port)) = 0xffff;*/

    self->flush_ivl = TIME2TS(config->meas_ivl, 0);
    return config;
}

