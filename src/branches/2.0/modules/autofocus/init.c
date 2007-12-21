/*
 * Copyright (c) 2007, Universitat Politecnica de Catalunya
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
 * $Id: init.c 1211 2007-09-26 15:01:49Z jsanjuas $
 */
#include "como.h"
#include "data.h"

config_t *
init(mdl_t * self, hash_t *args)
{
    config_t *config;
    /*pkt_t * pkt; 
    metadesc_t *inmd, *outmd;*/
    char *val;

    config = mdl_alloc_config(self, config_t);
    config->meas_ivl = 1;
    config->output_ivl = 1;
    config->use_srcs = 0;
    
    /*
     * process input arguments
     */
    if ((val = hash_lookup_string(args, "interval")))
        config->meas_ivl = atoi(val);

    if ((val = hash_lookup_string(args, "output_interval")))
        config->output_ivl = atoi(val);
    else
        config->output_ivl = config->meas_ivl;

    if ((val = hash_lookup_string(args, "use_srcs")))
        config->use_srcs = 1;
    if ((val = hash_lookup_string(args, "use_dsts")))
        config->use_srcs = 0;

    if (config->meas_ivl == 0)
        config->meas_ivl = 1;
    if (config->output_ivl < config->meas_ivl)
        config->output_ivl = config->meas_ivl;

    /*
     * our input stream needs to contain the port numbers and
     * a packet length. for the timestamp, we use a default value of
     * one second or whatever we receive from configuration
     */
    
    /* setup indesc */
    /*inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = TIME2TS(config->meas_ivl, 0);
    
    pkt = metadesc_tpl_add(inmd, "none:none:~ip:none");
    IP(proto) = 0xff;
    N16(IP(len)) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    
    pkt = metadesc_tpl_add(inmd, "none:none:~ip:~tcp");
    IP(proto) = 0xff;
    N16(IP(len)) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    N16(TCP(src_port)) = 0xffff;
    N16(TCP(dst_port)) = 0xffff;
    
    pkt = metadesc_tpl_add(inmd, "none:none:~ip:~udp");
    IP(proto) = 0xff;
    N16(IP(len)) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    N16(UDP(src_port)) = 0xffff;
    N16(UDP(dst_port)) = 0xffff;*/
    
    /* setup outdesc */
    /*outmd = metadesc_define_out(self, 0);
    outmd->ts_resolution = TIME2TS(config->meas_ivl, 0);
    outmd->flags = META_PKT_LENS_ARE_AVERAGED;
    
    pkt = metadesc_tpl_add(outmd, "~nf:none:~ip:none");
    N16(NF(sampling)) = 0xffff;
    N32(NF(duration)) = 0xffffffff;
    N32(NF(pktcount)) = 0xffffffff;
    IP(proto) = 0xff;
    N16(IP(len)) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    
    pkt = metadesc_tpl_add(outmd, "~nf:none:~ip:~tcp");
    N16(NF(sampling)) = 0xffff;
    N32(NF(duration)) = 0xffffffff;
    N32(NF(pktcount)) = 0xffffffff;
    IP(proto) = 0xff;
    N16(IP(len)) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    N16(TCP(src_port)) = 0xffff;
    N16(TCP(dst_port)) = 0xffff;
    
    pkt = metadesc_tpl_add(outmd, "~nf:none:~ip:~udp");
    N16(NF(sampling)) = 0xffff;
    N32(NF(duration)) = 0xffffffff;
    N32(NF(pktcount)) = 0xffffffff;
    IP(proto) = 0xff;
    N16(IP(len)) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    N16(UDP(src_port)) = 0xffff;
    N16(UDP(dst_port)) = 0xffff;*/
    
    //self->flush_ivl = TIME2TS(config->meas_ivl, 0);
    self->flush_ivl = TIME2TS(1, 0);
    return config;
}


