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

#include "module.h"
#include "data.h"

config_t *
init(mdl_t * self, hash_t *args)
{
    config_t *config;
    /*metadesc_t *inmd;
    pkt_t *pkt;*/
    char *val;
    
    config = mdl_alloc_config(self, config_t);
    config->meas_ivl = 1;
    config->topn = 20;

    /* 
     * process input arguments 
     */
    if ((val = hash_lookup_string(args, "interval")))
        config->meas_ivl = atoi(val);
    if ((val = hash_lookup_string(args, "topn")))
        config->topn = atoi(val);
    if ((val = hash_lookup_string(args, "align-to")))
        config->last_export = atoi(val);
    if ((val = hash_lookup_string(args, "map"))) {
        /* example: map=tcp 21 ftp,tcp 22 ssh,udp 53 dns */
        while (val != NULL && *val != '\0') {
            char *next = strchr(val, ',');
            char *desc, *port_str;
            uint16_t port;
            size_t desc_len;

            if (next != NULL) {
                *next = '\0'; /* enforce null-termination of current atom */
                next++; /* prepare for next atom */
            }

            desc = strrchr(val, ' ');
            if (desc == NULL)
                goto error;

            port_str = strchr(val, ' ');
            if (port_str == NULL || port_str == desc)
                goto error;

            desc++;
            desc_len = strlen(desc) + 1;

            port_str++;
            port = atoi(port_str);

            if (!strncmp(val, "tcp ", 4)) {
                config->tcp_service[port] = mdl_malloc(self, desc_len);
                memcpy(config->tcp_service[port], desc, desc_len);
                goto done;
            } else if (!strncmp(val, "udp ", 4)) {
                config->udp_service[port] = mdl_malloc(self, desc_len);
                memcpy(config->udp_service[port], desc, desc_len);
                goto done;
            }

        error:
            warn("module topportsCC: arg atom `%s' not understood\n", val);
        done:
            val = next;
            continue;
        }

    }
    
    /* setup indesc */
    /*inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = TIME2TS(config->meas_ivl, 0);
    
    pkt = metadesc_tpl_add(inmd, "none:none:none:~tcp");
    N16(TCP(src_port)) = 0xffff;
    N16(TCP(dst_port)) = 0xffff;
    
    pkt = metadesc_tpl_add(inmd, "none:none:none:~udp");
    N16(UDP(src_port)) = 0xffff;
    N16(UDP(dst_port)) = 0xffff;*/

    self->flush_ivl = TIME2TS(config->meas_ivl, 0);
    return config;
}

