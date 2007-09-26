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
 * This module ranks addresses in terms of bytes.
 * The IP addresses can be destination or sources. 
 */
#include "como.h"

typedef struct tophwaddr_tuple tophwaddr_tuple_t;
typedef struct tophwaddr_record tophwaddr_record_t;
typedef struct tophwaddr_config tophwaddr_config_t;

#define HW_ADDR_SIZE 6

como_tuple struct tophwaddr_tuple {
    timestamp_t ts;             /* timestamp */
    uint8_t addr[HW_ADDR_SIZE]; /* src/dst address */ 
    uint64_t bytes;	        /* number of bytes */
    uint32_t pkts;	        /* number of packets */
    uint32_t hash;              /* hash of the addr */
};

como_record struct tophwaddr_record {
    timestamp_t ts;             /* timestamp */
    uint8_t addr[HW_ADDR_SIZE]; /* src/dst address */ 
    uint64_t bytes;	        /* number of bytes */
    uint32_t pkts;	        /* number of packets */
};

como_config struct tophwaddr_config {
    int use_dst; 		/* set if we should use destination address */ 
    int topn;			/* number of top destinations */
    uint32_t meas_ivl;		/* interval (secs) */
    uint32_t mask; 		/* privacy mask */
    uint32_t last_export;	/* last export time */
};

