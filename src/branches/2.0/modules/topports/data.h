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

como_tuple struct _tuple {
    timestamp_t ts;			/* timestamp of first packet */
    uint16_t maxtcpport;		/* max TCP port used */
    uint16_t maxudpport;		/* max UDP port used */
    double tcpbytes[65536];		/* TCP bytes per port number */
    double tcppkts[65536];		/* TCP pkts per port number */
    double udpbytes[65536];		/* UDP bytes per port number */
    double udppkts[65536];		/* UDP pkts per port number */
};

como_record struct record {
    timestamp_t ts;
    uint8_t  proto;             /* protocol */
    uint16_t port;              /* port number */
    uint64_t bytes;             /* bytes/port number */
    uint32_t pkts;              /* pkts/port number */
};

como_config struct config {
    uint16_t topn;    			/* number of top ports */
    uint32_t meas_ivl;			/* interval (secs) */
    uint32_t last_export;       	/* last export time */
    char * tcp_service[65536]; 		/* TCP application names */ 
    char * udp_service[65536];		/* UDP application names */
};

typedef struct _tuple tuple_t;
typedef struct record record_t;
typedef struct config config_t;

#define GETMAX(a, b) ((a) > (b) ? (a) : (b))
#define GETMIN(a, b) ((a) > (b) ? (b) : (a))

