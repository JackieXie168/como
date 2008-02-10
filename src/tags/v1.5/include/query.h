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


#ifndef _COMO_QUERY_H
#define _COMO_QUERY_H

#ifdef linux
#include <stdint.h>		/* uint8_t, etc. */
#endif

#include "comotypes.h"

/* 
 * well known port numbers
 */
#define QSERV_PORT  	44444

typedef enum qmode_t {
    QMODE_MODULE,
    QMODE_SERVICE
} qmode_t;

typedef enum qformat_t {
    QFORMAT_CUSTOM = 0,	/* any format (print() should know better) */
    QFORMAT_RAW,	/* raw binary data */
    QFORMAT_COMO,	/* output of replay() callback */
    QFORMAT_HTML	/* print() with format=html */
} qformat_t;

/* 
 * query request message 
 */
typedef struct qreq_t {
    qmode_t	mode;		/* query request mode */
    char *	module;		/* module name */
    char *	service;	/* service name */
    char *	filter_str;	/* filter string */
    char *	filter_cmp;	/* filter canonical form */
    uint32_t	start;		/* query starts at */
    uint32_t	end;		/* query ends at */
    int		wait;		/* set if query should wait for data */
    qformat_t	format;		/* query response format */

    char *	source;		/* source module to read data from */
    char **	args;		/* arguments to be passed to module */

    module_t *	mdl;		/* module producing data -- using print() */
    module_t *	src;		/* module retrieving data -- using load() */
} qreq_t;

/* 
 * prototypes 
 */
void query          (int client_fd, int supervisor_fd, int node_id);
int  query_recv     (qreq_t * q, int sd, timestamp_t now);
void query_ondemand (int client, qreq_t * req, int node_id);

/*
 * services
 */
typedef int (*service_fn) (int client_fd, int node_id, qreq_t * qreq);

service_fn service_lookup(const char *name);

#endif /* _COMO_QUERY_H */
