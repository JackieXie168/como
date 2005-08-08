/*
 * Copyright (c) 2004 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id$
 */

#ifndef _COMO_QUERY_H
#define _COMO_QUERY_H

#ifdef linux
#include <stdint.h>		/* uint8_t, etc. */
#endif


/* 
 * well known port numbers
 */
#define QSERV_PORT  	44444

/* 
 * query request message 
 */
struct _query_req
{
    uint16_t len; 		/* message length */
    char * module;		/* module name */
    char * filter; 		/* filter expression */
    uint32_t start;             /* query starts at */
    uint32_t end;               /* query ends at */
    int wait; 			/* set if query should wait for data */
    uint format;                /* query response format */
#define Q_OTHER		154	/* any format (print() should know better) */
#define Q_RAW		235	/* raw binary data */
#define Q_COMO		324	/* output of dump() callback */
#define Q_STATUS	542	/* node status, no module data */

    char ** args; 		/* query arguments to be passed to module*/
};

typedef struct _query_req qreq_t;

/* 
 * prototypes 
 */
void query_ondemand(int);
qreq_t * qryrecv(int); 



#endif /* _COMO_QUERY_H */
