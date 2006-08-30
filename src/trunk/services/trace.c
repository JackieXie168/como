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
#include <signal.h>
#include <unistd.h>
#include <errno.h>

#include "como.h"
#include "ipc.h"
#include "query.h"

int
service_trace(int client_fd, __unused int node_id, qreq_t * qreq)
{
    int capture_fd;
    cca_t * cca;
    char *http_resp;
    treenode_t *filter = NULL;
    int ret = 0;

    signal(SIGPIPE, SIG_IGN);
    
    /* send HTTP header */
    http_resp = "HTTP/1.0 200 OK\r\n"
		"Content-Type: application/octet-stream\r\n\r\n";
    ret = como_writen(client_fd, http_resp, strlen(http_resp)); 
    if (ret < 0)
	goto error;

    capture_fd = ipc_connect(CAPTURE);
    if (capture_fd < 0)
	goto error;
    
    cca = cca_open(capture_fd);
    if (cca == NULL)
	goto error;
    

    if (qreq->filter_str != NULL &&
	parse_filter(qreq->filter_str, &filter, NULL) != 0)
	goto error;
	
    for (;;) {
	pkt_t * pkt;
	int x;
	pkt = cca_next_pkt(cca);
	if (filter != NULL && evaluate(filter, pkt) == 0) {
	    continue;
	}
	
	x = como_writen(client_fd, (char *) pkt, sizeof(pkt_t));
	if (x < 0) {
	    logmsg(LOGWARN, "service trace error: %s\n", strerror(errno));
	    break;
	}
	/* TODO: padding */
	x = como_writen(client_fd, pkt->payload, pkt->caplen);
	if (x < 0) {
	    logmsg(LOGWARN, "service trace error: %s\n", strerror(errno));
	    break;
	}
    }

done:
    if (cca)
	cca_destroy(cca);
    if (capture_fd)
	close(capture_fd);

    return ret;

error:
    ret = -1;
    goto done;
}
