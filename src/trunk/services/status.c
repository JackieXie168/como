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
#include <unistd.h>
#include <time.h>
#include <err.h>
#include <assert.h>

#include "como.h"
#include "comopriv.h"
#include "storage.h"
#include "ipc.h"
#include "query.h"


/* global state */
extern struct _como map;

static timestamp_t
start_timestamp(module_t * mdl)
{
    int file_fd = -1;
    off_t ofs;
    size_t rlen, sz;
    timestamp_t ts = 0;
    char *ptr;
    
    file_fd = csopen(mdl->output, CS_READER_NOBLOCK, 0);
    if (file_fd >= 0) {
	/* get start offset */
	ofs = csgetofs(file_fd);
	
	/* read first record */
	rlen = mdl->callbacks.st_recordsize;
	ptr = csmap(file_fd, ofs, (ssize_t *) &rlen);
	if (ptr && rlen > 0) {
	    /* we got something, give the record to load() */
	    sz = mdl->callbacks.load(mdl, ptr, rlen, &ts);
	}
    }
    csclose(file_fd, 0);
    
    return ts;
}


/* 
 * -- service_status
 * 
 * send the node status back to the client. status information 
 * include node name, location, software version, link speed, data source, 
 * and some load information (memory usage, no. of modules, average traffic). 
 */
int
service_status(int client_fd, int node_id,
               __attribute__((__unused__)) qreq_t * qreq) 
{
    char buf[2048]; 
    char datebuf[30];
    char * httpstr;
    module_t * mdl;
    node_t * node;
    time_t start, last; 
    struct tm * timedata; 
    int ret, len, idx;
    int secs, dd, hh, mm, ss; 
    uint64_t ld_15m = 0, ld_1h = 0, ld_6h = 0, ld_1d = 0;
    int i;
    timestamp_t node_src_ts = 0;

    /* first find the node */ 
    assert(node_id < map.node_count); 
    node = &map.node[node_id];

    /* send HTTP header */
    httpstr = "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n";
    ret = como_writen(client_fd, httpstr, strlen(httpstr)); 
    if (ret < 0) 
	err(EXIT_FAILURE, "sending status to the client [%d]", client_fd);

    /* send name, location, version, build date, speed and data source 
     * all information that is static and present in the map 
     */

    len = sprintf(buf, "\nNode: %s | %s | %s\n",
	    node->name, node->location, node->type); 

    /* print the starting time */
    start = TS2SEC(map.stats->first_ts); 
    timedata = gmtime(&start); 
    strftime(datebuf, sizeof(datebuf), "%a %B %e %T %Z %Y", timedata); 
    len += sprintf(buf + len, "Start: %u | %s\n", (unsigned) start, datebuf); 
		
    /* print the last timestamp */
    last = TS2SEC(map.stats->ts); 
    timedata = gmtime(&last); 
    strftime(datebuf, sizeof(datebuf), "%a %B %e %T %Z %Y", timedata); 
    len += sprintf(buf + len, "Current: %u | %s\n", (unsigned) last, datebuf); 
    
    /* print the duration */
    secs = last - start; 
    dd = secs / 86400;
    hh = (secs % 86400) / 3600;
    mm = (secs % 3600) / 60;
    ss = secs % 60;
    len += sprintf(buf + len, "Duration: %dd %dh %dm %ds\n", dd, hh, mm, ss); 
    
    if (node_id == 0) {
	/* print the load */
	for (i = 0; i < 15; i++) {
	    ld_15m += map.stats->load_15m[i];
	}
	for (i = 0; i < 60; i++) {
	    ld_1h += map.stats->load_1h[i];
	}
	for (i = 0; i < 360; i++) {
	    ld_6h += map.stats->load_6h[i];
	}
	for (i = 0; i < 1440; i++) {
	    ld_1d += map.stats->load_1d[i];
	}
	len += sprintf(buf + len, "Load: %llu | %llu | %llu | %llu\n",
		       ld_15m, ld_1h, ld_6h, ld_1d);
    }
    
    /* add comments if any */
    if (node->comment != NULL) 
	len += sprintf(buf + len, "Comment: %s\n", node->comment); 

    /* send the results */
    ret = como_writen(client_fd, buf, len);
    if (ret < 0)
	err(EXIT_FAILURE, "sending status to the client [%d]", client_fd);

    /* 
     * connect to the storage process, open the module output file 
     * and read the very first timestamp. we will send this information 
     * to let the user know how much past data is available to each module
     */
    ipc_connect(STORAGE); 

    /* 
     * if this is the master node (i.e. node 0) and there 
     * are virtual nodes, send the list of virtual nodes as well
     */ 
    if (node_id == 0) { 
	for (i = 1; i < map.node_count; i++) {
	    node_t * nd = &map.node[i];

	    len = sprintf(buf, "Virtual: %s | %s | %s | ", 
			  nd->name, nd->location, nd->type);

	    if (nd->comment != NULL) 		/* add comments if any */
		len += sprintf(buf + len, "%s | ", nd->comment); 

	    len += sprintf(buf + len, "%d | %s\n", 
			nd->query_port, nd->filter_str); 

	    ret = como_writen(client_fd, buf, len);
	    if (ret < 0)
		err(EXIT_FAILURE, "sending status to the client [%d]",
		    client_fd);
	} 
    } else {
	mdl = module_lookup(node->source, 0); /* the source is in the node 0 */
	if (mdl) {
	    node_src_ts = start_timestamp(mdl);
	}
    }

    /* send list of loaded modules */
    for (idx = 0; idx <= map.module_last; idx++) {
	timestamp_t ts;
	alias_t * alias;

	mdl = &map.modules[idx]; 

	if (mdl->status == MDL_UNUSED) 
	    continue; 

	if (mdl->node != node_id)
	    continue; 

	if (mdl->running != RUNNING_ON_DEMAND) {
	    /* we now look at the very first record for this module 
    	     * to get an idea on how far in the past a query could go. 
 	     */
 	    ts = start_timestamp(mdl);
	} else {
	    ts = node_src_ts;
	}
	    
	len = sprintf(buf, "Module: %-15s | %s | %u | %s%s | %s\n",
		      mdl->name, mdl->filter_str, TS2SEC(ts),
		      mdl->callbacks.formats,
		      mdl->callbacks.replay ? " como" : "",
		      (mdl->description? mdl->description : "--"));

	ret = como_writen(client_fd, buf, len);
	if (ret < 0)
	    err(EXIT_FAILURE, "sending status to the client [%d]", client_fd);

	/* 
	 * before moving to the next module, check if this one has 
         * any aliases. we should print them as well in the ?status query
         */ 
	for (alias = map.aliases; alias; alias = alias->next) { 
	     if (strcmp(alias->module, mdl->name) != 0) 
		continue; 

	    len = sprintf(buf, "Module: %-15s | %s | %u | %s%s | %s\n",
		      alias->name, mdl->filter_str, TS2SEC(ts),
		      mdl->callbacks.formats,
		      mdl->callbacks.replay ? " como" : "",
		      (alias->description? alias->description : "--"));
	    ret = como_writen(client_fd, buf, len);
	    if (ret < 0)
		err(EXIT_FAILURE, 
		    "sending status to the client [%d]", client_fd);
	 } 
    } 

    /* print version and copyright information */
    len = sprintf(buf, "\n-- CoMo v%s (built: %s %s)\n", COMO_VERSION, 
		__DATE__, __TIME__); 

    ret = como_writen(client_fd, buf, len);
    if (ret < 0)
	err(EXIT_FAILURE, "sending status to the client [%d]", client_fd);

    return 0;
}
