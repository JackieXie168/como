/*
 * Copyright (c) 2006 Intel Corporation
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

#include <unistd.h>
#include <time.h>

#include "como.h"
#include "comopriv.h"
#include "storage.h"
#include "ipc.h"


/* global state */
extern struct _como map;


/* 
 * -- send_status
 * 
 * send the node status back to the client. status information 
 * include node name, location, software version, link speed, data source, 
 * and some load information (memory usage, no. of modules, average traffic). 
 */
void
send_status(int client_fd, int node_id) 
{
    char buf[2048]; 
    char datebuf[30];
    module_t * mdl;
    node_t * node;
    time_t start, last; 
    struct tm * timedata; 
    int storage_fd;
    int ret, len, idx;
    int secs, dd, hh, mm, ss; 

    /* first find the node */ 
    for (node = map.node; node && node->id != node_id; node = node->next)
	; 
    if (node == NULL)
	panicx("cannot find virtual node %d", node_id); 

    /* send HTTP header */
    ret = como_writen(client_fd, 
	    "HTTP/1.0 200 OK\nContent-Type: text/plain\n\n", 0);
    if (ret < 0) 
	panic("sending data to the client");  

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
 
    /* add comments if any */
    if (node->comment != NULL) 
	len += sprintf(buf + len, "Comment: %s\n", node->comment); 

    /* send the results */
    ret = como_writen(client_fd, buf, len);
    if (ret < 0)
	panic("sending status to the client");   

    /* 
     * if this is the master node (i.e. node 0) and there 
     * are virtual nodes, send the list of virtual nodes as well
     */ 
    if (node_id == 0) { 
	for (node = map.node; node; node = node->next) {
	    if (node->id == 0) 
		continue; 

	    len = sprintf(buf, "Virtual: %s | %s | %s | ", 
			  node->name, node->location, node->type);

	    if (node->comment != NULL) 		/* add comments if any */
		len += sprintf(buf + len, "%s | ", node->comment); 

	    len += sprintf(buf + len, "%d | %s\n", 
			node->query_port, node->filter_str); 

	    ret = como_writen(client_fd, buf, len);
	    if (ret < 0)
		panic("sending status to the client");
	} 
    } 

    /* 
     * connect to the storage process, open the module output file 
     * and then start reading the file and send the data back 
     */
    storage_fd = ipc_connect(STORAGE); 

    /* send list of loaded modules */
    for (idx = 0; idx <= map.module_last; idx++) { 
	int file_fd; 
	off_t ofs; 
	size_t rlen, sz;
	timestamp_t ts; 
	char * ptr;

	mdl = &map.modules[idx]; 

	if (mdl->status == MDL_UNUSED) 
	    continue; 

	if (mdl->node != node_id)
	    continue; 

	/* we now look at the very first record for this module 
    	 * to get an idea on how far in the past a query could go. 
 	 */
	file_fd = csopen(mdl->output, CS_READER_NOBLOCK, 0, storage_fd);
	if (file_fd < 0)
	    panic("opening file %s", mdl->output);

	/* get start offset */
	ofs = csgetofs(file_fd);
	
	/* read first record */
	ts = 0;
	rlen = mdl->callbacks.st_recordsize;
	ptr = csmap(file_fd, ofs, (ssize_t *) &rlen);
	if (ptr && rlen > 0) {
	    /* we got something, give the record to load() */
	    sz = mdl->callbacks.load(mdl, ptr, rlen, &ts);
	}

	len = sprintf(buf, 
		"Module: %-15s | %s | %u | %s\n", 
		mdl->name, mdl->filter_str, TS2SEC(ts), mdl->callbacks.formats);

	ret = como_writen(client_fd, buf, len);
	if (ret < 0)
	    panic("sending status to the client");

	csclose(file_fd, 0);
    } 


#if 0 
    /* send usage information */
    len = sprintf(buf, 
            "Memory current: %.1fMB\n"
            "Memory peak: %.1fMB\n"
            "Memory size: %dMB\n"
            "Modules total: %d\n"  
            "Modules active: %d\n"  
	    "Avg. Packets/sec (24 hours): %d\n"
	    "Avg. Packets/sec (1 hour): %d\n"
	    "Avg. Packets/sec (5 minutes): %d\n",
            (float) map.stats->mem_usage_cur/(1024*1024),
            (float) map.stats->mem_usage_peak/(1024*1024),
            map.mem_size, map.stats->modules_active, map.module_used,
	    map.stats->pps_24hrs, map.stats->pps_1hr, map.stats->pps_5min); 
    ret = como_writen(client_fd, buf, len);
    if (ret < 0)
        panic("sending status to the client");
#endif

    /* print version and copyright information */
    len = sprintf(buf, "\n-- CoMo v%s (built: %s %s)\n", COMO_VERSION, 
		__DATE__, __TIME__); 

    ret = como_writen(client_fd, buf, len);
    if (ret < 0)
	panic("sending status to the client");

    close(storage_fd);
}
