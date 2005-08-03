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

#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/socket.h> /* socket, bind, listen, accept */
#include <netinet/in.h> /* struct sockaddr_in */
#include <string.h>     /* bzero */
#include <errno.h>      /* errno */

#include "como.h"
#include "storage.h"
#include "query.h"


/*
 * This code implements the body of the query-ondemand process.
 * One instance is forked by SUPERVISOR right after accepting the
 * connection, and this process serves one single connection and
 * then terminates.
 */


/* global state */
extern struct _como map;


/* 
 * -- send_status
 * 
 * send the node status back to the client. status information 
 * include node name, location, software version, link speed, data source, 
 * and some load information (memory usage, no. of modules, average traffic). 
 */
static void
send_status(__unused qreq_t * req, int client_fd) 
{
    char buf[1024]; 
    int ret; 
    int len; 
    module_t *mdl;
    int idx;

    /* send HTTP header */
    ret = como_writen(client_fd, 
	    "HTTP/1.0 200 OK\nContent-Type: text/plain\n\n", 0);
    if (ret < 0) 
	panic("sending data to the client");  

    /* send name, location, version, build date, speed and data source 
     * all information that is static and present in the map 
     */
    len = sprintf(buf, 
	    "Name: %s\n"
	    "Location: %s\n" 
	    "Version: CoMo v%s\n"
	    "Build date: %s\n"
	    "Build time: %s\n"
	    "Speed: %s\n"
	    "Delay: %d\n",
	    map.name, map.location, COMO_VERSION, __DATE__, __TIME__,
	    map.linkspeed, map.stats->delay); 
    ret = como_writen(client_fd, buf, len);
    if (ret < 0)
	panic("sending status to the client");   

    /* send list of loaded modules */
    for (idx = 0; idx < map.module_count; idx++) { 
	mdl = &map.modules[idx]; 

	len = sprintf(buf, "Module: %-20s\tFilter: %s\n", mdl->name,
                      mdl->filter);
	ret = como_writen(client_fd, buf, len);
	if (ret < 0)
	    panic("sending status to the client");
    } 

    /* send comments if any */
    if (map.comment != NULL) { 
	len = sprintf(buf, "Comment: %s\n", map.comment); 
	ret = como_writen(client_fd, buf, len);
	if (ret < 0)
	    panic("sending status to the client");
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
            map.mem_size, map.stats->modules_active, map.module_count,
	    map.stats->pps_24hrs, map.stats->pps_1hr, map.stats->pps_5min); 
    ret = como_writen(client_fd, buf, len);
    if (ret < 0)
        panic("sending status to the client");
#endif
}


/*
 * -- getrecord
 *
 * This function reads a chunk from the file (as defined in the config file 
 * with the blocksize keyword). It then passes it to the load() callback to 
 * get the timestamp and the actual record length. 
 * 
 * Return values:
 *  - on success, returns a pointer to the record, its length and timestamp. 
 *   (with length > 0)
 *  - on 'end of bytestream', returns NULL and len=0
 *  - on 'error' (e.g. csmap failure), returns NULL and len != 0
 *  - on 'lost sync' (bogus data at the end of a file), returns
 *    a non-null (but invalid!) pointer GR_LOSTSYNC and ts = 0
 *
 */
#define	GR_LOSTSYNC	((void *)getrecord)
static void *
getrecord(int fd, off_t * ofs, load_fn *ld, size_t *len, timestamp_t *ts)
{
    size_t sz; 
    char * ptr; 

    assert(ld != NULL); 

    /* 
     * mmap len bytes starting from last ofs. 
     * 
     * len bytes are supposed to guarantee to contain
     * at least one record to make sure the load() doesn't
     * fail (note that only load knows the record length). 
     * 
     */ 
    ptr = csmap(fd, *ofs, len); 
    if (ptr == NULL) 
	return NULL;

    /* give the record to load() */
    sz = ld(ptr, *len, ts); 
    *ofs += sz; 

    /*
     * check if we have lost sync (indicated by a zero timestamp, i.e. 
     * the load() callback couldn't read the record, or by a load() callback
     * that asks for more bytes -- shouldn't be doing this given the 
     * assumption that we always read one full record. 
     * 
     * The only escape seems to be to seek to the beginning of the next 
     * file in the bytestream. 
     */
    if (*ts == 0 || sz > *len)
	ptr = GR_LOSTSYNC;

    *len = sz; 
    return ptr;
}



/* 
 * -- printrecord
 * 
 * calls the print() callback and sends all data to the client_fd
 *
 */
static void 
printrecord(module_t * mdl, char * ptr, char * args[], int client)  
{
    char * out; 
    size_t len; 

    out = mdl->callbacks.print(ptr, &len, args); 
    if (out == NULL) 
	panicx("module %s failed to print\n", mdl->name); 


    if (len > 0) {
	int ret = como_writen(client, out, len);
	if (ret < 0) 
	    panic("sending data to the client"); 
	logmsg(V_LOGQUERY, "print: %s\n", out); 
    }
}


/* 
 * -- replayrecord
 * 
 * replays a record generating a sequence of packets that are 
 * sent to the client. 
 * 
 */
static void 
replayrecord(module_t * mdl, char * ptr, int client) 
{
    char out[DEFAULT_REPLAY_BUFSIZE]; 
    size_t len; 
    int left; 
    int ret; 

    /*
     * one record may generate a large sequence of packets.
     * the replay() callback tells us how many packets are
     * left. we don't move to the next record until we are
     * done with this one.
     *
     * XXX there is no solution to this but the burden could
     *     stay with the module (in a similar way to
     *     sniffer-flowtools that has the same problem). this
     *     would require a method to allow modules to allocate
     *     memory. we need that for many other reasons too.
     *
     *     another approach that would solve the problem in
     *     certain cases is to add a metapacket field that
     *     indicates that a packet is a collection of packets.
     *
     *     in any case there is no definitive solution so we
     *     will have always to deal with this loop here.
     */
    do {
	len = DEFAULT_REPLAY_BUFSIZE;
	left = mdl->callbacks.replay(ptr, out, &len);
	if (left < 0)
	    panicx("%s.replay returns error", mdl->name);

	ret = como_writen(client, out, len);
	if (ret < 0)
	    panic("sending data to the client");
    } while (left > 0);
}


/*
 * -- query_ondemand
 *
 * This function is used for on-demand queries. It is called by
 * supervisor_mainloop() and runs in a new process. It is in charge of
 * authenticating the query, finding the relevant module output
 * data and send them back to the requester. 
 * 
 * A query comes over a TCP socket with the following information: 
 *
 *  . name, the module to run (the shared object must exist already)
 *  . filter, filter expression
 *  . start, start timestamp
 *  . end, end timestamp
 * 
 * XXX as of now, query_ondemand requires that the module has been running
 *     during the interval of interest. this way it just has to find the 
 *     output file, read them and send them "as is" to the client. 
 *
 */
void
query_ondemand(int client_fd)
{
    int idx;
    int ret; 
    module_t *mdl;
    qreq_t *req;
    int storage_fd, file_fd;
    off_t ofs; 
    char * output; 
    ssize_t len;
    int module_found; 

    /* set the name of this process */
    map.procname = "qd"; 
    setproctitle("ONDEMAND");

    /* connect to the supervisor so we can send messages */
    map.supervisor_fd = create_socket("supervisor.sock", NULL);
    logmsg(V_LOGWARN, "starting query-ondemand #%d: fd[%d] pid %d\n",
	client_fd, client_fd, getpid()); 

    if (map.debug) {
	if (strstr(map.debug, map.procname) != NULL) {
	    logmsg(V_LOGWARN, "waiting 60s for the debugger to attach\n");
	    sleep(60);
	    logmsg(V_LOGWARN, "wakeup, ready to work\n");
	}
    }

    req = (qreq_t *) qryrecv(client_fd); 
    if (req == NULL) {
	close(client_fd);
	return; 
    } 

    if (req->format == Q_STATUS) { 
	/* 
	 * status queries can always be answered. send 
	 * back the information about this CoMo instance (i.e., name, 
	 * location, version, etc.) 
	 */
	send_status(req, client_fd);
	close(client_fd);
	return; 
    }

    if (req->module == NULL) { 
	/* 
	 * no module defined. return warning message and exit
	 */
	logmsg(LOGWARN, "query module not defined\n"); 
	close(client_fd);
	return; 
    } 

    logmsg(V_LOGQUERY,
        "got query (%d bytes); mdl: %s filter: %s\n",  
        ntohs(req->len), req->module, req->filter); 
    logmsg(0, "    from %d to %d\n", req->start, req->end); 

    /* 
     * check if the module is running using the same filter 
     * 
     * XXX right now we just check if the module exists and is using the 
     *     exactly same filter. in the future we will have to check 
     *     if the module has been running during the interval of interest. 
     *     if not, we have to run it on the stored packet trace. 
     *     furthermore, the filter should be semantically equivalent but
     *     right now we check the syntax as well (i.e., right now "A and B" 
     *     is not the same as "B and A"). 
     * 
     */
    module_found = 0; 
    for (idx = 0; idx < map.module_count; idx++) { 
	mdl = &map.modules[idx]; 

	/* check module name */
	if (strcmp(req->module, mdl->name))
	    continue; 

	/* check filter string */
        module_found = 1;
	if (!strcmp(req->filter, mdl->filter)) 
	    break; 	/* found! */
    } 

    if (idx == map.module_count) { 
	/* 
	 * no module found. return an error message 
	 * to the client. 
	 */
        if (!module_found) {
	    logmsg(LOGWARN, "query module not found (%s)\n", req->module);
	    ret = como_writen(client_fd, 
		      "HTTP/1.0 404 Not Found\nContent-Type: text/plain\n\n"
		      "Module not found\n", 0);
        } else {
	    logmsg(LOGWARN, "query filter not found (%s)\n", req->filter);
	    ret = como_writen(client_fd, 
		      "HTTP/1.0 404 Not Found\nContent-Type: text/plain\n\n"
		      "Filter not found\n", 0);
	}
	if (ret < 0)
	    panic("sending data to the client"); 
	close(client_fd);
	return; 
    }

    /* 
     * connect to the storage process, open the module output file 
     * and then start reading the file and send the data back 
     */
    storage_fd = create_socket("storage.sock", NULL);

    logmsg(V_LOGQUERY, "opening file for reading (%s)\n", mdl->output); 
    file_fd = csopen(mdl->output, CS_READER, 0, storage_fd); 
    if (file_fd < 0) 
	panic("opening file %s", mdl->output);

    /* get start offset. this is needed because we access the file via
     * csmap instead of csreadp (that is not implemented yet) 
     */
    ofs = csgetofs(file_fd); 

    /*
     * initializations
     */
    switch (req->format) {
    case Q_OTHER:
	/*
	 * produce a response header
	 */
	if (mdl->callbacks.print == NULL) 
	    panicx("module %s does not support printing results\n", mdl->name); 
	ret = como_writen(client_fd, 
		"HTTP/1.0 200 OK\nContent-Type: text/plain\n\n", 0);
	if (ret < 0) 
	    panic("sending data to the client");  

	/* first print callback. we need to make sure that req->args != NULL. 
	 * if this is not the case we just make something up
	 */
	if (req->args == NULL) {
	    req->args = safe_calloc(1, sizeof(char **)); 
	    req->args[0] = NULL;
	} 
	printrecord(mdl, NULL, req->args, client_fd);
	break;
	
    case Q_COMO: 
	/*
	 * transmit the output stream description
	 */
	if (mdl->callbacks.outdesc == NULL || mdl->callbacks.replay == NULL)
	    panicx("module %s does not support trace replay\n", mdl->name); 
	ret = como_writen(client_fd, (char*) mdl->callbacks.outdesc, 
		sizeof(pktdesc_t)); 
	if (ret < 0)
	    panic("could not send pktdesc"); 

	/* allocate the output buffer */
	output = safe_malloc(DEFAULT_REPLAY_BUFSIZE); 
    }

    /*  
     * now look for the start time in the file 
     * 
     * XXX we do this without seeking the file. we read all the
     *     records one by one to find the beginning. very inefficient.
     *     one day STORAGE will support timestamp-based seeks.
     *  
     */
    for (;;) { 
	timestamp_t ts;
	char * ptr; 

        len = mdl->bsize; 
        ptr = getrecord(file_fd, &ofs, mdl->callbacks.load, &len, &ts);
        if (ptr == NULL) {	/* no data, but why ? */
	    if (len == -1) 
		panic("reading from file %s\n", mdl->output); 

	    if (len == 0) {
		logmsg(LOGQUERY, "reached end of file %s\n", mdl->output); 
		break;
	    }
	}

	/*
	 * Now we have either good data or or GR_LOSTSYNC.
	 * If lost sync, move to the next file and try again. 
	 */
	if (ptr == GR_LOSTSYNC) {
	    logmsg(LOGQUERY, "lost sync, trying next file %s\n", mdl->output); 
	    ofs = csseek(file_fd);
	    continue;
	}

    	if (TS2SEC(ts) < req->start)	/* before the required time. */
	    continue;
    	if (TS2SEC(ts) >= req->end) {
	    /* notify the end of stream to the module */
	    if (req->format == Q_OTHER) 
		printrecord(mdl, NULL, NULL, client_fd); 
	    logmsg(LOGQUERY, "query completed\n"); 
	    break;
	}

	switch (req->format) { 
	case Q_COMO: 	
	    replayrecord(mdl, ptr, client_fd); 
	    break; 

	case Q_RAW: 
	    /* send the data to the query client */
	    ret = como_writen(client_fd, ptr, len);
	    if (ret < 0) 
		panic("sending data to the client"); 
	    break;
            
	case Q_OTHER: 
	    printrecord(mdl, ptr, NULL, client_fd); 
	    break;
        }
    }

    /* close the socket and the file */
    close(client_fd);
    csclose(file_fd); 
}
