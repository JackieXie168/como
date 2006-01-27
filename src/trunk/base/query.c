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
send_status(int client_fd, int node_id) 
{
    char buf[2048]; 
    module_t * mdl;
    node_t * node;
    int storage_fd;
    int ret; 
    int len; 
    int idx;

    /* first find the node */ 
    for (node = &map.node; node && node->id != node_id; node = node->next)
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
    len = sprintf(buf, 
	    "Name: %s\n"
	    "Location: %s\n" 
	    "Version: CoMo v%s\n"
	    "Build date: %s\n"
	    "Build time: %s\n"
	    "Speed: %s\n"
	    "Start: %u\n"
	    "Current: %u\n",
	    node->name, node->location, 
	    COMO_VERSION, __DATE__, __TIME__, node->type, 
	    (uint) TS2SEC(map.stats->first_ts), (uint) TS2SEC(map.stats->ts)); 

    /* add comments if any */
    if (node->comment != NULL) 
	len += sprintf(buf + len, "Comment: %s\n", node->comment); 

    /* send the results */
    ret = como_writen(client_fd, buf, len);
    if (ret < 0)
	panic("sending status to the client");   

    /* 
     * connect to the storage process, open the module output file 
     * and then start reading the file and send the data back 
     */
    storage_fd = create_socket("storage.sock", NULL);

    /* send list of loaded modules */
    for (idx = 0; idx < map.module_count; idx++) { 
	int file_fd; 
	off_t ofs; 
	size_t rlen, sz;
	timestamp_t ts; 
	char * ptr;

	mdl = &map.modules[idx]; 

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
	rlen = mdl->bsize;
	ptr = csmap(file_fd, ofs, &rlen);
	if (ptr && rlen > 0) {
	    /* we got something, give the record to load() */
	    sz = mdl->callbacks.load(ptr, rlen, &ts);
	}

	len = sprintf(buf, 
		"Module: %-20s\tFilter: %s\tFormats: %s\tStart: %12u\n", 
		mdl->name, mdl->filter_str, mdl->callbacks.formats, TS2SEC(ts));

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
            map.mem_size, map.stats->modules_active, map.module_count,
	    map.stats->pps_24hrs, map.stats->pps_1hr, map.stats->pps_5min); 
    ret = como_writen(client_fd, buf, len);
    if (ret < 0)
        panic("sending status to the client");
#endif

    close(storage_fd);
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
getrecord(int fd, off_t * ofs, load_fn *ld, ssize_t *len, timestamp_t *ts)
{
    ssize_t sz; 
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
void 
printrecord(module_t * mdl, char * ptr, char * args[], int client)  
{
    char * out; 
    size_t len; 
    int i; 

    for (i = 0; args != NULL && args[i] != NULL; i++) 
	logmsg(V_LOGQUERY, "print arg #%d: %s\n", i, args[i]); 

    out = mdl->callbacks.print(ptr, &len, args);
    if (out == NULL) 
        panicx("module %s failed to print\n", mdl->name); 

    if (len > 0) {
        int ret = como_writen(client, out, len);
	if (ret < 0) 
	    panic("sending data to the client"); 
	logmsg(V_LOGDEBUG, "print: %s\n", out); 
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
    int left, count; 
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
    count = 0;
    do {
	len = DEFAULT_REPLAY_BUFSIZE;
	left = mdl->callbacks.replay(ptr, out, &len, &count);
	if (left < 0)
	    panicx("%s.replay returns error", mdl->name);

	ret = como_writen(client, out, len);
	if (ret < 0)
	    panic("sending data to the client");
    } while (left > 0);
}


/* 
 * -- validate_query
 * 
 * validates a query checking that the timestamps are correct, 
 * the module names are recognized and that the format of the entire
 * query is valid. it returns NULL in case of success or a string 
 * containing the HTTP error string in case of failure. 
 *
 */
static char * 
validate_query(qreq_t * req, int node_id)
{
    static char httpstr[8192];
    int idx;

    if (req->module == NULL) {
        /*
         * no module defined. return warning message and exit
         */
        logmsg(LOGWARN, "query module not defined\n");
	sprintf(httpstr, "HTTP/1.0 405 Method Not Allowed\n"
                         "Content-Type: text/plain\n\n"
                         "Module name is missing\n"); 
        return httpstr;
    }

    if (req->start > req->end) {
        /*
         * start time is after end time, return error message
         */
        logmsg(LOGWARN,
               "query start time (%d) after end time (%d)\n", 
               req->start, req->end);
         
	sprintf(httpstr, "HTTP/1.0 405 Method Not Allowed\n"
		         "Content-Type: text/plain\n\n"
                         "Query start time after end time\n");
        return httpstr;
    }

    /* check if the module is present in the configuration file */
    for (idx = 0; idx < map.module_count; idx++) {
        req->mdl = &map.modules[idx];

	if (node_id != req->mdl->node) 
	    continue; 

        /* check module name */
        if (!strcmp(req->module, req->mdl->name)) 
	    break;
    }

    if (idx == map.module_count) { 
	/*
	 * the module is not present in the configuration file 
	 */
	logmsg(LOGWARN, "module %s not found\n", req->module);
	sprintf(httpstr, 
		"HTTP/1.0 404 Not Found\n"
	 	"Content-Type: text/plain\n\n"
                "Module %s not found in the current configuration\n", 
		req->module);
	return httpstr;
    } 

    if (!req->mdl->callbacks.print && 
	 (req->format == Q_OTHER || req->format == Q_HTML)) {
	/*
	 * the module exists but does not support printing records. 
	 */
	logmsg(LOGWARN, "module \"%s\" does not have print()\n", req->module);
	sprintf(httpstr, 
		"HTTP/1.0 405 Method Not Allowed\n"
	 	"Content-Type: text/plain\n\n"
                "Module \"%s\" does not have print() callback\n", 
		req->module);
	return httpstr;
    } 
	
    /* 
     * there are two types of queries. the ones that just need to print or 
     * retrieve the data stored by a running instance of a module and the 
     * ones that require to process the output data of a different module 
     * (i.e. chain together two modules as defined by "source=..." in the 
     * query). 
     *
     * in the first case we have to make sure that the running module is 
     * using the same filter that is present in the query (we need that also
     * to distinguish between multiple instances of the same module). 
     * 
     * in the second case (if req->source is not NULL) we need to make sure
     * the source module actually exists. 
     * 
     * XXX we do not support the existance of multiple modules that have the
     *     same name as the source module but different filters. we assume
     *     whoever posted the query knew what was going on...
     * 
     * XXX in the future we will have to check if the module has been running
     *     during the interval of interest.
     */
    if (!req->source) { 
	char * running_filter; 

	parse_filter(req->mdl->filter_str, NULL, &running_filter); 

	/* 
	 * source is not defined, hence we just want to read 
	 * the output file. check the filter of the running modules. 
	 * it needs to be the same as the requested one otherwise the 
	 * query result would not be the ones we are looking for.  
	 */
	if (strcmp(req->filter_cmp, running_filter)) { 
	    /*
	     * the module is not present in the configuration file 
	     */
	    logmsg(LOGWARN, "module %s found but it is not using filter (%s)\n",
		req->module, req->filter_str); 
	    sprintf(httpstr, 
		    "HTTP/1.0 404 Not Found\n"
		    "Content-Type: text/plain\n\n"
		    "Module %s found but it is not using filter \"%s\"\n", 
		    req->module, req->filter_str);
	    return httpstr;
	}
	free(running_filter);
    } else { 
	/* 
	 * a source is defined. go look for it and forget about the 
	 * filter defined in the query. we will have to instantiate a
	 * new module anyway. 
	 * 
	 * XXX we are assuming that whoever posts the query is aware 
	 *     of the filtering that the source module could have done
	 *     on the data and we don't do any checks on that.
	 */
        for (idx = 0; idx < map.module_count; idx++) {
            req->src = &map.modules[idx];
            if (!strcmp(req->source, req->src->name))
		break;
        }
        
	if (idx == map.module_count) {
            /* No source module found,
             * return an error message to the client and finish
             */
            logmsg(LOGWARN, "source module not found (%s)\n", req->source);
	    sprintf(httpstr, 
		    "HTTP/1.0 404 Not Found\n"
		    "Content-Type: text/plain\n\n"
		    "Source module \"%s\" not found\n", 
		    req->source); 
            return httpstr;
        }

	if (!req->src->callbacks.outdesc || !req->src->callbacks.replay) {
	    /*	
	     * the source module does not have the replay() callback or 
	     * a description of the packets it can generate. return an 
	     * error message 
	     */
            logmsg(LOGWARN, "source module \"%s\" does not support replay()\n",
		   req->source);
	    sprintf(httpstr, 
		    "HTTP/1.0 404 Not Found\n"
		    "Content-Type: text/plain\n\n"
		    "Source module \"%s\" does not support replay()\n", 
		    req->source); 
            return httpstr;
        }
    } 

    return NULL;		/* everything OK, nothing to say */
}



/*
 * -- query
 *
 * This function is used for all queries. It is called by
 * supervisor_mainloop() and runs in a new process. It is in charge of
 * authenticating the query, finding the relevant module output
 * data and send them back to the requester. 
 * 
 * A query comes over a TCP socket with the following information: 
 *
 *  . name, the module to run (the shared object must exist already)
 *  . filter, filter expression
 *  . time, interval of interest 
 *  . source, data source if not one of the running sniffers 
 *  . format, to define the output format of the query
 * 
 * XXX as of now, if "source" is not defined, query_ondemand requires 
 *     that the module has been running during the interval of interest. 
 *     if "source" is defined then that module replay() callback is used. 
 *     in the future, query should independently pick the most appropriate
 *     source of data.
 *
 */
void
query(int client_fd, int node_id)
{
    qreq_t *req;
    int storage_fd, file_fd;
    off_t ofs; 
    char * output; 
    ssize_t len;
    int mode, ret;
    char * httpstr;

    /* set the name of this process */
    map.procname = "qd"; 
    setproctitle("ONDEMAND");

    /* connect to the supervisor so we can send messages */
    map.supervisor_fd = create_socket("supervisor.sock", NULL);
    logmsg(V_LOGWARN, "starting process QUERY #%d: node %d pid %d\n",
	client_fd, node_id, getpid()); 

    if (map.debug) {
	if (strstr(map.debug, map.procname) != NULL) {
	    logmsg(V_LOGWARN, "waiting 60s for the debugger to attach\n");
	    sleep(60);
	    logmsg(V_LOGWARN, "wakeup, ready to work\n");
	}
    }

    if (map.il_mode) {
        /* we are in inline mode. we need to do the accept on the socket
         * before reading any data, because supervisor cannot do this for us
         * as it is acting as our client now */
        struct sockaddr_in addr;
	socklen_t slen;
        int old_client_fd;
	    
	slen = sizeof(addr);
        old_client_fd = client_fd;
        client_fd = accept(old_client_fd, (struct sockaddr *)&addr, &slen);
	if (client_fd < 0) {
	    /* check if accept was unblocked by a signal */
	    if (errno == EINTR) {
		logmsg(LOGWARN, "accept unblocked by a signal\n");
                close(client_fd);
                return;
            }

	    logmsg(LOGWARN, "accepting connection: %s\n",
		   strerror(errno));
	}
        
	close(old_client_fd);
        
        logmsg(LOGQUERY, 
	       "query from %s on fd %d\n", 
               inet_ntoa(addr.sin_addr), client_fd);
    }
    
    req = (qreq_t *) qryrecv(client_fd, map.stats->ts); 
    if (req == NULL) {
	close(client_fd);
	return; 
    } 

    logmsg(V_LOGQUERY,
        "got query (%d bytes); mdl: %s filter: %s\n",  
        ntohs(req->len), req->module, req->filter_str); 
    logmsg(0, "    from %d to %d\n", req->start, req->end); 

    if (req->format == Q_STATUS) { 
	/* 
	 * status queries can always be answered. send 
	 * back the information about this CoMo instance (i.e., name, 
	 * location, version, etc.) 
	 */
	send_status(client_fd, node_id);
	close(client_fd);
	return; 
    }

    /* 
     * validate the query and find the relevant modules. 
     *
     * req->mdl will contain a pointer to the module that has to 
     * run the print() callback. 
     * 
     * req->src will point to the module that has to run load() or 
     * replay() callback. 
     * 
     * req->mdl and req->src are the same if load()/print() is all we 
     * need to do. they will be different for the load()/replay()/... 
     * cycle. 
     * 
     */
    httpstr = validate_query(req, node_id);
    if (httpstr != NULL) { 
	if (como_writen(client_fd, httpstr, 0) < 0) 
	    panic("sending data to the client [%d]", client_fd); 
        close(client_fd);
	return;
    } 
	
    /* 
     * if we have to retried the data using the replay callback of
     * another module instead of reading the output file of the module,
     * we need to create a new instance of the module itself. 
     */
    if (req->source) {
	init_ondemand_module(&req->mdl, req->args); 
    } else { 
	req->src = req->mdl; 	/* the source is the same as the module */
    } 
    
    /* 
     * connect to the storage process, open the module output file 
     * and then start reading the file and send the data back 
     */
    storage_fd = create_socket("storage.sock", NULL);

    logmsg(V_LOGQUERY, "opening file for reading (%s)\n", req->src->output); 
    mode =  req->wait? CS_READER : CS_READER_NOBLOCK; 
    file_fd = csopen(req->src->output, mode, 0, storage_fd); 
    if (file_fd < 0) 
	panic("opening file %s", req->src->output);

    /* get start offset. this is needed because we access the file via
     * csmap instead of csreadp (that is not implemented yet) 
     */
    ofs = csgetofs(file_fd);

    /*
     * initializations
     */
    httpstr = NULL;
    switch (req->format) {
    case Q_OTHER:
        asprintf(&httpstr, "HTTP/1.0 200 OK\nContent-Type: text/plain\n\n");
	/* pass thru */

    case Q_HTML:
        if (httpstr == NULL)
	    asprintf(&httpstr, "HTTP/1.0 200 OK\nContent-Type: text/html\n\n");

	/*
	 * produce a response header
	 */
	if (como_writen(client_fd, httpstr, 0) < 0) 
	    panic("sending data to the client");  
	free(httpstr);

	/* first print callback. we need to make sure that req->args != NULL. 
	 * if this is not the case we just make something up
	 */
	if (req->args == NULL) {
	    req->args = safe_calloc(1, sizeof(char **)); 
	    req->args[0] = NULL;
	} 
	printrecord(req->mdl, NULL, req->args, client_fd);
	break;
	
    case Q_COMO: 
	/*
	 * transmit the output stream description
	 */
	ret = como_writen(client_fd, (char*) req->src->callbacks.outdesc, 
			  sizeof(pktdesc_t)); 
	if (ret < 0)
	    panic("could not send pktdesc");

	/* allocate the output buffer */
	output = safe_calloc(1, DEFAULT_REPLAY_BUFSIZE);
        break;
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

        len = req->src->bsize; 
        ptr = getrecord(file_fd, &ofs, req->src->callbacks.load, &len, &ts);
        if (ptr == NULL) {	/* no data, but why ? */
	    if (len == -1) 
		panic("reading from file %s\n", req->src->output); 

	    if (len == 0) {
		/* notify the end of stream to the module */
		if (req->format == Q_OTHER || req->format == Q_HTML) 
		    printrecord(req->mdl, NULL, NULL, client_fd); 
		logmsg(LOGQUERY, "reached end of file %s\n", req->src->output); 
		break;
	    }
	}

	/*
	 * Now we have either good data or or GR_LOSTSYNC.
	 * If lost sync, move to the next file and try again. 
	 */
	if (ptr == GR_LOSTSYNC) {
	    ofs = csseek(file_fd);
	    logmsg(LOGQUERY, "lost sync, trying next file %s/%016llx\n", 
		req->src->output, ofs); 
	    continue;
	}

    	if (TS2SEC(ts) < req->start)	/* before the required time. */
	    continue;
    	if (TS2SEC(ts) >= req->end) {
	    /* 
	     * we have reached the end of the stream 
	     * we want to notify the module that there are 
	     * no more records so that it can cleanup data 
	     * structures and send the last messages if needed
	     */
	    if (req->source) {
		replay_source(req->mdl, req->src, NULL, client_fd);
	    } else { 
	       /* 
	        * ask the module to send the message footer if it 
		* has any to send. 
	        */  
		switch (req->format) { 
		case Q_OTHER:
		case Q_HTML:
		    printrecord(req->mdl, NULL, NULL, client_fd); 
		    break;

		case Q_COMO: 
		    replayrecord(req->src, NULL, client_fd);
		    break;
	    
		default:
		    break;
		} 
	    } 

	    logmsg(LOGQUERY, "query completed\n"); 
	    break;
	}

	if (req->source) {
	    replay_source(req->mdl, req->src, ptr, client_fd);
	} else { 
	    switch (req->format) { 
	    case Q_COMO: 	
		replayrecord(req->src, ptr, client_fd);
		break; 

	    case Q_RAW: 
		/* send the data to the query client */
		ret = como_writen(client_fd, ptr, len);
		if (ret < 0) 
		    panic("sending data to the client"); 
		break;
		
	    case Q_OTHER: 
	    case Q_HTML:
		printrecord(req->mdl, ptr, NULL, client_fd); 
		break;
	    }
	}
    }

    /* close the socket and the file */
    close(client_fd);
    csclose(file_fd, 0); 
    close(storage_fd);
}
