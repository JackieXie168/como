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

#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/socket.h> /* socket, bind, listen, accept */
#include <netinet/in.h> /* struct sockaddr_in */
#include <string.h>     /* bzero */
#include <err.h>
#include <errno.h>      /* errno */

#include "como.h"
#include "comopriv.h"
#include "storage.h"
#include "query.h"
#include "ipc.h"


/*
 * This code implements the body of the query-ondemand process.
 * One instance is forked by SUPERVISOR right after accepting the
 * connection, and this process serves one single connection and
 * then terminates.
 */

/* global state */
extern struct _como map;

#define HTTP_RESPONSE_404 \
"HTTP/1.0 404 Not Found\r\n" \
"Content-Type: text/plain\r\n\r\n"

#define HTTP_RESPONSE_405 \
"HTTP/1.0 405 Method Not Allowed\r\n" \
"Content-Type: text/plain\r\n\r\n"


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

    if (req->module == NULL) {
        /*
         * no module defined. return warning message and exit
         */
        logmsg(LOGWARN, "query module not defined\n");
	sprintf(httpstr, HTTP_RESPONSE_405
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
         
	sprintf(httpstr, HTTP_RESPONSE_405
		"Query start time after end time\n");
        return httpstr;
    }

    /* check if the module is present in the current configuration */
    req->mdl = module_lookup_with_name_and_node(req->module, node_id);
    if (req->mdl == NULL) {
	/*
	 * the module is not present in the configuration file 
	 */
	logmsg(LOGWARN, "module %s not found\n", req->module);
	sprintf(httpstr, HTTP_RESPONSE_404
                "Module \"%s\" not found in the current configuration\n", 
		req->module);
	return httpstr;
    } 

    if (!req->mdl->callbacks.print && 
	 (req->format == Q_OTHER || req->format == Q_HTML)) {
	/*
	 * the module exists but does not support printing records. 
	 */
	logmsg(LOGWARN, "module \"%s\" does not have print()\n", req->module);
	sprintf(httpstr, HTTP_RESPONSE_405
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
	if (req->mdl->running == RUNNING_ON_DEMAND) {
	    /*
	     * module is running on-demand: it needs a source
	     */
	    logmsg(LOGWARN,
		   "module on-demand %s can't be queried without a source\n",
		   req->mdl->name);
	    
	    sprintf(httpstr, HTTP_RESPONSE_405
		    "Module \"%s\" is running on-demand. A source is required "
		    "to run it.\n", req->mdl->name);
	    return httpstr;
	}
	
	if (req->filter_str != NULL) { 
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
		logmsg(LOGWARN, 
		       "module %s found but it is not using filter (%s)\n",
		       req->module, req->filter_str); 
		sprintf(httpstr, HTTP_RESPONSE_404
			"Module %s found but it is not using filter \"%s\"\n", 
			req->module, req->filter_str);
		free(running_filter);
		return httpstr;
	    }
	    free(running_filter);
	}
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
	req->src = module_lookup_with_name_and_node(req->source, node_id);
	if (req->src == NULL) {
            /* No source module found,
             * return an error message to the client and finish
             */
            logmsg(LOGWARN, "source module not found (%s)\n", req->source);
	    sprintf(httpstr, HTTP_RESPONSE_404
		    "Source module \"%s\" not found\n", 
		    req->source); 
            return httpstr;
        }

/*FIXME	if (!req->src->callbacks.outdesc || !req->src->callbacks.replay) {*/
	if (!req->src->callbacks.replay) {
	    /*	
	     * the source module does not have the replay() callback or 
	     * a description of the packets it can generate. return an 
	     * error message 
	     */
            logmsg(LOGWARN, "source module \"%s\" does not support replay()\n",
		   req->source);
	    sprintf(httpstr, HTTP_RESPONSE_405
		    "Source module \"%s\" does not support replay()\n", 
		    req->source); 
            return httpstr;
        }
    } 

    return NULL;		/* everything OK, nothing to say */
}


inline static void
handle_print_fail(module_t *mdl)
{
    if (errno == ENODATA) {
	panicx("module \"%s\" failed to print\n", mdl->name);
    } else {
	err(EXIT_FAILURE, "sending data to the client");
    }
}


inline static void
handle_replay_fail(module_t *mdl)
{
    if (errno == ENODATA) {
	panicx("module \"%s\" failed to print\n", mdl->name);
    } else {
	err(EXIT_FAILURE, "sending data to the client");
    }
}

inline static void
handle_db_eof(qreq_t * req, int client_fd) 
{
    logmsg(V_LOGQUERY, "reached end of file %s\n", req->src->output);

    /* notify the end of stream to the module */
    if (req->format == Q_OTHER || req->format == Q_HTML) {
	if (module_db_record_print(req->mdl, NULL, NULL, client_fd)) {
	    handle_print_fail(req->mdl);
	}
    }
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
    int supervisor_fd, storage_fd, file_fd;
    off_t ofs; 
    ssize_t len;
    int mode, ret;
    char * httpstr;
    char *null_args[] = {NULL};

    /* 
     * every new process has to set its name, specify the type of memory
     * the modules will be able to allocate and use, and change the process
     * name accordingly. 
     */
    map.parent = map.whoami; 
    map.whoami = buildtag(map.parent, QUERY, client_fd);
    map.mem_type = COMO_PRIVATE_MEM;
    setproctitle(getprocfullname(map.whoami));

    /* connect to the supervisor so we can send messages */
    supervisor_fd = ipc_connect(SUPERVISOR); 
    logmsg(V_LOGWARN, "starting process QUERY #%d: node %d pid %d\n",
	client_fd, node_id, getpid()); 

    if (map.debug) {
	if (strstr(map.debug, getprocname(map.whoami)) != NULL) {
	    logmsg(V_LOGWARN, "waiting 20s for the debugger to attach\n");
	    sleep(20);
	    logmsg(V_LOGWARN, "wakeup, ready to work\n");
	}
    }

    req = (qreq_t *) qryrecv(client_fd, map.stats->ts); 
    if (req == NULL) {
	close(client_fd);
	close(supervisor_fd);
	return; 
    } 

    logmsg(LOGQUERY,
        "query (%d bytes); node: %d mdl: %s filter: %s\n",  
        ntohs(req->len), node_id, req->module, req->filter_str); 
    if (req->filter_str) 
	logmsg(V_LOGQUERY, "    filter: %s\n", req->filter_str);
    logmsg(V_LOGQUERY, "    from %d to %d\n", req->start, req->end); 
    if (req->args != NULL) { 
	int n; 

        for (n = 0; req->args[n]; n++) 
	    logmsg(V_LOGQUERY, "    args: %s\n", req->args[n]); 
    } 

    if (req->format == Q_STATUS) { 
	/* 
	 * status queries can always be answered. send 
	 * back the information about this CoMo instance (i.e., name, 
	 * location, version, etc.) 
	 */
	send_status(client_fd, node_id);
	close(client_fd);
	close(supervisor_fd);
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
	if (como_writen(client_fd, httpstr, strlen(httpstr)) < 0) 
	    err(EXIT_FAILURE, "sending data to the client [%d]", client_fd); 
        close(client_fd);
        close(supervisor_fd);
	return;
    }
    
    /*
     * initializations
     */
    httpstr = NULL;
    switch (req->format) {
    case Q_OTHER:
        httpstr = "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n";
	break;

    case Q_HTML:
	httpstr = "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n";
	break;

    case Q_COMO:
	// httpstr = "HTTP/1.0 200 OK\r\n"
	//	  "Content-Type: application/octet-stream\r\n\r\n";
	break;
    }
    
    if (httpstr != NULL) {
	/*
	 * produce a response header
	 */
	if (como_writen(client_fd, httpstr, strlen(httpstr)) < 0) 
	    err(EXIT_FAILURE, "sending data to the client");  
    }

    /* 
     * if we have to retrieve the data using the replay callback of
     * another module instead of reading the output file of the module,
     * go to query_ondemand that will fork a new CAPTURE and EXPORT to 
     * execute this query.
     */
    if (req->source) {
	query_ondemand(client_fd, req, node_id); 
	assert_not_reached();
    }

    switch (req->format) {
    case Q_OTHER:
    case Q_HTML:
	/* first print callback. we need to make sure that req->args != NULL. 
	 * if this is not the case we just make something up
	 */
	if (req->args == NULL) {
	    req->args = null_args;
	}
	if (module_db_record_print(req->mdl, NULL, req->args, client_fd) < 0)
	    handle_print_fail(req->mdl);
	break;
    case Q_COMO:
#if 0
FIXME
        /*
         * transmit the output stream description
         */
        ret = como_writen(client_fd, (char*) req->src->callbacks.outdesc,
                          sizeof(pktdesc_t));
        if (ret < 0)
            panic("could not send pktdesc");
#endif
	break;
    }

    req->src = req->mdl; 	/* the source is the same as the module */
    
    /* 
     * connect to the storage process, open the module output file 
     * and then start reading the file and send the data back 
     */
    storage_fd = ipc_connect(STORAGE);

    logmsg(V_LOGQUERY, "opening file for reading (%s)\n", req->src->output); 
    mode =  req->wait? CS_READER : CS_READER_NOBLOCK; 
    file_fd = csopen(req->src->output, mode, 0, storage_fd); 
    if (file_fd < 0) 
	panic("opening file %s", req->src->output);


    /* quickly seek the file from which to start the search */
    ofs = module_db_seek_by_ts(req->src, file_fd, TIME2TS(req->start, 0));
    if (ofs == -1) {
	panic("seeking file %s", req->src->output);
    }

    for (;;) { 
	timestamp_t ts;
	char * ptr; 

        len = req->src->callbacks.st_recordsize; 
        ptr = module_db_record_get(file_fd, &ofs, req->src, &len, &ts);
        if (ptr == NULL) {	/* no data, but why ? */
	    if (len == 0) { 
		handle_db_eof(req, client_fd); 
		break;
	    }
	    panic("reading from file %s ofs %lld len %d", 
		  req->src->output, ofs, len); 
	}

	/*
	 * Now we have either good data or GR_LOSTSYNC.
	 * If lost sync, move to the next file and try again. 
	 */
	if (ptr == GR_LOSTSYNC) {
	    ofs = csseek(file_fd, CS_SEEK_FILE_NEXT);
	    if (ofs == -1) { 
		/* no more data, notify the end of the 
		 * stream to the module
		 */ 
		handle_db_eof(req, client_fd); 
                break;
	    } 
	    logmsg(LOGQUERY, "lost sync, trying next file %s/%016llx\n", 
		req->src->output, ofs); 
	    continue;
	}

    	if (ts < TIME2TS(req->start, 0))	/* before the required time. */
	    continue;
    	if (ts >= TIME2TS(req->end, 0)) {
	    /* 
	     * ask the module to send the message footer if it 
	     * has any to send. 
	     */  
	    switch (req->format) { 
	    case Q_OTHER:
	    case Q_HTML:
		if (module_db_record_print(req->mdl, NULL, NULL, client_fd))
		    handle_print_fail(req->mdl);
		break;
#if 0
	    /*
	     * DISABLED and UNUSED and BROKEN: broken because
	     * module_db_record_replay should be called with NULL prt also
	     * when the end of file is reached
	     */
	    case Q_COMO:
		if (module_db_record_replay(req->src, NULL, client_fd))
		    handle_replay_fail(req->src);
		break;
#endif
	    default:
		break;
	    } 

	    logmsg(LOGQUERY, "query completed\n"); 
	    
	    break;
	}

	switch (req->format) { 
	case Q_COMO: 	
	    if (module_db_record_replay(req->src, ptr, client_fd))
		handle_replay_fail(req->src);
	    break; 

	case Q_RAW: 
	    /* send the data to the query client */
	    ret = como_writen(client_fd, ptr, len);
	    if (ret < 0) 
		err(EXIT_FAILURE, "sending data to the client"); 
	    break;
		
	case Q_OTHER: 
	case Q_HTML:
	    if (module_db_record_print(req->mdl, ptr, NULL, client_fd))
		handle_print_fail(req->mdl);
	    break;
	}
    }
    
    /* close the file with STORAGE */
    csclose(file_fd, 0);
    /* close the socket and the file */
    close(client_fd);
    close(storage_fd);
    close(supervisor_fd);
}
