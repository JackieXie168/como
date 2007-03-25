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

#define HTTP_RESPONSE_400 \
"HTTP/1.0 400 Bad Request\r\n" \
"Content-Type: text/plain\r\n\r\n"

#define HTTP_RESPONSE_404 \
"HTTP/1.0 404 Not Found\r\n" \
"Content-Type: text/plain\r\n\r\n"

#define HTTP_RESPONSE_405 \
"HTTP/1.0 405 Method Not Allowed\r\n" \
"Content-Type: text/plain\r\n\r\n"

#define HTTP_RESPONSE_500 \
"HTTP/1.0 500 Internal Server Error\r\n" \
"Content-Type: text/plain\r\n\r\n"

enum {
    FORMAT_COMO = -2,
    FORMAT_RAW = -3
};

const qu_format_t QU_FORMAT_COMO =
{FORMAT_COMO, "como", "application/octet-stream"};

const qu_format_t QU_FORMAT_RAW =
{FORMAT_RAW, "raw", "application/octet-stream"};

/* vars 'inherited' from SU */
extern stats_t *como_stats;
extern como_config_t *como_config;

/* 
 * -- query_validate
 * 
 * validates a query checking that the timestamps are correct, 
 * the module names are recognized and that the format of the entire
 * query is valid. it returns NULL in case of success or a string 
 * containing the HTTP error string in case of failure. 
 *
 */
static char * 
query_validate(qreq_t * req, como_node_t * node)
{
    static char httpstr[2048];
    mdl_t *mdl;
    mdl_iquery_t *iq;

    if (req->module == NULL) {
        /*
         * no module defined. return warning message and exit
         */
        warn("query module not defined\n");
	sprintf(httpstr, HTTP_RESPONSE_400
		"Module name is missing\n"); 
        return httpstr;
    }

    if (req->start > req->end) {
        /*
         * start time is after end time, return error message
         */
        warn("query start time (%d) after end time (%d)\n", 
               req->start, req->end);
         
	sprintf(httpstr, HTTP_RESPONSE_400
		"Query start time after end time\n");
        return httpstr;
    }

    /* check if the module is present in the current configuration */
    mdl = mdl_lookup(node->mdls, req->module);
    if (mdl == NULL) {
	/*
	 * the module is not present in the configuration file.
	 * check if we have an alias instead.  
	 */
#if 0
	alias_t * alias; 
	int nargs, i; 

	for (alias = map.aliases; alias; alias = alias->next) {
	    if (strcmp(alias->name, req->module) == 0) 
		break;
	} 

	if (alias == NULL) {
#endif
	    warn("module %s not found\n", req->module);
	    sprintf(httpstr, HTTP_RESPONSE_404
		    "Module `%s' not found in the current configuration\n",
		    req->module);
	    return httpstr;
#if 0
	} 
	req->mdl = module_lookup(alias->module, node_id); 

	/* count the query arguments */
	for (nargs = 0; req->args[nargs]; nargs++)
	    ; 

	/* add the alias arguments to the query */
	req->args = safe_realloc(req->args,
				 (1 + nargs + alias->ac)*sizeof(char *));
	for (i = nargs; i < nargs + alias->ac; i++) 
	    req->args[i] = safe_strdup(alias->args[i - nargs]); 

	req->args[nargs + alias->ac] = NULL;
#endif
    }

    /*
     * mdl comes from supervisor
     * create a shallow copy of mdl but with a different private state
     */
    req->mdl = como_new0(mdl_t);
    *req->mdl = *mdl;
    req->mdl->priv = NULL;
    mdl_load(req->mdl, PRIV_IQUERY);
    
    iq = mdl_get_iquery(req->mdl);

    /*
     * if necessary first get the default format
     */
    if (req->format == NULL)
        req->format = como_strdup(iq->dflt_format);
    if (req->format == NULL) /* mdl has no default */
        req->format = como_strdup("plain");
    
    /*
     * set the qu_format
     */
    if (strcmp(req->format, "como") == 0) {
	req->qu_format = &QU_FORMAT_COMO;
    } else if (strcmp(req->format, "raw") == 0) {
	req->qu_format = &QU_FORMAT_RAW;
    } else {
	int i;
	for (i = 0; iq->formats[i].id != -1; i++) {
	    if (strcmp(iq->formats[i].name, req->format) == 0)
		break;
	}
	if (iq->formats[i].id == -1) {
	    /*
	     * the module exists but doesn't support the given output format
	     */
	    warn("module `%s' does not support format `%s'\n",
		 req->module, req->format);
	    sprintf(httpstr, HTTP_RESPONSE_500
		    "Module `%s' does not support format `%s'\n", 
		    req->module, req->format);
	    return httpstr;
	}
	req->qu_format = &iq->formats[i];
    }


    if (iq->print_rec == NULL && 
	(req->qu_format != &QU_FORMAT_COMO &&
	req->qu_format != &QU_FORMAT_RAW)) {
	/*
	 * the module exists but does not support printing records. 
	 */
	warn("module `%s' does not have print()\n", req->module);
	sprintf(httpstr, HTTP_RESPONSE_500
                "Module `%s' does not have print() callback\n", 
		req->module);
	return httpstr;
    } 

    if (iq->replay == NULL && req->qu_format == &QU_FORMAT_COMO) {
	/*	
	 * the module does not have the replay() callback
	 */
        warn("module `%s' does not have replay()\n", req->module);
	sprintf(httpstr, HTTP_RESPONSE_500
		"Module `%s' does not have replay() callback\n", 
		req->module);
	return httpstr;
    }

    /* validation of virtual nodes and ondemand queries */
#if 0
    /* 
     * virtual nodes require some additional manipolation of 
     * the query string. 
     */ 
    if (node_id > 0) {	/* virtual node */
        /*
         * set the source to whatever it is configured to be.
         * we also need to add the virtual node filter to filter_str;
         *
         * XXX this code assumes that query-ondemand sets the sniffer
         *     always only for the master node modules.
         */ 
        node_t * node = &map.node[node_id];
        
        if (req->source == NULL)
            req->source = safe_strdup(node->source);
        if (req->filter_str != NULL) {
            char * k = req->filter_str;
            asprintf(&req->filter_str, "(%s) and (%s)", node->filter_str, k);
            free(k);   
        } else {
            req->filter_str = req->mdl->filter_str;
        }
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
	    
	    sprintf(httpstr, HTTP_RESPONSE_400
		    "Module `%s' is running on-demand. A source is required "
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
			"Module %s found but it is not using filter `%s'\n", 
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
	 * 
	 * XXX the source is always a module running in the master node. 
	 */
	req->src = mdl_lookup(mdls, req->source);
	if (req->src == NULL) {
            /* No source module found,
             * return an error message to the client and finish
             */
            warn("source module not found (%s)\n", req->source);
	    sprintf(httpstr, HTTP_RESPONSE_404
		    "Source module `%s' not found\n", 
		    req->source); 
            return httpstr;
        }

/*FIXME	if (!req->src->callbacks.outdesc || !req->src->callbacks.replay) */
	if (!mdl_get_iquery(req->src)->replay) {
	    /*	
	     * the source module does not have the replay() callback or 
	     * a description of the packets it can generate. return an 
	     * error message 
	     */
            warn("source module `%s' does not support replay()\n",
		   req->source);
	    sprintf(httpstr, HTTP_RESPONSE_500
		    "Source module `%s' does not support replay()\n", 
		    req->source); 
            return httpstr;
        }
    }
#endif

    return NULL;		/* everything OK, nothing to say */
}
#if 0


inline static void
handle_print_fail(module_t *mdl)
{
    if (errno == ENODATA) {
	panicx("module `%s' failed to print\n", mdl->name);
    } else {
	err(EXIT_FAILURE, "sending data to the client");
    }
}


inline static void
handle_replay_fail(module_t *mdl)
{
    if (errno == ENODATA) {
	panicx("module `%s' failed to print\n", mdl->name);
    } else {
	err(EXIT_FAILURE, "sending data to the client");
    }
}


/*
 * -- qu_ipc_module_add
 *
 * handle IPC_MODULE_ADD messages by unpacking the module
 * and activating it.
 *
 */
static void
qu_ipc_module_add(procname_t src, __attribute__((__unused__)) int fd,
                  void * pack, size_t sz)
{
    module_t tmp;
    module_t * mdl;

    /* only the parent process should send this message */
    assert(src == map.parent);

    /* unpack the received module info */
    if (unpack_module(pack, sz, &tmp)) {
        logmsg(LOGWARN, "error when unpack module in IPC_MODULE_ADD\n");
        return;
    }

    /* find an empty slot in the modules array */
    mdl = copy_module(&map, &tmp, tmp.node, tmp.index, NULL);

    /* free memory from the tmp module */
    clean_module(&tmp);

    if (activate_module(mdl, map.libdir)) 
        logmsg(LOGWARN, "error when activating module %s\n", mdl->name);
}


/* 
 * -- qu_ipc_start 
 * 
 * once we get the IPC_START message from SUPERVISOR we can start
 * looking into the query itself... 
 *
 */
static void
qu_ipc_start(procname_t sender, __attribute__((__unused__)) int fd,
             __attribute__((__unused__)) void * buf,
             __attribute__((__unused__)) size_t len)
{
    /* only SUPERVISOR should send this message */
    assert(sender == map.parent);
    s_wait_for_modules = 0;
}
#endif

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

#define query_ondemand(...)

void
query_main(UNUSED ipc_peer_full_t * child, ipc_peer_t * parent,
	   UNUSED memmap_t * shmemmap, int client_fd, como_node_t * node)
{
    qreq_t req;
    int storage_fd, file_fd, supervisor_fd;
    off_t ofs; 
    int mode, ret;
    char *httpstr;
    timestamp_t ts, end_ts;
    char *dbname;
    void *como_qu;
    int format_id;
    mdl_iquery_t *iq;
    alc_t *alc;
    uint8_t *sbuf;
    void *mdlrec;

    log_set_program("QU");
    supervisor_fd = ipc_peer_get_fd(parent);
    memset(&como_qu, 0, sizeof(como_qu));

    /* 
     * wait for the debugger to attach
     */
    DEBUGGER_WAIT_ATTACH("qu");

    ipc_set_user_data(&como_qu);
#ifdef MONO_SUPPORT
    proxy_mono_init(como_config->mono_path);
#endif

    /* XXX needed? handle the message from SUPERVISOR */ 
    /*while (s_wait_for_modules) 
	ipc_handle(supervisor_fd); */
 
    ret = query_recv(&req, client_fd, como_stats->ts); 

    if (ret < 0) {
    	if (ret != -1) {
	    switch (ret) {
	    case -400:
		httpstr = HTTP_RESPONSE_400;
		break;
	    case -405:
		httpstr = HTTP_RESPONSE_405;
		break;
	    }
	    if (como_write(client_fd, httpstr, strlen(httpstr)) < 0) {
		error("sending data to the client [%d]", client_fd);
	    }
    	}
	close(client_fd);
	close(supervisor_fd);
	return; 
    } 

    if (req.mode == QMODE_SERVICE) {
	service_fn service = service_lookup(req.service);
	if (service) {
	    service(client_fd, node, &req);
	}
	close(client_fd);
	close(supervisor_fd);
	return;
    }

    debug("query: node: %s (#%d) module: %s\n",
	   node->name, node->id, req.module, req.filter_str); 
    if (req.filter_str)
	debug("       filter: %s\n", req.filter_str);
    if (req.source)
	debug("       source: %s\n", req.source);
    debug("       format: %s\n", req.format ? req.format : "(default)");
    debug("       from %d to %d, wait %s\n", req.start, req.end,
	   req.wait ? "yes" : "no");
#ifdef DEBUG
    if (req.args != NULL) { 
	hash_iter_t it;
        hash_iter_init(req.args, &it);
        debug("\targs:\n");
        while(hash_iter_next(&it))
            debug("\t\t%s=>%s\n",
                    hash_iter_get_string_key(&it),
                    hash_iter_get_value(&it));
    }
#endif

    /* 
     * validate the query and find the relevant modules. 
     *
     * req.mdl will contain a pointer to the module that has to 
     * run the print() callback. 
     * 
     * req.src will point to the module that has to run load() or 
     * replay() callback. 
     * 
     * req.mdl and req.src are the same if load()/print() is all we 
     * need to do. they will be different for the load()/replay()/... 
     * cycle. 
     * 
     */
    httpstr = query_validate(&req, node);
    if (httpstr != NULL) { 
	if (como_write(client_fd, httpstr, strlen(httpstr)) < 0) 
	    error("sending data to the client [%d]", client_fd); 
        close(client_fd);
        close(supervisor_fd);
	return;
    }

    /*
     * produce a response header
     */
    httpstr = NULL;
    httpstr = como_asprintf("HTTP/1.0 200 OK\r\nContent-Type: %s\r\n\r\n",
			    req.qu_format->content_type);
    if (como_write(client_fd, httpstr, strlen(httpstr)) < 0)
	error("sending data to the client");
    free(httpstr);

    /* 
     * if we have to retrieve the data using the replay callback of
     * another module instead of reading the output file of the module,
     * go to query_ondemand that will fork a new CAPTURE and EXPORT to 
     * execute this query.
     */
    if (req.source) {
        warn("TODO -- query_ondemand\n");
	query_ondemand(client_fd, &req, node_id); 
	assert_not_reached();
    }
    
    iq = mdl_get_iquery(req.mdl);
    iq->client_fd = client_fd;
    
    format_id = req.qu_format->id;

    /* 
     * connect to the storage process, open the module output file 
     * and then start reading the file and send the data back 
     */
    storage_fd = ipc_connect(COMO_ST);

    dbname = como_asprintf("%s/%s/%s", como_env_dbdir(), node->name,
			   req.mdl->name);
    debug("opening file for reading (%s)\n", dbname); 
    mode =  req.wait ? CS_READER : CS_READER_NOBLOCK; 
    file_fd = csopen(dbname, mode, 0, (ipc_peer_t *) COMO_ST);

    if (file_fd < 0) 
	error("opening file %s\n", dbname);

    /* seek on the first record */
    ts = TIME2TS(req.start, 0);
    end_ts = TIME2TS(req.end, 0);

#define module_db_record_replay(...) NULL
#define handle_replay_fail(...) error("TODO: handle_replay_fail\n")
    ofs = csseek_ts(file_fd, ts);
    if (ofs >= 0) {
	/* at this point at least one record exists as we seek on it */
	switch (format_id) {
        case FORMAT_RAW:
	case FORMAT_COMO:
	    /*
	     * TODO:transmit the output stream description
	     */
	    break;
	default:
            /*
             * set up a FILE * to be able to fprintf() to the user.
             */
            iq->clientfile = fdopen(client_fd, "w");
            if (iq->clientfile == NULL) 
                error("cannot fdopen() on client_fd\n");

	    /*
             * first print callback. we need to make sure that req.args != NULL. 
	     * if this is not the case we just make something up
	     */
	    iq->state = iq->init(req.mdl, format_id, req.args);
            debug("module `%s': qu_init() done\n", req.mdl->name);

	    break;
	}
	for (;;) {
	    csrec_t *rec;
	    
	    rec = csgetrec(file_fd, ofs);
	    if (rec == NULL) {
		ofs = csseek(file_fd, CS_SEEK_FILE_NEXT);
		if (ofs == -1) {
		    /* no more data, notify the end of the
		     * stream to the module
		     */
		    notice("reached end of file %s\n", dbname);
		    break;
		}
		notice("lost sync, trying next file %s/%016llx\n",
		       dbname, ofs);
		continue;
	    }
	    
	    if (rec->ts >= end_ts) {
                debug("end -- next ts is %llu, end ts is %llu\n", rec->ts, end_ts);
		break;
	    }
	    
	    switch (format_id) {
	    case FORMAT_COMO: 	
		if (module_db_record_replay(req.mdl, ptr, client_fd))
		    handle_replay_fail(req.mdl);
		break;

	    case FORMAT_RAW: 
		/* send the data to the query client */
		ret = como_write(client_fd, rec, rec->sz);
		if (ret < 0) 
		     err(EXIT_FAILURE, "sending data to the client"); 
		break;

	    default:
                /* TODO: deserialize rec */
                sbuf = (uint8_t *) &rec->ts;
                alc = como_alc();
                req.mdl->priv->mdl_record.deserialize(&sbuf, &mdlrec, alc);
                iq->print_rec(req.mdl, format_id, mdlrec, iq->state);
                break;
	    }
	    
	    ofs += rec->sz;
	}
	/* notify the end of stream to the module */
	if (format_id != FORMAT_COMO && format_id != FORMAT_RAW) {
	    /* print the footer */
	    iq->finish(req.mdl, format_id, iq->state);
	}
    }
    free(dbname);

    /* close the file with STORAGE */
    csclose(file_fd, 0);
    /* close the socket and the file */
    close(client_fd);
    close(storage_fd);
    close(supervisor_fd);
}
