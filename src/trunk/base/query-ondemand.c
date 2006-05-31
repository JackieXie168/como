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

#include <sys/types.h>		/* fork */
#include <unistd.h>		/* fork */
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <err.h>

#include "como.h"
#include "comopriv.h"
#include "query.h"
#include "ipc.h"


/* global state */
extern struct _como map;

#define QD_CHILDREN_COUNT	2 /* only CA and EX */
static child_info_t qd_children[QD_CHILDREN_COUNT];

/*
 * -- qd_ipc_sync()
 *
 * on receipt of an IPC_SYNC just send a start message. 
 * the processes already have all modules. 
 *
 */
static void
qd_ipc_sync(procname_t sender, __unused int fd, __unused void * b,
            __unused size_t l)
{
    char * pack;
    int sz;

    /* 
     * prepare the module for transmission and 
     * send it to the new process 
     */ 
    pack = pack_module(map.inline_mdl, &sz);
    ipc_send(sender, IPC_MODULE_ADD, pack, sz);
    free(pack);

    ipc_send(sender, IPC_MODULE_START, &map.stats, sizeof(void *));
}

#if 0
/*
 * -- qd_ipc_record
 *
 * prints a record to screen. this is used only when running
 * in inline mode
 *
 */  
static void
qd_ipc_record(__unused procname_t sender, __unused int fd, 
	void * buf, size_t len)
{
    int ret; 

    /* NOTE: len includes \0 */
    ret = como_writen(client_fd, (char *) buf, len - 1);
    if (ret < 0)
	errx(EXIT_FAILURE, "sending data to the client");
}
#endif

/*
 * -- qd_ipc_done  
 *
 * EXPORT should send this message to report that there are
 * no more records to be processed. 
 *
 */
static void
qd_ipc_done(procname_t sender, __unused int fd,
        __unused void * b, __unused size_t l)
{
    assert(map.running == INLINE);
    ipc_send(child(CAPTURE, getprocid(sender)), IPC_EXIT, NULL, 0);
    ipc_send(sender, IPC_EXIT, NULL, 0);
    ipc_finish();
    exit(EXIT_SUCCESS);
}


/*
 * -- defchld
 * 
 * handle dead children
 * 
 */
static void
defchld(__unused int si_code)
{
    if (handle_children(qd_children, QD_CHILDREN_COUNT))
	exit(EXIT_FAILURE);
}


/* 
 * -- query_ondemand
 * 
 * this function will create a new map with just one module 
 * (the one we are querying) and a sniffer-como set to receive
 * packets from the source module(s). it will then fork CAPTURE 
 * and EXPORT, have them run in inline mode and behave as a SUPERVISOR. 
 * 
 */ 
void 
query_ondemand(int fd, qreq_t * req, int node_id) 
{
    node_t * node; 
    source_t * src; 
    char sniffstr[2048];
    int len, idx, nargs; 
    int ondemand_fd; 
    procname_t tag; 
    fd_set valid_fds;
    int max_fd, capture_fd;
    
    /* catch some signals */
    signal(SIGCHLD, defchld);		/* catch SIGCHLD (defunct children) */

    /* 
     * the first thing to do is adapt the map to our needs. 
     * first set it to run in inline mode. then, set the sniffer 
     * to be sniffer-como to the module that we use as source. 
     */

    /* inline mode */
    map.running = INLINE;
    /* 
     * store the output file descriptor in a the map in order to make it
     * accessible to EXPORT
     */
    map.inline_fd = fd;

    /* disable all modules */
    for (idx = 0; idx < map.module_max; idx++)
	if (map.modules[idx].status == MDL_ACTIVE)
	    map.modules[idx].status = MDL_DISABLED;
    /* enable the source module for record replaying */
    req->src->status = MDL_ACTIVE_REPLAY;

    /* initialize the shared memory */
    memory_init(16);		/* XXX 16MB fixed memory size... check this! */
    
    /* 
     * copy the module we want to run,
     * activate it and initialize it 
     * NOTE: use the query arguments as extra module arguments
     */
    map.inline_mdl = copy_module(&map, req->mdl, -1, -1, req->args); 
    if (req->filter_str) {
	map.inline_mdl->filter_str = safe_strdup(req->filter_str);
    }
 
    if (activate_module(map.inline_mdl, map.libdir))
	panicx("cannot activate %s", map.inline_mdl->name); 

    if (init_module(map.inline_mdl))		
        panicx("cannot initialize module %s\n", map.inline_mdl->name);
   
    /* remove all current sources (i.e. sniffers) */
    while (map.sources) { 
	src = map.sources; 
	map.sources = src->next; 
	free(src); 
    } 

    /* find the virtual node this query refers to */
    for (node = map.node; node && node->id != node_id; node = node->next) 
	;
//#define REMOTE_QUERY
#ifdef REMOTE_QUERY
    /* now configure a new sniffer-como */
    len = snprintf(sniffstr, sizeof(sniffstr), 
        "http://localhost:%d/?module=%s&start=%d&end=%d&format=como&wait=no", 
	node->query_port, req->source, req->start, req->end); 

    /* add the arguments */
    for (nargs = 0; req->args[nargs]; nargs++) {
	if (strncmp("format=", req->args[nargs], 7) == 0)
	    continue;
	len += snprintf(sniffstr + len, sizeof(sniffstr) - len, 
			"&%s", req->args[nargs]); 
    }
    
    /* create the entry in the map */
    add_sniffer(&map, "como", sniffstr, NULL); 
#else
    /* now configure a new sniffer-ondemand */
    nargs = 0;
    len = snprintf(sniffstr, sizeof(sniffstr), "node=%d start=%lld end=%lld",
		   node_id, TIME2TS(req->start, 0), TIME2TS(req->end, 0));
    add_sniffer(&map, "ondemand", req->source, sniffstr);
#endif
    map.stats = mem_calloc(1, sizeof(stats_t)); 
    gettimeofday(&map.stats->start, NULL); 
    map.stats->first_ts = ~0;

    /* prepare a socket to listen to children processes */
    ondemand_fd = ipc_listen(map.whoami); 

    /* register various IPC handlers */
    ipc_clear();
    ipc_register(IPC_SYNC, qd_ipc_sync);
    ipc_register(IPC_DONE, qd_ipc_done); 

    /* now start a new CAPTURE process */ 
    tag = child(CAPTURE, fd); 
    capture_fd = ipc_listen(tag); 
    start_child(tag, COMO_SHARED_MEM, capture_mainloop, capture_fd,
		qd_children, SU_CHILDREN_COUNT);

    /* now start a new EXPORT process */ 
    tag = child(EXPORT, fd); 
    start_child(tag, COMO_PRIVATE_MEM, export_mainloop, -1,
		qd_children, SU_CHILDREN_COUNT);
    
    /* get ready for the mainloop */
    FD_ZERO(&valid_fds);
    max_fd = 0;
    max_fd = add_fd(fd, &valid_fds, max_fd);
    max_fd = add_fd(ondemand_fd, &valid_fds, max_fd);

    for (;;) {
        fd_set r;
        int i, n_ready;
   
        r = valid_fds;
        n_ready = select(max_fd, &r, NULL, NULL, NULL);
        /* first check if the client is still there */
	if (FD_ISSET(fd, &r)) {
	    char t;
	    int ret;
	    ret = read(fd, &t, 1);
	    if (ret <= 0) {
		/* client is gone */
		errx(EXIT_FAILURE, "client is gone");
	    }
	}
        for (i = 0; n_ready > 0 && i < max_fd; i++) {
            int ipcr; 

            if (!FD_ISSET(i, &r))
                continue;

            n_ready--;
            if (i == ondemand_fd) {
                int x;
                x = accept(i, NULL, NULL);
                if (x < 0) 
                    panic("accept fd[%d] got %d (%s)", i, x);
                else 
                    max_fd = add_fd(x, &valid_fds, max_fd);
                continue;
            }
            ipcr = ipc_handle(i);
            switch (ipcr) {
            case IPC_ERR: 
                /* an error. close the socket */
                panicx("error on IPC handle from %d", i);
            case IPC_EOF:
                close(i);
                max_fd = del_fd(i, &valid_fds, max_fd);
                break;
            }
        }
    }
}



