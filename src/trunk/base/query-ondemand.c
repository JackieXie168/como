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

#include <sys/types.h>		/* fork */
#include <unistd.h>		/* fork */
#include <string.h>
#include <assert.h>

#include "como.h"
#include "comopriv.h"
#include "query.h"
#include "ipc.h"


/* global state */
extern struct _como map;
static int client_fd;


/* 
 * -- start_ondemand_child
 * 
 * starts children of the query-ondemand process. 
 * this is used to start a special copy of CAPTURE and EXPORT. 
 *
 */
static void 
start_ondemand_child(procname_t who, int mem_type,
        void (*mainloop)(int out_fd, int in_fd), int fd)
{
    pid_t pid;
 
    /* ok, fork a regular process and return pid to the caller. */
    pid = fork();
    if (pid == 0) {     /* child */
        char *buf;
        int out_fd;
	int idx; 

        /* XXX TODO: close unneeded sockets */
        // fclose(stdout); // XXX
        // fclose(stderr); // XXX

        /*
         * every new process has to set its name, specify the type of memory
         * the modules will be able to allocate and use, and change the
         * process name accordingly.
         */
	map.parent = map.whoami; 
        map.whoami = who;
        map.mem_type = mem_type;

	/* 
	 * remove all modules. we will receive them with the 
	 * proper IPC_MODULE_ADD message. 
	 */
        for (idx = 0; idx < map.module_max; idx++)
            if (map.modules[idx].status != MDL_UNUSED)
                remove_module(&map, &map.modules[idx]);
        assert(map.module_used == 0);
        assert(map.module_last == -1);

	
        /* connect to the parent */
        out_fd = ipc_connect(map.parent);
        assert(out_fd > 0);

        asprintf(&buf, "%s", getprocfullname(who));
        setproctitle(buf);
        free(buf);

        logmsg(V_LOGWARN, "starting process %-20s pid %d\n",
               getprocfullname(who), getpid());

        mainloop(fd, out_fd);
        exit(EXIT_SUCCESS);
    }
}


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

    ret = como_writen(client_fd, (char *) buf, len);
    if (ret < 0)
	panic("sending data to the client");
}


/*
 * -- qd_ipc_done  
 *
 * EXPORT should send this message to report that there are
 * no more records to be processed. 
 *
 */
static void
qd_ipc_done(__unused procname_t sender, __unused int fd,
        __unused void * b, __unused size_t l)
{
    assert(map.running == INLINE);
    ipc_send(child(CAPTURE, getprocid(sender)), IPC_EXIT, NULL, 0);
    ipc_send(sender, IPC_EXIT, NULL, 0);
    ipc_finish();
    exit(EXIT_SUCCESS);
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

    /* 
     * the first thing to do is adapt the map to our needs. 
     * first set it to run in inline mode. then, set the sniffer 
     * to be sniffer-como to the module that we use as source. 
     */

    /* inline mode */
    map.running = INLINE; 

    /* disable all modules */
    for (idx = 0; idx < map.module_max; idx++)
	if (map.modules[idx].status == MDL_ACTIVE)
	    map.modules[idx].status = MDL_DISABLED;

    /* 
     * copy the module we want to run,
     * activate it and initialize it 
     * NOTE: use the query arguments as extra module arguments
     */
    map.inline_mdl = copy_module(&map, req->mdl, -1, -1, req->args); 
 
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

    /* initialize the shared memory */
    memory_init(16);		/* XXX fixed memory size... check this! */
    
    map.stats = mem_calloc(1, sizeof(stats_t)); 
    map.stats->mdl_stats = mem_calloc(map.module_max, sizeof(mdl_stats_t));
    gettimeofday(&map.stats->start, NULL); 
    map.stats->first_ts = ~0;

    /* prepare a socket to listen to children processes */
    ondemand_fd = ipc_listen(map.whoami); 

    /* register various IPC handlers */
    ipc_clear();
    ipc_register(IPC_SYNC, qd_ipc_sync);
    ipc_register(IPC_RECORD, qd_ipc_record); 
    ipc_register(IPC_DONE, qd_ipc_done); 

    /* 
     * store the output file descriptor in a global variable
     * accessible to the IPC handlers 
     */
    client_fd = fd; 
 
    /* now start a new CAPTURE process */ 
    tag = child(CAPTURE, fd); 
    capture_fd = ipc_listen(tag); 
    start_ondemand_child(tag, COMO_SHARED_MEM, capture_mainloop, capture_fd); 

    /* now start a new EXPORT process */ 
    tag = child(EXPORT, fd); 
    start_ondemand_child(tag, COMO_PRIVATE_MEM, export_mainloop, -1); 
    
    /* get ready for the mainloop */
    FD_ZERO(&valid_fds);
    max_fd = 0;
    max_fd = add_fd(ondemand_fd, &valid_fds, max_fd);

    for (;;) {
        fd_set r;
        int i, n_ready;
   
        r = valid_fds;
        n_ready = select(max_fd, &r, NULL, NULL, NULL);
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



