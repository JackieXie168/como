/*
 * Copyright (c) 2004, Intel Corporation
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
#include <stdlib.h>
#include <unistd.h>     /* mkstemp */
#include <sys/wait.h>	/* wait3() */
#include <string.h>     /* bzero */
#include <errno.h>      /* errno */
#include <err.h>	/* errx */
#include <assert.h>

#include "como.h"
#include "comopriv.h"
#include "storage.h"
#include "query.h"	// XXX query();
#include "ipc.h"


/* global state */
extern struct _como map;

struct _child_info_t {
    procname_t who;
    pid_t pid;
};

static struct _child_info_t my_children[10]; 


/*
 * -- start_child 
 * 
 * fork a child with the given function and process name.
 * If 'procname' is NULL then don't fork, as this is the supervisor.
 * The last argument is an optional fd to be passed to the program.
 */
pid_t
start_child(procname_t who, int mem_type, 
	void (*mainloop)(int out_fd, int in_fd), int fd)
{
    pid_t pid;
    u_int i;

    /* find a slot for the child */
    for (i = 0; i < sizeof(my_children); i++)
	if (!isvalidproc(my_children[i].who))
	    break;
    if (i == sizeof(my_children)) 
	errx(EXIT_FAILURE, 
	     "--- cannot create child %s, no more slots\n", 
	     getprocfullname(who));

    my_children[i].who = who;

    /* ok, fork a regular process and return pid to the caller. */
    pid = fork();
    if (pid == 0) {	/* child */
	char *buf;
	int out_fd, idx;

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
	 * remove all modules in the map (it will
	 * receive the proper information from SUPERVISOR)
	 *
	 * XXX this is not that great but no other workaround comes
	 *     to mind. the problem is when an IPC_MODULE_ADD message
	 *     comes we don't want to waste time figuring out if we
	 *     already have that module somewhere or not. And those
	 *     messages may come when we are doing something important,
	 *     while this is done at the very beginning.
	 *
	 */
	for (idx = 0; idx < map.module_max; idx++)
	    if (map.modules[idx].status != MDL_UNUSED) 
		remove_module(&map, &map.modules[idx]);
	assert(map.module_used == 0); 
	assert(map.module_last == -1);

	/* connect to SUPERVISOR */
        out_fd = ipc_connect(map.parent);
        assert(out_fd > 0);

	asprintf(&buf, "%s", getprocfullname(who));
	setproctitle(buf);
	free(buf);

	logmsg(V_LOGWARN, "starting process %-20s pid %d\n", 
	       getprocfullname(who), getpid()); 

	mainloop(fd, out_fd);
	exit(0);
    }
    my_children[i].who = who;
    my_children[i].pid = pid;
    
    return pid;
}


/*
 * -- ipc_echo_handler()
 *
 * processes IPC_ECHO messages by printing their content to screen 
 * and to file if required.  
 * 
 * XXX the logfile should go thru STORAGE to allow for circular 
 *     files and better disk scheduling.
 * 
 */
static void 
su_ipc_echo(__unused procname_t sender, __unused int fd, void * buf, 
	    __unused size_t len) 
{
    logmsg(LOGUI, "%s", buf); 
    if (map.logfile != NULL) 
	fprintf(map.logfile, "%s", (char *) buf);
}


/*
 * -- ipc_sync_handler()
 * 
 * on receipt of an IPC_SYNC, send an IPC_MODULE_ADD for all 
 * active modules in the map. this is used to synchronize the 
 * SUPERVISOR with another process that has just started on 
 * which modules should be running. 
 * 
 */
static void
su_ipc_sync(procname_t sender, __unused int fd, __unused void * b, 
	    __unused size_t l)
{
    int i; 
    
    if (getprocclass(sender) == QUERY || getprocclass(sender) == STORAGE)
	return;

    /* 
     * initialize all modules and send the start signal to 
     * the other processes 
     */
    for (i = 0; i < map.module_max; i++) { 
        char * pack;
        int sz;

	if (map.modules[i].status != MDL_ACTIVE) 
	    continue; 

        /* prepare the module for transmission */
        pack = pack_module(&map.modules[i], &sz);

        /* inform the other processes */
        ipc_send(sender, IPC_MODULE_ADD, pack, sz);

        free(pack);
    }

    /* now we can send the start message */
    ipc_send(sender, IPC_MODULE_START, &map.stats, sizeof(void *));
}


/*  
 * -- su_ipc_record 
 * 
 * prints a record to screen. this is used only when running
 * in inline mode 
 *
 */
static void
su_ipc_record(__unused procname_t sender, __unused int fd, 
	void * buf, __unused size_t l)
{
    assert(map.running == INLINE);  
    fprintf(stdout, "%s", (char *) buf); 
}


/*  
 * -- su_ipc_done 
 * 
 * EXPORT should send this message to report that there are 
 * no more records to be processed. This messages happens only
 * in inine mode. As a result we exit (sending a SIGPIPE to all 
 * children as well).
 *
 */
static void
su_ipc_done(__unused procname_t sender, __unused int fd, 
	__unused void * b, __unused size_t l)
{
    assert(map.running == INLINE); 
    ipc_send(CAPTURE, IPC_EXIT, NULL, 0); 
    ipc_send(EXPORT, IPC_EXIT, NULL, 0); 
    ipc_send(STORAGE, IPC_EXIT, NULL, 0); 
    exit(EXIT_SUCCESS);
}


/* 
 * -- handle_children
 * 
 * Waits for children that have terminate and reports on the 
 * exit status. 
 */
static void
handle_children(void)
{
    u_int j;
    procname_t who = 0;
    pid_t pid;
    int statbuf; 

    pid = wait3(&statbuf, WNOHANG, NULL);
    if (pid <= 0)
	return;
    for (j = 0; j < sizeof(my_children); j++) {
	if (my_children[j].pid == pid) {
	    who = my_children[j].who;
	    break;
	}
    }

    if (j == sizeof(my_children))
	return; 

    if (WIFEXITED(statbuf)) 
	logmsg(LOGWARN, "WARNING!! process %d (%s) terminated (status: %d)\n",
	    pid, getprocfullname(who), WEXITSTATUS(statbuf)); 
    else if (WIFSIGNALED(statbuf)) 
	logmsg(LOGWARN, "WARNING!! process %d (%s) terminated (signal: %d)\n",
	    pid, getprocfullname(who), WTERMSIG(statbuf));
    else 
	logmsg(LOGWARN, "WARNING!! process %d (%s) terminated (unknown!!)\n", 
	    pid, getprocfullname(who)); 
}


/*
 * -- cleanup
 * 
 * cleanup() called at termination time to
 * remove the byproducts of the compilation.
 * The function is registered with atexit(), which does not provide  
 * a way to unregister the function itself. So we have to check which
 * process died (through map.procname) and determine what to do accordingly.
 */
static void
cleanup()
{
    char *cmd;
 
    if (map.whoami != SUPERVISOR) {
        logmsg(V_LOGWARN, "terminating normally\n");
        return;
    }
    logmsg(LOGUI, "\n\n\n--- about to exit... remove work directory %s\n",
        map.workdir);
    asprintf(&cmd, "rm -rf %s\n", map.workdir);
    system(cmd);
    logmsg(LOGUI, "--- done, thank you for using como\n");
}
  

/*
 * -- apply_map_changes
 *
 * compare two map data structures (struct _como) to verify
 * if anything relevant has changed. any change that we can
 * accomodate will be applied immediately.
 *
 * XXX right now we only allow to add or remove modules.
 *     it should be possible to modify more configuration
 *     parameters on-the-fly.
 * 
 * XXX this function doesn't handle multiple virtual nodes. 
 *
 */
static void
apply_map_changes(struct _como * x)
{
    int i, j;

    /*
     * browse thru the list of modules to find if all
     * modules in the running config are also present
     * in the new one. if not, remove them.
     */
    for (i = 0; i <= map.module_last; i++) {
	int found = 0; 

	if (map.modules[i].status == MDL_UNUSED) 
	    continue; 

        for (j = 0; j <= x->module_last; j++) {
            if (match_module(&x->modules[j], &map.modules[i])) { 
		/* don't need to look at this again */
		x->modules[j].status = MDL_UNUSED; 
		found = 1;
                break;
	    } 
        }
    
        if (!found) {
	    int active = (map.modules[i].status == MDL_ACTIVE); 

            remove_module(&map, &map.modules[i]);

	    /* inform the other processes */
	    ipc_send(CAPTURE, IPC_MODULE_DEL, (char *) &i, sizeof(int)); 
	    ipc_send(EXPORT, IPC_MODULE_DEL, (char *) &i, sizeof(int)); 
	    ipc_send(STORAGE, IPC_MODULE_DEL, (char *) &i, sizeof(int)); 

	    if (active) { 
		map.stats->modules_active--; 

		/* free metadesc information. to do this 
		 * we need to freeze CAPTURE for a while 
		 */ 
		ipc_send_blocking(CAPTURE, IPC_FREEZE, NULL, 0);
	        metadesc_list_free(map.modules[i].indesc);
		metadesc_list_free(map.modules[i].outdesc);
		ipc_send(CAPTURE, IPC_ACK, NULL, 0); 
	    } 

	}
    }

    /*
     * now add any modules in the new map that do
     * not exist in the old map
     */
    for (j = 0; j <= x->module_last; j++) {
        module_t * mdl;
	char * pack;
	int sz; 

        if (x->modules[j].status == MDL_UNUSED)
            continue;

	/* add this module to the main map */
        mdl = copy_module(&map, &x->modules[j], x->modules[j].node, -1, NULL);
	if (activate_module(mdl, map.libdir)) {
	    remove_module(&map, mdl);
	    continue;
	} 

	/* initialize this module, before doing so we 
	 * need to freeze CAPTURE to avoid conflicts in 
	 * the shared memory
	 */
	ipc_send_blocking(CAPTURE, IPC_FREEZE, NULL, 0);
        if (init_module(mdl)) { 
	    /* let CAPTURE resume */
	    ipc_send(CAPTURE, IPC_ACK, NULL, 0); 
	    remove_module(&map, mdl);
	    continue;
	} 
		
	/* prepare the module for transmission */
        pack = pack_module(mdl, &sz);

	/* inform the other processes */
   	ipc_send(CAPTURE, IPC_MODULE_ADD, pack, sz); 
   	ipc_send(EXPORT, IPC_MODULE_ADD, pack, sz); 
   	ipc_send(STORAGE, IPC_MODULE_ADD, pack, sz); 

	free(pack);
	map.stats->modules_active++; 
    }
}


/*
 * -- reconfigure
 * 
 * this is called when a SIGHUP is received to cause
 * como process again the config files and command line
 * parameters.
 *
 */
static void
reconfigure()
{
    struct _como tmp_map;

    init_map(&tmp_map);
    configure(&tmp_map, map.ac, map.av);
    apply_map_changes(&tmp_map);
}


/*
 * -- supervisor_mainloop
 * 
 * Basically mux incoming messages and show them to the console.
 * Also take care of processes dying. XXX update this comment
 */
void
supervisor_mainloop(int accept_fd)
{
    fd_set valid_fds;
    node_t * node;
    int * external_fd;	/* for http queries */
    int max_fd;
    int i; 
    
    /* catch some signals */
    signal(SIGINT, exit);               /* catch SIGINT to clean up */
    signal(SIGHUP, reconfigure);        /* catch SIGHUP to update config */

    /* register a handler for exit */
    atexit(cleanup);

    /* init my children array */
    bzero(my_children, sizeof(my_children)); 

    /* register handlers for IPC */
    ipc_clear();
    ipc_register(IPC_ECHO, su_ipc_echo); 
    ipc_register(IPC_SYNC, su_ipc_sync); 
    ipc_register(IPC_RECORD, su_ipc_record); 
    ipc_register(IPC_DONE, su_ipc_done); 

    if (map.running == INLINE) {
        inline_mainloop(accept_fd); 
	return; 
    } 

    max_fd = 0;
    FD_ZERO(&valid_fds);

    /* accept connections from other processes */
    max_fd = add_fd(accept_fd, &valid_fds, max_fd);

    /* 
     * create sockets and accept connections from the outside world. 
     * they are queries that can be destined to any of the virtual nodes. 
     */
    external_fd = safe_calloc(map.node_count, sizeof(int));
    for (node = map.node; node; node = node->next) { 
	char *buf;

	asprintf(&buf, "S:http://localhost:%d/", node->query_port);
	external_fd[node->id] = create_socket(buf, NULL);
	if (external_fd[node->id] < 0)
	    panic("creating the socket %s", buf);
	max_fd = add_fd(external_fd[node->id], &valid_fds, max_fd);
	free(buf);
    }

    /* initialize all modules */ 
    for (i = 0; i < map.module_max; i++) {
	module_t * mdl = &map.modules[i]; 

	if (mdl->status != MDL_LOADING) 
	    continue;

	if (activate_module(mdl, map.libdir)) {
	    logmsg(LOGWARN, "cannot start module %s\n", mdl->name); 
	    remove_module(&map, mdl);
	    continue; 
  	} 

	if (init_module(mdl)) { 
	    logmsg(LOGWARN, "cannot initialize module %s\n", mdl->name); 
	    remove_module(&map, mdl);
	    continue; 
  	} 

	map.stats->modules_active++;
    } 

    /* initialize resource management */
    resource_mgmt_init();

    for (;;) { 
#ifdef RESOURCE_MANAGEMENT
	/* 
	 * to do resource management we need the select timeout to 
	 * be shorter so that supervisor can be more reactive to 
	 * sudden changes in the resource usage. 
	 * 
	 * XXX shouldn't the other processes be more reactive and 
	 *     supervisor just wait for an "heads up" from them? 
	 */
	struct timeval to = {0, 50000};
#else
	struct timeval to = {1, 0};
#endif
        int secs, dd, hh, mm, ss;
	struct timeval now;
	int n_ready;
	int ipcr;
	
	fd_set r = valid_fds;

	/* 
         * user interface. just one line... 
         */
	gettimeofday(&now, NULL);
	secs = 1 + now.tv_sec - map.stats->start.tv_sec; 
 	dd = secs / 86400; 
        hh = (secs % 86400) / 3600; 
        mm = (secs % 3600) / 60;
        ss = secs % 60; 

	if (map.running == NORMAL) 
	    fprintf(stderr, 
		"\r- up %dd%02dh%02dm%02ds; mem %u/%u/%uMB (%d); "
		"pkts %llu drops %d; mdl %d/%d\r", 
		dd, hh, mm, ss,
		map.stats->mem_usage_cur/(1024*1024), 
		map.stats->mem_usage_peak/(1024*1024), 
		map.mem_size, map.stats->table_queue, 
		map.stats->pkts, map.stats->drops,
		map.stats->modules_active, map.module_used); 

	n_ready = select(max_fd, &r, NULL, NULL, &to);
	fprintf(stderr, "%78s\r", ""); /* clean the line */

	for (i = 0; n_ready > 0 && i < max_fd; i++) {
	    int id;
	    
	    if (!FD_ISSET(i, &r))
		continue;

	    if (i == accept_fd) {
		int x;
		x = accept(i, NULL, NULL);
		if (x < 0) {
		    logmsg(LOGWARN, "accept fd[%d] got %d (%s)\n",
			    i, x, strerror(errno));
		} else {
		    max_fd = add_fd(x, &valid_fds, max_fd);
		}
		goto next_one;
	    }

	    for (id = 0; id < map.node_count; id++) {
		struct sockaddr_in addr;
		socklen_t len;
		int cd;
		pid_t pid;
	    
		if (i != external_fd[id]) 
		    continue; 

		len = sizeof(addr);
		cd = accept(external_fd[id], (struct sockaddr *)&addr, &len); 
		if (cd < 0) {
		    /* check if accept was unblocked by a signal */
		    if (errno == EINTR)
			continue;

		    logmsg(LOGWARN, "accepting connection: %s\n",
			strerror(errno));
		}

		logmsg(LOGQUERY,
		       "query from %s on fd %d\n", 
		       inet_ntoa(addr.sin_addr), cd); 

		/* 
		 * fork a process to serve the query. 
	 	 * we don't use start_child here because we need to 
		 * pass down the virtual node information and we don't 
		 * really care to know if the query succeds or fails. 
	   	 */
		pid = fork(); 	
		if (pid < 0) 
		    logmsg(LOGWARN, "fork query-ondemand: %s\n",
				strerror(errno));

		if (pid == 0) {	/* here is the child... */
		    for (i = 3; i < max_fd; i++) {
			if (i != cd)
			    close(i);
		    }
		    query(cd, id); 
		    exit(EXIT_SUCCESS); 
		} else	/* parent */
		    close(cd);
		goto next_one;
	    }

	    /* this is internal. use ipc handler */
	    ipcr = ipc_handle(i);
	    switch (ipcr) {
	    case IPC_ERR:
		/* an error. close the socket */
		logmsg(LOGWARN, "error on IPC handle from %d\n", i);
	    case IPC_EOF:
		close(i);
		max_fd = del_fd(i, &valid_fds, max_fd);
		break;
	    }
  next_one:
	    n_ready--;
	}

	handle_children(); /* handle dead children etc */
	schedule(); /* resource management */
    }
}

