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




typedef struct como_su {
    como_env_t		env;
    event_loop_t	el;
    int			accept_fd;

    array_t *		nodes;		/* node information */
    
    pool_t *		pool;		/* the pool used to allocate this
					   structure */
    alc_t *		alc;		/* the pool's allocator */

    FILE *		logfile;	/* log file */
} como_su_t;



#define SIZEOF_LOGMSG_DOMAIN	8

typedef struct logmsg {
    char	domain[SIZEOF_LOGMSG_DOMAIN];
    log_level_t	level;
    char	message[0];
} logmsg_t;

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
static int 
su_ipc_echo(UNUSED ipc_peer_t * sender, logmsg_t * m, UNUSED size_t len,
	    UNUSED int swap, UNUSED void * user_data)
{
    log_out(m->domain, m->level, m->message);
    return IPC_OK;
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
static int
su_ipc_sync(ipc_peer_t * peer, UNUSED void * b, UNUSED size_t l,
	    UNUSED int swap, como_su_t * como_su)
{
    int i;
    como_node_t *node0;
    array_t * mdls;
    
    node0 = array_at(como_su->nodes, como_node_t, 0);
    mdls = node0->mdls;
    
    if (peer->class == COMO_CA_CLASS) {
	ipc_type t;
	ipc_send(peer, CA_INITIALIZE_SNIFFERS, NULL, 0);
	ipc_receive(peer, &t, NULL, NULL, NULL, NULL);
	assert(t == CA_SNIFFERS_INITIALIZED);
	
	/* TODO: metadesc comparison here */
	
	for (i = 0; i < mdls->len; i++) {
	    mdl_t *mdl;
	    uint8_t *buf, *sbuf;
	    size_t sz;

	    mdl = array_at(mdls, mdl_t, i);
	    sz = mdl_sersize(mdl);
	    buf = sbuf = como_malloc(sz);

	    mdl_serialize(&sbuf, mdl);

	    ipc_send(peer, CA_ADD_MODULE, buf, sz);
	    free(buf);
	}
	
	ipc_send(peer, CA_START, NULL, 0);
    }
    return IPC_OK;
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
static int
su_ipc_done(UNUSED ipc_peer_t * sender, UNUSED void * b, UNUSED size_t l,
	    UNUSED int swap, UNUSED como_su_t * como_su)
{
/* TODO
    ipc_send(CAPTURE, IPC_EXIT, NULL, 0); 
    ipc_send(EXPORT, IPC_EXIT, NULL, 0); 
    ipc_send(STORAGE, IPC_EXIT, NULL, 0); 
*/
    exit(EXIT_SUCCESS);
    return IPC_OK;
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
 
    msg("\n\n\n--- about to exit... remove work directory %s\n",
        map.workdir);
    asprintf(&cmd, "rm -rf %s\n", map.workdir);
    system(cmd);
    free(cmd);
    msg("--- done, thank you for using CoMo\n");
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
#if 0
/* TODO */
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
            remove_module(&map, &map.modules[i]);
            
            if (map.modules[i].running != RUNNING_ON_DEMAND) {
		/* inform the other processes */
		ipc_send(CAPTURE, IPC_MODULE_DEL, (char *) &i, sizeof(int)); 
		ipc_send(EXPORT, IPC_MODULE_DEL, (char *) &i, sizeof(int)); 
		ipc_send(STORAGE, IPC_MODULE_DEL, (char *) &i, sizeof(int)); 
            }

	    if (map.modules[i].status == MDL_ACTIVE && 
		map.modules[i].running != RUNNING_ON_DEMAND) { 
		map.stats->modules_active--; 
	    }
	    
	    if (map.modules[i].indesc || map.modules[i].outdesc) {
		/* free metadesc information. to do this 
		 * we need to freeze CAPTURE for a while 
		 */ 
		/* CHECKME: shouldn't this code be executed in any case? */
		ipc_send(COMO_CA, CA_FREEZE, NULL, 0);
		ipc_receive(COMO_CA, &res, NULL, NULL);
		
	        metadesc_list_free(map.modules[i].indesc);
		metadesc_list_free(map.modules[i].outdesc);
		
		ipc_send(COMO_CA, CA_RESUME, NULL, 0); 
	    } 

	}
    }

    /*
     * now add any modules in the new map that do
     * not exist in the old map
     */
    for (j = 0; j <= x->module_last; j++) {
        module_t * mdl;
	int sz; 

        if (x->modules[j].status == MDL_UNUSED)
            continue;

	/* add this module to the main map */
        mdl = copy_module(&map, &x->modules[j], x->modules[j].node, -1, NULL);
	if (activate_module(mdl, map.libdir)) {
	    remove_module(&map, mdl);
	    continue;
	} 

	/* if this module is not running on demand, initialize it. 
	 * however, before doing so freeze CAPTURE to avoid conflicts 
         * in the shared memory
	 */
	if (mdl->running != RUNNING_ON_DEMAND) {
	    char * pack;

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
	    map.stats->modules_active++; 

	    free(pack);
	}

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
reconfigure(UNUSED int si_code)
{
    struct _como tmp_map;

    init_map(&tmp_map);
    tmp_map.cli_args = map.cli_args;
    configure(&tmp_map, map.ac, map.av);
    apply_map_changes(&tmp_map);
}
#endif

/*
 * -- defchld
 * 
 * handle dead children
 * 
 */
static void
defchld(UNUSED int si_code)
{
    handle_children();
}

static como_node_t *
como_node_lookup_by_fd(array_t * nodes, int fd)
{
    int i;
    
    for (i = 0; i < nodes->len; i++) {
	como_node_t *node;
	node = array_at(nodes, como_node_t, i);
	if (node->query_fd == fd)
	    return node;
    }
    return NULL;
}


static void
como_node_handle_query(como_node_t * node)
{
    struct sockaddr_in addr;
    ipc_peer_full_t *peer;
    socklen_t len;
    int cd;
    
    len = sizeof(addr);
    cd = accept(node->query_fd, (struct sockaddr *) &addr, &len);
    if (cd < 0) {
	/* check if accept was unblocked by a signal */
	warn("Failed on accept(): %s\n", strerror(errno));
	return;
    }
    
    notice("query from %s on fd %d\n", inet_ntoa(addr.sin_addr), cd);
    /* 
     * start a query process. 
     */
    peer = ipc_peer_child(COMO_QU, cd);
    //start_child(peer, query, cd, node);
    close(cd);
}


static void
como_node_listen(como_node_t * node)
{
    char *cp;
    asprintf(&cp, "%s:%hd", "localhost", node->query_port);
    node->query_fd = create_socket(cp, TRUE);
    free(cp);
}

/*
 * -- como_su_run
 * 
 * Basically mux incoming messages and show them to the console.
 * Also take care of processes dying. XXX update this comment
 */
void
como_su_run(como_su_t * como_su)
{
    fd_set nodes_fds;
    int i;
    como_node_t *node0;
    array_t *mdls;
    runmode_t runmode;
    
    /* catch some signals */
    signal(SIGINT, exit);               /* catch SIGINT to clean up */
    signal(SIGTERM, exit);              /* catch SIGTERM to clean up */
    signal(SIGCHLD, defchld);		/* catch SIGCHLD (defunct children) */

#if 0
    /* TODO */
    if (como_su->env.runmode == RUNMODE_NORMAL)
	signal(SIGHUP, reconfigure);    /* catch SIGHUP to update config */
#endif

    /* register a handler for exit */
    atexit(cleanup);

    /* register handlers for IPC */
    ipc_register(SU_CONNECT, (ipc_handler_fn) su_ipc_sync);
    ipc_register(SU_DONE, (ipc_handler_fn) su_ipc_done);
    ipc_register(SU_ECHO, (ipc_handler_fn) su_ipc_echo);
    
#if 0
    /* TODO */
    if (como_su->env.runmode == RUNMODE_INLINE) {
        inline_mainloop(accept_fd); 
	return; 
    } 
#endif

    event_loop_init(&como_su->el);

    /* accept connections from other processes */
    event_loop_add(&como_su->el, como_su->accept_fd);

    FD_ZERO(&nodes_fds);
    /* 
     * create sockets and accept connections from the outside world. 
     * they are queries that can be destined to any of the virtual nodes. 
     */
    for (i = 0; i < como_su->nodes->len; i++) {
	como_node_t *node;
	node = array_at(como_su->nodes, como_node_t, i);
	como_node_listen(node);
	event_loop_add(&como_su->el, node->query_fd);
	FD_SET(node->query_fd, &nodes_fds);
    }

    /* initialize all modules */ 
    node0 = array_at(como_su->nodes, como_node_t, 0);
    mdls = node0->mdls;
    for (i = 0; i < mdls->len; i++) {
	mdl_t *mdl;
	mdl = array_at(mdls, mdl_t, i);

/*
	if (mdl_init(mdl)) {
	    remove_module(&map, mdl);
	    continue; 
  	} 


	if (mdl->running != RUNNING_ON_DEMAND) {
	    if (init_module(mdl)) { 
		logmsg(LOGWARN, "cannot initialize module %s\n", mdl->name); 
		remove_module(&map, mdl);
		continue; 
	    } 

	    map.stats->modules_active++;
	}
*/
    } 

    /* initialize resource management */
    resource_mgmt_init();
    
    runmode = como_env_runmode();

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
	
	fd_set r;
	
	event_loop_set_timeout(&como_su->el, &to);

	/* 
         * user interface. just one line... 
         */
	gettimeofday(&now, NULL);
	secs = 1 + now.tv_sec - map.stats->start.tv_sec; 
 	dd = secs / 86400; 
        hh = (secs % 86400) / 3600; 
        mm = (secs % 3600) / 60;
        ss = secs % 60; 

	if (runmode == RUNMODE_NORMAL) {
	    fprintf(stderr, 
		"\r- up %dd%02dh%02dm%02ds; mem %u/%u/%uMB (%d); "
		"pkts %llu drops %d; mdl %d/%d\r", 
		dd, hh, mm, ss,
		    (unsigned int)map.stats->mem_usage_cur/(1024*1024), 
		    (unsigned int)map.stats->mem_usage_peak/(1024*1024), 
		    (unsigned int)map.mem_size, map.stats->table_queue,
		map.stats->pkts, map.stats->drops,
		map.stats->modules_active, map.module_used);
	}

	n_ready = event_loop_select(&como_su->el, &r);
	if (runmode == RUNMODE_NORMAL) {
	    fprintf(stderr, "%78s\r", ""); /* clean the line */
	}

	for (i = 0; n_ready > 0 && i < como_su->el.max_fd; i++) {
	    
	    if (!FD_ISSET(i, &r))
		continue;

	    if (i == como_su->accept_fd) {
		int x;
		x = accept(i, NULL, NULL);
		if (x < 0) {
		    warn("Failed on accept(): %s\n", strerror(errno));
		} else {
		    event_loop_add(&como_su->el, x);
		}
	    } else if (FD_ISSET(i, &nodes_fds)) {
		como_node_t *node = como_node_lookup_by_fd(como_su->nodes, i);
		como_node_handle_query(node);
	    } else {
		/* this is IPC */
		int ipcr;
		ipcr = ipc_handle(i);
		switch (ipcr) {
		case IPC_ERR:
		    /* an error. close the socket */
		    warn("error on IPC handle from %d\n", i);
		case IPC_CLOSE:
		case IPC_EOF:
		    close(i);
		    event_loop_del(&como_su->el, i);
		    break;
		}
	    }
	    n_ready--;
	}
	schedule(); /* resource management */
    }
}



/*
 * -- main
 *
 * set up the data structures. basically open the config file,
 * parse the options and dynamically link in the modules. it
 * spawns the CAPTURE, EXPORT, QUERY and STORAGE processes and 
 * then sits there (SUPERVISOR) monitoring the other processes.
 *
 */
int
main(int argc, char ** argv)
{
    como_su_t *como_su;
    como_node_t *node0;
    
    /* create a global pool */
    pool_t *pool = pool_create();
    alc_t alc;
    
    pool_alc_init(pool, &alc);
    como_su = alc_new0(&alc, como_su_t);
    como_su->pool = pool;
    como_su->alc = &alc;
    
    como_init(argc, argv);
    
    como_su->nodes = array_new(sizeof(como_node_t));
    
    /* set default values */
    como_env_init(&como_su->env);
    
    /*
     * parse command line and configuration files
     */
    //configure(&map, argc, argv);

    /* write welcome message */ 
    msg("----------------------------------------------------\n");
    msg("  CoMo v%s (built %s %s)\n",
			COMO_VERSION, __DATE__, __TIME__ ); 
    msg("  Copyright (c) 2004-2006, Intel Corporation\n"); 
    msg("  All rights reserved.\n"); 
    msg("----------------------------------------------------\n");
    notice("... workdir %s\n", como_su->env.workdir);


    notice("log level: %s\n", log_level_name(log_get_level())); 

    /*
     * Initialize the shared memory region.
     * All processes will be able to see it.
     */
    //memory_init(map.mem_size);

    /* initialize IPC */
    ipc_init(ipc_peer_at(COMO_SU, como_su->env.workdir), como_su);
    
    /* prepare the SUPERVISOR socket */
    como_su->accept_fd = ipc_listen();
    
    node0 = array_at(como_su->nodes, como_node_t, 0);

    /* start the CAPTURE process */
    if (node0->sniffers_count > 0) {
	ipc_peer_full_t *ca;
	pid_t pid;
	
	ca = ipc_peer_child(COMO_CA, 0);
	pid = start_child(ca, capture, -1, node0);
	if (pid < 0) {
	    warn("Can't start CAPTURE\n");
	}
    }
    
    /* move to the SUPERVISOR process (we don't fork here) */
    //setproctitle("%s", getprocfullname(map.whoami));

    como_su_run(como_su);

    return EXIT_SUCCESS;
}
