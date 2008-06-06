/*
 * Copyright (c) 2004-2007, Intel Corporation
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
#include <sys/stat.h>   /* mkdir */
#include <sys/types.h>  /* mkdir */
#include <sys/mman.h>   /* mmap */


#define LOG_DEBUG_DISABLE
#include "como.h"
#include "comopriv.h"
#include "query.h"	// XXX query();
#include "ipc.h"

#ifdef LOADSHED
#include "lsfunc.h"
#endif

como_su_t *s_como_su;

stats_t *como_stats;
como_config_t *como_config;

int s_saved_argc;
char **s_saved_argv;

ipc_peer_full_t *COMO_SU;
ipc_peer_full_t *COMO_CA;
ipc_peer_full_t *COMO_EX;
ipc_peer_full_t *COMO_ST;
ipc_peer_full_t *COMO_QU;

/*
 * -- launch_inline_query
 *
 * If the system is running in inline mode, Supervisor automatically
 * starts a query to present the data to the user. The output of the
 * query is then redirected to stdout.
 */
static void
launch_inline_query(void)
{
    ipc_peer_full_t *peer;
    pid_t pid;

    como_node_t *n = &array_at(s_como_su->nodes, como_node_t, 0);

    /* the last loaded module is the one that needs to be queried */
    s_como_su->query_module =
        array_at(n->mdls, mdl_t *, n->mdls->len - 1)->name;
    
    peer = ipc_peer_child(COMO_QU, 0);
    pid = start_child(peer, query_main_plain, s_como_su->memmap, stdout, n);

    /* warn("COMPLETED, pid = %d\n", pid); */
}

/*
 * -- send_module
 *
 * Serialize and send a module to a peer using the
 * given msg_id. free's the temporary buffer afterwards.
 */
static void
send_module(ipc_peer_t * peer, int msg_id, mdl_t *mdl)
{
    uint8_t *buf, *sbuf;
    size_t sz;

    sz = mdl_sersize(mdl);
    buf = sbuf = safe_malloc(sz);

    mdl_serialize(&sbuf, mdl);

    ipc_send(peer, msg_id, buf, sz);
    free(buf);
}

/*
 * -- su_ipc_onconnect()
 * 
 * Triggers when any process connects to SU. It is in charge
 * of initializing the system. When CA and EX connect, send
 * them the list of modules. When both CA and EX have connected,
 * signal CA to start receiving pkts.
 */
static int
su_ipc_onconnect(ipc_peer_t * peer, como_su_t * como_su)
{
    static int ca_done = 0, st_done = 0, ex_started = 0;
    como_node_t *node0;
    array_t * mdls;
    ipc_type t;
    int i;

    debug("su_ipc_onconnect()\n");
    
    node0 = &array_at(como_su->nodes, como_node_t, 0);
    mdls = node0->mdls;

    switch (peer->class) {
        case COMO_CA_CLASS: { /* connect from CA */
            int nsent;
            debug("su_ipc_onconnect -- CAPTURE\n");
            como_su->ca = peer;

            ipc_receive(peer, &t, NULL, NULL, NULL, NULL);
            assert(t == CA_SU_SNIFFERS_INITIALIZED);
            
            /* TODO: metadesc comparison here */
            
            nsent = 0;
            for (i = 0; i < mdls->len; i++) { /* send the mdls */
                /* TODO only send compatible modules */
                mdl_t *mdl = array_at(mdls, mdl_t *, i);
                if (mdl->priv->ondemand)
                    continue;
                send_module(peer, SU_CA_ADD_MODULE, mdl);
                nsent++;
            }
            for (i = 0; i < nsent; i++) { /* wait for acks */
                ipc_receive(peer, &t, NULL, NULL, NULL, NULL);
                assert(t == CA_SU_MODULE_ADDED || t == CA_SU_MODULE_FAILED);
            }
            
            ca_done = 1;
            break;
        }
        case COMO_ST_CLASS: { /* connect from ST */
            debug("su_ipc_onconnect -- STORAGE\n");
            como_su->st = peer;
            st_done = 1;
            break;   
        }
        case COMO_EX_CLASS: { /* connect from EX */
            int nsent;
            debug("su_ipc_onconnect -- EXPORT\n");
            assert(ca_done && st_done);
            como_su->ex = peer;

            nsent = 0;
            for (i = 0; i < mdls->len; i++) { /* send the mdls */
                /* TODO only send compatible modules */
                mdl_t *mdl = array_at(mdls, mdl_t *, i);
                if (mdl->priv->ondemand)
                    continue;
                    nsent++;
                send_module(peer, SU_EX_ADD_MODULE, mdl);
            }
            for (i = 0; i < nsent; i++) { /* wait for acks */
                ipc_receive(peer, &t, NULL, NULL, NULL, NULL);
                assert(t == EX_SU_MODULE_ADDED || t == EX_SU_MODULE_FAILED);
            }

            /*
             * At this point all processes are running and configured.
             * Tell CAPTURE to start processing input traffic.
             */
            debug("su_ipc_onconnect -- all procs ready, starting CA\n");
            ipc_send(como_su->ca, SU_CA_START, NULL, 0);

            /*
             * If we are running inline we can start querying the module
             */
            if (como_config->inline_mode)
                launch_inline_query();
        }
    }

    if (ca_done && st_done && !ex_started) { /* CA && ST done, can go for EX */
	ipc_peer_full_t *ex;
	pid_t pid;
        debug("CA and ST initialized, starting export\n");

	ex = ipc_peer_child(COMO_EX, 0);
	pid = start_child(ex, export_main, como_su->memmap, NULL, node0);
	if (pid < 0) {
	    warn("Can't start EXPORT\n");
	}
        ex_started = 1;
    }
    return IPC_OK;
}

/*  
 * -- finalize_como
 * 
 * Request that all processes exit and quit.
 *
 */
static void
finalize_como(como_su_t *como_su)
{
    ipc_send(como_su->ca, SU_ANY_EXIT, NULL, 0);
    ipc_send(como_su->ex, SU_ANY_EXIT, NULL, 0);
    ipc_send(como_su->st, SU_ANY_EXIT, NULL, 0);

    exit(EXIT_SUCCESS);
}

/*
 * -- qu_su_ipc_done
 *
 * Query informs that it is done with its job. If we are
 * in inline mode, this means that CoMo has finished its
 * task.
 */
static int
qu_su_ipc_done(UNUSED ipc_peer_t * sender, UNUSED void * b, UNUSED size_t l,
	    UNUSED int swap, como_su_t * como_su)
{
    if (como_config->inline_mode) {
        debug("exiting at QU request\n");
        finalize_como(como_su);
    }
    return IPC_OK;
}

/*
 * -- cleanup
 * 
 * cleanup() called at termination time to remove temporary files.
 * The function is registered with atexit(), which does not provide
 * a way to unregister the function itself. So we have to check which
 * process died (through map.procname) and determine what to do accordingly.
 */
static void
cleanup()
{
    char *cmd;
    const char *workdir;
    
    if (s_como_su->su_pid != getpid())
	return;

    signal(SIGCHLD, SIG_DFL); /* don't handle children anymore */
    
    workdir = s_como_su->workdir;
 
    msg("--- about to exit... remove work directory %s\n",
        workdir);

    asprintf(&cmd, "rm -rf %s %s\n", workdir,
        como_config->inline_mode ? como_config->db_path : "");
    system(cmd);
    free(cmd);
    /* TODO wait for children processes */
    msg("--- done, thank you for using CoMo\n");
}
  
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

/*
 * -- set_reconfigure_flag
 * 
 * this is called when a SIGHUP is received to cause
 * como process again the config files and command line
 * parameters. The mainloop will perform the actual
 * reconfiguration.
 *
 */
static void
set_reconfigure_flag(UNUSED int si_code)
{
    s_como_su->reconfigure = 1;
}

/*
 * -- como_node_lookup_by_fd
 *
 * Locate the como_node_t from its filedes.
 */
static como_node_t *
como_node_lookup_by_fd(array_t * nodes, int fd)
{
    int i;
    
    for (i = 0; i < nodes->len; i++) {
	como_node_t *node;
	node = &array_at(nodes, como_node_t, i);
	if (node->query_fd == fd)
	    return node;
    }
    return NULL;
}

/*
 * -- como_node_handle_query
 *
 * Forks to Query to process an incoming user connection.
 */
static void
como_node_handle_query(como_node_t * node)
{
    struct sockaddr_in addr;
    ipc_peer_full_t *peer;
    socklen_t len;
    pid_t pid;
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
    pid = start_child(peer, query_main_http, s_como_su->memmap, fdopen(cd, "a"), node);
    s_como_su->qu = (ipc_peer_t *)peer;
    close(cd);
}

/*
 * -- como_node_listen
 *
 * Opens the TCP query port of the node in order for users
 * to connect and send queries.
 */
static int
como_node_listen(como_node_t * node)
{
    char *cp;
    asprintf(&cp, "%s:%hu", "localhost", node->query_port);
    node->query_fd = create_socket(cp, TRUE);
    free(cp);
    return node->query_fd;
}

/*
 * -- como_node_init_mdl
 *
 * Load a module and configure it from its definition
 * in the config file. If everything is ok, add it to
 * the array of working modules.
 */
static mdl_t *
como_node_init_mdl(como_node_t * node, mdl_def_t * def)
{
    static int s_mdl_ids = 0;

    mdl_isupervisor_t *is;
    mdl_t *mdl = safe_malloc(sizeof(mdl_t));

    mdl->id = s_mdl_ids++;
    if (mdl->id > MDL_ID_MAX)
        error("the system currently supports %d mdls\n", MDL_ID_MAX);

    mdl->name = safe_strdup(def->name);
    mdl->mdlname = safe_strdup(def->mdlname);
    mdl->streamsize = def->streamsize;
    mdl->filter = safe_strdup(def->filter);
    mdl->description = safe_strdup(def->descr);
#ifdef LOADSHED
    mdl->shed_method = safe_strdup(def->shed_method);
    mdl->minimum_srate = def->minimum_srate;
#endif

    if (mdl_load(mdl, PRIV_ISUPERVISOR) < 0) {
        //mdl_destroy(mdl);
        return NULL;
    }

    mdl->priv->ondemand = def->ondemand;

    is = mdl_get_isupervisor(mdl);
    mdl->config = is->init(mdl, def->args);
    if (mdl->config == NULL) {
        warn("Initialization of module `%s' failed.\n", mdl->name);
        //mdl_destroy(mdl);
        return NULL;
    }

    array_add(node->mdls, &mdl);
    mdl = array_at(node->mdls, mdl_t *, node->mdls->len - 1);

    return mdl;
}

/*
 * -- como_node_init_mdls
 *
 * Call como_node_init_mdl for each module definition in an
 * array of definitions.
 */
static void
como_node_init_mdls(como_node_t * node, array_t * mdl_defs)
{
    int i;
    for (i = 0; i < mdl_defs->len; i++) {
	mdl_def_t *def = &array_at(mdl_defs, mdl_def_t, i);
        como_node_init_mdl(node, def);
    }
}


/*
 * -- reconfigure
 *
 * Reconfigures CoMo. Called by the mainloop whenever it sees
 * the reconfiguration flag raised. It calls configure() to fill
 * a new como_config_t and compares the running config with the
 * new como_config_t. Implements whatever changes can be implemented.
 *
 * As of now, the only action that reconfigure() can perform is to
 * load additional modules.
 */
static void
reconfigure(como_su_t *como_su)
{
    hash_t *current_modules, *newcfg_modules, *new_modules, *rem_modules;
    como_config_t new_cfg;
    como_node_t *node;
    hash_iter_t it;
    ipc_type t;
    int i;

    node = &array_at(como_su->nodes, como_node_t, 0);

    /* re-run the config routines */
    configure(s_saved_argc, s_saved_argv, &new_cfg);

    /* load module names from current cfg into a hash */
    current_modules = hash_new(NULL, HASHKEYS_STRING, NULL, NULL);
    for (i = 0; i < como_config->mdl_defs->len; i++) {
        mdl_def_t *def = &array_at(como_config->mdl_defs, mdl_def_t, i);
        hash_insert_string(current_modules, def->name, def);
    }

    /* load module names from the new cfg info a hash */
    newcfg_modules = hash_new(NULL, HASHKEYS_STRING, NULL, NULL);
    for (i = 0; i < new_cfg.mdl_defs->len; i++) {
        mdl_def_t *def = &array_at(new_cfg.mdl_defs, mdl_def_t, i);
        hash_insert_string(newcfg_modules, def->name, def);
    }

    /* find new modules */
    new_modules = hash_new(NULL, HASHKEYS_STRING, NULL, NULL);
    hash_iter_init(newcfg_modules, &it);
    while(hash_iter_next(&it)) {
        mdl_def_t *def = hash_iter_get_value(&it);
        mdl_t *mdl;

        if (hash_lookup_string(current_modules, def->name) != NULL)
            continue;

        /* new module */
        mdl = como_node_init_mdl(node, def);
        if (mdl == NULL)
            continue;

        /* add new modules to the new_modules hash table */
        msg("new module: `%s'\n", mdl->name);
        hash_insert_string(new_modules, mdl->name, mdl);
        array_add(como_config->mdl_defs, def);
    }

    /* find modules to be removed */
    rem_modules = hash_new(NULL, HASHKEYS_STRING, NULL, NULL);
    hash_iter_init(current_modules, &it);
    while(hash_iter_next(&it)) {
        mdl_def_t *def = hash_iter_get_value(&it);
        mdl_def_t *first_def;
        int pos;

        if (hash_lookup_string(newcfg_modules, def->name) != NULL) {
            debug("still have `%s'\n", def->name);
            continue;
        }

        /* this module must be removed */
        msg("removing module: `%s'\n", def->name);
        hash_insert_string(rem_modules, def->name, def->name);

        /* calculate the position of this module defn in the array */
        first_def = &array_at(como_config->mdl_defs, mdl_def_t, 0);
        pos = ((char *)def - (char *)first_def) / sizeof(mdl_def_t);
        
        /* remove from the array of configured modules */
        array_remove(como_config->mdl_defs, pos);

        /* remove from the node */
        pos = mdl_lookup_position(node->mdls, def->name);
        array_remove(node->mdls, pos);
    }

    /*
     * XXX this piece of code assumes that CA and EX don't send
     *     messages to SU by themselves, but only as a response
     *     to messages from SU. If this changes then this code
     *     needs to be rewritten. Making this assumption greatly
     *     simplifies the code, since the next message after a
     *     SU_XX_ADD_MODULE is either MODULE_ADDED or MODULE_FAILED.
     */

    /*
     * adding the new modules
     */
    hash_iter_init(new_modules, &it);
    while(hash_iter_next(&it)) { /* send new modules to CA */
        mdl_t *mdl = hash_iter_get_value(&it);
        send_module(como_su->ca, SU_CA_ADD_MODULE, mdl);
    }

    for (i = 0; i < hash_size(new_modules); i++) { /* wait for acks from CA */
        ipc_receive(como_su->ca, &t, NULL, NULL, NULL, NULL);
        if (t != CA_SU_MODULE_ADDED && t != CA_SU_MODULE_FAILED)
            error("communication protocol violation from CA\n");
        if (t == CA_SU_MODULE_FAILED)
            error("capture failed to load a module!\n");
    }

    hash_iter_init(new_modules, &it);
    while(hash_iter_next(&it)) { /* send new modules to EX */
        mdl_t *mdl = hash_iter_get_value(&it);
        send_module(como_su->ex, SU_EX_ADD_MODULE, mdl);
    }

    for (i = 0; i < hash_size(new_modules); i++) { /* wait for acks from EX */
        ipc_receive(como_su->ex, &t, NULL, NULL, NULL, NULL);
        if (t != EX_SU_MODULE_ADDED && t != EX_SU_MODULE_FAILED)
            error("communication protocol violation from EX\n");
        if (t == EX_SU_MODULE_FAILED)
            error("export failed to load a module!\n");
    }

    /*
     * removing the old modules
     */
    hash_iter_init(rem_modules, &it);
    while(hash_iter_next(&it)) { /* tell CA to remove old modules */
        char *name = hash_iter_get_value(&it);
        char *buffer, *ptr;
        size_t sz;

        sz = sersize_string(name);
        buffer = safe_malloc(sz);
        ptr = buffer;

        serialize_string(&ptr, name);
        ipc_send(como_su->ca, SU_CA_DEL_MODULE, buffer, sz);
        free(buffer);
    }

    for (i = 0; i < hash_size(rem_modules); i++) { /* wait for acks from CA */
        ipc_receive(como_su->ca, &t, NULL, NULL, NULL, NULL);
        if (t != CA_SU_MODULE_REMOVED && t != CA_SU_MODULE_FAILED)
            error("communication protocol violation from CA\n");
        if (t == CA_SU_MODULE_FAILED)
            error("capture failed to remove a module!\n");
    }

    hash_iter_init(rem_modules, &it);
    while(hash_iter_next(&it)) { /* tell EX to remove old modules */
        char *name = hash_iter_get_value(&it);
        char *buffer, *ptr;
        size_t sz;

        sz = sersize_string(name);
        buffer = safe_malloc(sz);
        ptr = buffer;

        serialize_string(&ptr, name);
        ipc_send(como_su->ex, SU_EX_DEL_MODULE, buffer, sz);
        free(buffer);
    }
    for (i = 0; i < hash_size(rem_modules); i++) { /* wait for acks from EX */
        ipc_receive(como_su->ex, &t, NULL, NULL, NULL, NULL);
        if (t != EX_SU_MODULE_REMOVED && t != EX_SU_MODULE_FAILED)
            error("communication protocol violation from CA\n");
        if (t == EX_SU_MODULE_FAILED)
            error("export failed to remove a module!\n");
    }

    /* free unnecessary data */
    hash_destroy(current_modules);
    hash_destroy(newcfg_modules);
    hash_destroy(new_modules);
    hash_destroy(rem_modules);
    destroy_config(&new_cfg);
}



/*
 * -- como_su_run
 * 
 * Supervisor's mainloop. Basically initialize the IPC, load the
 * modules, send them to other processes, receive incoming queries,
 * and reconfigure the system if necessary.
 *
 */
void
como_su_run(como_su_t * como_su)
{
    fd_set nodes_fds;
    int i;
    como_node_t *real_node;
    memmap_stats_t *mem_stats;

    /* catch some signals */
    signal(SIGINT, exit);               /* catch SIGINT to clean up */
    signal(SIGTERM, exit);              /* catch SIGTERM to clean up */
    signal(SIGCHLD, defchld);		/* catch SIGCHLD (defunct children) */
    signal(SIGHUP, set_reconfigure_flag); /* catch SIGHUP to update cfg */

    /* register a handler for exit */
    atexit(cleanup);

    /* register handlers for IPC */
    ipc_register(QU_SU_DONE, (ipc_handler_fn) qu_su_ipc_done);

    como_su->el = event_loop_new();

    /* accept connections from other processes */
    event_loop_add(como_su->el, como_su->accept_fd);

    FD_ZERO(&nodes_fds);

    /* 
     * create sockets and accept connections from the outside world. 
     * they are queries that can be destined to any of the virtual nodes. 
     */
    for (i = 0; i < como_su->nodes->len; i++) {
	como_node_t *node;
	node = &array_at(como_su->nodes, como_node_t, i);

	if (!como_config->inline_mode && como_node_listen(node) != -1) {
	    event_loop_add(como_su->el, node->query_fd);
	    FD_SET(node->query_fd, &nodes_fds);
	}
    }

    /* initialize all modules */ 
    real_node = &array_at(como_su->nodes, como_node_t, 0);

    mem_stats = memmap_stats_location(como_su->memmap);

    /* initialize resource management */
    resource_mgmt_init();
    
    for (;;) {
	struct timeval to = {1, 0};
        int secs, dd, hh, mm, ss;
	struct timeval now;
	int n_ready, max_fd;
	
	fd_set r;
	
	event_loop_set_timeout(como_su->el, &to);

	/* 
         * user interface. just one line... 
         */
	gettimeofday(&now, NULL);
	secs = 1 + now.tv_sec - como_stats->start.tv_sec;
 	dd = secs / 86400; 
        hh = (secs % 86400) / 3600; 
        mm = (secs % 3600) / 60;
        ss = secs % 60; 

	if (! como_config->silent_mode) {
	    fprintf(stderr, 
		"\r- up %dd%02dh%02dm%02ds; mem %u/%u/%uMB (%d); "
		"pkts %llu drops %d; mdl %d/%d\r", 
		dd, hh, mm, ss,
		    (unsigned int)mem_stats->usage/(1024*1024), 
		    (unsigned int)mem_stats->peak/(1024*1024), 
		    como_su->shmem_size / (1024 * 1024),
		    como_stats->table_queue,
		    como_stats->pkts,
		    como_stats->drops,
		    como_stats->modules_active,
		    real_node->mdls->len);
	}

	n_ready = event_loop_select(como_su->el, &r, &max_fd);
	if (! como_config->inline_mode)
	    fprintf(stderr, "%78s\r", ""); /* clean the line */

	for (i = 0; n_ready > 0 && i < max_fd; i++) {
	    
	    if (!FD_ISSET(i, &r))
		continue;

	    if (i == como_su->accept_fd) {
		int x;
		x = accept(i, NULL, NULL);
		if (x < 0) {
		    warn("accept() failed: %s\n", strerror(errno));
		} else {
		    event_loop_add(como_su->el, x);
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
		    event_loop_del(como_su->el, i);
		    break;
		}
	    }
	    n_ready--;
	}
	schedule(); /* resource management */

        if (como_su->reconfigure) { /* reconfiguration flag is raised */
            como_su->reconfigure = 0;
            reconfigure(como_su);
        }
    }
}

void
como_node_init_sniffers(como_node_t * node, array_t * sniffer_defs,
			alc_t * alc)
{
    sniffer_list_t *sniffers;
    
    int live_sniffers = 0, file_sniffers = 0;
    int i;
    int sniffer_id = 0;
    
    sniffers = &node->sniffers;

    for (i = 0; i < sniffer_defs->len; i++) {
	sniffer_cb_t *cb;
	sniffer_t *s;
	sniffer_def_t *def;
	
	def = &array_at(sniffer_defs, sniffer_def_t, i);
	
	cb = sniffer_cb_lookup(def->name);
	if (cb == NULL)
	    error("Can't find sniffer `%s'. Either the sniffer does not exist, "
	            "it has not been compiled in, or your system does not "
		    "support it.\n", def->name);

	/* initialize the sniffer */
	s = cb->init(def->device, def->args, alc);
	if (s == NULL) {
	    warn("Initialization of sniffer `%s` on device `%s` failed.\n",
		 def->name, def->device);
	    continue;
	}
	
	s->cb = cb;
        s->device = safe_strdup(def->device);

	/* check that the sniffer is consistent with the sniffers already
	 * configured */
	if (((s->flags & SNIFF_FILE) && live_sniffers > 0) ||
	    (!(s->flags & SNIFF_FILE) && file_sniffers > 0)) {
	    warn("Can't activate sniffer `%s`: "
		 "file and live sniffers cannot be used "
		 "at the same time\n", def->name);
	    cb->finish(s, alc);
	    continue;
	}

	if (s->flags & SNIFF_FILE) {
	    file_sniffers++;
	    node->live_thresh = ~0;
	} else {
	    live_sniffers++;
	}
	
	notice("Initialized sniffer `%s` on device `%s`.\n",
	       def->name, def->device);
    
	sniffer_list_insert_head(sniffers, s);
	sniffer_id++;
	node->sniffers_count++;
    }

}

/*
 * -- copy_argv
 *
 * Copies given argc & argv into out_argc and out_argv.
 */
static void
copy_args(int argc, char **argv, int *out_argc, char ***out_argv)
{
    char **argv2;
    int i;

    argv2 = safe_calloc(argc + 1, sizeof(char *));
    for (i = 0; i <= argc; i++) /* <= is correct, must copy final NULL */
        argv2[i] = safe_strdup(argv[i]);

    *out_argc = argc;
    *out_argv = argv2;
}

/*
 * -- como_init_nodes
 *
 * Build the array of nodes according to the user configuration.
 *
 */
static void
como_init_nodes(UNUSED como_su_t *como_su, como_config_t *cfg)
{
    como_node_t node;
    char *str;
    int i;

    como_su->nodes = array_new(sizeof(como_node_t));

    /* node #0 is the main node */
    memset(&node, 0, sizeof(node));
    node.kind = COMO_NODE_REAL;
    node.id = 0;

    node.name = safe_strdup("CoMo Node");
    node.location = safe_strdup(cfg->location);
    node.type = safe_strdup(cfg->type);
    node.query_port = cfg->query_port;
    node.mdls = array_new(sizeof(mdl_t *));

    if (node.location == NULL)
        node.location = safe_strdup("Unknown");
    if (node.type == NULL)
        node.type = safe_strdup("Unknown");

    str = safe_asprintf("%s/%s", como_config->db_path, node.name);
    if (mkdir(str, 0700) == -1 && errno != EEXIST)
        error("cannot create db dir `%s'\n", str);
    free(str);

    array_add(como_su->nodes, &node);

    /* virtual nodes follow */
    for (i = 0; i < cfg->vnode_defs->len; i++) {
        virtual_node_def_t *def = &array_at(cfg->vnode_defs,
                virtual_node_def_t, 0);

        bzero(&node, sizeof(node));

        node.kind = COMO_NODE_VIRTUAL;
        node.real_node_id = 0;
        node.id = i + 1;

        node.name = safe_strdup(def->name);
        node.location = safe_strdup(def->location);
        node.type = safe_strdup(def->type);
        node.query_port = def->query_port;
        node.source = safe_strdup(def->source);
        node.filter = safe_strdup(def->filter);

        if (node.location == NULL)
            node.location = safe_strdup("Unknown");
        if (node.type == NULL)
            node.type = safe_strdup("Unknown");

        array_add(como_su->nodes, &node);
    }
}

#ifndef MAP_NOSYNC
#define MAP_NOSYNC 0
#endif
/* Not all systems seem to have MAP_FAILED defined, but it should always
 * just be (void *)-1. */
#ifndef MAP_FAILED
#define MAP_FAILED ((void *)-1)
#endif

/*
 * -- shmem_create
 *
 * Creates a shared memory region
 *
 */
void *
shmem_create(size_t size)
{
    void *mem;

    mem = mmap(NULL, size, PROT_READ|PROT_WRITE,
                MAP_ANON|MAP_NOSYNC|MAP_SHARED, -1, 0);

    if (mem == (void *)MAP_FAILED)
        error("shmem_create(): %s\n", strerror(errno));
    else
        notice("allocated %lu of mapped memory\n", size);

    return mem;
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
    static como_config_t cfg;
    como_su_t *como_su;
    como_node_t *main_node;
    ipc_peer_full_t *ca, *st;
    pid_t pid;
    int i;
    
    log_set_program("SU");
    if (!isatty(fileno(stderr)))
        log_set_use_color(FALSE);

#if defined(linux) || defined(__APPLE__)
    /* linux/Mac OS X does not support setproctitle. we have our own. */
    setproctitle_init(argc, argv);
#endif

    COMO_SU = ipc_peer_new(COMO_SU_CLASS, "su", "SUPERVISOR");
    COMO_CA = ipc_peer_new(COMO_CA_CLASS, "ca", "CAPTURE");
    COMO_EX = ipc_peer_new(COMO_EX_CLASS, "ex", "EXPORT");
    COMO_ST = ipc_peer_new(COMO_ST_CLASS, "st", "STORAGE");
    COMO_QU = ipc_peer_new(COMO_QU_CLASS, "qu", "QUERY");

    como_su = safe_malloc(sizeof(como_su_t));
    como_su->su_pid = getpid();
    como_su->workdir = mkdtemp(strdup("/tmp/comoXXXXXX"));
    s_como_su = como_su;
    
    /*
     * parse command line and configuration files
     */
    copy_args(argc, argv, &s_saved_argc, &s_saved_argv);
    como_config = configure(s_saved_argc, s_saved_argv, &cfg);

    if (como_config->silent_mode)
        log_set_level(LOG_LEVEL_WARNING); /* disable most UI messages */

    if (como_config->inline_mode) { /* use temporary storage */
        char *template = safe_asprintf("%s/XXXXXX", como_su->workdir);
        como_config->db_path = como_config->db_path = mkdtemp(template);
    }

    /* initialize nodes */
    como_init_nodes(como_su, como_config);
    main_node = &array_at(como_su->nodes, como_node_t, 0);
    assert(main_node->kind == COMO_NODE_REAL);

    /* create database dir */
    if (mkdir(como_config->db_path, 0700) == -1 && errno != EEXIST)
        error("cannot create db dir `%s'\n", como_config->db_path);

    /* write welcome message */ 
    msg("----------------------------------------------------\n");
    msg("  CoMo v%s (built %s %s)\n",
			COMO_VERSION, __DATE__, __TIME__ ); 
    msg("  Copyright (c) 2004-2006, Intel Corporation\n"); 
    msg("  All rights reserved.\n"); 
    msg("----------------------------------------------------\n");

    notice("... workdir %s\n", como_su->workdir);
    notice("log level: %s\n", log_level_name(log_get_level())); 

    /*
     * Initialize the shared memory region.
     * CAPTURE and QUERY processes will be able to see it.
     */
    como_su->shmem_size = como_config->shmem_size;
    como_su->shmem = shmem_create(como_config->shmem_size);
    como_su->memmap = memmap_create(como_su->shmem, como_su->shmem_size, 2048);
    memmap_alc_init(como_su->memmap, &como_su->shalc);
    
    /* allocate statistics into shared memory */
    como_stats = alc_new0(&como_su->shalc, stats_t);
    gettimeofday(&como_stats->start, NULL);
    como_stats->first_ts = ~0;
    
    /* initialize IPC */
    ipc_init(ipc_peer_at(COMO_SU, como_su->workdir),
             (ipc_on_connect_fn) su_ipc_onconnect, como_su);
    
    /* prepare the SUPERVISOR socket */
    como_su->accept_fd = ipc_listen();
    
    /* init the sniffers and modules of nodes */
    for (i = 0; i < como_su->nodes->len; i++) {
        como_node_t *n = &array_at(como_su->nodes, como_node_t, i);
        if (n->kind != COMO_NODE_REAL)
            continue;
        como_node_init_sniffers(n, como_config->sniffer_defs, &como_su->shalc);
        como_node_init_mdls(n, como_config->mdl_defs);
    }

    if (como_config->inline_mode && main_node->mdls->len == 0) {
        /* inline mode and could not load any module. nothing to do. */
        debug("inline mode: no modules could be loaded, exiting.\n");
        return EXIT_FAILURE;
    }

#ifdef LOADSHED
    ls_init();
#endif

    /* spawn STORAGE */
    st = ipc_peer_child(COMO_ST, 0);
    pid = start_child(st, storage_main, como_su->memmap, NULL, main_node);

    /* read ASN file */
    asn_readfile(como_config->asn_file);

    if (main_node->sniffers_count > 0) {
        /* start the CAPTURE process */
	ca = ipc_peer_child(COMO_CA, 0);
	pid = start_child(ca, capture_main, como_su->memmap, NULL, main_node);
	if (pid < 0)
	    error("Can't start CAPTURE\n");
    }

    setproctitle("SUPERVISOR");

    /* move to the SUPERVISOR process (we don't fork here) */
    como_su_run(como_su);

    return EXIT_SUCCESS;
}

