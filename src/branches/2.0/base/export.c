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
#include <unistd.h>	
#include <string.h>	
#include <errno.h>	
#ifndef	__CYGWIN32__
#include <libgen.h>		/* basename */
#endif
#include <sys/types.h>
#include <err.h>
#include <assert.h>
#include <signal.h>

/* #define DISABLE_EXPORT */
#define LOG_DEBUG_DISABLE
#define ENABLE_TIMERS
#include "como.h"
#include "comopriv.h"
#include "comotypes.h"
#include "storage.h"
#include "ipc.h"
#include "query.h"

#include "export-logging.c"
#include "tupleset_queue.h"

typedef struct tupleset tupleset_t;

enum {
    TUPLES_FROM_SHMEM,
    TUPLES_FROM_SOCKET,
};

struct tupleset {
    tupleset_queue_entry_t list;

    char mdl_name[MDLNAME_MAX];   
    int mdl_id;
    tuples_t tuples;
    size_t ntuples;
    size_t tuple_mem;
    size_t queue_size_at_capture;
    ipc_peer_t *peer;
    int mechanism;

    msg_process_shm_tuples_t shmem_msg;

    timestamp_t ivl_start;
};

typedef struct _como_ex como_ex_t;
struct _como_ex {
    event_loop_t * el;
    char * st_dir;
    int use_shmem;
    hash_t *mdls; /* mdl name to mdl */
    ipc_peer_t *supervisor;

    int received_tuples;
    int queue_len;
    tupleset_queue_t queue;
};

enum {
    EX_MDL_STATE_RUNNING,
    EX_MDL_STATE_FLUSHED,
} EX_MDL_STATES;

/* config 'inherited' from supervisor */
extern como_config_t *como_config;

/* stats 'inherited' from SU */
extern stats_t *como_stats;

/* 
 * -- handle_su_ex_add_module
 * 
 * handle IPC_MODULE_ADD messages by unpacking the module, 
 * activating it and initializing the data structures it 
 * needs to run in EXPORT. 
 * 
 */
static int
handle_su_ex_add_module(ipc_peer_t * peer, uint8_t * sbuf, UNUSED size_t sz,
			UNUSED int swap, UNUSED como_ex_t * como_ex)
{
    mdl_iexport_t *ie;
    msg_attach_module_t msg;
    pool_t *pool;
    mdl_t *mdl;
    char *str;
    ipc_type t;
    alc_t alc;

    pool = pool_create();
    pool_alc_init(pool, &alc);

    mdl_deserialize(&sbuf, &mdl, &alc, PRIV_IEXPORT);
    if (mdl == NULL) { /* failure */
	warn("failed to receive + deserialize + load a module\n");
	ipc_send(peer, EX_SU_MODULE_ADDED, NULL, 0);
	return IPC_OK;
    }
    debug("handle_su_ex_add_module -- recv'd & loaded module `%s'\n",mdl->name);

    ie = mdl_get_iexport(mdl);
    ie->running_state = EX_MDL_STATE_RUNNING;
    ie->migrable = FALSE;
    ie->used_mem = 0;
    ie->mem = pool;
    mdl->priv->alc = alc;

    /*
     * open output file
     */
    str = safe_asprintf("%s/%s", como_ex->st_dir, mdl->name);
    ie->cs_writer = csopen(str, CS_WRITER, (off_t) mdl->streamsize,
			 (ipc_peer_t *) COMO_ST);
    if (ie->cs_writer < 0) {
        warn("cannot start storage for module `%s'\n", mdl->name);
        free(str);
        ipc_send(peer, EX_SU_MODULE_ADDED, NULL, 0);
        return IPC_OK;
    }
    ie->woff = csgetofs(ie->cs_writer);
    debug("handle_su_ex_add_module -- output file `%s' open\n", str);
    free(str);

    if (ie->init) {
        debug("handle_su_ex_add_module -- init export state: call ex_init()\n");
        ie->state = ie->init(mdl);
    }
    else
        ie->state = NULL;

    debug("handle_su_ex_add_module -- attaching to capture\n");
    strcpy(msg.mdl_name, mdl->name);
    msg.use_shmem = como_ex->use_shmem;
    ipc_send((ipc_peer_t *) COMO_CA, EX_CA_ATTACH_MODULE, &msg, sizeof(msg));
    ipc_receive((ipc_peer_t *) COMO_CA, &t, NULL, NULL, NULL, NULL);
    assert(t == CA_EX_MODULE_ATTACHED);

    ipc_send(peer, EX_SU_MODULE_ADDED, NULL, 0);

    hash_insert_string(como_ex->mdls, mdl->name, mdl); /* add to mdl index */
    debug("handle_su_ex_add_module -- module `%s' fully loaded\n", mdl->name);

    return IPC_OK;
}

#if 0
static int
handle_ca_ex_process_ser_tuples(UNUSED ipc_peer_t * peer,
				msg_process_ser_tuples_t * msg,
				UNUSED size_t sz, UNUSED int swap,
				UNUSED como_ex_t * como_ex)
{
    uint8_t *sbuf = msg->data;
    alc_t *alc = como_alc();
    mdl_iexport_t *ie;
    void **tuples;
    mdl_t *mdl;
    size_t i;

    debug("recv'd %d serialized tuples\n", msg->ntuples);

    /*
     * locate the module
     */
    mdl = hash_lookup_string(como_ex->mdls, msg->mdl_name);
    if (mdl == NULL)
        error("capture sent tuples from an unknown module\n");

    ex_log_start_measuring();

    debug("handle_ca_ex_process_ser_tuples - tuples for mdl `%s'\n", mdl->name);

    ie = mdl_get_iexport(mdl);
    tuples = como_calloc(msg->ntuples, sizeof(void *));

    /*
     * create an array for the tuples
     */
    debug("handle_ca_ex_process_ser_tuples -- deserializing tuples\n");
    for (i = 0; i < msg->ntuples; i++)
        mdl->priv->mdl_tuple.deserialize(&sbuf, &tuples[i], alc);
    debug("handle_ca_ex_process_ser_tuples -- deserialized the tuples\n");

    /*
     * let the module process 'em
     */
    if (ie->export)
        ie->export(mdl, tuples, msg->ntuples, msg->ivl_start, ie->state);
    else
        error("TODO: store the tuples directly\n");

    /*
     * free allocated mem.
     */
    free(tuples);

    /*
     * we are done
     */
    ex_log_stop_measuring();
    ex_log_module_info(mdl, msg->ntuples, msg->queue_size, msg->tuple_mem);

    debug("handle_ca_ex_process_ser_tuples -- tuples processed\n");

    return IPC_OK;
}
#endif

static int
handle_ca_ex_process_shm_tuples(UNUSED ipc_peer_t * peer,
				msg_process_shm_tuples_t * msg,
				UNUSED size_t sz, UNUSED int swap,
				UNUSED como_ex_t * como_ex)
{
    tupleset_t *tset;

    debug("handle_ca_ex_process_shm_tuples -- recv'd %d tuples in shared mem\n",
            msg->ntuples);
    
    tset = safe_malloc(sizeof(tupleset_t));

    tset->tuples = msg->tuples;
    tset->ntuples = msg->ntuples;
    tset->tuple_mem = msg->tuple_mem;
    tset->queue_size_at_capture = msg->queue_size;
    tset->ivl_start = msg->ivl_start;
    tset->peer = peer;
    tset->mechanism = TUPLES_FROM_SHMEM;

    strcpy(tset->mdl_name, msg->mdl_name);
    bcopy(msg, &tset->shmem_msg, sizeof(msg_process_shm_tuples_t));

    tupleset_queue_insert_tail(&como_ex->queue, tset);
    como_ex->received_tuples++;
    como_ex->queue_len++;

    return IPC_OK;
}


static void
process_tuples(como_ex_t *como_ex)
{
    mdl_iexport_t *ie;
    mdl_t *mdl;
    tupleset_t *tset = tupleset_queue_first(&como_ex->queue);

    if (tset == NULL)
        return;

    /*
     * locate the module
     */
    mdl = hash_lookup_string(como_ex->mdls, tset->mdl_name);
    if (mdl == NULL)
        error("capture sent tuples from an unknown module\n");

    debug("processing queued tuples for mdl `%s'\n", mdl->name);

    ex_log_start_measuring();

    ie = mdl_get_iexport(mdl);

    /*
     * let the module process 'em
     */
    #ifndef DISABLE_EXPORT
    if (ie->export) {
        struct tuple *t;
        void **tuples;
	size_t i;

	tuples = safe_calloc(tset->ntuples, sizeof(void *));

	debug("handle_ca_ex_process_shm_tuples -- building tuple array\n");
	i = 0;
	tuples_foreach(t, &tset->tuples) {
	    tuples[i++] = t->data;
	}

	assert(i == tset->ntuples);

        ie->export(mdl, tuples, tset->ntuples, tset->ivl_start, ie->state);

	/*
	 * free allocated mem.
	 */
	free(tuples);
    } else {
        struct tuple *t;
        debug("handle_ca_ex_process_shm_tuples -- store the tuples directly\n");
        tuples_foreach(t, &tset->tuples) {
	    mdl_store_rec(mdl, t->data);
        }
    }

    ex_log_stop_measuring();
    ex_log_module_info(mdl, tset->ntuples, tset->queue_size_at_capture,
            tset->tuple_mem);
    #endif

    debug("handle_ca_ex_process_shm_tuples -- done, sending reply\n");
    if (tset->mechanism == TUPLES_FROM_SHMEM) {
        msg_process_shm_tuples_t *msg = &tset->shmem_msg;
        ipc_send(tset->peer, EX_CA_TUPLES_PROCESSED, msg, sizeof(*msg));
    }

    tupleset_queue_remove(&como_ex->queue, tset);
    como_ex->queue_len--;
    debug("tupleset queue size is now %d\n", como_ex->queue_len);
}

/*
 * -- handle_ca_ex_done
 *
 * handle CA_EX_DONE messages sent by CAPTURE (sibling). 
 * if we are processing this it means we are done.
 */
static int
handle_ca_ex_done(UNUSED ipc_peer_t * peer,
                    UNUSED void * msg,
                    UNUSED size_t sz, UNUSED int swap,
                    UNUSED como_ex_t * como_ex)
{
    mdl_iexport_t *ie;
    mdl_t *mdl;
    hash_iter_t it;

    debug("capture is done, flushing\n");

    hash_iter_init(como_ex->mdls, &it);
    while(hash_iter_next(&it)) {
        mdl = hash_iter_get_value(&it);
        ie = mdl_get_iexport(mdl);

        if (ie->running_state == EX_MDL_STATE_FLUSHED)
            continue; /* already flushed */

        debug("flushing tuples for mdl `%s'\n", mdl->name);

        if (ie->export != NULL)
            ie->export(mdl, NULL, 0, ~0, ie->state);

        debug("closing output file\n");
        csclose(ie->cs_writer, ie->woff);

        ie->running_state = EX_MDL_STATE_FLUSHED;
    }
    
    /*
     * we are done
     */
    debug("handle_ca_ex_done -- modules flushed\n");

    /* ipc_send(como_ex->supervisor, EX_SU_DONE, msg, sz); */

    return IPC_OK;
}

static int
handle_su_any_exit(UNUSED ipc_peer_t * peer,
                    UNUSED void * msg,
                    UNUSED size_t sz, UNUSED int swap,
                    UNUSED como_ex_t * como_ex)
{
    debug("exiting at supervisor's request\n");
    exit(EXIT_SUCCESS);
}


/* 
 * -- handle_su_ex_del_module
 * 
 * removes a module from the map. it also frees all data 
 * structures related to that module and close the output 
 * file. 
 * 
 */ 
static int
handle_su_ex_del_module(UNUSED ipc_peer_t * peer, char * sbuf, UNUSED size_t sz,
                        UNUSED int swap, como_ex_t * como_ex)
{
    tupleset_t *tset;
    mdl_iexport_t *ie;
    char *name;
    mdl_t *mdl;

    deserialize_string(&sbuf, &name, como_alc());

    mdl = hash_lookup_string(como_ex->mdls, name);
    if (mdl == NULL) {
        warn("removal of unknown module `%s' requested\n", name);
        ipc_send(peer, EX_SU_MODULE_FAILED, NULL, 0);
        free(name);
        return IPC_OK;
    }

    ie = mdl_get_iexport(mdl);

    /*
     * remove pending tuples
     */
    tset = tupleset_queue_first(&como_ex->queue);
    while (tset != NULL) {
    	tupleset_t *next = tupleset_queue_next(tset);

	if (! strcmp(tset->mdl_name, name)) {
            /*
             * tell CA it can free the memory used by these tuples
             */
            if (tset->mechanism == TUPLES_FROM_SHMEM) {
                msg_process_shm_tuples_t *msg = &tset->shmem_msg;
                ipc_send(tset->peer, EX_CA_TUPLES_PROCESSED, msg, sizeof(*msg));
            }
            else
                error("unimplemented\n");

            /*
             * remove from the queue and free the tupleset
             */
            tupleset_queue_remove(&como_ex->queue, tset);
            free(tset);
        }

	tset = next;
    }

    /* free state of the module */
    pool_clear(ie->mem);
    pool_destroy(ie->mem);

    /*
     * close output file
     */
    csclose(ie->cs_writer, ie->woff);

    mdl_destroy(mdl, PRIV_IEXPORT);
    ipc_send(peer, EX_SU_MODULE_REMOVED, NULL, 0);

    hash_insert_string(como_ex->mdls, mdl->name, mdl); /* add to mdl index */
    debug("handle_su_ex_add_module -- module `%s' fully loaded\n", mdl->name);

    msg("export removes module `%s'\n", name);
    free(name);

    return IPC_OK;
}


/*
 * -- export_main
 *
 * This is the EXPORT process main loop. It sits there
 * waiting for flow tables flushed by CAPTURE. It also 
 * communicates with STORAGE to save module data to disk.  
 *
 * On the receipt of a table, EXPORT will go through all the entries,
 * and process them (either accumulate info in the EXPORT flow tables
 * (etable_t), or save to the bytestream and drop them
 * The EXPORT flow tables are processed periodically according to what
 * the action() callback tells us to do (save, discard, etc.).
 */
void
export_main(ipc_peer_t * parent, memmap_t * shmemmap, UNUSED FILE * f,
            como_node_t * node)
{
    int supervisor_fd, capture_fd, storage_fd;
    como_ex_t como_ex;
    
    log_set_program("EX");

    /* initialize como_ex */
    bzero(&como_ex, sizeof(como_ex));
    como_ex.mdls = hash_new(como_alc(), HASHKEYS_STRING, NULL, NULL);
    tupleset_queue_init(&como_ex.queue);

    como_ex.st_dir = safe_asprintf("%s/%s", como_config->db_path, node->name);

#ifdef MONO_SUPPORT
    /* initialize mono */
    proxy_mono_init(como_config->mono_path);
#endif
    
    /* register handlers for signals */ 
    signal(SIGPIPE, exit); 
    signal(SIGINT, exit);
    signal(SIGTERM, exit);
    signal(SIGHUP, SIG_IGN); /* ignore SIGHUP */

    /* register handlers for IPC messages */ 
    /* todo deregister IPC handlers */
    como_ex.supervisor = parent;

    ipc_set_user_data(&como_ex);
    ipc_register(SU_EX_ADD_MODULE, (ipc_handler_fn) handle_su_ex_add_module);
    ipc_register(SU_EX_DEL_MODULE, (ipc_handler_fn) handle_su_ex_del_module);
    ipc_register(SU_ANY_EXIT, (ipc_handler_fn) handle_su_any_exit);
    ipc_register(CA_EX_DONE, (ipc_handler_fn) handle_ca_ex_done);
    #if 0
    ipc_register(CA_EX_PROCESS_SER_TUPLES,
                    (ipc_handler_fn) handle_ca_ex_process_ser_tuples);
    #endif
    ipc_register(CA_EX_PROCESS_SHM_TUPLES,
                    (ipc_handler_fn) handle_ca_ex_process_shm_tuples);
    /* ipc_register(IPC_EXIT, ex_ipc_exit);*/

    /* listen to the parent */
    como_ex.el = event_loop_new();
    
    supervisor_fd = ipc_peer_get_fd(parent);
    event_loop_add(como_ex.el, supervisor_fd);

    /* 
     * wait for the debugger to attach
     */
    DEBUGGER_WAIT_ATTACH("ex");

    storage_fd = ipc_connect(COMO_ST); 
    debug("storage_fd = %d\n", storage_fd);
    event_loop_add(como_ex.el, storage_fd);

    capture_fd = ipc_connect(COMO_CA);

    /* save whether we're using shmem */
    como_ex.use_shmem = (shmemmap != NULL);
    event_loop_add(como_ex.el, capture_fd);

    /* allocate the timers */
    ex_init_timers();

    /*
     * The real main loop. First process the flow_table's we 
     * receive from the CAPTURE process, then look at the export 
     * tables to see if any action is required.
     */
    for (;;) {
	int n_ready, i, ipcr, max_fd;
        struct timeval tv_zero;
	fd_set r;

        tv_zero.tv_sec = 0;
        tv_zero.tv_usec = 0;

        /*
         * tells if we have received any tuples in
         * the current iteration of the mainloop.
         */
        como_ex.received_tuples = 0;

	profiler_start_tsctimer(como_stats->ex_full_timer); 

        n_ready = event_loop_select(como_ex.el, &r, &max_fd);
	if (n_ready < 0) {
	    if (errno == EINTR) {
		continue;
	    }
	    error("error in the select (%s)\n", strerror(errno));
	}

	profiler_start_tsctimer(como_stats->ex_loop_timer); 

    	for (i = 0; n_ready > 0 && i < max_fd; i++) {
	    if (!FD_ISSET(i, &r))
		continue;
	    
	    ipcr = ipc_handle(i);
            if (ipcr == IPC_EOF) {
                /* EOF reading from a socket. */
                debug("EOF from fd %d\n", i);
                event_loop_del(como_ex.el, i);
            } else if (ipcr != IPC_OK) {
		/* an error. close the socket */
		warn("error on IPC handle from %d (%d)\n", i, ipcr);
		exit(EXIT_FAILURE);
	    }
	    
	    n_ready--;
	}

        /*
         * we want to receive all the messages from capture
         * before processing the first tuples in the queue.
         */
        if (como_ex.received_tuples == 0 && como_ex.queue_len > 0)
            process_tuples(&como_ex);

        /*
         * if the tuple queue is not empty, next select
         * must not lock, because we have work to do
         */
        if (como_ex.queue_len > 0)
            event_loop_set_timeout(como_ex.el, &tv_zero);

	profiler_end_tsctimer(como_stats->ex_loop_timer); 
	profiler_end_tsctimer(como_stats->ex_full_timer); 

	/* store profiling information */
	/* ex_print_timers(); */
	ex_reset_timers();
    }

    exit(EXIT_FAILURE); /* never reached */
}

