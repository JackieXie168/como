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

#define LOG_DISABLE
#include "como.h"
#include "comopriv.h"
#include "storage.h"
#include "ipc.h"
#include "query.h"

typedef struct _como_ex como_ex_t;
struct _como_ex {
    event_loop_t el;
    char * st_dir;
    int use_shmem;
    hash_t *mdls; /* mdl name to mdl */
};


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
    mdl_t *mdl;
    alc_t *alc;
    char *str;
    ipc_type t;
    alc = como_alc();
    mdl_deserialize(&sbuf, &mdl, alc, PRIV_IEXPORT);
    if (mdl == NULL) { /* failure */
	warn("failed to receive + deserialize + load a module\n");
	ipc_send(peer, EX_SU_MODULE_ADDED, NULL, 0);
	return IPC_OK;
    }
    debug("handle_su_ex_add_module -- recv'd & loaded module `%s'\n", mdl->name);

    ie = mdl_get_iexport(mdl);

    /*
     * open output file
     */
    str = como_asprintf("%s/%s", como_ex->st_dir, mdl->name);
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
    debug("handle_ca_ex_process_ser_tuples -- tuples processed\n");

    return IPC_OK;
}

static int
handle_ca_ex_process_shm_tuples(ipc_peer_t * peer,
				msg_process_shm_tuples_t * msg,
				UNUSED size_t sz, UNUSED int swap,
				UNUSED como_ex_t * como_ex)
{
    mdl_iexport_t *ie;
    struct tuple *t;
    mdl_t *mdl;

    //debug("handle_ca_ex_process_shm_tuples -- recv'd %d tuples in shared mem\n", msg->ntuples);

    /*
     * locate the module
     */
    mdl = hash_lookup_string(como_ex->mdls, msg->mdl_name);
    if (mdl == NULL)
        error("capture sent tuples from an unknown module\n");

    //debug("handle_ca_ex_process_shm_tuples -- tuples for mdl `%s'\n", mdl->name);

    ie = mdl_get_iexport(mdl);
    /*
     * let the module process 'em
     */
    if (ie->export) {
	void **tuples;
	size_t i;

	tuples = como_calloc(msg->ntuples, sizeof(void *));

	//debug("handle_ca_ex_process_shm_tuples -- building tuple array\n");
	i = 0;
	tuples_foreach(t, &msg->tuples) {
	    tuples[i++] = t->data;
	}

	assert(i == msg->ntuples);

        ie->export(mdl, tuples, msg->ntuples, msg->ivl_start, ie->state);
	/*
	 * free allocated mem.
	 */
	free(tuples);
    } else {
        //debug("handle_ca_ex_process_shm_tuples -- store the tuples directly\n");
        tuples_foreach(t, &msg->tuples) {
	    mdl_store_rec(mdl, t->data);
        }
    }

    //debug("handle_ca_ex_process_shm_tuples -- tuples processed, sending response\n");
    ipc_send(peer, EX_CA_TUPLES_PROCESSED, msg, sz);

    return IPC_OK;
}

#if 0
/* 
 * -- ex_ipc_module_del
 * 
 * removes a module from the map. it also frees all data 
 * structures related to that module and close the output 
 * file. 
 * 
 */ 
static void
ex_ipc_module_del(procname_t sender, __attribute__((__unused__)) int fd,
                    void * buf, __attribute__((__unused__)) size_t len)
{
    module_t * mdl;
    etable_t * et; 
    earray_t * ea;
    uint32_t i, rec_size;
    int idx;

    /* only the parent process should send this message */
    assert(sender == map.parent);

    idx = *(int *)buf;
    mdl = &map.modules[idx];
    et = mdl->ex_hashtable;
    ea = mdl->ex_array;
    rec_size = sizeof(rec_t) + mdl->callbacks.ex_recordsize;
 
    /*
     * drop export hash table
     */
    free(et);
    mdl->ex_hashtable = NULL;

    /*
     * drop records
     */
    for (i = 0; i < ea->size; i++) {
        if (ea->record[i]) {
            free(ea->record[i]);
            ea->record[i] = NULL;
        }
    }

    /*
     * drop export array
     */
    free(ea);
    mdl->ex_array = NULL;
    csclose(mdl->file, mdl->offset);
    remove_module(&map, mdl);
}

/* 
 * -- ex_ipc_flush
 * 
 * process the expired tables that have been received from CAPTURE.
 * 
 */ 
static void
ex_ipc_flush(procname_t sender, __attribute__((__unused__)) int fd,
                void *buf, size_t len)
{
    expiredmap_t *em;
    
    assert(sender == sibling(CAPTURE));
    assert(len == sizeof(expiredmap_t *));
    
    for (em = *((expiredmap_t **) buf); em; em = em->next) {
	module_t * mdl; 

	/*
	 * use the correct module flush state & shared map
	 */
	mdl = em->mdl; 
	mdl->fstate = em->fstate;
	mdl->shared_map = em->shared_map;
	
	/* if in inline mode, make sure this is the inline module */
	assert(map.runmode == RUNMODE_NORMAL || mdl == map.inline_mdl); 

	/*
	 * Process the table, if the module it belongs to is active.
	 */
	if (mdl->status != MDL_ACTIVE)
	    continue;

	if (em->ct->records) {
	    /* process capture table and update export table */
	    start_tsctimer(map.stats->ex_table_timer);
	    process_table(em->ct, mdl);
	    end_tsctimer(map.stats->ex_table_timer);
	} else {
	    assert(em->ct->flexible);
	}

	/* process export table, storing/discarding records */
	start_tsctimer(map.stats->ex_store_timer);
	store_records(mdl, em->ct->ivl, em->ct->ts);
	end_tsctimer(map.stats->ex_store_timer);
    }

    /*
     * The tables have been processed. Return them to capture
     * so it can merge and reuse the memory.
     */
    ipc_send(sender, IPC_FLUSH, buf, len);
}


/*
 * -- ex_ipc_start 
 *
 * handle IPC_MODULE_START message sent by the parent process to 
 * indicate when it is possible to start processing traces and 
 * forward it to CAPTURE (sibling).
 *
 */
static void
ex_ipc_start(procname_t sender, __attribute__((__unused__)) int fd, void * buf,
                size_t len)
{
    /* only the parent process should send this message */
    assert(sender == map.parent);
    map.stats = *((void **) buf);
    ipc_send(sibling(CAPTURE), IPC_MODULE_START, buf, len); 
}


/*
 * -- ex_ipc_done
 *
 * handle IPC_DONE messages sent by CAPTURE (sibling). 
 * if we are processing this it means we are really done 
 * store this information in the map.
 *
 */
static void
ex_ipc_done(procname_t sender, __attribute__((__unused__)) int fd,
            __attribute__((__unused__)) void * buf,
	__attribute__((__unused__)) size_t len)
{
    int i;
    
    /* only CAPTURE should send this message */
    assert(sender == sibling(CAPTURE)); 

    for (i = 0; i <= map.module_last; i++) {
	module_t * mdl = &map.modules[i];
	
	if (mdl->status != MDL_ACTIVE)
	    continue;

	/* 
	 * we will not receive any more messages from CAPTURE. let's 
	 * try to store all records we have before reporting to be 
	 * done. 
	 */
	store_records(mdl, ~0, ~0);
    }

    if (map.runmode == RUNMODE_INLINE) {
	/* print the footer since running inline  */
	if (module_db_record_print(map.inline_mdl, NULL,
				   NULL, map.inline_fd) < 0)
	    handle_print_fail(map.inline_mdl);
    }
    
    ipc_send(map.parent, IPC_DONE, NULL, 0); 
}


/*
 * -- ex_ipc_exit 
 *
 */
static void
ex_ipc_exit(procname_t sender, __attribute__((__unused__)) int fd,
             __attribute__((__unused__)) void * buf,
             __attribute__((__unused__)) size_t len)
{
    assert(sender == map.parent);  
    exit(EXIT_SUCCESS); 
}
#endif


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
export_main(UNUSED ipc_peer_full_t * child, ipc_peer_t * parent,
	    memmap_t * shmemmap, UNUSED int client_fd, como_node_t * node)
{
    int supervisor_fd, capture_fd, storage_fd;
    como_ex_t como_ex;
    como_env_t *env;
    
    log_set_program("EX");

    /* initialize como_ex */
    bzero(&como_ex, sizeof(como_ex));
    como_ex.mdls = hash_new(como_alc(), HASHKEYS_STRING, NULL, NULL);

    env = como_env();
    como_ex.st_dir = como_asprintf("%s/%s", env->dbdir, node->name);
    
    /* register handlers for signals */ 
    signal(SIGPIPE, exit); 
    signal(SIGINT, exit);
    signal(SIGTERM, exit);
    signal(SIGHUP, SIG_IGN); /* ignore SIGHUP */

    /* register handlers for IPC messages */ 
    ipc_set_user_data(&como_ex);
    ipc_register(SU_EX_ADD_MODULE, (ipc_handler_fn) handle_su_ex_add_module);
    ipc_register(CA_EX_PROCESS_SER_TUPLES, (ipc_handler_fn) handle_ca_ex_process_ser_tuples);
    ipc_register(CA_EX_PROCESS_SHM_TUPLES, (ipc_handler_fn) handle_ca_ex_process_shm_tuples);
    /*ipc_register(IPC_MODULE_DEL, ex_ipc_module_del);
    ipc_register(IPC_MODULE_START, ex_ipc_start);
    ipc_register(IPC_FLUSH, (ipc_handler_fn) ex_ipc_flush);
    ipc_register(IPC_DONE, ex_ipc_done);
    ipc_register(IPC_EXIT, ex_ipc_exit);*/

/* In SU
    COMO_CA = ipc_peer_at(COMO_CA, ca_location);
    ((ipc_peer_t *)COMO_CA)->id = 0;
    ((ipc_peer_t *)COMO_CA)->parent_class = COMO_SU_CLASS;
    */
    /* listen to the parent */
    event_loop_init(&como_ex.el);
    
    supervisor_fd = ipc_peer_get_fd(parent);
    event_loop_add(&como_ex.el, supervisor_fd);

    /* 
     * wait for the debugger to attach
     */
    DEBUGGER_WAIT_ATTACH("ex");

    storage_fd = ipc_connect(COMO_ST); 
    event_loop_add(&como_ex.el, storage_fd);

    capture_fd = ipc_connect(COMO_CA);

    /* save whether we're using shmem */
    como_ex.use_shmem = (shmemmap != NULL);
    event_loop_add(&como_ex.el, capture_fd);

 
    /* allocate the timers */
    init_timers();

    /*
     * The real main loop. First process the flow_table's we 
     * receive from the CAPTURE process, then look at the export 
     * tables to see if any action is required.
     */
    for (;;) {
	fd_set r;
	int n_ready;
        int i;
        int ipcr;

	start_tsctimer(map.stats->ex_full_timer); 

        n_ready = event_loop_select(&como_ex.el, &r);
	if (n_ready < 0) {
	    if (errno == EINTR) {
		continue;
	    }
	    error("error in the select (%s)\n", strerror(errno));
	}

	start_tsctimer(map.stats->ex_loop_timer); 

    	for (i = 0; n_ready > 0 && i < como_ex.el.max_fd; i++) {
	    if (!FD_ISSET(i, &r))
		continue;
	    
	    ipcr = ipc_handle(i);
	    if (ipcr != IPC_OK) {
		/* an error. close the socket */
		warn("error on IPC handle from %d (%d)\n", i, ipcr);
		exit(EXIT_FAILURE);
	    }
	    
	    n_ready--;
	}

	end_tsctimer(map.stats->ex_loop_timer); 
	end_tsctimer(map.stats->ex_full_timer); 

	/* store profiling information */
	print_timers();
	reset_timers();
    }

    exit(EXIT_FAILURE); /* never reached */
}

#if 0
/*
 * -- main
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
int
main(int argc, char **argv)
{
    int supervisor_fd, capture_fd, storage_fd;
    char *ipc_location, *ca_location;
    como_ex_t como_ex;
    como_env_t *env;

    if (argc < 5)
        error("usage: %s ipc_location ca_location st_dir lib_dir", argv[0]);

    /* initialize como_ex */
    bzero(&como_ex, sizeof(como_ex));
    como_ex.mdls = hash_new(como_alc(), HASHKEYS_STRING, NULL, NULL);

    ipc_location = como_strdup(argv[1]);
    ca_location = como_strdup(argv[2]);
    como_ex.st_dir = como_strdup(argv[3]);
    env = como_env();
    env->libdir = como_strdup(argv[4]);
    
    como_init("EX", argc, argv);
}

#endif
