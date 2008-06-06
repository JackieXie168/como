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
#include <fcntl.h>		/* F_GETFL */
#include <unistd.h>		/* read, write etc. */
#include <string.h>		/* bzero */
#include <errno.h>		/* errno */
#include <time.h>               /* time */
#include <signal.h>
#include <assert.h>

#define CAPTURE_SOURCE

#define LOG_DEBUG_DISABLE
#include "como.h"
#include "comopriv.h"
#include "sniffers.h"
#include "ipc.h"

#include "ppbuf.c"
#include "capture-profiling.c"

#ifdef LOADSHED
#include "lsfunc.h"
#endif

/* poll time (in usec) */
#define POLL_WAIT   1000

/* flush and freeze/unfreeze thresholds */
#define FREEZE_THRESHOLD(mem)		(mem*3/4)
#define THAW_THRESHOLD(mem)		(mem*1/8)

#define CA_MAXCLIENTS		(64 - 1)	/* 1 is CAPTURE itself */

#define CACLIENT_NOSAMPLING_THRESH	0.25
#define CACLIENT_SAMPLING_THRESH	0.35
#define CACLIENT_WAIT_THRESH		0.65

/* config 'inherited' from supervisor */
extern como_config_t *como_config;

typedef struct cabuf_cl {
    ipc_peer_t *peer;		/* peer to communicate with the client */
    uint64_t	ref_mask;	/* client mask */
    float *	sniff_usage;	/* cumulative client usage of sniffer resources
				   for each sniffer */
    int *	sampling;	/* current sampling rate */
} cabuf_cl_t;

/*
 * The cabuf is a ring buffer containing pointers to captured packets.
 */
static struct {
    int tail;
    int size;
    pkt_t **pp;
    tailq_t batches;
    int has_clients_support;
    int clients_count;
    cabuf_cl_t *clients[CA_MAXCLIENTS];
    fd_set clients_fds;
} s_cabuf;

como_ca_t *s_como_ca;

/* stats 'inherited' from SU */
extern stats_t *como_stats;

/*
 * -- ppbuf_free
 *
 * release the ppbuf data structure and mark the sniffer inactive
 *
 */
static void
ppbuf_free(sniffer_t * sniff)
{
    ppbuf_destroy(sniff->ppbuf);
    sniff->priv->state = SNIFFER_INACTIVE;
}


/*
 * -- batch_free
 *
 * release the batch data structure 
 */
static inline void
batch_free(batch_t * batch)
{
    alc_free(&s_como_ca->shalc, batch);
}


/*
 * -- cleanup
 * 
 * This function is registered to get called at exit.
 * Calls the stop callback for each sniffer still active.
 */
static void
cleanup()
{
    sniffer_t *sniff;

    ipc_finish(TRUE);

    sniffer_list_foreach(sniff, s_como_ca->sniffers) {

	if (sniff->priv->state == SNIFFER_INACTIVE)
	    continue;

	sniff->cb->stop(sniff);
	ppbuf_free(sniff);
    }
}

/*
 * -- batch_filter()
 *
 * Filter function.
 * When a packet arrives, we evaluate an expression tree for each filter.
 * This needs to be optimized.
 *
 */
static char *
batch_filter(batch_t * batch, como_ca_t * como_ca)
{
    array_t *mdls;
    int i, c, l;
    char *out;
    int idx;
    int first_done = 0;
    
    static int size;
    static char *which;
    static uint64_t ld_bytes;	/* bytes seen in one minute */
    static timestamp_t ld_ts;	/* end of load meas interval */
    static uint32_t ld_idx;	/* index of load meas interval */

    if (ld_ts == 0) {
	ld_ts = (*batch->pkts0)->ts + TIME2TS(60, 0);
    }

    mdls = como_ca->mdls;
    i = batch->count * mdls->len;	/* size of the output bitmap */

    if (size < i) {
	size = i;
	which = safe_realloc(which, i);
    }

    bzero(which, i);

    out = which;

    for (idx = 0; idx < mdls->len; idx++) {
	mdl_t *mdl = array_at(mdls, mdl_t *, idx);
	mdl_icapture_t *ic;
	pkt_t *pkt, **pktptr;

	if (mdl == NULL)
	    continue;

	ic = mdl_get_icapture(mdl);
	
	c = 0;
	pktptr = batch->pkts0;
	l = MIN(batch->pkts0_len, batch->count);
	do {
	    for (i = 0; i < l; i++, pktptr++, out++, c++) {
		pkt = *pktptr;

		*out = evaluate(ic->filter, pkt);
		if (first_done == 0) {
		    if (COMO(ts) < ld_ts) {
			ld_bytes += (uint64_t) COMO(len);
		    } else {
			como_stats->load_15m[ld_idx % 15] = ld_bytes;
			como_stats->load_1h[ld_idx % 60] = ld_bytes;
			como_stats->load_6h[ld_idx % 360] = ld_bytes;
			como_stats->load_1d[ld_idx] = ld_bytes;
			ld_idx = (ld_idx + 1) % 1440;
			ld_bytes = (uint64_t) COMO(len);
			ld_ts += TIME2TS(60, 0);
		    }
		}
	    }
	    pktptr = batch->pkts1;
	    l = batch->pkts1_len;
	} while (c < batch->count);
	first_done = 1;
    }

    return which;
}

/*
 * -- mdl_flush
 *
 * Flush the state of a module to export. Free all its state.
 * If next_ts != 0, there is a change of ivl, so update the
 * module's private information to reflect this.
 */
static void
mdl_flush(mdl_t *mdl, timestamp_t next_ts)
{
    mdl_icapture_t *ic = mdl_get_icapture(mdl);

    /*
     * Change of interval management
     */
    if (ic->ivl_start != 0) {
        debug("module `%s': flushing %u tuples at interval %lu\n", mdl->name,
	      ic->tuple_count, TS2SEC(ic->ivl_start));

        if (ic->flush != NULL) /* call flush callback, if defined */
            ic->flush(mdl, ic->ivl_state);

        /*
         * we're flushing all the tuples, so the memory now is
         * in the export queue and not in the module.
         */
        como_stats->mdl_stats[mdl->id].ex_queue_size += ic->tuple_mem;

        /*
         * Send the tuples to export
         */
        if (ic->use_shmem) { /* send msg with tuples' location */
            msg_process_shm_tuples_t msg;
            strcpy(msg.mdl_name, mdl->name);
            msg.tuples = ic->tuples;
            msg.ivl_start = ic->ivl_start;
            msg.ntuples = ic->tuple_count;
            msg.mdl_id = mdl->id;
            msg.tuple_mem = ic->tuple_mem;
            msg.queue_size = como_stats->mdl_stats[mdl->id].ex_queue_size;

            como_stats->table_queue++;
            ipc_send(ic->export, CA_EX_PROCESS_SHM_TUPLES, &msg, sizeof(msg));

            /* prepare a new empty tuple list */
            tuples_init(&ic->tuples);
            ic->tuple_count = 0;
            ic->tuple_mem = 0;

            /*
             * the tuples are still in the shared memory. this memory
             * will be free'd when capture gets the message back
             * from export, which will happen after export has processed
             * the tuples.
             */
        } else { /* serialize & send tuples */
            msg_process_ser_tuples_t *msg;
            uint8_t *sbuf;
            size_t sz, ntuples;
            struct tuple *t;

            /*
             * XXX never tested
             */

            debug("module `%s': flushing - get sersize\n", mdl->name);
            sz = 0;
            ntuples = 0;
            tuples_foreach(t, &ic->tuples) { /* get serialized size */
                sz += mdl->priv->mdl_tuple.sersize(t);
                ntuples++;
            }

            msg = safe_malloc(sz + sizeof(msg_process_ser_tuples_t));
            strcpy(msg->mdl_name, mdl->name);
            msg->ntuples = ntuples;
            msg->tuple_mem = ic->tuple_mem;
            msg->ivl_start = ic->ivl_start;
            msg->mdl_id = mdl->id;
            msg->queue_size = como_stats->mdl_stats[mdl->id].ex_queue_size;

            debug("module `%s': flushing - serializing\n", mdl->name);
            sbuf = msg->data;
            tuples_foreach(t, &ic->tuples) /* get serialized size */
                mdl->priv->mdl_tuple.serialize(&sbuf, t->data);

            assert(sz == (size_t)(sbuf - msg->data));
            como_stats->table_queue++;
            ipc_send(ic->export, CA_EX_PROCESS_SER_TUPLES, msg, sz +
		     sizeof(msg_process_ser_tuples_t));
            debug("module `%s': flushing - sent serialized tuples to EX\n",
                    mdl->name);

            ic->tuple_count = 0;
            ic->tuple_mem = 0;
            debug("module `%s': flushing - capture state cleared\n", mdl->name);

            free(msg);
        }
    }

    /* update ivl_start and ivl_end */
    if (next_ts != 0) {
        ic->ivl_start = next_ts - (next_ts % mdl->flush_ivl);
        ic->ivl_end = ic->ivl_start + mdl->flush_ivl;
    }

    /* initialize new state */
    pool_clear(ic->ivl_mem);
    if (ic->init)
        ic->ivl_state = ic->init(mdl, ic->ivl_start);
}

static timestamp_t
mdl_batch_process(mdl_t * mdl, batch_t * batch, char * fltmap)
{
    pkt_t **pktptr;
    int i, c, l;
    timestamp_t ts;

    mdl_icapture_t *ic = mdl_get_icapture(mdl);

    for (c = 0, pktptr = batch->pkts0, l = MIN(batch->pkts0_len, batch->count);
	 c < batch->count;
	 pktptr = batch->pkts1, l = batch->pkts1_len)
    {
	for (i = 0; i < l; i++, pktptr++, c++, fltmap++) {
	    pkt_t *pkt = *pktptr;

            ts = pkt->ts;

	    if (ts >= ic->ivl_end) /* change of ivl or 1st batch */
                mdl_flush(mdl, ts);

	    if (*fltmap == 0)
		continue;	/* no interest in this packet */

            #ifdef LOADSHED
	    ic->capture(mdl, pkt, ic->ivl_state, ic->ls.srate);
            #else
	    ic->capture(mdl, pkt, ic->ivl_state, 1.0);
            #endif
	}
    }

    return ts;
}

/* 
 * -- batch_process 
 * 
 * take a batch of packets, run them thru the batch_filter and 
 * then call the capture_pkt function for each individual 
 * module. return the last timestamp of the batch.
 * 
 */
static timestamp_t
batch_process(batch_t * batch, como_ca_t *como_ca)
{
    char *which;
    int idx;

    /*
     * Select which classifiers need to see which packets The batch_filter()
     * function (see comments in file base/template) returns a
     * bidimensional array of integer which[cls][pkt] where the first
     * index indicates the classifier, the second indicates the packet
     * in the batch.  The element of the array is set if the packet is
     * of interest for the given classifier, and it is 0 otherwise.
     */
    debug("calling batch_filter with pkts %p, count %d\n",
	  *batch->pkts0, batch->count);

    profiler_start_tsctimer(como_stats->ca_filter_timer);
    which = batch_filter(batch, como_ca);
    profiler_end_tsctimer(como_stats->ca_filter_timer);

#ifdef LOADSHED
    /* apply load shedding to the batch
     * before processing it with the modules */
    batch_loadshed_pre(batch, como_ca, which);
#endif

    /*
     * Now browse through the classifiers and perform the capture
     * actions needed.
     *
     * XXX we do it this way just because anyway we have got a
     * single-threaded process.  will have to change it in the
     * future...
     *
     */
    for (idx = 0; idx < como_ca->mdls->len; idx++) {
	mdl_t *mdl = array_at(como_ca->mdls, mdl_t *, idx);
	mdl_icapture_t *ic = mdl_get_icapture(mdl);

	if (ic->status != MDL_ACTIVE)
	    continue;

	assert(mdl->name != NULL);
	debug("sending %d packets to module %s for processing\n",
	      batch->count, mdl->name);

	profiler_start_tsctimer(como_stats->ca_module_timer);
#ifdef LOADSHED
        start_profiler(ic->ls.prof);
#endif
        mdl_batch_process(mdl, batch, which);
#ifdef LOADSHED
        end_profiler(ic->ls.prof);
#endif
	profiler_end_tsctimer(como_stats->ca_module_timer);
	which += batch->count;	/* next module, new list of packets */
    }

    #if 0 /* XXX need to define como_ca->mem_size */
    if (memory_usage() >= FREEZE_THRESHOLD(como_ca->mem_size)) {
        for (idx = 0; idx < como_ca->mdls->len; idx++) {
            mdl_t *mdl = array_at(como_ca->mdls, mdl_t *, idx);
            mdl_icapture_t *ic = mdl_get_icapture(mdl);

	    if (ic->status != MDL_ACTIVE) /* not running */
		continue;

	    if (ic->capabilities.has_flexible_flush == 0
                || tuple_collection_empty(&ic->tuples)) {
		continue; /* not flushable or no memory to free */
	    }

	    debug("flexible flush for %s occurred\n", mdl->name);
            mdl_flush(mdl, 0); /* flush without ivl change */

            #if 0
	    /* reset capture table */
	    mdl->shared_map = memmap_new(allocator_shared(), 64,
					 POLICY_HOLD_IN_USE_BLOCKS);
	    mdl->ca_hashtable = create_table(mdl, ivl);
	    if (mdl->ca_hashtable == NULL)
		continue;
	    mdl->ca_hashtable->flexible = 1;
	    if (mdl->callbacks.flush != NULL) {
		mdl->fstate = mdl->callbacks.flush(mdl);
	    }
            #endif
	}
    }
    #endif
#if 0
    /*
     * send to EXPORT information on the memory to be read, 
     * where to free it and what module it refers to. 
     */
    first_exp_table = TQ_HEAD(&exp_tables);
    if (first_exp_table != NULL) {
	int ret;

	ret = ipc_send(sibling(EXPORT), IPC_FLUSH,
		       &first_exp_table, sizeof(expiredmap_t *));
	if (ret != IPC_OK)
	    panic("IPC_FLUSH failed!");
    }
#endif

#ifdef LOADSHED
    /* get feedback for the load shedding scheme after having
     * processed the batch with the modules */
    batch_loadshed_post(batch, como_ca);
#endif

    /*  
     * get batch timestamp, i.e. the timestamp of the last packet 
     * of the batch. 
     */
    return batch->last_pkt_ts;
}

/* 
 * -- ca_ipc_module_add
 * 
 * this is the handler for IPC_MODULE_ADD messages from SUPERVISOR. 
 * first check it is coming from SUPERVISOR. then unpack the module 
 * and add it to the map. finally, make suer the module is compatible
 * with current sniffers, install the filter, activate the module and 
 * initialize capture hash table. 
 * 
 */
static int
handle_su_ca_add_module(ipc_peer_t * peer, uint8_t * sbuf, UNUSED size_t sz,
			UNUSED int swap, como_ca_t * como_ca)
{
    mdl_t *mdl;
    mdl_icapture_t *ic;

    debug("capture adding module - deserialize\n");
    mdl_deserialize(&sbuf, &mdl, como_alc(), PRIV_ICAPTURE);
    if (mdl == NULL) {
	/* failed */
	ipc_send(peer, CA_SU_MODULE_FAILED, NULL, 0);
	return IPC_OK;
    }

    ic = mdl_get_icapture(mdl);
    
    /* parse the filter string */
    debug("capture adding module - parse filter\n");
    if (mdl->filter)
        parse_filter(mdl->filter, &(ic->filter), NULL);

    /* save the minimum flush interval */
    if (como_ca->min_flush_ivl == 0 ||
	como_ca->min_flush_ivl > mdl->flush_ivl) {
	como_ca->min_flush_ivl = mdl->flush_ivl;
    }
    
    tuples_init(&ic->tuples);

    ic->ivl_mem = pool_create();
    pool_alc_init(ic->ivl_mem, &mdl->priv->alc);

#ifdef LOADSHED
    ls_init_mdl(mdl->name, &ic->ls, mdl->shed_method);
#endif

    array_add(como_ca->mdls, &mdl);

    debug("capture adding module - done, waiting for EX to attach\n");
    ic->status = MDL_WAIT_FOR_EXPORT;

    ipc_send(peer, CA_SU_MODULE_ADDED, NULL, 0);
    msg("adding module %s\n", mdl->name);

    como_stats->modules_active++;

    return IPC_OK;
}

static int
handle_ex_ca_attach_module(UNUSED ipc_peer_t * peer, msg_attach_module_t * msg,
			   UNUSED size_t sz, UNUSED int swap,
			   como_ca_t * como_ca)
{
    mdl_icapture_t *ic;
    mdl_t *mdl;

    debug("capture - export attaches to module `%s'\n", msg->mdl_name);

    mdl = mdl_lookup(como_ca->mdls, msg->mdl_name);
    if (mdl == NULL) {
        warn("export attaches to an unknown module `%s'\n",
            msg->mdl_name);
        return IPC_CLOSE;
    }

    ic = mdl_get_icapture(mdl);
    ic->export = peer;

    if (msg->use_shmem) {
        debug("capture - using shmem\n");
        memmap_alc_init(como_ca->shmemmap, &ic->tuple_alc);
        ic->use_shmem = TRUE;
    } else {
        debug("capture - will use serialized interface for `%s'\n", mdl->name);
        ic->tuple_alc = mdl->priv->alc;
        ic->use_shmem = FALSE;
    }

    ipc_send(peer, CA_EX_MODULE_ATTACHED, NULL, 0);

    debug("capture - module `%s' can run\n", mdl->name);
    ic->status = MDL_ACTIVE;

    return IPC_OK;
}

/* 
 * -- ca_ipc_module_del 
 * 
 * this function removes a module. The message contains the
 * name of the module to remove.
 * 
 */
static int
handle_su_ca_ipc_module_del(UNUSED ipc_peer_t * peer, char *sbuf,
			UNUSED size_t sz, UNUSED int swap, como_ca_t * como_ca)
{
    char *name;
    mdl_t *mdl;
    int pos;

    deserialize_string(&sbuf, &name, como_alc());

    mdl = mdl_lookup(como_ca->mdls, name);
    if (mdl == NULL) {
        warn("deletion of unknown module `%s' requested\n", name);
        ipc_send(peer, CA_SU_MODULE_FAILED, NULL, 0);
        free(name);
        return IPC_OK;
    }

    if (mdl_get_icapture(mdl)->status == MDL_ACTIVE) {
        struct tuple *t, *next;
        mdl_icapture_t *ic = mdl_get_icapture(mdl);

        t = tuples_first(&ic->tuples);
        while (t != NULL) { /* free the associated tuples */
            next = tuples_next(t);
            alc_free(&como_ca->shalc, t);
            t = next;
        }

        pool_clear(ic->ivl_mem); /* free all the memory of the mdl */
    }

    /*
     * forget about the module 
     */
    pos = mdl_lookup_position(como_ca->mdls, name);
    mdl_destroy(mdl, PRIV_ICAPTURE);
    array_remove(como_ca->mdls, pos);
    ipc_send(peer, CA_SU_MODULE_REMOVED, NULL, 0);

    msg("capture removes module `%s'\n", name);
    free(name);
    return IPC_OK;
}

static int
handle_ex_ca_tuples_processed(UNUSED ipc_peer_t * peer,
			      msg_process_shm_tuples_t *msg,
			      UNUSED size_t sz, UNUSED int swap,
			      como_ca_t * como_ca)
{
    struct tuple *t, *t2;

    /*
     * we can't use info from como_ca->mdls here, because these tuples
     * may come from a module that has been recently removed.
     */

    t = tuples_first(&msg->tuples);
    while (t != NULL) {
	t2 = t;
	t = tuples_next(t);
	alc_free(&como_ca->shalc, t2);
    }

    como_stats->table_queue--;
    como_stats->mdl_stats[msg->mdl_id].ex_queue_size -= msg->tuple_mem;

    return IPC_OK;
}

#if 0
/* 
 * -- ca_ipc_freeze
 * 
 * this IPC causes CAPTURE to wait for the next message before 
 * doing any other processing. this usually happens right before 
 * an IPC_MODULE_ADD message. SUPERVISOR needs to stop CAPTURE to 
 * allocate some memory in shared space. 
 * 
 */
static void
ca_ipc_freeze(procname_t sender, UNUSED int fd,
              UNUSED void *buf,
	      UNUSED size_t len)
{
    fd_set r;
    int s;

    /* only the parent process should send this message */
    assert(sender == map.parent);

    /* send acknowledgement */
    ipc_send(SUPERVISOR, IPC_ACK, NULL, 0);

    /* wait on an infinite select() */
    FD_ZERO(&r);
    FD_SET(fd, &r);

    s = -1;
    while (s < 0) {
	s = select(fd + 1, &r, NULL, NULL, NULL);
	if (s < 0 && errno != EINTR)
	    panic("select");
    }

    ipc_handle(fd);		/* FIXME: error handling */
}

/* 
 * -- ca_ipc_flush
 * 
 * this is the handler for IPC_FLUSH messages from EXPORT.
 * a pointer to a list of expired map is received and all the memory
 * associated with its entries has to be freed.
 * 
 */
static void
ca_ipc_flush(procname_t sender, UNUSED int fd,
             void *buf, size_t len)
{
    expiredmap_t *em;

    /* only EXPORT (sibling) should send this message */
    assert(sender == sibling(EXPORT));
    assert(len == sizeof(expiredmap_t *));

    em = *((expiredmap_t **) buf);

    while (em) {
	expiredmap_t *em_next = em->next;

	/* ok, move freed memory into the main memory */
	memmap_destroy(em->shared_map);

	como_stats->table_queue--;

	/* NOTE: *em was allocated inside em->shared_map so memmap_destroy
	 * will deallocate that too. That's why we use em_next.
	 */
	em = em_next;
    }
}
#endif

/* 
 * -- handle_su_ca_start
 * 
 * handle IPC_MODULE_START message sent by SUPERVISOR to indicate when 
 * it is possible to start processing traces. 
 * 
 */
static int
handle_su_ca_start(UNUSED ipc_peer_t * peer, UNUSED void * m, UNUSED size_t sz,
		   UNUSED int swap, como_ca_t * como_ca)
{
    if (como_ca->min_flush_ivl == 0) {
	como_ca->min_flush_ivl = TIME2TS(1, 0);
    }

    como_ca->timebin = 100000;

    msg("starting to capture packets\n");
    como_ca->ready = TRUE;
    return IPC_OK;
}


/* 
 * -- handle_su_ca_exit
 * 
 * terminate this processing cleaning up the sniffers. 
 * 
 */
static int
handle_su_any_exit(UNUSED ipc_peer_t * peer, UNUSED void * m, UNUSED size_t sz,
		  UNUSED int swap, UNUSED como_ca_t * como_ca)
{
    exit(EXIT_SUCCESS);

    return IPC_OK; /* not reached */
}


/**
 * -- cabuf_cl_destroy
 * 
 * Actually performs client state destruction.
 */
static void
cabuf_cl_destroy(int id, cabuf_cl_t * cl, como_ca_t * como_ca)
{
    batch_t *bi, *bn;
    int fd;

    /* update s_cabuf */
    s_cabuf.clients[id] = NULL;
    s_cabuf.clients_count--;
    fd = ipc_peer_get_fd(cl->peer);
    event_loop_del(como_ca->el, fd);
    FD_CLR(fd, &s_cabuf.clients_fds);

    close(fd);

    bi = TQ_HEAD(&s_cabuf.batches);
    while (bi) {
	bn = bi->next;
	bi->ref_mask &= ~cl->ref_mask;
	if (bi->ref_mask == 0) {
	    TQ_POP(&s_cabuf.batches, bi, next);
	    batch_free(bi);
	}
	bi = bn;
    }

    free(cl->sniff_usage);
    free(cl);
}


/**
 * -- cabuf_cl_handle_failure
 * 
 * Handles a client failure by logging a message and destroying its state.
 */
static void
cabuf_cl_handle_failure(int id, cabuf_cl_t * cl, como_ca_t * como_ca)
{
    warn("sending message to capture client (%d): %s\n",
	 id, strerror(errno));
    cabuf_cl_destroy(id, cl, como_ca);
}


/**
 * -- cabuf_cl_handle_gone
 * 
 * Handles a client gone by logging a message and destroying its state.
 */
static void
cabuf_cl_handle_gone(int fd, como_ca_t * como_ca)
{
    int id;

    /* iterate over the clients */
    for (id = 0; id < s_cabuf.clients_count; id++) {
	cabuf_cl_t *cl;

	cl = s_cabuf.clients[id];
	/* skip unwanted clients */
	if (cl == NULL || ipc_peer_get_fd(cl->peer) != fd)
	    continue;

	warn("capture client is gone (id: `%d`, fd: `%d`)\n",
	     id, fd);
	cabuf_cl_destroy(id, cl, como_ca);
	break;
    }
}


/**
 * -- ca_ipc_cca_open
 * 
 * Handles a CCA_OPEN message. Accepts the new capture client if possible
 * and allocates a new cabuf_cl_t structure. Sends a response message
 * to the client.
 * If it's not possible to accept the new client replies with a CCA_ERROR
 * message.
 */
static int
ca_ipc_cca_open(ipc_peer_t * peer, UNUSED void * buf, UNUSED size_t len,
		UNUSED int swap, como_ca_t * como_ca)
{
    ccamsg_t m;
    cabuf_cl_t *cl;
    size_t sz;
    int id;

    if (s_cabuf.has_clients_support == 0) {
	warn("rejecting capture-client: clients support disabled. "
	       "does sniffer define SNIFF_SHBUF?\n");
	ipc_send(peer, CCA_ERROR, NULL, 0);
	return IPC_CLOSE;
    }

    if (s_cabuf.clients_count == CA_MAXCLIENTS) {
	warn("rejecting capture-client: too many clients\n");
	ipc_send(peer, CCA_ERROR, NULL, 0);
	return IPC_CLOSE;
    }

    /* look for an empty slot */
    for (id = 0; id < CA_MAXCLIENTS; id++)
	if (s_cabuf.clients[id] == NULL)
	    break;

    assert(id < CA_MAXCLIENTS);
    cl = como_new0(cabuf_cl_t);
    cl->peer = peer;
    cl->ref_mask = (1LL << (uint64_t) (id + 1));	/* id 0 -> mask 2 */
    cl->sniff_usage = safe_calloc(como_ca->sniffers_count , sizeof(float));
    cl->sampling = alc_new0(&como_ca->shalc, int); /* sampling rate is kept
						      into shared memory */

    s_cabuf.clients[id] = cl;
    s_cabuf.clients_count++;
    FD_SET(ipc_peer_get_fd(peer), &s_cabuf.clients_fds);

    m.open_res.id = id;
    m.open_res.sampling = cl->sampling;
    sz = sizeof(m.open_res);

    if (ipc_send(peer, CCA_OPEN_RES, &m, sz) != IPC_OK) {
	cabuf_cl_handle_failure(id, cl, como_ca);
	return IPC_CLOSE;
    }
    return IPC_OK;
}


/**
 * -- ca_ipc_cca_ack_batch
 * 
 * Handles a CCA_ACK_BATCH message. Updates the client state and the s_cabuf
 * state.
 */
static int
ca_ipc_cca_ack_batch(UNUSED ipc_peer_t * peer, void * buf, UNUSED size_t len,
		     UNUSED int swap, como_ca_t * como_ca)
{
    ccamsg_t *m = (ccamsg_t *) buf;
    cabuf_cl_t *cl;
    batch_t *batch;
    int source_id;

    cl = s_cabuf.clients[m->ack_batch.id];
    assert(cl != NULL);

    batch = TQ_HEAD(&s_cabuf.batches);
    while (batch) {
	if (batch == m->ack_batch.batch) {
	    break;
	}
	batch = batch->next;
    }
    assert(batch != NULL);
    batch->ref_mask &= ~cl->ref_mask;

    /* update the usage */
    for (source_id = 0; source_id < como_ca->sniffers_count; source_id++) {
	cl->sniff_usage[source_id] -= batch->sniff_usage[source_id];
#ifdef DEBUG
	if (cl->sniff_usage[source_id] > 2)
	    debug("decr usage: %d\n", cl->sniff_usage[source_id]);
#endif
    }
    
    if (batch->ref_mask == 0) {
	assert(batch == TQ_HEAD(&s_cabuf.batches));
	TQ_POP(&s_cabuf.batches, batch, next);
	batch_free(batch);
    }
    
    return IPC_OK;
}


/*
 * -- cabuf_init
 * 
 * initializes the cabuf kept in the static variable s_cabuf.
 * 
 */
static void
cabuf_init(como_ca_t * como_ca, size_t size)
{
    sniffer_t *sniff;
    sniffer_list_t *sniffers;
    
    sniffers = como_ca->sniffers;

    /*
     * allocate the buffer of pointers to captured packets in shared
     * memory.
     */
    s_cabuf.size = size;
    s_cabuf.pp = alc_calloc(&como_ca->shalc, s_cabuf.size, sizeof(pkt_t *));
    s_cabuf.has_clients_support = 1;

    sniffer_list_foreach(sniff, sniffers) {

	if (sniff->priv->state == SNIFFER_INACTIVE)
	    continue;

	/*
	 * if a sniffer doesn't expose the payloads in shared memory
	 * we turn off the support for clients
	 */
	if (!(sniff->flags & SNIFF_SHBUF))
	    s_cabuf.has_clients_support = 0;
    }
}


/*
 * -- cabuf_reserve
 * 
 * reserves the specified number of pkt pointers from the cabuf.
 * 
 */
static void
cabuf_reserve(batch_t * batch, int reserved)
{
    int new_tail;
    pkt_t **end;

    /* compute the new tail */
    new_tail = (s_cabuf.tail + reserved) % s_cabuf.size;
    /* set end to point to the pkt pointer corresponding to the new tail */
    end = &s_cabuf.pp[new_tail];
    /* complete the initialization of batch */
    batch->woff = s_cabuf.tail;
    batch->reserved = reserved;
    batch->pkts0 = &s_cabuf.pp[s_cabuf.tail];
    if (end > batch->pkts0 || end == s_cabuf.pp) {
	/* all the pkt pointers are contiguous */
	batch->pkts1 = NULL;
	batch->pkts0_len = reserved;
	batch->pkts1_len = 0;
    } else {
	/* the pkt pointers are not contiguous */
	batch->pkts1 = s_cabuf.pp;
	batch->pkts0_len = s_cabuf.size - s_cabuf.tail;
	batch->pkts1_len = reserved - batch->pkts0_len;
    }
    /* update the tail */
    s_cabuf.tail = new_tail;
}


/*
 * -- cabuf_complete
 * 
 * updates the cabuf tail so that the previously reserved pkt pointers which
 * were not used are returned to cabuf.
 * 
 */
static void
cabuf_complete(batch_t * batch)
{
    s_cabuf.tail = batch->woff;

    if (batch->count < batch->pkts0_len) {
	batch->pkts1 = NULL;
	batch->pkts0_len = batch->count;
	batch->pkts1_len = 0;
    } else {
	batch->pkts1_len = batch->count - batch->pkts0_len;
    }
    batch->reserved = batch->count;
}


#if 0
/*
 * -- batch_export
 * 
 * Exports a batch to capture clients. The batch is queued to s_cabuf.batches
 * and a CCA_NEW_BATCH is sent to all clients.
 */
static void
batch_export(batch_t * batch, como_ca_t * como_ca)
{
    int id;

    /* iterate over clients */

    for (id = 0; id < s_cabuf.clients_count; id++) {
	ccamsg_t m;
	size_t sz;
	int source_id;

	cabuf_cl_t *cl = s_cabuf.clients[id];

	/* skip NULL clients */

	if (cl == NULL)
	    continue;

	/* prepare the message */

	m.new_batch.id = id;
	m.new_batch.batch = batch;
	sz = sizeof(m.new_batch);

	/* send the message */

	if (ipc_send(cl->peer, CCA_NEW_BATCH, &m, sz) != IPC_OK) {
	    cabuf_cl_handle_failure(id, cl, como_ca);
	    continue;
	}
	
	/* update the usage */
	for (source_id = 0; source_id < como_ca->sniffers_count; source_id++) {
	    cl->sniff_usage[source_id] += batch->sniff_usage[source_id];
#ifdef DEBUG
	    if (cl->sniff_usage[source_id] > 2)
		debug("incr usage: %d\n", cl->sniff_usage[source_id]);
#endif
	}

	batch->ref_mask |= cl->ref_mask;
    }

    if (batch->ref_mask > 1) {
	/* append the batch to the queue of active batches */
	TQ_APPEND(&s_cabuf.batches, batch, next);
    }
}
#endif


static pkt_t *
batch_append(batch_t * batch, ppbuf_t * ppbuf)
{
    pkt_t *pkt;

    pkt = ppbuf_get(ppbuf);

    ppbuf_next(ppbuf);
    
    batch->count++;
    assert(batch->count <= batch->reserved);

    s_cabuf.pp[batch->woff] = pkt;
    batch->woff = (batch->woff + 1) % s_cabuf.size;
    
    batch->last_pkt_ts = pkt->ts;

    return pkt;
}

static timestamp_t UNUSED
timebin_end(timestamp_t ts, uint32_t tb)
{
    timestamp_t t;
    
    t = TIME2TS(TS2SEC(ts), TS2USEC(ts) - TS2USEC(ts) % tb + tb);

    if (ts == t) /* avoid rounding error */
        t = TIME2TS(TS2SEC(ts + 1),
                TS2USEC(ts + 1) - TS2USEC(ts + 1) % tb + tb);

    assert(ts != t);
    return t;
}

/*
 * -- batch_create
 * 
 * creates a new batch by merging and sorting the captured packets
 *
 * XXX should be revised
 */
static batch_t *
batch_create(int force_batch, como_ca_t * como_ca)
{
    static timestamp_t last_bin_end = 0;
    batch_t *batch;
    sniffer_t *sniff;
    ppbuf_t *ppbuf;
    ppbuf_list_t ppblist;
    timestamp_t max_last_pkt_ts = 0;
    timestamp_t min_first_pkt_ts = ~0;
    int pc = 0;
    int one_full_flag = 0;
    sniffer_list_t * sniffers;
    timestamp_t live_th;
    timestamp_t bin_end;
    
    sniffers = como_ca->sniffers;
    live_th = como_ca->live_th;

    ppbuf_list_init(&ppblist);

    /*
     * count packets
     * find max(last packet timestamp) and min(first packet timestamp)
     * determine if any sniffer has filled its buffer
     */
    sniffer_list_foreach(sniff, sniffers) {

	if (sniff->priv->state == SNIFFER_INACTIVE)
	    continue;

	ppbuf = sniff->ppbuf;
	
	ppbuf_list_insert_head(&ppblist, ppbuf);

	pc += ppbuf->count;

	if (ppbuf->last_pkt_ts > max_last_pkt_ts)
	    max_last_pkt_ts = ppbuf->last_pkt_ts;

        if (ppbuf->count > 0) {
            pkt_t *pkt = ppbuf_get(ppbuf);
            if (pkt->ts < min_first_pkt_ts)
                min_first_pkt_ts = pkt->ts;
        }

	if (ppbuf->count == ppbuf->size || sniff->priv->full ||
                sniff->priv->closing)
	    one_full_flag = 1;

#ifdef DEBUG_PPBUF
	assert(ppbuf_is_ordered(ppbuf));
#endif
    }

    /* easy if no packets */

    if (pc == 0)
	return NULL;

    /*
     * if no buffer is full (and our caller did not set force_batch)
     * then we consider if the batch would cover too small a time period
     * and we would be better waiting for more packets
     *
     * we look for a live sniffer that has provided no packets and
     * where the latest packet we have from anyone is close in time
     * to the last packet that sniffer provided to us
     */

    if (!one_full_flag && !force_batch) {
	ppbuf_list_foreach (ppbuf, &ppblist) {
	    if (ppbuf->count == 0) {
		if ((max_last_pkt_ts - ppbuf->last_pkt_ts) <= live_th) {
                    debug("live threshold prevents batch creation\n");
		    return NULL;
                }
            }
	}
    }

    /*
     * calculate the end of the current time bin. make sure that
     * the time bin advances, even if there are packets that
     * belong to previous timebins. this helps overcome non-increasing
     * timestamps in the packet stream.
     */
    bin_end = timebin_end(min_first_pkt_ts, como_ca->timebin);
    
    if (last_bin_end != 0 && bin_end <= last_bin_end)
        bin_end = timebin_end(last_bin_end + 1, como_ca->timebin);

    /*
     * if we do not have a complete timebin, wait until we receive more
     * packets from the sniffers
     */
    if (max_last_pkt_ts <= bin_end && !force_batch && !one_full_flag)
        return NULL;

    /* create the batch structure */

    batch = alc_new0(&como_ca->shalc, batch_t);
    cabuf_reserve(batch, pc);
    last_bin_end = bin_end;

    if (s_cabuf.clients_count > 0) {
	batch->first_ref_pkts = alc_calloc(&como_ca->shalc,
					   como_ca->sniffers_count,
					   sizeof(pkt_t *));
	batch->sniff_usage = alc_calloc(&como_ca->shalc,
					como_ca->sniffers_count,
					sizeof(float));
	
	ppbuf_list_foreach (ppbuf, &ppblist) {
	    if (ppbuf->count > 0)
		batch->first_ref_pkts[ppbuf->id] = ppbuf_get(ppbuf);
	}
    }

    /*
     * We transfer the packets into the batch structure in time order. We
     * locate the sniffer with the earliest packet and copy it, looping
     * until either all packets are done, or we have too small a time period
     */

    while (pc) {
	ppbuf_t *this_ppbuf;
        pkt_t *pkt;
	/* find minimum ts */

	timestamp_t min_ts = ~0;
	ppbuf = NULL;

	ppbuf_list_foreach (this_ppbuf, &ppblist) {
	    timestamp_t this_ts;

	    if (this_ppbuf->count == 0)
		continue;

	    this_ts = (ppbuf_get(this_ppbuf))->ts;

	    if (this_ts < min_ts) {
		min_ts = this_ts;
		ppbuf = this_ppbuf;
	    }
	}

	assert(ppbuf);

        ppbuf->sniffer->priv->full = 0;
        pkt = ppbuf_get(ppbuf);
        if (pkt->ts >= bin_end)
            break;

	/* update batch */
	pkt = batch_append(batch, ppbuf);
        como_ca->first_ref_pkts[ppbuf->id] = pkt;
	pc--;

	/* 
	 * if there are no more packets from this sniffer and we are
	 * getting close to the maximum time of any packet from any
	 * sniffer then we break out of the loop so that we can collect
	 * some more packets and put them into a new batch
	 */

	if (ppbuf->count == 0)
	    if ((max_last_pkt_ts - ppbuf->last_pkt_ts) <= live_th)
		break;
    }

    if (batch->count < batch->reserved)
	cabuf_complete(batch);

    if (s_cabuf.clients_count > 0) {
	sniffer_list_foreach(sniff, sniffers) {
	    float usage;
	    if (sniff->priv->state == SNIFFER_INACTIVE)
		continue;

	    ppbuf = sniff->ppbuf;

	    if (batch->first_ref_pkts[ppbuf->id] == NULL)
		continue;

	    usage = sniff->cb->usage(sniff,
				     batch->first_ref_pkts[ppbuf->id],
				     ppbuf->last_rpkt);
	    batch->sniff_usage[ppbuf->id] = usage;
	}
    }

    batch->ref_mask = 1LL;
    
    return batch;
}


static int
cabuf_cl_res_mgmt(int wait_for_clients, int avg_batch_len,
		  UNUSED sniffer_list_t * sniffers, int sniffers_count)
{
    int id;
#ifdef DEBUG
    int new_wait_for_clients = 0;
#endif

    wait_for_clients = 0;

    /*
     * for each client check the current usage that the client
     * has on each sniffer
     */
    for (id = 0; id < s_cabuf.clients_count; id++) {
	int src_id;
	int sampling = 0;

	cabuf_cl_t *cl = s_cabuf.clients[id];

	/* skip NULL clients */
	if (cl == NULL)
	    continue;

	for (src_id = 0; src_id < sniffers_count; src_id++) {
	    float u = cl->sniff_usage[src_id];
#ifdef DEBUG
	    if (u > CACLIENT_WAIT_THRESH) {
		/*
		 * if the client usage is above the wait theshold
		 * we set the new_wait_for_clients flag and increment
		 * a wait counter
		 */
		new_wait_for_clients = 1;
	    } else
#endif
	    if (u > CACLIENT_SAMPLING_THRESH) {
		/*
		 * if the client usage is above the sampling threshold
		 * we tell the client to start sampling
		 * the sampling rate is proportional to the distance of
		 * the current usage from the threshold
		 */
		float m;
		int s;
		u -= CACLIENT_SAMPLING_THRESH;
		m = 1.0 - CACLIENT_SAMPLING_THRESH;
		s = (int) ((float) avg_batch_len * u / m);
		if (s > sampling)
		    sampling = s;
	    } else if (u < CACLIENT_NOSAMPLING_THRESH) {
		/*
		 * if the client usage is below the nosampling threshold
		 * we tell the client to stop sampling
		 */
		if (1 > sampling)
		    sampling = 1;
	    }
	}
	/* set the sampling rate */
	if (sampling > 0) {
	    *cl->sampling = sampling;
	}
    }
#ifdef DEBUG
    if (new_wait_for_clients == 0) {
    	if (wait_for_clients) {
	    sniffer_t *sniff;
	    debug("client rate normal, unfreezing all sniffers\n");
	    sniffer_list_foreach(sniff, sniffers) {
		if (sniff->priv->state == SNIFFER_INACTIVE)
		    continue;

		sniff->priv->state = SNIFFER_ACTIVE;
		sniff->priv->touched = TRUE;
	    }
    	}
    	wait_for_clients = 0;
    } else {
	/*
	 * start a sync communication with the client(s) by freezing
	 * all the sniffers if necessary and setting the
	 * wait_for_clients flag
	 */
    	if (wait_for_clients == 0) { 
	    sniffer_t *sniff;
	    debug("client rate low, freezing all sniffers\n");
	    sniffer_list_foreach(sniff, sniffers) {
		if (sniff->priv->state == SNIFFER_INACTIVE)
		    continue;

		sniff->priv->state = SNIFFER_FROZEN;
	    }
	}
	wait_for_clients = 1;
    }
#endif
    return wait_for_clients;
}


/* 
 * -- setup_sniffers 
 * 
 * scan the list of sniffers to identify all the file descriptors 
 * that need a select() and to set the appropriate polling interval
 *
 * Note that if no sniffer has been "TOUCHED" then we leave the
 * select structure AND the timeout alone.
 *
 * Returns -1 if all sniffers have finished.
 * 
 */
static int
setup_sniffers(struct timeval *tout, sniffer_list_t * sniffers,
	       como_ca_t * como_ca)
{
    sniffer_t *sniff;

    /* if no sniffers are marked "touched" then very easy */

    int active = 0;
    int touched = 0;
    timestamp_t polling = ~0;

    sniffer_list_foreach(sniff, sniffers) {

	if (sniff->priv->touched == TRUE)
	    touched++;

	if (sniff->priv->state == SNIFFER_ACTIVE ||
                sniff->priv->state == SNIFFER_FROZEN)
	    active++;
    }

    if (touched == 0)
	return active;

    if (como_ca->ready != TRUE)
        return active;

    /* rebuild the list of file selectors and recalculate the timeout */
    tout->tv_sec = 3600;
    tout->tv_usec = 0;

    sniffer_list_foreach(sniff, sniffers) {

	sniff->priv->touched = FALSE;

	/* 
	 * remove the file descriptor from the list independently if 
	 * it is a valid one or not. we will add it later if needed. 
	 * del_fd() deals with invalid fd. 
	 */
	if (sniff->priv->fd != -1)
	    event_loop_del(como_ca->el, sniff->priv->fd);

	/* inactive and frozen sniffers can be ignored */

	if (sniff->priv->state == SNIFFER_INACTIVE) {
	    sniff->fd = -1;
	    continue;
	}

	if (sniff->priv->state == SNIFFER_FROZEN)
	    continue;

	/* sniffers marked complete need to be finished off ASAP */

	if (sniff->priv->state == SNIFFER_COMPLETED) {
	    polling = 0;
	    continue;
	}

	/* if sniffer uses polling, reduce timeout to <= polling interval */

	if ((sniff->flags & SNIFF_POLL) && sniff->polling < polling) {
	    polling = sniff->polling;
	}

	/* if sniffer uses select(), add the file descriptor to the list */

	if (sniff->flags & SNIFF_SELECT) {
	    sniff->priv->fd = sniff->fd;
	    event_loop_add(como_ca->el, sniff->priv->fd);
	}
    }

    if (polling < TS_MAX) {
	tout->tv_sec = TS2SEC(polling);
	tout->tv_usec = TS2USEC(polling);
    }

    /* if no sniffers now active then we log this change of state */

    if ((active == 0) && (! como_config->inline_mode)) {
        array_t *mdls;
        int idx;

        mdls = como_ca->mdls;

        debug("no sniffers left - flushing all modules\n");
        for (idx = 0; idx < mdls->len; idx++) {
            mdl_t *mdl = array_at(mdls, mdl_t *, idx);
            mdl_icapture_t *ic = mdl_get_icapture(mdl);

            if (ic->status != MDL_ACTIVE)
                continue;

            debug("no sniffers left - flushing `%s'\n", mdl->name);
            mdl_flush(mdl, 0);
        }

	msg("no sniffers left. waiting for queries\n");

        return -1; /* signal that we are done. this will be returned 
                    * once, because at this point all sniffers have
                    * been removed from the list and from now on
                    * this will return 0. */
    }

    return active;
}


/*
 * -- delay_batch
 *
 * When replaying a trace, we may want to process it as fast
 * as the live packet stream would have been. If this is the,
 * case, we have to delay batches that arrive too early.
 * If TS_AWARE_TRACE_REPLAY is not defined below, this
 * function is replaced by a macro that does nothing.
 * This feature is disabled by default.
 */
/* #define TS_AWARE_TRACE_REPLAY */
#ifndef TS_AWARE_TRACE_REPLAY
#define delay_batch(x)
#else
static void
delay_batch(batch_t *batch)
{
    static timestamp_t delay_vs_trace_ts = 0; /* delay at 1st batch */
    timestamp_t now, current_delay;
    struct timeval tv;
    int ret;

    if (gettimeofday(&tv, NULL) != 0)
        error("gettimeofday() fails\n");

    now = TIME2TS(tv.tv_sec, tv.tv_usec);
    current_delay = now - batch->last_pkt_ts;

    if (delay_vs_trace_ts == 0) { /* initialize at 1st batch */
        if (now < batch->last_pkt_ts)
            error("replaying a trace in the future?\n");
        delay_vs_trace_ts = current_delay;
        debug("trace delay = %d.%06d seconds\n", TS2SEC(delay_vs_trace_ts),
                TS2USEC(delay_vs_trace_ts));
        warn("simulating real batch arrival rate\n");
    }

    if (current_delay < delay_vs_trace_ts) {
        /* this batch has come too early. sleep for some time
         * to simulate the real batch arrival rate.
         */
        timestamp_t sleep_time = delay_vs_trace_ts - current_delay;
        struct timespec tspec, rem;

        tspec.tv_sec = TS2SEC(sleep_time);
        tspec.tv_nsec = TS2USEC(sleep_time) * 1000;

    back_to_sleep:
        #ifdef LOADSHED
        ls_select_start(&como_ca);
        #endif
        ret = nanosleep(&tspec, &rem);
        #ifdef LOADSHED
        ls_select_end(&como_ca);
        #endif
        if (ret == -1) {
            tspec.tv_sec = rem.tv_sec;
            tspec.tv_nsec = rem.tv_nsec;
            warn("nanosleep interrupted!!\n");
            goto back_to_sleep; /* nanosleep interrupted, sleep more */
        }
    }
}
#endif

/*
 * -- capture_main
 *
 * This is the CAPTURE mainloop. It opens all the sniffer devices.
 * Then the real mainloop starts and it sits on a select()
 * waiting for messages from EXPORT, the SUPERVISOR or (once 
 * all modules are loaded) for packets from the sniffers.
 *
 */
void
capture_main(ipc_peer_t * parent, memmap_t * shmemmap, UNUSED FILE* f,
        como_node_t * node)
{
    como_ca_t como_ca;
    struct timeval timeout = { 0, 0 };
    fd_set ipc_fds;
    int force_batch = 0;
    size_t sum_max_pkts = 0; /* sum of max pkts across initialized sniffers */
    int avg_batch_len = 0;
    int wait_for_clients = 0;
    int supervisor_fd;
    int max_sniffer_id;
    sniffer_t *sniff;
    sniffer_list_t *sniffers;

    log_set_program("CA");

    supervisor_fd = ipc_peer_get_fd(parent);
    
    memset(&como_ca, 0, sizeof(como_ca_t));
    s_como_ca = &como_ca; /* used only by cleanup */
    
    como_ca.shmemmap = shmemmap;
    como_ca.mdls = array_new(sizeof(mdl_t *));
    memmap_alc_init(shmemmap, &como_ca.shalc);
    
    /* register handlers for signals */

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, sighdlr_exit);
    signal(SIGTERM, sighdlr_exit);
    signal(SIGHUP, SIG_IGN);
    atexit(cleanup);

    /* listen for IPC messages */
    ipc_set_user_data(&como_ca);
    como_ca.accept_fd = ipc_listen();

    /* wait for the debugger to attach */
    DEBUGGER_WAIT_ATTACH("ca");
    
    /* register handlers for IPC messages */
    ipc_register(SU_CA_ADD_MODULE, (ipc_handler_fn) handle_su_ca_add_module);
    ipc_register(SU_CA_DEL_MODULE, (ipc_handler_fn)handle_su_ca_ipc_module_del);
    ipc_register(SU_CA_START, (ipc_handler_fn) handle_su_ca_start);
    ipc_register(SU_ANY_EXIT, (ipc_handler_fn) handle_su_any_exit);
    ipc_register(CCA_OPEN, (ipc_handler_fn) ca_ipc_cca_open);
    ipc_register(CCA_ACK_BATCH, (ipc_handler_fn) ca_ipc_cca_ack_batch);
    ipc_register(EX_CA_ATTACH_MODULE, (ipc_handler_fn) handle_ex_ca_attach_module);
    ipc_register(EX_CA_TUPLES_PROCESSED, (ipc_handler_fn) handle_ex_ca_tuples_processed);
    /* ipc_register(IPC_FREEZE, ca_ipc_freeze); */

    /* alias to the sniffer list */
    sniffers = como_ca.sniffers = &node->sniffers;

    /* start all the sniffers */
    max_sniffer_id = 0;
    sniffer_list_foreach(sniff, sniffers) {
	/* initialize private state */
	sniff->priv = como_new0(sniffer_priv_t);
	sniff->priv->state = SNIFFER_UNINITIALIZED;
    	sniff->priv->fd = -1;

	/* create the ppbuf */
	sniff->ppbuf = ppbuf_new(sniff->max_pkts, sniff);

	if (sniff->cb->start(sniff) < 0) {
	    sniff->priv->state = SNIFFER_INACTIVE;

	    warn("error while starting sniffer %s (%s): %s\n",
		 sniff->cb->name, sniff->device, strerror(errno));
	    continue;
	}

        sniff->first_access = time(NULL);
	sniff->priv->state = SNIFFER_ACTIVE;

        msg("sniffer %s (%s) started\n", sniff->cb->name, sniff->device);

	sum_max_pkts += sniff->max_pkts;
        max_sniffer_id = MAX(max_sniffer_id, sniff->priv->id);

    }

    como_ca.first_ref_pkts = safe_calloc(sizeof(void *),
            (max_sniffer_id + 1));

    /* initialize the capture buffer */
    cabuf_init(&como_ca, sum_max_pkts);
    
    /* notify SUPERVISOR that all the sniffers are ready */
    ipc_send(parent, CA_SU_SNIFFERS_INITIALIZED, NULL, 0);

    /* touches all the sniffers */
    sniffer_list_foreach(sniff, sniffers) {
	if (sniff->priv->state == SNIFFER_ACTIVE)
            sniff->priv->touched = TRUE;
    }

    /* initialize select()able file descriptors */
    como_ca.el = event_loop_new();
    FD_ZERO(&ipc_fds);

    /* ensure we handle messages from SUPERVISOR */
    event_loop_add(como_ca.el, supervisor_fd);
    FD_SET(supervisor_fd, &ipc_fds);

    /* accept connections from EXPORT process(es) and CAPTURE CLIENTS */
    event_loop_add(como_ca.el, como_ca.accept_fd);

    /* initialize the timers */
    ca_init_timers();


#ifdef LOADSHED
    /* initialize load shedding data */
    ls_init_ca(&como_ca);
#endif

    /*
     * This is the actual main loop where we monitor the various
     * sniffers and the sockets to communicate with other processes.
     * If a sniffer's data stream is complete or fails, we close it.
     * The loop terminates when all sniffers are closed and there is
     * no pending communication with export.
     */

    for (;;) {
	fd_set r;
	int n_ready, max_fd;

	batch_t *batch;
	int active_sniff;
	int i;
	int touched;

        capture_profiler_notify(CP_START_SNIFFERS);

	profiler_start_tsctimer(como_stats->ca_full_timer);

	/* add sniffers to the select structure as is necessary */

	active_sniff = setup_sniffers(&timeout, sniffers, &como_ca);

        if (active_sniff < 0) { /* all sniffers done */
            int idx;

            for (idx = 0; idx < como_ca.mdls->len; idx++) {
                mdl_t *mdl = array_at(como_ca.mdls, mdl_t *, idx);
                mdl_icapture_t *ic = mdl_get_icapture(mdl);
                ipc_send(ic->export, CA_EX_DONE, NULL, 0);
            }
        }

        capture_profiler_notify(CP_END_SNIFFERS);
        capture_profiler_notify(CP_START_SELECT);

	/* wait for messages, sniffers or up to the polling interval */
	if (active_sniff > 0)
	    event_loop_set_timeout(como_ca.el, &timeout);

#ifdef LOADSHED
        ls_select_start(&como_ca);
#endif
	n_ready = event_loop_select(como_ca.el, &r, &max_fd);
#ifdef LOADSHED
        ls_select_end(&como_ca);
#endif
        capture_profiler_notify(CP_END_SELECT);

	if (n_ready < 0)
	    continue;

	/* process any IPC messages that have turned up */

	profiler_start_tsctimer(como_stats->ca_loop_timer);

	for (i = 0; n_ready > 0 && i < max_fd; i++) {

	    if (!FD_ISSET(i, &r))
		continue;

	    if (i == como_ca.accept_fd) {
		int x = accept(como_ca.accept_fd, NULL, NULL);
		if (x < 0) {
		    warn("Failed on accept(): %s\n", strerror(errno));
		} else {
 		    event_loop_add(como_ca.el, x);
		    FD_SET(x, &ipc_fds);
		}

		n_ready--;
	    }

	    if (FD_ISSET(i, &ipc_fds)) {
		int ipcr = ipc_handle(i);
		if (ipcr != IPC_OK) {
		    if (FD_ISSET(i, &s_cabuf.clients_fds)) {
			/* handle capture client gone */
			cabuf_cl_handle_gone(i, &como_ca);
			FD_CLR(i, &ipc_fds);
		    } else {
			/* an error. close the socket */
			warn("error on IPC handle from %d (%d)\n",
			     i, ipcr);
			exit(EXIT_FAILURE);
		    }
		}

		n_ready--;
	    }
	}

        if (como_ca.ready != TRUE)
            continue; /* don't go any further until ready */

	/* check resources usage occupied by capture clients */
	if (s_cabuf.clients_count > 0) {
	    wait_for_clients = cabuf_cl_res_mgmt(wait_for_clients,
						 avg_batch_len,
						 sniffers,
						 como_ca.sniffers_count);
	    if (wait_for_clients)
		continue; /* skip capturing more packets */
	}

	/*
	 * check sniffers for packet reception (both the ones that use 
	 * select() and the ones that don't)
	 */
        capture_profiler_notify(CP_START_SNIFFERS);
	sniffer_list_foreach(sniff, sniffers) {
	    pkt_t *first_ref_pkt = NULL;

	    int res;
	    int max_no;		/* max number of packets to capture */
	    int drops = 0;

	    if (sniff->priv->state == SNIFFER_FROZEN)
		continue;	/* frozen devices */

            if (sniff->priv->state != SNIFFER_ACTIVE)
                continue;       /* skip inactive sniffers */

	    if ((sniff->flags & SNIFF_SELECT) && !FD_ISSET(sniff->fd, &r))
		continue;	/* nothing to read here. */

	    if (sniff->ppbuf->count == sniff->ppbuf->size)
		continue;	/* the ppbuf is full */

            #if 0
	    if (s_cabuf.clients_count > 0) {
		batch_t *b;
		b = TQ_HEAD(&s_cabuf.batches);
		while (b != NULL) {
		    if (b->first_ref_pkts[sniff->priv->id] != NULL) {
			first_ref_pkt = b->first_ref_pkts[sniff->priv->id];
			break;
		    }
		    b = b->next;
		}
	    }
            #endif

            first_ref_pkt = como_ca.first_ref_pkts[sniff->priv->id];

	    /* initialize the ppbuf for capture mode */

	    max_no = ppbuf_begin(sniff->ppbuf);
	    assert(max_no > 0);

	    /* capture more packets */

	    profiler_start_tsctimer(como_stats->ca_sniff_timer);
	    res = sniff->cb->next(sniff, max_no, como_ca.min_flush_ivl,
				  first_ref_pkt, &drops);
	    profiler_end_tsctimer(como_stats->ca_sniff_timer);

	    /* tell the ppbuf we're done with capture */

	    ppbuf_end(sniff->ppbuf);

            /*
             * update the first ref pkt if still null. this ensures
             * that, after sniffers have returned at least one packet,
             * this pointer is meaningful. batch_create is in charge
             * of further updates.
             */
            if (como_ca.first_ref_pkts[sniff->priv->id] == NULL && 
                                    ppbuf_get_count(sniff->ppbuf) > 0)
                como_ca.first_ref_pkts[sniff->priv->id] =
                    ppbuf_get(sniff->ppbuf);

	    /* disable the sniffer if a problem occurs */

            if (res < 0) /* something went wrong, sniffer is to be closed */
                sniff->priv->closing = 1;
	    
	    /* monitor the current sniffer fd */
	    if (sniff->priv->fd != sniff->fd) {
		sniff->priv->touched = TRUE;
		touched++;
	    }

	    /* update drop statistics */

	    como_stats->drops += drops;
	    sniff->priv->stats.tot_dropped_pkts += drops;

	    debug("received %d packets from sniffer %s\n",
		  sniff->ppbuf->captured,
		  sniff->cb->name);

            /* inform user of progress when reading from a trace */
            if ((sniff->flags & SNIFF_FILE) && sniff->filesize != 0 &&
                                        sniff->last_report + 30 < time(NULL)) {
                time_t ts = time(NULL);
                time_t elapsed = ts - sniff->first_access;
                double completed =  (double) sniff->curr_pos /
                    (double) sniff->filesize;
                int etc = completed == 0 ? 0 : elapsed / completed - elapsed;

                if (etc != 0 && sniff->last_report != 0)
                    msg("sniffer %s(%s): progress %.2f%%, ETC %dm%02ds\n",
                            sniff->cb->name, sniff->device, completed * 100,
                            etc / 60, etc % 60);

                sniff->last_report = ts;
            }
	}
        capture_profiler_notify(CP_END_SNIFFERS);

	/*
         * try to create a batch using the captured packets
         */
        capture_profiler_notify(CP_START_BATCH_CREATE);
        batch = batch_create(force_batch, &como_ca);
        capture_profiler_notify(CP_END_BATCH_CREATE);

        if (batch != NULL) {
            delay_batch(batch); /* only delayed if necessary */

            capture_profiler_notify(CP_START_PROCESS_BATCH);
	    if (avg_batch_len == 0)
		avg_batch_len = batch->count;
	    else
		avg_batch_len = (batch->count / 8) + (avg_batch_len * 7 / 8);

#if 0
	    /* export the batch to clients */
	    if (s_cabuf.clients_count > 0)
		batch_export(batch, &como_ca);
#endif

	    /* process the batch */
	    profiler_start_tsctimer(como_stats->ca_pkts_timer);
	    como_stats->ts = batch_process(batch, &como_ca);
	    profiler_end_tsctimer(como_stats->ca_pkts_timer);

	    /* update the stats */
	    como_stats->pkts += batch->count;

	    if (como_stats->ts < como_stats->first_ts)
		como_stats->first_ts = como_stats->ts;

	    if (batch->ref_mask != 1)
		batch->ref_mask &= ~1LL;
	    else
		batch_free(batch);

            capture_profiler_notify(CP_END_PROCESS_BATCH);
	}

	sniffer_list_foreach(sniff, sniffers) {
            if (! sniff->priv->closing)
                continue;

            sniff->cb->stop(sniff);
            debug("stopping sniffer `%s': res < 0\n", sniff->cb->name);
            ppbuf_free(sniff);
            /* disable the sniffer */
            sniff->priv->state = SNIFFER_INACTIVE;
            sniff->priv->touched = TRUE;
            sniff->priv->closing = 0;
        }

	/* 
         * Check shared mem usage. If above FREEZE_THRESHOLD, and export
         * has work to do, freeze sniffers that read from files. If below
         * THAW_THRESHOLD, or export has no work left (therefore it cannot
         * free any memory) then thaw any frozen sniffer.
	 */
	if (como_stats->table_queue == 0 || memmap_usage(shmemmap) <
                THAW_THRESHOLD(como_config->shmem_size)) {
	    /* 
             * either memory is below threshold or export cannot free more mem.
             * unfreeze any source.
	     */
            sniffer_list_foreach(sniff, sniffers) {
		if (sniff->priv->state == SNIFFER_FROZEN) {
		    sniff->priv->state = SNIFFER_ACTIVE;
                    sniff->priv->touched = TRUE;
		    warn("unfreezing sniffer %s on %s\n", sniff->cb->name,
                            sniff->device);
		}
	    }
	} else if (memmap_usage(shmemmap) >
                        FREEZE_THRESHOLD(como_config->shmem_size)) {
            /*
             * too much mem being used, freeze sniffer running from files.
             */
            sniffer_list_foreach(sniff, sniffers) {
		if (sniff->priv->state == SNIFFER_INACTIVE)
		    continue;
            
                if (sniff->priv->state == SNIFFER_FROZEN)
                    continue;

		if (sniff->flags & SNIFF_FILE) {
		    sniff->priv->state = SNIFFER_FROZEN;
                    sniff->priv->touched = TRUE;
		    warn("high mem usage. Freezing sniffer %s on %s\n",
                            sniff->cb->name, sniff->device);
		}
            }
	}
	profiler_end_tsctimer(como_stats->ca_loop_timer);
	profiler_end_tsctimer(como_stats->ca_full_timer);
    }
}

/* end of file */
