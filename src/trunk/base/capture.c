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
#include <fcntl.h>		/* F_GETFL */
#include <unistd.h>		/* read, write etc. */
#include <string.h>		/* bzero */
#include <errno.h>		/* errno */
#include <signal.h>
#include <assert.h>

#define CAPTURE_SOURCE

#include "como.h"
#include "comopriv.h"
#include "sniffers.h"
#include "ipc.h"

#include "ppbuf.c"

/* poll time (in usec) */
#define POLL_WAIT   1000

/* flush and freeze/unfreeze thresholds */
#define MB(m)				((m)*1024*1024)
#define FREEZE_THRESHOLD(mem)		(MB(mem)*3/4)
#define THAW_THRESHOLD(mem)		(MB(mem)*1/8)

/* global state */
extern struct _como map;

static fd_set s_valid_fds;
static int s_max_fd;

static int wait_for_modules = 2;

static timestamp_t s_min_flush_ivl = 0;

static int s_active_modules = 0;

#define CA_MAXCLIENTS	(64 - 1)	/* 1 is CAPTURE itself */

typedef struct cabuf_cl {
    int fd;
    uint64_t ref_mask;
} cabuf_cl_t;

/*
 * The cabuf is a ring buffer containing pointers to captured packets.
 */
static struct {
    int tail;
    int size;
    pkt_t **pp;
    tailq_t batches;
    int clients_count;
    cabuf_cl_t *clients[CA_MAXCLIENTS];
    fd_set clients_fds;
} s_cabuf;


static inline void capture_loop_del_fd(int fd);


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
    sniff->flags |= SNIFF_INACTIVE | SNIFF_TOUCHED;
}


/*
 * -- batch_free
 *
 * release the batch data structure 
 */
static inline void
batch_free(batch_t * batch)
{
    mem_free(batch);
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
    source_t *src;

    for (src = map.sources; src; src = src->next) {
	sniffer_t *sniff = src->sniff;

	if (sniff->flags & SNIFF_INACTIVE)
	    continue;

	src->cb->stop(sniff);
	ppbuf_free(sniff);
    }
//#ifdef DEBUG
//    print_rusage(stderr, 0);
//#endif
}


/* 
 * -- create_table 
 * 
 * allocates and initializes a hash table
 */
static ctable_t *
create_table(module_t * mdl, timestamp_t ivl)
{
    ctable_t *ct;
    size_t len;

    len = sizeof(ctable_t) + mdl->ca_hashsize * sizeof(void *);
    ct = alc_malloc(&(mdl->alc), len);
    if (ct == NULL)
	return NULL;

    ct->bytes += len;

    ct->size = mdl->ca_hashsize;
    ct->first_full = ct->size;	/* all records are empty */
    ct->last_full = 0;		/* all records are empty */
    ct->records = 0;
    ct->live_buckets = 0;
    ct->flexible = 0;

    /*
     * save the timestamp indicating with flush interval this 
     * table belongs to. this information will be useful for 
     * EXPORT when it processes the flushed tables. 
     */
    ct->ivl = ivl;
    return ct;
}


/*
 * -- flush_state
 *
 * Called by capture_pkt() process when a timeslot is complete.
 * it flushes the flow table (if it exists and it is non-empty)
 * and all memory state of the module. The state is queued in the 
 * em_tables list to be sent to EXPORT later.
 * 
 * XXX we send both the pointer to the module state and the 
 *     capture table. this is going to change in the near future 
 *     when the hash table will be managed from inside the modules.
 *
 */
static void
flush_state(module_t * mdl, tailq_t * em_tables)
{
    ctable_t *ct;
    expiredmap_t *em;

    /* check if the table is there and if it is non-empty */
    ct = mdl->ca_hashtable;
    assert(ct != NULL);
    assert(ct->records > 0 || ct->flexible == 1);

    logmsg(V_LOGCAPTURE,
	   "flush_tables %p(%s) buckets %d records %d live %d\n"
	   "ivl %llu ts %llu\n",
	   ct, mdl->name, ct->size, ct->records, ct->live_buckets,
	   ct->ivl, ct->ts);

    /* update the hash table size for next time if it is underutilized 
     * or overfull. 
     */
#ifdef ADAPTIVE_HASH_TABLES
    if (ct->records > ct->size) {
	/* hashtable underprovisioned, try resize it */
	mdl->ca_hashsize <<= 2;
	logmsg(LOGCAPTURE,
	       "table '%s' overfull (%d vs %d) -- %d live : new size %d\n",
	       mdl->name, ct->records, ct->size,
	       ct->live_buckets, mdl->ca_hashsize);
    } else if (ct->records < ct->size >> 5) {
	/* the hashtable is overprovisioned. try resize it */
	mdl->ca_hashsize >>= 2;
	logmsg(LOGCAPTURE,
	       "table '%s' underused (%d vs %d) -- %d live : new size %d\n",
	       mdl->name, ct->records, ct->size,
	       ct->live_buckets, mdl->ca_hashsize);
    }
#endif

    em = alc_malloc(&(mdl->alc), sizeof(expiredmap_t));
    em->next = NULL;
    em->ct = ct;
    em->mdl = mdl;
    em->fstate = mdl->fstate;
    em->shared_map = mdl->shared_map;

    TQ_APPEND(em_tables, em, next);
    map.stats->table_queue++;

    /* reset the state of the module */
    mdl->ca_hashtable = NULL;
    mdl->fstate = NULL;
    mdl->shared_map = NULL;
}


/*
 * -- capture_pkt
 *
 * This function is called for every batch of packets that need to be
 * processed by a classifier.
 * For each packet in the batch it runs the check()/hash()/match()/update()
 * methods of the classifier cl_index. The function also checks if the
 * current flow table needs to be flushed.
 *
 */
static void
capture_pkt(module_t * mdl, batch_t * batch, char *which, tailq_t * exp_tables)
{
    pkt_t *pkt, **pktptr;
    int i, c, l;
    int new_record;
    int record_size;		/* effective record size */

    record_size = mdl->callbacks.ca_recordsize + sizeof(rec_t);

    c = 0;
    pktptr = batch->pkts0;
    l = MIN(batch->pkts0_len, batch->count);
    do {

	for (i = 0; i < l; i++, pktptr++, which++, c++) {
	    rec_t *prev, *cand;
	    uint32_t hash;
	    uint bucket;

	    pkt = *pktptr;

	    /* flush the current flow table, if needed */
	    if (mdl->ca_hashtable) {
		ctable_t *ct = mdl->ca_hashtable;

		if (pkt->ts >= ct->ivl + mdl->flush_ivl) {
		    if (ct->records || ct->flexible) {
			/*
			 * even if the table doesn't contain any record, if
			 * the flexible flag is set it will be flushed to
			 * guarantee that export can call store_records for
			 * the previously seen tables belonging to the same
			 * interval.
			 */
			ct->ts = ct->ivl + mdl->flush_ivl;
			flush_state(mdl, exp_tables);
		    } else {
			/* 
			 * the table that would have been flushed if it
			 * contained some record must be updated to refer to
			 * the right ivl value.
			 */
			ct->ivl = pkt->ts - (pkt->ts % mdl->flush_ivl);
		    }
		}
	    }
	    if (!mdl->ca_hashtable) {
		timestamp_t ivl;
		ivl = pkt->ts - (pkt->ts % mdl->flush_ivl);
		mdl->shared_map = memmap_new(allocator_shared(), 64,
					     POLICY_HOLD_IN_USE_BLOCKS);
		mdl->ca_hashtable = create_table(mdl, ivl);
		if (!mdl->ca_hashtable) {
		    /* XXX no memory, we keep going. 
		     *     need better solution! */
		    logmsg(LOGWARN, "out of memory for %s, skipping pkt\n",
			   mdl->name);
		    continue;
		}
		if (mdl->callbacks.flush != NULL) {
		    mdl->fstate = mdl->callbacks.flush(mdl);
		}
	    }
	    mdl->ca_hashtable->ts = pkt->ts;

	    if (*which == 0)
		continue;	/* no interest in this packet */

	    /*
	     * check if there are any errors in the packet that
	     * make it unacceptable for the classifier.
	     * (if check() is not provided, we take the packet anyway)
	     */
	    if (mdl->callbacks.check && !mdl->callbacks.check(mdl, pkt))
		continue;

	    /*
	     * find the entry where the information related to
	     * this packet reside
	     * (if hash() is not provided, it defaults to 0)
	     */
	    hash = (mdl->callbacks.hash) ? mdl->callbacks.hash(mdl, pkt) : 0;
	    bucket = hash % mdl->ca_hashtable->size;

	    /*
	     * keep track of the first entry in the table that is used.
	     * this is useful for the EXPORT process that will have to
	     * scan the entire hash table later.
	     */
	    if (bucket < mdl->ca_hashtable->first_full)
		mdl->ca_hashtable->first_full = bucket;
	    if (bucket > mdl->ca_hashtable->last_full)
		mdl->ca_hashtable->last_full = bucket;

	    prev = NULL;
	    cand = mdl->ca_hashtable->bucket[bucket];
	    while (cand) {
		/* if match() is not provided, any record matches */
		if (mdl->callbacks.match == NULL ||
		    mdl->callbacks.match(mdl, pkt, cand))
		    break;
		prev = cand;
		cand = cand->next;
	    }

	    if (cand != NULL) {
		/*
		 * found!
		 * two things to do first:
		 *   i) move this record to the front of the bucket to
		 *      speed up future (and likely) accesses.
		 *  ii) check if this record was flagged as full and
		 *      in that case create a new one;
		 */

		/* move to the front, if needed */
		if (mdl->ca_hashtable->bucket[bucket] != cand) {
		    prev->next = cand->next;
		    cand->next = mdl->ca_hashtable->bucket[bucket];
		    mdl->ca_hashtable->bucket[bucket] = cand;
		}

		/* check if this record was flagged as full */
		if (cand->full) {
		    rec_t *x;

		    /* allocate a new record */
		    x = alc_malloc(&(mdl->alc), record_size);
		    if (x == NULL)
			continue;	/* XXX no memory, we keep going. 
					 *     need better solution! */

		    mdl->ca_hashtable->bytes += record_size;

		    x->hash = hash;
		    x->next = cand->next;

		    /* link the current full one to the list of full records */
		    x->prev = cand;
		    cand->next = x;

		    /* we moved cand to the front, now is x */
		    mdl->ca_hashtable->bucket[bucket] = x;

		    /* done. new empty record ready. */
		    /* 
		     * NOTE: we do not increment mdl->ca_hashtable->records
		     * here because we count this just as a variable size
		     * record.
		     */

		    new_record = 1;
		    mdl->ca_hashtable->filled_records++;
		    cand = x;
		} else {
		    new_record = 0;
		}
	    } else {
		/*
		 * not found!
		 * create a new record, update table stats
		 * and link it to the bucket.
		 */
		cand = alc_malloc(&(mdl->alc), record_size);
		if (cand == NULL)
		    continue;
		mdl->ca_hashtable->bytes += record_size;

		cand->hash = hash;
		cand->next = mdl->ca_hashtable->bucket[bucket];

		mdl->ca_hashtable->records++;
		mdl->ca_hashtable->bucket[bucket] = cand;
		if (cand->next == NULL)
		    mdl->ca_hashtable->live_buckets++;

		new_record = 1;
	    }
	    start_tsctimer(map.stats->ca_updatecb_timer);
	    cand->full = mdl->callbacks.update(mdl, pkt, cand, new_record);
	    end_tsctimer(map.stats->ca_updatecb_timer);
	}
	pktptr = batch->pkts1;
	l = batch->pkts1_len;
    } while (c < batch->count);
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
batch_filter(batch_t * batch)
{
    static char *which;
    static int size;
    int i, c, l;
    char *out;
    int idx;
    int first_done = 0;
    static uint64_t ld_bytes;	/* bytes seen in one minute */
    static timestamp_t ld_ts;	/* end of load meas interval */
    static uint32_t ld_idx;	/* index of load meas interval */

    if (ld_ts == 0) {
	ld_ts = (*batch->pkts0)->ts + TIME2TS(60, 0);
    }

    i = batch->count * s_active_modules;	/* size of the output bitmap */

    if (which == NULL) {
	size = i;
	which = safe_malloc(i);
    } else if (size < i) {
	size = i;
	which = safe_realloc(which, i);
    }

    bzero(which, i);

    out = which;

    for (idx = 0; idx <= map.module_last; idx++) {
	module_t *mdl = &map.modules[idx];
	pkt_t *pkt, **pktptr;

	if (mdl->status != MDL_ACTIVE) {
	    continue;
	}

	c = 0;
	pktptr = batch->pkts0;
	l = MIN(batch->pkts0_len, batch->count);
	do {
	    for (i = 0; i < l; i++, pktptr++, out++, c++) {
		pkt = *pktptr;

		*out = evaluate(mdl->filter_tree, pkt);
		if (first_done == 0) {
		    if (COMO(ts) < ld_ts) {
			ld_bytes += (uint64_t) COMO(len);
		    } else {
			map.stats->load_15m[ld_idx % 15] = ld_bytes;
			map.stats->load_1h[ld_idx % 60] = ld_bytes;
			map.stats->load_6h[ld_idx % 360] = ld_bytes;
			map.stats->load_1d[ld_idx] = ld_bytes;
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
 * -- batch_process 
 * 
 * take a batch of packets, run them thru the batch_filter and 
 * then call the capture_pkt function for each individual 
 * module. return the last timestamp of the batch.
 * 
 */
static timestamp_t
batch_process(batch_t * batch)
{
    char *which;
    int idx;
    tailq_t exp_tables = { NULL, NULL };
    expiredmap_t *first_exp_table;

    /*
     * Select which classifiers need to see which packets The batch_filter()
     * function (see comments in file base/template) returns a
     * bidimensional array of integer which[cls][pkt] where the first
     * index indicates the classifier, the second indicates the packet
     * in the batch.  The element of the array is set if the packet is
     * of interest for the given classifier, and it is 0 otherwise.
     */
    logmsg(V_LOGCAPTURE,
	   "calling batch_filter with pkts %p, count %d\n",
	   *batch->pkts0, batch->count);
    start_tsctimer(map.stats->ca_filter_timer);
    which = batch_filter(batch);
    end_tsctimer(map.stats->ca_filter_timer);

    /*
     * Now browse through the classifiers and perform the capture
     * actions needed.
     *
     * XXX we do it this way just because anyway we have got a
     * single-threaded process.  will have to change it in the
     * future...
     *
     */
    for (idx = 0; idx <= map.module_last; idx++) {
	module_t *mdl = &map.modules[idx];

	if (mdl->status != MDL_ACTIVE)
	    continue;

	assert(mdl->name != NULL);
	logmsg(V_LOGCAPTURE,
	       "sending %d packets to module %s for processing\n",
	       batch->count, map.modules[idx].name);

	start_tsctimer(map.stats->ca_module_timer);
	capture_pkt(mdl, batch, which, &exp_tables);
	end_tsctimer(map.stats->ca_module_timer);
	which += batch->count;	/* next module, new list of packets */
    }

    if (memory_usage() >= FREEZE_THRESHOLD(map.mem_size)) {
	for (idx = 0; idx <= map.module_last; idx++) {
	    module_t *mdl = &map.modules[idx];
	    timestamp_t ivl;

	    if (mdl->status != MDL_ACTIVE) {
		continue;
	    }

	    if (mdl->callbacks.capabilities.has_flexible_flush == 0
		|| mdl->ca_hashtable == NULL
		|| mdl->ca_hashtable->records == 0) {
		continue;
	    }

	    ivl = mdl->ca_hashtable->ivl;
	    flush_state(mdl, &exp_tables);
	    logmsg(LOGCAPTURE, "flexible flush for %s occurred\n", mdl->name);

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
	}
    }

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
static void
ca_ipc_module_add(procname_t sender, __unused int fd, void *pack, size_t sz)
{
    module_t tmp;
    module_t *mdl;

    /* only the parent process should send this message */
    assert(sender == map.parent);

    /* unpack the received module info */
    if (unpack_module(pack, sz, &tmp)) {
	logmsg(LOGWARN, "error when unpack module in IPC_MODULE_ADD\n");
	return;
    }

    /* find an empty slot in the modules array */
    mdl = copy_module(&map, &tmp, tmp.node, tmp.index, NULL);

    /* free memory from the tmp module */
    clean_module(&tmp);

    if (activate_module(mdl, map.libdir)) {
	logmsg(LOGWARN, "error when activating module %s\n", mdl->name);
	return;
    }

    /*
     * browse the list of sniffers to make sure that this module
     * understands the incoming packets. compare the indesc defined 
     * in the module callbacks data structure with the output descriptor 
     * defined in the source. if there is a mismatch, the module is 
     * marked as incompatible and will not receive packets. 
     */
    /* NOTE: Blindly assume the module can get any kind of pkts */
    if (mdl->indesc) {
	source_t *src;
	char *desc_flt;

	for (src = map.sources; src != NULL; src = src->next) {
	    metadesc_match_t bm;
	    metadesc_incompatibility_t *incomps = NULL;
	    int incomps_count;
	    if (!src->outdesc) {
		logmsg(LOGWARN, "sniffer %s does not provide outdesc\n",
		       src->cb->name);
		continue;
	    }
	    if (!metadesc_best_match(src->outdesc, mdl->indesc, &bm,
				     &incomps, &incomps_count)) {
		int i;
		logmsg(LOGWARN, "module %s does not get %s packets:\n",
		       mdl->name, src->cb->name);
		for (i = 0; i < incomps_count; i++) {
		    logmsg(LOGWARN, "%s\n",
			   metadesc_incompatibility_reason(&incomps[i]));
		}
		free(incomps);
		mdl->status = MDL_INCOMPATIBLE;
		map.stats->modules_active--;
		return;
	    }
	}

	desc_flt = metadesc_determine_filter(mdl->indesc);
	if (desc_flt) {
	    if (strcmp(mdl->filter_str, "all") == 0) {
		mdl->filter_str = desc_flt;	/* CHECKME: leak? */
	    } else {
		char *flt;
		asprintf(&flt, "%s and (%s)", desc_flt, mdl->filter_str);
		free(mdl->filter_str);
		mdl->filter_str = flt;
	    }
	}

	/* CHECKME: probably the indesc should not be freed here! */
	/*
	   metadesc_list_free(mdl->indesc);
	   mdl->indesc = NULL;
	 */
    }

    /* Default values for filter stuff */
    mdl->filter_tree = NULL;

    logmsg(LOGCAPTURE, "module %s activated with filter %s\n",
	   mdl->name, mdl->filter_str);

    /* Parse the filter string from the configuration file */
    parse_filter(mdl->filter_str, &(mdl->filter_tree), NULL);

    if (s_min_flush_ivl == 0 || s_min_flush_ivl > mdl->flush_ivl) {
	s_min_flush_ivl = mdl->flush_ivl;
    }

    s_active_modules++;
}


/* 
 * -- ca_ipc_module_del 
 * 
 * this function removes a module from the current map. 
 * the index of the module is contained in the message. 
 * 
 */
static void
ca_ipc_module_del(procname_t sender, __unused int fd, void *buf,
		  __unused size_t len)
{
    module_t *mdl;
    int idx;

    /* TODO: send flush state */

    /* only the parent process should send this message */
    assert(sender == map.parent);

    idx = *(int *) buf;
    mdl = &map.modules[idx];

    if (mdl->status == MDL_ACTIVE) {
	s_active_modules--;
    }

    remove_module(&map, mdl);
}


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
ca_ipc_freeze(procname_t sender, __unused int fd, __unused void *buf,
	      __unused size_t len)
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
ca_ipc_flush(procname_t sender, __unused int fd, void *buf, size_t len)
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

	map.stats->table_queue--;

	/* NOTE: *em was allocated inside em->shared_map so memmap_destroy
	 * will deallocate that too. That's why we use em_next.
	 */
	em = em_next;
    }
}

/* 
 * -- ca_ipc_start
 * 
 * handle IPC_MODULE_START message sent by SUPERVISOR to indicate when 
 * it is possible to start processing traces. 
 * 
 */
static void
ca_ipc_start(procname_t sender, __unused int fd, void *buf,
	     __unused size_t len)
{
    /* only SUPERVISOR or EXPORT should send this message */
    assert(sender == map.parent || sender == sibling(EXPORT));

    if (sender == map.parent)
	map.stats = *((void **) buf);

    wait_for_modules--;

    if (wait_for_modules == 0) {
	source_t *src;

	for (src = map.sources; src; src = src->next) {
	    src->sniff->flags |= SNIFF_TOUCHED;
	}

	if (s_min_flush_ivl == 0) {
	    s_min_flush_ivl = TIME2TS(1, 0);
	}

	logmsg(LOGCAPTURE, "sniffers enabled\n");
    }
}


/* 
 * -- ca_ipc_exit
 * 
 * terminate this processing cleaning up the sniffers. 
 * 
 */
static void
ca_ipc_exit(procname_t sender, __unused int fd, __unused void *buf,
	    __unused size_t len)
{
    assert(sender == map.parent);
    ipc_finish();
    exit(EXIT_SUCCESS);
}


/**
 * -- cabuf_cl_destroy
 * 
 * Actually performs client state destruction.
 */
static void
cabuf_cl_destroy(int id, cabuf_cl_t * cl)
{
    batch_t *bi, *bn;

    /* update s_capbuf */
    s_cabuf.clients[id] = NULL;
    s_cabuf.clients_count--;
    capture_loop_del_fd(cl->fd);
    FD_CLR(cl->fd, &s_cabuf.clients_fds);

    close(cl->fd);

    bi = TQ_HEAD(&s_cabuf.batches);
    while (bi) {
	bn = bi->next;
	bi->ref_mask &= ~cl->ref_mask;
	if (bi->ref_mask == 0) {
	    TQ_POP(&s_cabuf.batches, bi, next);
	    map.stats->batch_queue--;
	    batch_free(bi);
	}
	bi = bn;
    }

    free(cl);

    map.stats->ca_clients = s_cabuf.clients_count;
}


/**
 * -- cabuf_cl_handle_failure
 * 
 * Handles a client failure by logging a message and destroying its state.
 */
static void
cabuf_cl_handle_failure(int id, cabuf_cl_t * cl)
{
    logmsg(LOGWARN, "sending message to capture client (%d): %s\n",
	   id, strerror(errno));
    cabuf_cl_destroy(id, cl);
}


/**
 * -- cabuf_cl_handle_gone
 * 
 * Handles a client gone by logging a message and destroying its state.
 */
static void
cabuf_cl_handle_gone(int fd)
{
    int id;

    /* iterate over the clients */
    for (id = 0; id < s_cabuf.clients_count; id++) {
	cabuf_cl_t *cl;

	cl = s_cabuf.clients[id];
	/* skip unwanted clients */
	if (cl == NULL || cl->fd != fd)
	    continue;

	logmsg(LOGWARN, "capture client is gone (id: `%d`, fd: `%d`)\n",
	       id, fd);
	cabuf_cl_destroy(id, cl);
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
static void
ca_ipc_cca_open(__unused procname_t sender, int fd, __unused void *buf,
		__unused size_t len)
{
    ccamsg_t m;
    cabuf_cl_t *cl;
    size_t sz;
    int id;

    if (s_cabuf.clients_count == CA_MAXCLIENTS) {
	logmsg(LOGWARN, "rejecting capture-client: too many clients\n");
	ipc_send_with_fd(fd, CCA_ERROR, NULL, 0);
	close(fd);
	capture_loop_del_fd(fd);
	return;
    }

    /* look for an empty slot */
    for (id = 0; id < CA_MAXCLIENTS; id++)
	if (s_cabuf.clients[id] != NULL)
	    break;

    assert(id < CA_MAXCLIENTS);
    cl = safe_calloc(1, sizeof(cabuf_cl_t));
    cl->fd = fd;
    cl->ref_mask = (1LL << (uint64_t) (id + 1));	/* id 0 -> mask 2 */

    s_cabuf.clients[id] = cl;
    s_cabuf.clients_count++;
    FD_SET(fd, &s_cabuf.clients_fds);

    m.open_res.id = id;
    sz = sizeof(m.open_res);

    if (ipc_send_with_fd(fd, CCA_OPEN_RES, &m, sz) != IPC_OK) {
	cabuf_cl_handle_failure(id, cl);
    }

    map.stats->ca_clients = s_cabuf.clients_count;
}


/**
 * -- ca_ipc_cca_ack_batch
 * 
 * Handles a CCA_ACK_BATCH message. Updates the client state and the s_cabuf
 * state.
 */
static void
ca_ipc_cca_ack_batch(__unused procname_t sender, __unused int fd,
		     void *buf, __unused size_t len)
{
    ccamsg_t *m = (ccamsg_t *) buf;
    cabuf_cl_t *cl;
    batch_t *batch;

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

    if (batch->ref_mask == 0) {
	assert(batch == TQ_HEAD(&s_cabuf.batches));
	TQ_POP(&s_cabuf.batches, batch, next);
	map.stats->batch_queue--;
	batch_free(batch);
    }
}


/*
 * -- cabuf_init
 * 
 * initializes the cabuf kept in the static variable s_cabuf.
 * 
 */
static void
cabuf_init(size_t size)
{
    /*
     * allocate the buffer of pointers to captured packets in shared
     * memory.
     */
    s_cabuf.size = size;
    s_cabuf.pp = mem_calloc(s_cabuf.size, sizeof(pkt_t *));
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
    }
    batch->reserved = batch->count;
}


/*
 * -- batch_export
 * 
 * Exports a batch to capture clients. The batch is queued to s_cabuf.batches
 * and a CCA_NEW_BATCH is sent to all clients.
 */
static void
batch_export(batch_t * batch)
{
    int id;

    /* iterate over clients */

    for (id = 0; id < s_cabuf.clients_count; id++) {
	ccamsg_t m;
	size_t sz;

	cabuf_cl_t *cl = s_cabuf.clients[id];

	/* skip NULL clients */

	if (cl == NULL)
	    continue;

	/* prepare the message */

	m.new_batch.id = id;
	m.new_batch.batch = batch;
	sz = sizeof(m.new_batch);

	/* send the message */

	if (ipc_send_with_fd(cl->fd, CCA_NEW_BATCH, &m, sz) != IPC_OK) {
	    cabuf_cl_handle_failure(id, cl);
	    continue;
	}

	batch->ref_mask |= cl->ref_mask;
    }

    if (batch->ref_mask > 1) {
	/* append the batch to the queue of active batches */
	TQ_APPEND(&s_cabuf.batches, batch, next);
	map.stats->batch_queue++;
    }
}


static void
batch_append(batch_t * batch, ppbuf_t * ppbuf)
{
    pkt_t *pkt;

    pkt = ppbuf_get(ppbuf);
    
    if (pkt->ts < batch->last_pkt_ts) {
	logmsg(LOGCAPTURE,"dropping pkt no. %d: timestamps not increasing "
			   "(%u.%06u --> %u.%06u)\n",
			   batch->woff,
			   TS2SEC(batch->last_pkt_ts),
			   TS2USEC(batch->last_pkt_ts),
			   TS2SEC(pkt->ts),
			   TS2USEC(pkt->ts));
	/* drop */
	map.stats->drops++;
	return;
    }

    batch->count++;
    assert(batch->count <= batch->reserved);

    s_cabuf.pp[batch->woff] = pkt;
    batch->woff = (batch->woff + 1) % s_cabuf.size;

    ppbuf_next(ppbuf);
    
    batch->last_pkt_ts = pkt->ts;
}

/*
 * -- batch_create
 * 
 * creates a new batch by merging and sorting the captured packets
 *
 */
static batch_t *
batch_create(int force_batch)
{
    batch_t *batch;
    source_t *src;
    ppbuf_t *ppbuf;
    timestamp_t max_last_pkt_ts = 0;
    int pc = 0;

    /* CHECKME: value ??? */
    static const timestamp_t live_th = TIME2TS(0, 10000);

    int one_full_flag = 0;

    /*
     * count packets
     * find max(last packet timestamp)
     * determine if any sniffer has filled its buffer
     */

    for (src = map.sources; src; src = src->next) {
	if (src->sniff->flags & SNIFF_INACTIVE)
	    continue;

	ppbuf = src->sniff->ppbuf;

	pc += ppbuf->count;

	if (ppbuf->last_pkt_ts > max_last_pkt_ts)
	    max_last_pkt_ts = ppbuf->last_pkt_ts;

	if (ppbuf->count == ppbuf->size)
	    one_full_flag = 1;

	assert(ppbuf_is_ordered(ppbuf));
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

    if ((one_full_flag == 0) && !force_batch) {

	for (src = map.sources; src; src = src->next) {
	    if (src->sniff->flags & SNIFF_INACTIVE)
		continue;

	    ppbuf = src->sniff->ppbuf;

	    if (ppbuf->count == 0)
		if ((max_last_pkt_ts - ppbuf->last_pkt_ts) <= live_th)
		    return NULL;
	}
    }

    /* create the batch structure */

    batch = mem_calloc(1, sizeof(batch_t));
    cabuf_reserve(batch, pc);

    /*
     * We transfer the packets into the batch structure in time order. We
     * locate the sniffer with the earliest packet and copy it, looping
     * until either all packets are done, or we have too small a time period
     */

    while (pc) {

	/* find minimum ts */

	timestamp_t min_ts = ~0;
	ppbuf = NULL;

	for (src = map.sources; src; src = src->next) {
	    timestamp_t this_ts;
	    ppbuf_t *this_ppbuf;

	    if (src->sniff->flags & SNIFF_INACTIVE)
		continue;

	    this_ppbuf = src->sniff->ppbuf;

	    if (this_ppbuf->count == 0)
		continue;

	    this_ts = (ppbuf_get(this_ppbuf))->ts;

	    if (this_ts < min_ts) {
		min_ts = this_ts;
		ppbuf = this_ppbuf;
	    }
	}

	assert(ppbuf);

	/* update batch */
	batch_append(batch, ppbuf);
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

    batch->ref_mask = 1LL;

    return batch;
}


static inline void
capture_loop_add_fd(int fd)
{
    s_max_fd = add_fd(fd, &s_valid_fds, s_max_fd);
}

static inline void
capture_loop_del_fd(int fd)
{
    s_max_fd = del_fd(fd, &s_valid_fds, s_max_fd);
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
 */
static int
setup_sniffers(struct timeval *tout)
{
    source_t *src;
    sniffer_t *sniff;

    /* if no sniffers are marked "touched" then very easy */

    int active = 0;
    int touched = 0;

    for (src = map.sources; src; src = src->next) {
	sniff = src->sniff;

	if (sniff->flags & SNIFF_TOUCHED)
	    touched++;

	if (!(sniff->flags & SNIFF_INACTIVE))
	    active++;
    }

    if (touched == 0)
	return active;

    /* rebuild the list of file selectors and recalculate the timeout */

    tout->tv_sec = 3600;
    tout->tv_usec = 0;

    for (src = map.sources; src; src = src->next) {
	sniff = src->sniff;

	sniff->flags &= ~SNIFF_TOUCHED;

	/* 
	 * remove the file descriptor from the list independently if 
	 * it is a valid one or not. we will add it later if needed. 
	 * del_fd() deals with invalid fd. 
	 */

	capture_loop_del_fd(sniff->fd);

	/* inactive and frozen sniffers can be ignored */

	if (sniff->flags & SNIFF_INACTIVE)
	    continue;

	if (sniff->flags & SNIFF_FROZEN)
	    continue;

	/* sniffers marked complete need to be finished off ASAP */

	if (sniff->flags & SNIFF_COMPLETE) {
	    tout->tv_sec = 0;
	    tout->tv_usec = 0;
	    continue;
	}

	/* if sniffer uses polling, reduce timeout to <= polling interval */

	if (sniff->flags & SNIFF_POLL) {
	    if (sniff->polling < TIME2TS(tout->tv_sec, tout->tv_usec)) {
		tout->tv_sec = TS2SEC(sniff->polling);
		tout->tv_usec = TS2USEC(sniff->polling);
	    }
	}

	/* if sniffer uses select(), add the file descriptor to the list */

	if (sniff->flags & SNIFF_SELECT)
	    capture_loop_add_fd(sniff->fd);
    }

    /* if no sniffers now active then we log this change of state */

    if ((active == 0) && (map.runmode == RUNMODE_NORMAL)) {
	logmsg(LOGWARN, "no sniffers left. waiting for queries\n");
	print_timers();
    }

    return active;
}

/*
 * -- capture_mainloop
 *
 * This is the CAPTURE mainloop. It opens all the sniffer devices.
 * Then the real mainloop starts and it sits on a select()
 * waiting for messages from EXPORT, the SUPERVISOR or (once 
 * all modules are loaded) for packets from the sniffers.
 *
 */
void
capture_mainloop(int accept_fd, int supervisor_fd, __unused int id)
{
    struct timeval timeout = { 0, 0 };
    source_t *src;
    fd_set ipc_fds;
    int done_msg_sent = 0;
    int force_batch = 0;
    size_t sum_max_pkts = 0; /* sum of max pkts across initialized sniffers */

    /* wait for the debugger to attach */

    DEBUGGER_WAIT_ATTACH(map);

    /* register handlers for signals */

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, exit);
    signal(SIGTERM, exit);
    signal(SIGHUP, SIG_IGN);
    atexit(cleanup);

    /* register handlers for IPC messages */

    ipc_clear();
    ipc_register(IPC_MODULE_ADD, ca_ipc_module_add);
    ipc_register(IPC_MODULE_DEL, ca_ipc_module_del);
    ipc_register(IPC_MODULE_START, ca_ipc_start);
    ipc_register(IPC_FLUSH, (ipc_handler_fn) ca_ipc_flush);
    ipc_register(IPC_FREEZE, ca_ipc_freeze);
    ipc_register(IPC_EXIT, ca_ipc_exit);
    ipc_register(CCA_OPEN, ca_ipc_cca_open);
    ipc_register(CCA_ACK_BATCH, ca_ipc_cca_ack_batch);

    /* initialize select()able file descriptors */

    s_max_fd = 0;
    FD_ZERO(&s_valid_fds);
    FD_ZERO(&ipc_fds);

    /* ensure we handle messages from SUPERVISOR */

    capture_loop_add_fd(supervisor_fd);
    FD_SET(supervisor_fd, &ipc_fds);

    /* accept connections from EXPORT process(es) */

    capture_loop_add_fd(accept_fd);

    /* initialize the timers */

    init_timers();

    /* start all the sniffers */

    for (src = map.sources; src; src = src->next) {
	sniffer_t *sniff = src->sniff;

	if (src->cb->start(sniff) < 0) {
	    sniff->flags |= SNIFF_INACTIVE | SNIFF_TOUCHED;

	    logmsg(LOGWARN,
		   "error while starting sniffer %s (%s): %s\n",
		   src->cb->name, src->device, strerror(errno));
	    continue;
	}

	/* setup the sniffer metadesc */
	src->cb->setup_metadesc(sniff);

	/* create the ppbuf */
	sniff->ppbuf = ppbuf_new(src->sniff->max_pkts);

	/* ensure select structures will be set up */
	sniff->flags |= SNIFF_TOUCHED;
	
	sum_max_pkts += src->sniff->max_pkts;
    }

    /* initialize the capture buffer */
    cabuf_init(sum_max_pkts /* TODO: * service_buffering */);

    /*
     * This is the actual main loop where we monitor the various
     * sniffers and the sockets to communicate with other processes.
     * If a sniffer's data stream is complete or fails, we close it.
     * The loop terminates when all sniffers are closed and there is
     * no pending communication with export.
     */

    for (;;) {
	struct timeval t;
	fd_set r;
	int n_ready;

	batch_t *batch;
	int active_sniff;
	int i;

	start_tsctimer(map.stats->ca_full_timer);

	errno = 0;

	/* add sniffers to the select structure as is necessary */

	active_sniff = setup_sniffers(&timeout);

	/* 
	 * if no sniffers are left, flush all the tables given that
	 * no more packets will be received. 
	 */
	if ((active_sniff == 0) && (wait_for_modules == 0)) {
	    int idx;

	    tailq_t exp_tables = { NULL, NULL };

	    for (idx = 0; idx <= map.module_last; idx++) {
		module_t *mdl = &map.modules[idx];
		ctable_t *ct = mdl->ca_hashtable;

		if (ct && ct->records)
		    flush_state(mdl, &exp_tables);
	    }

	    if (TQ_HEAD(&exp_tables)) {
		expiredmap_t *x = TQ_HEAD(&exp_tables);
		if (ipc_send(sibling(EXPORT), IPC_FLUSH, &x, sizeof(x)) !=
		    IPC_OK)
		    panic("IPC_FLUSH failed!");
	    }

	    if (map.runmode == RUNMODE_INLINE && done_msg_sent == 0) {
		done_msg_sent = 1;
		/* inform export that no more message will come */
		if (ipc_send(sibling(EXPORT), IPC_DONE, NULL, 0) != IPC_OK)
		    panic("IPC_DONE failed!");
	    }
	}

	/* wait for messages, sniffers or up to the polling interval */

	r = s_valid_fds;
	t = timeout;
	n_ready = select(s_max_fd, &r, NULL, NULL, active_sniff ? &t : NULL);

	if (n_ready < 0) {
	    if (errno == EINTR)
		continue;

	    panic("select");
	}

	/* process any IPC messages that have turned up */

	start_tsctimer(map.stats->ca_loop_timer);

	for (i = 0; n_ready > 0 && i < s_max_fd; i++) {

	    if (!FD_ISSET(i, &r))
		continue;

	    if (i == accept_fd) {
		/* an EXPORT process wants to connect */
		int fd = accept(accept_fd, NULL, NULL);
		if (fd < 0)
		    panic("accepting export process");

		capture_loop_add_fd(fd);
		FD_SET(fd, &ipc_fds);

		n_ready--;
	    }

	    if (FD_ISSET(i, &ipc_fds)) {
		int ipcr = ipc_handle(i);
		if (ipcr != IPC_OK) {
		    if (FD_ISSET(i, &s_cabuf.clients_fds)) {
			/* handle capture client gone */
			cabuf_cl_handle_gone(i);
			FD_CLR(i, &ipc_fds);
		    } else {
			/* an error. close the socket */
			logmsg(LOGWARN, "error on IPC handle from %d (%d)\n",
			       i, ipcr);
			exit(EXIT_FAILURE);
		    }
		}

		n_ready--;
	    }
	}

	/* ignore the sniffers if SUPERVISOR hasn't sent start signal */

	if (wait_for_modules > 0)
	    continue;

	/*
	 * check sniffers for packet reception (both the ones that use 
	 * select() and the ones that don't)
	 */

	for (src = map.sources; src; src = src->next) {
	    sniffer_t *sniff = src->sniff;

	    int res;
	    int max_no;		/* max number of packets to capture */
	    int drops = 0;

	    if (sniff->flags & (SNIFF_INACTIVE | SNIFF_FROZEN))
		continue;	/* inactive/frozen devices */

	    if ((sniff->flags & SNIFF_SELECT) && !FD_ISSET(sniff->fd, &r))
		continue;	/* nothing to read here. */

	    if (sniff->ppbuf->count == sniff->ppbuf->size)
		continue;	/* the ppbuf is full */

	    /* initialize the ppbuf for capture mode */

	    max_no = ppbuf_begin(sniff->ppbuf);
	    assert(max_no > 0);

	    /* capture more packets */

	    start_tsctimer(map.stats->ca_sniff_timer);
	    res = src->cb->next(sniff, max_no, s_min_flush_ivl, &drops);
	    end_tsctimer(map.stats->ca_sniff_timer);

	    /* tell the ppbuf we're done with capture */

	    ppbuf_end(sniff->ppbuf);

	    /* TODO set force_batch if sniffer needs RAM ?? RNC1 21SEP06 */

	    /* disable the sniffer if a problem occurs */

	    if (res < 0) {
		src->cb->stop(src->sniff);
		/* NB: freeing ppbuf here discards some previously
		 *     OK packets. Fixing this needs a new "dying"
		 *     state to be added.  so TODO!   RNC1 21SEP06
		 */
		ppbuf_free(sniff);
		continue;
	    }

	    /* update drop statistics */

	    map.stats->drops += drops;
	    src->tot_dropped_pkts += drops;

	    logmsg(V_LOGCAPTURE, "received %d packets from sniffer %s\n",
		   sniff->ppbuf->captured, src->cb->name);
	}

	/* try to create a new batch containing all captured packets */

	batch = batch_create(force_batch);

	if (batch) {
	    /* export the batch to clients */
	    if (s_cabuf.clients_count > 0)
		batch_export(batch);

	    /* process the batch */
	    start_tsctimer(map.stats->ca_pkts_timer);
	    map.stats->ts = batch_process(batch);
	    end_tsctimer(map.stats->ca_pkts_timer);

	    /* update the stats */
	    map.stats->pkts += batch->count;

	    if (map.stats->ts < map.stats->first_ts)
		map.stats->first_ts = map.stats->ts;

	    if (batch->ref_mask != 1)
		batch->ref_mask &= ~1LL;
	    else
		batch_free(batch);
	}

	/* 
	 * we check the memory usage and stop any sniffer that is 
	 * running from file if the usage is above the FREEZE_THRESHOLD. 
	 * this will give EXPORT some time to process the tables and free
	 * memory. we resume as soon as memory usage goes below the 
	 * THAW_THRESHOLD. 
	 */

	map.stats->mem_usage_cur = memory_usage();
	map.stats->mem_usage_peak = memory_peak();

	if (map.stats->mem_usage_cur > FREEZE_THRESHOLD(map.mem_size)) {
	    for (src = map.sources; src; src = src->next) {
		sniffer_t *sniff = src->sniff;

		if (sniff->flags & SNIFF_INACTIVE)
		    continue;

		if (sniff->flags & SNIFF_FILE)
		    sniff->flags |= SNIFF_FROZEN | SNIFF_TOUCHED;
	    }
	} else if (map.stats->mem_usage_cur < THAW_THRESHOLD(map.mem_size)) {
	    /* 
	     * memory is now below threshold. unfreeze any source
	     */
	    for (src = map.sources; src; src = src->next) {
		sniffer_t *sniff = src->sniff;

		if (sniff->flags & SNIFF_FROZEN) {
		    sniff->flags &= ~SNIFF_FROZEN;
		    sniff->flags |= SNIFF_TOUCHED;
		}
	    }
	}

	end_tsctimer(map.stats->ca_loop_timer);
	end_tsctimer(map.stats->ca_full_timer);

#if 0
	XXX this part of the code does not apply to the current code
	    anymore.if (table_sent) {
	    /* store profiling information every time 
	     * tables are sent to EXPORT 
	     */
	    print_timers();
	    reset_timers();
	    table_sent = 0;
	}
#endif

    }

    logmsg(LOGWARN, "Capture: no sniffers left, terminating.\n");
}

/* end of file */
