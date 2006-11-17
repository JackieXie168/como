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

#if 0
extern struct _como map;	/* Global state structure */

int storage_fd;                 /* socket to storage 
				 * 
				 * XXX this is temporary until IPC are
				 *     used to communicate with STORAGE too
				 */

inline static void
handle_print_fail(module_t *mdl)
{
    if (errno == ENODATA) {
	panicx("module \"%s\" failed to print\n", mdl->name);
    } else {
	err(EXIT_FAILURE, "sending data to the client");
    }
}

/**
 * -- create_record
 *               
 * allocates a new record, updates the ex_array and the 
 * counters (records, live_buckets) 
 */
static rec_t *
create_record(module_t * mdl, uint32_t hash)
{
    etable_t * et = mdl->ex_hashtable; 
    earray_t * ea = mdl->ex_array; 
    rec_t * rp; 

    /* first of all check if the ex_array is large enough. 
     * reallocate it if necessary 
     */
    if (et->records >= ea->size) { 
	size_t len; 

	logmsg(V_LOGEXPORT, "need to reallocate ex_array for %s (%d -> %d)\n", 
	    mdl->name, ea->size, et->records * 2); 

	len = sizeof(earray_t) + et->records * 2 * sizeof(rec_t *);
	ea = safe_realloc(ea, len); 
	ea->size = et->records * 2; 
	mdl->ex_array = ea;
    } 

    /* allocate the new record */
    rp = safe_calloc(1, mdl->callbacks.ex_recordsize + sizeof(rec_t));
    ea->record[et->records] = rp;
    et->records++;
    if (et->bucket[hash] == NULL) 
	et->live_buckets++;

    return rp;
}


/**
 * -- export_record
 *
 * Invoked by process_tables for each individual record that
 * is received by CAPTURE. It stores persistent state in the EXPORT
 * flow table. 
 *
 * Using the hash value in the flow_hdr, this block scans the hash
 * table to determine the bucket and store the info.
 * 
 */
static int
export_record(module_t * mdl, rec_t * rp)
{
    etable_t *et; 
    rec_t *cand; 
    uint32_t hash;
    int isnew; 

    start_tsctimer(map.stats->ex_export_timer); 

    /* 
     * get the right bucket in the hash table. we do not need to 
     * compute a new hash but we use the same that was used in CAPTURE, 
     * just a different number of bit, given the new size of the table.
     */
    et = mdl->ex_hashtable;
    hash = rp->hash % et->size; 

    /* 
     * browse thru the elements in the bucket to 
     * find the right one (with ematch())
     */
    for (cand = et->bucket[hash]; cand != NULL; cand = cand->next) {
        int ret;

        /* If there's no ematch() callback, any record matches */
        if (mdl->callbacks.ematch == NULL)
            break;
        
        ret = mdl->callbacks.ematch(mdl, cand, rp);
        if (ret)
            break;
    }

    isnew = 0; 
    if (cand == NULL) {
	cand = create_record(mdl, hash);
	isnew = 1; 	/* new record */
        cand->hash = rp->hash;
    } 

    /* 
     * update the export record. 
     */
    mdl->callbacks.export(mdl, cand, rp, isnew);

    /*
     * move the record to the front of the bucket in the  
     * hash table to speed up successive accesses
     */
    if (cand->prev) 
	cand->prev->next = cand->next;
    if (cand->next)
	cand->next->prev = cand->prev;
    if (cand != et->bucket[hash])
        cand->next = et->bucket[hash];
    if (cand->next)
        cand->next->prev = cand;
    cand->prev = NULL; 
    et->bucket[hash] = cand;

    end_tsctimer(map.stats->ex_export_timer); 
    return 0;		// XXX just to have same prototype of call_store
}


/**
 * -- call_store
 * 
 * call_store() maps memory and stores the content of a record.
 * Anything >= 0 means success, <0 is failure.
 * 
 */
static int
call_store(module_t * mdl, rec_t *rp)
{
    char *dst = NULL;
    int ret, done = 0;
    
    ssize_t bsize = mdl->callbacks.st_recordsize; 

    start_tsctimer(map.stats->ex_mapping_timer); 
    
    if (map.runmode == RUNMODE_INLINE) {
	/* running inline */
	dst = alloca(bsize); /* NOTE: might be replaced with a heap allocated
				area using a static variable to keep track of
				it */
    }
    
    do {
	if (map.runmode == RUNMODE_NORMAL) { 
	    dst = csmap(mdl->file, mdl->offset, (ssize_t *) &bsize);
	    if (dst == NULL)
		panic("fail csmap for module %s", mdl->name);
	    if (bsize < (ssize_t) mdl->callbacks.st_recordsize) {
		logmsg(LOGWARN, "cannot write to disk for module %s\n",
		       mdl->name);
		logmsg(0, "   need %d bytes, got %d\n",
		       mdl->callbacks.st_recordsize, bsize);
		return -1;
	    }
	}

	/* call the store() callback */
	ret = mdl->callbacks.store(mdl, rp, dst);
	if (ret < 0) {
	    logmsg(LOGWARN, "store() of %s fails\n", mdl->name);
	    return ret;
	}
	
	if (ret <= bsize) {
	    done = 1;
	} else {
	    ret -= ACT_STORE_BATCH;
	}
	
	if (map.runmode == RUNMODE_NORMAL) { 
	    /*
	     * update the offset and commit the bytes written to 
	     * disk so far so that they are available to readers 
	     */
	    mdl->offset += ret;
	    cscommit(mdl->file, mdl->offset);
	} else {
	    char * p;
	    size_t left;
	    
	    /* now the dst pointer contains the entire output of 
	     * store. note that store could save more than one record
	     * in a single call. we pass this pointer to the load callback
	     * to get that information. 
	     */
	    p = dst;
	    left = ret;
	    while (left > 0) {
		size_t sz;
		timestamp_t ts;
		sz = mdl->callbacks.load(mdl, p, ret, &ts);
		assert(sz > 0 && ts != 0);
		
		/* print this record */
		if (module_db_record_print(mdl, p, NULL, map.inline_fd) < 0)
		    handle_print_fail(mdl);
		
		/* move to next */
		p += sz;
		left -= sz;
	    }
	}
    } while (done == 0);

    end_tsctimer(map.stats->ex_mapping_timer); 
    return ret;
}


/**
 * -- process_table
 *
 * Process a table from the expired list (ct). It will go through the buckets
 * of the table, process each single entry in a random order (i.e. the
 * way the entries were hashed into the table). The process consists
 * of writing the content of the entry to disk (via the store() callback)
 * save some information in the EXPORT table (via the ehash/ematch/eupdate 
 * callbacks). 
 *
 * On entry:
 *	mem	is the map where memory can be freed.
 *	ct	points to a list of tables to be flushed
 *
 */
static void
process_table(ctable_t * ct, module_t * mdl)
{
    int (*record_fn)(module_t *, rec_t *);
    
    /*
     * call export() if available, otherwise just store() and
     * bypass the rest of the export code (see above)
     */
    record_fn = mdl->callbacks.export? export_record : call_store;

    /*
     * scan all buckets and save the information to the output file.
     * then see what the EXPORT process has to keep about the entry.
     */
    for (; ct->first_full <= ct->last_full; ct->first_full++) {
	rec_t *rec; 

	/*
	 * Each entry in the bucket is a list of records for the same record.
	 * Remember, CAPTURE does not support variable size records, so when 
	 * a fixed record fills up, CAPTURE creates a new record and attaches 
	 * to it the full one with the most recent one at the head.
	 *
	 * We store in 'end' a pointer to the next record, and walk back to the
	 * oldest record using the 'prev' field, then store() all the 
	 * records one by one. Once done, unlink the saved records so we
	 * do not hit them again.
	 */
	rec = ct->bucket[ct->first_full];
	while (rec != NULL) {
	    rec_t *end = rec->next;	/* Mark next record to scan */

	    /* Walk back to the oldest record */
	    while (rec->prev) 
	        rec = rec->prev;

	    /*
	     * now save the entries for this flow one by one
	     */
	    while (rec != end) {
		rec_t *p;

                /* keep the next record because fh will be freed */
		p = rec->next; 

		/* store or export this record */
                record_fn(mdl, rec);

		rec = p;		/* move to the next one */
	    }

	    /* done with the entry, move to next */
	    ct->bucket[ct->first_full] = rec;
	}
    }

    /* 
     * if we have update the export table, keep track of the 
     * flush interval for which the table is up-to-date. 
     */
    if (mdl->callbacks.export) 
	mdl->ex_hashtable->ts = ct->ivl; 
}

/** 
 * -- destroy_record
 * 
 * remove the export record from the hash table and 
 * free the memory. 
 */
static void 
destroy_record(int i, module_t * mdl) 
{
    etable_t * et = mdl->ex_hashtable; 
    earray_t * ea = mdl->ex_array; 
    rec_t * rp; 

    rp = ea->record[i];

    /* unlink this record from the hash table */
    et->records--; 
    if (rp->next != NULL) 
	rp->next->prev = rp->prev; 
    if (rp->prev != NULL) {
	rp->prev->next = rp->next; 
    } else { 
	et->bucket[rp->hash % et->size] = rp->next; 
	if (rp->next == NULL) 
	    et->live_buckets--; 
    } 

    /* remove this record from the array keeping all 
     * used entries compact 
     */
    ea->record[i] = NULL;
    ea->record[i] = ea->record[ea->first_full];
    ea->record[ea->first_full] = NULL;
    ea->first_full++;
    free(rp);
}


/**
 * -- store_records
 * 
 * Sweep through the entire table and stores
 * all records that the module is willing to store at 
 * this time.
 *
 * Nothing of this is done if export is not defined, as all
 * the module does is store() directly the input from CAPTURE. 
 * 
 * Before doing that, however, it sorts the records if 
 * the module needs to do so (this is true if the compare()
 * callback is defined). 
 *
 */ 
static void
store_records(module_t * mdl, timestamp_t ivl, timestamp_t ts) 
{
    etable_t * et = mdl->ex_hashtable; 
    earray_t * ea = mdl->ex_array;
    uint32_t i, max;
    int what;

    if (mdl->callbacks.export == NULL)
	return;

    /* check the global action to be done on the 
     * export records at this time. 
     */
    what = mdl->callbacks.action(mdl, NULL, ivl, ts, 0); 
    assert( (what | ACT_MASK) == ACT_MASK );
    if (what & ACT_STOP) 
	return; 

    /* check if we need to sort the records */
    if (mdl->callbacks.compare != NULL)  
	qsort(ea->record, et->records, sizeof(rec_t*), mdl->callbacks.compare); 

    /* now go thru the sorted list of records and 
     * store whatever needs to be stored 
     */
    max = et->records;
    for (i = 0; i < max; i++) { 
        
        if (ea->record[i] == NULL) 
            panicx("EXPORT array should be compact!");

	what = mdl->callbacks.action(mdl, ea->record[i], ivl, ts, i);
	/* only bits in the mask are valid */
	logmsg(V_LOGEXPORT, "action %d returns 0x%x (%s%s%s%s)\n",
		i, what,
		what & ACT_STORE ? "STORE ":"",
		what & ACT_STORE_BATCH ? "STORE_BATCH ":"",
		what & ACT_DISCARD ? "DISCARD ":"",
		what & ACT_STOP ? "STOP ":""
		);
	assert( (what | ACT_MASK) == ACT_MASK );

	if ((what & ACT_STORE) || (what & ACT_STORE_BATCH)) {
	    /* store the thing. Do not destroy if store returns < 0
	     * because it means a failure
	     */
	    if (call_store(mdl, ea->record[i]) < 0)
		continue;
	}

	/* check if the module wants to discard this record */
	if (what & ACT_DISCARD)
	    destroy_record(i, mdl);
	if (what & ACT_STOP)
	    break;
    }

    /* reorganize the export record array so that all 
     * used entries are at the beginning of the array with no holes
     */
    bcopy(&ea->record[ea->first_full], &ea->record[0], 
		et->records * sizeof(rec_t *));
    bzero(&ea->record[et->records], (ea->size - et->records) * sizeof(rec_t*));
    ea->first_full = 0;
}
#endif

/* 
 * -- ex_ipc_module_add
 * 
 * handle IPC_MODULE_ADD messages by unpacking the module, 
 * activating it and initializing the data structures it 
 * needs to run in EXPORT. 
 * 
 */
static int
ex_ipc_add_module(UNUSED ipc_peer_t *peer, uint8_t * sbuf, UNUSED size_t sz,
                    UNUSED int swap, UNUSED como_ex_t * como_ex)
{
    mdl_iexport_t *ie;
    caexmsg_t msg;
    mdl_t *mdl;
    alc_t *alc;
    char *str;

    alc = como_alc();
    mdl_deserialize(&sbuf, &mdl, alc, PRIV_IEXPORT);
    if (mdl == NULL) { /* failure */
        warn("failed to receive + deserialize + load a module");
        return IPC_OK;
    }
    debug("ex_ipc_add_module -- recv'd & loaded module `%s'\n", mdl->name);

    ie = mdl_get_iexport(mdl);

    /*
     * open output file
     */
    str = como_asprintf("%s/%s", como_ex->st_dir, mdl->name);
    ie->outfile = csopen(str, CS_WRITER, (off_t)mdl->streamsize, (ipc_peer_t *)COMO_ST);
    if (ie->outfile < 0) {
        warn("cannot start storage for module `%s'\n", mdl->name);
        free(str);
        return IPC_CLOSE;
    }
    ie->woff = csgetofs(ie->outfile);
    debug("ex_ipc_add_module -- output file `%s' open\n", str);
    free(str);

    strcpy(msg.mdl_name, mdl->name);
    if (como_ex->use_shmem) {
        str = como_asprintf("%s/%s/shmem", como_ex->st_dir, mdl->name);
        shmem_remove(str);
        ie->shmem = shmem_create(10 * 1024 * 1024, str);
        if (ie->shmem == NULL) {
            alc_free(alc, mdl);
            free(str);
            return IPC_CLOSE;
        }
        msg.base_addr = shmem_baseaddr(ie->shmem);
        debug("ex_ipc_add_module -- created shared mem region\n");
        strcpy(msg.shmem_filename, str);
        free(str);
    }
    else {
        ie->shmem = NULL;
        msg.shmem_filename[0] = '\0';
        debug("ex_ipc_add_module -- will use serialization interface\n");
    }

    ipc_send((ipc_peer_t*)COMO_CA, CA_EXPORT_RUNNING_MODULE, &msg, sizeof(msg));
    ipc_send(peer, EX_MODULE_ADDED, NULL, 0);

    hash_insert_string(como_ex->mdls, mdl->name, mdl); /* add to mdl index */
    debug("ex_ipc_add_module -- module `%s' fully loaded\n", mdl->name);

    return IPC_OK;
}

static int
ex_ipc_serialized_tuples(UNUSED ipc_peer_t *peer, sertuplesmsg_t *msg, UNUSED size_t sz,
                    UNUSED int swap, UNUSED como_ex_t * como_ex)
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

    debug("ex_ipc_serialized_tuples - tuples for mdl `%s'\n", mdl->name);

    ie = mdl_get_iexport(mdl);
    tuples = como_calloc(msg->ntuples, sizeof(void *));

    /*
     * create an array for the tuples
     */
    debug("ex_ipc_serialized_tuples -- deserializing tuples\n");
    for (i = 0; i < msg->ntuples; i++)
        mdl->priv->mdl_tuple.deserialize(&sbuf, &tuples[i], alc);
    debug("ex_ipc_serialized_tuples -- deserialized the tuples\n");

    /*
     * let the module process 'em
     */
    if (ie->export)
        ie->export(mdl, tuples, msg->ntuples, msg->ivl_start);
    else
        error("TODO: store the tuples directly\n");

    /*
     * free allocated mem.
     */
    free(tuples);

    /*
     * we are done
     */
    debug("ex_ipc_serialized_tuples -- tuples processed\n");
    return IPC_OK;
}

static int
ex_ipc_shmem_tuples(UNUSED ipc_peer_t *peer, tuplesmsg_t * msg,
        UNUSED size_t sz, UNUSED int swap, UNUSED como_ex_t * como_ex)
{
    mdl_iexport_t *ie;
    void **tuples;
    mdl_t *mdl;
    size_t i;
    struct tuple *t;

    debug("ex_ipc_shmem_tuples -- recv'd %d tuples in shared mem\n", msg->ntuples);

    /*
     * locate the module
     */
    mdl = hash_lookup_string(como_ex->mdls, msg->mdl_name);
    if (mdl == NULL)
        error("capture sent tuples from an unknown module\n");

    debug("ex_ipc_shmem_tuples -- tuples for mdl `%s'\n", mdl->name);

    ie = mdl_get_iexport(mdl);
    tuples = como_calloc(msg->ntuples, sizeof(void *));

    debug("ex_ipc_shmem_tuples -- building tuple array\n", mdl->name);
    i = 0;
    tuples_foreach(t, &msg->tuples)
        tuples[i++] = t;

    assert(i == msg->ntuples);

    /*
     * let the module process 'em
     */
    if (ie->export)
        ie->export(mdl, tuples, msg->ntuples, msg->ivl_start);
    else
        error("TODO: store the tuples directly\n");

    debug("ex_ipc_shmem_tuples -- tuples processed, sending response\n");
    ipc_send(peer, EX_MODULE_SHMEM_TUPLES, msg, sz);
    /*
     * free allocated mem.
     */
    free(tuples);

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

    /* register handlers for signals */ 
    signal(SIGPIPE, exit); 
    signal(SIGINT, exit);
    signal(SIGTERM, exit);
    signal(SIGHUP, SIG_IGN); /* ignore SIGHUP */

    /* register handlers for IPC messages */ 
    ipc_init(ipc_peer_at(COMO_EX, ipc_location), NULL, &como_ex);
    ipc_register(EX_ADD_MODULE, (ipc_handler_fn) ex_ipc_add_module);
    ipc_register(EX_MODULE_SERIALIZED_TUPLES, (ipc_handler_fn) ex_ipc_serialized_tuples);
    ipc_register(EX_MODULE_SHMEM_TUPLES, (ipc_handler_fn) ex_ipc_shmem_tuples);
    /*ipc_register(IPC_MODULE_DEL, ex_ipc_module_del);
    ipc_register(IPC_MODULE_START, ex_ipc_start);
    ipc_register(IPC_FLUSH, (ipc_handler_fn) ex_ipc_flush);
    ipc_register(IPC_DONE, ex_ipc_done);
    ipc_register(IPC_EXIT, ex_ipc_exit);*/

    COMO_CA = ipc_peer_at(COMO_CA, ca_location);
    
    /* listen to the parent */
    event_loop_init(&como_ex.el);
    supervisor_fd = ipc_connect(COMO_SU);
    event_loop_add(&como_ex.el, supervisor_fd);

    storage_fd = ipc_connect(COMO_ST); 
    event_loop_add(&como_ex.el, storage_fd);

    ((ipc_peer_t *)COMO_CA)->id = 0;
    ((ipc_peer_t *)COMO_CA)->parent_class = COMO_SU_CLASS;
    capture_fd = ipc_connect(COMO_CA);
    como_ex.use_shmem = ca_location[0] == '/'; /* check if local or remote CA */
    event_loop_add(&como_ex.el, capture_fd);

    /* 
     * wait for the debugger to attach
     */
    DEBUGGER_WAIT_ATTACH(COMO_EX);
 
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
