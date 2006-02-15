/*
 * Copyright (c) 2004 Intel Corporation All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. 2.
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
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

#ifdef linux
   /* XXX what does this do?
    *     anyway it works only for linux
    *     -gianluca
    */
#include <mcheck.h>
#else
#define mcheck(x)
#endif

#include "como.h"
#include "storage.h"

extern struct _como map;	/* Global state structure */

int storage_fd;                 /* socket to storage */


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

	logmsg(LOGWARN, "need to reallocate ex_array for %s (%d -> %d)\n", 
	    mdl->name, ea->size, et->records * 2); 

	len = sizeof(earray_t) + et->records * 2 * sizeof(rec_t *);
	ea = safe_realloc(ea, len); 

        map.stats->mdl_stats[mdl->index].mem_usage_export += 
            len - ea->size;

	ea->size = et->records * 2; 

	mdl->ex_array = ea;
    } 

    /* allocate the new record */
    rp = safe_calloc(1, mdl->callbacks.ex_recordsize + sizeof(rec_t));
    map.stats->mdl_stats[mdl->index].mem_usage_export += 
        mdl->callbacks.ex_recordsize + sizeof(rec_t);
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
        
        ret = mdl->callbacks.ematch(cand, rp);
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
    mdl->callbacks.export(cand, rp, isnew);

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
    char *dst;
    int ret; 

    start_tsctimer(map.stats->ex_mapping_timer); 

    dst = csmap(mdl->file, mdl->offset, (ssize_t *) &mdl->bsize); 
    if (dst == NULL)
	panic("fail csmap for module %s", mdl->name);

    /* call the store() callback */
    ret = mdl->callbacks.store(rp, dst, mdl->bsize);
    if (ret < 0) {
	logmsg(LOGWARN, "store() of %s fails\n", mdl->name);
	return ret; 
    } 

    /*
     * update the offset and commit the bytes written to 
     * disk so far so that they are available to readers 
     */
    mdl->offset += ret;
    cscommit(mdl->file, mdl->offset); 

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
process_table(ctable_t * ct, memlist_t * mem)
{
    module_t *mdl = ct->module;
    int (*record_fn)(module_t *, rec_t *);
    int record_size = ct->module->callbacks.ca_recordsize + sizeof(rec_t);
    
    /*
     * call export() if available, otherwise just store() and
     * bypass the rest of the export code (see above)
     */
    record_fn = mdl->callbacks.export? export_record : call_store;

    /*
     * scan all buckets and save the information to the output file.
     * then see what the EXPORT process has to keep about the entry.
     */
    for (; ct->first_full < ct->size; ct->first_full++) {
	rec_t *rec; 

	logmsg(V_LOGEXPORT, "processing table for module %s (bucket %d)\n",
	       mdl->name, ct->first_full);

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

                /* update the memory counters */
                MDL_STATS(ct->module)->mem_usage_shmem_f += record_size;

		mfree_mem(mem, rec, 0);	/* done, free this record */
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
 * -- ignore_capture_table
 *
 * Walk through a capture table and just free its contents
 * and update memory counters.
 */
static void
ignore_capture_table(ctable_t * ct, memlist_t * mem)
{
    int record_size = ct->module->callbacks.ca_recordsize + sizeof(rec_t);

    for (; ct->first_full < ct->size; ct->first_full++) {
        rec_t *rec = ct->bucket[ct->first_full];
        while(rec != NULL) {
            rec_t *end  = rec->next;

            while (rec->prev) 
	        rec = rec->prev;

            while (rec != end) {
                rec_t *p = rec->next;
                mfree_mem(mem, rec, 0);
                MDL_STATS(ct->module)->mem_usage_shmem_f += record_size;
                rec = p;
            }
        }
    }
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
	
    map.stats->mdl_stats[mdl->index].mem_usage_export -= 
        mdl->callbacks.ex_recordsize + sizeof(rec_t);
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
store_records(module_t * mdl, timestamp_t ts) 
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
    what = mdl->callbacks.action(NULL, ts, 0); 
    assert( (what | ACT_MASK) == ACT_MASK );
    if (what & ACT_STOP) 
	return; 

    /* check if we need to sort the records */
    if (mdl->callbacks.compare != NULL)  
	qsort(ea->record, et->records, sizeof(rec_t*), mdl->callbacks.compare); 

    mcheck(NULL);

    /* now go thru the sorted list of records and 
     * store whatever needs to be stored 
     */
    max = et->records;
    for (i = 0; i < max; i++) { 
        
        if (ea->record[i] == NULL) 
            panicx("EXPORT array should be compact!");

	what = mdl->callbacks.action(ea->record[i], ts, i);
	/* only bits in the mask are valid */
	logmsg(V_LOGEXPORT, "action %d returns 0x%x (%s%s%s)\n",
		i, what,
		what & ACT_STORE ? "STORE ":"",
		what & ACT_DISCARD ? "DISCARD ":"",
		what & ACT_STOP ? "STOP ":""
		);
	assert( (what | ACT_MASK) == ACT_MASK );
	mcheck(NULL);

	if (what & ACT_STORE) {
	    /* store the thing. Do not destroy if store returns < 0
	     * because it means a failure
	     */
	    if (call_store(mdl, ea->record[i]) < 0)
		continue;
	}

	mcheck(NULL);

	/* check if the module wants to discard this record */
	if (what & ACT_DISCARD)
	    destroy_record(i, mdl);
	if (what & ACT_STOP)
	    break;
    }

    mcheck(NULL);

    /* reorganize the export record array so that all 
     * used entries are at the beginning of the array with no holes
     */
    bcopy(&ea->record[ea->first_full], &ea->record[0], 
		et->records * sizeof(rec_t *));
    bzero(&ea->record[et->records], (ea->size - et->records) * sizeof(rec_t*));
    ea->first_full = 0;
    mcheck(NULL);
}

/**
 * -- init_export_tables
 *
 * Allocate the hash table and record array.
 */
static void
init_export_tables(module_t *mdl)
{
    /* allocate hash table */
    int len;
    len = sizeof(etable_t) + mdl->ex_hashsize * sizeof(void *);
    mdl->ex_hashtable = safe_calloc(1, len);
    mdl->ex_hashtable->size = mdl->ex_hashsize;

    /* allocate record array */
    len = sizeof(earray_t) + mdl->ex_hashsize * sizeof(void *);
    mdl->ex_array = safe_calloc(1, len);
    mdl->ex_array->size = mdl->ex_hashsize;

    mcheck(NULL);
    map.stats->mdl_stats[mdl->index].mem_usage_export += 
        sizeof(etable_t) + sizeof(earray_t) +
        2 * mdl->ex_hashsize * sizeof(void *);

}

/**
 * -- init_module
 *
 * Do export-specific module initialization of a module. 
 */
static void
ex_init_module(module_t *mdl)
{
    char * nm; 
    /*
     * initialize hash table and record array
     */
    init_export_tables(mdl);
    /*
     * open output file
     */
    logmsg(V_LOGEXPORT, "module %s: opening file\n", mdl->name);
    asprintf(&nm, "%s", mdl->output);
    mdl->file = csopen(nm, CS_WRITER, mdl->streamsize, storage_fd);
    if (mdl->file < 0) 
        panic("cannot open file %s for %s", nm, mdl->name);
    free(nm);
    mdl->offset = csgetofs(mdl->file);
}

/**
 * -- ex_disable_module
 *
 * Free all memory used by a module.
 */
static void
ex_disable_module(module_t *mdl)
{
    etable_t * et = mdl->ex_hashtable;
    earray_t * ea = mdl->ex_array;
    uint32_t i, rec_size;
    mdl_stats_t *stats;

    stats = &map.stats->mdl_stats[mdl->index];
    rec_size = sizeof(rec_t) + mdl->callbacks.ex_recordsize;

    /*
     * drop export hash table
     */
    stats->mem_usage_export -= sizeof(etable_t) + et->size * sizeof(void *);
    free(et);
    mdl->ex_hashtable = NULL;
    /*
     * drop records 
     */
    for (i = 0; i < ea->size; i++) {
        if (ea->record[i]) {
            free(ea->record[i]);
            stats->mem_usage_export -= rec_size;
            ea->record[i] = NULL;
        }
    }
    /*
     * drop export array
     */
    stats->mem_usage_export -= sizeof(earray_t) + ea->size * sizeof(void *);
    free(ea);
    mdl->ex_array = NULL;
}

/*
 * -- ex_remove_module
 *
 * Free all memory used by a module and close its
 * output file. Forget about that module.
 */
static void
ex_remove_module(module_t *mdl)
{
    if (mdl->status != MDL_DISABLED)
        ex_disable_module(mdl);

    csclose(mdl->file, mdl->offset);
}

/*
 * callbacks of the export process
 */
static proc_callbacks_t export_callbacks = {
    NULL,                   /* ignore new filter functions */
    ex_init_module,         /* initialize a module */
    init_export_tables,     /* enable a module */
    ex_disable_module,      /* disable a module */
    ex_remove_module        /* remove a module */
};


/**
 * -- export_mainloop
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
export_mainloop(__unused int fd)
{
    int capture_fd; 
    int	max_fd;
    fd_set rx;
    uint pkt_thresh;

    mcheck(NULL);

    storage_fd = create_socket("storage.sock", NULL);
    capture_fd = create_socket("capture.sock", NULL);

    /*
     * The first message from supervisor contains the modules information.
     */
    logmsg(LOGDEBUG, "wait for 1st msg from SU\n");
    recv_message(map.supervisor_fd, &export_callbacks);

    /* allocate the timers */
    init_timers();

    mcheck(NULL);
    /* find max fd for the select */
    max_fd = map.supervisor_fd > capture_fd ? map.supervisor_fd : capture_fd;

    FD_ZERO(&rx);
    FD_SET(capture_fd, &rx);
    FD_SET(map.supervisor_fd, &rx);

    /*
     * The real main loop. First process the flow_table's we 
     * receive from the CAPTURE process, then look at the export 
     * tables to see if any action is required.
     */
    pkt_thresh = 100000;
    for (;;) {
	fd_set r = rx;
	int ret;

	start_tsctimer(map.stats->ex_full_timer); 

	mcheck(NULL);
	ret = select(max_fd + 1, &r, NULL, NULL, NULL);
	if (ret < 0 && errno != EINTR) 
	    panic("error in the select (%s)\n", strerror(errno)); 

	start_tsctimer(map.stats->ex_loop_timer); 

	/*
	 * Message from supervisor
	 */
	if (FD_ISSET(map.supervisor_fd, &r))
            recv_message(map.supervisor_fd, &export_callbacks);

        /*
         * Message from capture
         */

	if (FD_ISSET(capture_fd, &r)) {
	    msg_t x;

	    logmsg(V_LOGEXPORT, "received a message from capture\n");

	    /*
	     * Received a list of expired flow headers from CAPTURE. 
	     * Process all of them one by one. 
	     */
	    ret = read(capture_fd, &x, sizeof(x));
	    if (ret != sizeof(x)) 
		panic("error reading capture_fd");

	    /*
	     * process the tables that have been received
	     */
	    while (x.ft != NULL) {
		ctable_t * next = x.ft->next_expired;
		size_t sz = sizeof(ctable_t) + x.ft->size * sizeof(void *);

        /*
         * Process the table, if the module it belongs to is active.
         */
        if (x.ft->module->status == MDL_ACTIVE) {
		    mcheck(NULL);
		    /* process capture table and update export table */
		    start_tsctimer(map.stats->ex_table_timer); 
		    process_table(x.ft, x.m);
		    end_tsctimer(map.stats->ex_table_timer); 
		    mcheck(NULL);

		    /* process export table, storing/discarding records */
		    start_tsctimer(map.stats->ex_store_timer); 
		    store_records(x.ft->module, x.ft->ts); 
		    end_tsctimer(map.stats->ex_store_timer); 
		    mcheck(NULL);
        }
        else
            ignore_capture_table(x.ft, x.m);

        /* update memory counter */
        MDL_STATS(x.ft->module)->mem_usage_shmem_f += sz;
		
        /* free the capture table and move to next */
		mfree_mem(x.m, x.ft, sz);  
		mcheck(NULL);
		x.ft = next;
	    }

	    /*
	     * The tables have been processed and deleted. Return the memory
	     * map to capture so it can merge and reuse the memory.
	     */
	    write(capture_fd, &x, sizeof(x));
	}

	end_tsctimer(map.stats->ex_loop_timer); 
	end_tsctimer(map.stats->ex_full_timer); 

	/* store profiling information */
	print_timers();
	reset_timers();
    }
}
