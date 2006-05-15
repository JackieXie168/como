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

extern struct _como map;	/* Global state structure */

int storage_fd;                 /* socket to storage 
				 * 
				 * XXX this is temporary until IPC are
				 *     used to communicate with STORAGE too
				 */


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
    char *dst;
    int ret, done = 0;
    
    ssize_t bsize = mdl->callbacks.st_recordsize; 

    start_tsctimer(map.stats->ex_mapping_timer); 
    
    if (map.running == INLINE) {
	/* running inline */
	dst = alloca(bsize); /* NOTE: might be replaced with a heap allocated
				area using a static variable to keep track of
				it */
    }
    
    do {
	if (map.running == NORMAL) { 
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
	
	if (map.running == NORMAL) { 
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
		
		/* print this record */
		printrecord(mdl, p, NULL, -1);
		
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
    for (; ct->first_full < ct->size; ct->first_full++) {
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
    what = mdl->callbacks.action(mdl, NULL, ts, 0); 
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

	what = mdl->callbacks.action(mdl, ea->record[i], ts, i);
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


/* 
 * -- ex_ipc_module_add
 * 
 * handle IPC_MODULE_ADD messages by unpacking the module, 
 * activating it and initializing the data structures it 
 * needs to run in EXPORT. 
 * 
 */
static void
ex_ipc_module_add(procname_t src, __unused int fd, void * pack, size_t sz) 
{
    module_t tmp; 
    module_t * mdl;
    int len;

    /* only the parent process should send this message */
    assert(src == map.parent);

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
     * initialize hash table and record array
     */
    len = sizeof(etable_t) + mdl->ex_hashsize * sizeof(void *);
    mdl->ex_hashtable = safe_calloc(1, len);
    mdl->ex_hashtable->size = mdl->ex_hashsize;
        
    /* allocate record array */
    len = sizeof(earray_t) + mdl->ex_hashsize * sizeof(void *);
    mdl->ex_array = safe_calloc(1, len);
    mdl->ex_array->size = mdl->ex_hashsize;

    /*
     * open output file unless we are running in inline mode 
     */
    if (map.running == NORMAL) {
	logmsg(V_LOGEXPORT, "module %s: opening file\n", mdl->name);
	mdl->file = csopen(mdl->output, CS_WRITER, mdl->streamsize, storage_fd);
	if (mdl->file < 0)
	    panic("cannot open file %s for %s", mdl->output, mdl->name);
	mdl->offset = csgetofs(mdl->file);
    } else { 
	char * x[] = {NULL}; 
	char ** p = mdl->args? mdl->args : x; 

	/* setup the print format (make sure we 
	 * don't send a NULL args pointer down)
	 */
	printrecord(mdl, NULL, p, -1);
    } 
}
 

/* 
 * -- ex_ipc_module_del
 * 
 * removes a module from the map. it also frees all data 
 * structures related to that module and close the output 
 * file. 
 * 
 */ 
static void
ex_ipc_module_del(procname_t sender, __unused int fd, void * buf,
		  __unused size_t len)
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
ex_ipc_flush(procname_t sender, __unused int fd, void *buf, size_t len)
{
    expiredmap_t *exp;
    
    assert(sender == sibling(CAPTURE));
    assert(len == sizeof(expiredmap_t *));
    
    for (exp = *((expiredmap_t **) buf); exp; exp = exp->next) {
	module_t * mdl; 

	/*
	 * use the correct module flush state & shared map
	 */
	mdl = exp->mdl; 
	mdl->fstate = exp->fstate;
	mdl->shared_map = exp->shared_map;
	
	/* if in inline mode, make sure this is the inline module */
	assert(map.running == NORMAL || mdl == map.inline_mdl); 

	/*
	 * Process the table, if the module it belongs to is active.
	 */
	if (mdl->status != MDL_ACTIVE)
	    continue;
	
	/* process capture table and update export table */
	start_tsctimer(map.stats->ex_table_timer);
	process_table(exp->ct, mdl);
	end_tsctimer(map.stats->ex_table_timer);

	/* process export table, storing/discarding records */
	start_tsctimer(map.stats->ex_store_timer);
	store_records(mdl, exp->ct->ts);
	end_tsctimer(map.stats->ex_store_timer);
    }

    /*
     * The tables have been processed. Return them to capture
     * so it can merge and reuse the memory.
     */
    ipc_send_with_fd(fd, IPC_FLUSH, buf, len);
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
ex_ipc_start(procname_t sender, __unused int fd, void * buf, size_t len)
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
ex_ipc_done(procname_t sender, __unused int fd, __unused void * buf,
	__unused size_t len)
{
    /* only the parent process should send this message */
    assert(sender == sibling(CAPTURE)); 

    /* this should happen only in inline mode */ 
    assert(map.running == INLINE); 

    /* 
     * we will not receive any more messages from CAPTURE. let's 
     * try to store all records we have before reporting to be 
     * done. 
     */
    store_records(map.inline_mdl, ~0);

    /* print the footer since running inline (asserted before) */
    printrecord(map.inline_mdl, NULL, NULL, -1);
    
    ipc_send(map.parent, IPC_DONE, NULL, 0); 
}


/*
 * -- ex_ipc_exit 
 *
 */
static void
ex_ipc_exit(procname_t sender, __unused int fd, __unused void * buf,
             __unused size_t len)
{
    assert(sender == map.parent);  
    exit(EXIT_SUCCESS); 
}


/*
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
export_mainloop(__unused int in_fd, int parent_fd)
{
    int capture_fd; 
    int	max_fd;
    fd_set rx;

    /* initialize select()able file descriptors */
    max_fd = -1; 
    FD_ZERO(&rx);

    /* register handlers for signals */ 
    signal(SIGPIPE, exit); 
    signal(SIGINT, exit);
    /* ignore SIGHUP */
    signal(SIGHUP, SIG_IGN); 

    /* register handlers for IPC messages */ 
    ipc_clear();
    ipc_register(IPC_MODULE_ADD, ex_ipc_module_add);
    ipc_register(IPC_MODULE_DEL, ex_ipc_module_del);
    ipc_register(IPC_MODULE_START, ex_ipc_start);
    ipc_register(IPC_FLUSH, (ipc_handler_fn) ex_ipc_flush);
    ipc_register(IPC_DONE, ex_ipc_done);
    ipc_register(IPC_EXIT, ex_ipc_exit);
    
    /* listen to the parent */
    max_fd = add_fd(parent_fd, &rx, max_fd); 

    storage_fd = ipc_connect(STORAGE); 
    max_fd = add_fd(storage_fd, &rx, max_fd); 

    capture_fd = ipc_connect(sibling(CAPTURE)); 
    max_fd = add_fd(capture_fd, &rx, max_fd); 

    /*
     * now that all sockets are ready we can wait for
     * the debugger if needed.
     */
    if (map.debug) {
        if (strstr(map.debug, getprocname(map.whoami)) != NULL) {
            logmsg(V_LOGWARN, "waiting 30s for the debugger to attach\n");
            sleep(30);
            logmsg(V_LOGWARN, "wakeup, ready to work\n");
        }
    }
 
    /* allocate the timers */
    init_timers();

    /*
     * The real main loop. First process the flow_table's we 
     * receive from the CAPTURE process, then look at the export 
     * tables to see if any action is required.
     */
    for (;;) {
	fd_set r = rx;
	int n_ready;
        int i;
        int ipcr;

	start_tsctimer(map.stats->ex_full_timer); 

	n_ready = select(max_fd + 1, &r, NULL, NULL, NULL);
	if (n_ready < 0 && errno != EINTR) 
	    panic("error in the select (%s)\n", strerror(errno)); 

	start_tsctimer(map.stats->ex_loop_timer); 

    	for (i = 0; n_ready > 0 && i < max_fd; i++) {
	    if (!FD_ISSET(i, &r))
		continue;
	    
	    ipcr = ipc_handle(i);
	    switch (ipcr) {
	    case IPC_ERR:
		/* an error. close the socket */
		logmsg(LOGWARN, "error on IPC handle from %d\n", i);
		exit(EXIT_FAILURE);
	    case IPC_EOF:
		close(i);
		max_fd = del_fd(i, &rx, max_fd);
	    }
	    
	    n_ready--;
	}

	end_tsctimer(map.stats->ex_loop_timer); 
	end_tsctimer(map.stats->ex_full_timer); 

	/* store profiling information */
	print_timers();
	reset_timers();
    }
}
