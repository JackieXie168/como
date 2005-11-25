/*
 * Copyright (c) 2004 Intel Corporation
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
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/socket.h> /* socket, bind, listen, accept */
#include <netinet/in.h> /* struct sockaddr_in */
#include <string.h>     /* bzero */
#include <errno.h>      /* errno */

#include "como.h"
#include "storage.h"
#include "query.h"


/*
 * This code implements the body of the query-ondemand process.
 * One instance is forked by SUPERVISOR right after accepting the
 * connection, and this process serves one single connection and
 * then terminates.
 */

/* global state */
extern struct _como map;

tailq_t expired_tables;  /* expired flow tables */

/* 
 * -- send_status
 * 
 * send the node status back to the client. status information 
 * include node name, location, software version, link speed, data source, 
 * and some load information (memory usage, no. of modules, average traffic). 
 */
static void
send_status(__unused qreq_t * req, int client_fd) 
{
    char buf[1024]; 
    int ret; 
    int len; 
    module_t *mdl;
    int idx;

    /* send HTTP header */
    ret = como_writen(client_fd, 
	    "HTTP/1.0 200 OK\nContent-Type: text/plain\n\n", 0);
    if (ret < 0) 
	panic("sending data to the client");  

    /* send name, location, version, build date, speed and data source 
     * all information that is static and present in the map 
     */
    len = sprintf(buf, 
	    "Name: %s\n"
	    "Location: %s\n" 
	    "Version: CoMo v%s\n"
	    "Build date: %s\n"
	    "Build time: %s\n"
	    "Speed: %s\n"
	    "Time: %u\n",
	    map.name, map.location, COMO_VERSION, __DATE__, __TIME__,
	    map.linkspeed, TS2SEC(map.stats->ts)); 
    ret = como_writen(client_fd, buf, len);
    if (ret < 0)
	panic("sending status to the client");   

    /* send list of loaded modules */
    for (idx = 0; idx < map.module_count; idx++) { 
	mdl = &map.modules[idx]; 

	len = sprintf(buf, "Module: %-20s\tFilter: %s\n", mdl->name,
                      mdl->filter_str);
	ret = como_writen(client_fd, buf, len);
	if (ret < 0)
	    panic("sending status to the client");
    } 

    /* send comments if any */
    if (map.comment != NULL) { 
	len = sprintf(buf, "Comment: %s\n", map.comment); 
	ret = como_writen(client_fd, buf, len);
	if (ret < 0)
	    panic("sending status to the client");
    }

#if 0 
    /* send usage information */
    len = sprintf(buf, 
            "Memory current: %.1fMB\n"
            "Memory peak: %.1fMB\n"
            "Memory size: %dMB\n"
            "Modules total: %d\n"  
            "Modules active: %d\n"  
	    "Avg. Packets/sec (24 hours): %d\n"
	    "Avg. Packets/sec (1 hour): %d\n"
	    "Avg. Packets/sec (5 minutes): %d\n",
            (float) map.stats->mem_usage_cur/(1024*1024),
            (float) map.stats->mem_usage_peak/(1024*1024),
            map.mem_size, map.stats->modules_active, map.module_count,
	    map.stats->pps_24hrs, map.stats->pps_1hr, map.stats->pps_5min); 
    ret = como_writen(client_fd, buf, len);
    if (ret < 0)
        panic("sending status to the client");
#endif
}


/*
 * -- getrecord
 *
 * This function reads a chunk from the file (as defined in the config file 
 * with the blocksize keyword). It then passes it to the load() callback to 
 * get the timestamp and the actual record length. 
 * 
 * Return values:
 *  - on success, returns a pointer to the record, its length and timestamp. 
 *   (with length > 0)
 *  - on 'end of bytestream', returns NULL and len=0
 *  - on 'error' (e.g. csmap failure), returns NULL and len != 0
 *  - on 'lost sync' (bogus data at the end of a file), returns
 *    a non-null (but invalid!) pointer GR_LOSTSYNC and ts = 0
 *
 */
#define	GR_LOSTSYNC	((void *)getrecord)
static void *
getrecord(int fd, off_t * ofs, load_fn *ld, ssize_t *len, timestamp_t *ts)
{
    ssize_t sz; 
    char * ptr; 

    assert(ld != NULL); 

    /* 
     * mmap len bytes starting from last ofs. 
     * 
     * len bytes are supposed to guarantee to contain
     * at least one record to make sure the load() doesn't
     * fail (note that only load knows the record length). 
     * 
     */ 
    ptr = csmap(fd, *ofs, len); 
    if (ptr == NULL) 
	return NULL;

    /* give the record to load() */
    sz = ld(ptr, *len, ts); 
    *ofs += sz; 

    /*
     * check if we have lost sync (indicated by a zero timestamp, i.e. 
     * the load() callback couldn't read the record, or by a load() callback
     * that asks for more bytes -- shouldn't be doing this given the 
     * assumption that we always read one full record. 
     * 
     * The only escape seems to be to seek to the beginning of the next 
     * file in the bytestream. 
     */
    if (*ts == 0 || sz > *len)
	ptr = GR_LOSTSYNC;

    *len = sz; 
    return ptr;
}



/* 
 * -- printrecord
 * 
 * calls the print() callback and sends all data to the client_fd
 *
 */
static void 
printrecord(module_t * mdl, char * ptr, char * args[], int client)  
{
    char * out; 
    size_t len; 
    int i; 

    for (i = 0; args != NULL && args[i] != NULL; i++) 
	logmsg(V_LOGQUERY, "print arg #%d: %s\n", i, args[i]); 

    out = mdl->callbacks.print(ptr, &len, args);
    if (out == NULL) 
        panicx("module %s failed to print\n", mdl->name); 

    if (len > 0) {
        int ret = como_writen(client, out, len);
	if (ret < 0) 
	    panic("sending data to the client"); 
	logmsg(V_LOGDEBUG, "print: %s\n", out); 
    }
}


/* 
 * -- replayrecord
 * 
 * replays a record generating a sequence of packets that are 
 * sent to the client. 
 * 
 */
static void 
replayrecord(module_t * mdl, char * ptr, int client) 
{
    char out[DEFAULT_REPLAY_BUFSIZE]; 
    size_t len; 
    int left, count; 
    int ret; 

    /*
     * one record may generate a large sequence of packets.
     * the replay() callback tells us how many packets are
     * left. we don't move to the next record until we are
     * done with this one.
     *
     * XXX there is no solution to this but the burden could
     *     stay with the module (in a similar way to
     *     sniffer-flowtools that has the same problem). this
     *     would require a method to allow modules to allocate
     *     memory. we need that for many other reasons too.
     *
     *     another approach that would solve the problem in
     *     certain cases is to add a metapacket field that
     *     indicates that a packet is a collection of packets.
     *
     *     in any case there is no definitive solution so we
     *     will have always to deal with this loop here.
     */
    do {
	len = DEFAULT_REPLAY_BUFSIZE;
	left = mdl->callbacks.replay(ptr, out, &len, &count);
	if (left < 0)
	    panicx("%s.replay returns error", mdl->name);

	ret = como_writen(client, out, len);
	if (ret < 0)
	    panic("sending data to the client");
    } while (left > 0);
}

/*
 * -- q_filter()
 *
 * Filter function.
 * When a packet arrives, we evaluate an expression tree for each filter.
 * This needs to be optimized.
 *
 */
int *
q_filter(pkt_t *pkt, int n_packets, int n_out, module_t *modules)
{
    static int *which;
    static int size;
    int i = n_packets*n_out*sizeof(int); /* size of the output bitmap */
    int j;
    int *outs[n_out];

    if (which == NULL) {
        size = i;
        which = (int *)malloc(i);
    } else if (size < i) {
        size = i;
        which = (int *)realloc(which, i);
    }

    bzero(which, i);
    for (i = 0; i < n_out; i++)
        outs[i] = which + n_packets*i;

    for (i = 0; i < n_packets; i++, pkt++)
        for (j = 0; j < n_out; j++)
            outs[j][i] = evaluate(modules[j].filter_tree, pkt);

    return which;
}

/* 
 * -- q_create_table 
 * 
 * allocates and initializes a hash table
 */
static ctable_t *
q_create_table(module_t * mdl, timestamp_t ts) 
{
    ctable_t * ct; 
    size_t len;

    len = sizeof(ctable_t) + mdl->ca_hashsize * sizeof(void *);
    ct = safe_calloc(1, len);
    if (ct == NULL)
	return NULL;

    ct->bytes += len;

    ct->size = mdl->ca_hashsize;
    ct->first_full = ct->size;      /* all records are empty */
    ct->records = 0;
    ct->live_buckets = 0;
    ct->module = mdl;
    ct->mem = NULL;                 /* use the system's map */
    ct->ts = ts;
    ct->next_expired = NULL;

    /*
     * save the timestamp indicating with flush interval this 
     * table belongs to. this information will be useful for 
     * EXPORT when it processes the flushed tables. 
     */
    ct->ivl = ts - (ts % mdl->max_flush_ivl);
    return ct; 
}

/*
 * -- q_flush_table
 *
 * Called by q_capture_pkt() process when a timeslot is complete.
 * it flushes the flow table (if it exists and it is non-empty)
 * and then it allocates a new one.
 *
 */
static void
q_flush_table(module_t * mdl, tailq_t * expired)
{
    ctable_t *ct;

    logmsg(V_LOGQUERY, "flush_table start\n");

    /* check if the table is there and if it is non-empty */
    ct = mdl->ca_hashtable;
    assert(ct != NULL); 
    assert(ct->records > 0); 

    if (ct->records > ct->size)
	logmsg(LOGWARN,
	    "flush_table table '%s' overfull (%d vs %d) -- %d live\n",
	    mdl->name, ct->records, ct->size, ct->live_buckets);

    logmsg(V_LOGQUERY,
	"flush_tables %p(%s) buckets %d records %d live %d\n", ct,
	mdl->name, ct->size, ct->records, ct->live_buckets);

    /* add to linked list and remove from here. */
    TQ_APPEND(expired, ct, next_expired);
    map.stats->table_queue++; 
    mdl->ca_hashtable = NULL;

    logmsg(V_LOGQUERY, "module %s flush_table done.\n", mdl->name);
}

/*
 * -- q_capture_pkt
 *
 * This function is called for every batch of packets that need to be
 * processed by a classifier.
 * For each packet in the batch it runs the check()/hash()/match()/update()
 * methods of the classifier cl_index. The function also checks if the
 * current flow table needs to be flushed.
 *
 */
timestamp_t
q_capture_pkt(module_t * mdl, void *pkt_buf, int no_pkts, int * which, 
	    tailq_t * expired)
{
    pkt_t *pkt = (pkt_t *) pkt_buf;
    timestamp_t max_ts; 
    int i;
    int new_record;
    int record_size; /* effective record size */

    record_size = mdl->callbacks.ca_recordsize + sizeof(rec_t);

    if (mdl->ca_hashtable == NULL)
	mdl->ca_hashtable = q_create_table(mdl, pkt->ts); 

    max_ts = 0; 
    for (i = 0; i < no_pkts; i++, pkt = (pkt_t *)(((char *)pkt) +
                                    sizeof(pkt_t) + pkt->caplen)) { 
        rec_t *prev, *cand;
        uint32_t hash;
        uint bucket;

	if (pkt->ts >= max_ts) {
	    max_ts = pkt->ts; 
	} else {
	    logmsg(LOGQUERY,
		"pkt no. %d timestamps not increasing (%u.%06u --> %u.%06u)\n", 
		i, TS2SEC(max_ts), TS2USEC(max_ts), 
		TS2SEC(pkt->ts), TS2USEC(pkt->ts));
	}

        /* flush the current flow table, if needed */
	if (mdl->ca_hashtable) {
	    ctable_t * ct = mdl->ca_hashtable; 
	
	    ct->ts = pkt->ts; 
	    if (ct->ts > ct->ivl + mdl->max_flush_ivl && ct->records) {  
		q_flush_table(mdl, expired);
		mdl->ca_hashtable = NULL;
	    }
	}
	if (!mdl->ca_hashtable) {
	    mdl->ca_hashtable = q_create_table(mdl, pkt->ts); 
	    if (!mdl->ca_hashtable) 
		continue;		/* XXX no memory, we keep going. 
					 *     need better solution! */
	}


        if (which[i] == 0)
            continue;   /* no interest in this packet */

        /* unset the filter for this packet */
        which[i] = 0;

        /*
         * check if there are any errors in the packet that
         * make it unacceptable for the classifier.
         * (if check() is not provided, we take the packet anyway)
         */
        if (mdl->callbacks.check != NULL && !mdl->callbacks.check(pkt))
            continue;

        /*
         * find the entry where the information related to
         * this packet reside
         * (if hash() is not provided, it defaults to 0)
         */
        hash = mdl->callbacks.hash != NULL ? mdl->callbacks.hash(pkt) : 0;
        bucket = hash % mdl->ca_hashtable->size;

        /*
         * keep track of the first entry in the table that is used.
         * this is useful for the EXPORT process that will have to
         * scan the entire hash table later.
         */
        if (bucket < mdl->ca_hashtable->first_full)
            mdl->ca_hashtable->first_full = bucket;

        prev = NULL;
        cand = mdl->ca_hashtable->bucket[bucket];
        while (cand) {
            /* if match() is not provided, any record matches */
            if (mdl->callbacks.match == NULL || mdl->callbacks.match(pkt, cand))
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
                rec_t * x;

                /* allocate a new record */
                x = safe_calloc(1, record_size);
		if (x == NULL)
		    continue;		/* XXX no memory, we keep going. 
					 *     need better solution! */

                mdl->ca_hashtable->bytes += record_size;

                x->hash = hash;
                x->next = cand->next;

                /* link the current full one to the list of full records */
                x->prev = cand;
                cand->next = x;

                /* we moved cand to the front, now is x */
                mdl->ca_hashtable->bucket[bucket] = x;

                /* done. new empty record ready.
                 * 
		 * NOTE: we do not increment mdl->ca_hashtable->records here 
		 *       because we count this just as a variable size record. 
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
	    cand = safe_calloc(1, record_size);
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
	cand->full = mdl->callbacks.update(pkt, cand, new_record);
    }

    return max_ts; 
}

/* 
 * -- q_process_batch 
 * 
 * take a batch of packets, run them thru the filter and 
 * then call the capture_pkt function for each individual 
 * module. return the last timestamp of the batch.
 * 
 */
static timestamp_t
q_process_batch(pkt_t *pkts, int count, tailq_t *expired, module_t *mdl) 
{
    timestamp_t last_ts;
    int * which;

    /*
     * Select if the classifier needs to see the packets. The q_filter()
     * function returns an array of integer which[pkt] where the index
     * indicates the packet in the batch.  The element of the array is set
     * if the packet is of interest for the given classifier, and it is 0
     * otherwise.
     */
    logmsg(V_LOGQUERY, 
	   "calling filter with pkts %p, n_pkts %d, n_out %d\n", 
	   pkts, count, 1); 
    which = q_filter(pkts, count, 1, mdl);

    /*
     * Now perform the capture actions needed.
     *
     * XXX we do it this way just because anyway we have got a
     * single-threaded process.  will have to change it in the
     * future...
     *
     */
    assert(mdl->name != NULL);
	logmsg(V_LOGQUERY,
	       "sending %d packets to module %s for processing",
	       count, mdl->name);

    last_ts = q_capture_pkt(mdl, pkts, count, which, expired);

    return last_ts;
}

/**
 * -- q_create_record
 *               
 * allocates a new record, updates the ex_array and the 
 * counters (records, live_buckets) 
 */
static rec_t *
q_create_record(module_t * mdl, uint32_t hash)
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
 * -- q_export_record
 *
 * Invoked by q_process_table for each individual record that
 * is received from CAPTURE. It stores persistent state in the EXPORT
 * flow table. 
 *
 * Using the hash value in the flow_hdr, this block scans the hash
 * table to determine the bucket and store the info.
 * 
 */
static int
q_export_record(module_t * mdl, rec_t * rp, __unused int client_fd)
{
    etable_t *et; 
    rec_t *cand; 
    uint32_t hash;
    int isnew; 

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
	cand = q_create_record(mdl, hash);
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

    return 0;		// XXX just to have same prototype of q_call_print
}

/**
 * -- q_call_print
 * 
 * q_call_print() sends the content of a record to the client.
 * Anything >= 0 means success, < 0 is failure.
 * 
 */
static int
q_call_print(module_t * mdl, rec_t *rp, int client_fd)
{
    char *dst;
    int ret; 

    dst = safe_calloc(1, (ssize_t)mdl->bsize); 

    ret = mdl->callbacks.store(rp, dst, mdl->bsize);
    if (ret < 0) 
        logmsg(LOGWARN, "store() of %s fails\n", mdl->name);

    printrecord(mdl, dst, NULL, client_fd);
    
    free(dst);
    
    return ret;
}

/**
 * -- q_process_table
 *
 * Process a table from the expired list. It will go through the buckets
 * of the table, process each single entry in a random order (i.e. the
 * way the entries were hashed into the table). The process consists
 * of writing the content of the entry to the client (via the print() callback)
 * or save some information in the EXPORT table (via the hash/ematch/export
 * callbacks). 
 *
 * On entry:
 *	ct points to a list of tables to be flushed
 *
 */
static void
q_process_table(ctable_t * ct, int client_fd)
{
    module_t *mdl = ct->module;
    int (*record_fn)(module_t *, rec_t *, int);
    int record_size = ct->module->callbacks.ca_recordsize + sizeof(rec_t);
    
    /*
     * call export() if available, otherwise just print() and
     * bypass the rest of the export code (see above)
     */
    record_fn = mdl->callbacks.export? q_export_record : q_call_print;

    /*
     * scan all buckets and save the information to the output file.
     * then see what the EXPORT process has to keep about the entry.
     */
    for (; ct->first_full < ct->size; ct->first_full++) {
	rec_t *rec; 

	logmsg(V_LOGQUERY, "processing table for module %s (bucket %d)\n",
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

		/* print or export this record */
                record_fn(mdl, rec, client_fd);

                /* update the memory counters */
                MDL_STATS(ct->module)->mem_usage_shmem_f += record_size;

		free(rec);	/* done, free this record */
		rec = p;		/* move to the next one */
	    }

	    /* done with the entry, move to next */
	    ct->bucket[ct->first_full] = rec;
	}
    }

    /* 
     * if we have updated the export table, keep track of the 
     * flush interval for which the table is up-to-date. 
     */
    if (mdl->callbacks.export) 
	mdl->ex_hashtable->ts = ct->ivl; 
}

/** 
 * -- q_destroy_record
 * 
 * remove the export record from the hash table and 
 * free the memory. 
 */
static void 
q_destroy_record(int i, module_t * mdl) 
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
 * -- q_print_records
 * 
 * Sweep through the entire table and print
 * all records that the module is willing to store at 
 * this time.
 *
 * Nothing of this is done if export is not defined, as all
 * the module does is print() directly the input from CAPTURE. 
 * 
 * Before doing that, however, it sorts the records if 
 * the module needs to do so (this is true if the compare()
 * callback is defined). 
 *
 */
static void
q_print_records(module_t * mdl, timestamp_t ts, int client_fd) 
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

	if (what & ACT_STORE) {
	    /* print the thing. Do not destroy if print returns < 0
	     * because it means a failure
	     */
	    if (q_call_print(mdl, ea->record[i], client_fd) < 0)
		continue;
	}

	/* check if the module wants to discard this record */
	if (what & ACT_DISCARD)
	    q_destroy_record(i, mdl);
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
 * -- replay_source
 * 
 * replays a record generating a sequence of packets that are 
 * passed through the check/hash/match/update/ematch/export/print callbacks
 * of another module, sending the print result to the client. 
 * 
 */
static void 
replay_source(module_t * orig_mdl, module_t * mdl,
              char * ptr, int client_fd) 
{
    char out[DEFAULT_REPLAY_BUFSIZE]; 
    size_t len, sz; 
    int left, count;
    ctable_t *ft, *next;

    /*
     * one record may generate a large sequence of packets.
     * the replay() callback tells us how many packets are
     * left. we don't move to the next record until we are
     * done with this one.
     *
     * XXX there is no solution to this but the burden could
     *     stay with the module (in a similar way to
     *     sniffer-flowtools that has the same problem). this
     *     would require a method to allow modules to allocate
     *     memory. we need that for many other reasons too.
     *
     *     another approach that would solve the problem in
     *     certain cases is to add a metapacket field that
     *     indicates that a packet is a collection of packets.
     *
     *     in any case there is no definitive solution so we
     *     will have always to deal with this loop here.
     */
    do {
        len = DEFAULT_REPLAY_BUFSIZE;
	left = mdl->callbacks.replay(ptr, out, &len, &count);
	if (left < 0)
	    panicx("%s.replay returns error", mdl->name);

        /* Here we have a batch of replayed packets in "out".
         * Pass them through the capture sequence. */
    
        map.stats->ts = q_process_batch((pkt_t *)out, count, &expired_tables,
                                        orig_mdl);
    } while (left > 0);
        
    /* Here we should do the export stuff */
    ft = TQ_HEAD(&expired_tables);
    while (ft != NULL) {
	next = ft->next_expired;
	sz = sizeof(ctable_t) + ft->size * sizeof(void *);

        /* process capture table and update export table */
        q_process_table(ft, client_fd);

	/* process export table, printing/discarding records */
	q_print_records(ft->module, ft->ts, client_fd);

        /* update memory counter */
        MDL_STATS(ft->module)->mem_usage_shmem_f += sz;
		
        /* free the capture table and move to next */
	free(ft);  
	ft = next;
    }
    
    /* We are finished with the expired tables */
    TQ_HEAD(&expired_tables) = NULL;
}

/**
 * -- q_init_export_tables
 *
 * Allocate the hash table and record array.
 */
static void
q_init_export_tables(module_t *mdl)
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

    map.stats->mdl_stats[mdl->index].mem_usage_export += 
        sizeof(etable_t) + sizeof(earray_t) +
        2 * mdl->ex_hashsize * sizeof(void *);
}

/*
 * -- query_ondemand
 *
 * This function is used for on-demand queries. It is called by
 * supervisor_mainloop() and runs in a new process. It is in charge of
 * authenticating the query, finding the relevant module output
 * data and send them back to the requester. 
 * 
 * A query comes over a TCP socket with the following information: 
 *
 *  . name, the module to run (the shared object must exist already)
 *  . filter, filter expression
 *  . start, start timestamp
 *  . end, end timestamp
 * 
 * XXX as of now, query_ondemand requires that the module has been running
 *     during the interval of interest. this way it just has to find the 
 *     output file, read them and send them "as is" to the client. 
 *
 */
void
query_ondemand(int client_fd)
{
    int idx;
    int ret; 
    module_t *mdl, *orig_mdl;
    qreq_t *req;
    int storage_fd, file_fd;
    off_t ofs; 
    char * output; 
    ssize_t len;
    int module_found; 
    int mode;
    int arg, narg;
    callbacks_t *cb;

    /* set the name of this process */
    map.procname = "qd"; 
    setproctitle("ONDEMAND");

    /* connect to the supervisor so we can send messages */
    map.supervisor_fd = create_socket("supervisor.sock", NULL);
    logmsg(V_LOGWARN, "starting query-ondemand #%d: fd[%d] pid %d\n",
	client_fd, client_fd, getpid()); 

    if (map.debug) {
	if (strstr(map.debug, map.procname) != NULL) {
	    logmsg(V_LOGWARN, "waiting 60s for the debugger to attach\n");
	    sleep(60);
	    logmsg(V_LOGWARN, "wakeup, ready to work\n");
	}
    }

    req = (qreq_t *) qryrecv(client_fd); 
    if (req == NULL) {
	close(client_fd);
	return; 
    } 

    logmsg(V_LOGQUERY,
        "got query (%d bytes); mdl: %s filter: %s\n",  
        ntohs(req->len), req->module, req->filter_str); 
    logmsg(0, "    from %d to %d\n", req->start, req->end); 

    if (req->format == Q_STATUS) { 
	/* 
	 * status queries can always be answered. send 
	 * back the information about this CoMo instance (i.e., name, 
	 * location, version, etc.) 
	 */
	send_status(req, client_fd);
	close(client_fd);
	return; 
    }

    if (req->module == NULL) { 
	/* 
	 * no module defined. return warning message and exit
	 */
	logmsg(LOGWARN, "query module not defined\n"); 
	close(client_fd);
	return; 
    } 

    if (req->start > req->end) { 
	/* 
	 * start time is after end time, return error message 
	 */  
	logmsg(LOGWARN, 
	       "query start time (%d) after end time (%d)\n", 
	       req->start, req->end); 

	ret = como_writen(client_fd, 
		  "HTTP/1.0 405 Method Not Allowed\n"
		  "Content-Type: text/plain\n\n"
		  "Query start time after end time\n", 0); 
	close(client_fd);
	return; 
    } 

    /* 
     * check if the module is running using the same filter 
     * 
     * XXX right now we just check if the module exists and is using an
     * equivalent filter:
     * - With the new filter parser that uses Flex and Bison, the filters
     *   only need to be semantically equivalent
     *   (i.e., "A and B" is the same as "B and A").
     * In the future we will have to check if the module has been running
     * during the interval of interest. If not, we have to run it on the
     * stored packet trace. 
     */
    module_found = 0; 
    for (idx = 0; idx < map.module_count; idx++) { 
        mdl = &map.modules[idx]; 

	/* check module name */
	if (strcmp(req->module, mdl->name))
	    continue; 

	/* check filter string */
        module_found = 1;
	if (!strcmp(req->filter_cmp, mdl->filter_cmp)) 
            break;  /* found! */
    } 

    if (idx == map.module_count) { 
	/* 
	 * no module found. return an error message 
	 * to the client. 
	 */
        if (!module_found) {
	    logmsg(LOGWARN, "query module not found (%s)\n", req->module);
	    ret = como_writen(client_fd, 
		      "HTTP/1.0 404 Not Found\nContent-Type: text/plain\n\n"
		      "Module not found\n", 0);
        } else {
	    logmsg(LOGWARN, "query filter not found (%s)\n", req->filter_str);
	    ret = como_writen(client_fd, 
		      "HTTP/1.0 404 Not Found\nContent-Type: text/plain\n\n"
		      "Filter not found\n", 0);
	}
	if (ret < 0)
	    panic("sending data to the client"); 
	close(client_fd);
	return; 
    }

    /* Check if we have to retrieve the data using the replay callback of
     * another module instead of connecting to storage and reading a file
     */
    if (req->source) {
        
        /* Set up a new module structure and call the init callback */
        orig_mdl = safe_calloc(1, sizeof(module_t));
        orig_mdl->name = safe_strdup(mdl->name);
        orig_mdl->description = safe_strdup(mdl->description);
        orig_mdl->filter_tree = tree_copy(mdl->filter_tree);
        orig_mdl->filter_str = safe_strdup(mdl->filter_str);
        orig_mdl->filter_cmp = safe_strdup(mdl->filter_cmp);
        orig_mdl->output = safe_strdup(mdl->output);
        
        /* Copy module arguments */
        narg = 0;
        if (mdl->args)
            for (narg = 0; mdl->args[narg] != NULL; narg++);
            orig_mdl->args = safe_calloc(narg + 1, sizeof(char *));
            for (arg = 0; arg < narg; arg++)
                orig_mdl->args[arg] = safe_strdup(mdl->args[arg]);
            orig_mdl->args[arg] = NULL;
        
        orig_mdl->source = safe_strdup(mdl->source);
        orig_mdl->msize = mdl->msize;
        if (orig_mdl->msize)
	    orig_mdl->mem = safe_calloc(1, orig_mdl->msize);
        load_callbacks(orig_mdl);
        mdl->status = MDL_ACTIVE;
        orig_mdl->ca_hashsize = mdl->ca_hashsize;
        orig_mdl->ex_hashsize = mdl->ex_hashsize;
        orig_mdl->min_flush_ivl = mdl->min_flush_ivl;
        orig_mdl->max_flush_ivl = mdl->max_flush_ivl;
        orig_mdl->bsize = mdl->bsize;
        
        cb = &(orig_mdl->callbacks);
        if (cb->init != NULL && cb->init(orig_mdl->mem,
                                         orig_mdl->msize, orig_mdl->args) != 0)
	    panicx("could not initialize %s\n", mdl->name);
        
        /* Init expired flow tables queue */
        TQ_HEAD(&expired_tables) = NULL;
        map.stats->table_queue = 0;
        
        /* Init capture tables */
        orig_mdl->ca_hashtable = NULL;
        
        /* Init export tables */
        q_init_export_tables(orig_mdl);
        
        /* Find the source module */
        module_found = 0;
        for (idx = 0; !module_found && idx < map.module_count; idx++) {
            mdl = &map.modules[idx];
            if (!strcmp(req->source, mdl->name))
                module_found = 1;
        }
        
        if (!module_found) {
            /* No source module found,
             * return an error message to the client and finish
             */
            logmsg(LOGWARN, "source module not found (%s)\n", req->source);
	        ret = como_writen(client_fd, 
		        "HTTP/1.0 404 Not Found\nContent-Type: text/plain\n\n"
		        "Source module not found\n", 0);
            if (ret < 0)
                panic("sending data to the client");
            close(client_fd);
            return;
        }

        /* mdl is our source module here.
         * We want it to output using its replay callback
         */
        req->format = Q_COMO;
    }
    
    /* 
     * connect to the storage process, open the module output file 
     * and then start reading the file and send the data back 
     */
    storage_fd = create_socket("storage.sock", NULL);

    logmsg(V_LOGQUERY, "opening file for reading (%s)\n", mdl->output); 
    mode =  req->wait? CS_READER : CS_READER_NOBLOCK; 
    file_fd = csopen(mdl->output, mode, 0, storage_fd); 
    if (file_fd < 0) 
	panic("opening file %s", mdl->output);

    /* get start offset. this is needed because we access the file via
     * csmap instead of csreadp (that is not implemented yet) 
     */
    ofs = csgetofs(file_fd); 

    /*
     * initializations
     */
    switch (req->format) {
    case Q_OTHER:
	/*
	 * produce a response header
	 */
	if (mdl->callbacks.print == NULL) 
	    panicx("module %s does not support printing results\n", mdl->name); 
	ret = como_writen(client_fd, 
		"HTTP/1.0 200 OK\nContent-Type: text/plain\n\n", 0);
	if (ret < 0) 
	    panic("sending data to the client");  

	/* first print callback. we need to make sure that req->args != NULL. 
	 * if this is not the case we just make something up
	 */
	if (req->args == NULL) {
	    req->args = safe_calloc(1, sizeof(char **)); 
	    req->args[0] = NULL;
	} 
	printrecord(mdl, NULL, req->args, client_fd);
	break;
	
    case Q_COMO: 
	/*
	 * transmit the output stream description
	 */
	if (mdl->callbacks.outdesc == NULL || mdl->callbacks.replay == NULL)
	    panicx("module %s does not support trace replay\n", mdl->name); 
	if (!req->source) {
            ret = como_writen(client_fd, (char*) mdl->callbacks.outdesc, 
		              sizeof(pktdesc_t)); 
	    if (ret < 0)
	        panic("could not send pktdesc");
        } else {
            /* Do the first print callback for the original module */
            if (req->args == NULL) {
                req->args = safe_calloc(1, sizeof(char **));
                req->args[0] = NULL;
            }
            printrecord(orig_mdl, NULL, req->args, client_fd);
        }

	/* allocate the output buffer */
	output = safe_calloc(1, DEFAULT_REPLAY_BUFSIZE);
        break;
    }

    /*  
     * now look for the start time in the file 
     * 
     * XXX we do this without seeking the file. we read all the
     *     records one by one to find the beginning. very inefficient.
     *     one day STORAGE will support timestamp-based seeks.
     *  
     */
    for (;;) { 
	timestamp_t ts;
	char * ptr; 

        len = mdl->bsize; 
        ptr = getrecord(file_fd, &ofs, mdl->callbacks.load, &len, &ts);
        if (ptr == NULL) {	/* no data, but why ? */
	    if (len == -1) 
		panic("reading from file %s\n", mdl->output); 

	    if (len == 0) {
		/* notify the end of stream to the module */
		if (req->format == Q_OTHER) 
		    printrecord(mdl, NULL, NULL, client_fd); 
		logmsg(LOGQUERY, "reached end of file %s\n", mdl->output); 
		break;
	    }
	}

	/*
	 * Now we have either good data or or GR_LOSTSYNC.
	 * If lost sync, move to the next file and try again. 
	 */
	if (ptr == GR_LOSTSYNC) {
	    logmsg(LOGQUERY, "lost sync, trying next file %s\n", mdl->output); 
	    ofs = csseek(file_fd);
	    continue;
	}

    	if (TS2SEC(ts) < req->start)	/* before the required time. */
	    continue;
    	if (TS2SEC(ts) >= req->end) {
	    /* notify the end of stream to the module */
	    if (req->format == Q_OTHER) 
		printrecord(mdl, NULL, NULL, client_fd); 
	    logmsg(LOGQUERY, "query completed\n"); 
	    break;
	}

	switch (req->format) { 
	case Q_COMO: 	
	    if (!req->source)
            replayrecord(mdl, ptr, client_fd);
        else {
            replay_source(orig_mdl, mdl, ptr, client_fd);
        }
	    break; 

	case Q_RAW: 
	    /* send the data to the query client */
	    ret = como_writen(client_fd, ptr, len);
	    if (ret < 0) 
		panic("sending data to the client"); 
	    break;
            
	case Q_OTHER: 
	    printrecord(mdl, ptr, NULL, client_fd); 
	    break;
        }
    }

    /* close the socket and the file */
    close(client_fd);
    csclose(file_fd); 
}
