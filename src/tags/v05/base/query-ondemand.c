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
	    "Start: %u\n"
	    "Current: %u\n",
	    map.name, map.location, 
	    COMO_VERSION, __DATE__, __TIME__, map.linkspeed, 
	    (uint) TS2SEC(map.stats->first_ts), (uint) TS2SEC(map.stats->ts)); 
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
    count = 0;
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

    for (i = 0; i < n_packets; i++, pkt = (pkt_t *)(((char *)pkt) +
                                    sizeof(pkt_t) + pkt->caplen)) {
        for (j = 0; j < n_out; j++)
            outs[j][i] = evaluate(modules[j].filter_tree, pkt);
    }

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
     * save the timestamp to indicate which flush interval this 
     * table belongs to. this information will be useful for 
     * EXPORT when it processes the flushed tables. 
     */
    ct->ivl = ts; 
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

    logmsg(V_LOGDEBUG, "flush_table start\n");

    /* check if the table is there and if it is non-empty */
    ct = mdl->ca_hashtable;
    assert(ct != NULL); 
    assert(ct->records > 0); 

    if (ct->records > ct->size)
	logmsg(LOGWARN,
	    "flush_table table '%s' overfull (%d vs %d) -- %d live\n",
	    mdl->name, ct->records, ct->size, ct->live_buckets);

    logmsg(V_LOGDEBUG,
	"flush_tables %p(%s) buckets %d records %d live %d\n", ct,
	mdl->name, ct->size, ct->records, ct->live_buckets);

    /* add to linked list and remove from here. */
    TQ_APPEND(expired, ct, next_expired);
    mdl->ca_hashtable = NULL;

    logmsg(V_LOGDEBUG, "module %s flush_table done.\n", mdl->name);
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
static void
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
	    if (ct->ts >= ct->ivl + mdl->flush_ivl && ct->records) {  
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
}

/* 
 * -- q_process_batch 
 * 
 * take a batch of packets, run them thru the filter and 
 * then call the capture_pkt function for each individual 
 * module. return the last timestamp of the batch.
 * 
 */
static void
q_process_batch(pkt_t *pkts, int count, tailq_t *expired, module_t *mdl) 
{
    int * which;

    /*
     * Select if the classifier needs to see the packets. The q_filter()
     * function returns an array of integer which[pkt] where the index
     * indicates the packet in the batch.  The element of the array is set
     * if the packet is of interest for the given classifier, and it is 0
     * otherwise.
     */
    logmsg(V_LOGDEBUG, 
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
    logmsg(V_LOGDEBUG, "sending %d packets to module %s for processing\n",
	   count, mdl->name);

    q_capture_pkt(mdl, pkts, count, which, expired);
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
    char *dst, *p;
    ssize_t ret; 
    size_t left; 

    dst = safe_calloc(1, (ssize_t)mdl->bsize); 

    ret = mdl->callbacks.store(rp, dst, mdl->bsize);
    if (ret < 0) 
        logmsg(LOGWARN, "store() of %s fails\n", mdl->name);

    /* now the dst pointer contains the entire output of 
     * store. note that store could save more than one record
     * in a single call. we pass this pointer to the load callback
     * to get that information. 
     */
    p = dst; 
    left = (size_t) ret; 
    while (left > 0) { 
	size_t sz; 
	timestamp_t ts; 

 	sz = mdl->callbacks.load(p, (size_t) ret, &ts);  

	/* print this record */
        printrecord(mdl, p, NULL, client_fd);

	/* move to next */
	p += sz; 
	left -= sz; 
    } 
    
    free(dst);
    return (int) ret;
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

    logmsg(V_LOGDEBUG, "processing table for module %s (bucket %d)\n",
	   mdl->name, ct->first_full);
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
replay_source(module_t * mdl, module_t * src, char * ptr, int client_fd) 
{
    char out[DEFAULT_REPLAY_BUFSIZE]; 
    size_t len, sz; 
    int left, count;
    ctable_t *ft, *next;
    tailq_t expired_tables;  /* expired flow tables */

    /* init expired flow tables */
    TQ_HEAD(&expired_tables) = NULL;

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
	count = 0;
        len = DEFAULT_REPLAY_BUFSIZE;
	left = src->callbacks.replay(ptr, out, &len, &count);
	if (left < 0)
	    panicx("%s.replay() returns error", src->name);

        /* 
	 * we have a batch of replayed packets in "out".
         * pass them through the capture sequence. 
         */
	if (count)
	    q_process_batch((pkt_t *)out, count, &expired_tables, mdl);
    } while (left > 0);

    /* 
     * if the record (ptr) is NULL, this is the last call to 
     * replay_source(). flush all tables independently if the 
     * timer has expired. 
     */
    if (!ptr && mdl->ca_hashtable && mdl->ca_hashtable->records) {
	q_flush_table(mdl, &expired_tables);
	mdl->ca_hashtable = NULL;
    }

    /* 
     * here we do the export stuff and process all 
     * expired tables before processing any more packets
     */  
    ft = TQ_HEAD(&expired_tables);
    while (ft != NULL) {
	next = ft->next_expired;
	sz = sizeof(ctable_t) + ft->size * sizeof(void *);

        /* process capture table and update export table */
        q_process_table(ft, client_fd);

	/* process export table, printing/discarding records */
	q_print_records(ft->module, ft->ts, client_fd);

        /* free the capture table and move to next */
	free(ft);  
	ft = next;
    }
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
 * -- validate_query
 * 
 * validates a query checking that the timestamps are correct, 
 * the module names are recognized and that the format of the entire
 * query is valid. it returns NULL in case of success or a string 
 * containing the HTTP error string in case of failure. 
 *
 */
static char * 
validate_query(qreq_t * req)
{
    static char httpstr[8192];
    int idx;

    if (req->module == NULL) {
        /*
         * no module defined. return warning message and exit
         */
        logmsg(LOGWARN, "query module not defined\n");
	sprintf(httpstr, "HTTP/1.0 405 Method Not Allowed\n"
                         "Content-Type: text/plain\n\n"
                         "Module name is missing\n"); 
        return httpstr;
    }

    if (req->start > req->end) {
        /*
         * start time is after end time, return error message
         */
        logmsg(LOGWARN,
               "query start time (%d) after end time (%d)\n", 
               req->start, req->end);
         
	sprintf(httpstr, "HTTP/1.0 405 Method Not Allowed\n"
		         "Content-Type: text/plain\n\n"
                         "Query start time after end time\n");
        return httpstr;
    }

    /* check if the module is present in the configuration file */
    for (idx = 0; idx < map.module_count; idx++) {
        req->mdl = &map.modules[idx];

        /* check module name */
        if (!strcmp(req->module, req->mdl->name))
	    break;
    }

    if (idx == map.module_count) { 
	/*
	 * the module is not present in the configuration file 
	 */
	logmsg(LOGWARN, "module %s not found\n", req->module);
	sprintf(httpstr, 
		"HTTP/1.0 404 Not Found\n"
	 	"Content-Type: text/plain\n\n"
                "Module %s not found in the current configuration\n", 
		req->module);
	return httpstr;
    } 

    if (!req->mdl->callbacks.print && 
	 (req->format == Q_OTHER || req->format == Q_HTML)) {
	/*
	 * the module exists but does not support printing records. 
	 */
	logmsg(LOGWARN, "module \"%s\" does not have print()\n", req->module);
	sprintf(httpstr, 
		"HTTP/1.0 405 Method Not Allowed\n"
	 	"Content-Type: text/plain\n\n"
                "Module \"%s\" does not have print() callback\n", 
		req->module);
	return httpstr;
    } 
	
    /* 
     * there are two types of queries. the ones that just need to print or 
     * retrieve the data stored by a running instance of a module and the 
     * ones that require to process the output data of a different module 
     * (i.e. chain together two modules as defined by "source=..." in the 
     * query). 
     *
     * in the first case we have to make sure that the running module is 
     * using the same filter that is present in the query (we need that also
     * to distinguish between multiple instances of the same module). 
     * 
     * in the second case (if req->source is not NULL) we need to make sure
     * the source module actually exists. 
     * 
     * XXX we do not support the existance of multiple modules that have the
     *     same name as the source module but different filters. we assume
     *     whoever posted the query knew what was going on...
     * 
     * XXX in the future we will have to check if the module has been running
     *     during the interval of interest.
     */
    if (!req->source) { 
	/* 
	 * source is not defined, hence we just want to read 
	 * the output file. check the filter of the running modules 
	 */
	for (idx = 0; idx < map.module_count; idx++) {
	    req->mdl = &map.modules[idx];

	    /* check module name */
	    if (strcmp(req->module, req->mdl->name))
		continue;
	 
	    /* check filter string */
	    if (!strcmp(req->filter_cmp, req->mdl->filter_cmp))
		break;  /* found! */
	}

	if (idx == map.module_count) {
	    /*
	     * the module is not present in the configuration file 
	     */
	    logmsg(LOGWARN, "module %s found but it is not using filter (%s)\n",
		req->module, req->filter_str); 
	    sprintf(httpstr, 
		    "HTTP/1.0 404 Not Found\n"
		    "Content-Type: text/plain\n\n"
		    "Module %s found but it is not using filter \"%s\"\n", 
		    req->module, req->filter_str);
	    return httpstr;
	}
    } else { 
	/* 
	 * a source is defined. go look for it and forget about the 
	 * filter defined in the query. we will have to instantiate a
	 * new module anyway. 
	 */
        for (idx = 0; idx < map.module_count; idx++) {
            req->src = &map.modules[idx];
            if (!strcmp(req->source, req->src->name))
		break;
        }
        
	if (idx == map.module_count) {
            /* No source module found,
             * return an error message to the client and finish
             */
            logmsg(LOGWARN, "source module not found (%s)\n", req->source);
	    sprintf(httpstr, 
		    "HTTP/1.0 404 Not Found\n"
		    "Content-Type: text/plain\n\n"
		    "Source module \"%s\" not found\n", 
		    req->source); 
            return httpstr;
        }

	if (!req->src->callbacks.outdesc || !req->src->callbacks.replay) {
	    /*	
	     * the source module does not have the replay() callback or 
	     * a description of the packets it can generate. return an 
	     * error message 
	     */
            logmsg(LOGWARN, "source module \"%s\" does not support replay()\n",
		   req->source);
	    sprintf(httpstr, 
		    "HTTP/1.0 404 Not Found\n"
		    "Content-Type: text/plain\n\n"
		    "Source module \"%s\" does not support replay()\n", 
		    req->source); 
            return httpstr;
        }
    } 

    return NULL;		/* everything OK, nothing to say */
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
 *  . time, interval of interest 
 *  . source, data source if not one of the running sniffers 
 *  . format, to define the output format of the query
 * 
 * XXX as of now, if "source" is not defined, query_ondemand requires 
 *     that the module has been running during the interval of interest. 
 *     if "source" is defined then that module replay() callback is used. 
 *     in the future, query should independently pick the most appropriate
 *     source of data.
 *
 */
void
query_ondemand(int client_fd)
{
    qreq_t *req;
    int storage_fd, file_fd;
    off_t ofs; 
    char * output; 
    ssize_t len;
    int mode, ret;
    int arg, narg;
    callbacks_t *cb;
    char * httpstr;

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

    if (map.il_mode) {
        /* we are in inline mode. we need to do the accept on the socket
         * before reading any data, because supervisor cannot do this for us
         * as it is acting as our client now */
        struct sockaddr_in addr;
	socklen_t slen;
	    
	slen = sizeof(addr);
	client_fd = accept(client_fd, (struct sockaddr *)&addr, &slen);
	if (client_fd < 0) {
	    /* check if accept was unblocked by a signal */
	    if (errno == EINTR) {
		logmsg(LOGWARN, "accept unblocked by a signal\n");
                close(client_fd);
                return;
            }

	    logmsg(LOGWARN, "accepting connection: %s\n",
		   strerror(errno));
	}

	logmsg(LOGQUERY, 
	       "query from %s on fd %d\n", 
               inet_ntoa(addr.sin_addr), client_fd);
    }
    
    req = (qreq_t *) qryrecv(client_fd, map.stats->ts); 
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

    /* 
     * validate the query and find the relevant modules. 
     *
     * req->mdl will contain a pointer to the module that has to 
     * run the print() callback. 
     * 
     * req->src will point to the module that has to run load() or 
     * replay() callback. 
     * 
     * req->mdl and req->src are the same if load()/print() is all we 
     * need to do. they will be different for the load()/replay()/... 
     * cycle. 
     * 
     */
    httpstr = validate_query(req);
    if (httpstr != NULL) { 
	if (como_writen(client_fd, httpstr, 0) < 0) 
	    panic("sending data to the client [%d]", client_fd); 
        close(client_fd);
	return;
    } 
	
    /* 
     * if we have to retried the data using the replay callback of
     * another module instead of reading the output file of the module,
     * we need to create a new instance of the module itself. 
     */
    if (req->source) {
	module_t * x; 

	/* 
	 * creat a new instance of the module and initialize it 
	 */
        x = safe_calloc(1, sizeof(module_t));
        x->name = safe_strdup(req->mdl->name);
        x->description = safe_strdup(req->mdl->description);
	x->filter_str = safe_strdup(req->filter_str);
        parse_filter(x->filter_str, &(x->filter_tree), &(x->filter_cmp));
        x->output = safe_strdup(req->mdl->output);
        x->source = safe_strdup(req->mdl->source);
        x->msize = req->mdl->msize;
        if (x->msize)
	    x->mem = safe_calloc(1, x->msize);
        x->ca_hashsize = req->mdl->ca_hashsize;
        x->ex_hashsize = req->mdl->ex_hashsize;
        
        /* we get the new module arguments from the request command. 
	 * 
	 * XXX note that we do not distinguish between arguments for the 
  	 *     init() or print() callback. we assume the two callback will
	 *     just ignore any argument they do not understand 
	 *
	 */ 
	for (narg = 0; req->args[narg]; narg++) 
	    ; 
	x->args = safe_calloc(narg + 1, sizeof(char *));
	for (arg = 0; arg < narg; arg++)
	    x->args[arg] = safe_strdup(req->args[arg]);
        
        load_callbacks(x);
        cb = &(x->callbacks);
	x->flush_ivl = cb->init == NULL? 
		DEFAULT_CAPTURE_IVL: cb->init(x->mem, x->msize, x->args);
	if (x->flush_ivl == 0)
	    panicx("could not initialize the new module %s\n", x->name);

        /* init capture tables */
        x->ca_hashtable = NULL;
        
        /* init export tables */
        q_init_export_tables(x);
        
        /* replace the pointer in the query request */
	req->mdl = x; 
    } else { 
	/* the source is the same as the module */
	req->src = req->mdl;
    } 
    
    /* 
     * connect to the storage process, open the module output file 
     * and then start reading the file and send the data back 
     */
    storage_fd = create_socket("storage.sock", NULL);

    logmsg(V_LOGQUERY, "opening file for reading (%s)\n", req->src->output); 
    mode =  req->wait? CS_READER : CS_READER_NOBLOCK; 
    file_fd = csopen(req->src->output, mode, 0, storage_fd); 
    if (file_fd < 0) 
	panic("opening file %s", req->src->output);

    /* get start offset. this is needed because we access the file via
     * csmap instead of csreadp (that is not implemented yet) 
     */
    ofs = csgetofs(file_fd); 

    /*
     * initializations
     */
    httpstr = NULL;
    switch (req->format) {
    case Q_OTHER:
        asprintf(&httpstr, "HTTP/1.0 200 OK\nContent-Type: text/plain\n\n");
	/* pass thru */

    case Q_HTML:
        if (httpstr == NULL)
	    asprintf(&httpstr, "HTTP/1.0 200 OK\nContent-Type: text/html\n\n");

	/*
	 * produce a response header
	 */
	if (como_writen(client_fd, httpstr, 0) < 0) 
	    panic("sending data to the client");  
	free(httpstr);

	/* first print callback. we need to make sure that req->args != NULL. 
	 * if this is not the case we just make something up
	 */
	if (req->args == NULL) {
	    req->args = safe_calloc(1, sizeof(char **)); 
	    req->args[0] = NULL;
	} 
	printrecord(req->mdl, NULL, req->args, client_fd);
	break;
	
    case Q_COMO: 
	/*
	 * transmit the output stream description
	 */
	ret = como_writen(client_fd, (char*) req->src->callbacks.outdesc, 
			  sizeof(pktdesc_t)); 
	if (ret < 0)
	    panic("could not send pktdesc");

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

        len = req->src->bsize; 
        ptr = getrecord(file_fd, &ofs, req->src->callbacks.load, &len, &ts);
        if (ptr == NULL) {	/* no data, but why ? */
	    if (len == -1) 
		panic("reading from file %s\n", req->src->output); 

	    if (len == 0) {
		/* notify the end of stream to the module */
		if (req->format == Q_OTHER || req->format == Q_HTML) 
		    printrecord(req->mdl, NULL, NULL, client_fd); 
		logmsg(LOGQUERY, "reached end of file %s\n", req->src->output); 
		break;
	    }
	}

	/*
	 * Now we have either good data or or GR_LOSTSYNC.
	 * If lost sync, move to the next file and try again. 
	 */
	if (ptr == GR_LOSTSYNC) {
	    logmsg(LOGQUERY, "lost sync, trying next file %s\n", 
		req->src->output); 
	    ofs = csseek(file_fd);
	    continue;
	}

    	if (TS2SEC(ts) < req->start)	/* before the required time. */
	    continue;
    	if (TS2SEC(ts) >= req->end) {
	    /* 
	     * we have reached the end of the stream 
	     * we want to notify the module that there are 
	     * no more records so that it can cleanup data 
	     * structures and send the last messages if needed
	     */
	    if (req->source) {
		replay_source(req->mdl, req->src, NULL, client_fd);
	    } else { 
	       /* 
	        * ask the module to send the message footer if it 
		* has any to send. 
	        */  
		switch (req->format) { 
		case Q_OTHER:
		case Q_HTML:
		    printrecord(req->mdl, NULL, NULL, client_fd); 
		    break;

		case Q_COMO: 
		    replayrecord(req->src, NULL, client_fd);
		    break;
	    
		default:
		    break;
		} 
	    } 

	    logmsg(LOGQUERY, "query completed\n"); 
	    break;
	}

	if (req->source) {
	    replay_source(req->mdl, req->src, ptr, client_fd);
	} else { 
	    switch (req->format) { 
	    case Q_COMO: 	
		replayrecord(req->src, ptr, client_fd);
		break; 

	    case Q_RAW: 
		/* send the data to the query client */
		ret = como_writen(client_fd, ptr, len);
		if (ret < 0) 
		    panic("sending data to the client"); 
		break;
		
	    case Q_OTHER: 
	    case Q_HTML:
		printrecord(req->mdl, ptr, NULL, client_fd); 
		break;
	    }
	}
    }

    /* close the socket and the file */
    close(client_fd);
    csclose(file_fd); 
}
