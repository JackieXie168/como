/*
 * Copyright (c) 2004, Intel Corporation
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
#include <stdlib.h>
#include <fcntl.h>	/* F_GETFL */
#include <unistd.h>     /* read, write etc. */
#include <string.h>     /* bzero */
#include <errno.h>      /* errno */
#include <assert.h>

#include "como.h"
#include "sniffers.h"
#include "sniffer-list.h"

/* poll time (in usec) */
#define POLL_WAIT   1000

/* packet buffer */
#define PKT_BUFFER 	8192		
 
/* flush and freeze/unfreeze thresholds */
#define MB(m)				((m)*1024*1024)
#define FREEZE_THRESHOLD(mem)		(MB(mem)*3/4) 

/* global state */
extern struct _como map;

/* sniffer list and callbacks */
extern struct _sniffer *__sniffers[];

tailq_t expired_tables;  /* expired flow tables */


/*
 * -- match_desc
 * 
 * This function checks if the packet stream output by a source (sniffer or
 * module via dump interface) is compatible with the input requirements of
 * a module; it does so by checking the values of their pktdesc_t, in
 * particular matching the bitmask part.
 */
static int
match_desc(pktdesc_t *req, pktdesc_t *bid)
{
    char *a, *b;
    size_t i; 
    
    /* if req or bid are NULL they always match 
     * XXX this assumption could go away once we introduce meta-packet 
     *     fields (e.g., anonymized addresses, etc.)
     */
    if (!req || !bid)
        return 1;
    
    /* compare time granularity */ 
    if (req->ts < bid->ts)
        return 0;

    /* check if we are capturing enough bytes per packet */
    if (req->caplen > bid->caplen) 
	return 0; 
         
    a = (char *) req; 
    b = (char *) bid; 

    i = sizeof(req->ts) + sizeof(req->caplen); 
    while (i < sizeof(pktdesc_t)) { 
        if (a[i] & ~b[i])
            return 0;
        i++; 
    } 
    
    return 1;
}

#define SHMEM_USAGE(mdl) \
    map.stats->mdl_stats[(mdl)->index].mem_usage_shmem

/* 
 * -- create_table 
 * 
 * allocates and initializes a hash table
 */
static ctable_t *
create_table(module_t * mdl, timestamp_t ts) 
{
    ctable_t * ct; 
    size_t len;

    len = sizeof(ctable_t) + mdl->ca_hashsize * sizeof(void *);
    ct = new_mem(NULL, len, "new_flow_table");
    if (ct == NULL)
	return NULL;

    SHMEM_USAGE(mdl) += len;
    ct->bytes += len;

    ct->size = mdl->ca_hashsize;
    ct->first_full = ct->size;      /* all records are empty */
    ct->records = 0;
    ct->live_buckets = 0;
    ct->module = mdl;
    ct->mem = NULL;                 /* use the system's map */
    ct->ts = ts; 

    /*
     * save the timestamp indicating with flush interval this 
     * table belongs to. this information will be useful for 
     * EXPORT when it processes the flushed tables. 
     */
    ct->ivl = ts - (ts % mdl->flush_ivl);
    return ct; 
}


/*
 * -- flush_table
 *
 * Called by capture_pkt() process when a timeslot is complete.
 * it flushes the flow table (if it exists and it is non-empty)
 * and then it allocates a new one.
 *
 */
static void
flush_table(module_t * mdl, tailq_t * expired)
{
    ctable_t *ct;

    logmsg(V_LOGCAPTURE, "flush_table start\n");

    /* check if the table is there and if it is non-empty */
    ct = mdl->ca_hashtable;
    assert(ct != NULL); 
    assert(ct->records > 0); 

    logmsg(V_LOGCAPTURE,
	"flush_tables %p(%s) buckets %d records %d live %d\n", ct,
	mdl->name, ct->size, ct->records, ct->live_buckets);

    /* update the hash table size for next time if it is underutilized 
     * or overfull. 
     */

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

    /* add to linked list and remove from here. */
    TQ_APPEND(expired, ct, next_expired);
    map.stats->table_queue++; 
    mdl->ca_hashtable = NULL;

    logmsg(V_LOGCAPTURE, "module %s flush_table done.\n", mdl->name);
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
static timestamp_t
capture_pkt(module_t * mdl, void *pkt_buf, int no_pkts, int * which, 
	    tailq_t * expired)
{
    pkt_t *pkt = (pkt_t *) pkt_buf;
    timestamp_t max_ts; 
    int i;
    int new_record;
    int record_size; /* effective record size */


    record_size = mdl->callbacks.ca_recordsize + sizeof(rec_t);

    if (mdl->ca_hashtable == NULL)
	mdl->ca_hashtable = create_table(mdl, pkt->ts); 

    max_ts = 0; 
    for (i = 0; i < no_pkts; i++, pkt++) { 
        rec_t *prev, *cand;
        uint32_t hash;
        uint bucket;

	if (pkt->ts >= max_ts) {
	    max_ts = pkt->ts; 
	} else {
	    logmsg(LOGCAPTURE,
		"pkt no. %d timestamps not increasing (%u.%06u --> %u.%06u)\n", 
		i, TS2SEC(max_ts), TS2USEC(max_ts), 
		TS2SEC(pkt->ts), TS2USEC(pkt->ts));
	}

        /* flush the current flow table, if needed */
	if (mdl->ca_hashtable) {
	    ctable_t * ct = mdl->ca_hashtable; 
	
	    ct->ts = pkt->ts; 
	    if (ct->ts >= ct->ivl + mdl->flush_ivl && ct->records) {  
		flush_table(mdl, expired);
		mdl->ca_hashtable = NULL;
	    }
	}
	if (!mdl->ca_hashtable) {
	    mdl->ca_hashtable = create_table(mdl, pkt->ts); 
	    if (!mdl->ca_hashtable) {
		/* XXX no memory, we keep going. 
		 *     need better solution! */
		logmsg(LOGWARN, "out of memory for %s, skipping pkt\n",
		    mdl->name);
		continue;	
	    } 
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
                x = new_mem(mdl->ca_hashtable->mem, record_size, "new");
		if (x == NULL)
		    continue;		/* XXX no memory, we keep going. 
					 *     need better solution! */

                SHMEM_USAGE(mdl) += record_size;
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
	    cand = new_mem(mdl->ca_hashtable->mem, record_size, "new");
	    if (cand == NULL)
		continue;
            SHMEM_USAGE(mdl) += record_size;
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
	cand->full = mdl->callbacks.update(pkt, cand, new_record);
	end_tsctimer(map.stats->ca_updatecb_timer); 
    }

    return max_ts; 
}

/*
 * -- ca_init_module
 *
 * Do capture-specific initialization of a module.
 * Make sure module is compatible with current sniffers and
 * initialize capture hashsize.
 * Also parse the filter string from the config file for this module.
 */
static void
ca_init_module(module_t *mdl)
{
    source_t *src;
    
    /* Default values for filter stuff */
    mdl->filter_tree = NULL;
    
    /* Parse the filter string from the configuration file */
    parse_filter(mdl->filter_str, &(mdl->filter_tree), NULL); 
    
    /*
     * we browse the list of sniffers to make sure that this module
     * understands the packets coming them. to do so, we compare the
     * indesc defined in the module callbacks data structure
     * with the output descriptor defined in the source.
     * if there is a mismatch, the module is shut down.
     */
    for (src = map.sources; src != NULL; src = src->next) {
        if (!match_desc(mdl->callbacks.indesc, src->output)) {
            logmsg(LOGWARN, "module %s does not get %s packets\n",
                mdl->name, src->cb->name);
            mdl->status = MDL_INCOMPATIBLE;
            map.stats->modules_active--;
            break;
        }
    }
}

/*
 * -- drop table
 *
 * Free all memory in a table, and update memory counters.
 */
static void
drop_table(ctable_t *ct, module_t *mdl)
{
    int record_size = mdl->callbacks.ca_recordsize + sizeof(rec_t);

    for (; ct->first_full < ct->size; ct->first_full++) {
        rec_t *rec = ct->bucket[ct->first_full]; 
        while (rec != NULL) {
            rec_t *end = rec->next;

            while (rec->prev)
                rec = rec->prev;

            while (rec != end) {
                rec_t *p = rec->next;
                mfree_mem(NULL, rec, 0);
                SHMEM_USAGE(mdl) -= record_size;
                rec = p;
            }
        }
    }

    SHMEM_USAGE(mdl) -= sizeof(ctable_t) + ct->size * sizeof(void *);
    mfree_mem(NULL, ct, 0);
}

/*
 * -- disable_module
 *
 * When a module is disabled, capture must drop its
 * tables to free as much memory as possible
 */
static void
ca_disable_module(module_t *mdl)
{
    ctable_t *ct, *prev, *head/*, *tail*/;

    if (mdl->ca_hashtable)
        drop_table(mdl->ca_hashtable, mdl);
    mdl->ca_hashtable = NULL;

    head = TQ_HEAD(&expired_tables);
    ct = head;
    prev = NULL;

    while (ct != NULL) {
        ctable_t *next = ct->next_expired;

        if (ct->module->index != mdl->index)
            prev = ct;

        else { /* table belongs to module to be disabled */

            if (prev == NULL) /* first table in the queue */
                expired_tables.__head = next;
            else              /* not the first table */
                prev->next_expired = next;

            if (next == NULL) /* last table in the queue */
                expired_tables.__tail = prev;

            drop_table(ct, mdl);
        }
        ct = next;
    }
}

/* callbacks */
static proc_callbacks_t capture_callbacks = {
    NULL,
    ca_init_module,
    NULL,   /* enable_module not needed because necessary structures
               are allocated when necessary in capture. */
    ca_disable_module, /* disable and remove are the same in capture */
    ca_disable_module
};

/*
 * -- filter()
 *
 * Filter function.
 * When a packet arrives, we evaluate an expression tree for each filter.
 * This needs to be optimized.
 *
 */
int *
filter(pkt_t *pkt, int n_packets, int n_out, module_t *modules)
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
 * -- process_batch 
 * 
 * take a batch of packets, run them thru the filter and 
 * then call the capture_pkt function for each individual 
 * module. return the last timestamp of the batch.
 * 
 */
static timestamp_t
process_batch(pkt_t *pkts, unsigned count, tailq_t *expired) 
{
    int * which;
    int idx;

    /*
     * Select which classifiers need to see which packets The filter()
     * function (see comments in file base/template) returns a
     * bidimensional array of integer which[cls][pkt] where the first
     * index indicates the classifier, the second indicates the packet
     * in the batch.  The element of the array is set if the packet is
     * of interest for the given classifier, and it is 0 otherwise.
     */
    logmsg(V_LOGCAPTURE, 
	   "calling filter with pkts %p, n_pkts %d, n_out %d\n", 
	   pkts, count, map.module_count); 
    start_tsctimer(map.stats->ca_filter_timer); 
    which = filter(pkts, count, map.module_count, map.modules);
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
    for (idx = 0; idx < map.module_count; idx++) {
	module_t * mdl = &map.modules[idx]; 

	if (mdl->status != MDL_ACTIVE) {
	    /* Even if the module isn't active, we still must skip
             * some bytes in which[]
             */
            which += count;
            continue;
        }

	assert(mdl->name != NULL);
	logmsg(V_LOGCAPTURE,
	       "sending %d packets to module %s for processing",
	       count, map.modules[idx].name);

	start_tsctimer(map.stats->ca_module_timer); 
	capture_pkt(mdl, pkts, count, which, expired);
	end_tsctimer(map.stats->ca_module_timer); 
	which += count; /* next module, new list of packets */
    }

    /*  
     * get batch timestamp, i.e. the timestamp of the first packet 
     * of the batch. 
     */
    return pkts[count - 1].ts;
}


/* 
 * -- setup_sniffers 
 * 
 * Browse the list of sniffers to identify all the file descrptors 
 * that need a select() and to set the appropriate polling interval. 
 * We also switch off sniffers if needed. The function returns the 
 * fd_set for the select, the max file descriptor and the timeout value. 
 * 
 */
int 
setup_sniffers(source_t *src, fd_set *fds, int *max_fd, struct timeval *tout) 
{
    source_t * p; 
    int active; 

    active = 0; 
    tout->tv_sec = 3600; 
    tout->tv_usec = 0; 
    for (p = src; p != NULL; p = p->next) { 
	/* reset the TOUCHED bit */
	src->flags &= ~SNIFF_TOUCHED;

	/* 
	 * remove the file descriptor from the list independently if 
	 * it is a valid one or not. we will add it later if needed. 
	 * del_fd() deals with invalid fd. 
	 */
	*max_fd = del_fd(src->fd, fds, *max_fd); 
                
	if (src->flags & SNIFF_INACTIVE)  
	    continue;		/* go to next one */
                
	active++; 

	if (src->flags & SNIFF_FROZEN) 
	    continue; 		/* do nothing */

	/*  
	 * if this sniffer uses polling, check if the polling interval 
	 * is lower than the current timeout.
	 */
	if (src->flags & SNIFF_POLL) {
	    if (src->polling < TIME2TS(tout->tv_sec, tout->tv_usec)) {
		tout->tv_sec = TS2SEC(src->polling);
		tout->tv_usec = TS2USEC(src->polling);
	    }
	}

	/* 
	 * if this sniffer uses select(), add the file descriptor 
	 * to the list of file descriptors. 
	 */
	if (src->flags & SNIFF_SELECT) 
	    *max_fd = add_fd(src->fd, fds, *max_fd); 
    }

    return active; 
}


/*
 * -- capture_mainloop
 *
 * This is the CAPTURE mainloop. It first prepares the filter
 * (that could be compiled on the fly) and then opens the sniffer
 * device. Then the real mainloop starts and it sits on a select
 * waiting for messages from EXPORT, the SUPERVISOR or for packets
 * from the sniffer.
 *
 */
void
capture_mainloop(int accept_fd)
{
    pkt_t pkts[PKT_BUFFER]; 	/* packet buffer */
    memlist_t * flush_map;	/* freed blocks in the flow tables */
    int active_sniffers;	/* how many sniffers are left ? */
    int sent2export = 0;	/* message sent to EXPORT */
    int export_fd; 		/* descriptor used to talk to EXPORT */
    struct timeval tout;
    source_t *src;
    fd_set valid_fds;
    int max_fd;
    int table_sent;
    int idx;

    /* initialize select()able file descriptors */
    max_fd = 0;
    FD_ZERO(&valid_fds);

    /* get ready to accept requests from EXPORT process(es) */
    max_fd = add_fd(accept_fd, &valid_fds, max_fd);
    export_fd = -1; 

    /* initialize the timers */
    init_timers(); 

    /* 
     * browse the list of sniffers and start them
     */
    for (src = map.sources; src; src = src->next) {
	if (src->cb->sniffer_start(src) < 0) { 
	    src->flags |= SNIFF_INACTIVE; 
	    logmsg(LOGWARN, 
		   "sniffer %s (%s): %s\n",
		   src->cb->name, src->device, strerror(errno));
	    continue; 
	} 
	assert(src->flags & SNIFF_TOUCHED); 
    }
    active_sniffers = 0;

    /*
     * allocate memory used to pass flow tables
     * between CAPTURE and EXPORT
     */
    flush_map = new_memlist(32);

    /* init expired flow tables queue */
    TQ_HEAD(&expired_tables) = NULL;
    map.stats->table_queue = 0; 

    /*
     * The first message from supervisor contain the
     * modules and filter function.
     */
    logmsg(LOGDEBUG, "wait for 1st msg from SU\n");
    recv_message(map.supervisor_fd, &capture_callbacks);

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

	start_tsctimer(map.stats->ca_full_timer); 

        errno = 0;

	/* always listen to supervisor */
	max_fd = add_fd(map.supervisor_fd, &valid_fds, max_fd);

	/* 
	 * browse the list of sniffers. if any of them have changed 
  	 * the settings then go thru all of them to rebuild the list of 
	 * descriptors to use in the select() as well as to set the 
	 * correct polling interval. 
	 */
	for (src = map.sources; src; src = src->next) {
	    if (src->flags & SNIFF_TOUCHED) { 
		active_sniffers = setup_sniffers(map.sources, &valid_fds, 
					 &max_fd, &tout); 
		if (active_sniffers == 0) 
		    logmsg(LOGWARN, "no sniffers left. waiting for queries\n");
		break;
	    } 
	} 

	/* 
	 * if no sniffers are left, flush all the tables given that
	 * no more packets will be received. 
	 */
	if (active_sniffers == 0) { 
	    for (idx = 0; idx < map.module_count; idx++) {
		module_t * mdl = &map.modules[idx];
		ctable_t *ct = mdl->ca_hashtable;

		if (ct && ct->records)  
		    flush_table(mdl, &expired_tables);
	    }
	} 

        /* need to write and have no pending jobs from export */
        if (!sent2export && TQ_HEAD(&expired_tables) && export_fd >= 0) {
	    msg_t x;	/* message to EXPORT */
	    int ret; 

            x.m  = flush_map;
            x.ft = TQ_HEAD(&expired_tables);
            ret = write(export_fd, &x, sizeof(x)); 
            if (ret != sizeof(x))
                panic("error writing export_fd got %d", ret);  

            TQ_HEAD(&expired_tables) = NULL;   /* we are done with this. */
	    map.stats->table_queue = 0; /* reset counter */
            sent2export = 1;            /* wait response from export */
	    table_sent = 1; 		/* for profiling */
        }

	/* wait for messages, sniffers or up to the polling interval */
	r = valid_fds;
	t = tout; 
	n_ready = select(max_fd, &r, NULL, NULL, &t);
	if (n_ready < 0)
	    panic("select"); 

	start_tsctimer(map.stats->ca_loop_timer); 

        if (FD_ISSET(accept_fd, &r)) { 
	    /* EXPORT process wants to connect */
	    export_fd = accept(accept_fd, NULL, NULL);
	    if (export_fd < 0)
		panic("accepting export process"); 
	    max_fd = add_fd(export_fd, &valid_fds, max_fd);
	}

        if (export_fd >= 0 && FD_ISSET(export_fd, &r)) {
	    int ret;
	    msg_t reply;

	    /* EXPORT replies to a message */
	    errno = 0;	/* reset */
	    ret = read(export_fd, &reply, sizeof(reply));
	    if (ret != 0 && errno != EAGAIN) {
		if (ret != sizeof(reply))
		    panic("error reading export_fd got %d", ret);

		if (reply.m != flush_map)
		    panicx("bad flush_map from export_fd");

		/* ok, export freed memory into the map for us */
		mem_merge_maps(NULL, flush_map);
	
                /* update memory counters */
                for (idx = 0; idx < map.module_count; idx++) {
                    module_t *mdl = &map.modules[idx];
                    MDL_STATS(mdl)->mem_usage_shmem -=
                        MDL_STATS(mdl)->mem_usage_shmem_f;
                    MDL_STATS(mdl)->mem_usage_shmem_f = 0;
                }

		sent2export = 0;   /* mark no pending jobs */
	    }
        }

        if (FD_ISSET(map.supervisor_fd, &r))
            recv_message(map.supervisor_fd, &capture_callbacks);

        /*
	 * check sniffers for packet reception (both the ones that use 
	 * select() and the ones that don't)
         */
	for (src = map.sources; src; src = src->next) {
	    int count;

	    if (src->flags & (SNIFF_INACTIVE|SNIFF_FROZEN))
		continue;	/* inactive/frozen devices */

	    if ((src->flags & SNIFF_SELECT) && !FD_ISSET(src->fd, &r))
		continue;	/* nothing to read here. */

	    start_tsctimer(map.stats->ca_sniff_timer); 
	    count = src->cb->sniffer_next(src, pkts, PKT_BUFFER);
	    end_tsctimer(map.stats->ca_sniff_timer); 

	    if (count == 0)
		continue;

            if (count < 0) {
		src->flags |= SNIFF_INACTIVE|SNIFF_TOUCHED; 
                src->cb->sniffer_stop(src);
                continue;
            }

	    /* update drop statistics */
	    map.stats->drops += src->drops;

	    logmsg(V_LOGCAPTURE, "received %d packets from sniffer\n", count);
	    map.stats->pkts += count; 

	    start_tsctimer(map.stats->ca_pkts_timer); 
	    map.stats->ts = process_batch(pkts, count, &expired_tables);
	    end_tsctimer(map.stats->ca_pkts_timer); 

	    if (map.stats->ts < map.stats->first_ts) 
	        map.stats->first_ts = map.stats->ts;
        }

	/* 
	 * we check the memory usage and stop any sniffer that is 
  	 * running from file if the usage is above the FREEZE_THRESHOLD. 
	 * this will give EXPORT some time to process the tables and free
	 * memory. we resume as soon as memory usage goes below the 
	 * threshold. 
	 * 
	 */
	map.stats->mem_usage_cur = memory_usage(); 
	map.stats->mem_usage_peak = memory_peak(); 
	if (map.stats->mem_usage_cur > FREEZE_THRESHOLD(map.mem_size)) {
	    for (src = map.sources; src; src = src->next) {
		if (src->flags & SNIFF_INACTIVE) 
		    continue; 

		if (src->flags & SNIFF_FILE) 
		    src->flags |= SNIFF_FROZEN|SNIFF_TOUCHED; 
	    } 
	} else {
	    /* 
	     * memory is now below threshold. unfreeze any source
	     */
	    for (src = map.sources; src; src = src->next) {
		if (src->flags & SNIFF_FROZEN) {
		    src->flags &= ~SNIFF_FROZEN; 
		    src->flags |= SNIFF_TOUCHED; 
		} 
	    } 
	}

	end_tsctimer(map.stats->ca_loop_timer);
	end_tsctimer(map.stats->ca_full_timer);

	if (table_sent) {
	    /* store profiling information every time 
	     * tables are sent to EXPORT 
	     */
	    print_timers();
	    reset_timers();
	    table_sent = 0; 
 	} 
    }

    logmsg(LOGWARN, "Capture: no sniffers left, terminating.\n");
}
/* end of file */
