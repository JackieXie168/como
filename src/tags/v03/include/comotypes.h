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

#ifndef _COMOTYPES_H
#define _COMOTYPES_H

#include <inttypes.h>
#include "stdpkt.h"
#include "sniffers.h"

/*
 * New definitions of object types
 */
typedef struct _module          module_t;       /* module package */
typedef struct _callbacks       callbacks_t;    /* callbacks */
typedef struct _como_msg        msg_t;          /* message capture/export */

typedef struct _memlist         memlist_t;      /* opaque, memory manager */

typedef struct _record 	        rec_t;          /* table record header */
typedef struct _capture_table   ctable_t;       /* capture hash table */
typedef struct _export_table    etable_t;       /* export hash table */
typedef struct _export_array    earray_t;       /* export record array */

typedef struct _statistics	stats_t; 	/* statistic counters */

typedef uint64_t 		timestamp_t;	/* NTP-like timestamps */

typedef enum {
    MDL_INVALID, 			/* unused for debugging */
    MDL_UNUSED,				/* just loaded */
    MDL_INCOMPATIBLE,			/* not compatible with sniffer */
    MDL_ACTIVE, 			/* active and processing packets */
    MDL_PASSIVE, 			/* passive waiting for queries */
    MDL_FROZEN				/* temporary frozen */
} state_t;				

/*
 * Module callbacks
 */

/**
 * init_fn() does whatever is needed to initialize a module,
 * For the time being, just initialize the private memory for the module,
 * and take arguments from the config file.
 * Returns 0 on success, >0 on error.
 * Not mandatory, default does nothing and returns 0.
 */
typedef int (init_fn)(void *mem, size_t msize, char * args[]);

/**
 * check_fn() ... checks for the validity of a packet before
 * trying to hash/match it. It can be used to implement an additional
 * filter after the one in the config file (eg to avoid to re-do
 * the checks every time in hash(), because we cannot trust the
 * user-supplied filter in the config file to be correct).
 * 
 * Returns 1 on success, 0 on failure.
 * Not mandatory, default returns 1.
 */
typedef int (check_fn)(pkt_t *pkt);

/**
 * hash_fn() computes a 32-bit hash value for a packet.
 * Not mandatory, the default returns 0 (which makes further classification
 * steps potentially very expensive).
 */
typedef uint32_t (hash_fn)(pkt_t *pkt);

/**
 * match_fn() checks that a packet belongs to the record passed as second
 * argument.
 * Returns 1 on success, 0 on failure.
 * Not mandatory, default returns 1. XXX luigi is not convinced.
 */
typedef int (match_fn)(pkt_t *pkt, void *fh);

/**
 * update_fn() run from capture to update *fh with the info from *pkt.
 * is_new is 1 if *fh was never used before hence needs to be
 * initialized.
 * Returns 1 if *fh becomes full after the call, 0 otherwise (failure is
 * not contemplated).
 * Mandatory.
 */
typedef int (update_fn)(pkt_t *pkt, void *fh, int is_new);

/**
 * ematch_fn() same as match_fn() but now it uses the current capture
 * record instead of the packet.
 * Returns 1 on match, 0 on no-match.
 * Not mandatory, default returns 1; useless if there's no export_fn().
 * Called by export upon receipt of *eh from capture.
 */
typedef int (ematch_fn)(void *eh, void *fh);

/**
 * export_fn() same as update_fn(), is the core of export's processing.
 * It updates *efh with the info in *fh.
 * new_rec = 1 if *fh has just been allocated.
 * Returns 1 if *fh becomes full after the call, 0 otherwise (failure is
 * not contemplated).
 * Not mandatory; if defined, an action_fn() should be defined too.
 */
typedef int (export_fn)(void *efh, void *fh, int new_rec);

/**
 * compare_fn() is the compare function used by qsort.
 * If defined, it means that the records are sorted before being scanned
 * by export.
 * Not mandatory; useless if there's no export_fn().
 */
typedef int (compare_fn)(const void *, const void *);

/**
 * action_fn() called by export to determine if a record can be discarded.
 * Returns a bitmap on what to do with the record given the current time t
 * and the number, count, of calls on this table.
 *	ACT_DISCARD	discard the record after this step;
 *	ACT_STORE	store the record;
 *	ACT_STOP	stop the scanning after this record
 *      ACT_GO		start scanning all the records
 * 
 * This function if called with fh = NULL and count = 0 indicates 
 * that the action must be taken on the entire table. In this case
 * an ACT_STOP means that no record is processed at all. ACT_GO instead
 * makes export process the entire table (and sort it if needed).
 * Not mandatory; if defined, an export_fn() should be defined too.
 * 
 */
typedef int (action_fn)(void * fh, timestamp_t t, int count);
#define	ACT_DISCARD	0x0400
#define	ACT_STORE	0x4000
#define	ACT_STOP	0x0040
#define ACT_GO		0x0010
#define	ACT_MASK	(ACT_DISCARD|ACT_STORE|ACT_STOP|ACT_GO)

/**
 * store_fn() writes the record in the buffer,
 * returns the actual len (0 is valid), or -1 on error.
 * Mandatory.
 * XXX in case of failure e.g. for lack of room, we don't know what to do.
 * This is always due to a configuration error (because in write mode,
 * the storage module will always give you what you requested as long as
 * it is not larger than a single file). So the response to this should
 * be disable the module or some other strong action.
 */
typedef ssize_t (store_fn)(void *, char * buf, size_t);

/**
 * load_fn() given a buffer, returns the size of the first record in the
 * buffer and the associated timestamp in *ts.
 * On error returns 0 and leaves *ts invalid.
 * Mandatory.
 */
typedef size_t (load_fn)(char *buf, size_t len, timestamp_t * ts);

/**
 * print_fn() given a data buffer, returns a printable
 * representation of the content of the data in a static buffer.
 * Returns the length in *len. It can receive arguments in the array args
 * (the last element is NULL) to format the string. 
 * This function is overloaded. If buf == NULL and args != NULL, it indicates
 * that this is the first call to print() within a query. If buf == NULL and
 * args == NULL, this is the last call of print(). If buf != NULL and 
 * args == NULL, this is a call of print() for one valid record. 
 * On error returns NULL.
 * Optional
 */
typedef char * (print_fn)(char *buf, size_t *len, char * const args[]);

/**
 * replay_fn() - given a data buffer (ptr), returns a reconstructed packet 
 * trace in the output buffer (out). The output buffer is allocated by the 
 * caller. 
 * Returns the number of packet left to send, -1 on error. 
 * out_buf_len is also updated to indicate the valid bytes in out. 
 * Not mandatory.
 */
typedef int (replay_fn)(char *ptr, char *out, size_t * out_buf_len);

/*
 * This structure contains the callbacks for a classifier.
 * Each classifier which is implemented as a shared
 * object is expected to export a structure of this kind,
 * named 'callbacks', properly initialized.
 */
struct _callbacks {
    size_t ca_recordsize; 
    size_t ex_recordsize; 
    
    pktdesc_t   * const indesc;   /* packet requirements */
    pktdesc_t   * const outdesc;  /* packet offer */

    /* callbacks called by the capture process */
    init_fn     * const init;
    check_fn    * const check;
    hash_fn     * const hash;
    match_fn    * const match;
    update_fn   * const update;

    /* callbacks called by the export process */
    ematch_fn   * const ematch;  
    export_fn   * const export;
    compare_fn  * const compare;
    action_fn   * const action;
    store_fn    * const store; 

    /* callbacks called by the query process */
    load_fn     * const load;
    print_fn    * const print;
    replay_fn   * const replay;
};


/*
 * Packet filter.
 *
 * On input, a list of packets and a count. On output, it returns the
 * number of outputs in *n_outputs, and also allocates and fills a
 * matrix of n_output rows, n_packet columns, indicating,
 * for each output, who is going to receive which packets.
 * The pointer to the matrix is returned by the function.
 *
 * For the time being, the array is one of integers. Later it
 * will be packed to use bits.
 */
typedef int *(filter_fn)(void *pkt_buf, int n_packets, int n_outputs);


/*
 * "Module" data structure. It needs a set of configuration parameters
 * (e.g., weigth, base output directory, etc.), some runtime information
 * (e.g., CPU usage stats), and finally a list of classifier that are
 * associated to it.
 */
struct _module {
    int index;          	/* order in the array of classifiers */
    char * name;		/* name of the module */
    char * description;		/* module description */
    char * filter; 	        /* filter expression */
    char * output;              /* output file basename */
    char ** args;               /* parameters for the module */
    char * source;              /* filename of the shared lib. */
    void * mem;           	/* private memory for the classifier */
    size_t msize;          	/* size of private memory */
    callbacks_t callbacks;      /* callbacks (static, from the shared obj) */

    state_t status; 		/* current module status */
    size_t memusage; 		/* current memory usage */

    ctable_t *ca_hashtable;  	/* capture hash table */
    uint ca_hashsize;    	/* capture hash table size (by config) */
    timestamp_t min_flush_ivl;  /* min interval between two table flushes */
    timestamp_t max_flush_ivl;  /* max interval between two table flushes */

    etable_t *ex_hashtable;  	/* export hash table */
    uint ex_hashsize; 	   	/* export hash table size (by config) */
    earray_t *ex_array; 	/* array of export records */

    int	file;			/* output file for export records */
    size_t bsize;		/* block size */
    off_t streamsize;       	/* max bytestream size */
    off_t offset;		/* current offset in the export file */
};


/*
 * _record is the header assumed to be in front of each 
 * record descriptor for the purpose of hash table manipulations
 * both in export and capture.
 * One pointer (next) for the linked list, one for the hash table
 * manipulation, and one word for the hash function. 
 * 
 * The pointer (prev) is used differently by capture and export. 
 * In capture it points to the previous block of the same record (this is 
 * to implement variable record sizes with fixed-size data structures), 
 * in export it points to the previous record in the same bucket. 
 */
struct _record {
    rec_t * next;          /* next in bucket or in record */
    rec_t * prev;          /* previous block same record */
    uint32_t hash;          /* full hash value (from packets) */
    int full;               /* set if this record is full */
};


/*
 * Message exchanged between CAPTURE and EXPORT.
 */
struct _como_msg {
    memlist_t * m;
    ctable_t * ft;
};


/*
 * Flow table descriptor -- one for each protocol or group of protocols.
 * The number of buckets ("size") is a parameter. While we insert/remove
 * elements we also track the number of active buckets and entries.
 *
 * As individual flow descriptors become full, they are linked off
 * new ones in the chain.
 */
struct _capture_table {
    module_t *module;		/* module that is using this table */
    memlist_t *mem;		/* map to be used for malloc/free */
    ctable_t * next_expired;	/* next expired table */
    timestamp_t ts;             /* last observed packet */ 
    timestamp_t ivl;            /* first insertion (flush_ivl aligned) */
    uint32_t size;		/* size of hash table */
    uint32_t records;		/* no. active records */
    uint32_t first_full;	/* index of first full slot */
    uint32_t live_buckets;	/* no. active buckets */
    rec_t *bucket[0];           /* pointers to records -- actual hash table */
};


/*
 * export table descriptor.
 * This is persistent, and records are flushed according to the 
 * discard strategy of the module. 
 */
struct _export_table {
    timestamp_t ts;             /* time of most recent update */
    uint32_t size;		/* size of hash table */
    uint32_t live_buckets;	/* no. active buckets */
    uint32_t records;		/* no. active records */
    rec_t *bucket[0];		/* pointers to records -- actual hash table */
};


/* 
 * export record array 
 * 
 * This is persistent EXPORT and keeps all active records in an 
 * array that will then be used to sort records, and browse thru 
 * all the records for storing/discarding them. 
 */ 
struct _export_array { 
    uint32_t size; 		/* size of array */
    uint32_t first_full;	/* first full record */
    rec_t *record[0]; 		/* pointers to records */
};


/* 
 * statistic counters 
 */
struct _statistics { 
    struct timeval start; 	/* CoMo start time */

    int modules_active;		/* no. of modules processing packets */

    size_t mem_usage_cur; 	/* current shared memory usage */
    size_t mem_usage_peak; 	/* peak shared memory usage */

    uint64_t pkts; 		/* sniffed packets so far */

};
    

#endif /* _COMOTYPES_H */
