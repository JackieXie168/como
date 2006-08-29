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

#ifndef _COMOTYPES_H
#define _COMOTYPES_H

#include <inttypes.h>
#include <sys/time.h>
#include "stdpkt.h"
#include "filter.h"

/*
 * New definitions of object types
 */
typedef struct _como		como_t;		/* main como map */
typedef struct _module          module_t;       /* module package */
typedef struct _alias           alias_t;        /* aliases */
typedef uint32_t		procname_t;	/* process names */
typedef struct _callbacks       callbacks_t;    /* callbacks */
typedef struct _callbacks       module_cb_t;    /* callbacks */
typedef struct _flushmsg        flushmsg_t;     /* message capture/export */

typedef struct memmap_t         memmap_t;      /* opaque, memory manager */
typedef struct _expiredmap	expiredmap_t;	/* expired list of mem maps */

typedef struct _record 	        rec_t;          /* table record header */
typedef struct _capture_table   ctable_t;       /* capture hash table */
typedef struct _export_table    etable_t;       /* export hash table */
typedef struct _export_array    earray_t;       /* export record array */

typedef struct _tsc		tsc_t; 		/* timers (using TSC) */
typedef struct _statistics	stats_t; 	/* statistic counters */

typedef struct _como_metadesc	metadesc_t;
typedef struct _como_metatpl	metatpl_t;

typedef struct _como_headerinfo headerinfo_t;

typedef struct _como_allocator  allocator_t;

typedef uint64_t 		timestamp_t;	/* NTP-like timestamps */

typedef enum runmodes_t { 
    NORMAL = 0, 
    INLINE = 1
} runmodes_t;

typedef enum status_t {
    MDL_UNUSED,				/* module unused, free entry */
    MDL_LOADING,            		/* module is being loaded */
    MDL_INCOMPATIBLE,			/* not compatible with sniffer */
    MDL_ACTIVE, 			/* active and processing packets */
    MDL_ACTIVE_REPLAY,			/* active only to replay records */
    MDL_DISABLED            		/* disabled or turned off */
} status_t;

typedef enum running_t {
    RUNNING_NORMAL,			/* running normally in CAPTURE */
    RUNNING_ON_DEMAND			/* running in query on demand */
} running_t;


typedef void * (*alc_malloc_fn) (size_t size,
				 const char * file, int line,
				 void *data);

typedef void * (*alc_calloc_fn) (size_t nmemb, size_t size,
				 const char * file, int line,
				 void *data);

typedef void * (*alc_free_fn)   (void *ptr,
				 const char * file, int line,
				 void *data);

struct _como_allocator {
    alc_malloc_fn	malloc;
    alc_calloc_fn	calloc;
    alc_free_fn		free;
    void *		data;
};

#define alc_malloc(alc, size)		\
    (alc)->malloc(size, __FILE__, __LINE__, (alc)->data)

#define alc_calloc(alc, nmemb, size)	\
    (alc)->calloc(nmemb, size, __FILE__, __LINE__, (alc)->data)

#define alc_free(alc, ptr)		\
    (alc)->free(ptr, __FILE__, __LINE__, (alc)->data)

/*
 * Module callbacks
 */

/**
 * init_fn() does whatever is needed to initialize a module,
 * For the time being, just initialize the private memory for the module,
 * and take arguments from the config file.
 * Returns the capture flush interval on success, 0 on failure. 
 * Not mandatory, default does nothing and returns DEFAULT_CAPTURE_IVL.
 */
typedef timestamp_t (init_fn)(void * self, char * args[]);

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
typedef int (check_fn)(void * self, pkt_t *pkt);

/**
 * hash_fn() computes a 32-bit hash value for a packet.
 * Not mandatory, the default returns 0 (which makes further classification
 * steps potentially very expensive).
 */
typedef uint32_t (hash_fn)(void * self, pkt_t *pkt);

/**
 * match_fn() checks that a packet belongs to the record passed as second
 * argument.
 * Returns 1 on success, 0 on failure.
 * Not mandatory, default returns 1. XXX luigi is not convinced.
 */
typedef int (match_fn)(void * self, pkt_t *pkt, void *fh);

/**
 * update_fn() run from capture to update *fh with the info from *pkt.
 * is_new is 1 if *fh was never used before hence needs to be
 * initialized.
 * fs points to current flush state.
 * Returns 1 if *fh becomes full after the call, 0 otherwise (failure is
 * not contemplated).
 * Mandatory.
 */
typedef int (update_fn)(void * self, pkt_t *pkt, void *fh, int is_new);

/**
 * flush_fn() run from capture at every flush interval to obtain a clean
 * flush state.
 * Not mandatory, default module state is NULL.
 */
typedef void * (flush_fn)(void * self);

/**
 * ematch_fn() same as match_fn() but now it uses the current capture
 * record instead of the packet.
 * Returns 1 on match, 0 on no-match.
 * Not mandatory, default returns 1; useless if there's no export_fn().
 * Called by export upon receipt of *eh from capture.
 */
typedef int (ematch_fn)(void * self, void *eh, void *fh);

/**
 * export_fn() same as update_fn(), is the core of export's processing.
 * It updates *efh with the info in *fh.
 * new_rec = 1 if *fh has just been allocated.
 * fs points to current flush state.
 * Returns 1 if *fh becomes full after the call, 0 otherwise (failure is
 * not contemplated).
 * Not mandatory; if defined, an action_fn() should be defined too.
 */
typedef int (export_fn)(void * self, void *efh, void *fh, int new_rec);

/**
 * compare_fn() is the compare function used by qsort.
 * If defined, it means that the records are sorted before being scanned
 * by export.
 * Not mandatory; useless if there's no export_fn().
 */
typedef int (compare_fn)(const void *, const void *);

/**
 * action_fn() called by export to determine if a record can be discarded.
 * Returns a bitmap on what to do with the record given the beginning of the
 * interval i, the current time t and the number, count of calls on this table.
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
typedef int (action_fn)(void * self, void * fh, timestamp_t i,
			timestamp_t t, int count);
#define	ACT_DISCARD	0x0400
#define	ACT_STORE	0x4000
#define	ACT_STORE_BATCH	0x8000
#define	ACT_STOP	0x0040
#define ACT_GO		0x0010
#define	ACT_MASK	(ACT_DISCARD|ACT_STORE|ACT_STORE_BATCH|ACT_STOP|ACT_GO)

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
typedef ssize_t (store_fn)(void * self, void * rec, char * buf);

/**
 * load_fn() given a buffer, returns the size of the first record in the
 * buffer and the associated timestamp in *ts.
 * On error returns 0 and leaves *ts invalid.
 * Mandatory.
 */
typedef size_t (load_fn)(void * self, char *buf, size_t len, timestamp_t * ts);

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
typedef char * (print_fn)(void * self, char * buf, size_t * len, 
			  char * const args[]);

/**
 * replay_fn() - given a data buffer (ptr), returns a reconstructed packet 
 * trace in the output buffer (out). The output buffer is allocated by the 
 * caller. The left variable tells the the module how many packets are left
 * to be genereted (i.e. the value returned by previous call with the 
 * same record).  
 *
 * Returns the number of packet left to send, -1 on error. 
 * out_len is also updated to indicate the valid bytes in out and count
 * is update to record the total number of packets generated so far from 
 * the record pointed by ptr.  
 * 
 * Not mandatory.
 */
typedef int (replay_fn)(void * self, char *ptr, char *out, 
			size_t * out_len, int left);

typedef struct capabilities_t {
    uint32_t has_flexible_flush:1;
    uint32_t _res:31;
} capabilities_t;

/*
 * This structure contains the callbacks for a classifier.
 * Each classifier which is implemented as a shared
 * object is expected to export a structure of this kind,
 * named 'callbacks', properly initialized.
 */
struct _callbacks {
    size_t ca_recordsize; 
    size_t ex_recordsize; 
    size_t st_recordsize;
    
    capabilities_t capabilities;
    
    /* callbacks called by the supervisor process */
    init_fn     * init;

    /* callbacks called by the capture process */
    check_fn    * check;
    hash_fn     * hash;
    match_fn    * match;
    update_fn   * update;
    flush_fn	* flush;

    /* callbacks called by the export process */
    ematch_fn   * ematch;  
    export_fn   * export;
    compare_fn  * compare;
    action_fn   * action;
    store_fn    * store;

    /* callbacks called by the query process */
    load_fn     * load;
    print_fn    * print;
    replay_fn   * replay;

    char * formats; 
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
 * The function also needs the array of modules, to check if a module
 * has been disabled (and if so, filter out all packets).
 *
 * For the time being, the array is one of integers. Later it
 * will be packed to use bits.
 */
typedef int *(filter_fn)(void *pkt_buf, int n_packets, int n_outputs,
        module_t *modules);


/*
 * "Module" data structure. It needs a set of configuration parameters
 * (e.g., weigth, base output directory, etc.), some runtime information
 * (e.g., CPU usage stats), and finally a list of classifier that are
 * associated to it.
 */
struct _module {
    int index;          	/* order in the array of classifiers */
    int node;			/* node this module is running for */
    char * name;		/* name of the module */
    char * description;		/* module description */

    treenode_t * filter_tree;   /* filter data */
    char * filter_str;          /* filter expression */

    metadesc_t *indesc;		/* requested input metadesc list */
    metadesc_t *outdesc;	/* offered output metadesc list */

    allocator_t alc;
    
    memmap_t * init_map;       /* memory map used in init() */
    memmap_t * shared_map;     /* memory map currently used in sh memory */
    memmap_t * inprocess_map;  /* memory map currently used in cur process */
    void * config;               /* persistent config state */
    void * fstate;		/* flush state */
    void * estate;		/* export state */

    char * output;              /* output file basename */
    char ** args;               /* parameters for the module */
    char * source;              /* filename of the shared lib. */

    callbacks_t callbacks;      /* callbacks (static, from the shared obj) */
    void * cb_handle;           /* handle of module's dynamic libraries */

    status_t status; 		/* current module status */
    running_t running;		/* running mode */
    size_t memusage; 		/* current memory usage */

    ctable_t *ca_hashtable;  	/* capture hash table */
    uint ca_hashsize;    	/* capture hash table size (by config) */
    timestamp_t flush_ivl;	/* capture flush interval */

    etable_t *ex_hashtable;  	/* export hash table */
    uint ex_hashsize; 	   	/* export hash table size (by config) */
    earray_t *ex_array; 	/* array of export records */

    int	file;			/* output file for export records */
    off_t streamsize;       	/* max bytestream size */
    off_t offset;		/* current offset in the export file */

    int priority;               /* resource management priority, the lower
                                 * the more important the module is */

    int seen;                   /* used in config.c to find out what modules
                                 * have been removed from cfg files */
};


/* 
 * aliases are used to define new module names that correspond to 
 * existing running modules with an additional set of arguments. 
 * they can be seen exactly as unix shell command aliases. 
 */ 
struct _alias { 
    char * name; 		/* alias name */
    char * description; 	/* alias description */ 
    char * module; 		/* actual module name */
    char ** args; 		/* arguments */ 
    int ac; 			/* no. of arguments */
    struct _alias * next; 	/* next alias */
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
 * Expired memory maps are stored by CAPTURE waiting to be sent to 
 * EXPORT on a per-module basis to pass the state. They contain the 
 * pointer to the private state of the module (at the time of being expired)
 * and the memory maps where blocks should be freed.
 */
struct _expiredmap { 
    expiredmap_t * next;	/* next expired map */
    module_t * mdl; 		/* module using this table */
    ctable_t * ct;		/* capture table expired */
    void * fstate;		/* flush state */
    memmap_t * shared_map;	/* module shared map */
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
    timestamp_t ts;             /* end of the flush interval or
				   time of last seen packet in the interval if
				   the table is flushed before */
    timestamp_t ivl;            /* first insertion (flush_ivl aligned) */
    uint32_t size;		/* size of hash table */
    uint32_t records;		/* no. active records */
    uint32_t first_full;	/* index of first full slot */
    uint32_t last_full;		/* index of last full slot */
    uint32_t live_buckets;	/* no. active buckets */
    uint32_t filled_records;    /* no. records filled */
    uint32_t bytes;             /* size of table and contents in memory */
    int flexible;		/* set to one if the table is created after a
				   flexible flush occurred in the interal */
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
 * timers (using TSC) 
 */
struct _tsc {
    char * name;                /* timer name */
    int n;                      /* number of samples */
    u_int64_t value;            /* latest value */
    u_int64_t min;              /* min value */
    u_int64_t max;              /* max value */
    u_int64_t total;            /* sum of all values */
};


struct _statistics { 
    struct timeval start; 	/* CoMo start time (with gettimeofday)*/

    /* XXX Pending: update correctly */

    timestamp_t ts;	 	/* timestamp last processed batch */
    timestamp_t first_ts; 	/* timestamp first processed batch */
    int modules_active;		/* no. of modules processing packets */
    int table_queue; 		/* expired tables in capture->export queue */
    size_t mem_usage_cur; 	/* current shared memory usage */
    size_t mem_usage_peak; 	/* peak shared memory usage */
    uint64_t pkts; 		/* sniffed packets so far */
    int drops; 			/* global packet drop counter */
    
    uint64_t load_15m[15];	/* bytes load in last 15m */
    uint64_t load_1h[60];	/* bytes load in last 1h */
    uint64_t load_6h[360];	/* bytes load in last 6h */
    uint64_t load_1d[1440];	/* bytes load in last 1d */

    /* we define here a set of timers that use TSC */
    tsc_t * ca_full_timer; 	/* capture entire mainloop */
    tsc_t * ca_loop_timer; 	/* capture mainloop */
    tsc_t * ca_pkts_timer; 	/* capture process pkts */
    tsc_t * ca_filter_timer;	/* capture filter */
    tsc_t * ca_module_timer;	/* capture modules */
    tsc_t * ca_updatecb_timer;	/* capture updatecb */
    tsc_t * ca_sniff_timer;	/* capture sniffer */

    tsc_t * ex_full_timer; 	/* export entire mainloop */
    tsc_t * ex_loop_timer; 	/* export mainloop */
    tsc_t * ex_table_timer; 	/* export process table */
    tsc_t * ex_store_timer;	/* export store table */
    tsc_t * ex_export_timer;	/* export export()/store() callbacks */
    tsc_t * ex_mapping_timer;	/* export export()/store() callbacks */
};

typedef enum meta_flags_t {
    META_PKT_LENS_ARE_AVERAGED = 0x1,
    META_HAS_FULL_PKTS = 0x2,
    META_PKTS_ARE_FLOWS = 0x4
} meta_flags_t;

typedef uint16_t pktmeta_type_t;

struct _como_metatpl {
    struct _como_metatpl *_next;
    char *protos;
    pkt_t tpl;
};

struct _como_metadesc {
    struct _como_metadesc *_next;
    allocator_t *_alc;
    uint32_t _tpl_count;
    struct _como_metatpl *_first_tpl;
    timestamp_t ts_resolution;
    meta_flags_t flags;
    uint32_t pktmeta_count;
    pktmeta_type_t *pktmeta_types;
};

typedef enum layer_t {
    LCOMO = 1,
    L2 = 2,
    L3 = 3,
    L4 = 4,
    L7 = 7,
    LALL = 0xffff
} layer_t;

struct _como_headerinfo {
    const char *name;
    layer_t layer;
    uint16_t type;
    uint16_t hdr_len;
};

/*
 * Support for tailq handling.
 * Used for the expired tables.
 */
typedef struct tailq_t {
    void * __head;
    void * __tail;
} tailq_t;

#define TQ_HEAD(queue)  ((queue)->__head)

#define TQ_APPEND(queue, entry, link_field)             \
    do {                                                \
        tailq_t *q = (queue);                           \
        typeof(entry) e = entry;                        \
        if (q->__head)                                  \
            ((typeof(entry))q->__tail)->link_field = e; \
        else                                            \
            q->__head = e;                              \
        q->__tail = e;                                  \
        e->link_field = NULL;                           \
    } while (0);

#endif /* _COMOTYPES_H */
