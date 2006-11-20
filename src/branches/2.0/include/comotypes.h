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

#define __OUT
#define __INOUT

#include <inttypes.h>
#include <sys/time.h>

typedef int  (*cmp_fn)            (const void *a, const void *b);
typedef void (*destroy_notify_fn) (void *data);

typedef uint64_t 		timestamp_t;	/* NTP-like timestamps */

#include "stdpkt.h"
#include "filter.h"
#include "allocator.h"
#include "array.h"
#include "shobj.h"
#include "hash.h"

#include "serialize.h"

struct tuple;
#include "tuples.h"
struct tuple {
    tuples_entry_t	entry;
    uint8_t		data[0]; /* variable size */
};


/*
 * New definitions of object types
 */
typedef struct _como		como_t;		/* main como map */
typedef struct _module          module_t;       /* XXX legacy module package */
typedef struct _mdl             mdl_t;          /* module package */
typedef struct _alias           alias_t;        /* aliases */
typedef uint32_t		procname_t;	/* process names */
typedef struct _callbacks       callbacks_t;    /* callbacks */
typedef struct _callbacks       module_cb_t;    /* callbacks */
typedef struct _flushmsg        flushmsg_t;     /* message capture/export */

typedef struct memmap           memmap_t;      /* opaque, memory manager */
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

typedef struct cca		cca_t;

typedef uint16_t		asn_t;		/* ASN values */

typedef enum runmode { 
    RUNMODE_NORMAL = 0, 
    RUNMODE_INLINE = 1
} runmode_t;

typedef enum status_t {
    MDL_UNUSED,				/* module unused, free entry */
    MDL_LOADING,            		/* module is being loaded */
    MDL_INCOMPATIBLE,			/* not compatible with sniffer */
    MDL_WAIT_FOR_EXPORT,                /* loaded in CA but no EX attached */
    MDL_ACTIVE, 			/* active and processing packets */
    MDL_ACTIVE_REPLAY,			/* active only to replay records */
    MDL_DISABLED            		/* disabled or turned off */
} status_t;

typedef enum running_t {
    RUNNING_NORMAL,			/* running normally in CAPTURE */
    RUNNING_ON_DEMAND			/* running in query on demand */
} running_t;

/*
 * Module callbacks
 */


/**
 * su_init_fn() run from supervisor to initialize a module,
 * For the time being, just initialize the private memory for the module,
 * and take arguments from the config file.
 * Returns the config state.
 */
typedef void * (*su_init_fn) (mdl_t * h, hash_t * args);


typedef struct mdl_ibase        mdl_ibase_t;

struct _mdl {
    /* public fields */
    timestamp_t	flush_ivl;
    char *	name;
    char *	description;
    char *	filter;
    char *	mdlname;
    void *	config;
    uint64_t    streamsize;
    /* private state */
    mdl_ibase_t * priv;
};

#define mdl_get_config(h,type) \
((type *) (h->config))

#define mdl_alloc_config(h,type) \
((type *) mdl__alloc_config(h, sizeof(type)))

void * mdl__alloc_config(mdl_t * h, size_t sz);

#define mdl_alloc_tuple(h,type) \
((type *) mdl__alloc_tuple(h, sizeof(type)))


void * mdl__alloc_tuple(mdl_t * mdl, size_t sz);
void   mdl_free_tuple(mdl_t * mdl, void *ptr);
char * mdl_alloc_string(mdl_t * mdl, size_t sz);

alc_t * mdl_get_alloc(mdl_t * mdl);


void * mdl__malloc(alc_t *alc, size_t sz);
#define mdl_malloc(self, sz) mdl__malloc(mdl_get_alloc(self), sz);


/* Module callbacks  (TODO: document) */


typedef void * (*ca_init_fn)(mdl_t * self, timestamp_t ts);
/**
 * ca_update_fn() run from capture to update *state with the info from *pkt.
 * state points to current flush state.
 * Normally returns COMO_OK to continue to process the packets, can return
 * COMO_FLUSH to force a flush.
 */
typedef void   (*ca_capture_fn)(mdl_t * self, pkt_t * pkt, void * state);
/**
 * ca_flush_fn() run from capture at every flush interval to obtain a clean
 * flush state.
 */
typedef void   (*ca_flush_fn)(mdl_t * self);

typedef void * (*ex_init_fn)(mdl_t *self);

typedef void   (*ex_export_fn)(mdl_t *self, void ** tuples, size_t count,
                                timestamp_t ivl_start, void *state);

typedef struct capabilities_t {
    uint32_t has_flexible_flush:1;
    uint32_t _res:31;
} capabilities_t;

#if 0 /* XXX legacy code */
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

    alc_t alc;
    
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
#endif


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
    int batch_queue;		/* pending batches */
    int ca_clients;		/* capture clients */
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
    alc_t *_alc;
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

#define TQ_POP(queue, entry, link_field)		\
    do {						\
    	tailq_t *q = (queue);				\
	entry = q->__head;				\
	if (entry) {					\
	    q->__head = entry->link_field;		\
	    entry->link_field = NULL;			\
	    if (q->__head == NULL)			\
		q->__tail = NULL;			\
	}						\
    } while (0);

#endif /* _COMOTYPES_H */
