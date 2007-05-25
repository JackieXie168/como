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

#define MDLNAME_MAX 1024

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
typedef struct como_node como_node_t;

typedef struct mdl		mdl_t;          /* module package */
typedef struct mdl_ibase	mdl_ibase_t;

typedef struct _timer		ctimer_t; 	/* timers */
typedef struct _statistics	stats_t; 	/* statistic counters */

typedef struct metadesc	metadesc_t;
typedef struct metatpl	metatpl_t;

typedef struct headerinfo headerinfo_t;

typedef struct cca		cca_t;

typedef struct sniffer_t	sniffer_t;
#include "sniffer_list.h"

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

typedef struct qu_format {
    int		id;
    char *	name;
    char *	content_type;
} qu_format_t;

#define QUERY_FORMATS_BEGIN	qu_format_t qu_formats[] = {
#define QUERY_FORMATS_END	{-1, NULL, NULL}};
#define DEFAULT_FORMAT          char * qu_dflt_fmt

/*
 * Module callbacks
 */


/**
 * su_init_fn()
 * Run: run once from supervisor when the module is loaded.
 * Purpose: initialize a module.
 * Arguments: - self: the instance of mdl_t representing the module.
 *            - args: hashtable of the arguments present in the configuration.
 * Return: the config state.
 */
typedef void * (*su_init_fn) (mdl_t * self, hash_t * args);

/**
 * ca_init_fn()
 * Run: run from capture at the beginning of the measurement interval.
 * Purpose: initialize the capture state valid within the current
 *          measurement interval.
 * Arguments: - self: the instance of mdl_t representing the module.
 *            - ivl_start: the beginning of the measurement interval.
 * Return: the capture state.
 */
typedef void * (*ca_init_fn) (mdl_t * self, timestamp_t ivl_start);

/**
 * ca_capture_fn()
 * Run: run from capture for each captured packet that has not been
 *      filtered out.
 * Purpose: update the capture state with the information carried in the
 *          packet.
 * Arguments: - self: the instance of mdl_t representing the module.
 *            - pkt: the packet that has been captured.
 *            - state: the current capture state.
 * Return: - COMO_OK: to continue to process packets for the current capture
 *           state.
 *         - COMO_FLUSH: to flush the current capture state with all the
 *           information collected so far.
 */
typedef void   (*ca_capture_fn)(mdl_t * self, pkt_t * pkt, void * state);

/**
 * ca_flush_fn()
 * Run: run from capture at the end of the measurement interval.
 * Purpose: perform the last computation on the capture state just before it
 *          is handed over to export.
 * Arguments: - self: the instance of mdl_t representing the module.
 *            - state: the current capture state.
 * Return: void.
 */
typedef void   (*ca_flush_fn) (mdl_t * self, void * state);

/**
 * ex_init_fn()
 * Run: run once from export when the module is loaded.
 * Purpose: initialize the export state.
 * Arguments: - self: the instance of mdl_t representing the module.
 * Return: the export state.
 */
typedef void * (*ex_init_fn) (mdl_t * self);

/**
 * ex_export_fn()
 * Run: run from export for each capture state that is flushed.
 * Purpose: update the export state with the information carried in the
 *          capture state, store the results of the performed measurements,
 *          dump unnecessary information.
 * Arguments: - self: the instance of mdl_t representing the module.
 *            - tuples: array of pointers to the tuples collected in capture.
 *            - tuple_count: the number of tuples inside the tuples array.
 *            - ivl_start: the beginning of the measurement interval.
 *            - state: the export state.
 * Return: void.
 */
typedef void   (*ex_export_fn) (mdl_t * self, void ** tuples,
				size_t tuple_count, timestamp_t ivl_start,
				void * state);

/**
 * qu_init_fn()
 * Run: run once from query when a user query is received.
 * Purpose: initialize the query state, print the header if necessary.
 * Arguments: - self: the instance of mdl_t representing the module.
 *            - format_id: the required output format identifier.
 *            - args: hashtable of the arguments provided by the user.
 * Return: the query state.
 */
typedef void * (*qu_init_fn)   (mdl_t * self, int format_id, hash_t * args);

/**
 * qu_print_fn()
 * Run: run from query for each record that has been selected by the user
 *      query.
 * Purpose: convert the record into a string that is sent to the user.
 * Arguments: - self: the instance of mdl_t representing the module.
 *            - format_id: the required output format identifier.
 *            - record: the record.
 *            - state: the query state.
 * Return: void.
 */
typedef void   (*qu_print_rec_fn) (mdl_t * self, int format_id, void * record,
				   void * state);

/**
 * qu_finish_fn()
 * Run: run once from query after all the selected records have been processed.
 * Purpose: print the footer if necessary.
 * Arguments: - self: the instance of mdl_t representing the module.
 *            - format_id: the required output format identifier.
 *            - state: the query state.
 * Return: void.
 */
typedef void   (*qu_finish_fn) (mdl_t * self, int format_id, void * state);

/*
 * TODO: qu_replay function
 *
 */
typedef void   (*qu_replay_fn) (mdl_t *self, void *record, void *state);

struct mdl {
    /* public fields */
    timestamp_t	    flush_ivl;
    char *	    name;
    char *	    description;
    char *	    filter;
    char *	    mdlname;
    uint64_t        streamsize;
    void *	    config;
    /* private state */
    mdl_ibase_t *   priv;
};


typedef enum ex_impl
{
    EX_IMPL_NONE,
    EX_IMPL_C,
    EX_IMPL_MONO,
} ex_impl_t;

typedef enum qu_impl
{
    QU_IMPL_NONE,
    QU_IMPL_C,
    QU_IMPL_MONO,
} qu_impl_t;


typedef struct capabilities_t {
    uint32_t has_flexible_flush:1;
    uint32_t _res:31;
} capabilities_t;


/* 
 * this structure contains the node specific 
 * information (name, location, etc.). It is a 
 * list given that one can define multiple virtual 
 * nodes to run in parallel. They will run the same 
 * modules and respond on different to query on 
 * different port. a virtual node may apply a filter on 
 * all packets before the module process them. 
 */

struct como_node { 
    int		id;
    char *	name;
    char *	location;
    char *	type;
    char *	comment;
    char *	source;		/* source module for all virtual modules */
    char *	filter;		/* filter expression */
    char **	args;		/* parameters for the modules */
    uint16_t	query_port;	/* port for incoming queries */
    int		query_fd;	/* socket accepting queries */
    array_t *	mdls;		/* module information */
    sniffer_list_t	sniffers;
    int			sniffers_count;
    timestamp_t		live_thresh;
};

/*
 * CoMo configuration structs
 */

typedef struct _sniffer_def sniffer_def_t;
typedef struct _mdl_def mdl_def_t;
typedef struct _como_config como_config_t;

struct _sniffer_def {
    char *	name;
    char *	device;
    char *	args;
};

struct _mdl_def {
    char *	name;
    char *	mdlname;
    char *      output;
    char *      filter;
    char *      descr;

    hash_t *	args;
    uint64_t	streamsize;
    uint64_t	hashsize;
};

struct _como_config {
    array_t *	sniffer_defs;
    array_t *	mdl_defs;

    char *      storage_path;
    char *      mono_path;
    char *      db_path;
    char *      libdir;
    char *      asn_file;

    char *      name;
    char *      location;
    char *      type;
    char *      comment;

    size_t      filesize;
    int         query_port;
    size_t      shmem_size;

    int         exit_when_done;
    int         inline_mode;
    int         silent_mode;
    hash_t *    query_args;
};


/* 
 * timers
 */
struct _timer {
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

    /* we define here a set of timers */
    ctimer_t * ca_full_timer; 	/* capture entire mainloop */
    ctimer_t * ca_loop_timer; 	/* capture mainloop */
    ctimer_t * ca_pkts_timer; 	/* capture process pkts */
    ctimer_t * ca_filter_timer;	/* capture filter */
    ctimer_t * ca_module_timer;	/* capture modules */
    ctimer_t * ca_updatecb_timer;   /* capture updatecb */
    ctimer_t * ca_sniff_timer;	/* capture sniffer */

    ctimer_t * ex_full_timer; 	/* export entire mainloop */
    ctimer_t * ex_loop_timer; 	/* export mainloop */
    ctimer_t * ex_table_timer; 	/* export process table */
    ctimer_t * ex_store_timer;	/* export store table */
    ctimer_t * ex_export_timer;	/* export export()/store() callbacks */
    ctimer_t * ex_mapping_timer;/* export export()/store() callbacks */
};

typedef enum meta_flags_t {
    META_PKT_LENS_ARE_AVERAGED = 0x1,
    META_HAS_FULL_PKTS = 0x2,
    META_PKTS_ARE_FLOWS = 0x4
} meta_flags_t;

typedef uint16_t pktmeta_type_t;

struct metatpl {
    metatpl_t *_next;
    char *protos;
    pkt_t tpl;
};

struct metadesc {
    metadesc_t *_next;
    alc_t *_alc;
    uint32_t _tpl_count;
    metatpl_t *_first_tpl;
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

struct headerinfo {
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


/*
 * query abstract syntax tree for query parsing
 */
#define QUERY_AST_MAX_KEYVALS 1024
typedef struct keyval keyval_t;
typedef struct query_ast query_ast_t;
struct keyval {
    char *key;
    char *val;
};
struct query_ast {
    char *resource;
    int  nkeyvals;
    keyval_t keyvals[QUERY_AST_MAX_KEYVALS];
};

#endif /* _COMOTYPES_H */
