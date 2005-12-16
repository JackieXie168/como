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
#include <sys/time.h>
#include "stdpkt.h"

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

typedef struct _tsc		tsc_t; 		/* timers (using TSC) */
typedef struct _statistics	stats_t; 	/* statistic counters */
typedef struct _mdl_statistics	mdl_stats_t; 	/* statistic counters */

typedef struct _proc_callbacks  proc_callbacks_t; /* callbacks of core procs */

typedef struct _como_pktdesc    pktdesc_t;      /* Packet description */

typedef uint64_t 		timestamp_t;	/* NTP-like timestamps */

typedef enum {
    MDL_INVALID, 			/* unused for debugging */
    MDL_UNUSED,				/* module removed, free entry */
    MDL_LOADING,            /* module is being loaded */
    MDL_INCOMPATIBLE,			/* not compatible with sniffer */
    MDL_ACTIVE, 			/* active and processing packets */
    MDL_PASSIVE, 			/* passive waiting for queries */
    MDL_FROZEN,				/* temporary frozen */
    MDL_DISABLED            /* disabled due to resource mgmt */
} state_t;				

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
typedef timestamp_t (init_fn)(void *mem, size_t msize, char * args[]);

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
typedef int (replay_fn)(char *ptr, char *out, size_t * out_buf_len,
                        int *count);

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
    pktdesc_t   * indesc;   /* packet requirements */
    pktdesc_t   * outdesc;  /* packet offer */

    /* callbacks called by the capture process */
    init_fn     * init;
    check_fn    * check;
    hash_fn     * hash;
    match_fn    * match;
    update_fn   * update;

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

struct _ipaddr {
    uint8_t direction;
    uint32_t ip;
    uint32_t nm;
};
typedef struct _ipaddr ipaddr_t;

struct _portrange {
    uint8_t direction;
    uint16_t lowport;
    uint16_t highport;
};
typedef struct _portrange portrange_t;

union _nodedata {
    ipaddr_t ipaddr;
    portrange_t ports;
    uint16_t proto;
};
typedef union _nodedata nodedata_t;

struct _treenode
{
    uint8_t type;
    uint8_t pred_type;
    char *string;
    nodedata_t *data;
    struct _treenode *left;
    struct _treenode *right;
};
typedef struct _treenode treenode_t;

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
    treenode_t * filter_tree;   /* filter data */
    char * filter_str;          /* filter expression */
    char * filter_cmp;          /* filter expression to compare with queries */
    char * output;              /* output file basename */
    char ** args;               /* parameters for the module */
    char * source;              /* filename of the shared lib. */
    void * mem;           	/* private memory for the classifier */
    size_t msize;          	/* size of private memory */
    callbacks_t callbacks;      /* callbacks (static, from the shared obj) */
    void * cb_handle;           /* handle of module's dynamic libraries */

    state_t status; 		/* current module status */
    size_t memusage; 		/* current memory usage */

    ctable_t *ca_hashtable;  	/* capture hash table */
    uint ca_hashsize;    	/* capture hash table size (by config) */
    timestamp_t flush_ivl;	/* capture flush interval */

    etable_t *ex_hashtable;  	/* export hash table */
    uint ex_hashsize; 	   	/* export hash table size (by config) */
    earray_t *ex_array; 	/* array of export records */

    int	file;			/* output file for export records */
    size_t bsize;		/* blocksize ... */
    off_t streamsize;       	/* max bytestream size */
    off_t offset;		/* current offset in the export file */

    int priority;               /* resource management priority, the lower
                                 * the more important the module is */

    int seen;                   /* used in config.c to find out what modules
                                 * have been removed from cfg files
                                 */
};

#define FILTER_ALL      0x0000
#define FILTER_PROTO    0x0001
#define FILTER_SRCIP    0x0002
#define FILTER_DSTIP    0x0004
#define FILTER_SRCPORT  0x0008
#define FILTER_DSTPORT  0x0010

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
    uint32_t filled_records;    /* no. records filled */
    uint32_t bytes;             /* size of table and contents in memory */
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


/*
 * callbacks of core processes
 */
/* TODO document better */
typedef void (filter_init_fn)(char *filter_file);
typedef void (mdl_init_fn)(module_t *mdl);
typedef void (mdl_enable_fn)(module_t *mdl);
typedef void (mdl_disable_fn)(module_t *mdl);
typedef void (mdl_remove_fn)(module_t *mdl);

struct _proc_callbacks {
    filter_init_fn * const filter_init;
    mdl_init_fn * const module_init;
    mdl_enable_fn * const module_enable;
    mdl_disable_fn * const module_disable;
    mdl_remove_fn * const module_remove;
};

/* 
 * statistic counters 
 */
struct _mdl_statistics {
    size_t mem_usage_shmem;     /* shared memory, only capture writes here */
    size_t mem_usage_shmem_f;   /* shmem freed by export, periodically flushed
                                 * into mem_usage_sh by capture. This is to
                                 * avoid the need of semaphores.
                                 */
    size_t mem_usage_export;    /* memory used by modules in export */

    /* in future, also store cpu usage, .. */
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
    
    mdl_stats_t *mdl_stats;     /* per-module stats */
};

#define MDL_STATS(mdl) \
    (& map.stats->mdl_stats[(mdl)->index])
    

/*
 * pktdesc_t describes both what a module is going to read or what a
 * sniffer/module is going to write in its ingoing/outgoing pkt_t streams.
 * The fields within the "bm" structure are all bitmasks.
 */
struct _como_pktdesc {
    uint64_t ts;                        /* timestamp granularity */
    uint16_t caplen;                    /* packet capture lenght (max) */
    uint16_t flags;                     /* flags for several options */
#define COMO_AVG_PKTLEN         0x0001  /* pkt len are averaged */
#define COMO_FULL_PKT           0x0002  /* full packet capture */

    struct _como_isl isl;               /* Cisco ISL bitmask */
    struct _como_eth eth;               /* Ethernet bitmask */
    struct _como_hdlc hdlc;             /* Cisco HDLC bitmask */
    struct _como_vlan vlan;             /* 802.1q bitmask */
    struct _como_iphdr ih;              /* IP header bitmask */
    struct _como_tcphdr tcph;           /* TCP header bitmask */
    struct _como_udphdr udph;           /* UDP header bitmask */
    struct _como_icmphdr icmph;         /* ICMP header bitmask */
};

/*
 * Support for tailq handling.
 * Used for the expired tables.
 */
typedef struct {
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
