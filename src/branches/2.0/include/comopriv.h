/*
 * Copyright (c) 2006, Intel Corporation
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

#ifndef COMOPRIV_H_
#define COMOPRIV_H_

#include "comotypes.h"
#include <stdlib.h> /* PATH_MAX */

typedef struct metadesc_match {
    metadesc_t *	in;
    metadesc_t *	out;
    int			affinity;
} metadesc_match_t;

typedef struct metadesc_incompatibility {
    metadesc_t *	in;
    metadesc_t *	out;
    int			reason;
} metadesc_incompatibility_t;

#define METADESC_INCOMPATIBLE_TS_RESOLUTION	-1
#define METADESC_INCOMPATIBLE_FLAGS		-2
#define METADESC_INCOMPATIBLE_PKTMETAS		-3
#define METADESC_INCOMPATIBLE_TPLS		-4



void   metadesc_list_free        (metadesc_t * head);
int    metadesc_best_match       (metadesc_t * out, metadesc_t * in,
				  metadesc_match_t * best,
				  metadesc_incompatibility_t ** incomps,
				  int *incomps_count);
char * metadesc_determine_filter (metadesc_t * md);

const char * metadesc_incompatibility_reason (metadesc_incompatibility_t *
					      incomp);

pktmeta_type_t pktmeta_type_from_name(const char * name);

/*
 * util-process.c
 */
typedef void (*mainloop_fn) (ipc_peer_full_t * child,
			     ipc_peer_t * parent,
			     memmap_t * shmemmap,
			     int client_fd,
			     como_node_t * node);

pid_t start_child (ipc_peer_full_t * child, mainloop_fn mainloop,
		   memmap_t * shmemmap, int client_fd, como_node_t * node);
int handle_children ();
pid_t spawn_child (ipc_peer_full_t * child, const char * path, ...);

/*
 * inline.c
 */
void inline_mainloop(int accept_fd);

/*
 * memory.c
 */
typedef struct memmap_stats {
    size_t	usage;	/* used memory */
    size_t	peak;	/* peak usage */
} memmap_stats_t;

memmap_t *       memmap_create         (shmem_t * shmem, uint32_t entries);
void             memmap_alc_init       (memmap_t * m, alc_t * alc);
memmap_stats_t * memmap_stats_location (memmap_t * m);
size_t           memmap_usage          (memmap_t * m);
size_t           memmap_peak           (memmap_t * m);


/* never call those function directly, use the macros below */
void *     _mem_malloc(size_t sz, const char * file, int line);
void *     _mem_calloc(size_t nmemb, size_t sz, const char * file, int line);
void       _mem_free(void * p, const char * file, int line);

#define mem_malloc(sz)		_mem_malloc(sz, __FILE__, __LINE__)
#define mem_calloc(nmemb,sz)	_mem_calloc(nmemb, sz, __FILE__, __LINE__)
#define mem_free(p)		_mem_free(p, __FILE__, __LINE__)

/*
 * modules.c
 */
module_t * module_lookup(const char *name, int node);
off_t      module_db_seek_by_ts(module_t *mdl, int fd, timestamp_t start);
void *     module_db_record_get(int fd, off_t * ofs, module_t * mdl,
				ssize_t *len, timestamp_t *ts);
int        module_db_record_print(module_t * mdl, char * ptr, char **args,
				  int client_fd);
int        module_db_record_replay(module_t * mdl, char * ptr, int client_fd);

#define	GR_LOSTSYNC	((void *) module_db_record_get)

/*
 * capture.c
 */

/*
 * A batch holds the packets to be processed.
 */
typedef struct batch {
    struct batch *	next;	/* next batch in the cabuf */
    int			woff;	/* write offset in cabuf */
    int			reserved; /* number of cabuf items reserved for this
				     batch */
    int			count;	/* number of items in the batch */
    int			pkts0_len; /* number of items in pkts0 */
    int			pkts1_len; /* number of items in pkts1 */
    pkt_t **		pkts0;	/* pointer to the first array of pkt_ts */
    pkt_t **		pkts1;	/* pointer to the second array of pkt_ts.
				   this is used to handle wrapping in cabuf.
				   it might be NULL */
    timestamp_t		last_pkt_ts; /* timestamp of last pkt in the batch */
    uint64_t		ref_mask; /* mask of capture clients referencing this
				     batch */
    pkt_t **		first_ref_pkts; /* the first packet referenced by this
					   batch in each sniffer */
    float *		sniff_usage;	/* resources taken by this batch in
					   each sniffer */
} batch_t;

typedef union ccamsg_t {
    struct {
	int		id;
	int *		sampling;
    } open_res;
    struct {
	int		id;
	batch_t *	batch;
    } new_batch;
    struct {
	int		id;
	batch_t *	batch;
    } ack_batch;
    struct {
	int		id;
    } close;
} ccamsg_t;

typedef struct { /* EX tells CA it's running a mdl. ex->ca */
    char mdl_name[MDLNAME_MAX];
    char shmem_filename[PATH_MAX];
} caexmsg_t;

typedef struct { /* tuples in shmem. ca->ex, ex->ca */
    char        mdl_name[MDLNAME_MAX];
    tuples_t    tuples;
    size_t      ntuples;
    timestamp_t	ivl_start;
} tuplesmsg_t;

typedef struct { /* serialized tuples. ca->ex */
    char        mdl_name[MDLNAME_MAX];
    size_t      ntuples;
    uint8_t     data[0];
    timestamp_t	ivl_start;
} sertuplesmsg_t;

typedef struct {
    char        mdl_name[MDLNAME_MAX];
} delmdlmsg_t;

void capture_main (ipc_peer_full_t * child, ipc_peer_t * parent,
		   memmap_t * shmemmap,int client_fd, como_node_t * node);

/* como.c */

typedef struct como_env {
    runmode_t	runmode;	/* mode of operation */
    char *	workdir;	/* work directory for templates etc. */
    char *	dbdir; 	    	/* database directory for output files */
    char *	libdir;		/* base directory for modules */
} como_env_t;

void         como_env_init();
como_env_t * como_env();
runmode_t    como_env_runmode();
const char * como_env_workdir();
const char * como_env_dbdir();
const char * como_env_libdir();

/* mdl.c */


typedef struct mdl_icapture     mdl_icapture_t;
typedef struct mdl_iexport      mdl_iexport_t;
typedef struct mdl_isupervisor  mdl_isupervisor_t;
typedef struct mdl_iquery       mdl_iquery_t;

typedef enum mdl_priv {
    PRIV_ISUPERVISOR = 1,
    PRIV_ICAPTURE,
    PRIV_IEXPORT,
    PRIV_IQUERY
} mdl_priv_t;

struct mdl_ibase {
    mdl_priv_t		type;
    shobj_t *		shobj;
    serializable_t	mdl_config;
    serializable_t	mdl_tuple;
    serializable_t	mdl_record;

    alc_t		alc;

    metadesc_t *        indesc;
    metadesc_t *        outdesc;
    union {
        mdl_icapture_t *	ca;
        mdl_iexport_t *		ex;
        mdl_isupervisor_t *	su;
        mdl_iquery_t *		qu;
    } proc;
};

struct mdl_icapture {
    mdl_priv_t		type;

    timestamp_t		ivl_start;
    timestamp_t		ivl_end;
    void *		ivl_state;

    ca_init_fn		init;
    ca_capture_fn	capture;
    ca_flush_fn		flush;
    capabilities_t	capabilities;

    tuples_t		tuples;
    alc_t		tuple_alc;
    size_t              tuple_count;
    
    treenode_t  *	filter;
    int			status;
    
    shmem_t *		shmem;
    memmap_t *          shmap;
    ipc_peer_t *	export;
};

struct mdl_isupervisor {
    mdl_priv_t	type;
    su_init_fn	init;
};

struct mdl_iexport {
    int			cs_writer;
    size_t		cs_cisz;
    off_t		woff;
    int         outfile;
    
    ex_init_fn		init;
    ex_export_fn	export;

    shmem_t *		shmem;
};

struct mdl_iquery {
};

mdl_isupervisor_t * mdl_get_isupervisor (mdl_t * h);
mdl_icapture_t *    mdl_get_icapture    (mdl_t * h);
mdl_iexport_t *     mdl_get_iexport     (mdl_t * h);
mdl_iquery_t *      mdl_get_iquery      (mdl_t * h);

int mdl_load (mdl_t * h, mdl_priv_t priv);
void   mdl_serialize   (uint8_t ** sbuf, const mdl_t * h);
size_t mdl_sersize     (const mdl_t * src);
void   mdl_deserialize (uint8_t ** sbuf, mdl_t ** h_out, alc_t * alc,
			mdl_priv_t priv);

#endif /*COMOPRIV_H_*/
