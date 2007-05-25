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

#ifndef _COMO_FUNC_H
#define _COMO_FUNC_H

/* 
 * Function prototypes -- in the same file just for convenience. 
 * 
 * this file is included by como.h and can be ignored by all other 
 */

#include "comotypes.h"
#include "ipc.h"

/*
 * mdl.c
 */
void mdl_store_rec(mdl_t * mdl, void * rec);

#define mdl_get_config(h,type) \
((type *) (h->config))

#define mdl_alloc_config(h,type) \
((type *) mdl__alloc_config(h, sizeof(type)))

#define mdl_alloc_tuple(h,type) \
((type *) mdl__alloc_tuple(h, sizeof(type)))

void   mdl_free_tuple(mdl_t * mdl, void *ptr);
char * mdl_alloc_string(mdl_t * mdl, size_t sz);

alc_t * mdl_alc(mdl_t * mdl);

#define mdl_malloc(self,sz)	alc_malloc(mdl_alc(self), sz)
#define mdl_calloc(self,n,sz)	alc_calloc(mdl_alc(self), n, sz)
#define mdl_free(self,ptr)	alc_free(mdl_alc(self), ptr)
#define mdl_new(self,type)	alc_new(mdl_alc(self), type)
#define mdl_new0(self,type)	alc_new0(mdl_alc(self), type)


void * mdl__alloc_config(mdl_t * mdl, size_t sz);
void * mdl__alloc_tuple(mdl_t * mdl, size_t sz);


void mdl_print(mdl_t * mdl, const char * s);
void mdl_printf(mdl_t * mdl, const char * fmt, ...);
void mdl_write(mdl_t *mdl, const char *str, size_t len);


/*
 * capture-client.c
 */
cca_t * cca_open     (int cd);
void	cca_destroy  (cca_t * cca);
pkt_t * cca_next_pkt (cca_t * cca);

/*
 * config.c
 */
void define_sniffer(char *name, char *device, char *args, como_config_t *cfg);
void initialize_module_def(mdl_def_t *mdl, alc_t *alc);
void define_module(mdl_def_t *mdl, como_config_t *cfg);
void set_filesize(int64_t size, como_config_t *cfg);
void set_memsize(int64_t size, como_config_t *cfg);
void set_queryport(int64_t port, como_config_t *cfg);

como_config_t *configure(int argc, char **argv, alc_t *alc, como_config_t *cfg);

/*
 * config-syntax.y
 */
como_config_t * parse_config_file(char *file, alc_t *alc, como_config_t *cfg);

/* 
 * filter-syntax.c
 */
int          parse_filter (char *, treenode_t **, char **);
int          evaluate     (treenode_t *t, pkt_t *pkt);

/*
 * query-syntax.c
 */
query_ast_t * parse_query_str(char *q);

/*
 * asn.c
 */
void asn_readfile(const char * filename);
int asn_test(const uint32_t addr, const uint16_t asn);

/*
 * util-socket.c
 */
int create_socket  (const char * path, int is_server);
int destroy_socket (const char * path);

/*
 * util-io.c
 */
int como_read(int fd, void *buf, size_t len);
int como_write(int fd, const void *buf, size_t len);

/* 
 * util-misc.c
 */
char * getprotoname (int proto);
char * strchug      (char *str);
char * strchomp     (char *str);

/* 
 * util-timers.c
 */
#ifdef ENABLE_PROFILING 

ctimer_t * new_timer(char *);
void destroy_timer(ctimer_t *);
void reset_timer(ctimer_t *);
void start_tsctimer(ctimer_t *);
void end_tsctimer(ctimer_t *);
void start_timer(ctimer_t *, uint64_t);
void end_timer(ctimer_t *, uint64_t);
char * print_timer(ctimer_t *);
uint64_t get_last_sample(ctimer_t *);
uint64_t get_avg_sample(ctimer_t *);
uint64_t get_max_sample(ctimer_t *);
uint64_t get_min_sample(ctimer_t *);

#else 

#define new_timer(x)
#define destroy_timer(x)
#define reset_timer(x)
#define start_tsctimer(x)
#define end_tsctimer(x);
#define start_timer(x);
#define end_timer(x);
#define print_timer(x)
#define get_last_sample(x)
#define get_avg_sample(x)
#define get_max_sample(x)
#define get_min_sample(x)

#endif

/*
 * res-mgmt.c
 */
#ifdef RESOURCE_MANAGEMENT

void resource_mgmt_init();
char *resource_usage_report();
void schedule();

#else 

#define resource_mgmt_init()
#define resource_usage_report()
#define schedule()

#endif


/* 
 * profiling.c 
 */
#ifdef ENABLE_PROFILING 

void ca_init_timers(void); 
void ex_init_timers(void); 
void ca_print_timers(void); 
void ex_print_timers(void); 
void ca_reset_timers(void); 
void ex_reset_timers(void); 
void enable_profiling(void);

#else

#define ca_init_timers()
#define ex_init_timers()
#define ca_print_timers()
#define ex_print_timers()
#define ca_reset_timers()
#define ex_reset_timers()
#define enable_profiling();

#endif

/*
 * metadesc.c
 */
metadesc_t * metadesc_new     (metadesc_t * head, alc_t * alc,
			       int pktmeta_count, ...);
pkt_t *      metadesc_tpl_add (metadesc_t * md, const char * protos);

metadesc_t * metadesc_define_in (mdl_t *self, int pktmeta_count, ...);
metadesc_t * metadesc_define_out(mdl_t *self, int pktmeta_count, ...);

/*
 * pktmetaion.c
 */
void pktmeta_set(pkt_t *pkt, const char *name, void *opt, uint16_t opt_len);
void * pktmeta_get(pkt_t *pkt, const char *name, uint16_t *opt_len);

/*
 * headerinfo.c
 */
const headerinfo_t * headerinfo_lookup_with_name_and_layer(const char *name,
							   layer_t l);
const headerinfo_t * headerinfo_lookup_with_type_and_layer(uint32_t type,
							   layer_t l);

/*
 * proxy-mono.c
 */
void proxy_mono_init(char *mono_path);
int proxy_mono_load_export(mdl_t * mdl);
int proxy_mono_load_query(mdl_t * mdl);
qu_format_t * proxy_mono_get_formats(mdl_t * mdl, char **dflt_format);
void * proxy_mono_ex_init(mdl_t * mdl);
void * proxy_mono_qu_init(mdl_t * mdl, int format_id, hash_t * args);
void proxy_mono_qu_finish(mdl_t * self, int format_id, void * state);
void proxy_mono_qu_print_rec(mdl_t * self, int format_id, void * record,
    void * state);
void proxy_mono_export(mdl_t * mdl, void ** tuples, size_t ntuples,
        timestamp_t ivl_start, void * state);

#define assert_not_reached()	\
    error("%s:%d should not be reached.\n", __FILE__, __LINE__)

#endif /* _COMO_FUNC_H */
