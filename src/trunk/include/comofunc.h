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

/*
 * config.c
 */
void configure(como_t * m, int argc, char *argv[]);
void init_map(como_t * m);
void add_sniffer(como_t * m, char *want, char *device, char *args);


/* 
 * modules.c 
 */
int activate_module(module_t * mdl, char * libdir);
int check_module(como_t * m, module_t *mdl);
module_t * new_module(como_t * m, char *name, int node, int idx);
module_t * copy_module(como_t * m, module_t * src, int node, int idx,
		       char ** extra_args);
void clean_module(module_t *mdl);
void remove_module(como_t * m, module_t *mdl);
char * pack_module(module_t * mdl, int * len);
int unpack_module(char * x, size_t len, module_t * mdl);
int init_module(module_t * mdl); 
int match_module(module_t * a, module_t * b); 

/* 
 * memory.c
 */
uint memory_usage();
uint memory_peak();

void * mem_mdl_smalloc(size_t sz, const char * file, int line, module_t * mdl);
void * mem_mdl_scalloc(size_t n, size_t sz, const char *, int, module_t * mdl);
void   mem_mdl_sfree  (void *ptr, const char * file, int line, module_t * mdl);

#define mem_mdl_malloc(self,sz)			\
	mem_mdl_smalloc(sz, __FILE__, __LINE__, (module_t *) self)
#define mem_mdl_calloc(self,nmemb,sz)		\
	mem_mdl_scalloc(nmemb, sz, __FILE__, __LINE__, (module_t *) self)
#define mem_mdl_free(self,p)			\
	mem_mdl_sfree(p, __FILE__, __LINE__, (module_t *) self)

/*
 * capture.c
 */
void capture_mainloop();

/*
 * export.c
 */
void export_mainloop();

/*
 * supervisor.c
 */
void supervisor_mainloop();

/* 
 * logging.c 
 */
typedef struct logmsg_t {
    struct timeval tv;
    int flags;
    char msg[0];
} logmsg_t;

char * loglevel_name (int flags); 
void   displaymsg    (FILE *f, procname_t sender, logmsg_t *lmsg);

/* don't call these directly, use the macros below */
void _logmsg  (const char * file, int line, int flags, const char *fmt, ...);
void _epanic  (const char * file, int line, const char *fmt, ...);
void _epanicx (const char * file, int line, const char *fmt, ...);

#define logmsg(flags,fmt...)	_logmsg(__FILE__, __LINE__, flags, fmt)
#define panic(fmt...)		_epanic(__FILE__, __LINE__, fmt)
#define panicx(fmt...)		_epanicx(__FILE__, __LINE__, fmt)

/* 
 * filter-syntax.c
 */
int parse_filter(char *, treenode_t **, char **);
int evaluate(treenode_t *t, pkt_t *pkt);
treenode_t *tree_copy(treenode_t *t);

/*
 * util-socket.c
 */
int create_socket(const char *path, char **arg);
int destroy_socket(const char *path);
int del_fd(int i, fd_set * fds, int max_fd);
int add_fd(int i, fd_set * fds, int max_fd);

/*
 * util-io.c
 */
int como_read(int fd, char *buf, size_t len);
int como_writen(int fd, const char *buf, size_t len);

/* 
 * util-misc.c
 */
char * getprotoname(int proto);

/* 
 * util-process.c
 */
char * getprocname(procname_t);
char * getprocfullname(procname_t);
procname_t sibling(procname_t who);
procname_t child(procname_t who, int id);
procname_t buildtag(procname_t parent, procname_t who, int id);
procname_t getprocclass(procname_t who);
int getprocid(procname_t who);
int isvalidproc(procname_t who);


/*
 * util-safe.c 
 * 
 * If possible, do not call malloc(),  calloc() and realloc() directly.
 * Instead use safe_malloc(), safe_calloc() and safe_realloc() which provide
 * wrappers to check the arguments and panic if necessary.
 */
void *_smalloc(size_t sz, const char * file, int line);
#define safe_malloc(sz) _smalloc(sz, __FILE__, __LINE__)
void *_scalloc(size_t n, size_t sz, const char * file, int line);
#define safe_calloc(n, sz) _scalloc(n, sz, __FILE__, __LINE__)
void *_srealloc(void * ptr, size_t sz, const char * file, const int line);
#define safe_realloc(ptr, sz) _srealloc(ptr, sz, __FILE__, __LINE__)
char *_sstrdup(const char * str, const char * file, const int line);
#define safe_strdup(str) _sstrdup(str, __FILE__, __LINE__)
void _sfree(void * ptr, const char * file, int line);
#define safe_free(ptr) _sfree(ptr, __FILE__, __LINE__)
void _sdup(char ** dst, char * src, const char * file, const int line);
#define safe_dup(dst, src) _sdup(dst, src, __FILE__, __LINE__)

/* 
 * util-timers.c
 */
#ifdef ENABLE_PROFILING 

tsc_t * new_tsctimer(char *);
void destroy_tsctimer(tsc_t *);
void reset_tsctimer(tsc_t *);
void start_tsctimer(tsc_t *);
void end_tsctimer(tsc_t *);
char * print_tsctimer(tsc_t *);
uint64_t get_avg_tscsample(tsc_t *);
uint64_t get_max_tscsample(tsc_t *);
uint64_t get_min_tscsample(tsc_t *);

#else 

#define new_tsctimer(x)
#define destroy_tsctimer(x)
#define reset_tsctimer(x)
#define start_tsctimer(x)
#define end_tsctimer(x);
#define print_tsctimer(x)
#define get_avg_tscsample(x)
#define get_max_tscsample(x)
#define get_min_tscsample(x)

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

void init_timers(void); 
void print_timers(void); 
void reset_timers(void); 

#else

#define init_timers()
#define print_timers()
#define reset_timers()

#endif

/*
 * metadesc.c
 */
metadesc_t * metadesc_define_in (module_t *self, int pktmeta_count, ...);
metadesc_t * metadesc_define_out(module_t *self, int pktmeta_count, ...);
pkt_t *      metadesc_tpl_add   (metadesc_t *fd, const char *protos);
void         test_metadesc      ();

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


#define assert_not_reached()	\
    assert((logmsg(LOGWARN, "should not be reached.\n"), 0))

#endif /* _COMO_FUNC_H */
