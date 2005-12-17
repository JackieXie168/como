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
int parse_cmdline(int argc, char *argv[]);
void configure(int argc, char *argv[]);
void reconfigure(void);
int load_callbacks(module_t *mdl);
module_t *load_module(module_t *mdl, int idx);
void remove_module(module_t *mdl);


/*
 * memory.c
 */
void dump_alloc(void);
int mem_merge_maps(memlist_t *dst, memlist_t *m);
void *new_mem(memlist_t *m, uint size, char *msg); 
void mfree_mem(memlist_t *m, void *p, uint size); 
void memory_init(uint size_mb);     
void memory_clear(void);        
uint memory_usage(void);
uint memory_peak(void);
memlist_t *new_memlist(uint entries); 


/*
 * capture.c
 */
void capture_mainloop(int fd);


/*
 * export.c
 */
void export_mainloop(int fd);


/*
 * supervisor.c
 */
void supervisor_mainloop(int fd);
pid_t start_child(char *name, char *procname, void (*mainloop)(int fd), int fd);
int get_sp_fd(char *name);


/* 
 * logging.c 
 */
void logmsg(int flags, const char *fmt, ...);
void rlimit_logmsg(unsigned interval, int flags, const char *fmt, ...);
char * loglevel_name(int flags); 
void _epanic(const char * file, const int line, const char *fmt, ...);
#define panic(...) _epanic(__FILE__, __LINE__, __VA_ARGS__)
void _epanicx(const char * file, const int line, const char *fmt, ...);
#define panicx(...) _epanicx(__FILE__, __LINE__, __VA_ARGS__)


/* 
 * filter-syntax.c
 */
int parse_filter(char *, treenode_t **, char **);
int evaluate(treenode_t *t, pkt_t *pkt);
treenode_t *tree_copy(treenode_t *t);


/*
 * util-socket.c
 */
int create_socket(const char *name, char **arg);
int del_fd(int i, fd_set * fds, int max_fd);
int add_fd(int i, fd_set * fds, int max_fd);


/*
 * util-io.c
 */
int como_readn(int fd, char *buf, size_t len);
int como_writen(int fd, const char *buf, size_t len);


/* 
 * util-misc.c
 */
char *getprotoname(int proto);
void *load_object(char *base_name, char *symbol);
void *load_object_h(char *base_name, char *symbol, void **handle);
void unload_object(void *handle);


/*
 * util-safe.c 
 * 
 * If possible, do not call malloc(),  calloc() and realloc() directly.
 * Instead use safe_malloc(), safe_calloc() and safe_realloc() which provide
 * wrappers to check the arguments and panic if necessary.
 */
void *_smalloc(const char * file, const int line, size_t sz); 
#define safe_malloc(...) _smalloc(__FILE__, __LINE__, __VA_ARGS__) 
void *_scalloc(const char * file, const int line, int n, size_t sz); 
#define safe_calloc(...) _scalloc(__FILE__, __LINE__, __VA_ARGS__) 
void *_srealloc(const char * file, const int line, void * ptr, size_t sz); 
#define safe_realloc(...) _srealloc(__FILE__, __LINE__, __VA_ARGS__) 
char *_sstrdup(const char * file, const int line, char * str); 
#define safe_strdup(...) _sstrdup(__FILE__, __LINE__, __VA_ARGS__) 
void _sfree(const char * file, const int line, void * ptr); 
#define safe_free(...) _sfree(__FILE__, __LINE__, __VA_ARGS__) 
void _sdup(const char * file, const int line, char ** dst, char * src); 
#define safe_dup(...) _sdup(__FILE__, __LINE__, __VA_ARGS__) 


/* 
 * util-timers.c
 */
#ifdef DO_PROFILING 

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
 * ipc.c
 */
void ipc_init(void);
void register_ipc_fd(int fd);
void unregister_ipc_fd(int fd);
int  sup_send_new_modules(void);
void sup_send_module_status(void);
void recv_message(int fd, proc_callbacks_t *callbacks);
int  sup_recv_message(int fd);
void sup_wait_for_ack(int fd);

/*
 * res-mgmt.c
 */
#ifdef RESOURCE_MANAGEMENT

void resource_mgmt_init(void);
char *resource_usage_report(void);
void schedule(void);

#else 

#define resource_mgmt_init(x)
#define resource_usage_report(x)
#define schedule(x)

#endif


/* 
 * profiling.c 
 */
#ifdef DO_PROFILING 

void init_timers(void); 
void print_timers(void); 
void reset_timers(void); 

#else

#define init_timers()
#define print_timers()
#define reset_timers()

#endif



#endif /* _COMO_FUNC_H */
