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

struct _como_metadesc_match {
    metadesc_t *in;
    metadesc_t *out;
    int affinity;
};

typedef struct _como_metadesc_match metadesc_match_t;

void   metadesc_list_free       (metadesc_t *head);
int    metadesc_best_match      (metadesc_t *out, metadesc_t *in,
				 metadesc_match_t *best);
char * metadesc_determine_filter(metadesc_t *md);

pktmeta_type_t pktmeta_type_from_name(const char *name);

/*
 * util-process.c
 */
typedef void (*mainloop_fn) (int out_fd, int in_fd);

typedef struct child_info_t {
    procname_t who;
    pid_t pid;
} child_info_t;

pid_t start_child (procname_t who, int mem_type, 
		   mainloop_fn mainloop, int in_fd,
		   child_info_t *children, int children_count);
int handle_children (child_info_t *children, int children_count);

/*
 * supervisor.c
 */
#define SU_CHILDREN_COUNT	10
extern child_info_t su_children[SU_CHILDREN_COUNT];

/*
 * inline.c
 */
void inline_mainloop(int accept_fd);

/*
 * memory.c
 */
typedef enum memmap_policy_t {
    POLICY_HOLD_FREE_BLOCKS = 0x5a,
    POLICY_HOLD_IN_USE_BLOCKS = 0xa5
} memmap_policy_t;

void          allocator_init_module(module_t *mdl);
allocator_t * allocator_safe();
allocator_t * allocator_shared();

void       memory_init(uint chunk);

memmap_t * memmap_new(allocator_t *alc, uint entries, memmap_policy_t pol);
void       memmap_destroy(memmap_t *ml);

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
module_t * module_lookup_with_name_and_node(const char *name, int node);
off_t      module_db_seek_by_ts(module_t *mdl, int fd, timestamp_t start);
void *     module_db_record_get(int fd, off_t * ofs, module_t * mdl,
				ssize_t *len, timestamp_t *ts);
int        module_db_record_print(module_t * mdl, char * ptr, char **args,
				  int client_fd);
int        module_db_record_replay(module_t * mdl, char * ptr, int client_fd);

#define	GR_LOSTSYNC	((void *) module_db_record_get)


#endif /*COMOPRIV_H_*/
