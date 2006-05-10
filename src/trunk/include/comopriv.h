/*
 * Copyright (c) 2006 Intel Corporation
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

void *     mem_smalloc(size_t sz, const char * file, int line);
void *     mem_scalloc(size_t nmemb, size_t sz, const char * file, int line);
void       mem_sfree(void * p, const char * file, int line);
void       mem_sreturn(memmap_t *m, void * p, const char * file, int line);

#define mem_malloc(sz)		mem_smalloc(sz, __FILE__, __LINE__)
#define mem_calloc(nmemb,sz)	mem_scalloc(nmemb, sz, __FILE__, __LINE__)
#define mem_free(p)		mem_sfree(p, __FILE__, __LINE__)
#define mem_return(m,p)		mem_sreturn(m, p, __FILE__, __LINE__)

#endif /*COMOPRIV_H_*/
