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

/* CoMo portability library */

#ifndef FLOWTABLE_H_
#define FLOWTABLE_H_

#include <stdpkt.h>

/** Hash iterator object. The iterator is on the stack, but its real
 * fields are hidden privately.
 */
struct flowtable_iter_t
{
  void *dummy1; /* Do not use. */
  void *dummy2; /* Do not use. */
  void *dummy3; /* Do not use. */
  void *dummy4; /* Do not use. */
  int   dummy5; /* Do not use. */
  int   dummy6; /* Do not use. */
};

/*
 * Forward declarations of flowtable_table_t and related types.
 */
typedef struct flowtable_t flowtable_t;
typedef struct flowtable_iter_t  flowtable_iter_t;

/*
 * A flow_t can be anything.
 */
typedef void * flow_t;

typedef unsigned int flowhash_t;

typedef int        (*flow_equal_fn)  (const flow_t * flow1,
				      const flow_t * flow2);
typedef int        (*flow_match_fn)  (const void * key,
				      const flow_t * flow);


flowtable_t * flowtable_new    (alc_t * alc, int size,
				flow_equal_fn flowEqualFn,
				flow_match_fn flowMatchFn,
				destroy_notify_fn flowDestroyFn);
int      flowtable_size        (flowtable_t * ftable);
flow_t * flowtable_lookup      (flowtable_t * ftable, flowhash_t hash,
				const void * key);
int      flowtable_insert      (flowtable_t * ftable, flowhash_t hash,
				flow_t * flow);
int      flowtable_remove      (flowtable_t * ftable, flowhash_t hash,
				flow_t * flow);
void     flowtable_destroy     (flowtable_t * ftable);

#ifdef DEBUG
const char * flowtable_dbg_stats (flowtable_t *ftable);
#endif

void     flowtable_iter_init   (flowtable_t * ftable, flowtable_iter_t * iter);
int      flowtable_iter_next   (flowtable_iter_t * iter);
void     flowtable_iter_remove (flowtable_iter_t * iter);
flow_t * flowtable_iter_get    (flowtable_iter_t * iter);

#endif /*FLOWTABLE_H_*/
