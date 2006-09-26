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


#ifndef HASH_H_
#define HASH_H_

#include "corlib.h"

/** Hash iterator object. The iterator is on the stack, but its real
 * fields are hidden privately.
 */
struct hash_iter_t
{
  void *dummy1; /* Do not use. */
  void *dummy2; /* Do not use. */
  void *dummy3; /* Do not use. */
  void *dummy4; /* Do not use. */
  int   dummy5; /* Do not use. */
  int   dummy6; /* Do not use. */
};

/*
 * Forward declarations of hash_table_t and related types.
 */
typedef struct hash_t hash_t;
typedef struct hash_iter_t  hash_iter_t;

typedef unsigned int (*hash_key_fn) (const void *keyPtr);
typedef int (*compare_hash_keys_fn) (const void *keyPtr1, const void *keyPtr2);

/*
 * Acceptable key types for hash tables:
 *
 * HASHKEYS_STRING:		The keys are strings, the pointer is stored in
 *				the entry.
 * HASHKEYS_ULONG:		The keys are ulongs, the value is stored
 *				in the entry.
 * HASHKEYS_POINTER:		The keys are pointers to arbitrary types, the
 *				pointer is stored in the entry.
 */
typedef enum {
	HASHKEYS_STRING =	0,
	HASHKEYS_ULONG =	1,
	HASHKEYS_POINTER =	2
} HASHKEYS;

hash_t *hash_new          (allocator_t *alc,
			   int keyType, hash_key_fn hashKeyFn,
			   compare_hash_keys_fn compareKeysFn);
hash_t *hash_new_full     (allocator_t *alc,
			   int keyType, hash_key_fn hashKeyFn,
			   compare_hash_keys_fn compareKeysFn,
			   destroy_notify_fn keyDestroyFn,
			   destroy_notify_fn valueDestroyFn);
int     hash_size     (hash_t * tablePtr);
void *  hash_lookup_string(hash_t *tablePtr, const char *key);
void *  hash_lookup_ulong (hash_t *tablePtr, unsigned long key);
void *  hash_lookup       (hash_t *tablePtr, void *key);
int     hash_insert_string(hash_t *tablePtr, const char *key, void *value);
int     hash_insert_ulong (hash_t *tablePtr, unsigned long key, void *value);
int     hash_insert       (hash_t *tablePtr, void *key, void *value);
int     hash_remove_string(hash_t *tablePtr, const char *key);
int     hash_remove_ulong (hash_t *tablePtr, unsigned long key);
int     hash_remove       (hash_t *tablePtr, void *key);
void    hash_destroy      (hash_t *tablePtr);

void          hash_iter_init          (hash_t * table, hash_iter_t * iter);
int           hash_iter_next          (hash_iter_t * iter);
void          hash_iter_remove_entry  (hash_iter_t * iter);
void *        hash_iter_get_value     (hash_iter_t * iter);
void          hash_iter_set_value     (hash_iter_t * iter, void *value);
void *        hash_iter_get_key       (hash_iter_t * iter);
unsigned long hash_iter_get_ulong_key (hash_iter_t * iter);
const char *  hash_iter_get_string_key(hash_iter_t * iter);

#endif /*HASH_H_*/
