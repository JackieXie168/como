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

#ifndef ALLOCATOR_H_
#define ALLOCATOR_H_

typedef void * (*alc_malloc_fn) (size_t size,
				 const char * file, int line,
				 void *data);

typedef void * (*alc_calloc_fn) (size_t nmemb, size_t size,
				 const char * file, int line,
				 void *data);

typedef void * (*alc_free_fn)   (void *ptr,
				 const char * file, int line,
				 void *data);

typedef struct alc {
    alc_malloc_fn	malloc;
    alc_calloc_fn	calloc;
    alc_free_fn		free;
    void *		data;
} alc_t;

#define alc_malloc(alc, size)		\
    (alc)->malloc(size, __FILE__, __LINE__, (alc)->data)

#define alc_calloc(alc, nmemb, size)	\
    (alc)->calloc(nmemb, size, __FILE__, __LINE__, (alc)->data)

#define alc_free(alc, ptr)		\
    (alc)->free(ptr, __FILE__, __LINE__, (alc)->data)

#define alc_new(alc, type)	alc_malloc(alc, sizeof(type))
#define alc_new0(alc, type)	alc_calloc(alc, 1, sizeof(type))

#endif /*ALLOCATOR_H_*/
