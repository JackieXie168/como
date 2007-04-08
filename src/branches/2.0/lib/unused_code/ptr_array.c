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

/* Based on eglib's ptr array */
/*
 * Pointer Array
 *
 * Author:
 *   Aaron Bockover (abockover@novell.com)
 *
 * (C) 2006 Novell, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <string.h>

#include "corlib.h"

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif


static void
ptr_array_grow(ptr_array_t * array, int length)
{
    int off = array->pdata - array->base;
    int new_length = array->len + length + off;

    if (new_length <= array->size) {
	return;
    }

    array->size = 1;

    while (array->size < new_length) {
	array->size <<= 1;
    }

    array->size = MAX(array->size, 16);
    array->base = safe_realloc(array->base, array->size * sizeof(void *));
    array->pdata = array->base + off;
}

ptr_array_t *
ptr_array_new()
{
    return ptr_array_sized_new(0);
}

ptr_array_t *
ptr_array_sized_new(int reserved_size)
{
    ptr_array_t *array = safe_calloc(1, sizeof(ptr_array_t));

    if (reserved_size > 0) {
	ptr_array_grow(array, reserved_size);
    }

    return (ptr_array_t *) array;
}

void **
ptr_array_free(ptr_array_t * array, int free_seg)
{
    void **data = NULL;

    if (array == NULL) {
	return NULL;
    }
    if (free_seg) {
	free(array->base);
    } else {
	if (array->pdata != array->base) {
	    memmove(array->base, array->pdata,
		    array->len * sizeof(void *));
	}
	data = array->base;
    }

    free(array);

    return data;
}

void
ptr_array_add(ptr_array_t * array, void *data)
{
    ptr_array_grow(array, 1);
    array->pdata[array->len++] = data;
}

void
ptr_array_sort(ptr_array_t * array, cmp_fn cmpFn)
{
    qsort(array->pdata, array->len, sizeof(void *), cmpFn);
}

void *
ptr_array_shift(ptr_array_t * array)
{
    void **x;
    x = array->pdata;
    array->pdata++;
    array->len--;
    return *x;
}

