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

#ifndef _SERIALIZE_H
#define _SERIALIZE_H
#include <string.h>
#include <stdint.h>
#include "allocator.h"

typedef void   (serialize_fn)   (uint8_t ** sbuf, const void * data);
typedef void   (deserialize_fn) (uint8_t ** sbuf, void ** data_out,
				  alc_t * alc);
typedef size_t (sersize_fn)  (const void * src);

typedef struct serializable {
    serialize_fn	* serialize;
    deserialize_fn	* deserialize;
    sersize_fn		* sersize;
} serializable_t;

#define serialize_type_value(sbuf, val, type) do {  \
    type __val = val;                               \
    memcpy(*sbuf, &__val, sizeof(type));            \
    *sbuf += sizeof(type);                          \
} while (0)

#define serialize_uint64_t(sbuf,x) serialize_type_value(sbuf, x, uint64_t)
#define serialize_uint32_t(sbuf,x) serialize_type_value(sbuf, x, uint32_t)
#define serialize_uint16_t(sbuf,x) serialize_type_value(sbuf, x, uint16_t)
#define serialize_uint8_t(sbuf,x)  serialize_type_value(sbuf, x, uint8_t)

#define serialize_int64_t(sbuf,x) serialize_type_value(sbuf, x, int64_t)
#define serialize_int32_t(sbuf,x) serialize_type_value(sbuf, x, int32_t)
#define serialize_int16_t(sbuf,x) serialize_type_value(sbuf, x, int16_t)
#define serialize_int8_t(sbuf,x)  serialize_type_value(sbuf, x, int8_t)

#define serialize_timestamp_t serialize_uint64_t
#define serialize_int serialize_int32_t

#define serialize_string(sbuf, val) do {\
    size_t __sz;			\
    __sz = strlen(val);		        \
    serialize_uint32_t(sbuf, __sz);	\
    memcpy(*sbuf, val, __sz);	        \
    *sbuf += __sz;			\
} while(0)


#define deserialize_type_value(sbuf,where,type) do {    \
    memcpy(where, *sbuf, sizeof(type));                 \
    *sbuf += sizeof(type);                              \
} while(0)

#define deserialize_uint64_t(sbuf,x) deserialize_type_value(sbuf, x, uint64_t)
#define deserialize_uint32_t(sbuf,x) deserialize_type_value(sbuf, x, uint32_t)
#define deserialize_uint16_t(sbuf,x) deserialize_type_value(sbuf, x, uint16_t)
#define deserialize_uint8_t(sbuf,x)  deserialize_type_value(sbuf, x, uint8_t)

#define deserialize_int64_t(sbuf,x) deserialize_type_value(sbuf, x, int64_t)
#define deserialize_int32_t(sbuf,x) deserialize_type_value(sbuf, x, int32_t)
#define deserialize_int16_t(sbuf,x) deserialize_type_value(sbuf, x, int16_t)
#define deserialize_int8_t(sbuf,x)  deserialize_type_value(sbuf, x, int8_t)

#define deserialize_timestamp_t deserialize_uint64_t
#define deserialize_int deserialize_int32_t

#define deserialize_string(sbuf,val_out,alc) do { \
    size_t sz;					\
    char *val;					\
    deserialize_uint32_t(sbuf, &sz);		\
    val = alc_malloc(alc, sz + 1);		\
    memcpy(val, sbuf, sz);			\
    val[sz] = '\0';				\
    *val_out = val;				\
    *sbuf += sz;				\
} while(0)


#define sersize_type(type) sizeof(type)
#define sersize_uint64_t(x) sersize_type(uint64_t)
#define sersize_uint32_t(x) sersize_type(uint32_t)
#define sersize_uint16_t(x) sersize_type(uint16_t)
#define sersize_uint8_t(x)  sersize_type(uint8_t)

#define sersize_int64_t(x) sersize_type(int64_t)
#define sersize_int32_t(x) sersize_type(int32_t)
#define sersize_int16_t(x) sersize_type(int16_t)
#define sersize_int8_t(x)  sersize_type(int8_t)

#define sersize_timestamp_t sersize_uint64_t
#define sersize_int sersize_int32_t

#define sersize_string(val) (sersize_uint32_t(x) + strlen(val))

#endif
