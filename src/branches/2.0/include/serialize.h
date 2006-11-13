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

typedef void   (*serialize_fn)   (uint8_t ** sbuf, const void * data);
typedef void   (*deserialize_fn) (uint8_t ** sbuf, void ** data_out,
				  alc_t * alc);
typedef size_t (*sersize_fn)  (const void * src);

typedef struct serializable {
    serialize_fn	serialize;
    deserialize_fn	deserialize;
    sersize_fn		sersize;
} serializable_t;

#define serialize_type_value(value, type) do {      \
    type __ser_value = (value);                     \
    memcpy(*buffer, &__ser_value, sizeof(type));    \
    *buffer += sizeof(type);                        \
    } while (0)

#define serialize_uint64_t(x) serialize_type_value(x, uint64_t)
#define serialize_uint32_t(x) serialize_type_value(x, uint32_t)
#define serialize_uint16_t(x) serialize_type_value(x, uint16_t)
#define serialize_uint8_t(x)  serialize_type_value(x, uint8_t)

#define serialize_int64_t(x) serialize_type_value(x, int64_t)
#define serialize_int32_t(x) serialize_type_value(x, int32_t)
#define serialize_int16_t(x) serialize_type_value(x, int16_t)
#define serialize_int8_t(x)  serialize_type_value(x, int8_t)

#define serialize_timestamp_t serialize_uint64_t
#define serialize_int serialize_int32_t

#define serialize_string(buffer,val) do {	\
    size_t sz;					\
    sz = strlen(val);				\
    serialize_uint32_t(buffer, sz);		\
    memcpy(*buffer, val, sz);			\
    *buffer += sz;				\
} while(0)


#define deserialize_type_value(where, type) do {    \
    memcpy(&(where), *buffer, sizeof(type));        \
    *buffer += sizeof(type);                        \
    } while(0)

#define deserialize_uint64_t(x) deserialize_type_value(x, uint64_t)
#define deserialize_uint32_t(x) deserialize_type_value(x, uint32_t)
#define deserialize_uint16_t(x) deserialize_type_value(x, uint16_t)
#define deserialize_uint8_t(x)  deserialize_type_value(x, uint8_t)

#define deserialize_int64_t(x) deserialize_type_value(x, int64_t)
#define deserialize_int32_t(x) deserialize_type_value(x, int32_t)
#define deserialize_int16_t(x) deserialize_type_value(x, int16_t)
#define deserialize_int8_t(x)  deserialize_type_value(x, int8_t)

#define deserialize_timestamp_t serialize_uint64_t
#define deserialize_int deserialize_int32_t

#define deserialize_string(buffer,val_out,alc) do { \
    size_t sz;					\
    char *val;					\
    sbuf = deserialize_uint32_t(buffer, &sz);	\
    val = alc_malloc(alc, sz + 1);		\
    memcpy(val, sbuf, sz);			\
    val[sz] = '\0';				\
    *val_out = val;				\
    *buffer += sz;				\
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
