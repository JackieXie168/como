/*
 * Copyright (c) 2004-2007, Intel Corporation
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
#include "data.h"
#include "como.h"

/*
 * this module's records have variable size, and this cannot
 * be handled by the core. We define the serialization
 * functions by hand.
 */
char * record_type = "record";

int
sersize_record(record_t *rec)
{
    return sizeof(timestamp_t) + sizeof(uint32_t) +
        rec->count * (sizeof(uint64_t) + sizeof(uint32_t));
}

void
serialize_record(char **buffer, record_t *rec)
{
    uint32_t i;

    serialize_timestamp_t(buffer, rec->ts);
    serialize_uint32_t(buffer, rec->count);
    for (i = 0; i < rec->count; i++) {
        serialize_uint64_t(buffer, rec->entry[i].bytes);
        serialize_uint32_t(buffer, rec->entry[i].pkts);
    }
}

void
deserialize_record(char **buffer, record_t **x, alc_t *alloc)

{
    uint32_t count, i;
    size_t sz;
    record_t *rec;
    uint64_t ts;

    deserialize_timestamp_t(buffer, &ts);
    deserialize_uint32_t(buffer, &count);

    /* now we have sufficient info to know how much to allocate */
    sz = sizeof(timestamp_t) + sizeof(uint32_t) +
            count * (sizeof(uint64_t) + sizeof(uint32_t));
    rec = alc_malloc(alloc, sz);
    rec->ts = ts;
    rec->count = count;

    for (i = 0; i < count; i++) {
        deserialize_uint64_t(buffer, &rec->entry[i].bytes);
        deserialize_uint32_t(buffer, &rec->entry[i].pkts);
    }

    *x = rec;
}

/*
 * the core now knows how to handle our record, so
 * we can define the module callbacks as usual.
 */
void *
ex_init(mdl_t *self)
{
    return NULL;
}

/* XXX this module needs explicit store/load! */

void
export(mdl_t *self, tuple_t **tuples, size_t ntuples, timestamp_t ivl_start,
        void *state)
{
    config_t *config = mdl_get_config(self, config_t);
    record_t *r;
    size_t i;

    for (i = 0; i < ntuples; i++) {
        uint32_t j;

        r = mdl_malloc(self, sizeof(record_t) +
                config->types_count * sizeof(rentry_t));

        r->ts = tuples[i]->ts;
        r->count = config->types_count;

        for (j = 0; j < r->count; j++) {
            r->entry[j].bytes = tuples[i]->bytes[j];
            r->entry[j].pkts = tuples[i]->pkts[j];
        }
        mdl_store_rec(self, r);
    }
}



