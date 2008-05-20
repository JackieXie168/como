/*
 * Copyright (c) 2008, Intel Corporation
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

#include <assert.h>
#include "como.h"
#include "data.h"

/*
 * -- ex_init
 *
 * This module does not keep any state in export
 */
void *
ex_init(mdl_t *self)
{
    return NULL;
}

/*
 * -- export
 *
 * Translate a tuple into a record
 *
 */
void
export(mdl_t * self, tuple_t **tuples, size_t ntuples,
        timestamp_t ivl_start, void *st)
{
    tuple_t *t;
    record_t rec;

    if (ntuples == 0) /* nothing to do */
        return;

    assert(ntuples == 1); /* can only have 1 tuple */

    t = tuples[0];
    rec.ts = t->ts;
    rec.bytes[0] = t->bytes[0];
    rec.bytes[1] = t->bytes[1];
    rec.pkts[0] = t->pkts[0];
    rec.pkts[1] = t->pkts[1];

    mdl_store_rec(self, &rec); /* store the record */
}

