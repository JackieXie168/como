/*
 * Copyright (c) 2006-2007, Intel Corporation
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
 * $Id: flowcount.c 1012 2006-11-13 15:04:31Z jsanjuas $
 */

/*
 * Flow counter.
 *
 * Provides a count of the active flows in the measurement interval.
 * The user can decide what the exact definition of a flow is (e.g. the
 * 5-tuple, or the pair of src and dst addresses)
 * 
 * It uses a techinque called "probabilistic counting" (see "A Linear-Time
 * Probabilistic Counting Algorithm for Database applications", by Kyu-Young
 * Whang, Brad T. Vander-Zanden and Howard M. Taylor) to provide an accurate
 * estimation of the number of flows, without the overhead of maintaining
 * per-flow entries in a hash table.
 *
 */

#include "como.h"

como_tuple como_record struct record {
    timestamp_t ts;
    uint32_t count;
};

como_config struct config {
    int meas_ivl;
    uint32_t max_keys;
    int flow_fields;
};

typedef struct record record_t;
typedef struct config config_t;

#define USE_SRC     0x01
#define USE_DST     0x02
#define USE_SPORT   0x04
#define USE_DPORT   0x08
#define USE_PROTO   0x10
#define USE_ALL     (USE_SRC|USE_DST|USE_SPORT|USE_DPORT|USE_PROTO)


