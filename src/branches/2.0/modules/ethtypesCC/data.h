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
 * $Id: ethtypes.c 1012 2006-11-13 15:04:31Z jsanjuas $
 */

#include "module.h"

#define MAX_TYPES		16

como_tuple struct et_tuple {
    timestamp_t ts;
    uint64_t bytes[MAX_TYPES];
    uint32_t pkts[MAX_TYPES];
};

typedef struct et_record_entry rentry_t;
struct et_record_entry {
    uint64_t bytes;
    uint32_t pkts;
};

struct et_record {
    timestamp_t	ts;
    uint32_t	count;
    rentry_t    entry[0];
};

#define TYPES_LTBL_MAX 512
como_config struct et_config {
    int		meas_ivl;	/* measurement interval */
    int		types_count;
    uint16_t    code[TYPES_LTBL_MAX];
    char        *name[TYPES_LTBL_MAX];
};

typedef struct et_tuple tuple_t;
typedef struct et_record record_t;
typedef struct et_config config_t;

