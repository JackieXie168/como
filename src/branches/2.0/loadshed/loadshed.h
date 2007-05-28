/*
 * Copyright (c) 2007 Universitat Politecnica de Catalunya
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: $
 */

#ifndef LOADSHED_H_
#define LOADSHED_H_

#include "prediction.h"
#include "ls-profiling.h"

#define SHED_METHOD_PKT    0
#define SHED_METHOD_FLOW   1

typedef struct ls ls_t;
typedef struct mdl_ls mdl_ls_t;

struct ls {
    uint64_t pcycles;       /* total predicted cycles */
    uint64_t rcycles;       /* total real cycles */
    profiler_t *ca_oh_prof; /* capture process overhead profiler */
};

struct mdl_ls {
    uint64_t batches;   /* number of batches */
    int obs;            /* number of the current observation */
    fextr_t fextr;      /* feature extraction info */
    prediction_t pred;  /* prediction info */
    profiler_t *prof;   /* module profiler */
    int shed_method;    /* method desired for load shedding */
    double srate;       /* shedding rate */
    double tmp_srate;
    double max_srate;
    uhash_t **hash;     /* hash functions used for shedding */
};

#endif /* LOADSHED_H_ */