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
 * $Id$
 */

#ifndef FEATS_H_
#define FEATS_H_

#include "bitmap.h"
#include "uhash.h"

#define LS_STRLEN      30

#define NUM_FEATS      55 
#define NO_BM_FEATS     3   /* number of features that do not need bitmaps
                               in order to be calculated */
#define NUM_HASH        5   /* src_ip, dst_ip, ip_proto, src_port, dst_port */
#define NUM_BITMAPS    13

#define NUM_KEYS   134190   /* number of keys expected per bitmap.
                               this is equivalent to a size of 2^15 bits */

typedef struct feat feat_t;
typedef struct fextr fextr_t;

struct feat {
    char name[LS_STRLEN];
    double value;
};

struct fextr {
    feat_t feats[NUM_FEATS];
    bitmap_t **bitmaps;
    uhash_t **hash;
    timestamp_t last_ivl;
};

#endif /* FEATS_H_ */
