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

#ifndef PREDICTION_H_
#define PREDICTION_H_

#include "feats.h"

#ifndef NUM_OBS
#define NUM_OBS     60          /* number of observations
                                   for the prediction (default: 60) */
#endif

#ifndef CORR_THRESH
#define CORR_THRESH 0.6         /* correlation threshold for
                                   feature selection (default: 0.6) */
#endif

#define NUM_PREDS   NUM_FEATS   /* number of predictors = number of feats */

typedef struct prediction prediction_t;
typedef struct pred pred_t;

struct pred {
    char name[LS_STRLEN];
    double corrcoef;
    double values[NUM_OBS];
};

struct prediction {
    int nsel;                 /* number of selected predictors */
    pred_t *sel[NUM_PREDS];   /* pointers to selected predictors */
    pred_t hist[NUM_PREDS];   /* history of predictors */
    double resp[NUM_OBS];     /* history of the response variable */
    double pcycles;           /* predicted cycles */
};

#endif /* PREDICTION_H_ */
