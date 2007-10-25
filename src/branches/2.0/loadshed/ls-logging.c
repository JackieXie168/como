/*
 * Copyright (c) 2007 Universitat Politecnica de Catalunya
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

/* #define LS_LOGGING */

#ifndef LS_LOGGING
#define log_prederr_start(x)
#define log_prederr_line(x, y, z)
#define log_prederr_end()
#define log_feats(x, y)
#else

#include <math.h>

static FILE *prederr_f = NULL;

static void UNUSED
log_prederr_start(array_t *mdls)
{
    int j;

    if (prederr_f != NULL)
        return;

    prederr_f = fopen("/tmp/como.log", "w");
    if (prederr_f == NULL)
        error("cannot open /tmp/como_prederr.log for writing\n");

    for (j = 0; j < mdls->len; j++) {
        mdl_t *mdl = array_at(mdls, mdl_t *, j);
        fprintf(prederr_f, "%s%s_pred\t%s_actual\t%s_err\t%s_npkts",
                j == 0 ? "" : "\t",
                mdl->name, mdl->name, mdl->name, mdl->name);
    }
    fprintf(prederr_f, "\n");
}

static void UNUSED
log_prederr_line(batch_t *batch, mdl_icapture_t *ic, int idx)
{
    float err = fabs(1 - (double)ic->ls.last_pred * ic->ls.srate /
              (double) ic->ls.prof->tsc_cycles->value);

    fprintf(prederr_f, "%s%f\t%llu\t%f\t%d", idx == 0 ? "" : "\t",
            (double)ic->ls.last_pred * ic->ls.srate,
            ic->ls.prof->tsc_cycles->value,
            err,
            batch->count);
}

static void UNUSED
log_prederr_end(void)
{
    fprintf(prederr_f, "\n");
}

static void UNUSED
log_feats(mdl_t *mdl, feat_t *feats)
{
    mdl = NULL;
    feats = NULL;
}

#endif

