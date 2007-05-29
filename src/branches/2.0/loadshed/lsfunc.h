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

#ifndef _LSFUNC_H
#define _LSFUNC_H

/* feats.c */
void feat_extr(batch_t *, char *, mdl_t *);

/* loadshed.c */
void batch_loadshed_pre(batch_t *, como_ca_t *, char *);
void batch_loadshed_post(como_ca_t *);
void ls_init_mdl(char *, mdl_ls_t *, char *);
void ls_init_ca(como_ca_t *);


/* prediction.c */
void pred_sel(mdl_ls_t *);
void update_pred_hist(mdl_ls_t *);
double predict(mdl_ls_t *);

/* ls-profiling.c */
profiler_t *new_profiler(char *name);
void start_profiler(profiler_t *);
void end_profiler(profiler_t *);
void reset_profiler(profiler_t *profiler);
void ca_init_profilers(como_ca_t *como_ca);


#endif /* _LSFUNC_H */
