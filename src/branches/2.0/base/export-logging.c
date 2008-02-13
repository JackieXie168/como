/*
 * Copyright (c) 2007, Universitat Politecnica de Catalunya
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

#define EX_LOGGING

#ifndef EX_LOGGING
#define ex_log_start_measuring()
#define ex_log_stop_measuring()
#define ex_log_module_info(a, b, c, d)
#else

#include <sys/time.h>       /* getrusage */
#include <sys/resource.h>   /* getrusage */

#define EX_LOG_TEMPLATE "/tmp/como/como_ex_%s.txt"

extern stats_t *como_stats;

static ctimer_t *ex_log_timer = NULL;
static int ex_log_ctxsw_counter;

typedef struct _ex_log_module_info ex_log_module_info_t;
struct _ex_log_module_info {
    FILE *file;
    uint64_t sum_cycles;
    uint64_t sum_ntuples;
    size_t tuple_size;
};

ex_log_module_info_t ex_log_mdl_info[MDL_ID_MAX];

static void
ex_log_start_measuring(void)
{
    struct rusage usg;

    if (ex_log_timer == NULL)
        ex_log_timer = new_timer("");

    start_tsctimer(ex_log_timer);
    getrusage(RUSAGE_SELF, &usg);
    ex_log_ctxsw_counter = -usg.ru_nvcsw - usg.ru_nivcsw;
    
}

static void
ex_log_stop_measuring(void)
{
    struct rusage usg;

    getrusage(RUSAGE_SELF, &usg);
    ex_log_ctxsw_counter += usg.ru_nvcsw + usg.ru_nivcsw;
    end_tsctimer(ex_log_timer);
}

static FILE *
ex_log_get_file(mdl_t *mdl)
{
    FILE **val;
    char *file;

    val = &ex_log_mdl_info[mdl->id].file;
    if (*val != NULL)
        return *val; /* found */

    file = como_asprintf(EX_LOG_TEMPLATE, mdl->name);
    *val = fopen(file, "w");
    if (*val == NULL)
        error("cannot open output file `%s' for export logging\n", file);
    free(file);

    fprintf(*val, "localtime\tex_mem\tqueued_mem\tcycles\tctxsw\tntuples"
            "\tbytes\tcycles_per_tuple\tremaining_work\n");

    return *val;

}

static void
ex_log_module_info(mdl_t *mdl, int ntuples, size_t queue_size,
        size_t tuple_mem)
{
    ex_log_module_info_t *info = &ex_log_mdl_info[mdl->id];
    uint64_t cycles = get_last_sample(ex_log_timer);
    double localtime, cpt, remaining_work;
    struct timeval tv;
    FILE *f;

    f = ex_log_get_file(mdl);

    if (gettimeofday(&tv, NULL) < 0)
        error("could not gettimeofday()\n");
    localtime = tv.tv_sec + (double)tv.tv_usec / 1000000;

    if (info->sum_ntuples != 0)
        cpt = (double)info->sum_cycles / (double)info->sum_ntuples;
    else
        cpt = 0;

    if (info->tuple_size == 0 && ntuples > 0)
        info->tuple_size = tuple_mem / ntuples;
    else if (ntuples > 0)
        assert(info->tuple_size == tuple_mem / ntuples);

    if (info->tuple_size == 0)
        remaining_work = 0;
    else
        remaining_work = queue_size * cpt / info->tuple_size;

    fprintf(f, "%f\t%d\t%d\t%llu\t%d\t%d\t%d\t%f\t%f\n", localtime,
                mdl_get_iexport(mdl)->used_mem,
                queue_size,
                cycles,
                ex_log_ctxsw_counter,
                ntuples,
                tuple_mem,
                cpt,
                remaining_work);
    fflush(f);

    if (ex_log_ctxsw_counter == 0) {
        info->sum_ntuples += ntuples;
        info->sum_cycles += cycles;
    }
}

#endif

