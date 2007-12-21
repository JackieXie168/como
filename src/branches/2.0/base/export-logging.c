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

/* #define EX_LOGGING */

#ifndef EX_LOGGING
#define ex_log_module_info(x, y, z)
#else

#define EX_LOG_TEMPLATE "/tmp/como/como_ex_%s.txt"

extern stats_t *como_stats;

static int ex_log_initialized = 0;
static hash_t *ex_log_mdl_info;

static void
ex_log_initialize(void)
{
    if (ex_log_initialized)
        return;

    ex_log_mdl_info = hash_new(como_alc(), HASHKEYS_STRING, NULL, NULL);
    ex_log_initialized = 1;
}

static FILE *
ex_log_get_file(mdl_t *mdl)
{
    FILE **val;
    char *file;

    if ((val = hash_lookup_string(ex_log_mdl_info, mdl->name)))
        return *val; /* found */

    val = como_malloc(sizeof(FILE *)); /* not found, create new entry */

    file = como_asprintf(EX_LOG_TEMPLATE, mdl->name);
    *val = fopen(file, "w");
    if (*val == NULL)
        error("cannot open output file `%s' for export logging\n", file);
    free(file);

    hash_insert_string(ex_log_mdl_info, mdl->name, val);

    fprintf(*val, "ex_mem\tqueued_mem\tcycles\tntuples\n");

    return *val;

}

static void
ex_log_module_info(mdl_t *mdl, uint64_t cycles, int ntuples)
{
    FILE *f;

    ex_log_initialize();
    f = ex_log_get_file(mdl);

    fprintf(f, "%d\t%d\t%llu\t%d\n", mdl_get_iexport(mdl)->used_mem,
                como_stats->mdl_stats[mdl->id].ex_queue_size,
                cycles, ntuples);
    fflush(f);
}

#endif

