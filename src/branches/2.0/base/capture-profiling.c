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
 * $Id: capture.c 1218 2007-10-30 14:06:49Z jsanjuas $
 */

/* #define CAPTURE_PROFILING */

#ifndef CAPTURE_PROFILING
#define capture_profiler_notify(x)
#else

#define CAPTURE_PROF_FILE "/tmp/como-capture-profiling.txt"

enum {
    CP_START_SNIFFERS,
    CP_END_SNIFFERS,
    CP_START_SELECT,
    CP_END_SELECT,
    CP_START_BATCH_CREATE,
    CP_END_BATCH_CREATE,
    CP_START_PROCESS_BATCH,
    CP_END_PROCESS_BATCH,
};

static int cp_initialized = 0;

static ctimer_t *cp_sniff_reads;
static ctimer_t *cp_select;
static ctimer_t *cp_batch_create;
static ctimer_t *cp_batch_process;

static FILE *cp_file;

static inline void
cp_initialize(void)
{
    if (cp_initialized)
        return;

    cp_initialized = 1;

    cp_sniff_reads = new_timer("sniffer_reads");
    cp_select = new_timer("select");
    cp_batch_create = new_timer("batch_create");
    cp_batch_process = new_timer("batch_process");

    cp_file = fopen(CAPTURE_PROF_FILE, "w");
    if (cp_file == NULL)
        error("Cannot open " CAPTURE_PROF_FILE " for writing\n");

    fprintf(cp_file, "select\tsniffer_reads\tbatch_create\tbatch_process\n");
}

static inline void
capture_profiler_notify(int event)
{
    cp_initialize();

    switch(event) {
        case CP_START_SNIFFERS:
            start_tsctimer(cp_sniff_reads);
            break;

        case CP_END_SNIFFERS:
            end_tsctimer(cp_sniff_reads);
            break;

        case CP_START_SELECT:
            start_tsctimer(cp_select);
            break;

        case CP_END_SELECT:
            end_tsctimer(cp_select);
            break;

        case CP_START_BATCH_CREATE:
            start_tsctimer(cp_batch_create);
            break;

        case CP_END_BATCH_CREATE:
            end_tsctimer(cp_batch_create);
            break;

        case CP_START_PROCESS_BATCH:
            start_tsctimer(cp_batch_process);
            break;

        case CP_END_PROCESS_BATCH:
            end_tsctimer(cp_batch_process);

            fprintf(cp_file, "%llu\t%llu\t%llu\t%llu\n",
                    cp_select->total, cp_sniff_reads->total,
                    cp_batch_create->total, cp_batch_process->total);

            reset_timer(cp_sniff_reads);
            reset_timer(cp_select);
            reset_timer(cp_batch_create);
            reset_timer(cp_batch_process);
            break;
    }
}

#endif
