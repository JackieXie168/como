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
 * $Id: $
 */

#include <sys/time.h>       /* getrusage */
#include <sys/resource.h>   /* getrusage */
#include "como.h"
#include "comopriv.h"
#include "ls-profiling.h"

profiler_t *
new_profiler(char *name)
{
    profiler_t *profiler = como_calloc(1, sizeof(profiler_t));
    profiler->name = como_strdup(name);
    profiler->ctx_switches = new_timer("ctxsw");
    profiler->tsc_cycles = new_timer("tsc");
    return profiler;
}


void
destroy_profiler(profiler_t *profiler)
{
    free(profiler->name);
    destroy_timer(profiler->ctx_switches);
    destroy_timer(profiler->tsc_cycles);
    free(profiler);
}


void
ca_init_profilers(como_ca_t *como_ca)
{
    como_ca->ls.ca_oh_prof = new_profiler("ca");
}


__inline__ void
start_ctxsw_counter(ctimer_t *t)
{
    struct rusage usg;
    /* XXX check return value */
    getrusage(RUSAGE_SELF, &usg);
    start_timer(t, usg.ru_nvcsw + usg.ru_nivcsw);
}


__inline__ void
end_ctxsw_counter(ctimer_t *t)
{   
    struct rusage usg;
    /* XXX check return value */
    getrusage(RUSAGE_SELF, &usg);
    end_timer(t, usg.ru_nvcsw + usg.ru_nivcsw);
}


/* 
 * -- rdtsc()
 * 
 * read the timestamp counter (TSC) and return its value (64 bit)
 * 
 */
static __inline__ uint64_t
rdtsc(void)
{
    u_int64_t rv;
#ifdef BUILD_FOR_ARM 
    rv = 0; 
#else
    __asm __volatile(".byte 0x0f, 0x31" : "=A" (rv));
#endif
    return (rv);
}


/*
 * -- serialize()
 *
 * Execute a serializing operation to increase accuracy of
 * performance counters (see IA-32 Architecture Software
 * Developer's Manual, 7.4 Serializing Instructions).
 * 
 */
#ifdef BUILD_FOR_ARM
#   define serialize()
#else
#   define serialize() \
        do { \
            __asm __volatile( "cpuid" ::: "eax", "ebx", "ecx", "edx"); \
        } while(0) 
#endif


__inline__ void
start_profiler(profiler_t *profiler)
{
    /* Start counters */
    serialize();
    start_tsctimer(profiler->tsc_cycles);
    start_ctxsw_counter(profiler->ctx_switches);
}


__inline__ void
end_profiler(profiler_t *profiler)
{
    /* Read counters and update */
    serialize();
    end_tsctimer(profiler->tsc_cycles);
    end_ctxsw_counter(profiler->ctx_switches);
}


__inline__ void
reset_profiler(profiler_t *profiler)
{
    reset_timer(profiler->ctx_switches);
    reset_timer(profiler->tsc_cycles);
}
