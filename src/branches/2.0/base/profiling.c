/*
 * Copyright (c) 2004-2006, Intel Corporation
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

/* 
 * XXX This code is still work in progress. It is used to time
 *     various operations of the CAPTURE and EXPORT processes. 
 *
 */

#include <sys/gmon.h>
#ifdef __APPLE__
#include <monitor.h>
#include <mach-o/getsect.h>
#endif /* __APPLE__ */

#include "como.h"
#include "comotypes.h"

/* stats 'inherited' from SU */
extern stats_t *como_stats;


void
enable_profiling()
{
    /* To get timing information after fork() the child has to call
     * monstartup().
     * 
     * http://gcc.gnu.org/ml/gcc-bugs/2001-09/msg00156.html
     */
#ifndef __APPLE__
    extern void _start (void), etext (void);
    monstartup ((u_long) &_start, (u_long) &etext);
#else
    /* There is no etext symbol in mach-o binaries, instead there's
     * a function call used to get the equivelent pointed.
     */
    unsigned long etext = get_etext();
    extern void _start (void);
    monstartup ((char*)&_start, (char*)etext);
#endif /* __APPLE__*/
}


/*  
 * -- init_timers
 * 
 * initialize timers for profiling CAPTURE and 
 * EXPORT performance 
 *
 */
void
ca_init_timers() 
{
    como_stats->ca_full_timer = new_timer("full");
    como_stats->ca_loop_timer = new_timer("loop");
    como_stats->ca_pkts_timer = new_timer("pkts");
    como_stats->ca_filter_timer = new_timer("filter");
    como_stats->ca_module_timer = new_timer("modules");
    como_stats->ca_updatecb_timer = new_timer("update");
    como_stats->ca_sniff_timer = new_timer("sniffer");
}

void
ex_init_timers()
{
    como_stats->ex_full_timer = new_timer("full");
    como_stats->ex_loop_timer = new_timer("loop");
    como_stats->ex_table_timer = new_timer("table");
    como_stats->ex_export_timer = new_timer("export");
    como_stats->ex_store_timer = new_timer("store");
    como_stats->ex_mapping_timer = new_timer("mapping");
}
	
     
/* 
 * -- print_timers
 * 
 * print timer values using LOGTIMER flag. 
 *
 */
void
ca_print_timers() 
{
    msg("timing after %llu packets\n", como_stats->pkts);
    msg("\t%s\n", print_timer(como_stats->ca_full_timer));
    msg("\t%s\n", print_timer(como_stats->ca_loop_timer));
    msg("\t%s\n", print_timer(como_stats->ca_sniff_timer));
    msg("\t%s\n", print_timer(como_stats->ca_pkts_timer));
    msg("\t%s\n", print_timer(como_stats->ca_filter_timer));
    msg("\t%s\n", print_timer(como_stats->ca_module_timer));
    msg("\t%s\n", print_timer(como_stats->ca_updatecb_timer));
}

void
ex_print_timers()
{
    msg("\t%s\n", print_timer(como_stats->ex_full_timer));
    msg("\t%s\n", print_timer(como_stats->ex_loop_timer));
    msg("\t%s\n", print_timer(como_stats->ex_table_timer));
    msg("\t%s\n", print_timer(como_stats->ex_store_timer));
    msg("\t%s\n", print_timer(como_stats->ex_mapping_timer));
    msg("\t%s\n", print_timer(como_stats->ex_export_timer));
}


/*
 * -- reset_timers
 *  
 * resets timers for next round 
 * 
 */
void
ca_reset_timers() 
{
    reset_timer(como_stats->ca_full_timer);
    reset_timer(como_stats->ca_loop_timer);
    reset_timer(como_stats->ca_sniff_timer);
    reset_timer(como_stats->ca_pkts_timer);
    reset_timer(como_stats->ca_filter_timer);
    reset_timer(como_stats->ca_module_timer);
    reset_timer(como_stats->ca_updatecb_timer);
}

void
ex_reset_timers()
{
    reset_timer(como_stats->ex_full_timer);
    reset_timer(como_stats->ex_loop_timer);
    reset_timer(como_stats->ex_table_timer);
    reset_timer(como_stats->ex_store_timer);
    reset_timer(como_stats->ex_mapping_timer);
    reset_timer(como_stats->ex_export_timer);
}
