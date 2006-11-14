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

extern struct _como map;		/* global state */


static void
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
 * EXPORT perforamce 
 *
 */
void
init_timers() 
{
    switch (getprocclass(map.whoami)) {
    case CAPTURE: 
	map.stats->ca_full_timer = new_tsctimer("full");
	map.stats->ca_loop_timer = new_tsctimer("loop");
	map.stats->ca_pkts_timer = new_tsctimer("pkts");
	map.stats->ca_filter_timer = new_tsctimer("filter");
	map.stats->ca_module_timer = new_tsctimer("modules");
	map.stats->ca_updatecb_timer = new_tsctimer("update");
	map.stats->ca_sniff_timer = new_tsctimer("sniffer");
	break;

    case EXPORT:
	map.stats->ex_full_timer = new_tsctimer("full");
	map.stats->ex_loop_timer = new_tsctimer("loop");
	map.stats->ex_table_timer = new_tsctimer("table");
	map.stats->ex_export_timer = new_tsctimer("export");
	map.stats->ex_store_timer = new_tsctimer("store");
	map.stats->ex_mapping_timer = new_tsctimer("mapping");
	break;
    }
}
	
     
/* 
 * -- print_timers
 * 
 * print timer values using LOGTIMER flag. 
 *
 */
void
print_timers() 
{
    switch (getprocclass(map.whoami)) {
    case CAPTURE: 
	logmsg(LOGTIMER, "timing after %llu packets\n", map.stats->pkts);
	logmsg(0, "\t%s\n", print_tsctimer(map.stats->ca_full_timer));
	logmsg(0, "\t%s\n", print_tsctimer(map.stats->ca_loop_timer));
	logmsg(0, "\t%s\n", print_tsctimer(map.stats->ca_sniff_timer));
	logmsg(0, "\t%s\n", print_tsctimer(map.stats->ca_pkts_timer));
	logmsg(0, "\t%s\n", print_tsctimer(map.stats->ca_filter_timer));
	logmsg(0, "\t%s\n", print_tsctimer(map.stats->ca_module_timer));
	logmsg(0, "\t%s\n", print_tsctimer(map.stats->ca_updatecb_timer));
	break; 

    case EXPORT:
        logmsg(LOGTIMER, "\t%s\n", print_tsctimer(map.stats->ex_full_timer));
        logmsg(0, "\t%s\n", print_tsctimer(map.stats->ex_loop_timer));
        logmsg(0, "\t%s\n", print_tsctimer(map.stats->ex_table_timer));
        logmsg(0, "\t%s\n", print_tsctimer(map.stats->ex_store_timer));
        logmsg(0, "\t%s\n", print_tsctimer(map.stats->ex_mapping_timer));
        logmsg(0, "\t%s\n", print_tsctimer(map.stats->ex_export_timer));
	break;
    }
}


/*
 * -- reset_timers
 *  
 * resets timers for next round 
 * 
 */
void
reset_timers() 
{
    switch (getprocclass(map.whoami)) {
    case CAPTURE: 
	reset_tsctimer(map.stats->ca_full_timer);
	reset_tsctimer(map.stats->ca_loop_timer);
	reset_tsctimer(map.stats->ca_sniff_timer);
	reset_tsctimer(map.stats->ca_pkts_timer);
	reset_tsctimer(map.stats->ca_filter_timer);
	reset_tsctimer(map.stats->ca_module_timer);
	reset_tsctimer(map.stats->ca_updatecb_timer);
	break;

    case EXPORT:
        reset_tsctimer(map.stats->ex_full_timer);
        reset_tsctimer(map.stats->ex_loop_timer);
        reset_tsctimer(map.stats->ex_table_timer);
        reset_tsctimer(map.stats->ex_store_timer);
        reset_tsctimer(map.stats->ex_mapping_timer);
        reset_tsctimer(map.stats->ex_export_timer);
	break;
    }
}

 

