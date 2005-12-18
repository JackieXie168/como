
/* 
 * XXX This code is still work in progress. It is used to time
 *     various operations of the CAPTURE and EXPORT processes. 
 *
 */

#include "como.h"
#include "comotypes.h"

extern struct _como map;		/* global state */

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
    switch (map.procname[0]) { 
    case 'c': 
	map.stats->ca_full_timer = new_tsctimer("full");
	map.stats->ca_loop_timer = new_tsctimer("loop");
	map.stats->ca_pkts_timer = new_tsctimer("pkts");
	map.stats->ca_filter_timer = new_tsctimer("filter");
	map.stats->ca_module_timer = new_tsctimer("modules");
	map.stats->ca_updatecb_timer = new_tsctimer("update");
	map.stats->ca_sniff_timer = new_tsctimer("sniffer");
	break;

    case 'e':
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
    switch (map.procname[0]) { 
    case 'c': 
	logmsg(LOGTIMER, "timing after %llu packets\n", map.stats->pkts);
	logmsg(0, "\t%s\n", print_tsctimer(map.stats->ca_full_timer));
	logmsg(0, "\t%s\n", print_tsctimer(map.stats->ca_loop_timer));
	logmsg(0, "\t%s\n", print_tsctimer(map.stats->ca_sniff_timer));
	logmsg(0, "\t%s\n", print_tsctimer(map.stats->ca_pkts_timer));
	logmsg(0, "\t%s\n", print_tsctimer(map.stats->ca_filter_timer));
	logmsg(0, "\t%s\n", print_tsctimer(map.stats->ca_module_timer));
	logmsg(0, "\t%s\n", print_tsctimer(map.stats->ca_updatecb_timer));
	break; 

    case 'e':
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
    switch (map.procname[0]) { 
    case 'c': 
	reset_tsctimer(map.stats->ca_full_timer);
	reset_tsctimer(map.stats->ca_loop_timer);
	reset_tsctimer(map.stats->ca_sniff_timer);
	reset_tsctimer(map.stats->ca_pkts_timer);
	reset_tsctimer(map.stats->ca_filter_timer);
	reset_tsctimer(map.stats->ca_module_timer);
	reset_tsctimer(map.stats->ca_updatecb_timer);
	break;

    case 'e':
        reset_tsctimer(map.stats->ex_full_timer);
        reset_tsctimer(map.stats->ex_loop_timer);
        reset_tsctimer(map.stats->ex_table_timer);
        reset_tsctimer(map.stats->ex_store_timer);
        reset_tsctimer(map.stats->ex_mapping_timer);
        reset_tsctimer(map.stats->ex_export_timer);
	break;
    }
}

 

