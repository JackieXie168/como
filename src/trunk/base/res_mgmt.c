/*
 * Copyright (c) 2005, Universitat Politecnica de Catalunya
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

#include <stdlib.h> /* random */
#include <stdio.h>  /* asprintf */
#include <string.h> /* strerror */
#include <errno.h>

#include "storage.h"
#include "como.h"

//#define SH_REL_UPPER_THRES 0.60
#define SH_REL_UPPER_THRES 0.15
#define SH_REL_LOWER_THRES 0.10

#define B2MB(x) (1024*1024*(x))

extern struct _como map;

/*
 * file descriptor to communicate to storage,
 * which will be used to store stats.
 */
int storage_fd;
int stats_file;
int stats_offset;

/*
 * resource are defined by an identifier, a name and the upper
 * and lower thresholds. Thresholds are used to check if a
 * resource usage is high or low.
 */
struct _resource {
    int id;
    char *name;
    char *short_descr;
    double upper_threshold;
    double lower_threshold;
};

typedef struct _resource resource_t;

/*
 * monitored resources
 */
enum _resource_ids {
    RES_SH_MEM = 0,
    RES_EX_MEM,
    RESOURCE_COUNT
};

/*
 * definitions of monitored resources
 */
resource_t resources[] = {
    /*
     * thresholds for the shared memory block are calculated in
     * resource_mgmt_init.
     *
     * XXX in the future, these thresholds should be readable from
     *     a config file.
     */
    { RES_SH_MEM, "Shared memory", "shmem", 0,  0 },
    { RES_EX_MEM, "memory used by export", "exmem", B2MB(200), B2MB(50) },
    { 0, NULL, NULL, 0, 0 }
};

/*
 * Record of utilization of a resource by a module in a
 * certain point of time.
 */
struct _stats_record {
    timestamp_t ts;
    char module[16];
    uint8_t resource_id;
    uint64_t usage;
};
typedef struct _stats_record stats_record_t;

/*
 * While running, CoMo's usage of memory fluctuates a lot
 * in short periods of time. Because of this, we won't take
 * decisions looking at memory usage in a certain point of
 * time, but we will be keeping a peak usage. This peak
 * is periodically decreased, so that it will keep up-to-date
 * information.
 */
double *mdl_peak_usages[RESOURCE_COUNT];
double peak_usages[RESOURCE_COUNT];

/*
 * this constant tells how much will each mdl_peak_usage be
 * decremented each time schedule() is called.
 */
#define DECREMENT 0.001

/*
 * -- resource_mgmt_init
 *
 * Initialize resource management-related data structures.
 */
void
resource_mgmt_init()
{
    resource_t *res;

    /*
     * turn relative thresholds into absolutes
     */
    resources[RES_SH_MEM].upper_threshold =
        map.mem_size * SH_REL_UPPER_THRES * 1024 * 1024;
    resources[RES_SH_MEM].lower_threshold =
        map.mem_size * SH_REL_LOWER_THRES * 1024 * 1024;

    /*
     * initialize peak usages
     */
    for (res = resources; res->name != NULL; res++) {
        mdl_peak_usages[res->id] = safe_calloc(map.module_max, sizeof(double));
        peak_usages[res->id] = 0;
    }

    /*
     * open output file
     */
    /*storage_fd = create_socket("storage.sock", NULL);
    stats_file = csopen("stats", CS_WRITER, 10000, storage_fd);
    if (stats_file < 0) {
        logmsg(LOGWARN, "Unable to open stats logfile (%s)\n",
                strerror(errno));
        return;
    }
        
    stats_offset = csgetofs(stats_file);*/
}

/*
 * -- get_mdl_usage
 *
 * Return the amount of a resource used by a module.
 */
__inline__ static double
get_mdl_usage(module_t *mdl, resource_t *res)
{
    mdl_stats_t *st = &map.stats->mdl_stats[mdl->index];

    switch(res->id) {
        case RES_SH_MEM:
            return st->mem_usage_shmem;
        case RES_EX_MEM:
            return st->mem_usage_export;
        default:
            return 0; /* !? */
    }
}

/*
 * -- get_total_usage
 *
 * Return overall usage of a resource. 
 */
__inline__ static double
get_usage(resource_t *res)
{
    double result = 0;
    int i;

    /*
     * we already have this value for RES_SH_MEM
     */
    if (res->id == RES_SH_MEM)
        return (double)map.stats->mem_usage_cur;
    /*
     * sum per-module usage for RES_EX_MEM
     */
    for (i = 0; i < map.module_count; i++)
        result += get_mdl_usage(&map.modules[i], res);

    return result;
}

/*
 * -- election
 *
 * Select a module for removal, given a limiting resource.
 * XXX document the algorithm
 *
 */
static module_t *
election(resource_t *limiting)
{
    module_t *elected = NULL;
    double elected_points = 0;
    int idx;

    for (idx = 0; idx < map.module_count; idx++) {
        double points = 0;
        int r;

        /*
         * only active modules are eligible
         */
        if (map.modules[idx].status != MDL_ACTIVE)
            continue;

        /*
         * sum peak usages of each resource
         */
        for (r = 0; r < RESOURCE_COUNT; r++) {
            double d;

            d = mdl_peak_usages[r][idx];
            if (d < 0) d = 0;
            else if (d > 1) d = 1;

            /*
             * the limiting resource counts as much
             * as the sum of all other resources
             */
            if (r == limiting->id)
                d *= RESOURCE_COUNT;

            points += d;
        }

        /*
         * apply priorities
         */
        points *= map.modules[idx].priority;

        /*
         * remember the highest
         */
        if ((idx == 0) || (points > elected_points)) {
            elected_points = points;
            elected = &map.modules[idx];
        }
    }

    return elected;
}

char *
resource_usage_report()
{
    char *buffer, *old;
    resource_t *res;

    buffer = NULL;

    for (res = resources; res->name != NULL; res++) {
        old = buffer;

        /*
         * by now all resources are memory
         */
        /*asprintf(&buffer, "%s%s%s %dMB",
                old ? old : "",
                old ? " " : "",
                res->short_descr,
                (int) (get_usage(res))/(1024*1024));*/
        asprintf(&buffer, "%s%s%s %d%%",
                old ? old : "",
                old ? " " : "",
                res->short_descr,
                (int)(get_usage(res)*100 / res->upper_threshold));
        free(old);
   }

    return buffer;
}

/*
 * -- schedule
 *
 * Do the resource management. Check usage thresholds and
 * react accordingly. If some resource usage is too high,
 * select a module and disable it. When all usages are
 * below the low thresholds, select a disabled module and
 * enable it.
 */
void
schedule()
{
    resource_t *over;
    int all_low, r, m;
    static int consecutive_all_low;

    /*
     * update peak usages
     */
    for(r = 0; r < RESOURCE_COUNT; r++) {
        peak_usages[r] = 0;

        for (m = 0; m < map.module_count; m++) {
            double cur_usage;
            module_t *mdl = &map.modules[m];
            resource_t *res = &resources[r];

            if (map.modules[m].status == MDL_DISABLED)
                mdl_peak_usages[r][m] = 0; /* drop as quick as possible for
                                              disabled modules */
            else
                mdl_peak_usages[r][m] -= DECREMENT;    /* decrement peak */

                                                   /* get current usage */
            cur_usage = get_mdl_usage(mdl, res) / res->upper_threshold;

            if (cur_usage > mdl_peak_usages[r][m]) /* keep the highest */
                mdl_peak_usages[r][m] = cur_usage;

            peak_usages[r] += mdl_peak_usages[r][m];
        }
    }

    /*
     * check thresholds
     */
    over = NULL;
    all_low = 1;

    for(r = 0; r < RESOURCE_COUNT; r++) {
        if (peak_usages[r] * resources[r].upper_threshold >
                resources[r].lower_threshold) /* above lower */
            all_low = 0;

        if (peak_usages[r] > 1) { /* above upper */
            over = &resources[r];
            break;
        }
    }

#if 0
    /*
     * print helper
     */
    {
        fprintf(stderr, "\nPEAK/MDL:  |");
        for(m=0;m<map.module_count;m++) {
            for(r=0;r<RESOURCE_COUNT;r++){
                if (r!=0) fprintf(stderr,":");
                fprintf(stderr, "%02.4f", (float)mdl_peak_usages[r][m]);
            }
            fprintf(stderr, "|");
        }
        fprintf(stderr, "\n");

        fprintf(stderr, "OVERALL: ");
        for(r=0;r<RESOURCE_COUNT;r++){
            if (r!=0) fprintf(stderr,"|");
            fprintf(stderr, "%d:%02.4f", (int)get_usage(&resources[r]),
                    peak_usages[r]);
        }

        if (over) {
            fprintf(stderr, " ('%s' TOO HIGH)", over->name);
        }
        else if (all_low)
            fprintf(stderr, " (EVERYTHING IS LOW)");
        fprintf(stderr, "\n");
    }
#endif

    /*
     * if some resource usage is too high, select
     * a module and disable it.
     */
    if (over) {
        module_t *elected;
        double drop, usage;
        int need_status_update;

        logmsg(LOGWARN, "Resource '%s' overload\n", over->name);

        /*
         * select and remove a module until the resource
         * usage will drop below upper threshold.
         */
        usage = get_usage(over);
        drop = 0;
        need_status_update = 0;
        do {
            elected = election(over);

            if (elected == NULL) /* no module could be elected */
                break;

            logmsg(LOGUI, "Resource management: module '%s' (priority "
                    "%d) disabled. \n", elected->name, elected->priority,
                    over->name);

            need_status_update = 1;
            drop += get_mdl_usage(elected, over);
            elected->status = MDL_DISABLED;
            map.stats->modules_active--;
        } while (usage - drop > over->upper_threshold);

        if (need_status_update) {
            logmsg(LOGWARN, "Disabling modules due to resource mgmt\n");
            sup_send_module_status();
        }
        else /* should be never reached */
            logmsg(LOGWARN, "No modules available for removal (weird)..\n");
    }

    if (all_low) {
        /*
         * all usages are low
         */
        consecutive_all_low++;

        logmsg(V_LOGDEBUG, "Resource management: all resource usages low.\n");

        /*
         * check if usages have been low for a while,
         * and if so, choose a random disabled module
         * and enable it back.
         */
        if (consecutive_all_low > 200) {
            int i, disabled_count;

            disabled_count = 0;
            for (i = 0; i < map.module_count; i++)
                if (map.modules[i].status == MDL_DISABLED)
                    disabled_count++;

            if (disabled_count > 0) {
                /*
                 * randomly choose a module
                 */
                int rnd = random() % disabled_count;
                module_t *mdl = NULL;

                /*
                 * locate and enable module
                 */
                for (i = 0; i < map.module_count; i++) {
                    if (map.modules[i].status != MDL_DISABLED)
                        continue;

                    if (rnd == 0) {
                        mdl = &map.modules[i];
                        break;
                    }
                        
                    rnd--;
                }
                
                mdl->status = MDL_ACTIVE;
                map.stats->modules_active++;
                sup_send_module_status();
                logmsg(LOGUI, "Resource management: module '%s' enabled\n",
                        mdl->name);

                /*
                 * enabled some module, restart the count.
                 */
                consecutive_all_low = 0;
            }
        }
    }
    else 
        consecutive_all_low = 0;
}

