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

#include <math.h>
#include "como.h"
#include "comopriv.h"
#include "loadshed.h"
#include "lsfunc.h"


/*
 * -- ewma
 *
 * Computes the EWMA (Exponentially Weigthed Moving Average) of the
 * data in a time series
 *
 */
static void
ewma(double factor, double *last_value, double curr_value)
{
    if (*last_value == 0)
        *last_value = curr_value;
    else
        *last_value = ((1.0 - factor) * (*last_value)) + (factor * curr_value);
}


/*
 * -- compute_srate
 *
 * Computes the shedding rate that needs to be applied to the modules in
 * order to avoid overload
 *
 */
static double
compute_srate(uint64_t avail_cycles, uint64_t pred_cycles,
              double perror_ewma, double shed_ewma)
{
    double srate;

    srate = (pred_cycles == 0) ?
        1 : MAX(0, (double)avail_cycles - shed_ewma) /
            ((double)pred_cycles * (1 + perror_ewma));

    if (srate > 1)
        srate = 1;

    debug("srate = %g\n", srate);

    return srate;
}


/*
 * -- assign_srates
 *
 * Assign shedding rates to the modules, according to some optimization
 * algorithm. XXX For now, just assign the same shedding rate to all modules.
 *
 */
static void
assign_srates(array_t *mdls, double srate)
{
    int i;
    mdl_icapture_t *ic;
    mdl_ls_t *mdl_ls;

    for (i = 0; i < mdls->len; i++) {
        mdl_t *mdl = array_at(mdls, mdl_t *, i);
        ic = mdl_get_icapture(mdl);
        mdl_ls = &ic->ls;
        mdl_ls->srate = srate;
    }
}


static __inline__ void
get_cpuid(int flag, uint32_t *output)
{
    asm volatile ("cpuid"
                 : "=a" (output[0]), "=b" (output[1]),
                   "=c" (output[2]), "=d" (output[3])
                 : "a" (flag));
}


/*
 * get_cpufreq_cpuid() - This gets the maximum qualified frequency of the
 * processor, not the actual frequency. Taken from the Intel IA32 Software
 * Developer's Manual, Volume 2A, page 3-172.
 */
static unsigned int
get_cpufreq_cpuid()
{
#define FREQ_STRLEN 5
    int flag = 0x80000004; /* get the last (third) part of the Brand String */
    uint32_t registers[4];
    unsigned int multiplier = 0;
    char *mult_found = NULL;
    char freq[FREQ_STRLEN];
    unsigned int i = 0, len = 0;
    
    get_cpuid(flag, registers);

    mult_found = strstr((char *)&registers[0], "MHz");
    if (mult_found) multiplier = 1000000;
    else {
        mult_found = strstr((char *)&registers[0], "GHz");
        if (mult_found) multiplier = 1000000000;
        else return 0; /* we didn't find a valid multiplier */
    }

    len = strlen((char *)&registers[0]) - strlen(mult_found);
    for (i = 1; (i <= len) && (*(mult_found - i) != ' '); i++);
    if (i > len) return 0; /* we didn't find a valid frequency count */
    
    strncpy(freq, mult_found - i + 1, FREQ_STRLEN);
    return (atoi(freq) * multiplier);
}


static uint64_t
get_avail_cycles(como_ca_t *como_ca)
{
    int64_t avail_cycles;
    int64_t ca_oh_cycles;
    int i;

    end_profiler(como_ca->ls.ca_oh_prof);

    ca_oh_cycles = como_ca->ls.ca_oh_prof->tsc_cycles->value;

    for (i = 0; i < como_ca->mdls->len; i++) {
        mdl_t *mdl = array_at(como_ca->mdls, mdl_t *, i);
        mdl_icapture_t *ic = mdl_get_icapture(mdl);
        ca_oh_cycles -= ic->ls.prof->tsc_cycles->value;
    }

    avail_cycles = ((double)como_ca->timebin / (double)1000000 *
                   (double)como_ca->ls.cpufreq) - (double)ca_oh_cycles;

    if (avail_cycles < 0)
        avail_cycles = 0;

    debug("avail_cycles = %llu, ca_oh = %llu\n",
          avail_cycles, ca_oh_cycles);

    reset_profiler(como_ca->ls.ca_oh_prof);
    start_profiler(como_ca->ls.ca_oh_prof);

    return avail_cycles;
}


/*
 * -- shed_load
 * 
 * Given a shedding rate, apply shedding to a module according to the
 * shedding method selected at configuration time
 *
 * Return the number of packets shed from the batch
 *
 */
static int
shed_load(batch_t *batch, char *which, mdl_t *mdl)
{
    int i, c, l;
    pkt_t **pktptr;
    mdl_icapture_t *ic;
    mdl_ls_t *mdl_ls;
    int nshed = 0;
    int initialized = 0;

    ic = mdl_get_icapture(mdl);
    mdl_ls = &ic->ls;

    /* If we do not need to do shedding, stop here */
    if (mdl_ls->srate == 1)
        return 0;

    /* For the modules that apply flow sampling, do not allow the
     * sampling rate to increase during a measurement interval */
    if (mdl_ls->shed_method == SHED_METHOD_FLOW) {
    
        mdl_ls->tmp_srate = mdl_ls->srate;

        if (!mdl_ls->max_srate)
            mdl_ls->max_srate = mdl_ls->srate;
        else {
            if (mdl_ls->srate >= mdl_ls->max_srate)
                mdl_ls->srate = mdl_ls->max_srate;
            else
                mdl_ls->max_srate = mdl_ls->srate;
        }
    }

    /* Sampling is done by modifying the filter matrix,
     * zeroing out the discarded packets */
    for (c = 0, pktptr = batch->pkts0, l = MIN(batch->pkts0_len, batch->count);
	 c < batch->count;
	 pktptr = batch->pkts1, l = batch->pkts1_len)
    {
	for (i = 0; i < l; i++, pktptr++, c++, which++) {
            pkt_t *pkt = *pktptr;

            if (*which == 0)
                continue; /* no interest in this packet */

            if (pkt->ts >= ic->ivl_end) {
                if (!initialized) {
                    int hi;
#if 0
                    debug("init shedding: %d batches, "
                          "ts = %llu, pkt no. %d, ca_ivl = %llu\n",
                          mdl_ls->nbatches, pkt->ts, i, ic->ivl_start);
#endif
                    initialized = 1;
                    for (hi = 0; hi < NUM_HASH; hi++)
                        uhash_initialize(mdl_ls->hash[hi]);
                    /* Clear the limit that avoids increasing the
                     * sampling rate while in the same interval */
                    if (mdl_ls->shed_method == SHED_METHOD_FLOW) {
                        mdl_ls->max_srate = 0;
                        /* Uncap the sampling rate */
                        mdl_ls->srate = mdl_ls->tmp_srate;
                    }
                }
            }

            if (mdl_ls->shed_method == SHED_METHOD_PKT) {
                /* Random packet sampling */
                double r = (double)rand() / (double)RAND_MAX;

                if (mdl_ls->srate < r) {
                    *which = 0;
                    nshed++;
                }
            } else if (mdl_ls->shed_method == SHED_METHOD_FLOW) {
                /* Flow sampling, using a hash table indexed
                 * by the packet's 5-tuple */
                uint32_t hash, threshold, tmp;
                uint16_t sport, dport;

                tmp = 0xffffffff;
                threshold =
                    (uint32_t)(mdl_ls->srate * (double)tmp);

                if (isTCP) {
                    sport = N16(TCP(src_port));
                    dport = N16(TCP(dst_port));
                }
                else if (isUDP) {
                    sport = N16(UDP(src_port));
                    dport = N16(UDP(dst_port));
                }
                else
                    sport = dport = 0;
                
                hash = uhash(mdl_ls->hash[0], (uint8_t *)&IP(src_ip), 4,
                             UHASH_NEW)
                    ^ uhash(mdl_ls->hash[1], (uint8_t *)&IP(dst_ip), 4,
                            UHASH_NEW)
                    ^ uhash(mdl_ls->hash[2], (uint8_t *)&sport, 2, UHASH_NEW)
                    ^ uhash(mdl_ls->hash[3], (uint8_t *)&dport, 2, UHASH_NEW)
                    ^ uhash(mdl_ls->hash[4], (uint8_t *)&IP(proto), 2,
                            UHASH_NEW);

                if (hash > threshold) {
                    *which = 0;
                    nshed++;
                }
            }
        }
    }
    
    return nshed;
}


/*
 * -- batch_loadshed_pre
 *
 * Apply load shedding to a batch before passing it to the modules
 *
 */
void
batch_loadshed_pre(batch_t *batch, como_ca_t *como_ca, char *which)
{
    array_t *mdls;
    int idx;
    mdl_icapture_t *ic;
    uint64_t avail_cycles;
    char *start_which = which;

    como_ca->ls.pcycles = 0;
    mdls = como_ca->mdls;

    for (idx = 0; idx < mdls->len; idx++) {
	mdl_t *mdl = array_at(mdls, mdl_t *, idx);
        ic = mdl_get_icapture(mdl);

        feat_extr(batch, which, mdl);

        if (ic->ls.batches < NUM_OBS) {
            /* Not enough history acquired yet to attempt the prediction */
            update_pred_hist(&ic->ls);
            which += batch->count;
            continue;
        }

        pred_sel(&ic->ls);

        como_ca->ls.pcycles += predict(&ic->ls);

	which += batch->count;  /* next module, new list of packets */
    }

    avail_cycles = get_avail_cycles(como_ca);

    como_ca->ls.srate =
        compute_srate(avail_cycles, como_ca->ls.pcycles,
                      como_ca->ls.perror_ewma, como_ca->ls.shed_ewma);

    start_profiler(como_ca->ls.shed_prof);

    assign_srates(mdls, como_ca->ls.srate);

    which = start_which;

    for (idx = 0; idx < mdls->len; idx++) {
        int nshed;
	mdl_t *mdl = array_at(mdls, mdl_t *, idx);
        ic = mdl_get_icapture(mdl);

        if (ic->ls.batches < NUM_OBS) {
            /* Not enough history acquired yet to try to shed load */
            which += batch->count;
            continue;
        }

        nshed = shed_load(batch, which, mdl);

        debug("module %s, %d pkts shed\n", mdl->name, nshed);

        feat_extr(batch, which, mdl);

        update_pred_hist(&ic->ls);

        which += batch->count;  /* next module, new list of packets */
    }

    end_profiler(como_ca->ls.shed_prof);

    ewma(SHED_EWMA_WEIGHT, &como_ca->ls.shed_ewma,
         como_ca->ls.shed_prof->tsc_cycles->value);
}


/*
 * -- batch_loadshed_post
 *
 * Get feedback for the load shedding procedure
 *
 */
void
batch_loadshed_post(como_ca_t *como_ca)
{
    array_t *mdls;
    int idx;
    mdl_icapture_t *ic;
    double pred_error;

    mdls = como_ca->mdls;

    como_ca->ls.rcycles = 0;

    for (idx = 0; idx < mdls->len; idx++) {
	mdl_t *mdl = array_at(mdls, mdl_t *, idx);
        ic = mdl_get_icapture(mdl);
        /* Update response variable history */
        ic->ls.pred.resp[ic->ls.obs] = ic->ls.prof->tsc_cycles->value;
        como_ca->ls.rcycles += ic->ls.pred.resp[ic->ls.obs];
        ic->ls.obs = ((ic->ls.obs + 1) % NUM_OBS);
        ic->ls.batches++;
        debug("module %s, %llu batches processed\n", mdl->name,
              ic->ls.batches);
    }

    pred_error = fabs(1 - (double)como_ca->ls.pcycles * como_ca->ls.srate /
                  (double)como_ca->ls.rcycles);

    ewma(PERROR_EWMA_WEIGHT, &como_ca->ls.perror_ewma, pred_error);

    debug("predicted cycles = %llu\n", como_ca->ls.pcycles);
    debug("real cycles = %llu\n", como_ca->ls.rcycles);
    debug("prediction error = %g\n", pred_error);
    debug("prediction error ewma = %g\n", como_ca->ls.perror_ewma);
    debug("shedding phase ewma = %g\n", como_ca->ls.shed_ewma);
}


static char * aggr_names[15] = {
    "pkts", "bytes", "sip", "dip", "sip_dip", "snet", "dnet", "snet_dnet",
    "proto_sport", "proto_dport", "proto_sport_sip", "proto_dport_dip",
    "proto_sport_dport", "5tuple", "proto"
};


/*
 * -- ls_init_mdl
 *
 * Initialize the load shedding data of a module
 *
 */
void
ls_init_mdl(char *name, mdl_ls_t *mdl_ls, char *shed_method)
{
    int i;
    feat_t *feats = mdl_ls->fextr.feats;
    pred_t *preds = mdl_ls->pred.hist;

    /* initialize profilers */
    mdl_ls->prof = new_profiler(name);

    /* get shedding method (use packet sampling by default) */
    mdl_ls->shed_method = SHED_METHOD_PKT;
    if (!strcmp(shed_method, "pkt")) {
        mdl_ls->shed_method = SHED_METHOD_PKT;
    }
    else if (!strcmp(shed_method, "flow")) {
        mdl_ls->shed_method = SHED_METHOD_FLOW;
    }

    /* initialize shedding hash functions */
    if (!mdl_ls->hash) {
        mdl_ls->hash = como_calloc(NUM_HASH, sizeof(uhash_t *));
        for (i = 0; i < NUM_HASH; i++)
            mdl_ls->hash[i] = como_malloc(sizeof(uhash_t));
    }

    /* initialize features' and predictors' names */
    for (i = 0; i < NO_BM_FEATS; i++) {
        strncpy(feats[i].name, aggr_names[i], LS_STRLEN);
        strncpy(preds[i].name, aggr_names[i], LS_STRLEN);
    }

    for (i = NO_BM_FEATS; i < NO_BM_FEATS + NUM_BITMAPS; i++) {
        strcat(feats[i].name, "u_");
        strcat(preds[i].name, "u_");
        strcat(feats[i + NUM_BITMAPS].name, "n_");
        strcat(preds[i + NUM_BITMAPS].name, "n_");
        strcat(feats[i + NUM_BITMAPS * 2].name, "br_");
        strcat(preds[i + NUM_BITMAPS * 2].name, "br_");
        strcat(feats[i + NUM_BITMAPS * 3].name, "ar_");
        strcat(preds[i + NUM_BITMAPS * 3].name, "ar_");
        strncat(feats[i].name, aggr_names[i], LS_STRLEN);
        strncat(preds[i].name, aggr_names[i], LS_STRLEN);
        strncat(feats[i + NUM_BITMAPS].name, aggr_names[i], LS_STRLEN);
        strncat(preds[i + NUM_BITMAPS].name, aggr_names[i], LS_STRLEN);
        strncat(feats[i + NUM_BITMAPS * 2].name, aggr_names[i], LS_STRLEN);
        strncat(preds[i + NUM_BITMAPS * 2].name, aggr_names[i], LS_STRLEN);
        strncat(feats[i + NUM_BITMAPS * 3].name, aggr_names[i], LS_STRLEN);
        strncat(preds[i + NUM_BITMAPS * 3].name, aggr_names[i], LS_STRLEN);
    }

    mdl_ls->fextr.bitmaps = NULL;
    mdl_ls->fextr.hash = NULL;
}


/*
 * -- ls_init_ca
 *
 * Initialize the load shedding data of the capture process
 *
 */
void
ls_init_ca(como_ca_t *como_ca)
{
    /* Initialize some values */
    como_ca->ls.perror_ewma = 0;
    como_ca->ls.shed_ewma = 0;

    /* Get the CPU frequency */
    como_ca->ls.cpufreq = get_cpufreq_cpuid();

    /* Initialize profilers */
    ca_init_profilers(como_ca);

    start_profiler(como_ca->ls.ca_oh_prof);
}
