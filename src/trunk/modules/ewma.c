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
 * $Id: anomaly-ewma.c 605 2006-06-05 16:37:25Z iannak1 $
 */

/*
 * Anomaly detection using exponential smoothing.
 *
 * This module tracks the number of packets, bytes and connections and 
 * computes a forecast using an exponential weighted moving average EWMA. 
 * If the actual value is very different from the forecast an alert is 
 * raised and stored to disk. 
 * 
 * The module presents three configuration parameters: 
 *
 *   .. interval, the measurement interval in second over which to 
 *      estimate the three quantities. 
 *   .. weight, the weight w to apply on the moving average, e.g.
 *      x_{i+1} = w * x_i + (1 - w) * b, where b is the quantity under 
 *      observation in the current interval and x_i is the previous estimate.  
 *   .. change_thresh, the threshold value for raising the alert. 
 *      an alert will be raised if b > change_threshold * x_i
 */

#include <stdio.h>
#include <time.h>
#include <assert.h>
#include "module.h"
#include "bitmap.h"
#include "uhash.h"

#define FLOWDESC	struct _capture_data
#define EFLOWDESC	struct _export_data

FLOWDESC { 
    timestamp_t ts;
};

typedef struct { 
    uint32_t    bytes; 
    uint32_t    pkts; 
    bitmap_t *  connx; 
} state_t; 

EFLOWDESC { 
    timestamp_t ts; 		/* timestamp of last update */
    float bytes;		/* bytes after EWMA */
    float pkts;			/* packets after EWMA */
    float connx;		/* connections after EWMA */
    int32_t ch_bytes;		/* change in byte volume */
    int32_t ch_pkts;		/* change in packet volume */
    int32_t ch_connx;		/* change in connections volume */
    uint16_t alert;	 	/* alert */
    uint16_t past_alert;	/* set if last interval raised alert */
};

#define ALERT_BYTES		0x1
#define ALERT_PKTS		0x2
#define ALERT_CONNX		0x4
    
typedef struct {
    int meas_ivl;     		/* measurement interval */
    float weight;		/* weigth for EWMA */
    int32_t change_thresh;      /* change threshold (fixed point number)*/ 
    int max_connx;
    uhash_t hfunc; 
} config_t;

static timestamp_t 
init(void * self, char *args[])
{
    config_t * cf;
    int i;
    pkt_t *pkt;
    metadesc_t *inmd;

    cf = mem_mdl_malloc(self, sizeof(config_t)); 
    cf->meas_ivl = 1;
    cf->weight = 0.9;
    cf->change_thresh = (uint16_t) (256 * 3.0);		// fixed point 
    cf->max_connx = 2000000; 
    uhash_initialize(&cf->hfunc);

    for (i = 0; args && args[i]; i++) {
	char * wh = index(args[i], '=') + 1;
	if (strstr(args[i], "interval")) 
	    cf->meas_ivl = atoi(wh);
        else if (strstr(args[i], "weight")) 
	    cf->weight = strtof(wh, NULL); 
        else if (strstr(args[i], "change_thresh")) 
	    cf->change_thresh = (int32_t) (256 * strtof(wh, NULL)); 
        else if (strstr(args[i], "max_connx")) 
	    cf->max_connx = atoi(wh);
    }
    
    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = TIME2TS(cf->meas_ivl, 0);
    pkt = metadesc_tpl_add(inmd, "none:none:none:none");

    CONFIG(self) = cf; 
    return TIME2TS(cf->meas_ivl, 0);
}

static void * 
flush(void * self)
{
    config_t * cf = CONFIG(self);
    state_t * st;
      
    st = mem_mdl_calloc(self, 1, sizeof(state_t));
    st->connx = mdl_new_bitmap(self, cf->max_connx);
    return st; 
}

static int
update(__unused void * self, pkt_t *pkt, void *rp, int isnew)
{
    config_t * cf = CONFIG(self);
    FLOWDESC *x = F(rp);
    state_t * st = FSTATE(self); 
    uint32_t hash; 

    if (isnew) {
	x->ts = COMO(ts);
    }

    st->bytes += COMO(len);
    st->pkts++;

    if (isIP) { 
	hash = uhash(&cf->hfunc, (uint8_t *) &IP(src_ip), 4, UHASH_NEW);
        hash = uhash(&cf->hfunc, (uint8_t *) &IP(dst_ip), 4, UHASH_APPEND);
        hash = uhash(&cf->hfunc, (uint8_t *) &IP(proto), 1, UHASH_APPEND);
        if (isTCP) { 
            hash = uhash(&cf->hfunc,(uint8_t*) &TCP(src_port),2,UHASH_APPEND);
            hash = uhash(&cf->hfunc, (uint8_t *) &TCP(dst_port),2,UHASH_APPEND);
	} else if (isUDP) { 
            hash = uhash(&cf->hfunc,(uint8_t*) &UDP(src_port),2,UHASH_APPEND);
            hash = uhash(&cf->hfunc, (uint8_t *) &UDP(dst_port),2,UHASH_APPEND);
	} 

	set_bit(st->connx, hash);              /* update bitmap */
    }

    return 0;
}

static int
export(void * self, void *erp, void *rp, int isnew)
{
    EFLOWDESC *ex = EF(erp);
    FLOWDESC *x = F(rp);
    config_t * cf = CONFIG(self); 
    state_t * st = FSTATE(self); 
    float connx = estimate_unique_keys(st->connx);

    if (isnew) {
	bzero(ex, sizeof(EFLOWDESC));
	ex->bytes = st->bytes;
	ex->pkts = st->pkts;
	ex->connx = connx; 
    } 
    
    ex->ts = x->ts;

    /* 
     * compute forecast error and store it in a fixed point 
     * number (with 8 bits fractional) 
     */ 
    ex->ch_pkts = (int32_t) (((st->pkts - ex->pkts) / ex->pkts) * 256);
    ex->ch_bytes = (int32_t) (((st->bytes - ex->bytes) / ex->bytes) * 256);
    ex->ch_connx = (int32_t) (((connx - ex->connx) / ex->connx) * 256);

    if (ex->ch_bytes > cf->change_thresh) 
	ex->alert |= ALERT_BYTES; 

    if (ex->ch_pkts > cf->change_thresh) 
	ex->alert |= ALERT_PKTS; 

    if (ex->ch_connx > cf->change_thresh) 
	ex->alert |= ALERT_CONNX; 

    /* update the moving averages */
    ex->bytes = (1.0 - cf->weight) * ex->bytes + cf->weight * st->bytes; 
    ex->pkts = (1.0 - cf->weight) * ex->pkts + cf->weight * st->pkts; 
    ex->connx = (1.0 - cf->weight) * ex->connx + cf->weight * connx; 

    /* reset the past alert flag if no alerts are raised */
    ex->past_alert &= ex->alert; 

    return 0;
}
    
static int
action(__unused void * self, void * rp,  __unused timestamp_t ivl,
       __unused timestamp_t t, __unused int count)
{
    EFLOWDESC *ex = EF(rp);

    if (rp == NULL)
        return ACT_GO;

    if (ex->past_alert)
	ex->alert = 0; 

    return (ex->alert)? ACT_STORE : ACT_STOP;
}

struct alert_record { 
    uint32_t ts; 
    uint16_t alert; 
    uint32_t ch_bytes; 
    uint32_t ch_pkts; 
    uint32_t ch_connx; 
};


static ssize_t
store(__unused void * self, void *rp, char *buf)
{
    EFLOWDESC *ex = EF(rp);

    PUTH32(buf, TS2SEC(ex->ts));
    PUTH16(buf, ex->alert); 
    PUTH32(buf, ex->ch_bytes);
    PUTH32(buf, ex->ch_pkts);
    PUTH32(buf, ex->ch_connx);

    ex->past_alert = ex->alert; 
    ex->alert = 0;

    return sizeof(struct alert_record);
}

static size_t
load(__unused void * self, char * buf, __unused size_t len, timestamp_t * ts)
{
    *ts = TIME2TS(ntohl(((struct alert_record *)buf)->ts),0); 
    return sizeof(struct alert_record);
}


#define PRETTYHDR	"Date                     Packets Bytes Connx\n"
#define PRETTYFMT	"%.24s %d.%1u %d.%1u %d.%1u\n"
#define PLAINFMT	"%12ld %d.%1u %d.%1u %d.%1u\n"

#define HTMLHDR                                                 \
    "<html>\n"							\
    "<head>\n"							\
    "  <style type=\"text/css\">\n"				\
    "   body {margin: 0; padding: 0\n"				\
    "     font-family: \"lucida sans unicode\", verdana, arial;\n" \
    "     font-size: 9pt; scrollbar-face-color: #ddd}\n"        \
    "   table,tr,td{\n"						\
    "     margin: 1;\n"						\
    "     font-family: \"lucida sans unicode\", verdana, arial;\n" \
    "     font-size: 9pt; background-color: #dddddd;}\n"	\
    "   a, a.visited { text-decoration: none;}\n"		\
    "   .netview {\n"						\
    "     top: 0px; width: 100%%; vertical-align:top;\n" 	\
    "     margin: 2; padding-left: 5px;\n" 			\
    "     padding-right: 5px; text-align:left;}\n" 		\
    "   .nvtitle {\n"						\
    "     font-weight: bold; padding-bottom: 3px;\n" 		\
    "     font-family: \"lucida sans unicode\", verdana, arial;\n" \
    "     font-size: 9pt; color: #475677;}\n"			\
    "  </style>\n"						\
    "</head>\n"							\
    "<body>\n" 							 

#define HTMLTITLE						\
    "<div class=nvtitle style=\"border-top: 1px dashed;\">"	\
    "Alerts</div>\n" 

#define STR_NOALERTS						\
    "No anomalies to report.\n"

#define HTML_ALERTS						\
    "<table class=netview>\n"                                   \
    "  <tr class=nvtitle>\n" 					\
    "    <td><b>Time</b></td>\n" 		                \
    "    <td><b>Packets</b></td>\n" 				\
    "    <td><b>Bytes</b></td>\n" 				\
    "    <td><b>Connx</b></td>\n" 				\
    "  </tr>\n"                                         

#define HTMLFMT							\
    "<tr><td><a href=%s target=_top>%s</a></td>"		\
    "<td>%d.%1u</td>"						\
    "<td>%d.%1u</td>"						\
    "<td>%d.%1u</td></tr>\n"

#define HTMLFOOTER_ALERTS                                       \
    "</table>\n"                                                

#define HTMLFOOTER                                              \
    "</body></html>\n"                                          

static char *
print(__unused void * self, char *buf, size_t *len, char * const args[])
{
    static char s[2048];
    static char urlstr[2048] = "#";
    static char * fmt; 
    static int alerts = 0; 
    struct alert_record *x; 
    time_t ts;
    int n; 

    if (buf == NULL && args != NULL) { 
        char * url = NULL;
        char * urlargs[20];
        int no_urlargs = 0;

	/* by default, pretty print */
	*len = sprintf(s, PRETTYHDR);  
	fmt = PRETTYFMT; 

	/* first call of print, process the arguments and return */
	for (n = 0; args[n]; n++) {
	    if (!strcmp(args[n], "format=plain")) {
		*len = 0; 
		fmt = PLAINFMT;
	    } else if (!strcmp(args[n], "format=html")) {
                *len = sprintf(s, HTMLHDR); 
                *len += sprintf(s + *len, HTMLTITLE); 
                fmt = HTMLFMT;
	    } else if (!strcmp(args[n], "format=sidebox")) {
                *len = sprintf(s, HTMLHDR); 
                fmt = HTMLFMT;
            } else if (!strncmp(args[n], "url=", 4)) {
                url = args[n] + 4;
            } else if (!strncmp(args[n], "urlargs=", 8)) {
                urlargs[no_urlargs] = args[n] + 8;
                no_urlargs++;
            }
        }

        if (url != NULL) {
            int w, k;

            w = sprintf(urlstr, "%s?", url);
            for (k = 0; k < no_urlargs; k++)
                w += sprintf(urlstr + w, "%s&", urlargs[k]);
	    w += sprintf(urlstr + w, "start=%%u&end=%%u"); 
        }

	return s; 
    } 

    if (buf == NULL && args == NULL) {  
	*len = alerts > 0 ? 0 : sprintf(s, STR_NOALERTS);  
	if (fmt == HTMLFMT) {
	    if (alerts > 0) {
		*len += sprintf(s + *len, HTMLFOOTER_ALERTS);
	    }
	    *len += sprintf(s + *len, HTMLFOOTER);
	}
	alerts = 0;	/* reset */
	return s;
    } 
	
    *len = 0; 

    if (alerts == 0) { 
	if (fmt == HTMLFMT) 
	    *len = sprintf(s, HTML_ALERTS); 
	alerts = 1;
    } 

    x = (struct alert_record *) buf; 
    ts = (time_t) ntohl(x->ts);

#define print_ch(c) 				\
	((int32_t) (ntohl(c) >> 8)), ((uint8_t) (ntohl(c) & 0xff))

    /* print according to the requested format */
    if (fmt == PRETTYFMT) {
	*len = sprintf(s, fmt, asctime(gmtime(&ts)), print_ch(x->ch_pkts), 
		       print_ch(x->ch_bytes), print_ch(x->ch_connx));
    } else if (fmt == HTMLFMT) {
	char timestr[30]; 
        char tmp[2048] = "#";

	strftime(timestr, sizeof(timestr), "%b %d %T", gmtime(&ts)); 

        if (urlstr[0] != '#')
            sprintf(tmp, urlstr, ts - 3600, ts + 3600);

	*len += sprintf(s + *len, fmt, tmp, timestr, print_ch(x->ch_pkts), 
			print_ch(x->ch_bytes), print_ch(x->ch_connx));
    } else {
	*len = sprintf(s, fmt, (long int)ts, print_ch(x->ch_pkts), 
		       print_ch(x->ch_bytes), print_ch(x->ch_connx));
    } 

#undef print_ch
	
    return s;
}

MODULE(ewma) = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: sizeof(EFLOWDESC),
    st_recordsize: sizeof(struct alert_record), 
    capabilities: {0, 0},
    init: init,
    check: NULL,
    hash: NULL,
    match: NULL,
    update: update,
    flush: flush,
    ematch: NULL,
    export: export,
    compare: NULL,
    action: action,
    store: store,
    load: load,
    print: print,
    replay: NULL,
    formats: "pretty plain html sidebox"
};
