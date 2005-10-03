/*
 * Copyright (c) 2004 Intel Corporation
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
 *
 * Debugging and various utility functions.
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h> 			/* va_start */
#include <string.h>
#include <errno.h>
#include <unistd.h>     
#include <dlfcn.h>
#undef __unused        /* XXX linux's netdb.h has a variable with this name */
#include <netdb.h>                     /* gethostbyname */
#include <assert.h>

#include "como.h"


/**
 * -- load_object
 *
 * dynamically links a library in. used for all modules as
 * well as for the filters.
 * 
 * XXX in the future we may want to use it for sniffers as well.
 *
 */
void *
load_object(char *base_name, char *symbol)
{
    void *handle, *sym;

    handle = dlopen(base_name, RTLD_NOW);
    if (handle == NULL) {
        logmsg(LOGCONFIG, "dlopen(%s, RTLD_NOW) error [%s]\n",
                base_name, dlerror());
        return NULL;
    }
    sym = dlsym(handle, symbol);
    if (sym == NULL) {
        logmsg(LOGCONFIG, "module %s missing '%s' (%s)\n",
                base_name, symbol, dlerror());
        dlclose(handle);
        return NULL;
    }
    logmsg(LOGCONFIG, "loaded shared object %s\n", base_name);

    return (void *) sym;
}


/* 
 * -- getprotoname
 * 
 * this function is basically getprotobynumber() that needs to 
 * be redefined here because linux's netdb.h uses __unused as  
 * variable name (?!?). In order to avoid the mess, it is easier
 * to rewrite the function from scratch. 
 * 
 * Given that we are at it we also fix the problem with /etc/protocols 
 * in Linux that gives uncommon names to common protocols (e.g., protocol 
 * number 50 is better known as ESP than IPV6-CRYPT). 
 * 
 * we know the name of the first 133 protocols.
 */

static char * 
alias[256] = { 
    "ip","icmp","igmp","ggp","ipencap","st2","tcp","cbt","egp",
    "igp","bbn-rcc","nvp","pup","argus","emcon","xnet","chaos",
    "udp","mux","dcn","hmp","prm","xns-idp","trunk-1","trunk-2",
    "leaf-1","leaf-2","rdp","irtp","iso-tp4","netblt","mfe-nsp",
    "merit-inp","sep","3pc","idpr","xtp","ddp","idpr-cmtp","tp++",
    "il","ipv6","sdrp","ipv6-route","ipv6-frag","idrp","rsvp","gre",
    "mhrp","bna","esp","ah","i-nlsp","swipe","narp","mobile","tlsp",
    "skip","ipv6-icmp","ipv6-nonxt","ipv6-opts","cftp","sat-expak",
    "kryptolan","rvd","ippc","sat-mon","visa","ipcv","cpnx","cphb",
    "wsn","pvp","br-sat-mon","sun-nd","wb-mon","wb-expak","iso-ip",
    "vmtp","secure-vmtp","vines","ttp","nsfnet-igp","dgp","tcf",
    "eigrp","ospf","sprite-rpc","larp","mtp","ax.25","ipip","micp",
    "scc-sp","etherip","encap","99","gmtp","ifmp","pnni","pim","aris",
    "scps","qnx","a/n","ipcomp","snp","compaq-peer","ipx-in-ip",
    "carp","pgm","l2tp","ddx","iatp","st","srp","uti","smp","sm",
    "ptp","isis","fire","crtp","crudp","sscopmce","iplt","sps",
    "pipe","sctp","fc","134","135","136","137","138","139","140",
    "141","142","143","144","145","146","147","148","149","150",
    "151","152","153","154","155","156","157","158","159","160",
    "161","162","163","164","165","166","167","168","169","170",
    "171","172","173","174","175","176","177","178","179","180",
    "181","182","183","184","185","186","187","188","189","190",
    "191","192","193","194","195","196","197","198","199","200",
    "201","202","203","204","205","206","207","208","209","210",
    "211","212","213","214","215","216","217","218","219","220",
    "221","222","223","224","225","226","227","228","229","230",
    "231","232","233","234","235","236","237","238","239","pfsync",
    "241","242","243","244","245","246","247","248","249","250",
    "251","252","253","254","255"};

__inline__ char *
getprotoname(int proto) 
{
    return alias[proto]; 
}
	    

#if 0 

/*
 * Debugging code.
 * XXX is never used in any part of the code. But we still keep it
 * in case it turns out to be useful (lr 2005.02.16)
 */
/*
 * op == 0: set counter to value
 * op != 0: add value to counter
 */
void
count_set(int off, int op, int value, char *name)
{
    ctr_t *ctr = &map.stats.base,
    *last = &map.last_stats.base,
    *t = &map.stats_times.base;

    ctr[off] = op ? ctr[off] + (uint)value : (uint)value;
    if ((uint)map.now.tv_sec != t[off]) {
        t[off] = map.now.tv_sec;
        logmsg(V_LOGDEBUG, "COUNT %8d [%8d] %s\n",
            ctr[off], ctr[off] - last[off], name);
        fflush(stdout);
        last[off] = ctr[off];
    }
}
#endif
