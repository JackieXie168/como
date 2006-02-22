/* Copyright (c) 2005 Microsoft Corporation. 
 * All rights reserved. 
 * 
 * See license details at the end of this file. 
 * The license and copyright notice only applies to sniffer-wpcap.c. 
 *
 * ------
 * The code in this file derives from sniffer-libpcap.c which had
 * the following original copyright notices:
 *
 * Copyright (c) 2004-2005 Intel Corporation
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
 * SUCH DAMAGE."
 *
 * $Id$ 
 */

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "como.h"
#include "sniffers.h"
#include "pcap.h"

/*
 * SNIFFER  ---    wpcap files 
 *
 * Reads wpcap trace files. 
 * It supports only ethernet traces (DLT_EN10MB). 
 *
 */

/* 
 * set this string to something that makes sense in 
 * your system 
 */
#define WPCAP_DEVICE_NAME "\\Device\\NPF_{7884D222-E6B8-4A54-B48D-BDB4C998586B}"

/*
 * default values for libpcap
 */
#define LIBPCAP_DEFAULT_PROMISC 1               /* promiscous mode */
#define LIBPCAP_DEFAULT_SNAPLEN 96              /* packet capture */
#define LIBPCAP_DEFAULT_TIMEOUT 0               /* timeout to serve packets */

/* sniffer specific information */
#define BUFSIZE (1024*1024) 
struct _snifferinfo { 
    pcap_t * handle; 
    char buf[BUFSIZE];   /* base of the capture buffer */
    int nbytes;      	 /* valid bytes in buffer */
};


/* 
 * -- sniffer_start
 *
 */
static int
sniffer_start(source_t * src) 
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *adhandle;
    struct _snifferinfo * info; 
    uint promisc = LIBPCAP_DEFAULT_PROMISC;
    uint slen = LIBPCAP_DEFAULT_SNAPLEN;
    uint tout = LIBPCAP_DEFAULT_TIMEOUT;

    if (src->args) {
        /* process input arguments */
        char * p;
  
        if ((p = strstr(src->args, "promisc=")) != NULL)
            promisc = atoi(p + 8);
        if ((p = strstr(src->args, "snaplen=")) != NULL)
            slen = atoi(p + 8);
        if ((p = strstr(src->args, "timeout=")) != NULL)
            tout = atoi(p + 8);
    }

    adhandle= pcap_open_live(WPCAP_DEVICE_NAME, slen, promisc, tout, errbuf);
    if (adhandle == NULL) {
        logmsg(LOGWARN,"sniffer-wpcap: adapter not supported by WinPcap\n");
        return -1;
    } 

    if (pcap_setnonblock(adhandle, 1, errbuf) < 0) {
        logmsg(LOGWARN, "%s\n", errbuf);
        return -1;
    }

    if (pcap_datalink(adhandle) != DLT_EN10MB) { 
	logmsg(LOGWARN, "sniffer-wpcap: unrecognized datalink format\n" );
	pcap_close(adhandle);
	return -1;
    }

    /* fill in como info */
    src->fd = -1; 
    src->flags = SNIFF_POLL|SNIFF_TOUCHED; 
    src->polling = TIME2TS(1,0); 
    src->ptr = safe_malloc(sizeof(struct _snifferinfo)); 
    info = (struct _snifferinfo *) src->ptr; 
    info->handle = adhandle; 

    return 0;
}

/*
 * sniffer_next
 *
 */
static int
sniffer_next(source_t *src, pkt_t *out, int max_no) 
{
    struct _snifferinfo * info; 
    struct pcap_pkthdr *header;
    const u_char *pkt_data;    
    int npkts;
    pkt_t * pkt;                 /* CoMo record structure */
    int res;
    
    info = (struct _snifferinfo *) src->ptr; 
    
    /* Retrieve the packets */
    npkts = 0; 
    pkt = out; 
    while ((res = pcap_next_ex(info->handle, &header, &pkt_data)) > 0) {
        if (res == 0) 
            /* Timeout elapsed */
            continue;
        
        /*      
         * Now we have a packet: start filling a new pkt_t struct
         * (beware that it could be discarded later on)
         */
        npkts++;

	COMO(ts) = TIME2TS(header->ts.tv_sec, header->ts.tv_usec);
	COMO(type) = COMOTYPE_LINK;
	COMO(len) = header->len;
	COMO(caplen) = header->caplen;
	COMO(payload) = (char *) pkt_data;

        /* 
         * update layer2 information and offsets of layer 3 and above. 
         * this sniffer only runs on ethernet frames. 
         */
	updateofs(pkt, L2, LINKTYPE_ETH);
        if (npkts >= max_no) 
	    break;
        pkt++;
    }

    if (res == -1) {
        logmsg(LOGWARN, "sniffer-wpcap: Error reading the packets: %s\n", 
	    pcap_geterr(info->handle)); 
        return -1;
    }
        
    return npkts;
}


/* 
 * -- sniffer_stop
 * 
 * Close the file descriptor. 
 */
static void
sniffer_stop (source_t * src)
{
    struct _snifferinfo * info; 
    info = (struct _snifferinfo *) src->ptr; 
    pcap_close(info->handle); 
    free(src->ptr);
}


sniffer_t wpcap_sniffer = {
    "wpcap", sniffer_start, sniffer_next, sniffer_stop
};

/* 
 * 
 * 

=======================================================
MICROSOFT RESEARCH SHARED SOURCE LICENSE AGREEMENT

This Microsoft Research Shared Source license agreement ("MSR-SSLA")
is a legal agreement between you and Microsoft Corporation
("Microsoft" or "we") for the software or data identified above, which
may include source code, and any associated materials, text or speech
files, associated media and "online" or electronic documentation and
any updates we provide in our discretion (together, the "Software").  

By installing, copying, or otherwise using this Software, found at
http://research.microsoft.com/downloads, you agree to be bound by the
terms of this MSR-SSLA. If you do not agree, do not install copy or
use the Software. The Software is protected by copyright and other
intellectual property laws and is licensed, not sold.     
 
SCOPE OF RIGHTS:
You may use, copy, reproduce, and distribute this Software for any
non-commercial purpose, subject to the restrictions in this
MSR-SSLA. Some purposes which can be non-commercial are teaching,
academic research, public demonstrations and personal
experimentation. You may also distribute this Software with books or
other teaching materials, or publish the Software on websites, that
are intended to teach the use of the Software for academic or other
non-commercial purposes. 
You may not use or distribute this Software or any derivative works in
any form for commercial purposes. Examples of commercial purposes
would be running business operations, licensing, leasing, or selling
the Software, distributing the Software for use with commercial
products, using the Software in the creation or use of commercial
products or any other activity which purpose is to procure a
commercial gain to you or others. 
If the Software includes source code or data, you may create
derivative works of such portions of the Software and distribute the
modified Software for non-commercial purposes, as provided herein. 

In return, we simply require that you agree:  
1. That you will not remove any copyright or other notices from the
   Software. 
2. That if any of the Software is in binary format, you will not
   attempt to modify such portions of the Software, or to reverse
   engineer or decompile them, except and only to the extent
   authorized by applicable law.  
3. That if you distribute the Software or any derivative works of the
   Software, you will distribute them under the same terms and
   conditions as in this license, and you will not grant other rights
   to the Software or derivative works that are different from those
   provided by this MSR-SSLA.  
4. That if you have created derivative works of the Software, and
   distribute such derivative works, you will cause the modified files
   to carry prominent notices so that recipients know that they are
   not receiving the original Software. Such notices must state: (i)
   that you have changed the Software; and (ii) the date of any
   changes. 
5. That Microsoft is granted back, without any restrictions or
   limitations, a non-exclusive, perpetual, irrevocable, royalty-free,
   assignable and sub-licensable license, to reproduce, publicly
   perform or display, install, use, modify, distribute, make and have
   made, sell and transfer your modifications to and/or derivative
   works of  the Software source code or data, for any purpose.  
6. That any feedback about the Software provided by you to us is
   voluntarily given, and Microsoft shall be free to use the feedback
   as it sees fit without obligation or restriction of any kind, even
   if the feedback is designated by you as confidential.  
7. THAT THE SOFTWARE COMES "AS IS", WITH NO WARRANTIES. THIS MEANS NO
   EXPRESS, IMPLIED OR STATUTORY WARRANTY, INCLUDING WITHOUT
   LIMITATION, WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A
   PARTICULAR PURPOSE, ANY WARRANTY AGAINST INTERFERENCE WITH YOUR
   ENJOYMENT OF THE SOFTWARE OR ANY WARRANTY OF TITLE OR
   NON-INFRINGEMENT. THERE IS NO WARRANTY THAT THIS SOFTWARE WILL
   FULFILL ANY OF YOUR PARTICULAR PURPOSES OR NEEDS. ALSO, YOU MUST
   PASS THIS DISCLAIMER ON WHENEVER YOU DISTRIBUTE THE SOFTWARE OR
   DERIVATIVE WORKS. 
8. THAT NEITHER MICROSOFT NOR ANY CONTRIBUTOR TO THE SOFTWARE WILL BE
   LIABLE FOR ANY DAMAGES RELATED TO THE SOFTWARE OR THIS MSR-SSLA,
   INCLUDING DIRECT, INDIRECT, SPECIAL, CONSEQUENTIAL OR INCIDENTAL
   DAMAGES, TO THE MAXIMUM EXTENT THE LAW PERMITS, NO MATTER WHAT
   LEGAL THEORY IT IS BASED ON. ALSO, YOU MUST PASS THIS LIMITATION OF
   LIABILITY ON WHENEVER YOU DISTRIBUTE THE SOFTWARE OR DERIVATIVE
   WORKS. 
9. That we have no duty of reasonable care or lack of negligence, and
   we are not obligated to (and will not) provide technical support
   for the Software. 
10. That if you breach this MSR-SSLA or if you sue anyone over patents
    that you think may apply to or read on the Software or anyone's
    use of the Software, this MSR-SSLA (and your license and rights
    obtained herein) terminate automatically.  Upon any such
    termination, you shall destroy all of your copies of the Software
    immediately.  Sections 5, 6, 7, 8, 9, 10, 13 and 14 of this
    MSR-SSLA shall survive any termination of this MSR-SSLA. 
11. That the patent rights, if any, granted to you in this MSR-SSLA
    only apply to the Software, not to any derivative works you make. 
12. That the Software may be subject to U.S. export jurisdiction at
    the time it is licensed to you, and it may be subject to
    additional export or import laws in other places. You agree to
    comply with all such laws and regulations that may apply to the
    Software after delivery of the software to you. 
13. That all rights not expressly granted to you in this MSR-SSLA are
    reserved. 
14. That this MSR-SSLA shall be construed and controlled by the laws
    of the State of Washington, USA, without regard to conflicts of
    law.  If any provision of this MSR-SSLA shall be deemed
    unenforceable or contrary to law, the rest of this MSR-SSLA shall
    remain in full effect and interpreted in an enforceable manner
    that most nearly captures the intent of the original language. 

*
*
*/
