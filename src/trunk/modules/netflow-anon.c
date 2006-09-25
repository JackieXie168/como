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
 * NetFlow Anonimization module
 * This module allows you to view all fields from 
 * version 5 netflow records.  The source and destination IP addresses
 * are anonimized with the mask.  You can select fields you would like 
 * to print with the field= argument.  Usage is also provided.
 *
 */

#include <stdio.h>
#include <time.h>
#include "module.h"

#define FLOWDESC    struct _netflow_anon

FLOWDESC {
    timestamp_t ts;
    uint32_t duration;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;

    uint8_t proto;
    uint8_t tcp_flags;
    char padding[2];
    uint64_t bytes;
    uint64_t pkts;

    uint16_t src_as;
    uint16_t dst_as;
    uint32_t exaddr;
    uint32_t nexthop;
    uint8_t src_mask;
    uint8_t dst_mask;
    uint8_t engine_type;
    uint8_t engine_id;
    uint16_t input;
    uint16_t output;
};


static timestamp_t 
init(__unused void * self, __unused char *args[])
{
    pkt_t *pkt;
    metadesc_t *inmd;
    
    /* setup indesc */
    inmd = metadesc_define_in(self, 0);
    inmd->ts_resolution = TIME2TS(300, 0);
    
    pkt = metadesc_tpl_add(inmd, "nf:none:~ip:none");
    IP(proto) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    
    pkt = metadesc_tpl_add(inmd, "nf:none:~ip:~tcp");
    IP(proto) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    N16(TCP(src_port)) = 0xffff;
    N16(TCP(dst_port)) = 0xffff;
    
    pkt = metadesc_tpl_add(inmd, "nf:none:~ip:~udp");
    IP(proto) = 0xff;
    N32(IP(src_ip)) = 0xffffffff;
    N32(IP(dst_ip)) = 0xffffffff;
    N16(UDP(src_port)) = 0xffff;
    N16(UDP(dst_port)) = 0xffff;
    
    return TIME2TS(300,0);
}


static uint32_t
hash(__unused void * self, pkt_t *pkt)
{
    uint sport, dport;

    if (IP(proto) == IPPROTO_TCP) {
        sport = H16(TCP(src_port));
        dport = H16(TCP(dst_port));
    } else if (IP(proto) == IPPROTO_UDP) {
        sport = H16(UDP(src_port));
        dport = H16(UDP(dst_port));
    } else {
        sport = dport = 0;
    }

    return (H32(IP(src_ip)) ^ H32(IP(dst_ip)) ^ (sport << 3) ^ (dport << 3));
}

static int
match(__unused void * self, pkt_t *pkt, void *fh)
{
    FLOWDESC *x = F(fh);
    uint sport, dport;

    if (IP(proto) == IPPROTO_TCP) {
        sport = H16(TCP(src_port));
        dport = H16(TCP(dst_port));
    } else if (IP(proto) == IPPROTO_UDP) {
        sport = H16(UDP(src_port));
        dport = H16(UDP(dst_port));
    } else {
        sport = dport = 0;
    }

    return (
         H32(IP(src_ip)) == x->src_ip &&
         H32(IP(dst_ip)) == x->dst_ip &&
         sport == x->src_port && dport == x->dst_port &&
         IP(proto) == x->proto
    );
}


static int
update(__unused void * self, pkt_t *pkt, void *fh, int isnew)
{
    FLOWDESC *x = F(fh);
    timestamp_t end_ts;
    uint32_t ms; 
  
    if (isnew) {
        x->ts = pkt->ts;
        x->bytes = 0;
        x->pkts = 0;
        x->proto = IP(proto);
        x->src_ip = H32(IP(src_ip));
        x->dst_ip = H32(IP(dst_ip));
        x->src_mask = NF(src_mask);
        x->dst_mask = NF(dst_mask);

        x->src_as = H16(NF(src_as));
        x->dst_as = H16(NF(dst_as));
        x->exaddr = H32(NF(exaddr));
        x->nexthop = H32(NF(nexthop));
        x->engine_type = NF(engine_type);
        x->engine_id = NF(engine_id);
        x->tcp_flags = NF(tcp_flags);
        x->input = H16(NF(input));
        x->output = H16(NF(output));

        if (IP(proto) == IPPROTO_TCP) {
            x->src_port = H16(TCP(src_port));
            x->dst_port = H16(TCP(dst_port));
        } else if (IP(proto) == IPPROTO_UDP) {
            x->src_port = H16(UDP(src_port));
            x->dst_port = H16(UDP(dst_port));
        } else {
            x->src_port = x->dst_port = 0;
        }
    }

    ms = H32(NF(duration));
    end_ts = pkt->ts + TIME2TS(ms / 1000, (ms % 1000) * 1000); 
    x->duration = TS2SEC(end_ts - x->ts) * 1000 + TS2MSEC(end_ts - x->ts);
    x->bytes += H32(NF(pktcount)) * COMO(len);
    x->pkts += (uint64_t) H32(NF(pktcount));

    return 0;
}


static ssize_t
store(__unused void * self, void *efh, char *buf)
{
    FLOWDESC *x = F(efh);
    uint32_t src, dst;

    /* anonyimize the address with mask  */
    src = x->src_ip & (0xffffffff << (32 - x->src_mask));
    dst = x->dst_ip & (0xffffffff << (32 - x->dst_mask));

    PUTH64(buf, x->ts);
    PUTH32(buf, x->duration);
    PUTH32(buf, src);
    PUTH32(buf, dst);
    PUTH16(buf, x->src_port);
    PUTH16(buf, x->dst_port);
    PUTH8(buf, x->proto);
    PUTH8(buf, x->tcp_flags);
    PUTH8(buf, x->padding[0]);
    PUTH8(buf, x->padding[1]);
    PUTH64(buf, x->bytes);
    PUTH64(buf, x->pkts);
    PUTH16(buf, x->src_as);
    PUTH16(buf, x->dst_as);
    PUTH32(buf, x->exaddr);
    PUTH32(buf, x->nexthop);
    PUTH8(buf, x->src_mask);
    PUTH8(buf, x->dst_mask);
    PUTH8(buf, x->engine_type);
    PUTH8(buf, x->engine_id);
    PUTH16(buf, x->input);
    PUTH16(buf, x->output);

    return sizeof(FLOWDESC);
}


/*
 * utility function used to pretty print tcp's control bits status
 */
static char*
print_tcp_flags(uint8_t flags)
{
    static char s[7];
    size_t i;

    i = 0;
    s[i] = '.';

    if (flags & 0x01)
        s[i++] = 'F';
    else
        s[i++] = '-';

    if (flags & 0x02)
        s[i++] = 'S';
    else
        s[i++] = '-';

    if (flags & 0x04)
        s[i++] = 'R';
    else
        s[i++] = '-';

    if (flags & 0x08)
        s[i++] = 'P';
    else
        s[i++] = '-';

    if (flags & 0x10)
        s[i++] = 'A';
    else
        s[i++] = '-';

    if (flags & 0x20)
        s[i++] = 'U';
    else
        s[i++] = '-';

    if (flags & 0x40)
        s[i++] = 'E';
    else
        s[i++] = '-';

    if (flags & 0x80)
        s[i++] = 'C';
    else
        s[i++] = '-';

    s[i] = '\0';
    return s;
}

static size_t
load(__unused void * self, char * buf, size_t len, timestamp_t * ts)
{
    if (len < sizeof(FLOWDESC)) {
        *ts = 0;
        return 0;
    }

    *ts = TIME2TS(ntohl(((FLOWDESC *)buf)->ts), 0);
    return sizeof(FLOWDESC);
}

#define PRETTYHDR                                                   \
    "                                Timestamp  Duration  "          \
    "Proto     Source IP/Mask  Port  Destination IP/Mask  Port    " \
    "Bytes  Packets    "                                            \
    "SrcAS    DstAS      TCP Flags  "                               \
    "Exporter Addr   Next Hop Addr  "                               \
    "Engine Type/ID  "                                              \
    "Input/Output Iface Index\n"

#define PRETTYFMT                                                \
    "%.24s %12u.%03u %9.3f %6d %15s/%d %5u %17s/%d %5u %8llu "         \
    "%8llu %8d %8d %4d(%s)%15s %15s %13d/%d %22d/%d\n"

#define USAGE                                                    \
    "USAGE:\n"                                                   \
    "fields=comma,seperated,list,of,options\n"                   \
    "Valid fields can be any of the following\n\n"               \
    "datetime - Timestamp in human readable format\n"            \
    "timestamp - Timestamp in seconds\n"                         \
    "proto - Protocol\n"                                         \
    "srcip - Source IP Address\n"                                \
    "srcmask - Source network mask\n"                            \
    "srcport - Source port\n"                                    \
    "dstip - Destination IP Address\n"                           \
    "dstmask - Destination network mask\n"                       \
    "dstport - Destination port\n"                               \
    "bytes - Number of Bytes\n"                                  \
    "pkts - Number of Packets\n"                                 \
    "srcas - Source AS number\n"                                 \
    "dstas - Destination AS number\n"                            \
    "tcpflags - OR of TCP header bits\n"                         \
    "exaddr - Exporter IP Address\n"                             \
    "nexthop - Next hop router IP address\n"                     \
    "enginetype - Type of flow switching engine (RP,VIP,etc.)\n" \
    "engineid - Slot number of the flow switching engine\n"      \
    "input - Input interface index\n"                            \
    "output - Output interface index\n\n"                        \
    "fivetuple - src/dst ip/mask:port protocol\n"                \
    "all - all fields\n"

#define PRINTPRETTYTS   0x00000001
#define PRINTTS         0x00000002
#define PRINTPROTO      0x00000004
#define PRINTSRCIP      0x00000008
#define PRINTSRCMASK    0x00000010
#define PRINTSRCPORT    0x00000020
#define PRINTDSTIP      0x00000040
#define PRINTDSTMASK    0x00000080
#define PRINTDSTPORT    0x00000100
#define PRINTBYTES      0x00000200
#define PRINTPACKETS    0x00000800
#define PRINTSRCAS      0x00001000
#define PRINTDSTAS      0x00002000
#define PRINTTCPFLAGS   0x00004000
#define PRINTEXADDR     0x00008000
#define PRINTNEXTHOP    0x00010000
#define PRINTENGINETYPE 0x00020000
#define PRINTENGINEID   0x00040000
#define PRINTINPUT      0x00080000
#define PRINTOUTPUT     0x00100000
#define PRINTFIVETUP    0x00200000
#define PRINTALL        0x00400000
#define PRINTUSAGE      0x00800000
#define PRINTDEF        0x01000000

static char *
print(__unused void * self, char *buf, size_t *len, char * const args[])
{
    static char s[2048];
    char src[20], dst[20], exaddr[20], nexthop[20];
    struct in_addr addr;
    static int flag; 
    static uint32_t printflags;
    FLOWDESC *x;
    time_t ts;
    float duration;
    int n;
    *len = 0;
    printflags |= PRINTDEF;

    /*  Print Header  */
    if (buf == NULL && args != NULL) {

	/* default to pretty printing */
	*len = sprintf(s, PRETTYHDR);

	/*  Parse the field args  */
	for (n = 0; args[n]; n++){
	    if (!strncmp(args[n], "fields=", 7)) {
		*len = 0;
		printflags = 0;
                flag=0;
                if (strstr(args[n], "datetime")){
                    printflags |= PRINTPRETTYTS;
                    *len += sprintf(s+*len,"Human Readable Timestamp  Duration");
                    flag++;
                }
                if (strstr(args[n], "timestamp")){
                    printflags |= PRINTTS;
                    *len += sprintf(s + *len, "       Timestamp  Duration");
                    flag++;
                }
                if (strstr(args[n], "proto")){
                    printflags |= PRINTPROTO;
                    *len += sprintf(s + *len, "  Proto");
                    flag++;
                }
                if (strstr(args[n], "srcip")){
                    printflags |= PRINTSRCIP;
                    *len += sprintf(s + *len, "      Source IP");
                    flag++;
                }
                if (strstr(args[n], "srcmask")){
                    printflags |= PRINTSRCMASK;
                    *len += sprintf(s + *len, "  Src Mask");
                    flag++;
                }
                if (strstr(args[n], "srcport")){
                    printflags |= PRINTSRCPORT;
                    *len += sprintf(s + *len, "  Src Port");
                    flag++;
                }
                if (strstr(args[n], "dstip")){
                    printflags |= PRINTDSTIP;
                    *len += sprintf(s + *len, "        Dest IP");
                    flag++;
                }
                if (strstr(args[n], "dstmask")){
                    printflags |= PRINTDSTMASK;
                    *len += sprintf(s + *len, "  Dst Mask");
                    flag++;
                }
                if (strstr(args[n], "dstport")){
                    printflags |= PRINTDSTPORT;
                    *len += sprintf(s + *len, "  Dst Port");
                    flag++;
                }
                if (strstr(args[n], "bytes")){
                    printflags |= PRINTBYTES;
                    *len += sprintf(s + *len, "     Bytes");
                    flag++;
                }
                if (strstr(args[n], "pkts")){
                    printflags |= PRINTPACKETS;
                    *len += sprintf(s + *len, "   Packets");
                    flag++;
                }
                if (strstr(args[n], "srcas")){
                    printflags |= PRINTSRCAS;
                    *len += sprintf(s + *len, "  Src AS");
                    flag++;
                }
                if (strstr(args[n], "dstas")){
                    printflags |= PRINTDSTAS;
                    *len += sprintf(s + *len, "  Dst AS");
                    flag++;
                }
                if (strstr(args[n], "tcpflags")){
                    printflags |= PRINTTCPFLAGS;
                    *len += sprintf(s + *len, "     TCP Flags");
                    flag++;
                }
                if (strstr(args[n], "exaddr")){
                    printflags |= PRINTEXADDR;
                    *len += sprintf(s + *len, "  Exporter Addr");
                    flag++;
                }
                if (strstr(args[n], "nexthop")){
                    printflags |= PRINTNEXTHOP;
                    *len += sprintf(s + *len, "  Next Hop Addr");
                    flag++;
                }
                if (strstr(args[n], "enginetype")){
                    printflags |= PRINTENGINETYPE;
                    *len += sprintf(s + *len, "   Engine Type");
                    flag++;
                }
                if (strstr(args[n], "engineid")){
                    printflags |= PRINTENGINEID;
                    *len += sprintf(s + *len, "   Engine ID");
                    flag++;
                }
                if (strstr(args[n], "input")){
                    printflags |= PRINTINPUT;
                    *len += sprintf(s + *len, "   Input");
                    flag++;
                }
                if (strstr(args[n], "output")){
                    printflags |= PRINTOUTPUT;
                    *len += sprintf(s + *len, "   Output");
                    flag++;
                }
                if (strstr(args[n], "fivetuple")){
                    printflags |= PRINTFIVETUP;
                    *len += sprintf(s + *len, "     Source IP/Mask  Port  "
                                    "Destination IP/Mask  Port  Proto ");
                    flag++;
                }
                if (strstr(args[n], "all")){
                    printflags |= PRINTALL;
		    *len = sprintf(s, PRETTYHDR);
                    flag=0;
                }
                if ((!flag) && (!(printflags & PRINTALL))){
                    *len = sprintf(s, USAGE);
                    printflags |= PRINTUSAGE;
                }
                /*  Add a newline  */
                if (!(printflags & PRINTALL))
		    *len += sprintf(s+*len, "\n");
            }
	}
        return s;
    }

    if (buf == NULL && args == NULL) {
        *len = 0;
        return s;
    }

    x = (FLOWDESC *) buf;
    ts = (time_t) TS2SEC(NTOHLL(x->ts));
    duration = ((float) ntohl(x->duration)) / 1000.0; 
    addr.s_addr = x->src_ip;
    sprintf(src, "%s", inet_ntoa(addr));
    addr.s_addr = x->dst_ip;
    sprintf(dst, "%s", inet_ntoa(addr));
    addr.s_addr = x->exaddr;
    sprintf(exaddr, "%s", inet_ntoa(addr));
    addr.s_addr = x->nexthop;
    sprintf(nexthop, "%s", inet_ntoa(addr));
     
    if (flag){
	if (printflags & PRINTPRETTYTS)
	    *len += sprintf(s + *len, "%.24s %9.3f", 
			    asctime(gmtime(&ts)), duration); 
	if (printflags & PRINTTS)
	    *len += sprintf(s + *len, "%12u.%03u %9.3f", 
                            (uint32_t) ts, TS2MSEC(NTOHLL(x->ts)), duration); 
	if (printflags & PRINTPROTO)
	    *len += sprintf(s + *len, "%7d", (uint) x->proto); 
	if (printflags & PRINTSRCIP)
	    *len += sprintf(s + *len, "%15s", src); 
	if (printflags & PRINTSRCMASK)
	    *len += sprintf(s + *len, "%10d", x->src_mask); 
	if (printflags & PRINTSRCPORT)
	    *len += sprintf(s + *len, "%10d", x->src_port); 
	if (printflags & PRINTDSTIP)
	    *len += sprintf(s + *len, "%15s", dst); 
	if (printflags & PRINTDSTMASK)
	    *len += sprintf(s + *len, "%10d", x->dst_mask); 
	if (printflags & PRINTDSTPORT)
	    *len += sprintf(s + *len, "%10d", x->dst_port); 
	if (printflags & PRINTBYTES)
	    *len += sprintf(s + *len, "%10llu", NTOHLL(x->bytes)); 
	if (printflags & PRINTPACKETS)
	    *len += sprintf(s + *len, "%10llu", NTOHLL(x->pkts)); 
	if (printflags & PRINTSRCAS)
	    *len += sprintf(s + *len, "%8d", ntohs(x->src_as)); 
	if (printflags & PRINTDSTAS)
	    *len += sprintf(s + *len, "%8d", ntohs(x->dst_as)); 
	if (printflags & PRINTTCPFLAGS)
	    *len += sprintf(s + *len, "%4d(%s)", 
                            x->tcp_flags,print_tcp_flags(x->tcp_flags)); 
	if (printflags & PRINTEXADDR)
	    *len += sprintf(s + *len, "%15s", exaddr); 
	if (printflags & PRINTNEXTHOP)
	    *len += sprintf(s + *len, "%15s", nexthop); 
	if (printflags & PRINTENGINETYPE)
	    *len += sprintf(s + *len, "%14d", x->engine_type); 
	if (printflags & PRINTENGINEID)
	    *len += sprintf(s + *len, "%12d", x->engine_id); 
	if (printflags & PRINTINPUT)
	    *len += sprintf(s + *len, "%8d", ntohs(x->input)); 
	if (printflags & PRINTOUTPUT)
	    *len += sprintf(s + *len, "%9d", ntohs(x->output)); 
	if (printflags & PRINTFIVETUP){
	    *len += sprintf(s + *len, "%15s/%2d %5u %17s/%d %5u %6d", 
                            src, x->src_mask, x->src_port, 
                            dst, x->dst_mask, x->dst_port, (uint) x->proto); 
        }
	/*  Add a newline  */
	*len += sprintf(s+*len, "\n");
    }else{
	if ((((!(printflags & PRINTUSAGE)) && (printflags & PRINTDEF))) 
	     || (printflags & PRINTALL)){
	    *len = sprintf(s + *len, PRETTYFMT,
            asctime(gmtime(&ts)), (uint32_t) ts, TS2MSEC(NTOHLL(x->ts)),
	    duration, (uint) x->proto,
            src, x->src_mask, (uint) ntohs(x->src_port),
            dst, x->dst_mask, (uint) ntohs(x->dst_port),
            NTOHLL(x->bytes), NTOHLL(x->pkts), 
	    ntohs(x->src_as), ntohs(x->dst_as), 
	    x->tcp_flags, print_tcp_flags(x->tcp_flags),
	    exaddr, nexthop,
	    x->engine_type, x->engine_id, 
	    ntohs(x->input), ntohs(x->output)
	    );
        }
    }
    return s;
};

MODULE(netflow_anon) = {
    ca_recordsize: sizeof(FLOWDESC),
    ex_recordsize: 0,
    st_recordsize: sizeof(FLOWDESC),
    init: init,
    check: NULL,
    hash: hash,
    match: match,
    update: update,
    ematch: NULL,
    export: NULL,
    compare: NULL,
    action: NULL,
    store: store,
    load: load,
    print: print,
    replay: NULL,
    formats: "pretty",
};
