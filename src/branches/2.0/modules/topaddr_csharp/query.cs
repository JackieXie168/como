/*
 * Copyright (c) 2007, Intel Corporation
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

namespace CoMo.Modules.topaddr_csharp
{
    using System;
    using System.Collections;
    
    public class Query : CoMo.Mdl, CoMo.IQuery
    {
        const string PRETTYHDR = "Date                          rank  {0:15} Bytes      Packets   \n";
        const string PRETTYFMT = "{0,29} {1,4:d} {2,15} {3,10:d} {4,8:d}\n";

        const string PLAINFMT = "{0,12} {1} {2,15} {3,10} {4,8}\n";

        const string HTMLHDR = @"
<html>
<head>
  <style type=""text/css"">
   body { font-family: ""lucida sans unicode"", verdana, arial;
          font-size: 9pt; margin: 0; padding: 0;}
   table, tr, td {background-color: #DDD;
     font-family: ""lucida sans unicode"", verdana, arial;
     font-size: 9pt;}
   a, a:visited { color: #475677; text-decoration: none;}
   .netviewbar{
     color :#FFF; width :100%%; padding :2px; text-align:center;}
   .netview {
     top: 0px; width: 100%%; vertical-align:top;
     margin: 2; padding-left: 5px;
     padding-right: 5px; text-align:left;}
   .nvtitle {
     font-weight: bold; font-size: 9pt; padding-bottom: 3px;
     color: #475677;}
  </style>
</head>
<body>
";

        const string HTMLTITLE = @"
<div class=nvtitle style=""border-top: 1px solid;"">
Top-{0} {1}</div>
<table class=netview>
  <tr class=nvtitle>
    <td>#</td>
    <td>IP Address</td>
    <td>bps</td>
    <td>pps</td>
  </tr>
";
        const string SIDEBOXTITLE = @"
<table class=netview>
  <tr class=nvtitle>
    <td>#</td>
    <td>IP Address</td>
    <td>bps</td>
    <td>pps</td>
  </tr>
";
        const string HTMLFOOTER	= "</table>\n</body></html>\n";
        const string HTMLFMT = @"
<tr><td>{0}</td><td><a href=""{1}"" target=_new>{2}</a></td>
<td>{3}</td><td>{4}</td></tr>
";

        public QueryFormat[] formats = {
            new QueryFormat("pretty", "text/plain"),
            new QueryFormat("plain", "text/plain"),
            new QueryFormat("html", "text/html"),
            new QueryFormat("sidebox", "text/html"),
        };
        public string default_format = "pretty";

        TopaddrConfig cfg;
        string what;

        string urlstr;
        uint current;
        int count;

        public void init(string format, Hashtable args)
        {
            cfg = (TopaddrConfig) config;
            if (cfg.use_dst != 0)
                what = "Destination IP";
            else
                what = "Source IP";

            switch (format) {
                case "pretty":
                    print(String.Format(PRETTYHDR, what));
                    break;
                case "html":
                    print(HTMLHDR);
                    print(String.Format(HTMLTITLE, cfg.topn, what));
                    break;
                case "sidebox":
                    print(HTMLHDR);
                    print(SIDEBOXTITLE);
                    break;
            }

            urlstr = "#";
            current = 0;
            count = 0;
        }
        
        public void finish(string format)
        {
            switch (format) {
                case "html":
                    print(HTMLFOOTER);
                    break;
                case "sidebox":
                    print(HTMLFOOTER);
                    break;
            }
        }

        
        public void print_rec(string format, Record _r)
        {
            TopaddrRecord r = (TopaddrRecord) _r;
            uint ts = TS.sec(r.ts);

            if (current != ts) {
                current = ts;
                count = 0;
            }
            count++;

            uint addr = r.addr & cfg.mask;
            ulong fullts = TS.from_time(ts, 0);

            switch (format) {
                case "pretty":
                    print(String.Format(PRETTYFMT, TS.to_string(fullts),
                                count, IP.to_string(addr), r.bytes, r.pkts));
                    break;

                case "plain":
                    print(String.Format(PLAINFMT, ts, count,
                                IP.to_string(addr), r.bytes, r.pkts));
                    break;

                case "html":
                    print(String.Format(HTMLFMT, count, urlstr,
                                IP.to_string(addr), r.bytes, r.pkts));
                    break;

                case "sidebox":
                    print(String.Format(HTMLFMT, count, urlstr,
                                IP.to_string(addr), r.bytes, r.pkts));
                    break;
                    
            }
        }
    }
} // namespace

