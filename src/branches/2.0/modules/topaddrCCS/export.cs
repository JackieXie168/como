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

namespace CoMo.Modules.topaddrCCS
{
    using System;
    using System.Collections;

    /*
     * we store records in ascending order by number of
     * bytes, we implement a class that has a function
     * to compare records. This way we can use Array.Sort()
     * later.
     */
    public class TopaddrRecordComparer : IComparer
    {
        int IComparer.Compare(Object _x, Object _y)  {
            TopaddrRecord x = (TopaddrRecord) _x;
            TopaddrRecord y = (TopaddrRecord) _y;
            if (x.bytes > y.bytes)
                return 1;
            if (x.bytes < y.bytes)
                return -1;
            return 0;
        }
    };

    public class Export : CoMo.Mdl, CoMo.IExport
    {
        ulong current_ivl;
        Hashtable table;
        TopaddrConfig cfg;

        protected void reset_state()
        {
            table = new Hashtable();
        }

        public void init()
        {
            cfg = (TopaddrConfig) config;
            current_ivl = 0;
            reset_state();
        }

        public void store_info()
        {
            ArrayList records = new ArrayList(); /* dump to array */
            foreach (DictionaryEntry d in table)
                records.Add(d.Value);
            
            TopaddrRecordComparer comp = new TopaddrRecordComparer(); /* sort */
            records.Sort(comp);

            int i = 0;
            foreach (TopaddrRecord r in records) { /* store top-N */
                if (i > cfg.topn)
                    break;
                store_rec(r);
                i++;
            }
        }

        public void process_tuple(TopaddrTuple t, ulong ts)
        {
            TopaddrRecord r = (TopaddrRecord) table[t.addr];

            if (r == null) { /* need new entry in hash table */
                r = new TopaddrRecord();
                r.addr = t.addr;
                r.bytes = 0;
                r.pkts = 0;
                r.ts = ts;
                table[t.addr] = r;
            }

            r.bytes += t.bytes; /* update entry */
            r.pkts += t.pkts;
        }

        public void export(object[] tuples, ulong ivl_start)
        {
            if (current_ivl == 0) /* first tuples */
                current_ivl = ivl_start;

            if (ivl_start != current_ivl) { /* change ivl */
                store_info();
                reset_state();
            }

            foreach(TopaddrTuple t in tuples)
                process_tuple(t, ivl_start);
        }
    }
}

