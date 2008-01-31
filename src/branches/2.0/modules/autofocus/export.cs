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

namespace CoMo.Modules.autofocus
{
    using System;
    using System.Collections;
    using System.Text;
    using System.Net;

    public class Export : CoMo.Mdl, CoMo.IExport
    {
        protected class TreeNode {
            public TreeNode left, right;
            public ulong volume;
            public byte interest;

            public TreeNode(Export ex) {
                left = null;
                right = null;
                volume = 0;
                interest = 0;

                /* XXX rough estimate */
                ex.mem_usage += 4 + 4 + 8 + 1;
            }
        };

        TreeNode tree;
        uint current_ivl_sec;
        ulong mem_usage;
        AutofocusConfig cfg;

        protected void reset_state() 
        {
            tree = null;
            mem_usage = 0;
        }

        protected void update_tree(uint addr, ulong volume)
        {
            if (tree == null)
                tree = new TreeNode(this);

            TreeNode t = tree;

            for (int shift = 31; shift >= 0; shift--) {
                uint bit = addr & (uint)(1 << shift);
                if (bit == 0) {
                    if (t.left == null)
                        t.left = new TreeNode(this);
                    t = t.left;
                } else {
                    if (t.right == null)
                        t.right = new TreeNode(this);
                    t = t.right;
                }
            }

            t.volume += volume;
        }

        protected ulong compute_volumes(TreeNode t)
        {
            if (t == null)
                return 0;

            t.volume += compute_volumes(t.left) + compute_volumes(t.right);
            return t.volume;
        }

        protected ulong compress(TreeNode t, ulong vol_thres,
                                    double redundancy_thres, int depth)
        {
            ulong rep_vol;

            if (t != null) /* initially set to non-interesting */
                t.interest = 0;

            if (t == null || t.volume < vol_thres) /* nothing to see here */
                return 0;

            /*
             * first iterate through the children
             */
            rep_vol = compress(t.left, vol_thres, redundancy_thres, depth + 1) +
                compress(t.right, vol_thres, redundancy_thres, depth + 1);

            /*
             * check if interesting children's volumes explain this node's.
             * if so, we don't have interest in reporting this one, and
             * we return the interesting children's.
             */
            if (rep_vol * redundancy_thres >= t.volume)
                return rep_vol;

            /*
             * otherwise this node shall be reported.
             */
            t.interest = 1;
            return t.volume;
        }

        protected void generate_report(TreeNode t, int depth, uint addr)
        {
            if (t == null)
                return;

            if (t.interest == 1) {
                AutofocusRecord r = new AutofocusRecord();
                r.ts = TS.from_time(current_ivl_sec, 0);
                r.addr = (uint)IPAddress.HostToNetworkOrder((int)addr);
                r.mask = (byte)depth;
                r.bytes = t.volume;
                store_rec(r);
            }

            generate_report(t.left, depth + 1, addr);
            generate_report(t.right, depth + 1,
                                addr | (uint)(1 << (31 - depth)));
        }

        protected void generate_report()
        {
            ulong total_volume;
            
            total_volume = compute_volumes(tree);
            compress(tree, (ulong)(total_volume * 0.05), 1.20, 0);
            generate_report(tree, 0, 0);
        }

        public void init()
        {
            cfg = (AutofocusConfig) config;
            current_ivl_sec = 0;
            reset_state();
        }

        public void export(object[] tuples, ulong ivl_start)
        {
            uint ivl_start_sec;
            
            ivl_start_sec = TS.sec(ivl_start);
            ivl_start_sec -= ivl_start_sec % cfg.output_ivl;

            if (current_ivl_sec == 0) /* first tuples */
                current_ivl_sec = ivl_start_sec;

            if (ivl_start_sec != current_ivl_sec) { /* change ivl */
                generate_report();
                reset_state();
                current_ivl_sec = ivl_start_sec;
            }

            foreach(AutofocusTuple t in tuples)
                update_tree(t.addr, (ulong) t.bytes);
        }
    }
}

