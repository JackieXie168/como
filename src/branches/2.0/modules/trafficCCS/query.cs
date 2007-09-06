namespace CoMo.Modules.trafficCCS
{
    using System;
    using System.Collections;
    
    public class Query : CoMo.Mdl, CoMo.IQuery
    {
        public QueryFormat[] formats = {
            new QueryFormat("pretty", "text/plain"),
            new QueryFormat("plain", "text/plain"),
            new QueryFormat("mbps", "text/plain"),
            new QueryFormat("gnuplot", "text/plain"),
        };

        public string default_format = "pretty";

        const string GNUPLOTHDR = @"
set terminal postscript eps color solid lw 1 ""Helvetica"" 14;
set grid;
set ylabel ""Mbps"" textcolor lt 3;
set xlabel ""Time (HH:MM UTC)"";
set y2label ""Packets/sec"" textcolor lt 4;
set y2tics nomirror;
set ytics nomirror;
set yrange [0:*];
set y2range [0:*];
set autoscale xfix;
set nokey;
set xdata time;
set timefmt ""%%s"";
set format x ""%%H:%%M"";
plot ""-"" using 1:2 axis x1y1 with lines lt 3, 
""-"" using 1:3 axis x1y2 with lines lt 4
";

        const string PRETTYHDR = "Date                     Timestamp          Bytes    Pkts\n";
        const string GNUPLOTFOOTER = "e\n";

        const string PRETTYFMT = "%.24s %12d.%06d %8llu %8u\n";
        const string PLAINFMT =	"%12ld %16llu %12llu %12u\n";
        const string MBPSFMT = "%4.2f Mbps\n";
        const string GNUPLOTFMT = "%ld %f %u\n";

        public void init(string format, Hashtable args)
        {
            switch (format) {
                case "gnuplot":
                    print(GNUPLOTHDR);
                    break;
                case "pretty":
                    print(PRETTYHDR);
                    break;
            }
        }
        
        public void finish(string format)
        {
            if (format == "gnuplot")
                print(GNUPLOTFOOTER);
        }

        public void print_rec(string format, Record _r)
        {
            TrafficTuple r = (TrafficTuple) _r;
            float mbps;

            switch (format) {
            case "plain":
                print(String.Format("{0} {1} {2} {3}\n", TS.sec(r.ts), r.ts,
                            r.bytes[0], r.pkts[0]));
                break;
            case "pretty":
                print(String.Format("{0} {1} {2} {3}\n", TS.to_string(r.ts),
                            TS.sec(r.ts), r.bytes[0], r.pkts[0]));
                break;
            case "gnuplot":
                mbps = 8.0f * (float) r.bytes[0] / 1000000.0f;
                print(String.Format("{0} {1} {2}\n", TS.sec(r.ts), mbps,
                            r.pkts[0]));
                break;
            case "mbps":
                mbps = 8.0f * (float) r.bytes[0] / 1000000.0f;
                print(String.Format("{0} {1} {2}\n", TS.sec(r.ts), mbps,
                            r.pkts[0]));
                print("rec, mbps\n");
                break;
            }
        }
    }
} // namespace
