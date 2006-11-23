namespace CoMo.Modules.trafficCCS
{

using System;
using System.Collections;

enum FORMATS
{
    PRETTY,
    PLAIN,
    MBPS,
    GNUPLOT
}

[Format(FORMATS.PRETTY, "pretty", "text/plain")]
[Format(FORMATS.PLAIN, "pretty", "text/plain")]
[Format(FORMATS.MBPS, "pretty", "text/plain")]
[Format(FORMATS.GNUPLOT, "pretty", "text/plain")]
public class Query : CoMo.Mdl, CoMo.IQuery
{
    static const string GNUPLOTHDR = @"
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
""-"" using 1:3 axis x1y2 with lines lt 4";

    static const string PREETYHDR = "Date                     Timestamp          Bytes    Pkts\n";


    static const string GNUPLOTFOOTER =	"e\n";

    static const string PRETTYFMT =	"%.24s %12d.%06d %8llu %8u\n";
    static const string PLAINFMT =	"%12ld %16llu %12llu %12u\n";
    static const string MBPSFMT =	"%4.2f Mbps\n";
    static const string GNUPLOTFMT =	"%ld %f %u\n";


    public void init(int format_id, Hashtable args)
    {
	Console.WriteLine("qu_init");
	Console.WriteLine("name: " + name);
	Console.WriteLine("flush_ivl: " + flush_ivl);
	Console.WriteLine(config.ToString());

	switch (format_id) {
	    case FORMATS.GNUPLOT:
		print(GNUPLOTHDR);
	    case FORMATS.PRETTY:
		print(PRETTYHDR);
	}
    }
    
    public void finish(int format_id)
    {
	if (format_id == FORMATS.GNUPLOT) {
	    print(GNUPLOTFMT);
	}
    }

    public void print_rec(int format_id, Record r)
    {
	float mbps;
    
	switch (format_id) {
	case FORMATS.PRETTY:
	    t = TS.sec(r.ts);
	    printf(PRETTYFMT, 
	            "", TS.sec(r.ts), TS.usec(r.ts), 
		    r.bytes[0], r.pkts[0]); 
	case FORMATS.PLAIN:
	    printf(PLAINFMT, TS.sec(r.ts), r.ts, r.bytes[0], r.pkts[0]);
	case FORMATS.GNUPLOT:
	    mbps = 8.0 * (float) r.bytes[0] / 1000000.0; 
	    printf(GNUPLOTFMT, TS.sec(r.ts), mbps, r.pkts[0]);
	case FORMATS.MBPS:
	    mbps = 8.0 * (float) r.bytes[0] / 1000000.0; 
	    printf(MBPSFMT, mbps, r.pkts[0]);
	}

    }

}


} // namespace
