namespace CoMo.Modules.trafficCCS
{
    using System;

    public class Export : CoMo.Mdl, CoMo.IExport
    {

        public void init()
        {
            Console.WriteLine("ex_init");
            Console.WriteLine("name: " + name);
            Console.WriteLine("flush_ivl: " + flush_ivl);
            Console.WriteLine(config.ToString());
        }
        
        public void export(object[] tuples, ulong ivl_start)
        {
            foreach(TrafficTuple t in tuples) {
                Console.WriteLine("RECORD:");
                Console.WriteLine("ts = " + t.ts.ToString());
                Console.WriteLine("bytes = " + t.bytes[0].ToString());
                store_rec(t);
            }
        }
    }
} // namespace

