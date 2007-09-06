namespace CoMo.Modules.trafficCCS
{
    using System;

    public class Export : CoMo.Mdl, CoMo.IExport
    {

        public void init()
        {

        }
        
        public void export(object[] tuples, ulong ivl_start)
        {
            foreach(TrafficTuple t in tuples)
                store_rec(t);
        }
    }
} // namespace

