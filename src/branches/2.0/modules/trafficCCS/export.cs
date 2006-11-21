namespace CoMo.Modules.trafficCCS
{

using System;

public class Export : CoMo.Mdl, CoMo.IExport
{

    public void ex_init()
    {
	Console.WriteLine("ex_init");
    }
    
    public void export(object[] tuples, ulong ivl_start)
    {
	Console.WriteLine("export");
    }

}


} // namespace
