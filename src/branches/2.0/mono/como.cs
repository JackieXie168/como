namespace CoMo
{

using System;
using System.Runtime.CompilerServices;

public abstract class Record
{
    public abstract int sersize();
    public abstract int serialize(byte[] array, int pos);
    public abstract int deserialize(byte[] array, int pos);
}

public class Mdl
{
    private IntPtr mdl;

    protected ulong flush_ivl;
    protected string name;
    protected string description;
    protected string filter;
    protected string mdlname;
    protected ulong streamsize;
    protected object config;

    public Mdl()
    {
    }


    protected void store_rec(Record rec)
    {
	byte[] data;
	int pos;
	int size;
	
	size = rec.sersize();
	data = new byte[size];
	pos = rec.serialize(data, 0);
	if (size != pos) {
	    Console.WriteLine("ERROR: size != pos: " + size + " != " + pos);
	}
	
	// Internal call mdl_store_rec!
	mdl_store_rec(mdl, data);
    }

    [MethodImplAttribute(MethodImplOptions.InternalCall)]
    extern static void mdl_store_rec(IntPtr mdl, byte[] data);
}

public interface IExport
{
    void ex_init();
    void export(object[] tuples, ulong ivl_start);
}

}
