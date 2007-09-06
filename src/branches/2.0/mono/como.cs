namespace CoMo
{

using System;
using System.Runtime.CompilerServices;
using System.Reflection;
using System.Collections;

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
    
    protected void print(string s)
    {
	// Internal call
	mdl_print(mdl, s);
    }
    
    protected void printf(string fmt, params object[] args)
    {
	// Internal call
	mdl_printf(mdl, fmt, args);
    }

    [MethodImplAttribute(MethodImplOptions.InternalCall)]
    extern static private void mdl_store_rec(IntPtr mdl, byte[] data);

    [MethodImplAttribute(MethodImplOptions.InternalCall)]
    extern static private void mdl_print(IntPtr mdl, string s);
    
    [MethodImplAttribute(MethodImplOptions.InternalCall)]
    extern static private void mdl_printf(IntPtr mdl, string fmt, params object[] args);

}


public interface IExport
{
    void init();
    void export(object[] tuples, ulong ivl_start);
}

public interface IQuery
{
    void init(string format, Hashtable args);
    void finish(string format);
    void print_rec(string format, Record r);
}

public class QueryFormat
{
    //int id;
    string name;
    string content_type;

    public QueryFormat(string name, string content_type)
    {
	this.name = name;
	this.content_type = content_type;
    }
    public string Name          { get { return name;         } }
    public string ContentType   { get { return content_type; } }
}

[AttributeUsage(AttributeTargets.Class, AllowMultiple = true)]
public class FormatAttribute : System.Attribute
{
    int id;
    string name;
    string content_type;
    
    public FormatAttribute(int id, string name, string content_type)
    {
	this.id = id;
	this.name = name;
	this.content_type = content_type;
    }
    
    public int Id
    {
	get
	{
	    return id;
	}
    }

    public string Name
    {
	get
	{
	    return name;
	}
	set
	{
	    name = value;
	}
    }

    public string ContentType
    {
	get
	{
	    return content_type;
	}
	set
	{
	    content_type = value;
	}
    }
}

public sealed class TS
{
    public static uint sec(ulong ts)
    {
	return (uint) (ts >> 32);
    }

    public static uint msec(ulong ts)
    {
	return (uint) ((((ts) & 0xffffffff) * 1000) >> 32);
    }

    public static uint usec(ulong ts)
    {
	return (uint) ((((ts) & 0xffffffff) * 1000000) >> 32);
    }

    public static ulong from_time(uint sec, uint usec)
    {
	return (((ulong) sec) << 32) + ((((ulong) usec) << 32) / 1000000);
    }

    public static float to_float(ulong ts)
    {
        return sec(ts) + (float)usec(ts)/1000000;
    }

    public static string to_string(ulong ts)
    {
        System.DateTime dt = new System.DateTime(1970, 1, 1, 0, 0, 0, 0);
        dt = dt.AddSeconds(TS.sec(ts));
        return String.Format("{0:r}", dt);
    }
}

public sealed class IP
{
    [MethodImplAttribute(MethodImplOptions.InternalCall)]
    extern static public string to_string(uint addr);
}

}
