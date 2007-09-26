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
