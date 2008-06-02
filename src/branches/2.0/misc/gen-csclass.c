/* 
 * Copyright (c) 2006, Intel Corporation 
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
#include <err.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h> /* asprintf */

#include "structmagic.h"

/*
 * Code to translate structs into C# classes.
 */
static void
print_type(FILE *out, field_t *f)
{
    int real_dim = f->dim;
    char *cstype;

    if (!strcmp(f->type, "char"))
        real_dim--;

    lookup_type_info(f->type, NULL, &cstype, NULL);
    if (cstype == NULL)
        errx(1, "type '%s' cannot be translated into c#", f->type);

    fprintf(out, "%s%s%s", cstype, real_dim ? "[]" : "",
        real_dim == 2 ? "[]" : "");
}

static void
gen_csharp_sersize_scalar(FILE *out, field_t *f, size_t *fixed_len)
{
    size_t s;

    lookup_type_info(f->type, &s, NULL, NULL);
    if (s == 0) { /* string */
        *fixed_len += 4;
        fprintf(out, "\t\tlen += this.%s.Length;\n", f->name);
    }
    else
        *fixed_len += s;
}

static void
gen_csharp_sersize_arr1(FILE *out, field_t *f, size_t *fixed_len)
{
    size_t s;

    lookup_type_info(f->type, &s, NULL, NULL);
    if (s != 0)
        *fixed_len += s * f->arrlen;
    else {
        *fixed_len += 4 * f->arrlen;
        fprintf(out, "\t\tfor(int i = 0; i < %d; i++)\n", f->arrlen);
        fprintf(out, "\t\t\tlen += this.%s[i].Length;\n", f->name);
    }
}

static void
gen_csharp_sersize_arr2(FILE *out, field_t *f, size_t *fixed_len)
{
    size_t s;

    lookup_type_info(f->type, &s, NULL, NULL);
    if (s != 0)
        *fixed_len += s * f->arrlen * f->arrlen2;
    else {
        *fixed_len += 4 * f->arrlen * f->arrlen2;
        fprintf(out, "\t\tfor(int i = 0; i < %d; i++)\n", f->arrlen);
        fprintf(out, "\t\t\tfor(int j = 0; j < %d; j++)\n", f->arrlen2);
        fprintf(out, "\t\t\t\tlen += this.%s[i][j].Length;\n", f->name);
    }
}

static void
gen_csharp_sersize(FILE *out, struct_t *st)
{
    int i;
    size_t fixed = 0;

    fprintf(out, "\tpublic override int sersize()\n\t{\n");
    fprintf(out, "\t\tint len = 0;\n");
    for (i = 0; i < st->n_fields; i++) {
        field_t *f = &st->fields[i];
        int realdim = (!strcmp(f->type, "char")) ? f->dim - 1: f->dim;
        switch(realdim) {
        case 0: gen_csharp_sersize_scalar(out, f, &fixed); break;
        case 1: gen_csharp_sersize_arr1(out, f, &fixed); break;
        case 2: gen_csharp_sersize_arr2(out, f, &fixed); break;
        }
    }
    fprintf(out, "\t\treturn len + %d;\n", fixed);
    fprintf(out, "\t}\n");
}

static void
gen_csharp_serial_aux(FILE *out)
{
    /* serialization aux functions */
    fprintf(out, "\tprotected void serialize_val8(byte[] array, ref int pos, ");
    fprintf(out,    "ulong val)\n\t{\n");
    fprintf(out, "\t\tarray[pos++] = (byte)(val     & 0xff);\n");
    fprintf(out, "\t\tarray[pos++] = (byte)(val>> 8 & 0xff);\n");
    fprintf(out, "\t\tarray[pos++] = (byte)(val>>16 & 0xff);\n");
    fprintf(out, "\t\tarray[pos++] = (byte)(val>>24 & 0xff);\n");
    fprintf(out, "\t\tarray[pos++] = (byte)(val>>32 & 0xff);\n");
    fprintf(out, "\t\tarray[pos++] = (byte)(val>>40 & 0xff);\n");
    fprintf(out, "\t\tarray[pos++] = (byte)(val>>48 & 0xff);\n");
    fprintf(out, "\t\tarray[pos++] = (byte)(val>>56 & 0xff);\n");
    fprintf(out, "\t}\n");

    fprintf(out, "\tprotected void serialize_val4(byte[] array, ref int pos, ");
    fprintf(out,    "uint val)\n\t{\n");
    fprintf(out, "\t\tarray[pos++] = (byte)(val     & 0xff);\n");
    fprintf(out, "\t\tarray[pos++] = (byte)(val>> 8 & 0xff);\n");
    fprintf(out, "\t\tarray[pos++] = (byte)(val>>16 & 0xff);\n");
    fprintf(out, "\t\tarray[pos++] = (byte)(val>>24 & 0xff);\n");
    fprintf(out, "\t}\n");

    fprintf(out, "\tprotected void serialize_val2(byte[] array, ref int pos, ");
    fprintf(out,    "ushort val)\n\t{\n");
    fprintf(out, "\t\tarray[pos++] = (byte)(val    & 0xff);\n");
    fprintf(out, "\t\tarray[pos++] = (byte)(val>>8 & 0xff);\n");
    fprintf(out, "\t}\n");

    fprintf(out, "\tprotected void serialize_val1(byte[] array, ref int pos, ");
    fprintf(out,    "byte val)\n\t{\n");
    fprintf(out, "\t\tarray[pos++] = (val);\n");
    fprintf(out, "\t}\n");

    fprintf(out, "\tprotected void serialize_string(byte[] array, ref int pos, "
                "string str)\n\t{\n");
    fprintf(out, "\t\tbyte[] serstr = System.Text.Encoding.ASCII.GetBytes(str);\n");
    fprintf(out, "\t\tint len = serstr.Length;\n");
    //fprintf(out, "\t\tint i;\n");
    fprintf(out, "\t\tserialize_val4(array, ref pos, (uint)len);\n");
    fprintf(out, "\t\tfor (int i = 0; i < len; i++)\n");
    //fprintf(out, "\t\t\tarray[pos++] = (byte)str[i];\n");
    fprintf(out, "\t\t\tarray[pos++] = serstr[i];\n");
    fprintf(out, "\t}\n");

    /* deserialization */
    fprintf(out, "\tprotected ulong deserialize_val8(byte[] array, ref int pos)\n");
    fprintf(out, "\t{\n");
    fprintf(out, "\t\tulong val = array[pos+7];\n");
    fprintf(out, "\t\tval = (val << 8) | array[pos+6];\n");
    fprintf(out, "\t\tval = (val << 8) | array[pos+5];\n");
    fprintf(out, "\t\tval = (val << 8) | array[pos+4];\n");
    fprintf(out, "\t\tval = (val << 8) | array[pos+3];\n");
    fprintf(out, "\t\tval = (val << 8) | array[pos+2];\n");
    fprintf(out, "\t\tval = (val << 8) | array[pos+1];\n");
    fprintf(out, "\t\tval = (val << 8) | array[pos+0];\n");
    fprintf(out, "\t\tpos += 8;\n");
    fprintf(out, "\t\treturn val;\n");
    fprintf(out, "\t}\n");

    fprintf(out, "\tprotected uint deserialize_val4(byte[] array, ref int pos)\n");
    fprintf(out, "\t{\n");
    fprintf(out, "\t\tuint val = array[pos+3];\n");
    fprintf(out, "\t\tval = (val << 8) | array[pos+2];\n");
    fprintf(out, "\t\tval = (val << 8) | array[pos+1];\n");
    fprintf(out, "\t\tval = (val << 8) | array[pos+0];\n");
    fprintf(out, "\t\tpos += 4;\n");
    fprintf(out, "\t\treturn val;\n");
    fprintf(out, "\t}\n");

    fprintf(out, "\tprotected ushort deserialize_val2(byte[] array, ref int pos)\n");
    fprintf(out, "\t{\n");
    fprintf(out, "\t\tushort val = (ushort)array[pos+1];\n");
    fprintf(out, "\t\tval = (ushort)((val << 8) | (ushort)array[pos+0]);\n");
    fprintf(out, "\t\tpos += 2;\n");
    fprintf(out, "\t\treturn val;\n");
    fprintf(out, "\t}\n");

    fprintf(out, "\tprotected byte deserialize_val1(byte[] array, ref int pos)\n");
    fprintf(out, "\t{\n");
    fprintf(out, "\t\tbyte val = array[pos++];\n");
    fprintf(out, "\t\treturn val;\n");
    fprintf(out, "\t}\n");

    fprintf(out, "\tprotected string deserialize_string(byte[] array, ref int pos)\n");
    fprintf(out, "\t{\n");
    fprintf(out, "\t\tint len = (int)deserialize_val4(array, ref pos);\n");
    fprintf(out, "\t\tstring val = System.Text.Encoding.ASCII.GetString(array, pos, len);\n");
    /*fprintf(out, "\t\tstring val = \"\";\n");
    fprintf(out, "\t\tfor (int i = 0; i < len; i++)\n");
    fprintf(out, "\t\t\tval += array[pos++];\n");*/
    fprintf(out, "\t\tpos += len;\n");
    fprintf(out, "\t\treturn val;\n");
    fprintf(out, "\t}\n");
}

static void
gen_csharp_serialize(FILE *out, struct_t *st)
{
    int i;

    fprintf(out, "\tpublic override int serialize(byte[] array, int pos)\n\t{\n");
    for (i = 0; i < st->n_fields; i++) {
        field_t *f = &st->fields[i];
        size_t s;
        int use_strings = !strcmp(f->type, "char") || !strcmp(f->type, "char *");
        int realdim = (!strcmp(f->type, "char")) ? f->dim - 1: f->dim;
        char *casts[9];
        casts[1] = "byte";
        casts[2] = "ushort";
        casts[4] = "uint";
        casts[8] = "ulong";
        lookup_type_info(f->type, &s, NULL, NULL);

        switch(realdim) {
        case 0:
            if (use_strings)
                fprintf(out, "\t\tserialize_string(array, ref pos, "
                        "this.%s);\n", f->name);
            else
                fprintf(out, "\t\tserialize_val%d(array, ref pos, "
                        "(%s)this.%s);\n", s, casts[s], f->name);
            break;
        case 1:
            fprintf(out, "\t\tfor(int i = 0; i < %d; i++)\n", f->arrlen);
            if (use_strings)
                fprintf(out, "\t\t\tserialize_string(array, ref pos, "
                                    "this.%s[i]);\n", f->name);
            else
                fprintf(out, "\t\t\tserialize_val%d(array, ref pos, "
                        "(%s)this.%s[i]);\n", s, casts[s], f->name);
            break; 
        case 2:
            fprintf(out, "\t\tfor(int i = 0; i < %d; i++)\n", f->arrlen);
            fprintf(out, "\t\t\tfor(int j = 0; j < %d; j++)\n", f->arrlen2);
            if (use_strings)
                fprintf(out, "\t\t\t\tserialize_string(array, ref pos, "
                                    "this.%s[i][j]);\n", f->name);
            else
                fprintf(out, "\t\t\t\tserialize_val%d(array, ref pos, "
                        "(%s)this.%s[i][j]);\n", s, casts[s], f->name);
            break; 
        }
    }
    fprintf(out, "\t\treturn pos;\n");
    fprintf(out, "\t}\n");
}

static void
gen_csharp_deserialize(FILE *out, struct_t *st)
{
    int i;

    fprintf(out, "\tpublic override int deserialize(byte[] array, int pos)\n\t{\n");
    for (i = 0; i < st->n_fields; i++) {
        field_t *f = &st->fields[i];
        size_t s;
        int use_strings = !strcmp(f->type, "char") || !strcmp(f->type, "char *");
        int realdim = (!strcmp(f->type, "char")) ? f->dim - 1: f->dim;
        char *monoclass;
        lookup_type_info(f->type, &s, &monoclass, NULL);

        switch(realdim) {
        case 0:
            if (use_strings)
                fprintf(out, "\t\tthis.%s = deserialize_string(array, "
                        "ref pos);\n", f->name);
            else
                fprintf(out, "\t\tthis.%s = (%s)deserialize_val%d(array, "
                        "ref pos);\n", f->name, monoclass, s);
            break;
        case 1:
            fprintf(out, "\t\tthis.%s = new %s[%d];\n", f->name, monoclass, f->arrlen);
            fprintf(out, "\t\tfor(int i = 0; i < %d; i++)\n", f->arrlen);
            if (use_strings)
                fprintf(out, "\t\t\tthis.%s[i] = "
                        "deserialize_string(array, ref pos);\n",
                        f->name);
            else
                fprintf(out, "\t\t\tthis.%s[i] = (%s)"
                        "deserialize_val%d(array, ref pos);\n",
                        f->name, monoclass, s);
            break; 
        case 2:
            fprintf(out, "\t\tthis.%s = new %s[%d][];\n", f->name, monoclass, f->arrlen);
            fprintf(out, "\t\tfor(int i = 0; i < %d; i++) { \n", f->arrlen);
            fprintf(out, "\t\tthis.%s[i] = new %s[%d];\n", f->name, monoclass, f->arrlen2);
            fprintf(out, "\t\t\tfor(int j = 0; j < %d; j++)\n", f->arrlen2);
            if (use_strings)
                fprintf(out, "\t\t\t\tthis.%s[i][j] = "
                        "deserialize_string(array, ref pos);\n",
                        f->name);
            else
                fprintf(out, "\t\t\t\tthis.%s[i][j] = (%s)"
                        "deserialize_val%d(array, ref pos);\n",
                        f->name, monoclass, s);
            fprintf(out, "\t\t}\n");
            break; 
        }
    }
    fprintf(out, "\t\treturn pos;\n");
    fprintf(out, "\t}\n");
}

static void
gen_csharp_ctor(FILE *out, struct_t *st, char *name)
{
    int i;

    fprintf(out, "\tpublic %s(", name);
    for (i = 0; i < st->n_fields; i++) {
        field_t *f = &st->fields[i];
        if (i != 0)
            fprintf(out, ", ");
        print_type(out, f);
        fprintf(out, " %s", f->name);
    }
    fprintf(out, ")\n\t{\n");
    for (i = 0; i < st->n_fields; i++) {
        field_t *f = &st->fields[i];
        fprintf(out, "\t\tthis.%s = %s;\n", f->name, f->name);
    }
    fprintf(out, "\t}\n");

    fprintf(out, "\tpublic %s() { }\n", name);
}

void
gen_csharp_class_header(FILE *out, const char * module)
{
    fprintf(out, "/* generated file, do not edit */\n");
    fprintf(out, "namespace CoMo.Modules.%s {\n", module);
    fprintf(out, "using System;\n");
    fprintf(out, "using System.Runtime.InteropServices;\n\n");
}

void
gen_csharp_class_footer(FILE *out, const char * module)
{
    fprintf(out, "} // namespace CoMo.Modules.%s \n", module);
}

void
gen_csharp_class(FILE *out, struct_t *st)
{
    char *name = csharpize(st->name);
    int i;

    fprintf(out, "public class %s : CoMo.Record \n{\n", name);
    for (i = 0; i < st->n_fields; i++) {
        field_t *f = &st->fields[i];

        fprintf(out, "\tpublic ");
        print_type(out, f);
        fprintf(out, " %s;\n", f->name);
    }
    fprintf(out, "\n\n\t/* constructors */\n");
    gen_csharp_ctor(out, st, name);
    fprintf(out, "\n\n\t/* serialized length */\n");
    gen_csharp_sersize(out, st);
    fprintf(out, "\n\n\t/* serialization function */\n");
    gen_csharp_serialize(out, st);
    fprintf(out, "\n\n\t/* deserialization function */\n");
    gen_csharp_deserialize(out, st);

    fprintf(out, "\n\n\t/* functions auxiliary to serialization */\n");
    gen_csharp_serial_aux(out);

    fprintf(out, "}\n");
}


