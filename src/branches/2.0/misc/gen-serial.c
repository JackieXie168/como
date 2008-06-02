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
 * -- macro_particle
 *
 * Get the trailing name for the serialize/deserialize_type
 * operations. Some types cannot be used directly in the name.
 * For example, 'uint32_t' can be used but 'char *' cannot.
 */
static char *
macro_particle(char *type)
{
    if (! strcmp(type, "char *") || ! strcmp(type, "char"))
        return "string";
    else return type;
}

/*
 * auxiliary functions for gen_serialization_skel (see below)
 */
static void
gen_serialization_skel_scalar(FILE *out, char *name, char *type, char *op,
        char *sep)
{
    char *particle = macro_particle(type);
    char *param1 = "buffer, ";
    char *param3 = "";
    char *accessor = "";

    if (! strcmp(op, "sersize"))
        param1 = "";
    else {
        if (! strcmp(op, "deserialize")) {
            accessor = "&";
            if (! strcmp(particle, "string"))
                param3 = ", alloc";
        }
    }
    
    fprintf(out, "\t%s%s_%s(%s%sx->%s%s);\n", sep, op,
            macro_particle(type), param1, accessor, name, param3);
}

static void
gen_serialization_skel_unidim(FILE *out, field_t *f, char *op, char *sep)
{
    char name[1024];

    sprintf(name, "%s[it1]", f->name);
    fprintf(out, "\tfor (it1 = 0; it1 < %d; it1++)\n\t", f->arrlen);
    gen_serialization_skel_scalar(out, name, f->type, op, sep);
}


static void
gen_serialization_skel_bidim(FILE *out, field_t *f, char *op, char *sep)
{
    char name[1024];

    sprintf(name, "%s[a][b]", f->name);
    fprintf(out, "\tfor (it1 = 0; it1 < %d; it1++)\n"
            "\t\tfor (it2 = 0; it2 < %d; it2++)\n\t\t\t",
            f->arrlen, f->arrlen2);
    gen_serialization_skel_scalar(out, name, f->type, op, sep);
}

/*
 * -- gen_serialization_skel
 *
 * Generate a skeleton to do operations on the fields of a struct. With that
 * and the help of some macros, we generate serialization, deserialization
 * and serialized_size functions of a struct.
 *
 * XXX beware likely performance hit on very large arrays of strings
 *
 */
static void
gen_serialization_skel(FILE *out, struct_t *st, char *op)
{
    int i, need_first, need_second;

    char *ret_type = "void";
    char *first_param = "char **buffer, ";
    char *first_statement = "";
    char *last_statement = "";
    char *third_param = "";
    char *sep = "";

    if (! strcmp(op, "deserialize")) { /* particularities of operations */
        third_param = ", alc_t *alloc";
        asprintf(&first_statement, "struct %s *x = alc_new(alloc, struct %s); ",
        	st->name, st->name);
        last_statement = "*_x = x;\n";
    }
    else if (!strcmp(op, "sersize")) {
        first_param = "";
        ret_type = "int";
        sep = "value += ";
        first_statement = "int value = 0;";
        last_statement = "return value;";
    }

    fprintf(out, "%s\n%s_%s(%sstruct %s *%sx%s)\n{\n",
        ret_type, op, st->name, first_param, st->name,
        strcmp(op, "deserialize") == 0 ? "*_" : "",
        third_param);

    if (first_statement)
        fprintf(out, "\t%s\n", first_statement);

    /* if necessary, print iterators */
    for (i = 0; i < st->n_fields; i++) {
        field_t *f = &st->fields[i];
        int ndim = f->dim;
        if (!strcmp(f->type, "char"))
            ndim--;
        if (ndim > 0)
            need_first = 1;
        if (ndim == 2) {
            need_second = 1;
            break;
        }
    }
    if (need_first)
        fprintf(out, "\tint it1;\n");
    if (need_second)
        fprintf(out, "\tint it2;\n");
    if (need_first || need_second)
        fprintf(out, "\n");

    sep = sep == NULL ? "" : sep;

    for (i = 0; i < st->n_fields; i++) {
        field_t *f = &st->fields[i];
        char is_char = !strcmp(f->type, "char");

        if (f->dim == 0 || (f->dim == 1 && is_char)) /* not an array */
            gen_serialization_skel_scalar(out, f->name, f->type, op, sep);

        else if (f->dim == 1 || (f->dim == 2 && is_char)) /* unidim array */
            gen_serialization_skel_unidim(out, f, op, sep);

        else if (f->dim == 2) /* bidimensional array */
            gen_serialization_skel_bidim(out, f, op, sep);

        else /* !? */
            errx(1, "Hit a bug. Please contact CoMo developers.");
    }
    if (last_statement)
        fprintf(out, "\t%s\n", last_statement);
    fprintf(out, "}\n\n");
}

/*
 * -- gen_serialization_header
 *
 * Print all the includes and headers for the generated serialization
 * functions.
 */
void
gen_serialization_header(FILE *out, char *structdef)
{
    fprintf(out, "#include \"serialize.h\"\n\n");
    fprintf(out, "#include \"%s\"\n\n", structdef);
}

/*
 * -- gen_serialization_funcs
 *
 * Use gen_serialization_skel to generate both the
 * serialization and deserialization functions.
 */
void
gen_serialization_funcs(FILE *out, struct_t *st)
{
    gen_serialization_skel(out, st, "serialize");
    gen_serialization_skel(out, st, "deserialize");
    gen_serialization_skel(out, st, "sersize");
    fprintf(out,"\n");
}

/*
 * -- gen_store_funcs
 *
 * generate store/load funcs. (TODO)
 */
__attribute__((__unused__)) static void
gen_store_funcs(__attribute__((__unused__)) struct_t *st)
{

}

