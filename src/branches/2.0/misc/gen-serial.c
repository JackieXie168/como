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

#define _GNU_SOURCE
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
gen_serialization_skel_scalar(FILE *out, field_t *f, char *op, char *sep,
        int unroll)
{
    fprintf(out, "\t%s%s_%s(x->%s)%s\n", sep, op, macro_particle(f->type),
            f->name, unroll ? "" : ";");
}

static void
gen_serialization_skel_unidim(FILE *out, field_t *f, char *op, char *sep,
        int unroll)
{
    if (unroll) {
        int a;
        for (a = 0; a < f->arrlen; a++)
            fprintf(out, "\t%s%s_%s(x->%s[%d])\n", sep, op,
                    macro_particle(f->type), f->name, a);

    } else {
        fprintf(out, "\tfor (it1 = 0; it1 < %d; it1++)\n"
                     "\t\t%s_%s(x->%s[it1]);\n",
                     f->arrlen, op, macro_particle(f->type), f->name);
    }
}


static void
gen_serialization_skel_bidim(FILE *out, field_t *f, char *op, char *sep,
        int unroll)
{
    if (unroll) {
        int a, b;
        for (a = 0; a < f->arrlen; a++)
            for (b = 0; b < f->arrlen2; b++)
                fprintf(out, "\t%s%s_%s(x->%s[%d][%d])\n", sep, op,
                        macro_particle(f->type), f->name, a, b);
    } else {
        fprintf(out, "\tfor (it1 = 0; it1 < %d; it1++)\n"
                "\t\tfor (it2 = 0; it2 < %d; it2++)\n"
                "\t\t\t%s_%s(x->%s[it1][it2]);\n",
                f->arrlen, f->arrlen2, op, macro_particle(f->type), f->name);

    }
}

/*
 * -- gen_serialization_skel
 *
 * Generate a skeleton to do operations on the fields of a struct. With that
 * and the help of some macros, we generate serialization, deserialization
 * and serialized_size functions of a struct.
 *
 * The caller can choose whether to generate an unrolled skeleton (useful
 * for serialized_size) or a rolled skeleton (with loops, generates more
 * compact code).
 *
 * Unrolled skeletons may contain a lot of code, so large array fields
 * will take a lot of code. In the case of serialized_size, though, most
 * of the code will be translated at compile time into a static value, plus
 * some strlen's. Not unrolling loops would most likely prevent the compiler
 * from pre-calculating that much. Some optimization could be made for the
 * case of serialized_size, but we choose to avoid code duplication.
 *
 * XXX beware likely performance hit on very large arrays of strings
 *
 */
static void
gen_serialization_skel(FILE *out, char *ret_type, char *first_statement,
        char *last_statement, struct_t *st, char *op, char *sep, int unroll)
{
    int i;

    fprintf(out, "static %s\n%s_%s(char **buffer, struct %s *x)\n{\n", ret_type,
            op, st->name, st->name);

    if (first_statement)
        fprintf(out, "\t%s\n", first_statement);

    if (! unroll) { /* not unrolling. if necessary, print iterators */
        int need_first = 0, need_second = 0;
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
    }

    sep = sep == NULL ? "" : sep;

    for (i = 0; i < st->n_fields; i++) {
        field_t *f = &st->fields[i];
        char is_char = !strcmp(f->type, "char");

        if (f->dim == 0 || (f->dim == 1 && is_char)) /* not an array */
            gen_serialization_skel_scalar(out, f, op, sep, unroll);

        else if (f->dim == 1 || (f->dim == 2 && is_char)) /* unidim array */
            gen_serialization_skel_unidim(out, f, op, sep, unroll);

        else if (f->dim == 2) /* bidimensional array */
            gen_serialization_skel_bidim(out, f, op, sep, unroll);

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
    gen_serialization_skel(out, "void", NULL, NULL, st, "serialize", NULL, 0);
    gen_serialization_skel(out, "void", NULL, NULL, st, "deserialize", NULL, 0);
    gen_serialization_skel(out, "int", "return 0", ";", st, "sersize", "+", 1);
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

