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
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define _GNU_SOURCE
#include <stdio.h> /* asprintf */

#include "structmagic.h"

extern struct_t *structs[];

/*
 * information about types
 */
cstype_conv_t cstypes[] = {
    { sizeof(uint64_t), "timestamp_t", "ulong",  "mono_get_uint64_class" },
    { sizeof(uint64_t), "uint64_t",    "ulong",  "mono_get_uint64_class" },
    { sizeof(uint32_t), "uint32_t",    "uint",   "mono_get_uint32_class" },
    { sizeof(uint16_t), "uint16_t",    "ushort", "mono_get_uint16_class" },
    { sizeof(int64_t),  "int64_t",     "long",   "mono_get_int64_class" },
    { sizeof(int32_t),  "int32_t",     "int",    "mono_get_int32_class" },
    { sizeof(int16_t),  "int16_t",     "short",  "mono_get_int16_class" },
    { sizeof(uint8_t),  "uint8_t",     "byte",   "mono_get_byte_class" },
    { sizeof(int8_t),   "int8_t",      "sbyte",  "mono_get_sbyte_class" },
    { sizeof(int),      "int",         "int",    "mono_get_int32_class" },

    /* char pointers will be interpreted as strings */
    { 0,                "char *",      "string", "mono_get_string_class" },

    /* chars are only accepted as unidimensional arrays (which represent
     * strings of a max fixed size) or bidimensional arrays (which then
     * represent arrays of fixed size strings)
     */
    { 0,                "char",        "string", "mono_get_string_class" },

    { 0, NULL, NULL, NULL } /* terminator */
};


/*
 * -- lookup_type_info
 *
 * Lookup information related to a ctype. Outputs the result
 * in the passed pointers (NULL pointers can be passed when
 * caller is not interested in some output values).
 */
void
lookup_type_info(char *ctype, size_t *sersize, char **class, char **lookup)
{
    cstype_conv_t *t;
    for (t = cstypes; t->ctype != NULL; t++)
        if (! strcmp(t->ctype, ctype))
            break;

    if (sersize != NULL)
        *sersize = t->sersize;
    if (class != NULL)
        *class = t->cstype;
    if (lookup != NULL)
        *lookup = t->class_lookup_fn;
}

/*
 * -- csharpize
 *
 * Return a C#'ish name for a struct name.
 */
char *
csharpize(char *name)
{
    static char buffer[1024], *str;
    int capitalize;
    if (strlen(name) >= 1024)
        errx(1, "class name '%s' too long\n", name);

    capitalize = 1;
    str = buffer;

    while (*name != '\0') {
        if (*name != '_') {
            *str = capitalize ? toupper(*name) : *name;
            str++;
        }
        capitalize = ! isalpha(*name);
        name++;
    }

    return buffer;
}

__attribute__((__unused__)) static void
dump_struct(struct_t *s)
{
    int i;

    printf("struct %s {\n", s->name);
    for (i = 0; i < s->n_fields; i++) {
        field_t *it = &s->fields[i];
        printf("\t%s %s", it->type, it->name);
        if (it->dim != 0)
            printf("[%d]", it->arrlen);
        if (it->dim == 2)
            printf("[%d]", it->arrlen2);
        printf(";\n");
    }
    printf("}\n");
}

FILE *
safe_fopen(char *file, char *mode)
{
    FILE *f;
    char *strmode;

    if (!strcmp(mode, "r"))
        strmode = "reading";
    else if(!strcmp(mode, "w"))
        strmode = "writing";
    else
        strmode = "!?";

    f = fopen(file, mode);
    if (f == NULL)
        errx(1, "cannot open \"%s\" for %s\n", file, strmode);

    return f;
}

int
main(int argc, char **argv)
{
    char *command, *input, *cpp_output, *str, *module, *full_path_input;
    struct_t *st;
    int ret, i;
    FILE *csout, *glueout, *serialout, *tnout;

    if (argc < 3)
        errx(1, "usage: %s mdl_name input_file.h [incdir1 incdir2..]", argv[0]);

    module = argv[1];
    input = argv[2];

    ret = asprintf(&cpp_output, "%s.cpp", input);
    if (ret < 0)
        err(1, "out of memory");

    /*
     * save a full path to input file
     */
    if (input[0] == '/')
        full_path_input = input;
    else
        asprintf(&full_path_input, "%s/%s", getcwd(NULL, 0), input);

    /*
     * run cpp on it to expand definitions/macros
     */
    ret = asprintf(&command, "cpp"); /* cpp .. */
    if (ret < 0)
        err(1, "out of memory");
    for (i = 3; i < argc ; i++) {    /* .. args .. */
        /* we don't care about mem leaks in successive asprintf's */
        ret = asprintf(&command, "%s -I %s", command, argv[i]);
        if (ret < 0)
            err(1, "out of memory");
    }
                                    /* .. input and output files */
    ret = asprintf(&command, "%s %s %s", command, input, cpp_output);
    if (ret < 0)
        err(1, "out of memory");

    ret = system(command); /* run cpp */
    if (ret < 0)
        err(1, "system() fails");
    if (WEXITSTATUS(ret) != 0)
        errx(1, "cpp failed to parse input file '%s' into '%s'", input,
                cpp_output);

    /*
     * parse cpp output to understand what the relevant structs are
     */
    parse(cpp_output);

    /*
     * generate serialization functions
     */
    str = strdup(input); /* chdir into module directory */
    if (strrchr(str, '/')) {
        *(strrchr(str, '/')) = '\0';
        chdir(str);
    }
    free(str);

    asprintf(&str, "%s/gen-class.cs", getcwd(NULL, 0));
    csout = safe_fopen(str, "w");
    free(str);

    asprintf(&str, "%s/gen-csglue.c", getcwd(NULL, 0));
    glueout = safe_fopen(str, "w");
    free(str);

    asprintf(&str, "%s/gen-serial.c", getcwd(NULL, 0));
    serialout = safe_fopen(str, "w");
    free(str);

    asprintf(&str, "%s/gen-typenames.c", getcwd(NULL, 0));
    tnout = safe_fopen(str, "w");
    free(str);

    gen_csharp_class_header(csout);
    gen_csharp_glue_header(glueout, full_path_input);
    gen_serialization_header(serialout, full_path_input);
    
    for (i = 0, st = structs[0]; st != NULL; i++, st = structs[i]) {
        char *sep = "(";
        printf("Generating code for struct %s ", st->name);
        if (st->flags & FLAG_TUPLE) {
            fprintf(tnout, "char * tuple_type = \"%s\";\n", st->name);
            printf("%stuple", sep);
            sep = ", ";
        }
        if (st->flags & FLAG_RECORD) {
            fprintf(tnout, "char * record_type = \"%s\";\n", st->name);
            printf("%srecord", sep);
            sep = ", ";
        }
        if (st->flags & FLAG_CONFIG) {
            fprintf(tnout, "char * config_type = \"%s\";\n", st->name);
            printf("%sconfig", sep);
        }
        printf("):\n");
        gen_serialization_funcs(serialout, st);
        printf("\tSerialization functions\n");
        //if (st->storable) {
        //    gen_store_funcs(st);
        //    printf("\tStore/Load functions");
        //}

        gen_csharp_class(csout, st);
        printf("\tC# class\n");
        gen_csharp_glue(glueout, module, st);
        printf("\tC to mono glue\n");
        printf("ok\n");
    }

    ret = unlink(cpp_output);
    if (ret != 0)
        warn("cannot unlink %s", cpp_output);
    exit(0);
}

