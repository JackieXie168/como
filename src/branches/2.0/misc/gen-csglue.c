/* 
 * Copyright (c) 2004-2006, Intel Corporation 
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

extern struct_t *structs[];
extern cstype_conv_t cstypes[];

#define CREATE_ARRAY_CODE \
"/* macro to copy an array into a mono array */\n" \
"#define CREATE_ARRAY(where, arr, type, class, len) do { \\\n" \
"   int __i;                                             \\\n" \
"   where = mono_array_new(domain, class, len);          \\\n" \
"   for (__i = 0; __i < len; __i++)                      \\\n" \
"       mono_array_set(((MonoArray*)where), type, __i, arr[__i]); \\\n" \
"   } while(0)\n\n"

#define CREATE_ARRAY_OF_ARRAYS_CODE \
"#define CREATE_ARRAY_OF_ARRAYS(where, arr, type, class, len1, len2) do {\\\n" \
"   int __i, __j;                                              \\\n" \
"   where = mono_array_new(domain, class, len1);               \\\n" \
"   for (__i = 0; __i < len1; __i++) {                         \\\n" \
"       MonoArray *__ma = mono_array_new(domain, class, len2); \\\n" \
"       mono_array_set(((MonoArray*)where), MonoArray *, __i, __ma); \\\n" \
"       for (__j = 0; __j < len2; __j++)                       \\\n" \
"           mono_array_set(__ma, type, __j, arr[__i][__j]);    \\\n" \
"    }                                                         \\\n" \
"   } while(0)                                                   \n"

#define MONO_FROM_STRING_CODE \
"#define MONO_FROM_STRING(str) mono_string_new(domain, str)\n"

#define CREATE_STR_ARRAY_CODE \
"#define CREATE_STR_ARRAY(where, arr, class, len) do {              \\\n" \
"   int __i;                                                        \\\n" \
"   where = mono_array_new(domain, class, len);                     \\\n" \
"   for (__i = 0; __i < len; __i++)                                 \\\n" \
"       mono_array_set(((MonoArray*)where), MonoString *,           \\\n" \
"           __i, MONO_FROM_STRING(arr[__i]));                       \\\n" \
"   } while(0)\n"

#define CREATE_STR_ARRAY_OF_ARRAYS_CODE \
"#define CREATE_STR_ARRAY_OF_ARRAYS(where, arr, class, len1, len2) do {\\\n" \
"   int __i, __j;                                              \\\n" \
"   where = mono_array_new(domain, class, len1);               \\\n" \
"   for (__i = 0; __i < len1; __i++) {                         \\\n" \
"       MonoArray *__ma = mono_array_new(domain, class, len2); \\\n" \
"       mono_array_set(((MonoArray*)where), MonoArray *, __i, __ma); \\\n" \
"       for (__j = 0; __j < len2; __j++)                       \\\n" \
"           mono_array_set(__ma, MonoString *, __j,            \\\n" \
"                MONO_FROM_STRING(arr[__i][__j]));             \\\n" \
"    }                                                         \\\n" \
"   } while(0)                                                   \n"

#define TOMONO_FUNC                                                     \
    "static MonoObject *\n" \
    "STRUCT_TO_MONO(MonoDomain *domain, MonoImage *image, TYPE *ref)\n" \
    "{\n"                                                               \
    "    static MonoClass *klass;\n"                                    \
    "    MonoObject *object;\n"                                         \
    "    MonoMethod *ctor;\n"                                           \
    "    void *args[NARGS];\n"                                          \
    "\n"                                                                \
    "    if (klass == NULL) {\n"                                        \
    "        klass = mono_class_from_name "                             \
    "(image, \"CoMo.\" MODULE, NAME);\n"                                \
    "        if (klass == NULL)\n"                                      \
    "            errx(1, \"Can't find \" NAME \" in assembly %%s\",\n"  \
    "                    mono_image_get_filename(image));\n"            \
    "    }\n"                                                           \
    "\n"                                                                \
    "    object = mono_object_new(domain, klass);\n"                    \
    "    ctor = mono_class_get_method_from_name(klass, \".ctor\", %d);\n" \
    "    PREPARE_ARGS(args, ref);\n"                                    \
    "\n"                                                                \
    "    mono_runtime_invoke(ctor, object, args, NULL);\n"              \
    "\n"                                                                \
    "    return object;\n"                                              \
    "}\n\n"

/*
 * header for csharp glue files.
 */
void
gen_csharp_glue_header(FILE *out, char *input)
{
    fprintf(out, "/* generated code. don't edit manually. */\n\n"
                 "#include <mono/jit/jit.h>\n"
                 "#include <mono/metadata/object.h>\n"
                 "#include <mono/metadata/environment.h>\n"
                 "#include <mono/metadata/assembly.h>\n"
                 "#include <mono/metadata/debug-helpers.h>\n"
                 "#include <string.h>\n"
                 "#include <stdlib.h>\n\n"
                 "#include <stdint.h>\n\n"
                 "#define como_serializable\n"
                 "#define como_storable\n"
                 "#include \"%s\""
                 "\n%s\n"
                 "\n%s\n"
                 "\n%s\n"
                 "\n%s\n"
                 "\n%s\n",
                 input,
                 MONO_FROM_STRING_CODE,
                 CREATE_ARRAY_CODE,
                 CREATE_ARRAY_OF_ARRAYS_CODE,
                 CREATE_STR_ARRAY_CODE,
                 CREATE_STR_ARRAY_OF_ARRAYS_CODE);
}

/*
 * generate the glue for a given struct
 */
void
gen_csharp_glue(FILE *out, char *mdl, struct_t *st)
{
    int i;

    fprintf(out, "/* --- begin glue for %s --- */\n", st->name);
    fprintf(out, "#undef STRUCT_TO_MONO\n"
                 "#undef TYPE\n"
                 "#undef NAME\n"
                 "#undef MODULE\n"
                 "#undef NARGS\n"
                 "#undef PREPARE_ARGS\n\n");

    fprintf(out, "#define STRUCT_TO_MONO to_mono_%s\n", st->name);
    fprintf(out, "#define TYPE struct %s\n", st->name);
    fprintf(out, "#define NAME \"%s\"\n", csharpize(st->name));
    fprintf(out, "#define MODULE \"%s\"\n", mdl);
    fprintf(out, "#define NARGS %d\n\n", st->n_fields);

    fprintf(out, "#define PREPARE_ARGS(v, ref) do {\t\\\n");

    for (i = 0; i < st->n_fields; i++) {
        field_t *f = &st->fields[i];
        char is_char = !strcmp(f->type, "char");
        char is_charptr = !strcmp(f->type, "char *");
        char *lookup;

        lookup_type_info(f->type, NULL, NULL, &lookup);

        /* not an array, not a char pointer */
        if (f->dim == 0 && !is_charptr)
            fprintf(out, "\tv[%d] = &ref->%s;\t\\\n", i, f->name);

        /* unidimensional array of non chars and non-char-pointers */
        else if (f->dim == 1 && !is_charptr && !is_char) {
            fprintf(out, "\tCREATE_ARRAY(v[%d], ref->%s, ", i, f->name);
            fprintf(out, "%s, %s(), %d);\t\\\n", f->type, lookup, f->arrlen);
        }
        /* bidimensional array of non chars and non-char-pointers */
        else if (f->dim == 2 && !is_charptr && !is_char) {
            fprintf(out, "\tCREATE_ARRAY_OF_ARRAYS(v[%d],ref->%s,", i, f->name);
            fprintf(out, "%s,%s(),%d,%d);\t\\\n", f->type, lookup, f->arrlen,
                f->arrlen2);
        }
        /* a char pointer or a unidim array of chars */
        else if (f->dim == 0 || (f->dim == 1 && is_char))
            fprintf(out, "\tv[%d] = MONO_FROM_STRING(ref->%s);\t\\\n", i,
                f->name);

        /* an array of char pointers or bidim array of chars */
        else if ((f->dim == 1 && is_charptr) || (f->dim == 2 && is_char)) {
            fprintf(out, "\tCREATE_STR_ARRAY(v[%d], ref->%s, ", i, f->name);
            fprintf(out, "%s(), %d);\t\\\n", lookup, f->arrlen);
        }

        /* a bidimensional array of char pointers */
        else if (f->dim == 2 && is_charptr) {
            fprintf(out, "\tCREATE_STR_ARRAY_OF_ARRAYS(v[%d],ref->%s,", i,
                f->name);
            fprintf(out, "%s(),%d,%d);\t\\\n", lookup, f->arrlen,
                f->arrlen2);
        }
        else /* !? */
            errx(1, "You hit a bug. Please contact CoMo developers.");
    }

    fprintf(out, "} while(0)\n\n\n");
    fprintf(out, TOMONO_FUNC, st->n_fields);
    fprintf(out, "/* --- end glue for %s --- */\n\n\n", st->name);
}

