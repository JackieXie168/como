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

typedef struct _field field_t;
struct _field {
    char *type;   /* type of the field */
    char *name;   /* field name */
    int  dim;     /* dimensions. 0 if not an array, 1 if unidim, 2 if bidim */
    int  arrlen;  /* if is an array, number of elements, otherwise 0 */
    int  arrlen2; /* if > 0, this is bidimensional array */
};


#define FLAG_TUPLE      1
#define FLAG_RECORD     2
#define FLAG_CONFIG     4

#define MAX_ITEMS 1024
typedef struct _struct struct_t;
struct _struct {
    int flags;
    char *name;
    int n_fields;
    field_t fields[MAX_ITEMS];
};

typedef struct _cstype_conv cstype_conv_t;
struct _cstype_conv {
    size_t sersize; /* size of the serialized type. 0 means variable  */
    char *ctype;    /* name of the type in C */
    char *cstype;   /* name of the type when monoized */
    char *class_lookup_fn; /* name of the function that gets the mono type */
};

/* grammar.y */
void parse(char *file);

/* structmagic.c */
char * csharpize(char *name);
void lookup_type_info(char *ctype, size_t *sersize, char **class, char **lookup);

/* gen-csclass.c */
void gen_csharp_class_header(FILE *out);
void gen_csharp_class(FILE *out, struct_t *st);

/* gen-csglue.c */
void gen_csharp_glue_header(FILE *out, char *input);
void gen_csharp_glue(FILE *out, char *mdl, struct_t *st);

/* gen-serial.c */
void gen_serialization_header(FILE *out, char *input);
void gen_serialization_funcs(FILE *out, struct_t *st);

