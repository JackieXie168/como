/*
 * Copyright (c) 2004 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id$
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h> 	/* bcmp */
#include <ctype.h>  	/* isalnum */
#include <err.h>    	/* warnx, errx */
#include <dirent.h>	/* opendir */
#include <sys/types.h>	/* mkdir, opendir */
#include <sys/stat.h>	/* mkdir */

#include <errno.h>

#include "como.h"
#include "sniffers.h"
#include "filter.h"

/* global data structure that contains all
 * configuration information
 */
extern struct _como map;


/* get the sniffers list */
extern sniffer_t *__sniffers[];

/*
 * tokens used in the dictionary
 */
enum tokens {
    TOK_NULL=0,

    TOK_BASEDIR,
    TOK_BLOCK_SIZE,
    TOK_SOURCE,
    TOK_DESCRIPTION,
    TOK_END,
    TOK_FILTER,
    TOK_HASHSIZE,
    TOK_LIBRARYDIR,
    TOK_LOGFLAGS,
    TOK_MEMSIZE,
    TOK_MODULE,
    TOK_MODULE_MAX,
    TOK_OUTPUT,
    TOK_QUERYPORT,
    TOK_SNIFFER,
    TOK_STREAMSIZE,
    TOK_ARGS,
    TOK_MIN_FLUSH,
    TOK_MAX_FLUSH,
    TOK_NAME,   
    TOK_LOCATION,
    TOK_LINKSPEED,
    TOK_COMMENT,
    TOK_DROPFILE,
    TOK_DROPLOGSIZE
};


/*
 * in the configuration file there are different scopes, or contexts.
 * the scope of a configuration variable could be global (i.e., default
 * values that affect all objects), or related to a specific module.
 */
#define CTX_ANY         0xff
#define CTX_GLOBAL      0x01
#define CTX_MODULE      0x02

/*
 * this structure is a dictionary of symbols that can be
 * found in the configuration file.
 *
 * _keyword is a structure that stores a string <-> token pairs, used in
 * various places in the parser. Entries are stored in arrays,
 * with an entry with s=NULL as terminator.
 * The search routines are match_token() and match_value().
 * Often, an element with x=0 contains an error string.
 *
 */

struct _keyword {
    char const *str;    /* keyword */
    int action;         /* related token */
    int nargs;          /* arguments */
    int scope;          /* specific scope */
};

typedef struct _keyword keyword_t;

keyword_t keywords[] = {
    { "basedir",     TOK_BASEDIR,     2, CTX_GLOBAL},
    { "librarydir",  TOK_LIBRARYDIR,  2, CTX_GLOBAL},
    { "logflags",    TOK_LOGFLAGS,    2, CTX_GLOBAL},
    { "module",      TOK_MODULE,      2, CTX_GLOBAL},
    { "module-limit",TOK_MODULE_MAX,  2, CTX_GLOBAL},
    { "query-port",  TOK_QUERYPORT,   2, CTX_GLOBAL},
    { "sniffer",     TOK_SNIFFER,     3, CTX_GLOBAL},
    { "memsize",     TOK_MEMSIZE,     2, CTX_GLOBAL|CTX_MODULE},
    { "output",      TOK_OUTPUT,      2, CTX_MODULE},
    { "blocksize",   TOK_BLOCK_SIZE,  2, CTX_MODULE},
    { "hashsize",    TOK_HASHSIZE,    2, CTX_MODULE},
    { "source",      TOK_SOURCE,      2, CTX_MODULE},
    { "filter",      TOK_FILTER,      2, CTX_GLOBAL|CTX_MODULE},
    { "description", TOK_DESCRIPTION, 2, CTX_MODULE},
    { "end",         TOK_END,         1, CTX_MODULE},
    { "streamsize",  TOK_STREAMSIZE,  2, CTX_MODULE},
    { "args",        TOK_ARGS,        2, CTX_MODULE},
    { "min-flush",   TOK_MIN_FLUSH,   2, CTX_MODULE},
    { "max-flush",   TOK_MAX_FLUSH,   2, CTX_MODULE},
    { "name",        TOK_NAME,        2, CTX_GLOBAL},
    { "location",    TOK_LOCATION,    2, CTX_GLOBAL},
    { "linkspeed",   TOK_LINKSPEED,   2, CTX_GLOBAL},
    { "comment",     TOK_COMMENT,     2, CTX_GLOBAL},
    { "drop-log",    TOK_DROPFILE,    2, CTX_GLOBAL},
    { "drop-log-size",TOK_DROPLOGSIZE,2, CTX_GLOBAL},
    { NULL,          0,               0, 0 }    /* terminator */
};


/*
 * -- match_token
 *
 * takes the keywords table and a string and returns
 * the value associated with the string in the table.
 *
 */
static keyword_t *
match_token(char * string, keyword_t *table)
{
    keyword_t *pt;
    uint i = strlen(string);

    for (pt = table ; i && pt->str != NULL ; pt++)
        if (strlen(pt->str) == i && !bcmp(string, pt->str, i))
            return pt;
    return NULL;
}

struct _sl {
    const char *name;
    uint32_t	op;
    uint32_t	value;
};
#define LO_ADD		1
#define LO_DEL		2
#define LO_VERBOSE	4
/*
 * set flags according to the argument, which are a list of comma-separated
 * names with optional + and - to add and remove them.
 */
static uint32_t
set_flags(uint32_t flags, char *arg)
{
    static struct _sl the_flags[] = {
	{ "-",		LO_DEL,	0		},
	{ "+",		LO_ADD,	0		},
	{ "v-",		LO_VERBOSE, 0		},
	{ "verbose-",	LO_VERBOSE, 0		},
	{ "ui",		0,	LOGUI		},
	{ "warn",	0,	LOGWARN		},
	{ "mem",	0,	LOGMEM		},
	{ "conf",	0,	LOGCONFIG	},
	{ "ca",		0,	LOGCAPTURE	},
	{ "ex",		0,	LOGEXPORT	},
	{ "st",		0,	LOGSTORAGE	},
	{ "qu",		0,	LOGQUERY	},
	{ "sniff",	0,	LOGSNIFFER	},
	{ "debug",	0,	LOGDEBUG	},
	{ "all",	0,	LOGALL		},
	{ NULL,		0,	0		}
    };
    char *a;
    uint32_t op, f;

    for (a = arg, op = 0; *a;) {
	struct _sl *p;

	for (p = the_flags; p->name &&
		strncasecmp(p->name, a, strlen(p->name)); p++)
	    ;
	if (p->name == NULL) {	/* no match */
	    logmsg(LOGWARN, "invalid logflags at %s [%s]\n", a, arg);
	    break; 
	}
	a += strlen(p->name);
	if (p->op != 0) {	/* modifier */
	    switch (p->op) {
	    case LO_DEL:
		if ( op & LO_ADD )
		    panic("cannot both add and del %s\n", arg);
		break;
	    case LO_ADD:
		if ( op & LO_DEL )
		    panic("cannot both add and del %s\n", arg);
		break;
	    case LO_VERBOSE:
		if ( op & LO_VERBOSE )
		    panic("verbose specified twice %s\n", arg);
		break;
	    default:
		break;
	    }
	    op |= p->op;
	} else {
	    /* add or delete as required, then skip to separator */
	    f = p->value;
	    if (op & LO_VERBOSE)
		f |= (f << 16);
	    flags = (op & LO_DEL) ? flags & ~f : flags | f;
	    /* reset fields and skip separator */
	    op = 0;
	    while (*a && *a++ != ',')
		;
	}
    }
    return flags;
}

/**
 * -- add_char
 *
 * add a character to a buffer, reallocating it if necessary
 *
 */
static char *
add_char(char *buf, int c, uint *dst, uint *len)
{
    logmsg(V_LOGCONFIG, "add_char '%c' dst %d len %d\n", c, *dst, *len);
    if (*dst >= *len) {
        if (*len < 1024)
            *len = 2* *len + 512;
        else
            *len += 2048;
        buf = (buf == NULL) ? malloc(*len) : realloc(buf, *len);
        logmsg(V_LOGCONFIG, "realloc config buf dst %d len %d\n", *dst, *len);
        if (buf == NULL)
            panic("parse buffer realloc failed at size %d\n", *len);
    }
    buf[ (*dst)++ ] = (char)c;
    return buf;
}

/*
 * makes a malloc'ed copy of src into *dst, freeing the previous one if any
 */
static void
safe_dup(char **dst, char *src)
{
    if (*dst)
	free(*dst);
    *dst = strdup(src);
}

/*
 * Check the configuration of a module, supply default values,
 * and load/initialize whatever we need for the module to run.
 */
static int
check_module(module_t *mdl)
{
    int len;
    char *clname;
    callbacks_t *cb;

    if (mdl->filter == NULL)
	asprintf(&mdl->filter, "ALL");
    if (mdl->output == NULL)
	mdl->output = strdup(mdl->name);
    if (map.basedir && mdl->output[0] != '/') { /* prepend basedir */
	char *p = mdl->output;
	asprintf(&mdl->output, "%s/%s", map.basedir, p);
	free(p);
    }
    if (mdl->source == NULL)
	asprintf(&mdl->source, "%s.so", mdl->name);
    if (mdl->ex_hashsize == 0)
	panic("config: module %s needs a hash size\n", mdl->name);

    if (mdl->streamsize < 2 * map.maxfilesize) {
	mdl->streamsize = 2*map.maxfilesize; 
	logmsg(LOGWARN, 
	    "module %s streamsize too small. set to %dMB\n", 
	    mdl->name, mdl->streamsize/(1024*1024)); 
    } 

    /* load the library */
    if (!map.libdir || mdl->source[0] == '/')
	clname = strdup(mdl->source);
    else
	asprintf(&clname, "%s/%s", map.libdir, mdl->source);

    cb = load_object(clname, "callbacks");
    if (cb == NULL)
	panic("could not load library %s: %s\n", clname, strerror(errno)); 
    free(clname);

    /* store the callbacks */
    mdl->callbacks = *cb;
    /* perform some checks on the callbacks */

    /* update(), store() and load() should definitely be there */
    if (cb->update == NULL)
	panic("source: module %s misses update()\n", mdl->name);
    if (cb->store == NULL)
	panic("source: module %s misses store()\n", mdl->name);
    if (cb->load == NULL)
	panic("source: module %s misses load()\n", mdl->name);

    /* 
     * either both or none of action() and export() are required 
     */
    if (cb->export == NULL) {
	/*
	 * no export(), then we we don't want
	 * action(), ematch() and compare().
	 */
	if (cb->action || cb->ematch || cb->compare )
	    panic("source: module %s has %s%s%s without export()\n",
			mdl->name,
			cb->action ? "action() " : "",
			cb->ematch ? "ematch() " : "",
			cb->compare ? "compare() " : ""
		);

    } else {
	if (cb->action == NULL) /* export() requires action() too */
	    panic("source: module %s has export() w/out action()\n", 
		mdl->name);
    }

    mdl->ca_hashsize = mdl->ex_hashsize; 
    /* XXX we would like to make the capture hashsize adaptive. 
     *     in general it is going to be much smaller than the 
     *     one used in export. 
     */

    /* allocate hash table */
    len = sizeof(etable_t) + mdl->ex_hashsize * sizeof(void *);
    mdl->ex_hashtable = safe_calloc(1, len); 
    mdl->ex_hashtable->size = mdl->ex_hashsize; 

    /* allocate record array */
    len = sizeof(earray_t) + mdl->ex_hashsize * sizeof(void *);
    mdl->ex_array = safe_calloc(1, len); 
    mdl->ex_array->size = mdl->ex_hashsize; 

    /* allocate module's private memory, if any */
    if (mdl->msize)
	mdl->mem = safe_calloc(1, mdl->msize);

    /* initialize module */
    if (cb->init != NULL && cb->init(mdl->mem, mdl->msize, mdl->args) != 0)
	panic("could not initialize %s\n", mdl->name); 

    logmsg(LOGUI, "... loaded module \"%s\"\n", mdl->name); 
    if (mdl->description != NULL) 
	logmsg(LOGUI,"     Description: %s\n", mdl->description); 
    logmsg(LOGUI,"     Filter: %s\n", mdl->filter); 
    logmsg(LOGUI,"     Output: %s\n", mdl->output); 
    logmsg(LOGUI,"     Streamsize: %llu\n", mdl->streamsize); 

    mdl->status = MDL_ACTIVE; 
    return 1;
}

/*
 * -- add_sniffer 
 * 
 * given a string, locate the corresponding sniffer and set it.
 * The device can be given as a separate argument, or as a
 * colon-separated part of the name (this way it is compatible
 * with the command line).
 * Failures are not fatal.
 */
static void
add_sniffer(char *want, char *device, char *args)
{
    int i;
    size_t devlen = 0;

    if (device == NULL && args == NULL) {
	device = index(want, ':');
	if (device) {
	    device++; /* skip ':' */
            args = index(device, ':');
            if (args)
                args++;
            devlen = args - device - 1;
        }
    }
    
    if (!device) {
        logmsg(LOGWARN, "sniffer %s: no device specified, ignoring\n", want);
        return;
    }

    for (i = 0; __sniffers[i]; i++) {
	const char *name = __sniffers[i]->name;
	if (bcmp(want, name, strlen(name)) == 0) {
	    source_t *s = safe_calloc(1, sizeof(*s));

	    s->next = map.sources;
	    s->cb = __sniffers[i];
	    s->device = devlen ? strndup(device, devlen) : strdup(device);
	    s->args = args ? strdup(args) : NULL;
	    s->fd = -1;	/* still closed */
	    map.sources = s;
	    break;
	}
    }
    if (__sniffers[i] == NULL) {
	logmsg(LOGWARN, "sniffer %s %s not found, ignoring\n", want, device);
	return; 
    }

    logmsg(LOGUI, "... sniffer [%s] %s\n", 
	map.sources->cb->name, map.sources->device);
}

static module_t *
new_module(char *name)
{
    module_t * mdl; 

    mdl = &map.modules[map.module_count]; 
    mdl->index = map.module_count;
    mdl->name = strdup(name);
    mdl->status = MDL_UNUSED; 

    /* set some default values */
    mdl->max_flush_ivl = DEFAULT_MAXCAPTUREIVL;
    mdl->min_flush_ivl = DEFAULT_MINCAPTUREIVL;
    mdl->bsize = DEFAULT_BLOCKSIZE;
    mdl->streamsize = DEFAULT_STREAMSIZE; 
    mdl->ex_hashsize = mdl->ca_hashsize = 1; 
    mdl->args = NULL;

    map.module_count++;
    return mdl;
}


/* 
 * -- createdir
 * 
 * creates the basedir for CoMo output files. it generates the 
 * entire directory tree if necessary. 
 * 
 */
void 
createdir(char * basedir) 
{
    char curdir[1024];

    sprintf(curdir, basedir);
    while (mkdir(basedir, (mode_t) (S_IRWXU | S_IRWXG | S_IRWXO)) != 0) {
	if (errno == ENOENT) { 
	    /* 
	     * we can deal with this trying to create a directory one 
	     * level up from basedir. 
	     */
            panic("cannot create basedir %s", basedir);
	} else  
            panic("cannot create basedir %s", basedir);
    } 
}

static off_t
parse_size(const char *arg)
{
    char *ptr;
    off_t res;
    res = strtol(arg, &ptr, 10);
    if (ptr[0] == 'G')
	res *= 1024*1024*1024;
    else if (ptr[0] == 'M')
	res *= 1024*1024;
    else if (ptr[0] == 'K')
	res *= 1024;
    return res;
}


/*
 * -- do_config
 *
 * Do the actual configuration.
 * Expect each useful line to start with a keyword.
 *
 */
static void
do_config(int argc, char *argv[])
{
    static int scope = CTX_GLOBAL;      /* scope of current keyword */
    static module_t * mdl = NULL;       /* module currently open */
    keyword_t *t;
    int i;

    /*
     * run some checks on the token (i.e., that it exists
     * and that we have all the arguments it needs).
     */
    t = match_token(argv[0], keywords);
    if (t == NULL)
        panic("unknown token \"%s\"\n", argv[0]);

    if (argc < t->nargs)
        panic("\"%s\" requires at least %d arguments\n", argv[0], t->nargs);
    if (!(t->scope & scope))
        panic("\"%s\" out of scope\n", argv[0]);

    switch (t->action) {
    case TOK_BASEDIR:
	safe_dup(&map.basedir, argv[1]);
	break;

    case TOK_BLOCK_SIZE:
	mdl->bsize = atoi(argv[1]);
	break;

    case TOK_QUERYPORT:
	map.query_port = atoi(argv[1]);
	break;

    case TOK_DESCRIPTION:
	safe_dup(&mdl->description, argv[1]);
	break;

    case TOK_END:
        /*
         * "end" of a module configuration.  run some checks depending 
         * on context to make sure that all mandatory fields are there
         * and set default values
         */
	check_module(mdl);
	scope = CTX_GLOBAL;
        break;

    case TOK_FILTER:
	if (scope == CTX_MODULE) {
#ifdef HAVE_FLEX_AND_BISON
            char *s;
            parse_filter(argv[1], &s);
            safe_dup(&mdl->filter, s);
            free(s);
#else
            safe_dup(&mdl->filter, argv[1]);
#endif	
        } else if (scope == CTX_GLOBAL) {
	    safe_dup(&map.filter, argv[1]);
        }
	break;

    case TOK_HASHSIZE:
        mdl->ex_hashsize = atoi(argv[1]);
        break;

    case TOK_SOURCE:
	safe_dup(&mdl->source, argv[1]);
	break;

    case TOK_LIBRARYDIR:
        safe_dup(&map.libdir, argv[1]);
        break;

    case TOK_LOGFLAGS:
        map.logflags = set_flags(0, argv[1]);
        break;

    case TOK_MEMSIZE:
        /* this keyword can be used in two contexts */
        if (scope == CTX_GLOBAL) {
            map.mem_size = atoi(argv[1]);
            if (map.mem_size <= 0 || map.mem_size > 512)
                panic("invalid memory size %d, range is 1..512\n", 
		    map.mem_size);
        } else if (scope == CTX_MODULE) {
            /* private module memory */
            mdl->msize = atoi(argv[1]);
        }
        break;

    case TOK_MODULE:
	if (map.module_count == map.module_max) 
	    panic("too many modules. current limit is %d\n", map.module_max); 

        /* new module. need to allocate a new module element */
        mdl = new_module(argv[1]);

        /* change scope */
        scope = CTX_MODULE;
        break;

    case TOK_MODULE_MAX:
	map.module_max = atoi(argv[1]);
	map.modules = 
	    safe_realloc(map.modules, sizeof(module_t)*map.module_max); 
        break;

    case TOK_OUTPUT:
	mdl->output = strdup(argv[1]);
	break;

    case TOK_SNIFFER:
	add_sniffer(argv[1], argv[2], argc > 3 ? argv[3] : NULL);
        break;

    case TOK_STREAMSIZE: 
	mdl->streamsize = parse_size(argv[1]);
	break;

    case TOK_ARGS:
        mdl->args = safe_calloc(argc, sizeof(char *));
        for (i = 1; i < argc; i++) {
            if (argv[i][0] == '$') {
		FILE *auxfp;
		char line[256];

                /* The arg must be read from an auxiliar file */
                
                /* Open the file */
                if((auxfp = fopen(&argv[i][1], "r")) == NULL)
                    panic("Error opening auxiliar file: %s\n", &argv[i][1]);
                
                /* Dump its content into a string */
                mdl->args[i-1] = safe_calloc(1, sizeof(char));
                strncpy(mdl->args[i-1], "\0", 1);
                while(fgets(line, sizeof(line), auxfp)) {
		    int sz; 

		    sz = strlen(mdl->args[i-1]) + strlen(line) + 1; 
                    mdl->args[i-1] = (char *)safe_realloc(mdl->args[i-1], sz); 
                    strncat(mdl->args[i-1], line, strlen(line));
                }
            } else 
		safe_dup(&(mdl->args[i-1]), argv[i]);
        }

        /* 
	 * Last position is set to null to be able to know
         * when args finish from the modules
         */
        mdl->args[i-1] = NULL;
        break;
    
    case TOK_MIN_FLUSH: 
	mdl->min_flush_ivl = 
		TIME2TS(atoi(argv[1])/1000,(atoi(argv[1])%1000)*1000);
	break; 

    case TOK_MAX_FLUSH: 
	mdl->max_flush_ivl = 
		TIME2TS(atoi(argv[1])/1000,(atoi(argv[1])%1000)*1000);
	break; 

    case TOK_NAME: 
        safe_dup(&map.name, argv[1]);
	break; 

    case TOK_LOCATION:
        safe_dup(&map.location, argv[1]);
	break; 

    case TOK_LINKSPEED:
        safe_dup(&map.linkspeed, argv[1]);
	break; 

    case TOK_COMMENT: 
        safe_dup(&map.comment, argv[1]);
	break; 

    case TOK_DROPFILE:
	safe_dup(&map.dropfile, argv[1]);
	break;

    case TOK_DROPLOGSIZE:
	map.dropfilesize = parse_size(argv[1]);
	break;

    default:
	logmsg(LOGWARN, "unknown keyword %s\n", argv[0]);
	break;
    }
}


/*
 * -- parse_cfgline
 *
 * parses a line in the configuration file. the way it operates
 * is simple: split the line into NULL-separated keywords and then
 * call do_config() to actually update the global "map".
 * note that this function handles multiple lines as well.
 * it keeps quite a lot of state between calls in order to process
 * the multiple lines as a single one.
 *
 */
static void
parse_cfgline(const char *line)
{
    static enum {
	IN_BLANK,
	IN_WORD,
	IN_QUOTES,
	END_QUOTES,
        ESCAPE,
	DONE
    } state = DONE;
    static int linenum;
    static uint dst;	/* output buffer, size and pointers */
    static uint len;
    static char *buf;

    int argc = 0;
    uint i, srclen;

#define EOL		"\n\r"		/* end of line */
#define WHITESP		" \t\f\v\n\r"	/* whitespace */
#define COMMENT		"#"		/* comment markers */
#define QUOTE		"\""		/* quote markers */
#define BACKSLASH       "\\"            /* backslash */

    srclen = strlen(line);
    linenum++;
    /*
     * check for any leftover from the previous round.
     */
    if (state == DONE) {
	dst = 0;
	state = IN_BLANK;
    }
    logmsg(V_LOGCONFIG, "parse [%3d] [%s]\n", linenum, line);
    for (i=0; i < srclen && state != DONE ; i++) {
	char c = line[i];
	int copy = 0;		/* must copy this character */
	int end_token = 0;	/* and also this is the end of a token */

	if (c == '\0') {
	    logmsg(LOGWARN, "unexpected end of line\n");
	    break;
	}
	switch (state) {
	case DONE:	/* we'll never get here, anyways */
	    break;

	case IN_BLANK:
	    /* we are seeing blanks. Just skip until next keyword */
	    if (index(WHITESP, c))	/* keep skipping spaces */
		break;
	    if (index(COMMENT, c)) {	/* end of line */
		state = DONE;
		break;
	    }
	    if (index(QUOTE, c)) {	/* start quote */
		state = IN_QUOTES;
		break;
	    }
	    if (isalnum(c)) {
		copy = 1;
		state = IN_WORD;
		break;
	    }
	    if (c == '\\' && i == srclen-1)	/* line cont */
		return;
	    logmsg(LOGCONFIG, "invalid char in line %d [%s]\n",
		linenum, line+i);
	    dst = 0;
	    return; /* error */

	case IN_WORD:
	    /* in a keyword. Keep reading until done. */
	    if (index(WHITESP, c)) {
		end_token = 1;
		state = IN_BLANK;
		break;
	    }
	    if (index(COMMENT, c)) {	/* end of line */
		end_token = 1;
		state = DONE;
		break;
	    }
	    if (index(QUOTE, c)) {	/* start quote */
		logmsg(LOGCONFIG, "invalid char in line %d [%s]\n",
		    linenum, line+i);
		dst = 0;
		return; /* error */
	    }
	    /* assume all the rest is valid (could be more restrictive). */
	    copy = 1;
	    break;

	case IN_QUOTES:
	    /* wait for end-quote */
	    if (index(BACKSLASH, c)) {
                state = ESCAPE;
                break;
            }
	    if (index(QUOTE, c)) {	/* end quote */
		state = END_QUOTES;
		break;
	    }
	    /* anything is fine here */
	    copy = 1;
	    break;

        case ESCAPE:
            copy = 1;
            state = IN_QUOTES;
            break;

        case END_QUOTES:
	    end_token = 1;
	    state = IN_BLANK;
	    break;
	}
	if (copy)
	    buf = add_char(buf, c, &dst, &len);
	if (end_token) {
	    buf[dst++] = '\0';
	    argc++;
	}
    }
    if (dst > 0 && buf[dst-1] == '\\') {
	buf = add_char(buf, '\n', &dst, &len);
	return;
    }
    switch(state) {
    case IN_QUOTES:
    case ESCAPE:
	logmsg(LOGCONFIG, "missing endquote in line %d [%s]\n",
	    linenum, line);
    	dst = 0;
	return; /* error */

    case END_QUOTES:
    case IN_WORD:
	buf = add_char(buf, '\0', &dst, &len);
	argc++;
	/* FALLTHROUGH */
    case DONE:
    case IN_BLANK:
	state = DONE;
	break;
    }
    /* now we have NUL-separated keywords. */
    if (argc == 0) {
	logmsg(V_LOGCONFIG, "empty line\n");
    } else {
	char **argv = malloc(argc * sizeof(char *));
	if (argv == NULL)
	    panic("cannot allocate buffer for line %d [%s]\n",
		    linenum, line);
	logmsg(V_LOGCONFIG, "");	/* start print */
	for (i=0, argc = 0; i<dst;i++) {
	    argv[argc++] = &buf[i];
	    logmsg(0, "<%s> ", buf+i);
	    while (i<dst && buf[i] != '\0')
		i++;
	}
	logmsg(0, "\n");
	do_config(argc, argv);
	free(argv);
    }
}


/*
 * -- parse_config_file
 *
 * it opens the file received as input and parses one
 * line at a time calling parse_cfgline().
 *
 */
static void
parse_cfgfile(char * name)
{
    char buf[2048];
    FILE *f;

    f = fopen(name, "r");
    if (f == NULL) {
	logmsg(LOGWARN, "cannot open config file (%s): %s\n",
	    name, strerror(errno));
	return;
    }

    while (fgets(buf, sizeof(buf), f)) {
        int l;

	/* get rid of last carriage return to handle multiple
	 * lines (i.e., lines that end with '\').
	 */
	l = strlen(buf);
	if (l > 0 && buf[l-1] == '\n')
	    buf[l-1] = '\0';

	parse_cfgline(buf);
    }

    fclose(f);
}


/*
 * use the malloc debugger (in FreeBSD)
 */
#if __FreeBSD__ == 4
#define	MALLOC_OPTS	malloc_options
#elif __FreeBSD__ == 5
#define	MALLOC_OPTS	_malloc_options
#else
const char *MALLOC_OPTS;	/* other systems don't have it */
#endif
extern const char *MALLOC_OPTS;

/*
 * -- parse_cmdline
 *
 * parses the command line options and fills in the "map" (global)
 * data structure.
 * The function does two passes on the arguments: in the first pass
 * checks if a config file has been specified -- if not, it assumes we
 * want the default one _before_ the rest of the command line.
 * In the second pass does the actual processing, in the order specified
 * by the command line.
 * This allows us to process multiple config files and override options
 * from either the command line or the config file.
 *
 */
int
parse_cmdline(int argc, char *argv[])
{
    int c;
    DIR *d;

    /*
     * command line flags are here, so we put here the 'usage'
     * string as well...
     */
    static const char * usage =
    "usage: %s [-c config_file] [-D basedir] [-L libdir] [-M module] [-m memsize] [-v logflags] [-x debug_opts] [-s sniffer] [-p query_port]\n";

    /* flag to be set if we parsed a configuration file */
    static const char *opts = "c:D:L:M:m:p:s:v:x:";

    while ((c = getopt(argc, argv, opts)) != -1) {
	if (c == 'c')	/* we have a valid config file */
	    break;
	else if (c == '?')
            errx(EXIT_FAILURE, usage, argv[0]);
    }

    if (c != 'c') /* no config, get the default one */
	parse_cfgfile(DEFAULT_CFGFILE);

    opterr = 0;
    optind = 1;
#ifdef linux
    /*
     * restart processing. Linux and FreeBSD do 
     * this in different ways. 
     */
    optind = 0;
#else
    optreset = 1;
#endif

    while ((c = getopt(argc, argv, opts)) != -1) {
        switch(c) {
	case 'x':
	    /* pass debug options into a string */
	    if (strstr(optarg,"malloc=") == optarg) {
		/* only significant on FreeBSD */
		MALLOC_OPTS = strdup(optarg+7);
		break;
	    }
	    if (map.debug) {
		char *old = map.debug;
		asprintf(&map.debug, "%s %s", old, optarg);
		free(old);
	    } else
		map.debug = strdup(optarg);
	    break;

        case 'c':   /* change config file name */
            parse_cfgfile(optarg);
            break;

	case 'D':	/* basedir */
	    safe_dup(&map.basedir, optarg);
	    break;

	case 'L':	/* libdir */
	    safe_dup(&map.libdir, optarg);
	    break;

	case 'M':	/* module */
	    {
	    module_t *mdl = new_module(optarg);
	    check_module(mdl);
	    }
	    break;

	case 'p':
	    map.query_port = atoi(optarg);
	    break;

        case 's':   /* sniffer */
            add_sniffer(optarg, NULL, NULL);
            break;

        case 'm':   /* capture/export memory usage */
            map.mem_size = atoi(optarg);
            if (map.mem_size <= 0 || map.mem_size > 512)
                panic("invalid memory size %d, range is 1-256\n", map.mem_size);
            break;

        case 'v':   /* verbose */
            // map.logflags |= (map.logflags << 16);
            map.logflags = set_flags(map.logflags, optarg);
            break;

        case '?':   /* unknown */
            warnx("unrecognized option (%s)\n", argv[optind]);
            errx(EXIT_FAILURE, usage, argv[0]);
            break;

        case ':':   /* missing argument */
            warnx("missing argument for option (%s)\n", argv[optind]);
            break;

        default:    /* should never get here... */
            errx(EXIT_FAILURE, usage, argv[0]);
        }
    }
    if (map.basedir == NULL)
	panic("missing basedir");
    d = opendir(map.basedir);
    if (d == NULL) 
	createdir(map.basedir); 
    else 
	closedir(d);
    return 0;
}
