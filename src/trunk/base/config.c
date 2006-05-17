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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h> 	/* bcmp */
#include <ctype.h>  	/* isalnum */
#include <err.h>    	/* warnx, errx */
#include <errno.h>
#include <assert.h>
#include <dirent.h>	/* opendir */
#include <sys/types.h>	/* mkdir, opendir */
#include <sys/stat.h>	/* mkdir */

#include "como.h"
#include "comopriv.h"
#include "sniffers.h"

/* get the sniffers list */
extern sniffer_t *__sniffers[];

/*
 * tokens used in the dictionary
 */
enum tokens {
    TOK_NULL=0,

    TOK_BASEDIR,
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
    TOK_ARGSFILE,
    TOK_PRIORITY,
    TOK_RUNNING,
    TOK_NAME,   
    TOK_LOCATION,
    TOK_TYPE,
    TOK_COMMENT,
    TOK_MAXFILESIZE,
    TOK_VIRTUAL 
};


/*
 * in the configuration file there are different scopes, or contexts.
 * the scope of a configuration variable could be global (i.e., default
 * values that affect all objects), or related to a specific module.
 *
 * special context CTX_NONE will get a variable ignored. this will
 * be useful because depending of configuration state, we will silently
 * ignore some keywords. 
 */
#define CTX_ANY         0xff
#define CTX_NONE        0x00
#define CTX_GLOBAL      0x01
#define CTX_MODULE      0x02
#define CTX_VIRTUAL	0x04		/* virtual node section */

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
 * We also store the contexts where the keyword is acceptable,
 * which changes if configuring or reconfiguring.
 *
 */
struct _keyword {
    char const *str;    /* keyword */
    int action;         /* related token */
    int nargs;          /* number of required arguments */
    int scope;          /* scope where the keyword is acceptable */
};

typedef struct _keyword keyword_t;

keyword_t keywords[] = {
    { "basedir",     TOK_BASEDIR,     2, CTX_GLOBAL },
    { "librarydir",  TOK_LIBRARYDIR,  2, CTX_GLOBAL },
    { "logflags",    TOK_LOGFLAGS,    2, CTX_GLOBAL },
    { "module",      TOK_MODULE,      2, CTX_GLOBAL },
    { "module-limit",TOK_MODULE_MAX,  2, CTX_GLOBAL },
    { "query-port",  TOK_QUERYPORT,   2, CTX_GLOBAL|CTX_VIRTUAL },
    { "sniffer",     TOK_SNIFFER,     3, CTX_GLOBAL },
    { "memsize",     TOK_MEMSIZE,     2, CTX_GLOBAL },
    { "output",      TOK_OUTPUT,      2, CTX_MODULE },
    { "hashsize",    TOK_HASHSIZE,    2, CTX_MODULE },
    { "source",      TOK_SOURCE,      2, CTX_MODULE },
    { "filter",      TOK_FILTER,      2, CTX_GLOBAL|CTX_VIRTUAL|CTX_MODULE },
    { "description", TOK_DESCRIPTION, 2, CTX_MODULE },
    { "end",         TOK_END,         1, CTX_MODULE|CTX_GLOBAL|CTX_VIRTUAL },
    { "streamsize",  TOK_STREAMSIZE,  2, CTX_MODULE },
    { "args",        TOK_ARGS,        2, CTX_MODULE },
    { "args-file",   TOK_ARGSFILE,    2, CTX_MODULE },
    { "priority",    TOK_PRIORITY,    1, CTX_MODULE },
    { "running",     TOK_RUNNING,     2, CTX_MODULE },
    { "name",        TOK_NAME,        2, CTX_GLOBAL },
    { "location",    TOK_LOCATION,    2, CTX_GLOBAL|CTX_VIRTUAL },
    { "type",        TOK_TYPE,        2, CTX_GLOBAL|CTX_VIRTUAL },
    { "comment",     TOK_COMMENT,     2, CTX_GLOBAL|CTX_VIRTUAL },
    { "filesize",    TOK_MAXFILESIZE, 2, CTX_GLOBAL|CTX_VIRTUAL },
    { "virtual-node",TOK_VIRTUAL,     2, CTX_GLOBAL },
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
	{ "timer",	0,	LOGTIMER	},
	{ "module",	0,	LOGMODULE	},
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
 * -- add_sniffer 
 * 
 * given a string, locate the corresponding sniffer and set it.
 * The device can be given as a separate argument, or as a
 * colon-separated part of the name (this way it is compatible
 * with the command line).
 * Failures are not fatal.
 */
void
add_sniffer(como_t * m, char *want, char *device, char *args)
{
    int i;

    if (device == NULL && args == NULL) {
	device = index(want, ':');
	if (device) {
	    *device = '\0';
	    device++; /* skip ':' */
            args = index(device, ':');
            if (args) {
                *args = '\0';
                args++;
            }
        }
    }
    
    if (!device) {
        logmsg(LOGWARN, "sniffer %s: no device specified, ignoring\n", want);
        return;
    }

    for (i = 0; __sniffers[i]; i++) {
	const char *name = __sniffers[i]->name;
	if (strcmp(name, want) == 0) {
	    source_t *s = safe_calloc(1, sizeof(*s));

	    s->next = m->sources; 
	    s->cb = __sniffers[i];
	    s->device = strdup(device);
	    s->args = args ? strdup(args) : NULL;
	    s->fd = -1;	/* still closed */
	    m->sources = s;
	    break;
	}
    }
    if (__sniffers[i] == NULL) {
	logmsg(LOGWARN, "sniffer %s %s not found, ignoring\n", want, device);
	return; 
    }

    logmsg(LOGUI, "... sniffer [%s] %s\n", 
	m->sources->cb->name, m->sources->device);
}


/* 
 * -- createdir
 * 
 * creates the basedir for CoMo output files. it generates the 
 * entire directory tree if necessary. 
 * 
 */
static void 
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
 * Apply the configuration on the map. It expects each useful line to 
 * start with a known keyword. Note the unconventional return values. 
 * It returns NULL if successful or an error string in case of error.
 *
 */
static char * 
do_config(struct _como * m, int argc, char *argv[])
{
    static char errstr[1024]; 
    static int scope = CTX_GLOBAL;      	/* scope of current keyword */
    static module_t * mdl = NULL;       	/* module currently open */
    keyword_t *t;

    /*
     * run some checks on the token (i.e., that it exists
     * and that we have all the arguments it needs).
     */
    t = match_token(argv[0], keywords);
    if (t == NULL) {
	sprintf(errstr, "unknown token \"%s\"\n", argv[0]);
        return errstr;
    }

    if (argc < t->nargs) {
	sprintf(errstr, "\"%s\", requires at least %d arguments\n", argv[0],
	      t->nargs);
        return errstr;
    }

    /*
     * Check if the keyword is ok in the current scope.
     */
    if (!(t->scope & scope)) {
	sprintf(errstr, "\"%s\" out of scope\n", argv[0]);
        return errstr;
    }

    /*
     * configuration actions
     */
    switch (t->action) {
    case TOK_BASEDIR:
	safe_dup(&m->basedir, argv[1]);
	break;

    case TOK_QUERYPORT:
	m->node->query_port = atoi(argv[1]);
	break;

    case TOK_DESCRIPTION:
	safe_dup(&mdl->description, argv[1]);
	break;

    case TOK_END:
	if (scope == CTX_MODULE) { 
	    /*
	     * "end" of a module configuration.  run some checks depending 
	     * on context to make sure that all mandatory fields are there
	     * and set default values
	     */

	    if (check_module(m, mdl)) { 
		remove_module(m, mdl); 
		scope = CTX_GLOBAL;
		break;
	    }

	    if (m->running == INLINE) 
		m->inline_mdl = mdl;

	    logmsg(LOGUI, "... module%s %s [%d][%d] ", 
		   (mdl->running == RUNNING_ON_DEMAND) ? " on-demand" : "",
		   mdl->name, mdl->node, mdl->priority); 
	    logmsg(LOGUI, " filter %s; out %s (%uMB)\n", 
		   mdl->filter_str, mdl->output, mdl->streamsize/(1024*1024));
	    if (mdl->description != NULL) 
		logmsg(LOGUI, "    -- %s\n", mdl->description); 
	    scope = CTX_GLOBAL;
        } else if (scope == CTX_VIRTUAL) { 
	    /* 
	     * we are done with this virtual node. let's recover
	     * the master node (associated with the global context)
	     */
	    node_t *p, *q;

	    for (p = m->node, q = NULL; p->id != 0; q = p, p = p->next)
		; 

	    if (q) {
		/* the master node is not at the head of the list. 
		 * move it there. 
		 */
		q->next = p->next; 
		p->next = m->node; 
		m->node = p;
	    } 
	    scope = CTX_GLOBAL; 
	}
	break;
	    
    case TOK_FILTER:
	if (scope == CTX_MODULE) 
            safe_dup(&mdl->filter_str, argv[1]);
        else if (scope == CTX_VIRTUAL) 
	    safe_dup(&m->node->filter_str, argv[1]);
	break;

    case TOK_HASHSIZE:
        mdl->ex_hashsize = mdl->ca_hashsize = atoi(argv[1]);
        break;

    case TOK_SOURCE:
	safe_dup(&mdl->source, argv[1]);
	break;

    case TOK_LIBRARYDIR:
        safe_dup(&m->libdir, argv[1]);
        break;

    case TOK_LOGFLAGS:
        m->logflags = set_flags(0, argv[1]);
        break;

    case TOK_MEMSIZE:
        /* this keyword can be used in two contexts */
	m->mem_size = atoi(argv[1]);
	if (m->mem_size <= 0 || m->mem_size > 512) {
	    sprintf(errstr, 
		    "invalid memory size %d, range is 1..512\n", 
		    m->mem_size);
	    return errstr; 
	} 
        break;

    case TOK_MODULE:
	mdl = new_module(m, argv[1], (m->running == INLINE? -1 : 0), -1);
        scope = CTX_MODULE; 		/* change scope */
        break;
        
    case TOK_MODULE_MAX:
	m->module_max = atoi(argv[1]);
	m->modules = safe_realloc(m->modules, sizeof(module_t)*m->module_max); 
        break;

    case TOK_OUTPUT:
        safe_dup(&mdl->output, argv[1]);
	break;

    case TOK_SNIFFER:
	add_sniffer(m, argv[1], argv[2], argc > 3 ? argv[3] : NULL);
        break;

    case TOK_STREAMSIZE: 
	mdl->streamsize = parse_size(argv[1]);
	break;

    case TOK_MAXFILESIZE: 
	m->maxfilesize = parse_size(argv[1]); 
	if (m->maxfilesize > 1024*1024*1024) { 
	    m->maxfilesize = DEFAULT_FILESIZE; 
	    sprintf(errstr, "'filesize' should be < 1GB --> set to %dMB\n", 
		   m->maxfilesize / (1024*1024));
	    return errstr; 
	} 
	break;

    case TOK_ARGS:
	do { 
	    int i,j;

	    if (mdl->args == NULL) {
		mdl->args = safe_calloc(argc, sizeof(char *));
		j = 0; 
	    } else { 
		/* 
		 * we need to add the current list of optional arguments 
		 * to the list we already have. first, count how many we 
		 * have got so far and then reallocate memory accordingly 
		 */
		for (j = 0; mdl->args[j]; j++) 
		    ; 
		mdl->args = safe_realloc(mdl->args, (argc + j) * sizeof(char*));
	    } 

	    for (i = 1; i < argc; i++) 
		mdl->args[i+j-1] = safe_strdup(argv[i]);

	    /* 
	     * Last position is set to null to be able to know
	     * when args finish from the modules
	     */
	    mdl->args[i+j-1] = NULL;
	} while (0); 
	break;

    case TOK_ARGSFILE: 
	do { 
	    FILE *auxfp;
	    char line[512];
	    int j;

	    /* open the file */
	    auxfp = fopen(argv[1], "r"); 
	    if (auxfp == NULL) { 
		sprintf(errstr, "opening file %s: %s\n", argv[1], 
			strerror(errno)); 
		return errstr; 
	    } 

	    /* count the number of arguments we already have */
	    for (j = 0; mdl->args[j]; j++) 
		; 

	    /* read each line in the file and parse it again */ 
	    /* XXX we reallocate mdl->args for each line in the file. 
	     *     this should be done better in a less expensive way. 
	     */
	    while (fgets(line, sizeof(line), auxfp)) {
		j++;
		mdl->args = safe_realloc(mdl->args, j * sizeof(char *));
		mdl->args[j - 1] = safe_strdup(line);
	    }

	    /* add the last NULL pointer */
	    mdl->args = safe_realloc(mdl->args, (j + 1) * sizeof(char *));
	    mdl->args[j] = NULL; 

	    fclose(auxfp);
	} while (0);
	break;
    
    case TOK_PRIORITY: 
        mdl->priority = atoi(argv[1]);
	break; 

    case TOK_RUNNING: 
        mdl->running = (strcmp(argv[1], "on-demand") == 0) ?
		       RUNNING_ON_DEMAND : RUNNING_NORMAL;
	break; 

    case TOK_NAME: 
        safe_dup(&m->node->name, argv[1]);
	break; 

    case TOK_LOCATION:
        safe_dup(&m->node->location, argv[1]);
	break; 

    case TOK_TYPE:
        safe_dup(&m->node->type, argv[1]);
	break; 

    case TOK_COMMENT: 
        safe_dup(&m->node->comment, argv[1]);
	break; 

    case TOK_VIRTUAL: 
	do { 
	    node_t * node; 
	    node = safe_calloc(1, sizeof(struct _node)); 
	    node->id = m->node_count; 
	    safe_dup(&node->name, argv[1]);
	    node->next = m->node;
	    m->node = node; 
	    m->node_count++;
	    scope = CTX_VIRTUAL; 
	} while (0);
	break;

    default:
	sprintf(errstr, "unknown keyword %s\n", argv[0]);
	return errstr; 
    }

    return NULL;
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
parse_cfgline(struct _como * m, const char *line)
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
	char **argv;
	char * str; 

	logmsg(V_LOGCONFIG, "");	/* start print */

	argv = safe_malloc(argc * sizeof(char *));
	for (i=0, argc = 0; i<dst;i++) {
	    argv[argc++] = &buf[i];
	    logmsg(0, "<%s> ", buf+i);
	    while (i<dst && buf[i] != '\0')
		i++;
	}
	logmsg(0, "\n");

	str = do_config(m, argc, argv); 
	if (str != NULL) 
	    logmsg(LOGWARN, "%s (line: %d): %s\n", line, linenum, str); 
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
parse_cfgfile(struct _como * m, char * name)
{
    char buf[2048];
    FILE *f;

    assert(m != NULL); 
    assert(name != NULL); 

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

	parse_cfgline(m, buf);
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

typedef struct cli_args_t {
    int		done;
    char	**cfg_files;
    int		cfg_files_count;
    char	*basedir;
    char	*libdir;
    int		query_port;
    size_t	mem_size;
    int		logflags;
    char	*debug;
    runmodes_t  running; 
    char	*sniffer;
    char	*module;
    char	*module_args;
    char	*filter;
} cli_args_t;


/*
 * -- parse_cmdline
 *
 * parses the command line options and fills in the "map" (global)
 * data structure. The function first checks if a config file has been 
 * specified.
 * If not, it assumes we want the default one _before_ the rest of
 * the command line. Then it does the actual processing, in the order
 * specified by the command line.
 * This allows us to process multiple config files and override options
 * from either the command line or the config file.
 *
 */
static void
parse_cmdline(cli_args_t * m, int argc, char ** argv)
{
    int c;

    /*
     * command line flags are here, so we put here the 'usage'
     * string as well...
     */
    static const char * usage =
	"usage: %s [-c config-file] [-D basedir] [-L libdir] [-p query-port] "
        "[-m mem-size] [-v logflags] "
        "[-s sniffer[:device[:\"args\"]]] [module[:\"module args\"] "
	"[filter]]\n";

    /* flag to be set if we parsed a configuration file */
    static const char *opts = "hc:D:L:p:m:v:x:s:";
    
    m->query_port = -1;
    m->mem_size = 0;
    m->logflags = -1;

    /*
     * parse command line options
     */
    while ((c = getopt(argc, argv, opts)) != -1) {
        switch(c) {
	case 'h':
            printf(usage, argv[0]);
            exit(0);
            break;
        case 'x':
	    /* pass debug options into a string */
	    if (strstr(optarg,"malloc=") == optarg) {
		/* only significant on FreeBSD */
		MALLOC_OPTS = strdup(optarg+7);
		break;
	    }
	    if (m->debug) {
		char *old = m->debug;
		asprintf(&m->debug, "%s %s", old, optarg);
		free(old);
	    } else
		m->debug = safe_strdup(optarg);
	    break;

        case 'c':
	    /* config file name */
	    m->cfg_files_count++;
	    if (m->cfg_files) {
		m->cfg_files = safe_realloc(m->cfg_files, 
					sizeof(char *) * m->cfg_files_count);
	    } else {
		m->cfg_files = safe_malloc(sizeof(char *));
	    }
	    m->cfg_files[m->cfg_files_count - 1] = optarg;
	    break;

	case 'D':	/* basedir */
	    m->basedir = optarg;
	    break;

	case 'L':	/* libdir */
	    m->libdir = optarg;
	    break;

	case 'p':
	    m->query_port = atoi(optarg);
	    break;

        case 's':   /* sniffer */
	    m->sniffer = optarg;
            break;

        case 'm':   /* capture/export memory usage */
	    {
		int size = atoi(optarg);
		if (size <= 0 || size > 512)
		    warnx("ignoring invalid memory size %d, range is 1..512", size);
		else 
		    m->mem_size = size;
	    }
	    break;

        case 'v':   /* verbose */
	    if (m->logflags == -1)
		m->logflags = 0;
            m->logflags = set_flags(m->logflags, optarg);
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
    
    if (optind < argc) {
	int i;
	
	/* Run with inline mode */
	m->running = INLINE;
	
	/* To define a module from command line, we use do_config().
	 *
	 * We need to start and end module configuration like done while
	 * parsing a configuration file, for do_config() to get all the
	 * context changes it expects.
	 */
	i = optind;
	m->module = argv[i];
	
	if ((m->module_args = strchr(m->module, ':')) != NULL) {
	    *m->module_args = '\0';
	    m->module_args++;
	}
	
	i++;
	if (i < argc) {
	    /* filter */
	    m->filter = strdup(argv[i]);
	    i++;
	    
	    while (i < argc) {
		char *filter2;
		asprintf(&filter2, "%s %s", m->filter, argv[i]);
		free(m->filter);
		m->filter = filter2;
		i++;
	    }
	}
    }
    
    m->done = 1;
}


/*  
 * -- init_map
 *
 * initializes global shared map.
 *
 */
void
init_map(struct _como * m)
{
    int i; 

    memset(m, 0, sizeof(struct _como));
    m->whoami = SUPERVISOR;
    m->running = NORMAL; 
    m->logflags = DEFAULT_LOGFLAGS;
    m->mem_size = DEFAULT_MEMORY;
    m->maxfilesize = DEFAULT_FILESIZE;
    m->module_max = DEFAULT_MODULE_MAX;
    m->module_last = -1; 
    m->modules = safe_calloc(m->module_max, sizeof(module_t));
    for (i = 0; i < m->module_max; i++) 
	m->modules[i].status = MDL_UNUSED; 
    m->workdir = mkdtemp(strdup("/tmp/comoXXXXXX"));
    m->basedir = strdup(DEFAULT_BASEDIR);
    m->libdir = strdup(DEFAULT_LIBDIR);
    m->node = safe_calloc(1, sizeof(node_t)); 
    m->node->id = 0;
    m->node->name = strdup("CoMo Node");
    m->node->location = strdup("Unknown");
    m->node->type = strdup("Unknown");
    m->node->query_port = DEFAULT_QUERY_PORT;
    m->node_count = 1;
}


/*
 * -- configure
 *
 * do a first pass of the command line parameters to find all
 * configuration files. the options in those files are processed
 * before any other command line parameter. command line will
 * overwrite any other configuration, as well as the last config
 * file will overwrite previous config files.
 *
 */
void
configure(struct _como * m, int argc, char ** argv)
{
    static cli_args_t cli_args;
    int config_file_exists;
    int c, i, j;
    DIR *d;
    
    if (cli_args.done == 0) {
	parse_cmdline(&cli_args, argc, argv);
    }
    
    m->running = cli_args.running;
    if (cli_args.logflags != -1)
	m->logflags = cli_args.logflags;

    /*
     * build list of config files
     */
    config_file_exists = 0;
    for (c = 0; c < cli_args.cfg_files_count; c++) {
	config_file_exists = 1;
	parse_cfgfile(m, cli_args.cfg_files[c]);
    }
    
    if (!config_file_exists && m->running == NORMAL) 
        parse_cfgfile(m, DEFAULT_CFGFILE);	/* add default config file */

    /* use cli args to override cfg file settings */
    if (cli_args.basedir != NULL)
	safe_dup(&m->basedir, cli_args.basedir);
    if (cli_args.libdir != NULL)
	safe_dup(&m->libdir, cli_args.libdir);
    if (cli_args.query_port != -1)
	m->node->query_port = cli_args.query_port;
    if (cli_args.mem_size != 0)
	m->mem_size = cli_args.mem_size;
    m->debug = cli_args.debug;
    
    if (m->running == INLINE) {
	char *conf_argv[2];
	
    	if (cli_args.sniffer != NULL) {
	    add_sniffer(m, cli_args.sniffer, NULL, NULL);
    	}
    	
	/* prepare the arguments for do_config() */
	conf_argv[0] = "module";
	conf_argv[1] = cli_args.module;
	do_config(m, 2, conf_argv);

	if (cli_args.module_args != NULL) {
	    conf_argv[0] = "args";
	    conf_argv[1] = cli_args.module_args;
	    do_config(m, 2, conf_argv);
	}
	
	if (cli_args.filter != NULL) {
	    conf_argv[0] = "filter";
	    conf_argv[1] = cli_args.filter;
	    do_config(m, 2, conf_argv);
	}
	
	conf_argv[0] = "end";
	do_config(m, 1, conf_argv);
    }

    /* 
     * now look into the virtual nodes and replicate
     * all modules that have been found in the config file(s)
     * 
     * these new modules will have the same name but will be 
     * running the additional filter associated with the virtual 
     * node and save data in the virtual node basedir.  
     */
    for (i = 0, j = m->module_last; i <= j; i++) { 
	node_t * node; 
	module_t * orig; 

	orig = &m->modules[i]; 
	for (node = m->node; node; node = node->next) { 
	    module_t * mdl; 
	    char * nm; 

	    if (node->id == 0) 
		break; 	/* master node. nothing to do */

	    /* create a new module and copy it from  new module */
	    mdl = copy_module(m, orig, node->id, -1, NULL);
	    
	    /* append node id to module's output file */
	    asprintf(&nm, "%s-%d", mdl->output, mdl->node); 
	    safe_dup(&mdl->output, nm); 
	    free(nm); 
	    
	    /* add the node filter to the module filter */
	    if (node->filter_str) {
		char * flt;
		if (!strcmp(mdl->filter_str, "all"))
		    asprintf(&flt, "%s", node->filter_str);
		else 
		    asprintf(&flt,"(%s) and (%s)", 
				node->filter_str, mdl->filter_str);
		mdl->filter_str = flt; /* FIXME: possible leak */
	    } 

            logmsg(LOGUI, "... module %s [%d][%d] ",
                   mdl->name, mdl->node, mdl->priority);
            logmsg(LOGUI, " filter %s; out %s (%uMB)\n",
                   mdl->filter_str, mdl->output, mdl->streamsize/(1024*1024));
            if (mdl->description != NULL)
                logmsg(LOGUI, "    -- %s\n", mdl->description);
	}
    }

    /* 
     * open the basedir for all nodes (virtual ones included) 
     */
    if (m->basedir == NULL)
	panicx("missing basedir");
    d = opendir(m->basedir);
    if (d == NULL) 
	createdir(m->basedir); 
    else 
	closedir(d);
}

