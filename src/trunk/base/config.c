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
    TOK_PRIORITY,
    TOK_NAME,   
    TOK_LOCATION,
    TOK_TYPE,
    TOK_COMMENT,
    TOK_MAXFILESIZE,
    TOK_VIRTUAL 
};

/*
 * We can be configuring for the first time or
 * configuring in runtime (reconfiguring).
 */
enum cfg_states {
    CFGSTATE_CONFIG,
    CFGSTATE_RECONFIG
};

int cfg_state;




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
    { "priority",    TOK_PRIORITY,    1, CTX_MODULE },
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
	{ "debug",	0,	LOGDEBUG	},
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

/**
 * -- load_callbacks
 *
 */
int
load_callbacks(module_t *mdl)
{
    callbacks_t *cb;
    char *clname;
    void *handle;

    logmsg(LOGDEBUG, "Callbacks loaded for module '%s'\n", mdl->name);

    /* load the library */
    if (!map.libdir || mdl->source[0] == '/')
        clname = strdup(mdl->source);
    else
        asprintf(&clname, "%s/%s", map.libdir, mdl->source);

    cb = load_object_h(clname, "callbacks", &handle);

    if (cb == NULL) {
        warnx("could not load library %s: %s\n", clname, strerror(errno));
        free(clname);
        return 0;
    }
    free(clname);

    /* store the callbacks */
    mdl->callbacks = *cb;
    mdl->bsize = cb->st_recordsize;	/* store the block size too */
    mdl->cb_handle = handle;

    return 1;
}

/*
 * Check the configuration of a module, supply default values.
 */
static int
check_module(module_t *mdl, __unused node_t * node)
{
    callbacks_t *cb;
    int idx;

    /* check that module names are unique within a node */
    for (idx = 0; idx < map.module_count; idx++) { 
        if (!strcmp(map.modules[idx].name, mdl->name) && 
					map.modules[idx].node == mdl->node) {
	    logmsg(LOGWARN, "config: module name '%s' already present\n",
		mdl->name);
	    return 0;
        }
    }

    if (map.basedir && mdl->output[0] != '/') { /* prepend basedir */
	char *p = mdl->output;
	asprintf(&mdl->output, "%s/%s", map.basedir, p);
	free(p);
    }


    if (mdl->ex_hashsize == 0) { /* hash size */
	logmsg(LOGWARN, "config: module %s needs a hash size\n", mdl->name);
        return 0;
    }

    if (mdl->streamsize < 2 * map.maxfilesize) { /* filesize */
	mdl->streamsize = 2*map.maxfilesize; 
	logmsg(LOGWARN, 
	    "module %s streamsize too small. set to %dMB\n", 
	    mdl->name, mdl->streamsize/(1024*1024)); 
    } 

    /* perform some checks on the callbacks */
    cb = &mdl->callbacks;

    /* update(), store() and load() should definitely be there */
    if (cb->update == NULL) {
	logmsg(LOGWARN, "module %s misses update()\n", mdl->name);
        return 0;
    }
    if (cb->store == NULL) {
	logmsg(LOGWARN, "module %s misses store()\n", mdl->name);
        return 0;
    }
    if (cb->load == NULL) {
	logmsg(LOGWARN, "module %s misses load()\n", mdl->name);
        return 0;
    }

    /* 
     * either both or none of action() and export() are required 
     */
    if (cb->export == NULL) {
	/*
	 * no export(), then we we don't want
	 * action(), ematch() and compare().
	 */
	if (cb->action || cb->ematch || cb->compare ) {
	    logmsg(LOGWARN, "module %s has %s%s%s without export()\n",
			mdl->name,
			cb->action ? "action() " : "",
			cb->ematch ? "ematch() " : "",
			cb->compare ? "compare() " : ""
		);
            return 0;
        }

    } else {
	if (cb->action == NULL) { /* export() requires action() too */
	    logmsg(LOGWARN, "module %s has export() w/out action()\n", 
		mdl->name);
            return 0;
        }
    }

    if (cb->formats == NULL) 
	asprintf(&cb->formats, "plain"); 

    logmsg(LOGCONFIG, "module %s checks ok\n");
    return 1;
}

/*
 * initialize the module and store it into map.modules[].
 * assumes callbacks are already loaded. assumes module
 * is already checked with check_module().
 *
 * returns the new location of the module.
 */
module_t *
load_module(module_t *mdl, int idx)
{
    callbacks_t *cb;
    int narg, i;
    char **args_backup;

    if (idx == map.module_max) 
	panicx("too many modules, cannot load %s", mdl->name);

    /* 
     * copy the module into the array and free the allocated module_t
     */
    bcopy(mdl, &map.modules[idx], sizeof(module_t));
    free(mdl); 

    mdl = &map.modules[idx];
    mdl->index = idx;
    if (idx == map.module_count)
        map.module_count++;

    cb = &mdl->callbacks;

    if (mdl->args) {
        /* Count how many args we have for this module */
        for (narg = 0; mdl->args[narg] != NULL; narg++);
        /* Allocate memory for the args backup array */
        args_backup = safe_calloc(narg, sizeof(char *));
        /* Backup the module's args */
        for (i = 0; i < narg; i++)
            safe_dup(&args_backup[i], mdl->args[i]);
        /* Expand some args reading from a file, if needed */
        for (i = 0; i < narg; i++) {
	    if (mdl->args[i][0] == '$') {
		FILE *auxfp;
		char line[512];

		/* The arg must be read from an auxiliar file */
		    
		/* Open the file */
		if((auxfp = fopen(&mdl->args[i][1], "r")) == NULL)
		    panic("Error opening auxiliar file: %s\n",
                          &mdl->args[i][1]);
		    
		/* Dump its content into a string */
		mdl->args[i] = safe_calloc(1, sizeof(char));
		strncpy(mdl->args[i], "\0", 1);
		while(fgets(line, sizeof(line), auxfp)) {
		    int sz; 
		    sz = strlen(mdl->args[i]) + strlen(line) + 1; 
		    mdl->args[i] = (char *)safe_realloc(mdl->args[i], sz); 
		    strncat(mdl->args[i], line, strlen(line));
		}
		/* Close the file */
		fclose(auxfp);
            }
        }
    }
    
    /* 
     * SUPERVISOR needs to allocate memory for this new module in the 
     * shared memory. Before doing so it needs to stop CAPTURE, allocate 
     * the memory and then let CAPTURE resume its operations. This is 
     * to avoid a fine grained locking mechanisms for the shared memory. 
     * 
     * XXX This code makes the assumption that new modules are loaded 
     *     rather unfrequently and that the init() callback is quick. 
     *     We may need to revisit these assumptions in the future. 
     */
    if (map.whoami == SUPERVISOR) { 
        /* 
	 * send lock message to CAPTURE 
	 */ 
        sup_send_ca_lock();

        /* 
	 * create a memory list for this module to 
	 * allocate memory and for EXPORT to flush 
	 * memory.
	 */ 
        mdl->mem_map = new_memlist(32); 
        mdl->flush_map = mdl->mem_map; 
        mdl->master_map = new_memlist(32); 

	/* initialize module */
	mdl->flush_ivl = 
	    (cb->init == NULL)? DEFAULT_CAPTURE_IVL: cb->init(mdl, mdl->args);
	if (mdl->flush_ivl == 0) 
	    panicx("could not initialize %s\n", mdl->name);

	mdl->master_ptr = mdl->ptr;
	mdl->ptr = NULL;

        /* Done, tell CAPTURE to resume its execution */
        sup_send_ca_unlock();
    } 

    /* Restore the module's args and free the backup array */
    if (mdl->args) {
        for (i = 0; i < narg; i++) {
            free(mdl->args[i]);
            mdl->args[i] = safe_calloc(1, sizeof(char *));
            safe_dup(&mdl->args[i], args_backup[i]);
        }
        for (i = 0; i < narg; i++)
            free(args_backup[i]);
        free(args_backup);
    }
    
    return mdl;
}

/**
 * -- free_module
 *
 * Free all information allocated in a module_t structure.
 */
static void
free_module(module_t *mdl)
{
    char *arg;
    int i;

    free(mdl->name);
    if (mdl->description != NULL) 
	free(mdl->description);
    free(mdl->output);
    free(mdl->source);
    /* Merge the module's memory list into the CoMo main map.
     * We need to pause and resume the CAPTURE process to avoid conflicts */
    sup_send_ca_lock();
    mem_free_map(mdl->master_map);
    mem_free_map(mdl->mem_map);
    sup_send_ca_unlock();
    if (mdl->args) {
        i = 0;
        arg = mdl->args[i];
        while (arg != NULL) {
            free(arg);
            i++;
            arg = mdl->args[i];
        }
        free(mdl->args);
    }
    mdl->name = NULL;
    mdl->description = NULL;
    mdl->output = NULL;
    mdl->source = NULL;
    mdl->args = NULL;
}

/**
 * -- remove_module
 *
 */
void
remove_module(module_t *mdl)
{
    free_module(mdl);
    unload_object(mdl->cb_handle);
    bzero(mdl, sizeof(mdl));
    /* XXX if possible, decrease module_count */
    mdl->name = strdup("");
    mdl->status = MDL_UNUSED;
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
new_module(char *name, __unused char * opt)
{
    module_t * mdl; 

    /* allocate new module */
    mdl = safe_calloc(1, sizeof(module_t));
    mdl->name = strdup(name);
    mdl->description = NULL; 
    mdl->status = MDL_UNUSED; 

    /* set some default values */
    mdl->streamsize = DEFAULT_STREAMSIZE; 
    mdl->ex_hashsize = mdl->ca_hashsize = 1; 
    mdl->args = NULL;
    mdl->priority = 5;
    mdl->filter_str = strdup("all");
    mdl->filter_tree = NULL;
    mdl->output = strdup(mdl->name);
    asprintf(&mdl->source, "%s.so", mdl->name);

    return mdl;
}


/* 
 * -- commit_module 
 *
 * load the callbacks, check if the module configuration is 
 * correct and initialize its state. It returns the index in 
 * the module array where this module should go or -1 in case 
 * of error. 
 */
static int
commit_module(module_t * mdl, node_t * node)
{
    int i; 

    if (!load_callbacks(mdl)) {
	logmsg(LOGWARN, "cannot load callbacks module '%s'\n", mdl->name);
	return -1; 
    } 

    if (!check_module(mdl, node)) {
	logmsg(LOGWARN, "module '%s' incorrectly configured\n", mdl->name);
	unload_object(mdl->cb_handle);  /* unload callbacks */
	return -1;
    }

    /*
     * module loaded ok.
     * locate first unused entry in map.modules.
     */
    for (i = 0; i < map.module_count; i++) {
	if (map.modules[i].status == MDL_UNUSED) {
	    break;
	}
    }

    return i;
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
    static int scope = CTX_GLOBAL;      	/* scope of current keyword */
    static struct _node *node = &map.node;	/* node currently used */
    static module_t * mdl = NULL;       	/* module currently open */
    static int module_is_new;           	/* is the module new? */
    keyword_t *t;
    int i;

    /*
     * if configuring, we will panic, but during reconfiguration
     * just warn the user and try to continue
     */
#define warn_fn(...) \
    (cfg_state == CFGSTATE_CONFIG ? panic(__VA_ARGS__) : warnx(__VA_ARGS__))

    /*
     * run some checks on the token (i.e., that it exists
     * and that we have all the arguments it needs).
     */
    t = match_token(argv[0], keywords);
    if (t == NULL) {
        warn_fn("unknown token \"%s\"\n", argv[0]);
        return;
    }

    if (argc < t->nargs) {
	warn_fn("\"%s\", requires at least %d arguments\n", argv[0],
	      t->nargs);
        return;
    }

    /*
     * Check if the keyword is ok in the current scope.
     */
    if (!(t->scope & scope)) {
	warn_fn("\"%s\" out of scope\n", argv[0]);
        return;
    }
#undef warn_fn

    /*
     * Sometimes we are not interested in modules' config options.
     * This happens when we are configuring for 1st time and
     * when reading options for modules that are already loaded.
     */
    if (scope == CTX_MODULE) {
        if (cfg_state == CFGSTATE_CONFIG || !module_is_new) {
            if (t->action == TOK_END) /* if TOK_END, update scope */
                scope = CTX_GLOBAL;
            else                      /* otherwise, ignore token */
                logmsg(V_LOGDEBUG, 
		    "Ignoring module cfg token \"%s\"\n", argv[0]);
            return;
        }
    }

    /*
     * If reconfiguring, we are interested in modules only, so
     * in CTX_GLOBAL, ignore everything but TOK_MODULE.
     */
    if ((scope != CTX_MODULE) && (cfg_state == CFGSTATE_RECONFIG)) {
        if (t->action != TOK_MODULE) {
            logmsg(V_LOGDEBUG, "Ignoring module cfg unrelated token \"%s\"\n",
                argv[0]);
            return;
        }
    }

    /*
     * configuration actions
     */
    switch (t->action) {
    case TOK_BASEDIR:
	safe_dup(&map.basedir, argv[1]);
	break;

    case TOK_QUERYPORT:
	node->query_port = atoi(argv[1]);
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
	    int idx; 

	    idx = commit_module(mdl, node); 
 	    if (idx < 0) {
		free_module(mdl); /* free the module_t */
		free(mdl);
		scope = CTX_GLOBAL;
		break;
	    }

	    /*
	     * load module in that index
	     */
	    mdl = load_module(mdl, idx);
        
	    /*
	     * MDL_LOADING is a temporary status that is used by
	     * reconfigure() to recognize new modules in the modules
	     * array.
	     */
	    if (map.il_mode)
		map.il_module = mdl;
	    mdl->status = MDL_LOADING;
	    mdl->seen = 1;

	    logmsg(LOGUI, "... module %s [%d][%d] ", 
		   mdl->name, mdl->node, mdl->priority); 
	    logmsg(LOGUI, " filter %s; out %s (%uMB)\n", 
		   mdl->filter_str, mdl->output, mdl->streamsize/(1024*1024));
	    if (mdl->description != NULL) 
		logmsg(LOGUI, "    -- %s\n", mdl->description); 
	    scope = CTX_GLOBAL;
        } else if (scope == CTX_VIRTUAL) { 
	    map.virtual_nodes++;
	    node->id = map.virtual_nodes;
	    node = &map.node;
	    scope = CTX_GLOBAL; 
	}
	break;
	    

    case TOK_FILTER:
	if (scope == CTX_MODULE) {
            safe_dup(&mdl->filter_str, argv[1]);
        } else if (scope == CTX_VIRTUAL) { 
	    safe_dup(&node->filter_str, argv[1]);
	}
	break;

    case TOK_HASHSIZE:
        mdl->ex_hashsize = mdl->ca_hashsize = atoi(argv[1]);
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
	map.mem_size = atoi(argv[1]);
	if (map.mem_size <= 0 || map.mem_size > 512)
	    panic("invalid memory size %d, range is 1..512\n", map.mem_size);
        break;

    case TOK_MODULE:
        /*
         * check if this module name is known
         */
        for (i = 0; i < map.module_count; i++) {
            if (! strcmp(map.modules[i].name, argv[1]))
                break;
        }

        if (i == map.module_count) { /* not found, new module  */

            if (map.module_count == map.module_max) { /* too many modules */
                logmsg(LOGWARN, "too many modules. current limit is %d\n",
                        map.module_max); 
                module_is_new = 0;

            } else { /* new module */
                mdl = new_module(argv[1], (argc > 2)? argv[2] : NULL);
		mdl->node = node->id;
                module_is_new = 1;
            }

        } else { /* found, not a new module */
            map.modules[i].seen = 1;
            //mdl = &map.modules[i];
            module_is_new = 0;
        }
        /* change scope */
        scope = CTX_MODULE;
        break;
        
    case TOK_MODULE_MAX:
	map.module_max = atoi(argv[1]);
	map.modules = 
	    safe_realloc(map.modules, sizeof(module_t)*map.module_max); 
        break;

    case TOK_OUTPUT:
        safe_dup(&mdl->output, argv[1]);
	break;

    case TOK_SNIFFER:
	add_sniffer(argv[1], argv[2], argc > 3 ? argv[3] : NULL);
        break;

    case TOK_STREAMSIZE: 
	mdl->streamsize = parse_size(argv[1]);
	break;

    case TOK_MAXFILESIZE: 
	map.maxfilesize = parse_size(argv[1]); 
	if (map.maxfilesize > 1024*1024*1024) { 
	    map.maxfilesize = DEFAULT_FILESIZE; 
	    logmsg(LOGWARN, "'filesize' should be < 1GB --> set to %dMB\n", 
		   map.maxfilesize / (1024*1024));
	} 
	break;

    case TOK_ARGS:
	mdl->args = safe_calloc(argc, sizeof(char *));
	for (i = 1; i < argc; i++) {
	    safe_dup(&(mdl->args[i-1]), argv[i]);
	}

	/* 
	 * Last position is set to null to be able to know
	 * when args finish from the modules
	 */
	mdl->args[i-1] = NULL;
	break;
    
    case TOK_PRIORITY: 
        mdl->priority = atoi(argv[1]);
	break; 

    case TOK_NAME: 
        safe_dup(&node->name, argv[1]);
	break; 

    case TOK_LOCATION:
        safe_dup(&node->location, argv[1]);
	break; 

    case TOK_TYPE:
        safe_dup(&node->type, argv[1]);
	break; 

    case TOK_COMMENT: 
        safe_dup(&node->comment, argv[1]);
	break; 

    case TOK_VIRTUAL: 
	node = safe_calloc(1, sizeof(struct _node)); 
	node->next = map.node.next;
	map.node.next = node; 
        safe_dup(&node->name, argv[1]);
	scope = CTX_VIRTUAL; 
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
 * tells if we need to parse the default cfg file.
 * set by configure().
 */
static int need_default_cfgfile;


/*
 * -- parse_cmdline
 *
 * parses the command line options and fills in the "map" (global)
 * data structure.
 * The function first checks if a config file has been specified.
 * If not, it assumes we want the default one _before_ the rest of
 * the command line. Then it does the actual processing, in the order
 * specified by the command line.
 * This allows us to process multiple config files and override options
 * from either the command line or the config file.
 *
 */
int
parse_cmdline(int argc, char *argv[])
{
    struct _node * node;
    int c, n;
    DIR *d;

    /*
     * command line flags are here, so we put here the 'usage'
     * string as well...
     */
    static const char * usage =
 	   "usage: %s [-I] [-q args] [-c config_file] [-D basedir] "
           "[-L libdir] " "[-M module] [-O keyword[=value]]..].. [-m memsize] "
           "[-v logflags] [-x debug_opts] " "[-s sniffer] [-p query_port]\n";

    /* flag to be set if we parsed a configuration file */
    static const char *opts = "Iq:c:D:L:M:O:m:p:s:v:x:";

    /* tells wether we are configuring a module or not */
    int mod_conf = 0;

    /*
     * if needed, parse the default config file first
     */
    if (need_default_cfgfile)
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

    /*
     * parse command line options
     */
    while ((c = getopt(argc, argv, opts)) != -1) {
        switch(c) {
	case 'I':
            /* inline mode. if present, this option must be the first one */
            map.il_mode = 1;
            /* treat the module as if we were reconfiguring */
            cfg_state = CFGSTATE_RECONFIG;
            break;
        case 'q':
            /* this option is valid only if we are in inline mode */
            if (!map.il_mode)
                logmsg(LOGWARN, "cannot use -q before -I (ignoring)\n");
	    else
                safe_dup(&map.il_qargs, optarg);
            break;
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
		/* To define a module from command line, we use do_config().
		 *
		 * We need to start and end module configuration like done while
		 * parsing a configuration file, for do_config() to get all the
		 * context changes it expects.
		 *
		 * When we have -M, start a module definition.
		 */
		char *conf_argv[2];

		if (mod_conf) {
		    /* we were configuring a module, so notify end of module
		     * configuration before starting with the next */
		    static char *argv_end[] = { "end" };
		    do_config(1, argv_end);
		}

		/* prepare the arguments for do_config() */
		conf_argv[0] = "module";
		conf_argv[1] = optarg;

		do_config(2, conf_argv);	/* call do_config() */

		mod_conf = 1;	/* we are configuring a module */
	    }
	    break;

	case 'O':		/* module option. */
	    {
		/* To pass options to module configuration, we make sure
		 * we are in mod_conf, then set some argv to make do_config()
		 * do the actual work.
		 *
		 * XXX can only handle 1 arg now
		 */
		char *arg, *keyword, *conf_argv[3];
		int conf_argc;

		if (!mod_conf) {	/* we must be configuring a module */
		    logmsg(LOGWARN,
			   "cannot use -O before -M (ignoring)\n");
		    break;
		}

		/* prepare args for do_config() */
		keyword = optarg;
		arg = index(optarg, '=');	/* arg begins with first '=', if any */

		if (arg != NULL) {	/* if '=' found */
		    *arg = 0;	/* split keyword and arg */
		    arg++;	/* arg begins at the next character */
		    conf_argc = 2;	/* we have 1 keyword + 1 arg */
		} else
		    conf_argc = 1;	/* otherwise, we have 1 keyword and no arg */

		conf_argv[0] = keyword;
		conf_argv[1] = arg;	/* might be null */

		/* call do_config() */
		do_config(conf_argc, conf_argv);
	    }
	    break;

	case 'p':
	    map.node.query_port = atoi(optarg);
	    break;

        case 's':   /* sniffer */
            add_sniffer(optarg, NULL, NULL);
            break;

        case 'm':   /* capture/export memory usage */
            {
            int size = atoi(optarg);
	    if (size <= 0 || size > 512)
		warnx("ignoring invalid memory size %d, range is 1..512", size);
            else 
	        map.mem_size = size;
            }
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

    /* if we were doing module configuration, end it */
    if (mod_conf) {
	static char *argv_end[] = { "end" };
	do_config(1, argv_end);
    }

    /* 
     * open the basedir for all nodes (virtual ones included) 
     */
    for (node = &map.node; node; node = node->next) { 
	if (map.basedir == NULL)
	    panic("missing basedir");
	d = opendir(map.basedir);
	if (d == NULL) 
	    createdir(map.basedir); 
	else 
	    closedir(d);
    } 

    /* 
     * for each virtual node we have to replicate the 
     * list of modules. these new modules will have the 
     * same name but will be running the additional filter 
     * associated with the virtual node and save data in the 
     * virtual node basedir.  
     */
    n = map.module_count; 
    for (node = map.node.next; node != NULL; node = node->next) { 
	int i; 

	for (i = 0; i < n; i++) { 
	    module_t * mdl; 
	    int idx; 

	    /* allocate new module */
	    mdl = safe_calloc(1, sizeof(module_t));
     
	    /* copy all values and pointers. note that at this stage not NULL
	     * pointers are just the ones that point to constant strings that
	     * are shared among virtual copies of the same modules.
	     */
	    memcpy(mdl, &map.modules[i], sizeof(module_t));
            mdl->status = MDL_LOADING;
            mdl->seen = 1;
	    mdl->node = node->id;
	    
	    /* append node id to module's output file */
	    asprintf(&mdl->output, "%s-%d", mdl->output, mdl->node); 
	    
	    /* add the node filter to the module filter */
	    if (node->filter_str) {
		char * flt;
		if (!strcmp(mdl->filter_str, "all"))
		    asprintf(&flt, "%s", node->filter_str);
		else 
		    asprintf(&flt,"%s and (%s)", 
				node->filter_str, mdl->filter_str);
		mdl->filter_str = flt; 
	    } 

	    idx = commit_module(mdl, node);
	    mdl = load_module(mdl, idx);

            logmsg(LOGUI, "... module %-16s [node:%d]", mdl->name, mdl->node);
            if (mdl->description != NULL)
                logmsg(LOGUI,"[%s]\n", mdl->description);
            logmsg(LOGUI, 
		   "\n    - prio %d; filter %s; out %s (max %uMB)\n",
                   mdl->priority, mdl->filter_str, mdl->output,
                   mdl->streamsize / (1024*1024));
	}
    }

    return 0;
}

/*
 * we will save argc and argv here
 */
static int como_argc;
static char **como_argv;

/*
 * saved mtimes of config files. This list will be used
 * by reconfigure() to check if it is necessary to parse
 * cfgfiles again.
 */
typedef struct _cfgfile {
    char *file;    /* filename */
    time_t mtime;  /* mtime */
    struct _cfgfile *next; /* next cfg file */
} cfgfile_t;

static cfgfile_t *cfg_files = NULL;

/*
 * -- link_cfgfile
 *
 * Allocate a cfgfile_t and link into cfg_files.
 * Mtimes are set to 0.
 */
static void
link_cfgfile(char *file)
{
    cfgfile_t *cfg = safe_calloc(1, sizeof(cfgfile_t));
    cfg->file = file;
    cfg->mtime = 0;
    cfg->next = cfg_files;
    cfg_files = cfg;
}

/*
 * -- configure
 *
 * Build a list of relevant configuration file(s), check if
 * we need the default config file, then call parse_cmdline,
 * which will parse both the command line and cfgfiles.
 *
 * Modules are not loaded in this stage, but during re-configuration.
 *
 */
void
configure(int argc, char **argv)
{
    int c;

    cfg_state = CFGSTATE_CONFIG; /* configuring for the 1st time */

    como_argc = argc; /* save argc and argv */
    como_argv = argv;

    /*
     * build list of config files
     */
    opterr = 0;
    while ((c = getopt(argc, argv, "c:")) != -1)
        if (c == 'c')
            link_cfgfile(optarg);

    need_default_cfgfile = (cfg_files == NULL);

    if (need_default_cfgfile)
        link_cfgfile(DEFAULT_CFGFILE);

    parse_cmdline(argc, argv);

    cfg_state = CFGSTATE_RECONFIG; /* from now on we will be
                                      reconfiguring */
}

/*
 * -- reconfigure
 *
 * Runtime re-configuration. Only module loading / unloading
 * is done here. This function must be called only when
 * we have all sockets from CA, EX and ST to SU open,
 * because it relies on interprocess communication.
 * The first time this function is being called, it loads
 * all modules.
 */
void
reconfigure(void)
{
    static int first_reconfig = 1;
    int idx, need_parse, have_new_modules;
    cfgfile_t *cfg;

    need_parse = 0;
    for (cfg = cfg_files; cfg != NULL; cfg = cfg->next) {
        struct stat st;

        if (stat(cfg->file, &st)) {
            /*
             * stop here. Continuing can be dangerous
             * because of some config file missing, so
             * we'll keep going with current configuration.
             */
            logmsg(LOGWARN, "reconfiguration aborted. stat on cfgfile "
                    "\"%s\" failed (%s)\n", cfg->file, strerror(errno));
            return;
        }

        /*
         * update mtimes of config files. If some mtime differs,
         * will need to re-parse.
         */
        if (cfg->mtime != st.st_mtime) {
            need_parse = 1;           /* need to re-parse cmdline */
            cfg->mtime = st.st_mtime; /* save new mtime */
        }
    }

    if (!need_parse)
        return;

    logmsg(LOGDEBUG, "Reconfiguration: re-parsing cfgfile\n");

    /*
     * mark modules as unseen. during parsing of cfgfiles,
     * modules will be marked seen.
     */
    for (idx = 0; idx < map.module_count; idx++)
        map.modules[idx].seen = 0;

    /*
     * do the actual re-parsing
     */
    parse_cmdline(como_argc, como_argv);

    /*
     * first check what modules must be removed
     * and if we have new modules.
     * new modules are those whose status is MDL_LOADING.
     */
    have_new_modules = 0;
    for (idx = 0; idx < map.module_count; idx++) {
        module_t *mdl = &map.modules[idx];

        if (mdl->status == MDL_LOADING)
            have_new_modules = 1;

        if (mdl->seen == 0 && mdl->status != MDL_UNUSED) {
            logmsg(LOGUI, "... removing module '%s'\n", mdl->name);
            if (mdl->status == MDL_ACTIVE)
                map.stats->modules_active--;
            mdl->status = MDL_UNUSED;
            sup_send_module_status(); /* TODO do only one send_module_status() */
            remove_module(mdl);
        }
    }

    /*
     * if no new modules, we are done, except if this is
     * the first reconfiguration. At first reconfiguration
     * we send the new modules anyway, because CA needs
     * loading them before entering its mainloop.
     */
    if ((! have_new_modules) && (! first_reconfig)) {
        logmsg(LOGDEBUG, "Reconfiguration: No new modules are found\n");
        return;
    }

    /*
     * tell processes to load the new modules.
     */
    if (sup_send_new_modules() < 0) { /* failed */
        logmsg(LOGUI, "Failed to load new modules, going back to old cfg\n");

        /* forget about modules */
        for (idx = 0; idx < map.module_count; idx++) {
            module_t *mdl = &map.modules[idx];

            if (mdl->status == MDL_LOADING)
                remove_module(mdl);
        }

        return; /* done */
    }

    /*
     * modules that were in MDL_LOADING status
     * are now active.
     */
    for (idx = 0; idx < map.module_count; idx++) {
        module_t *mdl = &map.modules[idx];

        if (mdl->status == MDL_LOADING) {
            mdl->status = MDL_ACTIVE;
            map.stats->modules_active++;
        }
    }

    first_reconfig = 0;
}

