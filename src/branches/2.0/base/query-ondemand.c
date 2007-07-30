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

#include <sys/types.h>		/* fork */
#include <unistd.h>		/* fork */
#include <sys/types.h>          /* wait */
#include <sys/wait.h>           /* wait */
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <err.h>
#include <errno.h>

#include "como.h"
#include "comopriv.h"
#include "query.h"

/* config 'inherited' from supervisor */
extern como_config_t *como_config;

#if DEBUG
/*
 * -- escape_quotes
 *
 * escape quotes of input string. returns
 * a dynamically allocated output string.
 * the func is sub-optimal but we don't care
 * as this is just for debugging.
 */
char *
escape_quotes(char *input)
{
    size_t s, i, j, final_len;
    char *output;

    s = strlen(input);
    final_len = s;

    for (i = 0; i < s; i++)
        if (input[i] == '\\' || input[i] == '"')
            final_len++;

    output = como_malloc(final_len + 1);

    for (i = j = 0; i < s; i++) {
        if (input[i] == '\\' || input[i] == '"')
            output[j++] = '\\';
        output[j++] = input[i];
    }
    output[j++] = '\0';

    return output;
}

#endif

void 
query_ondemand(UNUSED int fd, qreq_t * req, UNUSED int node_id) 
{
    char *my_argv[128], *mdl_code = NULL;
    mdl_def_t *def;
    int i;
    char *buffer;
    #ifdef DEBUG 
    char debugbuf[1024 * 10];
    #endif
    hash_iter_t it;

    /*
     * search the on-demand module in the module definitions
     */
    def = config_get_module_def_by_name(como_config, req->module);
    if (def == NULL)
        error("module `%s' not found\n", req->module);
    mdl_code = def->mdlname;

    i = 0; /* prepare the arguments to re-exec as an inline query */
    my_argv[i++] = como_config->como_executable_full_path;
    my_argv[i++] = "-D";
    my_argv[i++] = como_config->db_path;
    my_argv[i++] = "-L";
    my_argv[i++] = como_config->libdir;
    my_argv[i++] = "-t";
    my_argv[i++] = como_config->storage_path;

    my_argv[i++] = "-C"; /* add the definition for the ondemand mdl */
    
    buffer = como_malloc(8 * 1024);
    sprintf(buffer, "module \"%s\" source \"%s\"", req->module, mdl_code);

    hash_iter_init(req->args, &it);
    while (hash_iter_next(&it)) {
        strcat(buffer, " args \"");
        strcat(buffer, hash_iter_get_string_key(&it));
        strcat(buffer, "\" = \"");
        strcat(buffer, hash_iter_get_value(&it));
        strcat(buffer, "\"");
    }
    strcat(buffer, " end");
    my_argv[i++] = buffer;

    my_argv[i++] = "-i"; /* do an inline execution of the mdl */

    buffer = como_malloc(8 * 1024);
    sprintf(buffer, "%s?format=%s", req->module, req->format);

    hash_iter_init(req->args, &it);
    while (hash_iter_next(&it)) {
        strcat(buffer, "&");
        strcat(buffer, hash_iter_get_string_key(&it));
        strcat(buffer, "=");
        strcat(buffer, hash_iter_get_value(&it));
    }
    my_argv[i++] = buffer;

    my_argv[i++] = "-s"; /* with the appropriate input sniffer */
    my_argv[i++] = como_asprintf("como,http://localhost:%d/%s"
                                    "?format=como&start=%d&end=%d&wait=%s",
                                    como_config->query_port,
                                    req->source,
                                    req->start,
                                    req->end,
                                    req->wait ? "yes" : "no");

    my_argv[i++] = NULL; /* end of args */

#if DEBUG
    debug("running inline como to attend query:\n");
    debugbuf[0] = '\0';
    for (i = 0; my_argv[i] != NULL; i++) {
        char *tmp = escape_quotes(my_argv[i]);
        strcat(debugbuf, " ");
        if (strpbrk(tmp, " &"))
            strcat(debugbuf, "\"");
        strcat(debugbuf, tmp);
        if (strpbrk(tmp, " &"))
            strcat(debugbuf, "\"");
        free(tmp);
    }
    debug("command = %s\n", debugbuf);
#endif

    dup2(fd, 1); /* attach stdout to socket */

    i = execvp(my_argv[0], my_argv); /* run inline query */
    error("execvp() error\n");
}

