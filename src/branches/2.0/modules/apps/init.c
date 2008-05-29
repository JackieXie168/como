/*
 * Copyright (c) 2004-2008, Intel Corporation
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

#include <ctype.h>  /* isspace */
#include "como.h"
#include "data.h"

config_t *
init(mdl_t *self, hash_t *args)
{
    config_t *config;
    char *val;

    config = mdl_alloc_config(self, config_t);
    config->meas_ivl = 1;

    /*
     * add a class for unknown TCP/UDP traffic and an other
     * for all IP packets that are not TCP nor UDP.
     */
    config->names[0] = "unknown";
    config->names[1] = "Not TCP/UDP";
    config->classes = 2;

    if ((val = hash_lookup_string(args, "classes"))) {
        char *defn, *saveptr1;

        defn = strtok_r(val, "\n", &saveptr1);

        while(defn) { /* defn has the form name=proto port,proto port.. */
            char *name, *port_def, *saveptr2;

            if (config->classes >= CLASSES_MAX) {
                warn("error parsing configuration of module apps: "
                        "max amount of traffic classes (%d) reached\n",
                        CLASSES_MAX);
                break;
            }

            name = strtok_r(defn, "=", &saveptr2); /* get 1st tok until = */

            while (isspace(*name)) /* skip spaces */
                name++;

            /* copy the name of the class */
            config->names[config->classes] = mdl_malloc(self, strlen(name) + 1);
            strcpy(config->names[config->classes], name);

            /* get the ports. 1st port is mandatory */
            port_def = strtok_r(NULL, ",", &saveptr2);
            if (port_def == NULL) {
                warn("error parsing configuration of module apps: "
                        "no ports given for class `%s'\n", name);
                break;
            }

            while (port_def) { /* get successive proto-port pairs */
                char *proto, *port_str, *saveptr3;
                int port;

                proto = strtok_r(port_def, " ", &saveptr3);
                port_str = strtok_r(NULL, "", &saveptr3);

                if (port_str == NULL) {
                    warn("error parsing configuration of module apps: "
                            "class=proto port,proto port.. expected\n");
                    break;
                }

                port = atoi(port_str);

                if (port < 0 || port >= PORT_MAX)
                    warn("error parsing configuration of module apps: "
                            "protocol number %d is invalid\n", port);
                else if (!strcasecmp(proto, "tcp"))
                    config->tcp_port2app[port] = config->classes;
                else if (!strcasecmp(proto, "udp"))
                    config->udp_port2app[port] = config->classes;
                else
                    warn("parsing configuration of module apps: "
                            "invalid protocol `%s'\n", proto);

                port_def = strtok_r(NULL, ",", &saveptr2); /* next proto-port */
            }
                
            config->classes++;
            defn = strtok_r(NULL, "\n", &saveptr1);
        }
    }

    self->flush_ivl = TIME2TS(config->meas_ivl, 0);

    return config;
}

