/*
 * Copyright (c) 2005 Universitat Politecnica de Catalunya
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
 * LIABILITY, OR TORT INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id$
 */

/*
 * Author: Josep Sanjuas Cuxart (jsanjuas@ac.upc.es)
 */ 

#include <string.h>     /* strlen */
#include <sys/time.h>   /* FD_SET */
#include <sys/types.h>
#include <unistd.h>

#include "como.h"

extern struct _como map;

enum msg_ids {
    MSG_NEW_MODULES = 7,
    MSG_MDL_STATUS,
    MSG_STRING,
    MSG_ACK
};

/*
 * Macros to read and write strings and vars to a socket.
 *
 * The macros return 0 if ok, != 0 if error.
 */
#define write_var(fd, var) \
    (como_writen(fd, (char *) &(var), sizeof(var)))

#define read_var(fd, var) \
    (como_readn(fd, (char *) &(var), sizeof(var)))

__inline__ static int
write_str(int fd, char *str)
{
    int len = (int) strlen(str) + 1;
    if (sizeof(len) != write_var(fd, len))
        return -1; /* err */
    if (como_writen(fd, str, len) != len)
        return -1; /* err */
    return 0;      /* ok */
}

__inline__ static int
read_str_(int fd, char **str)
{
    int len;
    if (sizeof(len) != read_var(fd, len))
        return -1; /* err */
    *str = safe_calloc(1, len);
    if (como_readn(fd, *str, len) != len)
        return -1; /* err */
    return 0;      /* ok */
}

#define read_str(fd, str) read_str_(fd, &(str))

/*
 * 'safe' communication macros. If any operation
 * fails, panic. They are used by all procs but su.
 */
#define IPC_PANIC_REASON "Lost communication to supervisor"

#define safe_read_var(fd, var)          \
    do {                                \
        if (sizeof(var) != read_var(fd, var))          \
            panic(IPC_PANIC_REASON);    \
    } while(0);

#define safe_read_str(fd, str)          \
    do {                                \
        if (read_str(fd, str))          \
            panic(IPC_PANIC_REASON);    \
    } while(0);

#define safe_write_str(fd, str)         \
    do {                                \
        if (write_str(fd, str))         \
            panic(IPC_PANIC_REASON);    \
    } while(0);

#define safe_write_var(fd, var)         \
    do {                                \
        if (sizeof(var) != write_var(fd, var))         \
            panic(IPC_PANIC_REASON);    \
    } while(0);

/*
 * Communication functions.
 *
 * This communication is between supervisor and other processes.
 * They are used to communicate about:
 *
 *  - changes in the states of modules
 *  - removal of modules
 *  - insertion of a new module
 *
 * In order to make code as readable as possible, the following function
 * naming policy has been used:
 *
 * Functions that are to be called from supervisor begin with sup_,
 * while functions that are to be called from other processes don't.
 * Functions to send messages contain the particle send_, while functions
 * to receive messages contain recv_.
 *
 *
 * Each message begins with a message id, which identifies the type
 * of message.  The main functions to receive messages are sup_recv_message
 * and recv_message. They read the message id and call the appropiate
 * function for that particular type of message.
 *
 * Summing up, we have:
 *
 * - Functions to register core processes' file descriptors
 *      register_ipc_fd(int fd)
 *      unregister_ipc_fd(int fd)
 *
 * - Functions to send messages
 *      sup_send_new_modules(void)
 *      sup_send_module_status(void)
 *      send_string(char *str)
 *      send_ack(void)
 *
 * - Functions to receive messages
 *      sup_recv_message(int fd)
 *      sup_wait_for_ack(int fd)
 *      recv_message(int fd, proc_callbacks_t *callbacks)
 *
 * - Functions to process incoming messages
 *      recv_new_modules(int fd, proc_callbacks_t *callbacks)
 *      recv_module_status(int fd, proc_callbacks_t *callbacks)
 *
 * Exception handling:
 *
 * If supervisor fails at sending or receiving a message, don't care.
 * When the other processes detect failure communicating to supervisor,
 * they will panic, and supervisor will notice about that. So, here
 * we try to keep this code simple and let supervisor handle process
 * crashes elsewhere.
 *
 */


/*
 * Functions to register core processes' fds. These are the descriptors
 * that supervisor will be sending messages to.
 */
static fd_set proc_fds;
static int min_proc_fd, max_proc_fd;

void
ipc_init(void)
{
    FD_ZERO(&proc_fds);
    max_proc_fd = 0;
    min_proc_fd = 1024;
}

void
register_ipc_fd(int fd)
{
    FD_SET(fd, &proc_fds);

    if (fd > max_proc_fd)
        max_proc_fd = fd + 1;
    if (fd < min_proc_fd)
        min_proc_fd = fd;

    logmsg(LOGDEBUG, "ipc: registered fd %d\n", fd);
}

void
unregister_ipc_fd(int fd)
{
   FD_CLR(fd, &proc_fds);
   logmsg(LOGDEBUG, "ipc: unregistered fd %d\n", fd);
}

#define is_registered_fd(fd) FD_ISSET((fd), &proc_fds)


/**
 * -- sup_send_new_modules
 *
 * Tell core processes to load new modules. The map.modules
 * array will be scanned, and modules whose status is MDL_LOADING
 * will be sent to core processes.
 *
 * There is an optimization here. Capture needs a new filter function
 * when new modules are to be loaded. Instead of sending the new
 * modules and expecting capture to build itself a new filter, here
 * (as supervisor) we build it and send the shared object's filename
 * for capture to link it.
 *
 */
void
sup_send_new_modules(void)
{
    char msg_id;
    int idx, i;

    free(map.filter);
    map.filter = create_filter(map.modules, map.module_count,
            map.template, map.workdir);

    msg_id = MSG_NEW_MODULES;

    for (i = min_proc_fd; i < max_proc_fd; i++) {
        if (! is_registered_fd(i))
            continue;

        logmsg(LOGDEBUG, "writing new modules to fd %d\n", i);
        write_var(i, msg_id);
        write_str(i, map.filter);

        for(idx = 0; idx < map.module_count; idx++) {
            module_t *mdl = &map.modules[idx];
            int narg;

            if (mdl->status != MDL_LOADING)
                continue;

            write_var(i, idx);
            como_writen(i, (char *)mdl, sizeof(module_t));
            write_str(i, mdl->name);
            write_str(i, mdl->description);
            write_str(i, mdl->filter);
            write_str(i, mdl->output);
            write_str(i, mdl->source);

            narg = 0; /* count args */
            if (mdl->args)
                for (narg = 0; mdl->args[narg] != NULL; narg++);
            write_var(i, narg);

            if (mdl->args)
                for (narg = 0; mdl->args[narg] != NULL; narg++)
                    write_str(i, mdl->args[narg]);

            logmsg(LOGDEBUG, "sent module '%s'\n", mdl->name);
        }

        idx = -1;
        write_var(i, idx); /* end of message */
    }

    logmsg(LOGDEBUG, "sent new modules to all procs\n");
}

/**
 * -- sup_send_module_status
 *
 * Tell core processes that modules' status are,
 * so that they can update their information
 * and react to status changes.
 *
 * This function is sychronous, and
 * will only return when all processes have received
 * the message and sent back MSG_ACK in response.
 *
 * This function does not send info
 * for modules whose status is MDL_LOADING.
 */
void
sup_send_module_status(void)
{
    char msg_id = MSG_MDL_STATUS;
    int i, idx;

    logmsg(LOGDEBUG, "Updating module status\n");

    for (i = min_proc_fd; i < max_proc_fd; i++) {

        if (! is_registered_fd(i))
            continue;

        if (sizeof(msg_id) != write_var(i, msg_id)) {
            logmsg(LOGWARN, "Lost communication to fd %d\n", i);
            unregister_ipc_fd(i);
            continue;
        }

        if (sizeof(map.module_count) != write_var(i, map.module_count)) {
            logmsg(LOGWARN, "Lost communication to fd %d\n", i);
            unregister_ipc_fd(i);
            continue;
        }

        for (idx = 0; idx < map.module_count; idx++) {

            if (map.modules[idx].status == MDL_LOADING)
                continue;

            if (sizeof(idx) != write_var(i, idx)) {
                logmsg(LOGWARN, "Lost communication to fd %d\n", i);
                unregister_ipc_fd(i);
                break;
            }

            if (sizeof(map.modules[idx].status) !=
                    write_var(i, map.modules[idx].status)) {
                logmsg(LOGWARN, "Lost communication to fd %d\n", i);
                unregister_ipc_fd(i);
                break;
            }
        }

        idx = -1;
        write_var(i, idx); /* end of message is -1 XXX XXX we have a counter too */
    }

    for (i = min_proc_fd; i < max_proc_fd; i++) {
        if (! is_registered_fd(i))
            continue;

        sup_wait_for_ack(i);
    }
}

/**
 * -- send_string
 *
 * Send a string. This function is used by modules to send
 * logmsg's to supervisor, that will actually display them.
 * TODO We need to be sure that write() will not be locking to 
 * prevent a deadlock possibility.
 */
void
send_string(char *str)
{
    char msg_id = MSG_STRING;
    /*
     * cannot send a debug msg here, that would create
     * an endless loop.
     */
    safe_write_var(map.supervisor_fd, msg_id);
    safe_write_str(map.supervisor_fd, str);
}

/**
 * -- send_ack
 *
 * An ack message is used tell supervisor that a message
 * has been received and processed. This is useful when
 * supervisor needs to make sure a message has been received
 * by other processes.
 */
void
send_ack(void)
{
    char msg_id = MSG_ACK;
    logmsg(V_LOGDEBUG, "Send ack to supervisor\n");
    safe_write_var(map.supervisor_fd, msg_id);
}

/**
 * -- sup_recv_message
 *
 * Function that handles messages received by supervisor.
 * Returns msg_id if correctly received a message.
 * Returns < 0 on error
 */
int
sup_recv_message(int fd)
{
    char msg_id;

    logmsg(V_LOGDEBUG, "Receive message from fd %d\n", fd);

    if (sizeof(msg_id) != read_var(fd, msg_id))
        return -1;

    logmsg(V_LOGDEBUG, "Message type is %d\n", msg_id);
    
    switch(msg_id) {
        case MSG_ACK:
            break;
        case MSG_STRING:
            {
                char *str;
                if (read_str(fd, str))
                    return -1;
                logmsg(LOGUI, "%s", str);
                free(str);
            }
            break;
        default:
            return -1;
    }

    logmsg(V_LOGDEBUG, "Message successfully handled\n");
    return msg_id;
}

/**
 * -- sup_wait_for_ack
 *
 * Function that receives and processes messages, and
 * keeps looping until an ack is received.
 */
void
sup_wait_for_ack(int fd)
{
    char msg_id;

    logmsg(V_LOGDEBUG, "Awaiting ack from fd %d\n", fd);
    do {
        msg_id = sup_recv_message(fd);
        if (msg_id < 0) {
            logmsg(V_LOGDEBUG, "sup_wait_for_ack fails");
            return;
        }
    } while (msg_id != MSG_ACK);
    logmsg(V_LOGDEBUG, "Ack from fd %d received\n", fd);
}

/**
 * -- recv_new_modules
 *
 * Called from recv_message by processes when supervisor
 * requests loading a new module.
 */
static void
recv_new_modules(int fd, proc_callbacks_t *callbacks)
{
    logmsg(LOGDEBUG, "Loading new modules / filter function\n");

    free(map.filter);
    safe_read_str(fd, map.filter);

    if (callbacks->filter_init)
        callbacks->filter_init(map.filter);

    logmsg(LOGDEBUG, "Filter functions loaded\n");

    for(;;) {
        module_t *mdl;
        int narg, arg, idx;

        safe_read_var(fd, idx); /* index of the module */

        if (idx == -1) /* end of message */
            break;

        /* read the module */
        mdl = safe_calloc(1, sizeof(module_t));
        safe_read_var(fd, *mdl);
        safe_read_str(fd, mdl->name);
        safe_read_str(fd, mdl->description);
        safe_read_str(fd, mdl->filter);
        safe_read_str(fd, mdl->output);
        safe_read_str(fd, mdl->source);

        read_var(fd, narg);
        if (narg > 0) {
            mdl->args = safe_calloc(narg + 1, sizeof(char *));
            for (arg = 0; arg < narg; arg++)
                read_str(fd, mdl->args[arg]);
            mdl->args[arg] = NULL;
        }

        /* insert the module */
        load_callbacks(mdl);
        mdl = load_module(mdl, mdl->index);

        /* initialize */
        mdl->status = MDL_ACTIVE;
        if (callbacks->module_init)
            callbacks->module_init(mdl);

        logmsg(LOGDEBUG, "module loaded: '%s'\n", mdl->name);
    }
}

/**
 * -- recv_module_status
 *
 * Called by processes when supervisor asks to update
 * status of modules. Supervisor expects a confirmation,
 * send an ack when done.
 */
static void
recv_module_status(int fd, proc_callbacks_t *callbacks)
{
    module_t *mdl;
    int idx, count;
    uint new_status;

    safe_read_var(fd, count);

    for (;;) {
        safe_read_var(fd, idx);
        if (idx == -1) /* end of message */
            break;

        safe_read_var(fd, new_status);
        mdl = &map.modules[idx];

        if (mdl->status == new_status)
            continue;

        if (new_status == MDL_DISABLED) {
            logmsg(LOGWARN, "disabling module %s\n", mdl->name);
            /* XXX XXX active-- */
            if (callbacks->module_disable != NULL)
                callbacks->module_disable(mdl);
        }

        else if (new_status == MDL_ACTIVE) {
            logmsg(LOGWARN, "enabling module %s\n", mdl->name);
            if (callbacks->module_enable)
                callbacks->module_enable(mdl);
        }

        else if (new_status == MDL_UNUSED) {
            logmsg(LOGWARN, "removing module %s\n", mdl->name);
            if (callbacks->module_remove)
                callbacks->module_remove(mdl);
            remove_module(mdl);
        }

        mdl->status = new_status;
    }
    send_ack();
}

/**
 * -- recv_message
 *
 * Receive a message from supervisor and do whatever needed.
 * If there is no message to read, locks on the fd until something
 * is received.
 */
void
recv_message(int fd, proc_callbacks_t *callbacks)
{
    char msg_id;

    logmsg(V_LOGDEBUG, "message from supervisor\n");

    safe_read_var(fd, msg_id);
    
    logmsg(LOGDEBUG, "message from supervisor, type %d\n", msg_id);

    switch(msg_id) {
        case MSG_NEW_MODULES:
            recv_new_modules(fd, callbacks);
            break;
        case MSG_MDL_STATUS:
            recv_module_status(fd, callbacks);
            break;
        default: /* should never be reached */
            logmsg(LOGWARN, "an unknown message type was received from supervisor\n");
    }
}
 
