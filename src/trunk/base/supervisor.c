/*
 * Copyright (c) 2004, Intel Corporation
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
#include <unistd.h>     /* mkstemp */
#include <sys/wait.h>	/* wait3() */
#include <string.h>     /* bzero */
#include <errno.h>      /* errno */

#include "como.h"
#include "storage.h"
#include "query.h"	// XXX query_ondemand();

/* global state */
extern struct _como map;

struct _child_info_t {
    char *name;
    pid_t pid;
};

static struct _child_info_t my_children[10];


/*
 * -- start_child 
 * 
 * fork a child with the given function and process name.
 * If 'procname' is NULL then don't fork, as this is the supervisor.
 * The last argument is an optional fd to be passed to the program.
 */
pid_t
start_child(char *name, char *procname, void (*mainloop)(int fd), int fd)
{
    pid_t pid;
    u_int i;

    /* find a slot for the child */
    for (i=0; i < sizeof(my_children); i++)
	if (my_children[i].name == NULL)
	    break;
    if (i == sizeof(my_children)) {
	fprintf(stderr, "--- cannot create child %s, no more slots\n", name);
	exit(1); /* XXX do proper cleanup */
    }

    my_children[i].name = name;
    if (procname == NULL) {
	/* i am the supervisor. */
	pid = getpid();
    /* Print log messages on the terminal */
    map.supervisor_fd = -1;
	logmsg(LOGWARN, "starting process %-20s pid %d\n", name, pid); 
	my_children[i].pid = pid;
	mainloop(fd);
	exit(0);
    }

    /* ok, fork a regular process and return pid to the caller. */
    pid = fork();
    if (pid == 0) {	/* child */
	char *buf;

	/* XXX TODO: close unneeded sockets */
	map.procname = procname;
	map.supervisor_fd = create_socket("supervisor.sock", NULL);

	/* XXX should close all unused descriptors */
	// fclose(stdout); // XXX
	// fclose(stderr); // XXX

	logmsg(LOGWARN, "starting process %-20s pid %d\n", name, getpid()); 

	asprintf(&buf, "%s", name);
	setproctitle(buf);
	free(buf);

	if (map.debug) {
	    if (strstr(map.debug, map.procname) != NULL) {
		logmsg(LOGWARN, "waiting 60s for the debugger to attach\n");
		sleep(60);
		logmsg(LOGWARN, "wakeup, ready to work\n");
	    }
	}
	mainloop(fd);
	exit(0);
    }
    my_children[i].name = name;
    my_children[i].pid = pid;
    
    return pid;
}


#if 0
/*
 * -- echo_log_msgs()
 *
 * Read log messages from the indicated socket and print them on the local
 * terminal using logmsg()
 * 
 * Return 0 on success, >0 in case of failure.
 *
 */
static int 
echo_log_msgs(int fd, FILE * logfile) 
{
    static char buf[4097];
    int overflow = 0;
    int pos = 0;
    int nread = 0;

    /* 
     * Loop as long as we have a partially-read log message to 
     * process. 
     */
    do {
        bzero(buf, sizeof(buf));

        /* 
	 * Make sure the buffer is NULL-terminated by leaving a
         * NULL at the end 
	 */
        nread = read(fd, buf, sizeof(buf) - 1);
        if (nread <= 0) {     /* end of file on a socket ? */
            logmsg(LOGWARN, "reading fd[%d] got %d (%s)\n",
                fd, nread, strerror(errno));
            return 1;
        }

        logmsg(V_LOGDEBUG, "message(s) from fd[%d] (%d bytes)\n", fd, nread);

        /*
	 * Walk through the buffer, printing out messages.
	 * Note that it's safe to read nread + 1 into the
         * buffer because we added an extra byte at the end
         * of the buffer. 
	 */
        for (pos = 0; pos <= nread; pos += strlen(buf + pos) + 1) {
            logmsg(LOGUI, "%s", buf + pos);
	    if (logfile != NULL) 
		fprintf(logfile, "%s", buf + pos); 
	} 

        /* Did we chop a log message in half? */
        overflow = (pos == nread);

    } while (overflow);

    return 0;
}
#endif

/* 
 * -- handle_children
 * 
 * Waits for children that have terminate and reports on the 
 * exit status. 
 */
static void
handle_children(void)
{
    u_int j;
    char *name = "unknown";
    pid_t pid;
    int statbuf; 

    pid = wait3(&statbuf, WNOHANG, NULL);
    if (pid <= 0)
	return;
    for (j = 0; j < sizeof(my_children); j++) {
	if (my_children[j].pid == pid) {
	    name = my_children[j].name;
	    my_children[j].name = NULL;
	    break;
	}
    }

    if (j == sizeof(my_children)) { 
	/* this must be a query-ondemand */
	logmsg(V_LOGWARN, "query terminated\n");
	return; 
    } 

    if (WIFEXITED(statbuf)) 
	logmsg(LOGWARN, "WARNING!! process %d (%s) terminated (status: %d)\n",
	    pid, name, WEXITSTATUS(statbuf)); 
    else if (WIFSIGNALED(statbuf)) 
	logmsg(LOGWARN, "WARNING!! process %d (%s) terminated (signal: %d)\n",
	    pid, name, WTERMSIG(statbuf));
    else 
	logmsg(LOGWARN, "WARNING!! process %d (%s) terminated (unknown!!)\n", 
	    pid, name); 
}


/*
 * -- supervisor_mainloop
 * 
 * Basically mux incoming messages and show them to the console.
 * Also take care of processes dying. XXX update this comment
 */
void
supervisor_mainloop(int accept_fd)
{
    fd_set valid_fds;
    int max_fd;
    int client_fd;	/* for http queries */
    int num_procs;
    char *buf;
    FILE * logfile;
    
    /* 
     * open log file 
     */
    logfile = fopen("/tmp/como.log", "w"); 
    if (logfile == NULL)
	panic("opening /tmp/como.log"); 

    /* 
     * Start listening for query requests.
     */
    asprintf(&buf, "S:http://localhost:%d/", map.query_port);
    client_fd = create_socket(buf, NULL);
    if (client_fd < 0)
        panic("creating the socket %s: %s\n", buf, strerror(errno));
    free(buf);

    max_fd = 0;
    num_procs = 0;
    FD_ZERO(&valid_fds);
    max_fd = add_fd(accept_fd, &valid_fds, max_fd);
    max_fd = add_fd(client_fd, &valid_fds, max_fd);

    /*
     * initialize resource management and
     * interprocess communication
     */
#ifdef RESOURCE_MANAGEMENT
    resource_mgmt_init();
#endif
    ipc_init();

    for (;;) { 
        int secs, dd, hh, mm, ss;
	struct timeval now;
    /* XXX Resource management needs this timer to be small so supervisor
     * can wake up more frequently and look at the resources used, reacting
     * in time to any sudden changes in resource usage.
     */
#ifdef RESOURCE_MANAGEMENT
	struct timeval to = { 0, 50000 }; /* 0.05 sec */
#else
	struct timeval to = { 1, 0 }; /* fire every second */
#endif
	int i, n_ready;
	fd_set r = valid_fds;


	/* 
         * user interface. just one line... 
         */
	gettimeofday(&now, NULL);
	secs = 1 + now.tv_sec - map.stats->start.tv_sec; 
 	dd = secs / 86400; 
        hh = (secs % 86400) / 3600; 
        mm = (secs % 3600) / 60;
        ss = secs % 60; 

	fprintf(stderr, 
	    "\r- up %dd%02dh%02dm%02ds; mem %u/%u/%uMB (%d); "
	    "pkts %llu drops %d; mdl %d/%d\r", 
	    dd, hh, mm, ss,
	    map.stats->mem_usage_cur/(1024*1024), 
	    map.stats->mem_usage_peak/(1024*1024), 
	    map.mem_size, map.stats->table_queue, 
	    map.stats->pkts, map.stats->drops,
	    map.stats->modules_active, map.module_count); 

	n_ready = select(max_fd, &r, NULL, NULL, &to);
	fprintf(stderr, "%78s\r", ""); /* clean the line */

	for (i = 0; n_ready > 0 && i < max_fd; i++) {
	    if (!FD_ISSET(i, &r))
		continue;

	    n_ready--;
	    if (i == accept_fd) {
		int x;
		logmsg(V_LOGDEBUG, "accept on socket %d\n", i);
		x = accept(i, NULL, NULL);
		logmsg(V_LOGDEBUG,
		    "accept done on socket %d returns %d\n", i, x);
		if (x < 0)
		    logmsg(LOGWARN, "accept fd[%d] got %d (%s)\n",
			    i, x, strerror(errno));
		else {
            if (num_procs < 3) {
                /* XXX ugly hack. only add to proc_fds the first 3
                 * processes that connect to supervisor. they will be
                 * CA, EX or ST in no particular order. queries' fds
                 * don't belong into proc_fds.
                 */
                num_procs++;
                register_ipc_fd(x); //XXX XXX
            }
		    max_fd = add_fd(x, &valid_fds, max_fd);
		    logmsg(V_LOGDEBUG, "accept fd[%d] ok new desc %d\n", i, x);
		}
		continue;
	    }

	    if (i == client_fd) { 
		struct sockaddr_in addr;
		socklen_t len;
		int cd;
		pid_t pid;
	    
		len = sizeof(addr);
		cd = accept(client_fd, (struct sockaddr *)&addr, &len); 
		if (cd < 0) {
		    /* check if accept was unblocked by a signal */
		    if (errno == EINTR)
			continue;

		    logmsg(LOGWARN, "accepting connection: %s\n",
			    strerror(errno));
		}

		logmsg(LOGQUERY, 
		       "query from %s on fd %d\n", 
		       inet_ntoa(addr.sin_addr), cd); 

		/* fork a process to serve the query */
		pid = fork(); 	
		if (pid < 0) 
		    logmsg(LOGWARN, "fork query-ondemand: %s\n",
				strerror(errno));

		if (pid == 0) {	/* here is the child... */
		    for (i=0; i < max_fd; i++)
			if (i != cd)
			    close(i);
		    query_ondemand(cd); 
		    exit(EXIT_SUCCESS); 
		} else	/* parent */
		    close(cd);
		continue;
	    }

	    /* receive & process messages */
        if (sup_recv_message(i) < 0) {
            close(i);
            del_fd(i, &valid_fds, max_fd);
            unregister_ipc_fd(i);
        }
        
        /* echo message on stdout */
	    /* XXX For now all messages are handled with sup_recv_message
         * Should we change that ???
         */
        /* if (echo_log_msgs(i, logfile) != 0) { 
		close(i); 
		del_fd(i, &valid_fds, max_fd);
	    } */
	}
	handle_children(); /* handle dead children etc */

        if (num_procs >= 3) {
#ifdef RESOURCE_MANAGEMENT
            schedule();    /* resource management */
#endif
            reconfigure(); /* if needed, reconfigure */
        }
    }
}

