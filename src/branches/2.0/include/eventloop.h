#ifndef EVENTLOOP_H_
#define EVENTLOOP_H_

typedef struct event_loop {
    fd_set		fds;
    int			max_fd;
    struct timeval	*timeoutptr;
    struct timeval	timeout;
} event_loop_t;

void event_loop_init        (event_loop_t * el);
int  event_loop_add         (event_loop_t * el, int i);
int  event_loop_del         (event_loop_t * el, int i);
void event_loop_set_timeout (event_loop_t * el, struct timeval * timeout);
int  event_loop_select      (event_loop_t * el, fd_set * ready);

#endif /*EVENTLOOP_H_*/
