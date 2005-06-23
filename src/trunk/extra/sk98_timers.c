/*
 * Copyright (c) 2005 University of Cambridge Computer Laboratory.
 *
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <assert.h>
#include <err.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "sk98_timers.h"

#include "como.h"

/* This is the stuff necessary for run-time sk98 calibration. */

/* Notes on cards
 *
 * For the sk98 - reading the counter is expensive (you can't simply
 * get a pointer to the free-running counter, its byte swapped and de
 * referenced so the sk98 getcurtime does sort of what init_tstamp does
 * but it does work !
 *
 * */



// clock calculation
struct __clock_retimer_st {

    char *name; /* Of the interface we're attached to e.g. "eth2" */
    unsigned dev_num;

    enum {
	clock_mode_prestart,
	clock_mode_find_intercept,
	clock_mode_constant_output
    } mode;

    // next time for initial checking
    unsigned long nextdrift;

    // base time; ie at tic_base tics, the time actually was time_base
    struct timeval time_base;
    unsigned long long tic_base;

    unsigned long long tic_cur; /* Where we are at the moment,
				   monotonically increasing */
    unsigned tic_last; /* Where we are at the moment, wrapping at the
			  same time as the actual nictstamp. */

    unsigned int binned;  // number of consecutive binned samples

    // stats to get time intercept
    unsigned int samples;
    double sum;    // sum of diff
    double sum2;   // sum of diff*diff
    double tsum;   // sum of time
    double tsum2;  // sum of time*time
    double psum;   // sum of time*diff (product sum)
    double min;    // min(diff)
    double max;    // max(diff)

    unsigned long samples_bad; /* We know that the results we get are
				  not going to be good enough for the
				  final answer, but we can use them to
				  make initial estimates for the next
				  phase. */
};



static unsigned long drift_period = 1500000; // min= 48ms, max=0.432s
static unsigned long nictstamp_freq = 31250000;

/*************************************************************************/


/* Is x >= y, allowing for overflow? */
#define TSTAMP_GREATEREQ(x, y) \
	( (x) >= (y) ? ((x) - (y) < 1 << 30) : ((y) - (x) > 1 << 30) )

/* Decide how long we're going to wait before doing the next drift
   interval.  The randomness helps to avoid aliasing effects. */
static unsigned long drift_interval(void)
{
    return (unsigned long) (((drand48() * 8) + 1) * drift_period);
}

/* Convert a struct timeval to a double giving the time in seconds. */
static double tv_to_secs(const struct timeval *tv)
{
    return tv->tv_sec + (tv->tv_usec / 1000000.0);
}

/* Convert a double giving the time in seconds to a struct timeval. */
/* We round to the nearest microsecond. */
static void secs_to_tv(struct timeval *tv, double t)
{
    tv->tv_sec = (int)t;
    t -= tv->tv_sec;
    tv->tv_usec = (int)(t * 1000000 + 0.5);
    if (tv->tv_usec >= 1000000) {
	/* This can happen, due to rounding error. */
	tv->tv_sec ++;
	tv->tv_usec = 0;
    } else if (tv->tv_usec < 0) {
	tv->tv_sec --;
	tv->tv_usec += 1000000;
    }

    assert(tv->tv_usec >= 0 && tv->tv_usec < 1000000);
}

/* Reset the calibration */
static void reset_timer(clock_retimer_t *timer, unsigned long nictstamp,
			struct timeval *now)
{
    timer->tic_base = timer->tic_cur = nictstamp;
    timer->nextdrift = timer->tic_base + drift_interval();
    timer->time_base = *now;
    timer->samples = 0;
    timer->sum = 0;
    timer->sum2 = 0;
    timer->tsum = 0;
    timer->tsum2 = 0;
    timer->psum = 0;
    timer->max = 0;
    timer->min = 0;
    timer->samples_bad = 0;
}

clock_retimer_t *new_clock_retimer(const char *name, unsigned dev_num)
{
    clock_retimer_t *work;
    work = calloc(sizeof(*work), 1);
    if (!work)
	err(1, "allocating timer recalibration structure");
    work->name = strdup(name);
    work->dev_num = dev_num;
    return work;
}

/* Given that we *just* received a packet with tstamp nictstamp, update
   the clock calibration.  You really want to call this as soon after
   receiving the packet as possible.

   Returns 1 if we just went from an uncalibrated to a calibrated
   state. */
int doTimer(clock_retimer_t *timer, unsigned long nictstamp,
	    struct timeval *now)
{
    struct timeval est_time; /* Estimated packet arrival time */
    double timed; /* Difference between est_time and time, seconds */
    double tdiff; /* Difference between now and timer->time_base,
		     seconds */
    double s_xx;
    double s_xy;
    double s_yy;
    double grad;

    double m_x;
    double m_y;
    double inter;

    double s2_r;
    double uncerc2;

    if (timer->mode == clock_mode_prestart) {
	reset_timer(timer, nictstamp, now);
	timer->mode = clock_mode_find_intercept;
	timer->samples_bad = 0;
	return 0;
    }

    if (!TSTAMP_GREATEREQ(nictstamp, timer->nextdrift)) {
	/* It's too early to do the next phase. */
	return 0;
    }

    timer->nextdrift += drift_interval();

    if (timer->mode == clock_mode_constant_output) {
	/* That's all we need to do for now. */
	return 0;
    }

    getTime(timer, nictstamp, &est_time, NULL);

    timed = tv_to_secs(&est_time) - tv_to_secs(now);

    /* Okay, sanity check things a bit. */
    /* These can fail if the frequency estimate is badly wrong.  In
       that case, we calculate a new estimate, and keep going (hence
       setting timer->samples_bad to 1) */
    if(timed > timer->max + 0.0005 && timer->samples_bad == 0)
    {
	timer->samples_bad = 1;
	return 0;
    }
    if(timed < timer->min - 0.0005 && timer->samples_bad == 0)
    {
	timer->binned++;
	if((timer->binned % 20) == 19)
	{
	    timer->samples_bad = 1;
	}
	return 0;
    }

    /* Sample looks good, start processing it. */

    timer->binned = 0;

    tdiff = tv_to_secs(now) - tv_to_secs(&timer->time_base);

    /* Add it to the accumulated statistics */
    timer->samples++;
    timer->sum += timed;
    timer->sum2 += (timed * timed);
    timer->tsum += tdiff;
    timer->tsum2 += (tdiff * tdiff);
    timer->psum += tdiff * timed;
    if(timer->samples == 1 || timer->min > timed)
	timer->min = timed;
    if(timer->samples == 1 || timer->max < timed)
	timer->max = timed;

    if (timer->samples < 80) {
	/* Not enough samples available for calibration, yet. */
	return 0;
    }


    /* Interesting times:

       -- We start a calibration run, system clock (A)
       -- A packet arrives, sk98 clock (B)
       -- A packet arrives, system clock (C)

       tdiff = C - A
       time = C - B */
    /* The actual core calibration.  This is a fairly standard linear
       regression.  We think that tdiff is a function of time, and we
       want to find the equation.  (Remember that tdiff is the system
       clock time between calibration start and packet arrival, while
       time is the difference between measured system time shortly
       after packet arrival and estimated time of packet arrival.)*/
    s_xx = timer->tsum2 -
	(timer->tsum * timer->tsum / (double) timer->samples);
    s_xy = timer->psum -
	(timer->tsum * timer->sum / (double) timer->samples);
    s_yy = timer->sum2 -
	(timer->sum * timer->sum / (double) timer->samples);
    grad = s_xy / s_xx;
    /* m stands for mean, here, rather than gradient */
    m_x = timer->tsum / (double) timer->samples;
    m_y = timer->sum / (double) timer->samples;
    inter =  m_y - (grad * m_x);

    /* We now believe that time =~= inter + grad * tdiff.  Now, at
       tdiff = 0, inter provides a pretty good estimate of the time
       between a packet getting stamped on the card and its getting a
       system time stamp.  It is therefore the amount which we should
       subtract from the time base in order to get the actual packet
       arrival times.  The gradient gives a pretty good guide to the
       error in the clock frequency. */

    /* Estimate how bad a fit we have.  Again, the interesting thing
       is the uncertainty in inter. */
    s2_r = s_yy - (grad * grad * s_xx) / (timer->samples - 2);
    uncerc2 = s2_r * (1 + 1.0 / timer->samples + m_x * m_x / s_xx);

    logmsg(LOGCAPTURE, "Interface %d: timer uncerc %e, grad %e.\n",
	   timer->dev_num, sqrt(uncerc2), grad);

    /* Guess the nictstamp frequency from the data we've collected. */
    nictstamp_freq = ((1.0 + grad) * (double) nictstamp_freq)+0.5;

    if (grad > 1e-6 || grad < -1e-6 || timer->samples_bad) {
	/* We don't trust the calculated intercept if we've had to
	   change nictstamp_freq by more than a tiny amount, so
	   reset. */
	reset_timer(timer, nictstamp, now);
	return 0;
    }

    /* Adjust the time base as appropriate */
    secs_to_tv(&timer->time_base,
	       tv_to_secs(&timer->time_base) - inter);

    timer->mode = clock_mode_constant_output;

    return 1;
}

void getTime(clock_retimer_t *timer, unsigned long nictstamp, struct timeval *tv, struct timespec *ts)
{
    unsigned long long tdiff;
    struct timespec t;
    unsigned long long tics;

    // handle nictstamp wrap
    if (nictstamp < timer->tic_last)
	tdiff = ((unsigned long long) nictstamp + UINT_MAX) - (unsigned long long) timer->tic_last;
    else
	tdiff = (unsigned long long) nictstamp - (unsigned long long) timer->tic_last;
    timer->tic_last = nictstamp;

    timer->tic_cur += tdiff;

    /* What we'd like to do is:

       double t;
       t = (timer->tic_cur - timer->tic_base) / nictstamp_freq;
       t.tv_sec = (int)t;
       t.tv_nsec = (t - (int)t) * 1000000000;

       Unfortunately, doubles don't have a big enough mantissa for
       that to be safe, so we have to fart about with fixed point
       arithmetic, like so. */
    tics = timer->tic_cur - timer->tic_base;
    t.tv_sec = tics / nictstamp_freq;
    t.tv_nsec = (1000000000ull * (tics % nictstamp_freq)) /
	nictstamp_freq;
    assert(t.tv_nsec >= 0);
    assert(t.tv_nsec < 1000000000);

    t.tv_sec += timer->time_base.tv_sec;
    t.tv_nsec += timer->time_base.tv_usec * 1000;
    if (t.tv_nsec >= 1000000000) {
	t.tv_sec ++;
	t.tv_nsec -= 1000000000;
    }
    assert(t.tv_nsec >= 0);
    assert(t.tv_nsec < 1000000000);

    /* Assert that the time we've estimated is close to the current
       time.  This will have to change if we ever use this code on
       offline traces. */
    /* It turns out this isn't a good thign to assert: we can have
       stale packets on the ring when we start up, and they tend to
       confuse things.
    */
#if 0
#ifndef NDEBUG
    {
	unsigned n;
	n = time(NULL);
	assert(t.tv_sec >= n - 60);
	assert(t.tv_sec <= n + 60);
    }
#endif
#endif

    if(tv) {
	tv->tv_sec = t.tv_sec;
	tv->tv_usec = (t.tv_nsec + 500) / 1000;
	if (tv->tv_usec >= 1000000) {
	    tv->tv_sec--;
	    tv->tv_usec -= 1000000;
	}
	assert(tv->tv_usec >= 0);
	assert(tv->tv_usec < 1000000);
    }

    if(ts) {
	memcpy(ts, &t, sizeof(t));
    }

    return;
}

void initialise_timestamps(unsigned long initial_freq)
{
    if (initial_freq != 0)
	nictstamp_freq = initial_freq;
}
