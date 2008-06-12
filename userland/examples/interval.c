/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 * interval.c - how to handle time intervals (and some utility)
 *
 * 2Q 2008 Rocco Carbone <rocco /at/ ntop /dot/ org>
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */


/* Operating System header file(s) */
#include <stdio.h>
#include <time.h>
#include <sys/time.h>


/* The time since [t] in seconds */
time_t seconds (struct timeval * t)
{
  return t -> tv_sec + t -> tv_usec / 1000000.0;
}


/* The time since [t] in milliseconds */
time_t milliseconds (struct timeval * t)
{
  return t -> tv_sec * 1000.0 + t -> tv_usec / 1000.0;
}


/* The time since [t] in microseconds */
time_t microseconds (struct timeval * t)
{
  return t -> tv_sec * 1000000.0 + t -> tv_usec;
}


/* The time difference in seconds */
time_t delta_time_in_seconds (struct timeval * t2, struct timeval * t1)
{
  /* Compute delta in second */
  return t2 -> tv_sec - t1 -> tv_sec;
}


/* The time difference in milliseconds */
time_t delta_time_in_milliseconds (struct timeval * t2, struct timeval * t1)
{
  /* Compute delta in second, 1/10's and 1/1000's second units */
  time_t delta_seconds      = t2 -> tv_sec - t1 -> tv_sec;
  time_t delta_milliseconds = (t2 -> tv_usec - t1 -> tv_usec) / 1000;

  if (delta_milliseconds < 0)
    { /* manually carry a one from the seconds field */
      delta_milliseconds += 1000;                              /* 1e3 */
      -- delta_seconds;
    }
  return (delta_seconds * 1000) + delta_milliseconds;
}


/* The time difference in microseconds */
time_t delta_time_in_microseconds (struct timeval * t2, struct timeval * t1)
{
  /* Compute delta in second, 1/10's and 1/1000's second units */
  time_t delta_seconds      = t2 -> tv_sec - t1 -> tv_sec;
  time_t delta_microseconds = t2 -> tv_usec - t1 -> tv_usec;

  if (delta_microseconds < 0)
    { /* manually carry a one from the seconds field */
      delta_microseconds += 1000000;                            /* 1e6 */
      -- delta_seconds;
    }
  return (delta_seconds * 1000000) + delta_microseconds;
}


void print_time_in_secs (struct timeval * t, char * label)
{
  time_t abst = t -> tv_sec;

  printf ("%s%*.*s\n", label, 24, 24, ctime (& abst));
  fflush (stdout);
}


/* -=--=--=--=--=--=--=--=--=--=--=--=--=--=--=- */

/* number of microseconds per second */
#define SECS_PER_DAY   86400
#define SECS_PER_HOUR  3600
#define SECS_PER_MIN   60
#define MSEC_PER_SEC   1000
#define USEC_PER_SEC   1000000
#define USEC_PER_MIN   (1000000 * SECS_PER_MIN)
#define USEC_PER_HOUR  (SECS_PER_HOUR * USEC_PER_SEC)


/* Number of microseconds since 00:00:00 January 1, 1970 UTC */
time_t time_now (void)
{
  struct timeval now;
  gettimeofday (& now, NULL);
  return (time_t) now . tv_sec * USEC_PER_SEC + now . tv_usec;
}


/* Return time in microseconds */
time_t time_usec (time_t t)
{
  return (time_t) t % USEC_PER_SEC;
}


/* Return time in milliseconds */
int time_msec (time_t t)
{
  return t % MSEC_PER_SEC;
}


/* Return time in seconds */
int time_sec (time_t t)
{
  return (t / MSEC_PER_SEC) % SECS_PER_MIN;
}


/* Return time in minutes */
int time_min (time_t t)
{
  return (t / (MSEC_PER_SEC * 60)) % 60;
}


/* Return time in hours */
int time_hour (time_t t)
{
  return (t / (MSEC_PER_SEC * SECS_PER_HOUR)) % 24;
}


/* Return time in days */
int time_day (time_t t)
{
  return (t / (MSEC_PER_SEC * SECS_PER_DAY));
}


/* Days In Seconds */
int days (time_t t1, time_t t2)
{
  return (t2 - t1) / SECS_PER_DAY;
}


/* Hours In Seconds */
int hours (time_t t1, time_t t2)
{
  return (t2 - t1 - (days (t1, t2) * SECS_PER_DAY)) / SECS_PER_HOUR;
}


/* Minutes In Seconds */
int mins (time_t t1, time_t t2)
{
  return (t2 - t1 - (days (t1, t2) * SECS_PER_DAY) - (hours (t1, t2) * SECS_PER_HOUR)) / SECS_PER_MIN;
}


/* Return a well formatted string with a time difference at millisecond resolution */
char * elapsed_time (struct timeval * start, struct timeval * stop)
{
  static char et [64];

  time_t elapsed = delta_time_in_milliseconds (stop, start);

  if (time_day (elapsed))
    sprintf (et, "%d days, %02d:%02d:%02d.%03ld",
	     time_day (elapsed), time_hour (elapsed), time_min (elapsed), time_sec (elapsed), time_usec (elapsed));
  else if (time_hour (elapsed))
    sprintf (et, "%02d:%02d:%02d.%03ld",
	     time_hour (elapsed), time_min (elapsed), time_sec (elapsed), time_usec (elapsed));
  else if (time_min (elapsed))
    sprintf (et, "%02d:%02d.%03ld", time_min (elapsed), time_sec (elapsed), time_usec (elapsed));
  else if (time_sec (elapsed))
    sprintf (et, "%d.%03d secs", time_sec (elapsed), time_msec (elapsed));
  else
    sprintf (et, "%3d msecs", time_msec (elapsed));

  return et;
}


/* Well formatted percentage */
char * percentage (unsigned long partial, unsigned long total)
{
#define ITEMS 10
  static char buffer [ITEMS] [64];
  static short k = -1;

#define DECIMALS 2
  float percent;

  k = (k + 1) % ITEMS;

  if (partial && total)
    {
      percent = (float) partial * 100 / (float) total;

      if (partial == total)
	sprintf (buffer [k], "(%3d%%) ", (int) percent);
      else
	sprintf (buffer [k], "(%4.*f%%)", DECIMALS, percent);  /* d.dd% */
    }
  else
    sprintf (buffer [k], " ");    /* just a single blank */

  return buffer [k];
}


void showbar (unsigned long received)
{
  static int bar = 0;

  bar = received % 8;
  if (bar == 0 || bar == 4) 
    printf (" %lu |\r", received);
  else if (bar == 1 || bar == 5) 
    printf (" %lu /\r", received);
  else if (bar == 2 || bar == 6) 
    printf (" %lu -\r", received);
  else
    printf (" %lu \\\r", received);
  fflush (stdout);
}
