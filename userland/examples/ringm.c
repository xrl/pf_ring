/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 * ringm.c - multi-threads, single-ring packet sniffer
 *           for PF_RING aware interfaces
 *
 * 2Q 2008 Rocco Carbone <rocco /at/ ntop /dot/ org>
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *
 *           This is the multi-thread version of 'rings'.
 *
 *           It simply opens just a single ring and starts
 *           the requested number of threads to count packets
 *           received from the interface, until the maximum
 *           # of packets has been reached (default 100000).
 *
 *           When all the threads have finished to receive its
 *           own # of packets the program prints out statistics
 *           information per thread and the value of pkts/sec calculated
 *
 * rocco@ring 453> sudo ./rings
 * ringm: requested to start #23 threads
 * ringm: listening from eth0 using PF_RING driver ver 3.8.0
 *
 * ringm: starting to capture #434 packets per thread (please be patient)...
 *
 *   \    maxcount    received    elapsed time
 *    +========================================
 *    |
 *  1 |      435         435      176 msecs
 *  2 |      435         435      1.955 secs
 *  3 |      435         435      2.025 secs
 *  4 |      435         435      1.908 secs
 *  5 |      435         435      2.052 secs
 *  6 |      435         435      2.090 secs
 *  7 |      435         435      1.935 secs
 *  8 |      435         435      2.101 secs
 *  9 |      435         435      2.030 secs
 * 10 |      435         435      2.071 secs
 * 11 |      435         435      1.996 secs
 * 12 |      435         435      2.068 secs
 * 13 |      435         435      2.064 secs
 * 14 |      435         435      2.070 secs
 * 15 |      435         435      2.092 secs
 * 16 |      435         435      2.075 secs
 * 17 |      435         435      1.693 secs
 * 18 |      435         435      2.025 secs
 * 19 |      434         434      2.049 secs
 * 20 |      434         434      2.056 secs
 * 21 |      434         434      1.950 secs
 * 22 |      434         434      2.048 secs
 * 23 |      434         434      2.042 secs
 *    |
 *    +========================================
 *
 * Test results:
 * =============
 * ringm: min/avg/max => 176.095 / 1937.992 / 2101.423 ms
 *
 * Total:
 * ======
 * Started:       Thu Jun 12 16:56:26 2008
 * Finished:      Thu Jun 12 16:56:28 2008
 * Elapsed Time:  2.170 secs
 *
 * ringm: received #10000 of expected #10000 packets => 4608.29 pkts/sec
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


/* Package info */
static char __author__    [] = "R. Carbone <rocco /at/ ntop /dot/ org>";
static char __version__   [] = "version 0.0.1";
static char __released__  [] = "Jun 2008";
static char __copyright__ [] = "Copyright (c) 2008";


/* Operating System header file(s) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <values.h>
#include <signal.h>
#include <pthread.h>

/* Private header file(s) */
#include "pfring.h"


#define DEFAULT_INTERFACE "eth0"   /* default interface */
#define DEFAULT_SNAPSHOT  1500     /* default snapshot length */
#define DEFAULT_THREADS   1        /* default # of thread(s) to start */
#define DEFAULT_PACKETS   100000   /* default # of packets to capture per thread */


typedef struct
{
  pthread_t tid;
  pfring * ring;
  unsigned long maxcount;
  unsigned long partial;
  unsigned long errors;
  int snapshot;
  int bar;

  /* Timers for statistics */
  struct timeval started;
  struct timeval stopped;
  double elapsed;

} my_thread_t;


/* Public funtions in file time.c */
time_t delta_time_in_milliseconds (struct timeval * t2, struct timeval * t1);
time_t delta_time_in_microseconds (struct timeval * t2, struct timeval * t1);
void print_time_in_secs (struct timeval * t, char * label);
char * elapsed_time (struct timeval * start, struct timeval * stop);
void showbar (unsigned long partial);


/* Thread main loop */
static void * sniffer (void * _thread)
{
  my_thread_t * t = _thread;

  struct pfring_pkthdr header;
  char * packet;             /* pointer to the packet */

  /* Get memory for packet capturing */
  packet = calloc (t -> snapshot, 1);

  gettimeofday (& t -> started, NULL);

  t -> partial = 0;
  while (t -> partial < t -> maxcount)
    {
      /* Please give me just a packet from the ring */
      if (pfring_recv (t -> ring, packet, t -> snapshot, & header, 1) > 0)
	{
	  t -> partial ++;
	  if (t -> bar)
	    showbar (t -> partial);
	}
      else
	t -> errors ++;
    }

  gettimeofday (& t -> stopped, NULL);

  t -> elapsed = delta_time_in_microseconds (& t -> stopped, & t -> started);

  free (packet);

  return NULL;
}


/* What should be done on interrupt */
static void on_ctrl_c (int sig)
{
  printf ("\nCaught signal %d: terminating...\n", sig);
  exit (0);
}


/* Display version information */
static void version (char * progname)
{
  printf ("This is %s %s of %s\n", progname, __version__, __released__);
  printf ("%s %s\n", __copyright__, __author__);
}


/* How to use this program */
static void usage (char * progname)
{
  printf ("Usage: %s [options]\n", progname);

  printf ("   -h             show usage and exit\n");
  printf ("   -v             show version and exit\n");

  printf ("   -i interface   use 'interface' for packet capture. default '%s'\n", DEFAULT_INTERFACE);
  printf ("   -s len         snapshot length. default %d\n", DEFAULT_SNAPSHOT);

  printf ("   -t count       # of thread(s) to start. default %d\n", DEFAULT_THREADS);
  printf ("   -c count       # of packets to capture per thread. default %d - 0 means unlimited\n", DEFAULT_PACKETS);

  printf ("   -b             disable the showbar\n");
}


/*
 * 1. Open 1 ring
 * 2. Start 't' thread(s)
 * 3. Capture 'n' packets per thread
 * 4. Print global statistics information
 */
int main (int argc, char * argv [])
{
  int option;

  char * interface = DEFAULT_INTERFACE;    /* interface name */
  int promiscuous = 1;
  int snapshot = DEFAULT_SNAPSHOT;

  /* How many threads */
  int threadsno = DEFAULT_THREADS;
  my_thread_t ** threads = NULL;     /* table of pointers to the threads */
  int t;

  /* How many rings */
  pfring * ring = NULL;              /* pointer to the ring */
  u_int32_t ringdriver;

  /* How many packets */
  unsigned long maxcount = DEFAULT_PACKETS;
  unsigned long partial  = 0;
  unsigned long errors   = 0;
  int rest;

  int bar = 1;                       /* boolean to show progress bar */

  struct timeval started;
  struct timeval stopped;
  double delta;

  /* Counters for statistics */
  double min = MAXDOUBLE;
  double max = 0;
  double avg = 0;

  /* Notice the program name */
  char * progname = strrchr (argv [0], '/');
  progname = ! progname ? * argv : progname + 1;

#define OPTSTRING "hvi:s:t:c:b"
  while ((option = getopt (argc, argv, OPTSTRING)) != EOF)
    {
      switch (option)
	{
	default: return -1;

	case 'h': usage (progname);          return 0;
        case 'v': version (progname);        return 0;

	case 'i': interface = optarg;        break;
	case 's': snapshot  = atoi (optarg); break;

	case 't': threadsno = atoi (optarg);
	  if (! threadsno)
	    threadsno = 1;
	  break;

	case 'c': maxcount = atoi (optarg);  break;

	case 'b': bar     = 0; break;
	}
    }

  /* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

  /* Set unbuffered stdout */
  setvbuf (stdout, NULL, _IONBF, 0);

  if ((getuid () && geteuid ()) || setuid (0))
    {
      printf ("%s: sorry, you must be root in order to run this program\n", progname);
      return -1;
    }

  signal (SIGINT, on_ctrl_c);

  /* Announce */
  printf ("%s: requested to start #%d thread%s\n", progname, threadsno, threadsno > 1 ? "s" : "");

  /* Open the interface for packet capturing */
  if (! (ring = pfring_open (interface, promiscuous, snapshot, 1)))
    {
      printf ("%s: cannot open interface '%s'\n", progname, interface);
      return -1;
    } else
    pfring_set_application_name(ring, "ringm");

  /* Allocate enough memory to keep the pointers to the threads */
  threads = calloc ((threadsno + 1) * sizeof (my_thread_t *), 1);
  for (t = 0; t < threadsno; t ++)
    threads [t] = NULL;
  threads [t] = NULL;

  /* Print PF_RING driver version */
  pfring_set_application_name(ring, argv[0]);
  pfring_version (ring, & ringdriver);
  printf ("%s: listening from %s using PF_RING driver ver %d.%d.%d\n\n", progname, interface,
	  (ringdriver & 0xFFFF0000) >> 16, (ringdriver & 0x0000FF00) >> 8, ringdriver & 0x000000FF);

  /* Announce */
  printf ("%s: starting to capture #%lu packets per thread (please be patient)...\n", progname, maxcount / threadsno);

  /* Set time the application started to capture packets */
  gettimeofday (& started, NULL);

  rest = maxcount % threadsno;

  /* Create threads to capture packets */
  for (t = 0; t < threadsno; t ++)
    {
      int error;
      threads [t] = calloc (sizeof (my_thread_t), 1);

      threads [t] -> ring     = ring;
      threads [t] -> maxcount = maxcount / threadsno;
      threads [t] -> partial  = 0;
      threads [t] -> errors   = 0;
      threads [t] -> snapshot = snapshot;
      threads [t] -> bar      = bar;
      if (rest)
	threads [t] -> maxcount ++,
	  rest --;

      /* Start a new thread */
      if ((error = pthread_create (& threads [t] -> tid, NULL, sniffer, (void *) threads [t])))
	{
	  printf ("%s: cannot create a new thread (%d already spawned) [error %d - %s]\n",
		  progname, t, error, strerror (error));
	  return 0;
	}
    }

  /* Wait for thread completions */
  for (t = 0; t < threadsno; t ++)
    pthread_join (threads [t] -> tid, NULL);

  /* Done! */
  gettimeofday (& stopped, NULL);
  delta = (double) delta_time_in_milliseconds (& stopped, & started);

  /* Print out test results */
  printf ("          \n");
  printf ("   \\    maxcount    received    elapsed time\n");
  printf ("    +========================================\n");
  printf ("    |\n");

  /* Print out per thread results */
  for (t = 0; t < threadsno; t ++)
    {
      partial += threads [t] -> partial;
      errors += threads [t] -> errors;
      if (threads [t] -> elapsed)
	printf ("%3d |  %7lu     %7lu      %s\n", t + 1, threads [t] -> maxcount,
		threads [t] -> partial, elapsed_time (& threads [t] -> started, & threads [t] -> stopped)),
	  min = threads [t] -> elapsed > min ? min : threads [t] -> elapsed,
	  max = threads [t] -> elapsed < max ? max : threads [t] -> elapsed,
	  avg += threads [t] -> elapsed;
    }

  printf ("    |\n");
  printf ("    +========================================\n");

  /* Print out test results */
  printf ("\n");
  printf ("Test results:\n");
  printf ("=============\n");
  printf ("%s: min/avg/max => %.3f / %.3f / %.3f ms\n\n", progname, min / 1000.0, avg / threadsno / 1000, max / 1000.0);

  printf ("Total:\n");
  printf ("======\n");
  print_time_in_secs (& started, "Started:       ");
  print_time_in_secs (& stopped, "Finished:      ");
  printf ("Elapsed Time:  %s\n", elapsed_time (& started, & stopped));
  printf ("\n");

  printf ("%s: received #%lu of expected #%lu packets => %7.2f pkts/sec\n", progname, partial, maxcount, (double) 1000 * partial / delta);

  /* Threads clean up */
  for (t = 0; t < threadsno; t ++)
    free (threads [t]);
  free (threads);

  return 0;
}

