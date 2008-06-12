/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 * rings.c - single-process, multi-rings packet sniffer
 *           for PF_RING aware interfaces
 *
 * 2Q 2008 Rocco Carbone <rocco /at/ ntop /dot/ org>
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *
 *           It simply opens several rings (default 1) and uses
 *           them in round-robin to count packets received
 *           from the interface, until the maximum # of packets
 *           has been reached (default 100000).
 *
 *           At given intervals (a percentage of packets received
 *           which defaults to 10) it also prints out statistics
 *           information about the value of pkts/sec calculated
 *
 * rocco@ring 453> sudo ./rings
 * rings: requested to open #1 ring
 * rings: listening from eth0 using PF_RING driver ver 3.8.0
 *
 * rings: starting to capture #100000 pckts using #1 ring...
 * rings: pkts rcvd #10000 of #100000 (10.00%)
 * rings: pkts rcvd #20000 of #100000 (20.00%) [11037.53 pkts/sec => +10000 pkts in 906 msecs]
 * rings: pkts rcvd #30000 of #100000 (30.00%) [11049.72 pkts/sec => +10000 pkts in 905 msecs]
 * rings: pkts rcvd #40000 of #100000 (40.00%) [10917.03 pkts/sec => +10000 pkts in 916 msecs]
 * rings: pkts rcvd #50000 of #100000 (50.00%) [11123.47 pkts/sec => +10000 pkts in 899 msecs]
 * rings: pkts rcvd #60000 of #100000 (60.00%) [10989.01 pkts/sec => +10000 pkts in 910 msecs]
 * rings: pkts rcvd #70000 of #100000 (70.00%) [10917.03 pkts/sec => +10000 pkts in 916 msecs]
 * rings: pkts rcvd #80000 of #100000 (80.00%) [11074.20 pkts/sec => +10000 pkts in 903 msecs]
 * rings: pkts rcvd #90000 of #100000 (90.00%) [11086.47 pkts/sec => +10000 pkts in 902 msecs]
 * rings: pkts rcvd #100000 of #100000 (100%)  [10928.96 pkts/sec => +10000 pkts in 915 msecs]
 *
 * Time:
 * =====
 * Started:       Thu Jun  5 18:54:29 2008
 * Finished:      Thu Jun  5 18:54:38 2008
 * Elapsed Time:  9.089 secs
 *
 * Great Totals:
 * =============
 * pkts rcvd #100000 pckts of #100000 => 11002.31 pkts/sec
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
#include <signal.h>

/* Private header file(s) */
#include "pfring.h"


#define DEFAULT_INTERFACE "eth0"   /* default interface */
#define DEFAULT_SNAPSHOT  1500     /* default snapshot length */
#define DEFAULT_RINGS     1        /* default # of ring(s) to use */
#define DEFAULT_PACKETS   100000   /* default # of packets to capture per ring */
#define DEFAULT_HB        10       /* default heartbeat */


/* Public funtions in file time.c */
time_t delta_time_in_milliseconds (struct timeval * t2, struct timeval * t1);
void print_time_in_secs (struct timeval * t, char * label);
char * elapsed_time (struct timeval * start, struct timeval * stop);
char * percentage (unsigned long partial, unsigned long total);
void showbar (unsigned long partial);


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

  printf ("   -n count       # of ring(s) to open. default %d\n", DEFAULT_RINGS);
  printf ("   -c count       # of packets to capture per ring. default %d - 0 means unlimited\n", DEFAULT_PACKETS);

  printf ("   -b count       heartbeat in seconds to show intermediate results. default %d\n", DEFAULT_HB);
}


/*
 * 1. Open 'r' ring(s)
 * 2. Capture 'n' packets per ring using a round-robin algorithm
 * 3. Print global statistics information
 */
int main (int argc, char * argv [])
{
  int option;

  char * interface = DEFAULT_INTERFACE;    /* interface name */
  int promiscuous = 1;
  int snapshot = DEFAULT_SNAPSHOT;

  /* How many rings */
  int rings = DEFAULT_RINGS;
  pfring ** ringtable = NULL;
  int r;
  u_int32_t ringdriver;
  char * packet;
  struct pfring_pkthdr header;

  /* How many packets */
  unsigned long maxcount = DEFAULT_PACKETS;
  unsigned long partial  = 0;
  unsigned long errors   = 0;

  int hb = -1;      /* heartbeat */
  int quiet = 0;

  struct timeval started;
  struct timeval stopped;
  double delta;

  /* Notice the program name */
  char * progname = strrchr (argv [0], '/');
  progname = ! progname ? * argv : progname + 1;

#define OPTSTRING "hvi:s:n:c:b:q"
  while ((option = getopt (argc, argv, OPTSTRING)) != EOF)
    {
      switch (option)
	{
	default: return -1;

	case 'h': usage (progname);          return 0;
        case 'v': version (progname);        return 0;

	case 'i': interface = optarg;        break;
	case 's': snapshot  = atoi (optarg); break;

	case 'n': rings = atoi (optarg);
	  if (! rings)
	    rings = 1;
	  break;

	case 'c': maxcount = atoi (optarg);  break;

	case 'b': hb = atoi (optarg);        break;
	case 'q': quiet = 1;                 break;
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
  printf ("%s: requested to open #%d ring%s\n", progname, rings, rings > 1 ? "s" : "");

  /* Allocate enough memory to keep the pointers to the ring(s) */
  ringtable = calloc ((rings + 1) * sizeof (pfring *), 1);
  for (r = 0; r < rings; r ++)
    ringtable [r] = NULL;
  ringtable [r] = NULL;

  /* Open the interface for packet capturing */
  for (r = 0; r < rings; r ++)
    if (! (ringtable [r] = pfring_open (interface, promiscuous, snapshot, 0)))
      {
	printf ("%s: cannot open interface '%s'\n", progname, interface);
	return -1;
      }

  /* Get memory for packet capturing */
  packet = calloc (snapshot, 1);

  /* Print PF_RING driver version */
  pfring_version (ringtable [0], & ringdriver);
  printf ("%s: listening from %s using PF_RING driver ver %d.%d.%d\n\n", progname, interface,
	  (ringdriver & 0xFFFF0000) >> 16, (ringdriver & 0x0000FF00) >> 8, ringdriver & 0x000000FF);

  if (hb == -1)
    hb = maxcount / DEFAULT_HB;
  if (! hb)
    hb = 1;

  /* Announce */
  printf ("%s: starting to capture #%lu pckts using #%d ring%s...\n", progname, maxcount, rings, rings > 1 ? "s" : "");

  /* Set time the application started to capture packets */
  gettimeofday (& started, NULL);

  r = 0;
  while (! maxcount || (partial + errors) < maxcount)
    {
      /* Please give me just a packet at once from the ring */
      if (pfring_recv (ringtable [r], packet, snapshot, & header, 1) > 0)
	{
	  partial ++;
	  if (! quiet)
	    {
	      if (! (partial % hb))
		{
		  static unsigned long previous = 0;
		  static struct timeval latest;

		  struct timeval now;

		  /* Show pkts/secs in the latest period */
		  gettimeofday (& now, NULL);
		  delta = delta_time_in_milliseconds (& now, & latest);

		  printf ("%s: pkts rcvd #%lu of #%lu %s", progname, partial, maxcount, percentage (partial, maxcount));
		  if (previous && delta)
		    printf (" [%8.2f pkts/sec => +%lu pkts in %s]",
			    (double) (partial - previous) * 1000 / delta,
			    partial - previous, elapsed_time (& latest, & now));
		  printf ("\n");

		  previous = partial;
		  latest = now;
		}
	      else
		showbar (partial);
	    }
	}
      else
	errors ++;

      /* Round-robin to choose the ring candidate for the packet capture */
      r = (r + 1) % rings;
    }

  /* Close the ring(s) */
  for (r = 0; r < rings; r ++)
    pfring_close (ringtable [r]);
  free (ringtable);

  /* Done! */
  free (packet);

  gettimeofday (& stopped, NULL);
  delta = (double) delta_time_in_milliseconds (& stopped, & started);

  printf ("              \n");

  printf ("Time:\n");
  printf ("=====\n");
  print_time_in_secs (& started, "Started:       ");
  print_time_in_secs (& stopped, "Finished:      ");
  printf ("Elapsed Time:  %s\n", elapsed_time (& started, & stopped));
  printf ("\n");

  /* Print out test results */
  printf ("Great Totals:\n");
  printf ("=============\n");
  printf ("pkts rcvd #%lu pckts of #%lu => %7.2f pkts/sec\n", partial, maxcount, (double) partial * 1000 / delta);

  return 0;
}
