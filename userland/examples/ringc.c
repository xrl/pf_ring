/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 * ringc.c - a simple program to count packets and bytes
 *           from a PF_RING aware interface and print out
 *           at given heartbeat seconds (default 3) statistics
 *           information about the value of pkts/sec calculated
 *
 * 2Q 2008 Rocco Carbone <rocco /at/ ntop /dot/ org>
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *
 * rocco@ring 454> sudo ./ringc
 * ringc: listening from eth0 using PF_RING driver ver 3.8.0
 *
 * ringc: starting to capture (partial reports will be available every 3 secs)
 *  [use ^C to interrupt]
 *
 * [  1] pkts rcvd #35310 => 11770.00 pkts/sec in 3.000 secs
 * [  2] pkts rcvd #69690 => 11615.00 pkts/sec in 6.000 secs [+34380 => 11460.00 pkts/sec in 3.000 secs]
 * [  3] pkts rcvd #108640 => 12071.11 pkts/sec in 9.000 secs [+38950 => 12983.33 pkts/sec in 3.000 secs]
 * [  4] pkts rcvd #142784 => 11898.67 pkts/sec in 12.000 secs [+34144 => 11381.33 pkts/sec in 3.000 secs]
 * [  5] pkts rcvd #176988 => 11799.20 pkts/sec in 15.000 secs [+34204 => 11401.33 pkts/sec in 3.000 secs]
 * ^C
 * Caught signal 2: terminating...
 * Time:
 * =====
 * Started:       Thu Jun  5 19:14:21 2008
 * Finished:      Thu Jun  5 19:14:37 2008
 * Elapsed Time:  16.142 secs
 *
 * Great Totals:
 * =============
 * pkts rcvd #189801 pckts => 11758.21 pkts/sec => #20529143 bytes [10174.27 Mbits/sec]
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
#define DEFAULT_PACKETS   0        /* default # of packets to capture */
#define DEFAULT_HB        3        /* default heartbeat */

/* Public funtions in file time.c */
time_t delta_time_in_milliseconds (struct timeval * t2, struct timeval * t1);
void print_time_in_secs (struct timeval * t, char * label);
char * elapsed_time (struct timeval * start, struct timeval * stop);


/* Local variables */
static int done = 0;
static pfring * ring = NULL;
static int heartbeat = DEFAULT_HB;

static struct timeval started;           /* time the application started to receive packets */
static unsigned long long partial = 0;   /* # of packets so far received */
static unsigned long long bytes = 0;     /* # of bytes so far received */


/* Print out warning information in the event packet counter
 * maintained by the driver differ from those counted by the application,
 * then print out pkts/secs from the start of the program and in the latest time interval
 */
static void statistics (void)
{
  static unsigned hits = 0;
  static u_int64_t previous = 0;         /* # of packets received during last period */
  static struct timeval latest;

  struct timeval now;
  double delta;

  pfring_stat pstat;

  /* Print statistics information from PF_RING only they differ from those currently maintained by the application */
  if (pfring_stats (ring, & pstat) >= 0 && partial != pstat.recv)
    {
      if (pstat.drop)
	printf ("Warning: received by PF_RING #%llu received by the application #%llu [dropped #%llu (diff #%llu) (%%%.1f)]\n",
		(long long unsigned int)pstat.recv, partial, 
		(long long unsigned int)pstat.drop, 
		(long long unsigned int)(pstat.recv - pstat.drop),
		(!pstat.recv) ? 0 : (double) (pstat.drop * 100 / pstat.recv));
      else
	printf ("Warning: counted by PF_RING #%llu differ from those received by the application #%llu\n", 
		(long long unsigned int)pstat.recv, partial);
    }

  /* Calculate the time interval from the start of the capture */
  gettimeofday (& now, NULL);
  delta = delta_time_in_milliseconds (& now, & started);

  /* Show pkts/secs in the latest period */
  printf ("[%3u] pkts rcvd #%5llu => %.2f pkts/sec in %s ",
	  ++ hits, partial, (double) (partial * 1000 / delta), elapsed_time (& started, & now));

  if (previous)
    delta = delta_time_in_milliseconds (& now, & latest),
      printf ("[+%llu => %.2f pkts/sec in %s]",
	      partial - previous, (double) ((partial - previous) * 1000 / delta), elapsed_time (& latest, & now));
  printf ("\n");

  previous = partial;
  latest = now;
}


/* What has to be done at given timeout */
static void on_alarm (int sig)
{
  /* Print out statistics information */
  statistics ();

  signal (SIGALRM, on_alarm);
  alarm (heartbeat);
}


/* What has to be done on interrupt */
static void on_ctrl_c (int sig)
{
  printf ("\nCaught signal %d: terminating...\n", sig);

  done = 1;
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

  printf ("   -c count       # of packets to capture. default %d that means unlimited\n", DEFAULT_PACKETS);

  printf ("   -b count       heartbeat in seconds to show intermediate results. default %d\n", DEFAULT_HB);
}


int main (int argc, char * argv [])
{
  int option;

  char * interface = DEFAULT_INTERFACE;      /* interface name */
  int promiscuous = 1;
  int snapshot = DEFAULT_SNAPSHOT;

  u_int32_t ringdriver;
  char packet [2048];
  struct pfring_pkthdr header;

  /* How many packets */
  unsigned long maxcount = DEFAULT_PACKETS;  /* total # of packets to capture */

  struct timeval stopped;                    /* time the application was interrupted */
  double delta;

  /* Notice the program name */
  char * progname = strrchr (argv [0], '/');
  progname = ! progname ? * argv : progname + 1;

#define OPTSTRING "hvi:s:c:b:"
  while ((option = getopt (argc, argv, OPTSTRING)) != -1)
    {
    switch (option)
      {
      default: return -1;

      case 'h': usage (progname);   return 0;
      case 'v': version (progname); return 0;

      case 'i': interface = optarg;        break;
      case 's': snapshot  = atoi (optarg); break;

      case 'c': maxcount  = atoi (optarg); break;

      case 'b':	heartbeat = atoi (optarg); break;
      }
    }

  if (! heartbeat)
    heartbeat = 1;

  /* Set unbuffered stdout */
  setvbuf (stdout, NULL, _IONBF, 0);

  if ((getuid () && geteuid ()) || setuid (0))
    {
      printf ("%s: sorry, you must be root in order to run this program\n", progname);
      return -1;
    }

  if (! (ring = pfring_open (interface, promiscuous, snapshot, 0)))
    {
      printf ("%s: cannot open interface '%s'\n", progname, interface);
      return -1;
    } else
    pfring_set_application_name(ring, "ringc");

  /* Print PF_RING driver version */
  pfring_version (ring, & ringdriver);
  printf ("%s: listening from %s using PF_RING driver ver %d.%d.%d\n\n", progname, interface,
	  (ringdriver & 0xFFFF0000) >> 16, (ringdriver & 0x0000FF00) >> 8, ringdriver & 0x000000FF);

  signal (SIGINT, on_ctrl_c);
  signal (SIGALRM, on_alarm);
  alarm (heartbeat);

  /* Set time the application started to capture packets */
  gettimeofday (& started, NULL);

  /* Announce */
  printf ("%s: starting to capture (partial reports will be available every %d secs)\n", progname, heartbeat);
  printf (" [use ^C to interrupt]\n\n");

  while (! done && (! maxcount || partial < maxcount))
    /* Please give me just a packet at once from the ring */
    if (pfring_recv (ring, packet, sizeof (packet), & header, 1) > 0)
      partial ++,
	bytes += header.caplen,
	printf ("\r");

  /* Set time the application was interrupted */
  gettimeofday (& stopped, NULL);
  delta = (double) delta_time_in_milliseconds (& stopped, & started);

  printf ("Time:\n");
  printf ("=====\n");
  print_time_in_secs (& started, "Started:       ");
  print_time_in_secs (& stopped, "Finished:      ");
  printf ("Elapsed Time:  %s\n", elapsed_time (& started, & stopped));
  printf ("\n");

  /* Print out test results */
  printf ("Great Totals:\n");
  printf ("=============\n");
  printf ("pkts rcvd #%llu pckts => %.2f pkts/sec => #%llu bytes [%.2f Mbits/sec]\n",
	  partial, (double) partial * 1000 / delta,
	  bytes, (double) 8 * bytes / delta);

#if defined(ROCCO)
  /* Close the ring */
  pfring_close (ring);
#endif /* ROCCO */

  return 0;
}
