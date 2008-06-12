/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 * pcaps.c - single-process, multi-handle packet sniffer
 *           for PCAP aware interfaces (see rings.c)
 *
 * 2Q 2008 Rocco Carbone <rocco /at/ ntop /dot/ org>
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *
 *           It simply opens several pcap-handles (default 1) and uses
 *           them in round-robin to count packets received
 *           from the interface, until the maximum # of packets
 *           has been reached (default 100000).
 *
 *           At given intervals (a percentage of packets received
 *           which defaults to 10) it also prints out statistics
 *           information about the value of pkts/sec calculated
 *
 * rocco@ring.netikos.com 455> sudo ./ringp
 * ringp: requested to open #1 pcap-handle
 * ringp: listening from eth0 using libpcap version 0.9.8
 *
 * ringp: starting to capture #100000 pckts using #1 pcap-handle...
 * ringp: pkts rcvd #10000 of #100000 (10.00%)
 * ringp: pkts rcvd #20000 of #100000 (20.00%) [10683.76 pkts/sec => +10000 pkts in 936 msecs]
 * ringp: pkts rcvd #30000 of #100000 (30.00%) [10548.52 pkts/sec => +10000 pkts in 948 msecs]
 * ringp: pkts rcvd #40000 of #100000 (40.00%) [10493.18 pkts/sec => +10000 pkts in 953 msecs]
 * ringp: pkts rcvd #50000 of #100000 (50.00%) [10040.16 pkts/sec => +10000 pkts in 996 msecs]
 * ringp: pkts rcvd #60000 of #100000 (60.00%) [10537.41 pkts/sec => +10000 pkts in 949 msecs]
 * ringp: pkts rcvd #70000 of #100000 (70.00%) [10526.32 pkts/sec => +10000 pkts in 950 msecs]
 * ringp: pkts rcvd #80000 of #100000 (80.00%) [10638.30 pkts/sec => +10000 pkts in 940 msecs]
 * ringp: pkts rcvd #90000 of #100000 (90.00%) [10526.32 pkts/sec => +10000 pkts in 950 msecs]
 * ringp: pkts rcvd #100000 of #100000 (100%)  [10537.41 pkts/sec => +10000 pkts in 949 msecs]
 *
 * Time:
 * =====
 * Started:       Thu Jun  5 19:25:53 2008
 * Finished:      Thu Jun  5 19:26:03 2008
 * Elapsed Time:  9.550 secs
 *
 * Great Totals:
 * =============
 * pkts rcvd #100000 pckts of #100000 => 10471.20 pkts/sec
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
 *
 */


/* Package info */
static char __author__    [] = "R. Carbone <rocco /at/ ntop /dot/ org>";
static char __version__   [] = "version 0.0.1";
static char __released__  [] = "Jun 2008";
static char __copyright__ [] = "Copyright (c) 2008";


/* Operating System header file(s) */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>

/* Packet Capture Library */
#include <pcap.h>


#define DEFAULT_INTERFACE "eth0"   /* default interface */
#define DEFAULT_SNAPSHOT  1500     /* default snapshot length */
#define DEFAULT_HANDLES   1        /* default # of pcap-handle(s) to use */
#define DEFAULT_PACKETS   100000   /* default # of packets to capture per pcap-handle */
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

  exit (0);
}


/* How to use this program */
static void usage (char * progname)
{
  printf ("Usage: %s [options]\n", progname);

  printf ("   -h             show usage and exit\n");
  printf ("   -v             show version and exit\n");

  printf ("   -i interface   use 'interface' for packet capture. default '%s'\n", DEFAULT_INTERFACE);
  printf ("   -s len         snapshot length. default %d\n", DEFAULT_SNAPSHOT);

  printf ("   -n count       # of pcap-handle(s) to open. default %d\n", DEFAULT_HANDLES);
  printf ("   -c count       # of packets to capture per pcap-handle. default %d - 0 means unlimited\n", DEFAULT_PACKETS);

  printf ("   -b count       heartbeat in seconds to show intermediate results. default %d\n", DEFAULT_HB);
}


/*
 * 1. Open 'p' pcap-handle(s)
 * 2. Capture 'n' packets per pcap-handle using a round-robin algorithm
 * 3. Print global statistics information
 */
int main (int argc, char * argv [])
{
  int option;

  char * interface = DEFAULT_INTERFACE;    /* interface name */
  int promiscuous  = 1;
  int snapshot     = DEFAULT_SNAPSHOT;

  /* How many pcap-handles */
  int handles = DEFAULT_HANDLES;
  pcap_t ** table = NULL;
  int p;
  char ebuf [PCAP_ERRBUF_SIZE];
  const unsigned char * packet;
  struct pcap_pkthdr header;

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

	case 'h': usage (progname);   return 0;
        case 'v': version (progname); return 0;

	case 'i': interface = optarg;       break;
	case 's': snapshot = atoi (optarg); break;

	case 'n': handles = atoi (optarg);
	  if (! handles)
	    handles = 1;
	  break;

	case 'c': maxcount = atoi (optarg); break;

	case 'b': hb = atoi (optarg); break;
	case 'q': quiet = 1; break;
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

  /* Find a suitable interface, if you don't have one */
  if (! interface && ! (interface = pcap_lookupdev (ebuf)))
    {
      printf ("%s: no suitable interface found, please specify one with -d\n", progname);
      return -1;
    }

  signal (SIGINT, on_ctrl_c);

  /* Announce */
  printf ("%s: requested to open #%d pcap-handle%s\n", progname, handles, handles > 1 ? "s" : "");

  /* Allocate enough memory to keep the pointers to the pcap-handle(s) */
  table = calloc ((handles + 1) * sizeof (pcap_t *), 1);
  for (p = 0; p < handles; p ++)
    table [p] = NULL;
  table [p] = NULL;

  /* Open the interface for packet capturing */
  for (p = 0; p < handles; p ++)
    if (! (table [p] = pcap_open_live (interface, snapshot, promiscuous, 1000, ebuf)))
      {
	printf ("%s: cannot open interface '%s' due to '%s'\n", progname, interface, ebuf);
	return -1;
      }

  printf ("%s: listening from %s using %s\n\n", progname, interface, pcap_lib_version ());

  /* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

  if (hb == -1)
    hb = maxcount / DEFAULT_HB;
  if (! hb)
    hb = 1;

  printf ("%s: starting to capture #%lu pckts using #%d pcap-handle%s...\n", progname, maxcount, handles, handles > 1 ? "s" : "");

  gettimeofday (& started, NULL);

  p = 0;
  while (! maxcount || (partial + errors) < maxcount)
    {
      /* Please give me just a packet at once from the interface */
      if ((packet = pcap_next (table [p], & header)))
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

      /* Round-robin to choose the pcap-handle candidate for the packet capture */
      p = (p + 1) % handles;
    }

  /* Close the pcap-handle(s) */
  for (p = 0; p < handles; p ++)
    pcap_close (table [p]);
  free (table);

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
