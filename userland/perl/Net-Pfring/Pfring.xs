/*
 * Perl Net-Pfring - XS wrapper for PF_RING
 *
 * Pfring.xs - "the meat" of the entire package
 *
 * Copyright (c) 2008 Rocco Carbone <rocco /at/ ntop /dot/ org>
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *
 * This program is free software; you can redistribute it and/or modify 
 * it under the same terms as Perl itself.
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *
 */


/* perl include files */
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

/* Operating System header file(s) */
#include <net/ethernet.h>

/* PF_RING header file(s) */
#include "pfring.h"


/* Global definitions and variables */

static pfring * ring = NULL;


/* Function definition */


/* The name of the game! */
MODULE = Net::Pfring  PACKAGE = Net::Pfring  PREFIX = xs_pfring

#
# Attempt to open a device for packet capturing and filtering
#
pfring * xs_pfring_open (device = "eth0", promisc = 1, caplen = 1500)
  char * device
  int promisc
  int caplen
CODE:
{
  if (! ring)
    {
      ring = pfring_open (device, promisc, caplen, 0);
      if (ring)
	RETVAL = ring;
      else
	RETVAL = NULL;
    }
  else
    RETVAL = NULL;
}
OUTPUT:
 RETVAL


#
# Attempt to close a device for packet capturing and filtering
#
void xs_pfring_close (pfref)
      pfring * pfref
CODE:
{
  if (! ring)
    return;

  pfring_close (ring);
  ring = NULL;
}


#
# Attempt to read next incoming packet when available on the interface
#
void xs_pfring_next (pfref)
     pfring * pfref
PPCODE:
{
  char packet [2048];           /* the room for incoming packet data */
  char payload [2048 * 2 + 1] = "";
  struct pfring_pkthdr header;
  char * s;
  char * d;
  unsigned short len;

  EXTEND (sp, 1);

  if (ring && pfring_recv (ring, packet, sizeof (packet), & header, 1) > 0)
    {
#if defined(ROCCO)
      len = header . caplen -
	header . parsed_pkt . pkt_detail . offset . payload_offset -
	header . parsed_pkt . pkt_detail . offset . eth_offset;
#else
      len = header . caplen;
#endif /* ROCCO */
      if (len)
	{
	  s = packet + len;
	  d = payload;
	  while (len)
	    {
	      sprintf (d, "%02x", * s & 0x000000ff);
	      s ++;
	      d += 2;
	      len --;
	    }
	  * d = '\0';
	}
    }
  PUSHs (sv_2mortal (newSVpv (payload, FALSE)));
}


#
# Attempt to obtain statistics information
#
void xs_pfring_stats (pfref)
     pfring * pfref
PPCODE:
{
  pfring_stat stats;

  EXTEND (sp, 2);

  if (ring)
    {
      pfring_stats (ring, & stats);

      PUSHs (sv_2mortal (newSViv (stats . recv)));
      PUSHs (sv_2mortal (newSViv (stats . drop)));
    }
  else
    {
      PUSHs (sv_2mortal (newSViv (0)));
      PUSHs (sv_2mortal (newSViv (0)));
    }
}


#
# Attempt to obtain version information
#
void xs_pfring_version (pfref)
     pfring * pfref
PPCODE:
{
  u_int32_t version;

  EXTEND (sp, 3);

  if (ring)
    {
      pfring_version (ring, & version);

      PUSHs (sv_2mortal (newSViv ((version & 0xFFFF0000) >> 16)));
      PUSHs (sv_2mortal (newSViv ((version & 0x0000FF00) >> 8)));
      PUSHs (sv_2mortal (newSViv (version & 0x000000FF)));
    }
  else
    {
      PUSHs (sv_2mortal (newSViv (0)));
      PUSHs (sv_2mortal (newSViv (0)));
      PUSHs (sv_2mortal (newSViv (0)));
    }
}


#
# Attempt to read next incoming packet when available on the interface
# and return only the ethernet header
#
void xs_pfring_ethernet (pfref)
     pfring * pfref
PPCODE:
{
  char packet [2048];           /* the room for incoming packet data */
  char payload [2048 * 2 + 1] = "";
  struct pfring_pkthdr header;
  char * s;
  char * d;
  unsigned short len;

  EXTEND (sp, 1);

  if (ring && pfring_recv (ring, packet, sizeof (packet), & header, 1) > 0)
    {
      len = sizeof (struct ether_header);
      s = packet;
      d = payload;
      while (len)
	{
	  sprintf (d, "%02x", * s & 0x000000ff);
	  s ++;
	  d += 2;
	  len --;
	}
      * d = '\0';
    }
  PUSHs (sv_2mortal (newSVpv (payload, FALSE)));
}
