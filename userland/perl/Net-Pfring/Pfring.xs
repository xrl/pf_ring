/*
 * Pfring.xs - "the meat" of the entire package
 *
 * Perl Pfring - XS warapper for PF-Ring
 *
 * Copyright (c) 2008 Rocco Carbone
 *
 * Rocco Carbone <rocco /at/ ntop /dot/ org> 2Q 2008
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

/* PF-Ring header file(s) */
#include "pfring.h"


/* Global definitions and variables */

static pfring * ring = NULL;


/* Function definition */


/* The name of the game! */
MODULE = Net::Pfring  PACKAGE = Net::Pfring  PREFIX = xs_pfring

# BOOT:
# first blank line terminates bootstrap code


 ################################
 # Low Level exportable routines
 ################################

 #
 # Attempt to open a device for packet capturing and filtering
 #
pfring *
xs_pfring_open (device = NULL, promisc = 1)
 	char * device
	int promisc
CODE:
{
  if (! ring)
    {
      ring = pfring_open (device, promisc, 0);
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
void
xs_pfring_close (pfref)
 	pfring * pfref
CODE:
{
  if (! ring)
    return;

  pfring_close (ring);
  ring = NULL;
}


 #
 # Attempt to obtain version information
 #
void
xs_pfring_version (pfref)
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
 # Attempt to receive data
 #
void
xs_pfring_recv (pfref)
 	pfring * pfref
PPCODE:
{
  static unsigned int received;

  char packet [2048];
  char payload [2048 * 2] = "";
  char * s;
  char * d;
  struct pfring_pkthdr header;

  unsigned short len = 0;

  EXTEND (sp, 2);

  if (ring && pfring_recv (ring, packet, sizeof (packet), & header, 1) > 0)
    {
      len = header . caplen -
	header . parsed_pkt . pkt_detail . offset . payload_offset -
	header . parsed_pkt . pkt_detail . offset . eth_offset;
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
