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
#if !defined(__FAVOR_BSD)
# define __FAVOR_BSD
#endif

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

/* PF_RING header file(s) */
#include "pfring.h"


/* Global definitions and variables */

static pfring * ring = NULL;
static char packet [2048];     /* the room for incoming packets */


/* Function definition */

/* stolen from the addrtoname.c in tcpdump */
#define NOMAC    "00:00:00:00:00:00"

static char hex [] = "0123456789abcdef";

static char * etheraddr (u_char * e)
{
  static char buf [sizeof (NOMAC) + 1];

  int i;
  int j;
  char * p;

  /* hacked to manage DLT_NULL */
  if (! e)
    return (NOMAC);

  p = buf;
  if ((j = * e >> 4) != 0)
    * p ++ = hex [j];
  else
    * p ++ = '0';
  * p ++ = hex [* e ++ & 0xf];
  for (i = 5; -- i >= 0; )
    {
      * p ++ = ':';
      if ((j = * e >> 4) != 0)
	* p ++ = hex [j];
      else
	* p ++ = '0';
    * p ++ = hex [* e ++ & 0xf];
    }
  * p = '\0';

  return buf;
}


static char * proto2a (u_short proto)
{

  switch (proto)
    {
    case IPPROTO_IP:       return "IP";
    case IPPROTO_ICMP:     return "ICMP";
    case IPPROTO_IGMP:     return "IGMP";
    case IPPROTO_IPIP:     return "IPIP";
    case IPPROTO_TCP:      return "TCP";
    case IPPROTO_EGP:      return "EGP";
    case IPPROTO_PUP:      return "PUP";
    case IPPROTO_UDP:      return "UDP";
    case IPPROTO_IDP:      return "IDP";
    case IPPROTO_TP:       return "TP";
    case IPPROTO_IPV6:     return "IPV6";
    case IPPROTO_ROUTING:  return "ROUTING";
    case IPPROTO_FRAGMENT: return "FRAGMENT";
    case IPPROTO_RSVP:     return "RSVP";
    case IPPROTO_GRE:      return "GRE";
    case IPPROTO_ESP:      return "ESP";
    case IPPROTO_AH:       return "AH";
    case IPPROTO_ICMPV6:   return "ICMPV6";
    case IPPROTO_NONE:     return "NONE";
    }
  return "Unknown";
}




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


#
# Attempt to read next incoming packet when available on the interface,
# parse it for data at the application level (Layer 7) and return
# all the fields relevant at the application level, including:
# source and destination MAC addresses
# source and destination IP addresses
# source and destination port number
# packet payload
#
void xs_pfring_l7_next (pfref)
     pfring * pfref
PPCODE:
{
  struct pfring_pkthdr header;

  EXTEND (sp, 7);

  while (ring && pfring_recv (ring, packet, sizeof (packet), & header, 1) > 0)
    {
      /* Hook to the Ethernet Protocol in the packet */
      struct ether_header * e = (struct ether_header *) packet;

      /* Ethernet sizes */
      int eth_size = header . len;
      int eth_hlen = sizeof (struct ether_header);

      /* Process only IP packets only */
      if (ntohs (e -> ether_type) == ETHERTYPE_IP)
	{
	  /* Hook to the IP Protocol in the packet */
	  struct ip * ip = (struct ip *) (packet + eth_hlen);

	  /* IP sizes
	   *
	   * ip->ip_hl*4       = size of the IP (Header Only)
	   * ntohs(ip->ip_len) = size of the IP (Full Packet)
	   *           ip_size = eth_size - eth_hlen (better IMO)
	   */
	  int ip_size = eth_size - eth_hlen;
	  int ip_hlen = ip -> ip_hl * 4;

	  /* Process only TCP packets only */
	  if (ip -> ip_p == IPPROTO_TCP)
	    {
	      /* TCP Protocol */
	      u_char * q = (u_char *) ip + ip_hlen;
	      struct tcphdr * tcp = (struct tcphdr *) q;

	      /* TCP sizes
	       *
	       * tcp->th_off*4 = size of the TCP (Header Only)
	       */
	      int tcp_size = ip_size - ip_hlen;
	      int tcp_hlen = tcp -> th_off * 4;

	      /* Layer 7 Application Protocol */
	      char * l7 = (char *) e + eth_hlen + ip_hlen + tcp_hlen;

	      /* Layer 7 Application Protocol Packet Size */
	      int l7_size = header . caplen - (l7 - packet);

	      if (l7_size)
		{
		  char * s;
		  char * d;
		  int len;
		  char payload [2048 * 2 + 1] = "";

		  PUSHs (sv_2mortal (newSVpv (etheraddr ((u_char *) & e -> ether_shost), FALSE)));
		  PUSHs (sv_2mortal (newSVpv (etheraddr ((u_char *) & e -> ether_dhost), FALSE)));

		  PUSHs (sv_2mortal (newSVpv (inet_ntoa (ip -> ip_src), FALSE)));
		  PUSHs (sv_2mortal (newSViv (ntohs (tcp -> th_sport))));
		  PUSHs (sv_2mortal (newSVpv (inet_ntoa (ip -> ip_dst), FALSE)));
		  PUSHs (sv_2mortal (newSViv (ntohs (tcp -> th_dport))));

		  s = l7;
		  d = payload;
		  len = l7_size;
		  while (len)
		    {
		      sprintf (d, "%02x", * s & 0x000000ff);
		      s ++;
		      d += 2;
		      len --;
		    }
		  * d = '\0';

		  PUSHs (sv_2mortal (newSVpv (payload, FALSE)));

		  break;      /* Done! */
		}
	    }
	}
    }
}


void xs_pfring_l347_next (pfref)
     pfring * pfref
PPCODE:
{
  struct pfring_pkthdr header;

  EXTEND (sp, 20);

  while (ring && pfring_recv (ring, packet, sizeof (packet), & header, 1) > 0)
    {
      if (header . parsed_pkt . l3_proto)
	{
	  struct in_addr addr;
	  int len;
	  char * s;
	  char * d;
	  char payload [2048 * 2 + 1] = "";
	  char tutto [2048 * 2 + 1] = "";

	  PUSHs (sv_2mortal (newSViv (header . ts . tv_sec)));
	  PUSHs (sv_2mortal (newSViv (header . ts . tv_usec)));
	  PUSHs (sv_2mortal (newSViv (header . caplen)));
	  PUSHs (sv_2mortal (newSViv (header . len)));
	  PUSHs (sv_2mortal (newSViv (header . parsed_pkt . eth_type)));
	  PUSHs (sv_2mortal (newSViv (header . parsed_pkt . vlan_id)));
	  PUSHs (sv_2mortal (newSVpv (proto2a (header . parsed_pkt . l3_proto), FALSE)));
	  PUSHs (sv_2mortal (newSViv (header . parsed_pkt . ipv4_tos)));
	  PUSHs (sv_2mortal (newSViv (header . parsed_pkt . tcp. flags)));

	  addr . s_addr = header . parsed_pkt . ipv4_src;
	  PUSHs (sv_2mortal (newSVpv (inet_ntoa (addr), FALSE)));
	  PUSHs (sv_2mortal (newSViv (header . parsed_pkt . l4_src_port)));

	  addr . s_addr = header . parsed_pkt . ipv4_dst;
	  PUSHs (sv_2mortal (newSVpv (inet_ntoa (addr), FALSE)));
	  PUSHs (sv_2mortal (newSViv (header . parsed_pkt . l4_dst_port)));

	  PUSHs (sv_2mortal (newSViv (header . parsed_pkt . pkt_detail . offset . eth_offset)));
	  PUSHs (sv_2mortal (newSViv (header . parsed_pkt . pkt_detail . offset . vlan_offset)));
	  PUSHs (sv_2mortal (newSViv (header . parsed_pkt . pkt_detail . offset . l3_offset)));
	  PUSHs (sv_2mortal (newSViv (header . parsed_pkt . pkt_detail . offset . l4_offset)));
	  PUSHs (sv_2mortal (newSViv (header . parsed_pkt . pkt_detail . offset . payload_offset)));

	  len = header . caplen;
	  s = packet;
	  d = tutto;
	  while (len)
	    {
	      sprintf (d, "%02x", * s & 0x000000ff);
	      s ++;
	      d += 2;
	      len --;
	    }
	  * d = '\0';
	  PUSHs (sv_2mortal (newSVpv (tutto, FALSE)));

	  len = header . caplen - header . parsed_pkt . pkt_detail . offset . payload_offset - header . parsed_pkt . pkt_detail . offset . eth_offset;
	  s = packet + header . parsed_pkt . pkt_detail . offset . payload_offset;
	  d = payload;
	  while (len)
	    {
	      sprintf (d, "%02x", * s & 0x000000ff);
	      s ++;
	      d += 2;
	      len --;
	    }
	  * d = '\0';
	  PUSHs (sv_2mortal (newSVpv (payload, FALSE)));

	  break; /* Done! */
	}
    }
}


void xs_pfring_header (pfref, h)
     pfring * pfref
     SV * h

 CODE:

  struct pfring_pkthdr header;

  while (ring && pfring_recv (ring, packet, sizeof (packet), & header, 1) > 0)
    {
      if (header . parsed_pkt . l3_proto)
	{
	  /* Fill the %info hash fields */
	  struct in_addr addr;
	  int len;
	  char * s;
	  char * d;
	  char payload [2048 * 2 + 1] = "";
	  char tutto [2048 * 2 + 1] = "";

	  HV * info = (HV *) SvRV (h);	
	  hv_store (info, "a-seconds", strlen ("a-seconds"), newSViv (header . ts . tv_sec), 0);
	  hv_store (info, "b-microseconds", strlen ("b-microseconds"), newSViv (header . ts . tv_usec), 0);
	  hv_store (info, "c-caplen", strlen ("c-caplen"), newSViv (header . caplen), 0);
	  hv_store (info, "d-len", strlen ("d-len"), newSViv (header . len), 0);
	  hv_store (info, "e-eth_type", strlen ("e-eth_type"), newSViv (header . parsed_pkt . eth_type), 0);
	  hv_store (info, "f-vlan_id", strlen ("f-vlan_id"), newSViv (header . parsed_pkt . vlan_id), 0);
	  hv_store (info, "g-l3_proto", strlen ("g-l3_proto"), newSViv (header . parsed_pkt . l3_proto), 0);
	  hv_store (info, "h-ipv4_tos", strlen ("h-ipv4_tos"), newSViv (header . parsed_pkt . ipv4_tos), 0);

	  addr . s_addr = header . parsed_pkt . ipv4_src;
	  hv_store (info, "i-ipv4_src", strlen ("i-ipv4_src"), newSVpv (inet_ntoa (addr), FALSE), 0);
	  addr . s_addr = header . parsed_pkt . ipv4_dst;
	  hv_store (info, "j-ipv4_dst", strlen ("j-ipv4_dst"), newSVpv (inet_ntoa (addr), FALSE), 0);

	  hv_store (info, "k-l4_src_port", strlen ("k-l4_src_port"), newSViv (header . parsed_pkt . l4_src_port), 0);
	  hv_store (info, "l-l4_dst_port", strlen ("l-l4_dst_port"), newSViv (header . parsed_pkt . l4_dst_port), 0);
	  hv_store (info, "m-tcp_flags", strlen ("m-tcp_flags"), newSViv (header . parsed_pkt . tcp.flags), 0);
	  hv_store (info, "n-eth_offset", strlen ("n-eth_offset"), newSViv (header . parsed_pkt . pkt_detail . offset . eth_offset), 0);
	  hv_store (info, "o-vlan_offset", strlen ("o-vlan_offset"), newSViv (header . parsed_pkt . pkt_detail . offset . vlan_offset), 0);
	  hv_store (info, "p-l3_offset", strlen ("p-l3_offset"), newSViv (header . parsed_pkt . pkt_detail . offset . l3_offset), 0);
	  hv_store (info, "q-l4_offset", strlen ("q-l4_offset"), newSViv (header . parsed_pkt . pkt_detail . offset . l4_offset), 0);
	  hv_store (info, "r-payload_offset", strlen ("r-payload_offset"), newSViv (header . parsed_pkt . pkt_detail . offset . payload_offset), 0);

	  len = header . caplen - header . parsed_pkt . pkt_detail . offset . payload_offset - header . parsed_pkt . pkt_detail . offset . eth_offset;
	  s = packet + header . parsed_pkt . pkt_detail . offset . payload_offset;
	  d = payload;
	  while (len)
	    {
	      sprintf (d, "%02x", * s & 0x000000ff);
	      s ++;
	      d += 2;
	      len --;
	    }
	  * d = '\0';
	  hv_store (info, "s-payload", strlen ("s-payload"), newSVpv (payload, FALSE), 0);

	  len = header . caplen;
	  s = packet;
	  d = tutto;
	  while (len)
	    {
	      sprintf (d, "%02x", * s & 0x000000ff);
	      s ++;
	      d += 2;
	      len --;
	    }
	  * d = '\0';
	  hv_store (info, "t-tutto", strlen ("t-tutto"), newSVpv (tutto, FALSE), 0);

	  break; /* Done! */
	}
    }
