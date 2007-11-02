/*
 *
 * (C) 2007 - Luca Deri <deri@ntop.org>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include "PFring.h"
#include <string.h>
#include <stdlib.h>
#include <poll.h>
#include <errno.h>

/* *********************************************** */

PFring::PFring(char* _device_name, u_int _snaplen, bool promisc, char *bpf) {
  char errbuf[PCAP_ERRBUF_SIZE];
  
  snaplen = _snaplen, device_name = NULL;

  if(_device_name == NULL)
    _device_name = pcap_lookupdev(errbuf);

  if(_device_name == NULL) 
    pcapPtr = NULL;
  else {
    pcapPtr = pcap_open_live(_device_name, snaplen, promisc ? 1 : 0, 500, errbuf);
    if(pcapPtr) {
      device_name = strdup(_device_name);
      if(bpf) add_bpf_filter(bpf);
    }
  }
}

/* *********************************************** */

PFring::~PFring() {
  if(pcapPtr) {
    if(device_name) free(device_name);
    pcap_close(pcapPtr);
    pcapPtr = NULL;
  }
}

/* *********************************************** */

int PFring::add_bpf_filter(char *the_filter) {
  struct bpf_program fcode;

  if(pcapPtr == NULL) return(-1);
  if(the_filter == NULL) return(0);

  if(the_filter != NULL) {
    if(pcap_compile(pcapPtr, &fcode, the_filter, 1, 0xFFFFFF00) < 0) {
      return(-2);
    } else {
      if(pcap_setfilter(pcapPtr, &fcode) < 0) {
	pcap_freecode(&fcode);
	return(-3);
      } else
	pcap_freecode(&fcode);
    }    
  } else
    return(0);
}

/* *********************************************** */

int PFring::get_next_packet(struct pfring_pkthdr *hdr, const u_char *pkt, u_int pkt_len) {
  if((!pcapPtr) || (!hdr) || (pkt_len < snaplen)) return(-1);
  
  if(pcapPtr->ring) {
    return(pfring_recv(pcapPtr->ring, (char*)pkt, pkt_len, hdr, 1 /* wait_for_incoming_packet */));
  } else {
    pcap_pkthdr *_hdr = (pcap_pkthdr*)hdr;
    return(pcap_next_ex(pcapPtr, &_hdr, &pkt));
  }
}

/* *********************************************** */

bool PFring::wait_for_packets(int msec) {
  struct pollfd pfd;
  int rc;

  /* Sleep when nothing is happening */
  pfd.fd      = get_socket_id();
  pfd.events  = POLLIN|POLLERR;
  pfd.revents = 0;

  errno = 0;
  rc = poll(&pfd, 1, msec);
    
  if(rc == -1)
    return(false);
  else
    return((rc > 0) ? true : false);    
}
