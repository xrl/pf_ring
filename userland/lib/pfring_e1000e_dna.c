/*
 *
 * (C) 2008-10 - Luca Deri <deri@ntop.org>
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

#include "pfring.h"


time_t us(struct timeval * t)
{
  return t -> tv_sec * 1000000.0 + t -> tv_usec;
}

/* *************************************** */

inline u_int32_t get_e1000_rx_register(pfring* ring) {
  return((ring->rx_reg = *ring->rx_reg_ptr[ring->dna_dev.channel_id]));
}

/* *************************************** */

inline void set_e1000_rx_register(pfring* ring, u_int32_t value) { 
  *ring->rx_reg_ptr[ring->dna_dev.channel_id] = value, ring->rx_reg = value;
}

/* *************************************** */

char* get_next_e1000_packet(pfring* ring, 
			    char* buffer, u_int buffer_len, 
			    struct pfring_pkthdr *hdr) {
  struct e1000_rx_desc *head = (struct e1000_rx_desc*)ring->dna_dev.descr_packet_memory;
  char *pkt = (char*)ring->dna_dev.packet_memory;
  int offset = ring->rx_reg * ring->dna_dev.packet_memory_slot_len;

  if(head[ring->rx_reg].status) {
    hdr->len = head[ring->rx_reg].length;
    gettimeofday(&hdr->ts, NULL), memcpy(buffer, &pkt[offset], hdr->caplen = min(buffer_len, hdr->len));
    ring->tot_dna_read_pkts++;
    head[ring->rx_reg].status = 0; /* We've handled the packet */
  
    if(++ring->rx_reg == ring->dna_dev.descr_packet_memory_num_slots)
      ring->rx_reg = 0;

    if((ring->rx_reg % 32) == 0) {
      wmb(); /* Flush out memory first */  
      set_e1000_rx_register(ring, ring->rx_reg);  
    }
    
    /*
      FIX: increment packet read
      
      adapter->total_rx_bytes = 0;
      adapter->total_rx_packets = 0;
    */

    return(buffer);
  } else {
    hdr->len = 0;
    return(NULL);
  }
}

/* *************************************** */

u_int8_t e1000_there_is_a_packet_to_read(pfring* ring, u_int8_t wait_for_incoming_packet) {
  struct e1000_rx_desc *head = (struct e1000_rx_desc*)ring->dna_dev.descr_packet_memory;
  u_int8_t ret;

 do_e1000_there_is_a_packet_to_read:
  ret = head[ring->rx_reg].status & E1000_RXD_STAT_DD;
  
  if(ret || (wait_for_incoming_packet == 0))
    return(ret);
  else {
    struct pollfd pfd;
    int rc;

    if(0) printf("* poll [wait_for_incoming_packet=%d]*\n", wait_for_incoming_packet);

#ifdef PROFILE    
    struct timeval now, then;

    gettimeofday (& now, NULL);
#endif

    /* Make sure we're in sync */
    set_e1000_rx_register(ring, ring->rx_reg);

    /* Sleep when nothing is happening */
    pfd.fd      = ring->fd;
    pfd.events  = POLLIN|POLLERR;
    pfd.revents = 0;

    errno = 0;
    rc = poll(&pfd, 1, 1);
    ring->num_poll_calls++;

#ifdef PROFILE    
    gettimeofday (& then, NULL);

    printf("poll took %u usec [calls %u]\n", 
	   us(&then)-us(&now), ring->num_poll_calls);
#endif

    if(rc == -1) {
#if 0
      printf("poll failed [rc=%d][errno=%d/%s]\n",
	     rc, errno, strerror(errno));
#endif
      return(-1);
    } else
      goto do_e1000_there_is_a_packet_to_read;
  }
}

/* **************************************************** */

void init_e1000(pfring* ring) {
  ring->rx_reg_ptr[ring->dna_dev.channel_id] = (u_int32_t*)&ring->dna_dev.phys_card_memory[E1000_RDT(ring->dna_dev.channel_id)];
  ring->rx_reg = get_e1000_rx_register(ring);
}

/* **************************************************** */

void term_e1000(pfring* ring) {
  set_e1000_rx_register(ring, ring->rx_reg);
  /* printf("term_e1000() called\n"); */
}

/* **************************************************** */

void pfring_dump_dna_e1000_stats(pfring* ring) {
  int i, j, offset = 0;
  struct e1000_rx_desc *head;
  char *ptr;

  head = (struct e1000_rx_desc*)ring->dna_dev.descr_packet_memory;
  for(i=0; i<8 /* ring->dna_dev.descr_packet_memory_num_slots*/; i++) {
    if(head[offset].status & 0x01 /* E1000_RXD_STAT_DD */)
      printf("[%d=%d/len=%d]", offset,
	     head[offset].status, (head[offset].length));
    offset += ring->dna_dev.descr_packet_memory_slot_len;
  }

  /* ************************************************** */

  printf("\n[channel_id=%d][next_to_clean=%d]",
	 ring->dna_dev.channel_id, get_e1000_rx_register(ring));

  /* ************************************************** */

  ptr = (char*)ring->dna_dev.packet_memory;
  offset = 0;
  for(j=0; j<8; j++) {
    printf("\n[%d - %08d] ", j, offset);
    for(i=0; i<16; i++) printf("%02X ", ptr[i+offset] & 0xFF);
    offset += ring->dna_dev.packet_memory_slot_len;
  }

  printf("\n");
}

