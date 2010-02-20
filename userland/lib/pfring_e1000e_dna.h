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

#ifndef _PFRING_E1000_DNA_H_
#define _PFRING_E1000_DNA_H_

/* Receive Descriptor */
struct e1000_rx_desc {
  u_int64_t buffer_addr; /* Address of the descriptor's data buffer */
  u_int16_t length;      /* Length of data DMAed into data buffer */
  u_int16_t csum;        /* Packet checksum */
  u_int8_t  status;      /* Descriptor status */
  u_int8_t  errors;      /* Descriptor Errors */
  u_int16_t special;
};

#define E1000_RDT(_n)     ((_n) < 4 ? (0x02818 + ((_n) * 0x100)) : (0x0C018 + ((_n) * 0x40)))

#define E1000_RXD_STAT_DD 0x01

#define wmb()	__asm__ __volatile__ ("": : :"memory")

extern void set_e1000_rx_register(pfring* ring, u_int32_t value);
extern u_int32_t get_e1000_rx_register(pfring* ring);
extern u_int8_t e1000_there_is_a_packet_to_read(pfring* ring, 
						u_int8_t wait_for_incoming_packet);
extern char* get_next_e1000_packet(pfring* ring, char* buffer, u_int buffer_len, 
				   struct pfring_pkthdr *hdr);
extern void init_e1000(pfring* ring);
extern void term_e1000(pfring* ring);
extern void pfring_dump_dna_e1000_stats(pfring* ring);

#endif /* _PFRING_E1000_DNA_H_ */
