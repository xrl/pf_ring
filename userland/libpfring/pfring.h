/*
 *
 * (C) 2005-07 - Luca Deri <deri@ntop.org>
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

#ifndef HAVE_PCAP
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/sockios.h>
#endif

#include <linux/ring.h>

#define PAGE_SIZE         4096

#define POLL_SLEEP_STEP         10 /* ns = 0.1 ms */
#define POLL_SLEEP_MIN        POLL_SLEEP_STEP
#define POLL_SLEEP_MAX        1000 /* ns */
#define POLL_QUEUE_MIN_LEN     500 /* # packets */

#ifdef SAFE_RING_MODE
static char staticBucket[2048];
#endif

/* ********************************* */

typedef struct {
  char *buffer, *slots, *device_name;
  int  fd;
  FlowSlotInfo *slots_info;
  u_int page_id, slot_id, pkts_per_page;
  u_int poll_sleep;
  u_char clear_promisc;
  u_long num_poll_calls;
} pfring;

typedef struct {
  u_long recv, drop;
} pfring_stat;

/* NOTE: keep 'struct pfring_pkthdr' in sync with 'struct pcap_pkthdr' (ring.h) */
struct pfring_pkthdr {
  struct timeval ts;    /* time stamp */
  u_int32_t caplen;     /* length of portion present */
  u_int32_t len;        /* length this packet (off wire) */
  /* packet parsing info */
  u_int16_t eth_type; /* Ethernet type */
  u_int16_t vlan_id;  /* VLAN Id or -1 for no vlan */
  u_int8_t  l3_proto;  /* Layer 3 protocol */
  u_int16_t l3_offset, l4_offset; /* Offsets of L3 and L4 elements */
  u_int32_t ipv4_src, ipv4_dst;   /* IPv4 src/dst IP addresses */
  u_int16_t l4_src_port, l4_dst_port; /* Layer 4 src/dst ports */ 
  u_int8_t tcp_flags;   /* TCP flags (0 if not available) */
};

/* ********************************* */

int pfring_set_cluster(pfring *ring, u_int clusterId);
int pfring_remove_from_cluster(pfring *ring);
int pfring_set_reflector(pfring *ring, char *reflectorDevice);
pfring* pfring_open(char *device_name, int promisc);
void pfring_close(pfring *ring);
int pfring_stats(pfring *ring, pfring_stat *stats);
int pfring_recv(pfring *ring, char* buffer, int buffer_len, 
		struct pfring_pkthdr *hdr, u_char wait_for_incoming_packet);

int pfring_add_filtering_rule(pfring *ring, filtering_rule* rule_to_add);
int pfring_remove_filtering_rule(pfring *ring, u_int16_t rule_id);
int pfring_toggle_filtering_policy(pfring *ring, u_int8_t rules_default_accept_policy);

