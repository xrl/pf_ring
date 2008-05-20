/*
 *
 * (C) 2005-08 - Luca Deri <deri@ntop.org>
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

#define __USE_XOPEN2K
#include <sys/types.h>
#include <pthread.h>

#include "pfring.h"

// #define RING_DEBUG


/* ******************************* */

unsigned long long rdtsc() {
  unsigned long long a;
  asm volatile("rdtsc":"=A" (a));
  return(a);
}

/* ******************************* */

int pfring_set_cluster(pfring *ring, u_int clusterId) {
#ifdef USE_PCAP
  return(-1);
#else
  return(ring ? setsockopt(ring->fd, 0, SO_ADD_TO_CLUSTER,
			      &clusterId, sizeof(clusterId)): -1);
#endif
}

/* ******************************* */

int pfring_remove_from_cluster(pfring *ring) {
#ifdef USE_PCAP
  return(-1);
#else
  return(ring ? setsockopt(ring->fd, 0, SO_REMOVE_FROM_CLUSTER, 
			      NULL, 0) : -1);
#endif
}

/* ******************************* */

int pfring_set_reflector(pfring *ring, char *reflectorDevice) {
#ifdef USE_PCAP
  return(-1);
#else
  return(ring ?
	 setsockopt(ring->fd, 0, SO_SET_REFLECTOR,
		    reflectorDevice, strlen(reflectorDevice)) : -1);
#endif
}

/* ******************************* */

#ifndef USE_PCAP
static int set_if_promisc(const char *device, int set_promisc) {
  int sock_fd;
  struct ifreq ifr;

  if(device == NULL) return(-3);

  sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if(sock_fd <= 0) return(-1);
  
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
  if(ioctl(sock_fd, SIOCGIFFLAGS, &ifr) == -1) {  
    close(sock_fd);
    return(-2);
  }	  

  if(set_promisc) {
    if((ifr.ifr_flags & IFF_PROMISC) == 0) ifr.ifr_flags |= IFF_PROMISC;
  } else {
    /* Remove promisc */
    if((ifr.ifr_flags & IFF_PROMISC) != 0) ifr.ifr_flags &= ~IFF_PROMISC;    
  }
  
  if(ioctl(sock_fd, SIOCSIFFLAGS, &ifr) == -1) 
    return(-1);
  
  close(sock_fd);
  return(0);
}
#endif

/* **************************************************** */

pfring* pfring_open(char *device_name, u_int8_t promisc, u_int8_t _reentrant) {
#ifdef USE_PCAP
  char ebuf[256];

  pcap_t *pcapPtr = pcap_open_live(device_name,
				   1500,
				   1 /* promiscuous mode */,
				   1000 /* ms */,
				   ebuf);

  return((pfring*)pcapPtr);
#else
  int err = 0;
  pfring *ring = (pfring*)malloc(sizeof(pfring));
  
  if(ring == NULL) 
    return(NULL);
  else
    memset(ring, 0, sizeof(pfring));

  ring->reentrant = _reentrant;
  ring->fd = socket(PF_RING, SOCK_RAW, htons(ETH_P_ALL));

#ifdef RING_DEBUG
  printf("Open RING [fd=%d]\n", ring->fd);
#endif

  if(ring->fd > 0) {
    struct sockaddr sa;
    int             rc;
    u_int memSlotsLen;

    sa.sa_family   = PF_RING;
    snprintf(sa.sa_data, sizeof(sa.sa_data), "%s", device_name);
    rc = bind(ring->fd, (struct sockaddr *)&sa, sizeof(sa));

    if(rc == 0) {
      ring->buffer = (char *)mmap(NULL, PAGE_SIZE,
				       PROT_READ|PROT_WRITE,
				       MAP_SHARED,
				       ring->fd, 0);

      if(ring->buffer == MAP_FAILED) {
	printf("mmap() failed");
	free(ring);
	return (NULL);	
      }

      ring->slots_info = (FlowSlotInfo *)ring->buffer;
      if(ring->slots_info->version != RING_FLOWSLOT_VERSION) {
	printf("Wrong RING version: "
	       "kernel is %i, libpfring was compiled with %i\n",
	       ring->slots_info->version, RING_FLOWSLOT_VERSION);
	free(ring); 
	return (NULL);
      }
      memSlotsLen = ring->slots_info->tot_mem;
      munmap(ring->buffer, PAGE_SIZE);

      ring->buffer = (char *)mmap(NULL, memSlotsLen,
				 PROT_READ|PROT_WRITE,
				 MAP_SHARED, ring->fd, 0);

      if(ring->buffer == MAP_FAILED) {
	printf("mmap() failed");
	free(ring);
	return (NULL);
      }

      ring->slots_info   = (FlowSlotInfo *)ring->buffer;
      ring->slots = (char *)(ring->buffer+sizeof(FlowSlotInfo));

      /* Safety check */
      if(ring->slots_info->remove_idx >= ring->slots_info->tot_slots)
	ring->slots_info->remove_idx = 0;

      ring->page_id = PAGE_SIZE, ring->slot_id = 0, ring->pkts_per_page = 0;

      /* Set defaults */
      ring->device_name = strdup(device_name);

#ifdef RING_DEBUG
      printf("RING (%s): tot_slots=%d/slot_len=%d/"
	     "insertIdx=%d/remove_idx=%d/dropped=%d\n",
	     device_name,
	     ring->slots_info->tot_slots,
	     ring->slots_info->slot_len,
	     ring->slots_info->insert_idx,
	     ring->slots_info->remove_idx,
	     ring->slots_info->tot_lost);
#endif

      if(promisc) {
	if(set_if_promisc(device_name, 1) == 0)
	  ring->clear_promisc = 1;
      }

    } else {
      close(ring->fd);
      err = -1;
    }
  } else {
    err = -1; 
    free(ring);
  }

  if(err == 0) {
    if(ring->reentrant)
      pthread_spin_init(&ring->spinlock, PTHREAD_PROCESS_PRIVATE);    
    return(ring);
  } else    
    return(NULL);
#endif
}

/* **************************************************** */

void pfring_close(pfring *ring) {
#ifdef USE_PCAP
  pcap_t *pcapPtr = (pcap_t*)ring;
  pcap_close(pcapPtr);
#else
  if(!ring) return;

  if(ring->buffer != NULL) {
    munmap(ring->buffer, ring->slots_info->tot_mem);
  }

  if(ring->clear_promisc)
    set_if_promisc(ring->device_name, 0);

  free(ring->device_name);
  close(ring->fd);

  if(ring->reentrant)
    pthread_spin_destroy(&ring->spinlock);

  free(ring);
#endif
}

/* **************************************************** */

int pfring_toggle_filtering_policy(pfring *ring, u_int8_t rules_default_accept_policy) {
#ifdef USE_PCAP
  return(-1);
#else
  return(ring ? setsockopt(ring->fd, 0, SO_TOGGLE_FILTER_POLICY, 
			   &rules_default_accept_policy,
			   sizeof(rules_default_accept_policy)): -1);
#endif
}

/* **************************************************** */

int pfring_version(pfring *ring, u_int32_t *version) {
#ifdef USE_PCAP
  return(-1);
#else
  if(ring == NULL) 
    return(-1);
  else {
    socklen_t len = sizeof(u_int32_t);
    return(getsockopt(ring->fd, 0, SO_GET_RING_VERSION, version, &len));
  }
#endif
}

/* **************************************************** */

int pfring_get_filtering_rule_stats(pfring *ring, u_int16_t rule_id,
				    char* stats, u_int *stats_len) {
#ifdef USE_PCAP
  return(-1);
#else
  if((ring == NULL) || (*stats_len < sizeof(u_int16_t)))
    return(-1);
  else {
    memcpy(stats, &rule_id, sizeof(u_int16_t));
    return(getsockopt(ring->fd, 0,
		      SO_GET_FILTERING_RULE_STATS,
		      stats, stats_len));
  }
#endif
}

/* **************************************************** */

int pfring_get_hash_filtering_rule_stats(pfring *ring,
					 hash_filtering_rule* rule,
					 char* stats, u_int *stats_len) {
#ifdef USE_PCAP
  return(-1);
#else
  if(ring == NULL)
    return(-1);
  else {
    char buffer[2048];
    int rc;
    u_int len;
    
    memcpy(buffer, rule, sizeof(hash_filtering_rule));
    len = sizeof(buffer);
    rc = getsockopt(ring->fd, 0,
		    SO_GET_HASH_FILTERING_RULE_STATS,
		    buffer, &len);
    if(rc < 0) 
      return(rc);
    else {
      *stats_len = min(*stats_len, rc);
      memcpy(stats, buffer, *stats_len);
      return(0);
    }
  }
#endif
}

/* **************************************************** */

int pfring_add_filtering_rule(pfring *ring, filtering_rule* rule_to_add) {
#ifdef USE_PCAP
  return(-1);
#else
  int rc;

  if((!rule_to_add) || (!ring)) return(-1);

  /* Sanitize entry */
  if(rule_to_add->core_fields.port_low > rule_to_add->core_fields.port_high)
    rule_to_add->core_fields.port_low = rule_to_add->core_fields.port_high;
  if(rule_to_add->core_fields.host_low > rule_to_add->core_fields.host_high)
    rule_to_add->core_fields.host_low = rule_to_add->core_fields.host_high;
  
  if(rule_to_add->balance_id > rule_to_add->balance_pool)
    rule_to_add->balance_id = 0;
  
  rc = setsockopt(ring->fd, 0, SO_ADD_FILTERING_RULE,
		  rule_to_add, sizeof(filtering_rule));

  return(rc);
#endif
}

/* **************************************************** */

int pfring_enable_ring(pfring *ring) {
#ifdef USE_PCAP
  return(-1);
#else
  char dummy;

  if(!ring) return(-1);
  return(setsockopt(ring->fd, 0, SO_ACTIVATE_RING, &dummy, sizeof(dummy)));
#endif
}

/* **************************************************** */

int pfring_remove_filtering_rule(pfring *ring, u_int16_t rule_id) {
#ifdef USE_PCAP
  return(-1);
#else
  int rc;

  rc = ring ? setsockopt(ring->fd, 0, SO_REMOVE_FILTERING_RULE,
			 &rule_id, sizeof(rule_id)): -1;

  return(rc);
#endif
}

/* **************************************************** */

int pfring_handle_hash_filtering_rule(pfring *ring, 
				      hash_filtering_rule* rule_to_add,
				      u_char add_rule) {
#ifdef USE_PCAP
  return(-1);
#else
  int rc;

  if((!rule_to_add) || (!ring)) return(-1);

  rc = setsockopt(ring->fd, 0, add_rule ? SO_ADD_FILTERING_RULE : SO_REMOVE_FILTERING_RULE,
		  rule_to_add, sizeof(hash_filtering_rule));

  return(rc);
#endif
}

/* **************************************************** */

int pfring_set_sampling_rate(pfring *ring, u_int32_t rate /* 1 = no sampling */) {
#ifdef USE_PCAP
  return(-1);
#else
  int rc;

  rc = ring ? setsockopt(ring->fd, 0, SO_SET_SAMPLING_RATE,
			 &rate, sizeof(rate)): -1;

  return(rc);
#endif
}

/* ******************************* */

int pfring_stats(pfring *ring, pfring_stat *stats) {
#ifdef USE_PCAP
  return(-1);
#else
  if(ring && stats) {
    stats->recv = ring->slots_info->tot_read;
    stats->drop = ring->slots_info->tot_lost;
    return(1);
  } else
    return(0);
#endif
}

/* **************************************************** */

#ifdef USE_PCAP
struct eth_hdr {
  unsigned char   h_dest[ETH_ALEN];       /* destination eth addr */
  unsigned char   h_source[ETH_ALEN];     /* source ether addr    */
  u_int16_t          h_proto;                /* packet type ID field */
};

#define __LITTLE_ENDIAN_BITFIELD /* FIX */
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u_int8_t	ihl:4,
		version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	u_int8_t	version:4,
  		ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	u_int8_t	tos;
	u_int16_t	tot_len;
	u_int16_t	id;
	u_int16_t	frag_off;
	u_int8_t	ttl;
	u_int8_t	protocol;
	u_int16_t	check;
	u_int32_t	saddr;
	u_int32_t	daddr;
	/*The options start here. */
};

struct tcphdr {
	u_int16_t	source;
	u_int16_t	dest;
	u_int32_t	seq;
	u_int32_t	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif	
	u_int16_t	window;
	u_int16_t	check;
	u_int16_t	urg_ptr;
};

struct udphdr {
	u_int16_t	source;
	u_int16_t	dest;
	u_int16_t	len;
	u_int16_t	check;
};

#define TH_FIN_MULTIPLIER	0x01
#define TH_SYN_MULTIPLIER	0x02
#define TH_RST_MULTIPLIER	0x04
#define TH_PUSH_MULTIPLIER	0x08
#define TH_ACK_MULTIPLIER	0x10
#define TH_URG_MULTIPLIER	0x20


static int parse_pkt(char *pkt, struct pfring_pkthdr *hdr)
{
  struct iphdr *ip;
  struct eth_hdr *eh = (struct eth_hdr*)pkt;
  u_int16_t displ;

  memset(&hdr->parsed_pkt, 0, sizeof(struct pkt_parsing_info));

  hdr->parsed_pkt.eth_type = ntohs(eh->h_proto);
  hdr->parsed_pkt.pkt_detail.offset.eth_offset = 0;

  if(hdr->parsed_pkt.eth_type == 0x8100 /* 802.1q (VLAN) */)
    {
      hdr->parsed_pkt.pkt_detail.offset.vlan_offset = hdr->parsed_pkt.pkt_detail.offset.eth_offset + sizeof(struct eth_hdr);
      hdr->parsed_pkt.vlan_id = (pkt[hdr->parsed_pkt.pkt_detail.offset.eth_offset + 14] & 15) * 256
	+ pkt[hdr->parsed_pkt.pkt_detail.offset.eth_offset + 15];
      hdr->parsed_pkt.eth_type = (pkt[hdr->parsed_pkt.pkt_detail.offset.eth_offset + 16]) * 256
	+ pkt[hdr->parsed_pkt.pkt_detail.offset.eth_offset + 17];
      displ = 4;
    }
  else
    {
      displ = 0;
      hdr->parsed_pkt.vlan_id = 0; /* Any VLAN */
    }

  if(hdr->parsed_pkt.eth_type == 0x0800 /* IP */) {
    hdr->parsed_pkt.pkt_detail.offset.l3_offset = hdr->parsed_pkt.pkt_detail.offset.eth_offset+displ+sizeof(struct eth_hdr);
    ip = (struct iphdr*)(pkt+hdr->parsed_pkt.pkt_detail.offset.l3_offset);

    hdr->parsed_pkt.ipv4_src = ntohl(ip->saddr), hdr->parsed_pkt.ipv4_dst = ntohl(ip->daddr), hdr->parsed_pkt.l3_proto = ip->protocol;
    hdr->parsed_pkt.ipv4_tos = ip->tos;

    if((ip->protocol == IPPROTO_TCP) || (ip->protocol == IPPROTO_UDP))
      {
	u_int16_t ip_len = ip->ihl*4;

	hdr->parsed_pkt.pkt_detail.offset.l4_offset = hdr->parsed_pkt.pkt_detail.offset.l3_offset+ip_len;

	if(ip->protocol == IPPROTO_TCP)
	  {
	    struct tcphdr *tcp = (struct tcphdr*)(pkt+hdr->parsed_pkt.pkt_detail.offset.l4_offset);
	    hdr->parsed_pkt.l4_src_port = ntohs(tcp->source), hdr->parsed_pkt.l4_dst_port = ntohs(tcp->dest);
	    hdr->parsed_pkt.pkt_detail.offset.payload_offset = hdr->parsed_pkt.pkt_detail.offset.l4_offset+(tcp->doff * 4);
	    hdr->parsed_pkt.tcp_flags = (tcp->fin * TH_FIN_MULTIPLIER) + (tcp->syn * TH_SYN_MULTIPLIER) + (tcp->rst * TH_RST_MULTIPLIER) +
	      (tcp->psh * TH_PUSH_MULTIPLIER) + (tcp->ack * TH_ACK_MULTIPLIER) + (tcp->urg * TH_URG_MULTIPLIER);
	  } else if(ip->protocol == IPPROTO_UDP)
	    {
	      struct udphdr *udp = (struct udphdr*)(pkt+hdr->parsed_pkt.pkt_detail.offset.l4_offset);
	      hdr->parsed_pkt.l4_src_port = ntohs(udp->source), hdr->parsed_pkt.l4_dst_port = ntohs(udp->dest);
	      hdr->parsed_pkt.pkt_detail.offset.payload_offset = hdr->parsed_pkt.pkt_detail.offset.l4_offset+sizeof(struct udphdr);
	    } else
	      hdr->parsed_pkt.pkt_detail.offset.payload_offset = hdr->parsed_pkt.pkt_detail.offset.l4_offset;
      } else
	hdr->parsed_pkt.l4_src_port = hdr->parsed_pkt.l4_dst_port = 0;

    return(1); /* IP */
  } /* TODO: handle IPv6 */

  return(0); /* No IP */
}
#endif

/* **************************************************** */

int pfring_recv(pfring *ring, char* buffer, u_int buffer_len, 
		struct pfring_pkthdr *hdr, 
		u_char wait_for_incoming_packet) {
#ifdef USE_PCAP
  pcap_t *pcapPtr = (pcap_t*)ring;
  const u_char *packet;

  packet = pcap_next(pcapPtr, (struct pcap_pkthdr*)hdr);
  if(hdr->caplen > 0) {
    if(buffer && (buffer_len > 0)) {
      memcpy(buffer, packet, min(hdr->caplen, buffer_len));
      parse_pkt(buffer, hdr);
    }
    return(1);
  } else
    return(0);
#else
  FlowSlot *slot;
  u_int32_t queuedPkts;

  if((ring == NULL) || (ring->buffer == NULL)) return(-1);

 do_pfring_recv:
  if(ring->reentrant)
    pthread_spin_lock(&ring->spinlock);
	  
  slot = (FlowSlot*)&ring->slots[ring->slots_info->remove_idx*ring->slots_info->slot_len];

  if(ring->slots_info->tot_insert >= ring->slots_info->tot_read)
    queuedPkts = ring->slots_info->tot_insert - ring->slots_info->tot_read;
  else
    queuedPkts = ring->slots_info->tot_slots + ring->slots_info->tot_insert - ring->slots_info->tot_read;

  if(queuedPkts && (slot->slot_state == 1 /* There's a packet to read */)) {
    char *bucket = (char*)&slot->bucket;
    struct pfring_pkthdr *_hdr = (struct pfring_pkthdr*)bucket;
    int bktLen = _hdr->caplen+_hdr->parsed_header_len;

    if(bktLen > buffer_len) bktLen = buffer_len-1;
      
    if(buffer && (bktLen > 0)) {
      memcpy(buffer, &bucket[sizeof(struct pfring_pkthdr)], bktLen);
      bucket[bktLen] = '\0';
    }

    if(ring->slots_info->remove_idx >= (ring->slots_info->tot_slots-1)) {
      ring->slots_info->remove_idx = 0;
      ring->page_id = PAGE_SIZE, ring->slot_id = 0, ring->pkts_per_page = 0;
    } else {
      ring->slots_info->remove_idx++;
      ring->pkts_per_page++, ring->slot_id += ring->slots_info->slot_len;
    }
      
    if(hdr) memcpy(hdr, _hdr, sizeof(struct pfring_pkthdr));

    ring->slots_info->tot_read++;
    slot->slot_state = 0; /* Empty slot */
    if(ring->reentrant) pthread_spin_unlock(&ring->spinlock);
    return(1);
  } else if(wait_for_incoming_packet) {
    struct pollfd pfd;
    int rc;

    if(ring->reentrant) pthread_spin_unlock(&ring->spinlock);

    /* Sleep when nothing is happening */
    pfd.fd      = ring->fd;
    pfd.events  = POLLIN|POLLERR;
    pfd.revents = 0;

#ifdef RING_DEBUG
    printf("==>> poll [remove_idx=%u][insert_idx=%u][loss=%d][queuedPkts=%u]"
	   "[slot_state=%d][tot_insert=%u][tot_read=%u]\n",
	   ring->slots_info->remove_idx,
	   ring->slots_info->insert_idx,
	   ring->slots_info->tot_lost, 
	   queuedPkts, slot->slot_state,
	   ring->slots_info->tot_insert,
	   ring->slots_info->tot_read);
#endif
	      
    errno = 0;

    rc = poll(&pfd, 1, -1);

    ring->num_poll_calls++;

    if(rc == -1)
      return(-1);
    else
      goto do_pfring_recv;
  }

  return(-1); /* Not reached */
#endif
}

/* ******************************* */

int pfring_get_selectable_fd(pfring *ring) {
#ifdef USE_PCAP
  return(pcap_get_selectable_fd((pcap_t*)ring));
#else
  return(ring->fd);
#endif
}

