/*
 *
 * (C) 2007-08 - Luca Deri <deri@ntop.org>
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

#ifndef _PFRING_CLASS_
#define _PFRING_CLASS_

extern "C" {
#define HAVE_PF_RING
#include "pcap-int.h"
#define HAVE_PCAP
#include "pfring.h"
}

class PFring {
 private:
  struct pcap *pcapPtr;
  u_int snaplen;
  char *device_name;

 public:
  PFring(char* device, u_int snaplen, bool promisc, char *bpf = NULL);
  ~PFring();

  /* Cluster */
  inline int set_cluster(u_int clusterId)
    { return((pcapPtr && pcapPtr->ring) ? pfring_set_cluster(pcapPtr->ring, clusterId) : -1); };
  inline int remove_from_cluster()               
    { return((pcapPtr && pcapPtr->ring) ? pfring_remove_from_cluster(pcapPtr->ring) : -1);    };

  /* Channel */
  inline int set_channel_id(short channelId)
  { return((pcapPtr && pcapPtr->ring) ? pfring_set_channel_id(pcapPtr->ring, channelId) : -1); };

  /* Reflector */
  inline int set_reflector(char *reflectorDevice) 
    { return((pcapPtr && pcapPtr->ring) ? pfring_set_reflector(pcapPtr->ring, reflectorDevice) : -1); };

  /* Read Packets */
  bool wait_for_packets(int msec = -1 /* -1 == infinite */);
  int get_next_packet(struct pfring_pkthdr *hdr, const u_char *pkt, u_int pkt_len);

  /* Filtering */
  int add_bpf_filter(char *the_filter);
  inline int add_filtering_rule(filtering_rule* the_rule) 
    { return((pcapPtr && pcapPtr->ring) ? pfring_add_filtering_rule(pcapPtr->ring, the_rule) : -1);   };
  inline int remove_filtering_rule(u_int16_t rule_id)     
    { return((pcapPtr && pcapPtr->ring) ? pfring_remove_filtering_rule(pcapPtr->ring, rule_id) : -1); };
  inline int toggle_filtering_policy(bool rules_default_accept_policy)
    { return((pcapPtr && pcapPtr->ring) ? pfring_toggle_filtering_policy(pcapPtr->ring, rules_default_accept_policy ? 1 : 0) : -1); };
  inline int add_hash_filtering_rule(hash_filtering_rule *rule)
    { return((pcapPtr && pcapPtr->ring) ? pfring_handle_hash_filtering_rule(pcapPtr->ring, rule, 1) : -1); };
  inline int remove_hash_filtering_rule(hash_filtering_rule *rule)
    { return((pcapPtr && pcapPtr->ring) ? pfring_handle_hash_filtering_rule(pcapPtr->ring, rule, 0) : -1); };


  /* Stats */
  inline int get_stats(pfring_stat *stats)
    { return((pcapPtr && pcapPtr->ring) ? pfring_stats(pcapPtr->ring, stats) : -1); };
  inline int get_filtering_rule_stats(u_int16_t rule_id, char *stats, u_int *stats_len)
    { return((pcapPtr && pcapPtr->ring) ? pfring_get_filtering_rule_stats(pcapPtr->ring, rule_id, stats, stats_len) : -1); };
  inline int get_hash_filtering_rule_stats(hash_filtering_rule* rule, char *stats, u_int *stats_len)
    { return((pcapPtr && pcapPtr->ring) ? pfring_get_hash_filtering_rule_stats(pcapPtr->ring, rule, stats, stats_len) : -1); };

  /* Utils */
  inline char* get_device_name() { return(device_name); };
  inline int set_sampling_rate(u_int32_t rate /* 1 = no sampling */)
    { return((pcapPtr && pcapPtr->ring) ? pfring_set_sampling_rate(pcapPtr->ring, rate) : -1); };
  inline int get_version(u_int32_t *version) 
    { return((pcapPtr && pcapPtr->ring) ? pfring_version(pcapPtr->ring, version) : -1); };
  inline int get_socket_id() 
    { return((pcapPtr && pcapPtr->ring) ? pcapPtr->ring->fd : pcap_get_selectable_fd(pcapPtr)); };
  inline struct pcap* get_pcap() { return(pcapPtr); };
  inline const char* get_last_error() { return(pcapPtr ? pcap_geterr(pcapPtr) : "Device open has failed"); };
  
};

#endif /* _PFRING_CLASS_ */


