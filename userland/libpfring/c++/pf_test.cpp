#include "PFring.h"
#include <string.h>

struct simple_stats {
  u_int64_t num_pkts, num_bytes;
};

int main(int argc, char *argv[]) {
  char *device_name = "eth0";
  PFring *ring = new PFring(device_name, 128, 1);
  int rc;
  u_int16_t rule_id = 99;
  char stats[32];

  if(ring && ring->get_pcap())
    printf("Succesfully open device %s\n", device_name);
  else {
    printf("Problems while opening device %s: %s\n", device_name, ring->get_last_error());
    return(0);
  }

  if(true) {
    filtering_rule the_rule;

    ring->toggle_filtering_policy(false); /* Default to drop */
    memset(&the_rule, 0, sizeof(the_rule));

    the_rule.rule_id = rule_id;
    the_rule.pass_action = 1;
    the_rule.proto = 1 /* icmp */;
    rc = ring->add_filtering_rule(&the_rule);

    printf("Added filtering rule %d [rc=%d]\n", rule_id, rc);

    rc = ring->set_filtering_rule_plugin_id(rule_id, 1 /* dummy plugin */);
    printf("Associated plugin to filtering rule %d [rc=%d]\n", rule_id, rc);
  }



  while(true) {
    u_char pkt[1500];
    struct pfring_pkthdr hdr;
    struct simple_stats *the_stats = (struct simple_stats*)stats;

    if(ring->get_next_packet(&hdr, pkt, sizeof(pkt)) > 0) {
      u_int len;

      printf("Got %d bytes packet\n", hdr.len);

      len = sizeof(stats);
      rc = ring->get_filtering_rule_stats(rule_id, stats, &len);
      if(rc == sizeof(struct simple_stats))
	printf("Got stats for filtering rule %d [pkts=%u][bytes=%u]\n", 
	       rule_id,
	       (unsigned int)the_stats->num_pkts,
	       (unsigned int)the_stats->num_bytes);
    } else {
      printf("Error while calling get_next_packet()\n");
      break;
    }
  }

      delete ring;
  return(0);
}
