#include "PFring.h"
#include <string.h>

int main(int argc, char *argv[]) {
  char *device_name = "eth0";
  PFring *ring = new PFring(device_name, 128, 1);
  int rc;

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

    the_rule.rule_id = 99;
    the_rule.pass_action = 1;
    the_rule.proto = 1 /* icmp */;
    rc = ring->add_filtering_rule(&the_rule);

    printf("Added filtering rule [rc=%d]\n", rc);
  }

  while(true) {
    u_char pkt[1500];
    struct pfring_pkthdr hdr;
    
    if(ring->get_next_packet(&hdr, pkt, sizeof(pkt)) > 0)
      printf("Got %d bytes packet\n", hdr.len);
    else {
      printf("Error while calling get_next_packet()\n");
      break;
    }
  }

      delete ring;
  return(0);
}
