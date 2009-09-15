/*
 *
 * (C) 2008 - Felipe Huici <f.huici@cs.ucl.ac.uk>
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
 *
 */

#include <signal.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/poll.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>     /* the L2 protocols */
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "pfring.h"

void printHelp(void) 
{
  printf("-h              [Print help]\n");
  printf("-v              [Verbose]\n");
  printf("-i <device>     [Input device name]\n");
  printf("-o <device>     [Output device name]\n");
  printf("-n <device>     [Not promiscuous]\n");
}

/* ****************************************************** */

static char hex[] = "0123456789ABCDEF";

char* etheraddr_string(const u_char *ep, char *buf) {
  u_int i, j;
  char *cp;

  cp = buf;
  if ((j = *ep >> 4) != 0)
    *cp++ = hex[j];
  else
    *cp++ = '0';

  *cp++ = hex[*ep++ & 0xf];

  for(i = 5; (int)--i >= 0;) {
    *cp++ = ':';
    if ((j = *ep >> 4) != 0)
      *cp++ = hex[j];
    else
      *cp++ = '0';

    *cp++ = hex[*ep++ & 0xf];
  }

  *cp = '\0';
  return (buf);
}

/* ****************************************************** */

/*
 * A faster replacement for inet_ntoa().
 */
char* _intoa(unsigned int addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  u_int byte;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if (byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if (byte > 0)
	*--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

/* ************************************ */

char* intoa(unsigned int addr) {
  static char buf[sizeof "ff:ff:ff:ff:ff:ff:255.255.255.255"];

  return(_intoa(addr, buf, sizeof(buf)));
}

/* ****************************************************** */

char* proto2str(u_short proto) {
  static char protoName[8];

  switch(proto) {
  case IPPROTO_TCP:  return("TCP");
  case IPPROTO_UDP:  return("UDP");
  case IPPROTO_ICMP: return("ICMP");
  default:
    snprintf(protoName, sizeof(protoName), "%d", proto);
    return(protoName);
  }
}

/* ****************************************************** */

static int32_t thiszone;

int verbose = 0;

void dummyProcesssPacket(const struct pfring_pkthdr *h, const u_char *p) {
  if(verbose) {
    struct ether_header ehdr;
    u_short eth_type, vlan_id;
    char buf1[32], buf2[32];
    struct ip ip;
    int s = (h->ts.tv_sec + thiszone) % 86400;

    printf("[eth_type=0x%04X]", h->parsed_pkt.eth_type);
    printf("[l3_proto=%u]", (unsigned int)h->parsed_pkt.l3_proto);
    printf("[%s:%d -> ", intoa(h->parsed_pkt.ipv4_src), h->parsed_pkt.l4_src_port);
    printf("%s:%d] ", intoa(h->parsed_pkt.ipv4_dst), h->parsed_pkt.l4_dst_port);
    printf("%02d:%02d:%02d.%06u ",
	   s / 3600, (s % 3600) / 60, s % 60,
	   (unsigned)h->ts.tv_usec);

    memcpy(&ehdr, p+h->parsed_header_len, sizeof(struct ether_header));
    eth_type = ntohs(ehdr.ether_type);
    printf("[%s -> %s] ",
	   etheraddr_string(ehdr.ether_shost, buf1),
	   etheraddr_string(ehdr.ether_dhost, buf2));

    if(eth_type == 0x8100) {
      vlan_id = (p[14] & 15)*256 + p[15];
      eth_type = (p[16])*256 + p[17];
      printf("[vlan %u] ", vlan_id);
      p+=4;
    }
    if(eth_type == 0x0800) {
      memcpy(&ip, p+h->parsed_header_len+sizeof(ehdr), sizeof(struct ip));
      printf("[%s:%d ", intoa(ntohl(ip.ip_src.s_addr)), h->parsed_pkt.l4_src_port);
      printf("-> %s:%d] ", intoa(ntohl(ip.ip_dst.s_addr)), h->parsed_pkt.l4_dst_port);
    } else if(eth_type == 0x0806)
      printf("[ARP]");
    else
      printf("[eth_type=0x%04X]", eth_type);

    printf("[tos=%d][tcp_flags=%d][caplen=%d][len=%d][parsed_header_len=%d]"
	   "[eth_offset=%d][l3_offset=%d][l4_offset=%d][payload_offset=%d]\n",
	   h->parsed_pkt.ipv4_tos, h->parsed_pkt.tcp_flags,
	   h->caplen, h->len, h->parsed_header_len,
	   h->parsed_pkt.pkt_detail.offset.eth_offset,
	   h->parsed_pkt.pkt_detail.offset.l3_offset,
	   h->parsed_pkt.pkt_detail.offset.l4_offset,
	   h->parsed_pkt.pkt_detail.offset.payload_offset);
  }
}

int main(int argc, char* argv[]) 
{
  pfring *pd;
  char *in_dev = NULL, *out_dev = NULL, c;
  int promisc = 1;
  filtering_rule rule;

  while((c = getopt(argc,argv, "hi:o:c:nv")) != -1) 
  {
    switch(c) 
    {
      case 'h':
	printHelp();
	return 0;
	break;
      case 'i':
	in_dev = strdup(optarg);
	break;
      case 'o':
	out_dev = strdup(optarg);
	break;
      case 'n':
	promisc = 0;
	break;
      case 'v':
	verbose = 1;
	break;
    }
  }  
  if ( (!in_dev) || (!out_dev) )
  {
    printf("you must specify an input and an output device!\n");
    return -1;
  }

  /* open devices */
  if((pd = pfring_open(in_dev, promisc, 1500, 0)) == NULL) 
  {
    printf("pfring_open error for %s\n", in_dev);
    return -1;
  }  else
    pfring_set_application_name(pd, "forwarder");

  /* reflect all TCP packets received on in_dev -> out_dev */
  memset(&rule, 0, sizeof(rule));
  rule.rule_id = 1;
  rule.rule_action = reflect_packet_and_stop_rule_evaluation;
  rule.core_fields.proto = 6 /* tcp */;
  snprintf(rule.reflector_device_name, REFLECTOR_NAME_LEN, "%s", out_dev);

  if(pfring_add_filtering_rule(pd, &rule) < 0) {
    printf("pfring_add_filtering_rule() failed\n");
    pfring_close(pd);
    return(-1);
  } else
    printf("Reflecting TCP packets received on %s to %s\n",
	   in_dev, out_dev);
 
  /* Receive UDP packets in userland */
  memset(&rule, 0, sizeof(rule));
  rule.rule_id = 2;
  rule.rule_action = forward_packet_and_stop_rule_evaluation;
  rule.core_fields.proto = 17 /* udp */;
  if(pfring_add_filtering_rule(pd, &rule) < 0) {
    printf("pfring_add_filtering_rule() failed\n");
    pfring_close(pd);
    return(-1);
  } else
    printf("Capture UDP packets\n");

  /* Enable rings */
  pfring_enable_ring(pd);

  while(1) 
    {
      u_char buffer[2048];
      struct pfring_pkthdr hdr;
      
      /* need this line otherwise pkts are not reflected */
      if(pfring_recv(pd, (char*)buffer, sizeof(buffer), &hdr, 1) > 0) {
	dummyProcesssPacket(&hdr, buffer);
      }
    }

  pfring_close(pd);

  return 0;
}
