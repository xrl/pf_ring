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
 *
 * VLAN support courtesy of Vincent Magnin <vincent.magnin@ci.unil.ch>
 *
 */

#define _GNU_SOURCE
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

#ifndef ENABLE_DNA_SUPPORT

int main(int argc, char* argv[]) {
  printf("DNA is not enabled on this PF_RING instance\n");
  return(0);
}

#else

#define ALARM_SLEEP       1
#define DEFAULT_SNAPLEN 128
pfring  *pd;
int verbose = 0;
pfring_stat pfringStats;

static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;

#define DEFAULT_DEVICE "eth0"

/* *************************************** */
/*
 * The time difference in millisecond
 */
double delta_time (struct timeval * now,
		   struct timeval * before) {
  time_t delta_seconds;
  time_t delta_microseconds;

  /*
   * compute delta in second, 1/10's and 1/1000's second units
   */
  delta_seconds      = now -> tv_sec  - before -> tv_sec;
  delta_microseconds = now -> tv_usec - before -> tv_usec;

  if(delta_microseconds < 0) {
    /* manually carry a one from the seconds field */
    delta_microseconds += 1000000;  /* 1e6 */
    -- delta_seconds;
  }
  return((double)(delta_seconds * 1000) + (double)delta_microseconds/1000);
}

/* ******************************** */

void print_stats() {
  pfring_stat pfringStat;
  struct timeval endTime;
  double deltaMillisec;
  static u_int64_t lastPkts = 0;
  u_int64_t diff;
  static struct timeval lastTime;

  if(startTime.tv_sec == 0) {
    gettimeofday(&startTime, NULL);
    return;
  }

  gettimeofday(&endTime, NULL);
  deltaMillisec = delta_time(&endTime, &startTime);
  
  if(pfring_stats(pd, &pfringStat) >= 0) {
    double thpt = ((double)8*numBytes)/(deltaMillisec*1000);

    fprintf(stderr, "=========================\n"
	    "Absolute Stats: [%u pkts rcvd][%u pkts dropped]\n"
	    "Total Pkts=%u/Dropped=%.1f %%\n",
	    (unsigned int)pfringStat.recv, (unsigned int)pfringStat.drop,
	    (unsigned int)(pfringStat.recv-pfringStat.drop),
	    pfringStat.recv == 0 ? 0 : (double)(pfringStat.drop*100)/(double)pfringStat.recv);
    fprintf(stderr, "%llu pkts - %llu bytes", numPkts, numBytes);
    fprintf(stderr, " [%.1f pkt/sec - %.2f Mbit/sec]\n",
	    (double)(numPkts*1000)/deltaMillisec, thpt);

    if(lastTime.tv_sec > 0) {
      u_int32_t i, rx_reg = pd->rx_reg;

      deltaMillisec = delta_time(&endTime, &lastTime);
      diff = pfringStat.recv-lastPkts;
      fprintf(stderr, "=========================\n"
	      "RX Register [card=%d][program=%d]\n"
	      "Actual Stats: %llu pkts [%.1f ms][%.1f pkt/sec]\n",
	      get_e1000_rx_register(pd), rx_reg,
	      diff, deltaMillisec, ((double)diff/(double)(deltaMillisec/1000)));

      if(diff == 0) {
	struct e1000_rx_desc *head = (struct e1000_rx_desc*)pd->dna_dev.descr_packet_memory;

	for(i=0; i<pd->dna_dev.descr_packet_memory_num_slots; i++) {
	  if(head[rx_reg].status & E1000_RXD_STAT_DD) printf("[%d]", rx_reg);
	  if(++rx_reg == pd->dna_dev.descr_packet_memory_num_slots) rx_reg = 0;
	}

	printf("\n");
      }
    }

    lastPkts = pfringStat.recv;
  }

  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;

  fprintf(stderr, "=========================\n\n");
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;

  if(called) return; else called = 1;

  print_stats();
  pfring_close(pd);
  exit(0);
}

/* ******************************** */

void my_sigalarm(int sig) {
  print_stats();
  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
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

void dummyProcesssPacket(const struct pfring_pkthdr *h, const u_char *p) {
  if(verbose) {
    struct ether_header ehdr;
    u_short eth_type, vlan_id;
    char buf1[32], buf2[32];
    struct ip ip;
    int s = (h->ts.tv_sec + thiszone) % 86400;

    printf("[eth_type=0x%04X]", h->parsed_pkt.eth_type);
    printf("[l3_proto=%u]", (unsigned int)h->parsed_pkt.l3_proto);
    printf("[%s:%d -> ", intoa(h->parsed_pkt.ipv4_src), 
	   h->parsed_pkt.l4_src_port);
    printf("%s:%d] ", intoa(h->parsed_pkt.ipv4_dst), 
	   h->parsed_pkt.l4_dst_port);
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
      printf("[%s:%d ", intoa(ntohl(ip.ip_src.s_addr)), 
	     h->parsed_pkt.l4_src_port);
      printf("-> %s:%d] ", intoa(ntohl(ip.ip_dst.s_addr)), 
	     h->parsed_pkt.l4_dst_port);
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
 
  numPkts++, numBytes += h->len;
}

/* *************************************** */

int32_t gmt2local(time_t t) {
  int dt, dir;
  struct tm *gmt, *loc;
  struct tm sgmt;

  if (t == 0)
    t = time(NULL);
  gmt = &sgmt;
  *gmt = *gmtime(&t);
  loc = localtime(&t);
  dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 +
    (loc->tm_min - gmt->tm_min) * 60;

  /*
   * If the year or julian day is different, we span 00:00 GMT
   * and must add or subtract a day. Check the year first to
   * avoid problems when the julian day wraps.
   */
  dir = loc->tm_year - gmt->tm_year;
  if (dir == 0)
    dir = loc->tm_yday - gmt->tm_yday;
  dt += dir * 24 * 60 * 60;

  return (dt);
}

/* *************************************** */

void printHelp(void) {
  printf("pfmap\n(C) 2005-08 Deri Luca <deri@ntop.org>\n");
  printf("-h              [Print help]\n");
  printf("-i <device>     [Device name. Use device@channel for channels]\n");
  /* printf("-f <filter>     [pfring filter]\n"); */
  printf("-s <string>     [String to search on packets]\n");
  printf("-l <len>        [Capture length]\n");
  printf("-a              [Active packet wait]\n");
  printf("-v              [Verbose]\n");
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, c, *string = NULL;
  int promisc, snaplen = DEFAULT_SNAPLEN;
  u_char wait_for_packet = 1;
  struct pfring_pkthdr hdr;
  char buffer[2048];

  startTime.tv_sec = 0;
  thiszone = gmt2local(0);

  while((c = getopt(argc,argv,"hi:l:vs:a" /* "f:" */)) != -1) {
    switch(c) {
    case 'h':
      printHelp();
      return(0);
      break;
    case 'a':
      wait_for_packet = 0;
      break;
    case 'l':
      snaplen = atoi(optarg);
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'v':
      verbose = 1;
      break;
      /*
	case 'f':
	bpfFilter = strdup(optarg);
	break;
      */
    case 's':
      string = strdup(optarg);
      break;
    }
  }

  if(device == NULL) device = DEFAULT_DEVICE;

  printf("Capturing from %s\n", device);

  /* hardcode: promisc=1, to_ms=500 */
  promisc = 1;
  if((pd = pfring_open_dna(device, 0 /* we don't use threads */)) == NULL) {
    printf("pfring_open_dna() error\n");
    return(-1);
  } else {
    u_int32_t version;

    pfring_set_application_name(pd, "pfmap");
    pfring_version(pd, &version);

    printf("Using PF_RING v.%d.%d.%d\n",
	   (version & 0xFFFF0000) >> 16,
	   (version & 0x0000FF00) >> 8,
	   version & 0x000000FF);
  }

  signal(SIGINT, sigproc);
  
  if(!verbose) {
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);
  }

  /* ************************************************ */

  {
    int debug = 0;

    while(1) {
      if(pfring_recv(pd, buffer, sizeof(buffer), &hdr, 1)) {
	if(verbose) printf("Got packet [len=%d]\n", hdr.len);
	if(verbose || debug) {
	  int i;

	  //printf("[\n");
	  for(i=0; i<hdr.len; i++) {
	    printf("%02X ", buffer[i] & 0xFF);
	    if(i % 16 == 0) printf("\n");
	  }
	  printf("\n");
	}
      }
    }
  }

  /* ************************************************ */

  pfring_close(pd);
  return(0);
}

#endif
