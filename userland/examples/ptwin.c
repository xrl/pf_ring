/*
 *
 * (C) 2005-10 - Luca Deri <deri@ntop.org>
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

#define HAVE_PF_RING
#include <pcap/pcap.h>

#include "pfring.h"

#define ALARM_SLEEP       1
#define DEFAULT_SNAPLEN 128
int verbose = 0;
pfring_stat pfringStats;

static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;
u_int8_t do_shutdown = 0;

#define DEFAULT_DEVICE     "eth0"

pcap_t  *pd, *a_pd, *b_pd;

/* *************************************** */
/*
 * The time difference in microseconds
 */
long delta_time (struct timeval * now,
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
  return((delta_seconds * 1000000) + delta_microseconds);
}

/* ******************************** */

void print_stats() {
  struct pcap_stat pcapStat;
  struct timeval endTime;
  float deltaSec;
  static u_int64_t lastPkts = 0;
  u_int64_t diff;
  static struct timeval lastTime;

  if(startTime.tv_sec == 0) {
    lastTime.tv_sec = 0;
    gettimeofday(&startTime, NULL);
    return;
  }

  gettimeofday(&endTime, NULL);
  deltaSec = (double)delta_time(&endTime, &startTime)/1000000;

  if(pcap_stats(pd, &pcapStat) >= 0) {
    fprintf(stderr, "=========================\n"
	    "Absolute Stats: [%u pkts rcvd][%u pkts dropped]\n"
	    "Total Pkts=%d/Dropped=%.1f %%\n",
	    pcapStat.ps_recv, pcapStat.ps_drop, pcapStat.ps_recv-pcapStat.ps_drop,
	    pcapStat.ps_recv == 0 ? 0 : (double)(pcapStat.ps_drop*100)/(double)pcapStat.ps_recv);
    fprintf(stderr, "%llu pkts [%.1f pkt/sec] - %llu bytes [%.2f Mbit/sec]\n",
	    numPkts, (double)numPkts/deltaSec,
	    numBytes, (double)8*numBytes/(double)(deltaSec*1000000));

    if(lastTime.tv_sec > 0) {
      deltaSec = (double)delta_time(&endTime, &lastTime)/1000000;
      diff = pcapStat.ps_recv-lastPkts;
      fprintf(stderr, "=========================\n"
	      "Actual Stats: %llu pkts [%.1f ms][%.1f pkt/sec]\n",
	      diff, deltaSec*1000, ((double)diff/(double)(deltaSec)));
      lastPkts = pcapStat.ps_recv;
    }

    fprintf(stderr, "=========================\n");
  }
  
  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;

  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;
  do_shutdown = 1;
  print_stats();
  pcap_close(pd);

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

void dummyProcesssPacket(u_char *_deviceId,
			 const struct pcap_pkthdr *h,
			 const u_char *p) {
  if(verbose) {
    struct ether_header ehdr;
    u_short eth_type, vlan_id;
    char buf1[32], buf2[32];
    struct ip ip;
    int s = (h->ts.tv_sec + thiszone) % 86400;

    printf("%02d:%02d:%02d.%06u ",
	   s / 3600, (s % 3600) / 60, s % 60,
	   (unsigned)h->ts.tv_usec);

    memcpy(&ehdr, p, sizeof(struct ether_header));
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
      memcpy(&ip, p+sizeof(ehdr), sizeof(struct ip));
      printf("[%s ", intoa(ntohl(ip.ip_src.s_addr)));
      printf("-> %s] ", intoa(ntohl(ip.ip_dst.s_addr)));
    } else if(eth_type == 0x0806)
      printf("[ARP]");
    else
      printf("[eth_type=0x%04X]", eth_type);
    
    printf("[caplen=%d][len=%d]\n", h->caplen, h->len);
  }

  if(numPkts == 0) gettimeofday(&startTime, NULL);
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

void help(void) {
  printf("pftwin\n(C) 2005-10 Deri Luca <deri@ntop.org>\n\n");

  printf("Usage: pftwin -a <dev> -b <dev>\n"
	 "Simultaneously sniff from two devices using on single socket\n");

  printf("-h              Print this help\n");
  printf("-a <device>     First device name (on which to sniff)\n");
  printf("-b <device>     Second device name (on which to sniff)\n");
  
  printf("-c <BPF Filter> Filter for the first device\n");
  printf("-d <BPF Filter> Filter for the second device\n");

  printf("-s <string>     String to search on packets\n");
  printf("-l <len>        Capture length\n");

  printf("-v              Verbose\n");

  exit(0);  
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *a_device = NULL, *b_device = NULL, c;
  char *a_filter = NULL, *b_filter = NULL;
  int promisc, snaplen = DEFAULT_SNAPLEN;
  char errbuf[PCAP_ERRBUF_SIZE];

  startTime.tv_sec = 0;
  thiszone = gmt2local(0);

  while((c = getopt(argc,argv,"a:b:hl:vc:d:")) != -1) {
    switch(c) {
    case 'h':
      help();
      return(0);
      break;
    case 'l':
      snaplen = atoi(optarg);
      break;
    case 'a':
      a_device = strdup(optarg);
      break;
    case 'b':
      b_device = strdup(optarg);
      break;
    case 'c':
      a_filter = strdup(optarg);
      break;
    case 'd':
      b_filter = strdup(optarg);
      break;
    case 'v':
      verbose = 1;
      break;
    }
  }

  if((a_device == NULL) || (b_device == NULL)) help();

  /* hardcode: promisc=1, to_ms=500 */
  promisc = 1;

  if((pd = pcap_open_live("none", snaplen, promisc, 500, errbuf)) == NULL) {
    printf("pcap_open_live error\n");
    return(-1);
  }

  if(a_device) {
    if((a_pd = pcap_open_live(a_device, snaplen, promisc, 500, errbuf)) == NULL) {
      printf("pcap_open_live(%s) error\n", a_device);
      return(-1);
    } else {
      printf("Capturing from %s\n", a_device);

      if(a_filter) {
	struct bpf_program fcode;

	  if(pcap_compile(a_pd, &fcode, a_filter, 1, 0xFFFFFF00) < 0) {
	    printf("pcap_compile 'a' error: '%s'\n", pcap_geterr(a_pd));
	  } else {
	    if(pcap_setfilter(a_pd, &fcode) < 0) {
	      printf("pcap_setfilter 'a' error: '%s'\n", pcap_geterr(pd));
	    } else
	      printf("Successfully set filter '%s' on 'a'\n", a_filter);
	  }		
      }
      
      if(pcap_set_master(a_pd, pd) != 0)
	printf("pcap_set_master(a) failed\n");
      else
	printf("pcap_set_master(a) succeeded\n");
    }
  } else
	a_pd = NULL;
    
  if(b_device) {
    if((b_pd = pcap_open_live(b_device, snaplen, promisc, 500, errbuf)) == NULL) {
      printf("pcap_open_live(%s) error\n", b_device);
      return(-1);
    } else {
      printf("Capturing from %s\n", b_device);

      if(b_filter) {
	struct bpf_program fcode;

	  if(pcap_compile(b_pd, &fcode, b_filter, 1, 0xFFFFFF00) < 0) {
	    printf("pcap_compile 'b' error: '%s'\n", pcap_geterr(b_pd));
	  } else {
	    if(pcap_setfilter(b_pd, &fcode) < 0) {
	      printf("pcap_setfilter 'b' error: '%s'\n", pcap_geterr(pd));
	    } else
	      printf("Successfully set filter '%s' on 'b'\n", a_filter);
	  }		
      }

      if(pcap_set_master_id(b_pd, pcap_get_pfring_id(pd)) != 0)
	printf("pcap_set_master(b) failed\n");
      else
	printf("pcap_set_master(b) succeeded\n");
    }
  } else
    b_pd = NULL;

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);

  if(!verbose) {
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);
  }

  pcap_loop(pd, -1, dummyProcesssPacket, NULL);

  pcap_close(pd);

  return(0);
}
