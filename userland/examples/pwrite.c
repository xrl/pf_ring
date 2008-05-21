#include <pcap.h>
#include <signal.h>
#include <sched.h>
#include <stdlib.h>

#define HAVE_PCAP

#include "pfring.h"

pfring  *pd;
pcap_dumper_t *dumper = NULL;
int verbose = 0;
u_int32_t num_pkts=0;

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/poll.h>
#include <time.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>     /* the L2 protocols */

static u_int64_t totPkts, totLost;
static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;

#define DEFAULT_DEVICE "eth0"

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;

  if(called) return; else called = 1;

  pcap_dump_close(dumper);
  pfring_close(pd);

  printf("Saved %d packets on disk\n", num_pkts);
  exit(0);
}

/* *************************************** */

void printHelp(void) {

  printf("pcount\n(C) 2003-07 Deri Luca <deri@ntop.org>\n");
  printf("-h              [Print help]\n");
  printf("-i <device>     [Device name]\n");
  printf("-w <dump file>  [Dump file path]\n");
  printf("-v              [Verbose]\n");
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, c, *bpfFilter = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];
  int i, promisc;
  struct bpf_program fcode;
  u_int clusterId = 0;

#if 0  
  struct sched_param schedparam;

  schedparam.sched_priority = 99;
  if(sched_setscheduler(0, SCHED_FIFO, &schedparam) == -1) {
    printf("error while setting the scheduler, errno=%i\n",errno);
    exit(1);
  }      

  mlockall(MCL_CURRENT|MCL_FUTURE);

#define TEST_PROCESSOR_AFFINITY
#ifdef TEST_PROCESSOR_AFFINITY
  {
   unsigned long new_mask = 1;
   unsigned int len = sizeof(new_mask);
   unsigned long cur_mask;
   pid_t p = 0; /* current process */
   int ret;

   ret = sched_getaffinity(p, len, NULL);
   printf(" sched_getaffinity = %d, len = %u\n", ret, len);
   
   ret = sched_getaffinity(p, len, &cur_mask);
   printf(" sched_getaffinity = %d, cur_mask = %08lx\n", ret, cur_mask);
   
   ret = sched_setaffinity(p, len, &new_mask);
   printf(" sched_setaffinity = %d, new_mask = %08lx\n", ret, new_mask);
   
   ret = sched_getaffinity(p, len, &cur_mask);
   printf(" sched_getaffinity = %d, cur_mask = %08lx\n", ret, cur_mask);
 }
#endif
#endif

  while((c = getopt(argc,argv,"hi:w:vf:")) != -1) {
    switch(c) {
    case 'h':
      printHelp();
      return(0);
      break;
    case 'w':      
      dumper = pcap_dump_open(pcap_open_dead(DLT_EN10MB, 16384 /* MTU */), optarg);
      if(dumper == NULL) {
	printf("Unable to open dump file %s\n", optarg);
	return(-1);
      }
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'v':
      verbose = 1;
      break;
    case 'f':
      bpfFilter = strdup(optarg);
      break;
    }
  }

  if(dumper == NULL) {
    printHelp();
    return(-1);
  }

  promisc = 1;
  if((pd = pfring_open(device, promisc, 1500, 0)) == NULL) {
    printf("pfring_open error\n");
    return(-1);
  }

  printf("Capturing from %s\n", device);

  signal(SIGINT, sigproc);
  
  while(1) {
    u_char buffer[2048];
    struct pfring_pkthdr hdr;
    
    if(pfring_recv(pd, (char*)buffer, sizeof(buffer), &hdr, 1 /* wait_for_packet */) > 0)
      pcap_dump((u_char*)dumper, (struct pcap_pkthdr*)&hdr, buffer), num_pkts++;
  }

  pcap_dump_close(dumper);
  pfring_close(pd);

  return(0);
}
