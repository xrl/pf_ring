#include <pcap.h>
#include <signal.h>
#include <sched.h>
#include <stdlib.h>
#include <unistd.h>

/* *************************************** */

int main(int argc, char* argv[]) {
  pcap_if_t *alldevs, *d;
  u_int i=0;
  char errbuf[PCAP_ERRBUF_SIZE]; 

  while(1) {
    if(pcap_findalldevs(&alldevs, errbuf) == -1) {
      fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
      exit(1);
    }
        
    /* Print the list */
    for(i=0, d=alldevs; d; d=d->next) {
      printf("%d. %s", ++i, d->name);
      if (d->description)
	printf(" (%s)\n", d->description);
      else
	printf(" (No description available)\n");
    }

    printf("\n");
    sleep(3);
  }

  return(0);
}
