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

int main(int argc, char* argv[]) 
{
  pfring *pd, *td;
  char *in_dev = NULL, *out_dev = NULL, c;
  int promisc = 1, verbose = 0;

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
  if((pd = pfring_open(in_dev, promisc, 0)) == NULL) 
  {
    printf("pfring_open error for %s\n", in_dev);
    return -1;
  } 

  if ((td = pfring_open(out_dev, promisc, 0)) == NULL) {
    printf("pfring_open error for %s\n", out_dev);
    return -1;
  }

  /* set reflector */
  if (pfring_set_reflector(pd, out_dev) != 0)
  {
    printf("pfring_set_reflector error for %s\n", out_dev);
    return -1;
  }

  /* Enable rings */
  pfring_enable_ring(pd);
  pfring_enable_ring(td);

#if 1
  while(1)
    sleep(60);
#else
  while(1) 
    {
      u_char buffer[2048];
      struct pfring_pkthdr hdr;
      
      /* need this line otherwise pkts are not reflected */
      if(pfring_recv(pd, (char*)buffer, sizeof(buffer), &hdr, 1) > 0) {
	if(verbose) printf("got one\n");
      }
    }
#endif

  pfring_close(pd);
  pfring_close(td);

  return 0;
}
