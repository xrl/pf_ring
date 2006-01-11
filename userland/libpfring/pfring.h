/*
 *
 * (C) 2005-06 - Luca Deri <deri@ntop.org>
 *
 */

#ifndef HAVE_PCAP
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/sockios.h>
#endif

#include <linux/ring.h>

#define PAGE_SIZE         4096

#define POLL_SLEEP_STEP         10 /* ns = 0.1 ms */
#define POLL_SLEEP_MIN        POLL_SLEEP_STEP
#define POLL_SLEEP_MAX        1000 /* ns */
#define POLL_QUEUE_MIN_LEN     500 /* # packets */

#ifdef SAFE_RING_MODE
static char staticBucket[2048];
#endif

/* ********************************* */

typedef struct {
  char *buffer, *slots, *device_name;
  int  fd;
  FlowSlotInfo *slots_info;
  u_int page_id, slot_id, pkts_per_page;
  u_int poll_sleep;
  u_char clear_promisc;
  u_long num_poll_calls;
} pfring;

typedef struct {
  u_long recv, drop;
} pfring_stat;

struct pfring_pkthdr {
  struct timeval ts;    /* time stamp */
  u_int32_t caplen;     /* length of portion present */
  u_int32_t len;        /* length this packet (off wire) */
};

/* ********************************* */

int pfring_set_cluster(pfring *ring, u_int clusterId);
int pfring_remove_from_cluster(pfring *ring);
int pfring_set_reflector(pfring *ring, char *reflectorDevice);
pfring* pfring_open(char *device_name, int promisc);
void pfring_close(pfring *ring);
int pfring_stats(pfring *ring, pfring_stat *stats);
int pfring_recv(pfring *ring, char* buffer, int buffer_len, 
		struct pfring_pkthdr *hdr, u_char wait_for_incoming_packet);
