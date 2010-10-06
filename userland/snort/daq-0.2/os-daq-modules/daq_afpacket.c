/*
** Copyright (C) 2010 Sourcefire, Inc.
** Author: Michael R. Altizer <maltizer@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "daq_api.h"
#include "sfbpf.h"

#define DAQ_AFPACKET_VERSION 2

#define AF_PACKET_MAX_BUFFER_SIZE   128
#define AF_PACKET_MAX_INTERFACES    32

typedef struct _af_packet_entry
{
    struct _af_packet_entry *next;
    struct tpacket_hdr *hdr;
    const u_int8_t *begin;
} AFPacketEntry;

typedef struct _af_packet_instance
{
    struct _af_packet_instance *next;
    struct tpacket_req layout;
    AFPacketEntry *ring;
    AFPacketEntry *entry;
    void *buffer;
    char *name;
    int index;
    int fd;
    struct _af_packet_instance *peer;
    struct sockaddr_ll sll;
} AFPacketInstance;

typedef struct _afpacket_context
{
    char *device;
    char *filter;
    int snaplen;
    int timeout;
    AFPacketInstance *instances;
    struct tpacket_req layout;
    uint32_t frames_per_block;
    uint32_t intf_count;
    struct sfbpf_program fcode;
    int break_loop;
    DAQ_Stats_t stats;
    DAQ_State state;
    char errbuf[256];
} AFPacket_Context_t;

/* Return the index of the given device name.  Return -1 on failure. */
static int find_device_index(AFPacketInstance *instance, const char *device)
{
    struct ifreq ifr;

    if (!instance || instance->fd == -1)
        return -1;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

    if (ioctl(instance->fd, SIOCGIFINDEX, &ifr) == -1)
        return -1;

    return ifr.ifr_ifindex;
}

static int bind_interface(AFPacket_Context_t *afpc, AFPacketInstance *instance)
{
    struct sockaddr_ll *sll;
    int err;
    socklen_t errlen = sizeof(err);

    /* Bind to the specified device so we only see packets from it. */
    sll = &instance->sll;
    sll->sll_family = AF_PACKET;
    sll->sll_ifindex = instance->index;
    sll->sll_protocol = htons(ETH_P_ALL);

    if (bind(instance->fd, (struct sockaddr *) sll, sizeof(*sll)) == -1)
    {
        DPE(afpc->errbuf, "%s: bind(%s): %s\n", __FUNCTION__, instance->name, strerror(errno));
        return DAQ_ERROR;
    }

    /* Any pending errors, e.g., network is down? */
    if (getsockopt(instance->fd, SOL_SOCKET, SO_ERROR, &err, &errlen) || err)
    {
        DPE(afpc->errbuf, "%s: getsockopt: %s", __FUNCTION__, strerror(errno));
        return DAQ_ERROR;
    }

    return DAQ_SUCCESS;
}

static int iface_get_arptype(AFPacketInstance *instance)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, instance->name, sizeof(ifr.ifr_name));

    if (ioctl(instance->fd, SIOCGIFHWADDR, &ifr) == -1)
    {
        if (errno == ENODEV)
        {
            return DAQ_ERROR_NODEV;
        }
        return DAQ_ERROR;
    }

    return ifr.ifr_hwaddr.sa_family;
}

static void destroy_rx_ring(AFPacketInstance *instance)
{
    struct tpacket_req req;

    /* Tell the kernel to destroy the ring. */
    memset(&req, 0, sizeof(req));
    setsockopt(instance->fd, SOL_PACKET, PACKET_RX_RING, (void *) &req, sizeof(req));

    if (instance->buffer != MAP_FAILED)
    {
        munmap(instance->buffer, instance->layout.tp_block_nr * instance->layout.tp_block_size);
        instance->buffer = MAP_FAILED;
    }
}

static int create_rx_ring(AFPacket_Context_t *afpc, AFPacketInstance *instance)
{
    unsigned idx, block, frame, ringsize;

    /* Ask the kernel to create the ring. */
    if (setsockopt(instance->fd, SOL_PACKET, PACKET_RX_RING, (void*) &instance->layout, sizeof(struct tpacket_req)))
    {
        DPE(afpc->errbuf, "%s: Couldn't create kernel RX ring on packet socket: %s",
                __FUNCTION__, strerror(errno));
        return DAQ_ERROR_NOMEM;
    }

    /* Memory map the RX ring. */
    ringsize = instance->layout.tp_block_nr * instance->layout.tp_block_size;
    instance->buffer = mmap(0, ringsize, PROT_READ | PROT_WRITE, MAP_SHARED, instance->fd, 0);
    if (instance->buffer == MAP_FAILED)
    {
        DPE(afpc->errbuf, "%s: Couldn't MMAP the RX ring: %s", __FUNCTION__, strerror(errno));

        /* Destroy the kernel RX ring on error. */
        destroy_rx_ring(instance);
        return DAQ_ERROR;
    }

    /* Allocate a ring to hold packet pointers. */
    instance->ring = calloc(instance->layout.tp_frame_nr, sizeof(AFPacketEntry));
    if (!instance->ring)
    {
        DPE(afpc->errbuf, "%s: Could not allocate entry ring for device %s", __FUNCTION__, instance->name);
        destroy_rx_ring(instance);
        return DAQ_ERROR_NOMEM;
    }

    /* Set up the buffer entry pointers in the ring. */
    idx = 0;
    for (block = 0; block < instance->layout.tp_block_nr; block++)
    {
        for (frame = 0; frame < afpc->frames_per_block; frame++)
        {
            instance->ring[idx].begin = (uint8_t *) instance->buffer + (block * instance->layout.tp_block_size) + (frame * instance->layout.tp_frame_size);
            instance->ring[idx].hdr = (struct tpacket_hdr *)instance->ring[idx].begin;
            instance->ring[idx].next = &instance->ring[idx + 1];
            idx++;
        }
    }
    /* Make this a circular buffer ... a RING if you will! */
    instance->ring[instance->layout.tp_frame_nr - 1].next = &instance->ring[0];
    /* Initialize our entry point into the ring as the first buffer entry. */
    instance->entry = &instance->ring[0];

    return DAQ_SUCCESS;
}

static void destroy_instance(AFPacketInstance *instance)
{
    if (instance)
    {
        if (instance->fd != -1)
        {
            destroy_rx_ring(instance);
            close(instance->fd);
            instance->fd = -1;
        }
        if (instance->ring)
        {
            free(instance->ring);
            instance->ring = NULL;
        }
        if (instance->name)
        {
            free(instance->name);
            instance->name = NULL;
        }
        free(instance);
    }
}

static AFPacketInstance *create_instance(AFPacket_Context_t *afpc, const char *device)
{
    AFPacketInstance *instance = NULL;

    instance = calloc(1, sizeof(AFPacketInstance));
    if (!instance)
    {
        DPE(afpc->errbuf, "%s: Could not allocate a new instance structure.", __FUNCTION__);
        goto err;
    }

    instance->buffer = MAP_FAILED;

    if ((instance->name = strdup(device)) == NULL)
    {
        DPE(afpc->errbuf, "%s: Could not allocate a copy of the device name.", __FUNCTION__);
        goto err;;
    }

    /* Open the PF_PACKET raw socket to receive all network traffic completely unmodified. */
    instance->fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (instance->fd == -1)
    {
        DPE(afpc->errbuf, "%s: Could not open the PF_PACKET socket: %s", __FUNCTION__, strerror(errno));
        goto err;
    }
/*
#ifdef SO_BROADCAST
    tmp = 1;
    if (setsockopt(instance->fd, SOL_SOCKET, SO_BROADCAST, &tmp, sizeof(tmp)) < 0)
    {
        fprintf(stderr, "init_af_packet: failed to set broadcast for device %s", instance->name);
        rval = -8;
        goto bail;
    }
#endif
*/
    /* Find the device index of the specified interface. */
    instance->index = find_device_index(instance, instance->name);
    if (instance->index == -1)
    {
        DPE(afpc->errbuf, "%s: Could not find index for device %s", __FUNCTION__, instance->name);
        goto err;
    }

    return instance;

err:
    destroy_instance(instance);
    return NULL;
}

static int start_instance(AFPacket_Context_t *afpc, AFPacketInstance *instance)
{
    struct packet_mreq mr;
    int arptype;

    /* Bind to the specified device so we only see packets from it. */
    if (bind_interface(afpc, instance) != 0)
        return -1;

    /* Turn on promiscuous mode for the device. */
    memset(&mr, 0, sizeof(mr));
    mr.mr_ifindex = instance->index;
    mr.mr_type = PACKET_MR_PROMISC;
    if (setsockopt(instance->fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) == -1)
    {
        DPE(afpc->errbuf, "%s: setsockopt: %s", __FUNCTION__, strerror(errno));
        return -1;
    }

    /* Get the link-layer type. */
    arptype = iface_get_arptype(instance);
    if (arptype < 0)
    {
        DPE(afpc->errbuf, "%s: failed to get interface type for device %s: (%d) %s",
                __FUNCTION__, instance->name, errno, strerror(errno));
        return -1;
    }

    if (arptype != ARPHRD_ETHER)
    {
        DPE(afpc->errbuf, "%s: invalid interface type for device %s: %d != %d",
                __FUNCTION__, instance->name, arptype, ARPHRD_ETHER);
        return -1;
    }

    if (create_rx_ring(afpc, instance) != DAQ_SUCCESS)
        return -1;

    return 0;
}

static void update_hw_stats(AFPacket_Context_t *afpc)
{
    AFPacketInstance *instance;
    struct tpacket_stats kstats;
    socklen_t len = sizeof (struct tpacket_stats);

    for (instance = afpc->instances; instance; instance = instance->next)
    {
        memset(&kstats, 0, len);
        if (getsockopt(instance->fd, SOL_PACKET, PACKET_STATISTICS, &kstats, &len) > -1)
        {
            afpc->stats.hw_packets_received += kstats.tp_packets;
            afpc->stats.hw_packets_dropped += kstats.tp_drops;
        }
        else
            fprintf(stderr, "Failed to get stats for %s: %d %s", instance->name, errno, strerror(errno));
    }
}

static int af_packet_close(AFPacket_Context_t *afpc)
{
    AFPacketInstance *instance;

    if (!afpc)
        return -1;

    /* Cache the latest hardware stats before stopping. */
    update_hw_stats(afpc);

    while ((instance = afpc->instances) != NULL)
    {
        afpc->instances = instance->next;
        destroy_instance(instance);
    }

    sfbpf_freecode(&afpc->fcode);

    afpc->state = DAQ_STATE_STOPPED;

    return 0;
}

static int create_bridge(AFPacket_Context_t *afpc, const char *device_name1, const char *device_name2)
{
    AFPacketInstance *instance, *peer1, *peer2;

    peer1 = peer2 = NULL;
    for (instance = afpc->instances; instance; instance = instance->next)
    {
        if (!strcmp(instance->name, device_name1))
            peer1 = instance;
        else if (!strcmp(instance->name, device_name2))
            peer2 = instance;
    }

    if (!peer1 || !peer2)
        return DAQ_ERROR_NODEV;

    peer1->peer = peer2;
    peer2->peer = peer1;

    return DAQ_SUCCESS;
}

static void reset_stats(AFPacket_Context_t *afpc)
{
    AFPacketInstance *instance;
    struct tpacket_stats kstats;
    socklen_t len = sizeof (struct tpacket_stats);

    memset(&afpc->stats, 0, sizeof(DAQ_Stats_t));
    /* Just call PACKET_STATISTICS to clear each instance's stats. */
    for (instance = afpc->instances; instance; instance = instance->next)
        getsockopt(instance->fd, SOL_PACKET, PACKET_STATISTICS, &kstats, &len);
}

static int afpacket_daq_initialize(const DAQ_Config_t *config, void **ctxt_ptr, char *errbuf, size_t errlen)
{
    AFPacket_Context_t *afpc;
    AFPacketInstance *instance;
    const char *size_str = NULL;
    char *name1, *name2, *dev;
    char intf[IFNAMSIZ];
    uint32_t size;
    size_t len;
    int num_intfs = 0;
    int rval = DAQ_ERROR;
    int debug = 0;
    DAQ_Dict *entry;

    afpc = calloc(1, sizeof(AFPacket_Context_t));
    if (!afpc)
    {
        snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the new AFPacket context!", __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    afpc->device = strdup(config->name);
    if (!afpc->device)
    {
        snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the device string!", __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    afpc->snaplen = config->snaplen;
    afpc->timeout = config->timeout;

    dev = afpc->device;
    if (*dev == ':' || ((len = strlen(dev)) > 0 && *(dev + len - 1) == ':') || (config->mode == DAQ_MODE_PASSIVE && strstr(dev, "::")))
    {
        snprintf(errbuf, errlen, "%s: Invalid interface specification: %s!", __FUNCTION__, afpc->device);
        goto err;
    }

    while (*dev != '\0')
    {
        len = strcspn(dev, ":");
        if (len >= IFNAMSIZ)
        {
            snprintf(errbuf, errlen, "%s: Interface name too long! (%zu)", __FUNCTION__, len);
            goto err;
        }
        if (len != 0)
        {
            afpc->intf_count++;
            if (afpc->intf_count >= AF_PACKET_MAX_INTERFACES)
            {
                snprintf(errbuf, errlen, "%s: Using more than %d interfaces is not supported!", __FUNCTION__, AF_PACKET_MAX_INTERFACES);
                goto err;
            }
            snprintf(intf, len + 1, "%s", dev);
            instance = create_instance(afpc, intf);
            if (!instance)
                goto err;

            instance->next = afpc->instances;
            afpc->instances = instance;
            num_intfs++;
            if (config->mode != DAQ_MODE_PASSIVE)
            {
                if (num_intfs == 2)
                {
                    name1 = afpc->instances->next->name;
                    name2 = afpc->instances->name;

                    if (create_bridge(afpc, name1, name2) != DAQ_SUCCESS)
                    {
                        snprintf(errbuf, errlen, "%s: Couldn't create the bridge between %s and %s!", __FUNCTION__, name1, name2);
                        goto err;
                    }
                    num_intfs = 0;
                }
                else if (num_intfs > 2)
                    break;
            }
        }
        else
            len = 1;
        dev += len;
    }

    /* If there are any leftover unbridged interfaces and we're not in Passive mode, error out. */
    if (config->mode != DAQ_MODE_PASSIVE && num_intfs != 0)
    {
        snprintf(errbuf, errlen, "%s: Invalid interface specification: %s!", __FUNCTION__, afpc->device);
        goto err;
    }

    /* 
     * Determine the dimensions of the kernel RX ring(s) to request.
     */
    /* 1. Find the total desired packet buffer memory for all instances. */
    for (entry = config->values; entry; entry = entry->next)
    {
        if (!strcmp(entry->key, "buffer_size_mb"))
            size_str = entry->value;
        else if (!strcmp(entry->key, "debug"))
            debug = 1;
    }
    /* Fall back to the environment variable. */
    if (!size_str)
        size_str = getenv("AF_PACKET_BUFFER_SIZE");
    if (size_str && strcmp("max", size_str) != 0)
    {
        size = strtoul(size_str, NULL, 10);
        if (size > AF_PACKET_MAX_BUFFER_SIZE)
            size = AF_PACKET_MAX_BUFFER_SIZE;
    }
    else
        size = AF_PACKET_MAX_BUFFER_SIZE;
    /* The size is specified in megabytes. */
    size = size * 1024 * 1024;

    /* 2. Divide it evenly across the number of interfaces. */
    num_intfs = 0;
    for (instance = afpc->instances; instance; instance = instance->next)
        num_intfs++;
    size /= num_intfs;

    /* 3. Calculate the frame size and minimum block size required. */
    afpc->layout.tp_frame_size = TPACKET_ALIGN(afpc->snaplen + TPACKET_HDRLEN);
    afpc->layout.tp_block_size = getpagesize();
    while (afpc->layout.tp_block_size < afpc->layout.tp_frame_size)
        afpc->layout.tp_block_size <<= 1;
    afpc->frames_per_block = afpc->layout.tp_block_size / afpc->layout.tp_frame_size;
    if (afpc->frames_per_block == 0)
    {
        snprintf(errbuf, errlen, "%s: invalid frames per block (%u/%u) for %s",
                __FUNCTION__, afpc->layout.tp_block_size, afpc->layout.tp_frame_size, afpc->device);
        goto err;
    }

    /* 4. Find the total number of frames required to amount to the requested per-interface memory.
           Then find the number of blocks required to hold those packet buffer frames. */
    afpc->layout.tp_frame_nr = size / afpc->layout.tp_frame_size;
    afpc->layout.tp_block_nr = afpc->layout.tp_frame_nr / afpc->frames_per_block;
    /* afpc->layout.tp_frame_nr is requested to match frames_per_block*n_blocks */
    afpc->layout.tp_frame_nr = afpc->layout.tp_block_nr * afpc->frames_per_block;
    if (debug)
    {
        printf("AFPacket Layout:\n");
        printf("  Frame Size: %u\n", afpc->layout.tp_frame_size);
        printf("  Frames:     %u\n", afpc->layout.tp_frame_nr);
        printf("  Block Size: %u\n", afpc->layout.tp_block_size);
        printf("  Blocks:     %u\n", afpc->layout.tp_block_nr);
    }

    /* Propagate the calculated ring layout to the instances. */
    for (instance = afpc->instances; instance; instance = instance->next)
        memcpy(&instance->layout, &afpc->layout, sizeof(struct tpacket_req));

    afpc->state = DAQ_STATE_INITIALIZED;

    *ctxt_ptr = afpc;
    return DAQ_SUCCESS;

err:
    if (afpc)
    {
        af_packet_close(afpc);
        if (afpc->device)
            free(afpc->device);
        free(afpc);
    }
    return rval;
}

static int afpacket_daq_set_filter(void *handle, const char *filter)
{
    AFPacket_Context_t *afpc = (AFPacket_Context_t *) handle;
    struct sfbpf_program fcode;

    if (afpc->filter)
        free(afpc->filter);

    afpc->filter = strdup(filter);
    if (!afpc->filter)
    {
        DPE(afpc->errbuf, "%s: Couldn't allocate memory for the filter string!", __FUNCTION__);
        return DAQ_ERROR;
    }

    if (sfbpf_compile(afpc->snaplen, DLT_EN10MB, &fcode, afpc->filter, 1, 0) < 0)
    {
        DPE(afpc->errbuf, "%s: BPF state machine compilation failed!", __FUNCTION__);
        return DAQ_ERROR;
    }

    sfbpf_freecode(&afpc->fcode);
    afpc->fcode.bf_len = fcode.bf_len;
    afpc->fcode.bf_insns = fcode.bf_insns;

    return DAQ_SUCCESS;
}

static int afpacket_daq_start(void *handle)
{
    AFPacket_Context_t *afpc = (AFPacket_Context_t *) handle;
    AFPacketInstance *instance;

    for (instance = afpc->instances; instance; instance = instance->next)
    {
        if (start_instance(afpc, instance) != 0)
            return DAQ_ERROR;
    }

    reset_stats(afpc);

    afpc->state = DAQ_STATE_STARTED;

    return DAQ_SUCCESS;
}

static const DAQ_Verdict verdict_translation_table[MAX_DAQ_VERDICT] = {
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_PASS */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLOCK */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_REPLACE */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_WHITELIST */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLACKLIST */
    DAQ_VERDICT_PASS        /* DAQ_VERDICT_IGNORE */
};

static int afpacket_daq_acquire(void *handle, int cnt, DAQ_Analysis_Func_t callback, void *user)
{
    AFPacket_Context_t *afpc = (AFPacket_Context_t *) handle;
    AFPacketInstance *instance;
    DAQ_PktHdr_t daqhdr;
    DAQ_Verdict verdict;
    struct tpacket_hdr *hdr;
    struct pollfd pfd[AF_PACKET_MAX_INTERFACES];
    const uint8_t *data;
    uint32_t i;
    int got_one, ignored_one;
    int result, c = 0;
    struct sockaddr_ll *sll;
    const struct ethhdr *eth;

    while (cnt <= 0 || c < cnt)
    {
        got_one = 0;
        ignored_one = 0;
        for (instance = afpc->instances; instance; instance = instance->next)
        {
            /* Has breakloop() been called? */
            if (afpc->break_loop)
            {
                afpc->break_loop = 0;
                return 0;
            }

            hdr = instance->entry->hdr;
            if (hdr->tp_status)
            {
                data = instance->entry->begin + hdr->tp_mac;

                verdict = DAQ_VERDICT_PASS;
                if (afpc->fcode.bf_insns && sfbpf_filter(afpc->fcode.bf_insns, data, hdr->tp_len, hdr->tp_snaplen) == 0)
                {
                    ignored_one = 1;
                    afpc->stats.packets_filtered++;
                    goto send_packet;
                }
                got_one = 1;
                daqhdr.caplen = hdr->tp_snaplen;
                daqhdr.pktlen = hdr->tp_len;
                daqhdr.ts.tv_sec = hdr->tp_sec;
                daqhdr.ts.tv_usec = hdr->tp_usec;
                daqhdr.device_index = instance->index;
                daqhdr.flags = 0;

                if (callback)
                {
                    verdict = callback(user, &daqhdr, data);
                    if (verdict >= MAX_DAQ_VERDICT)
                        verdict = DAQ_VERDICT_PASS;
                    afpc->stats.verdicts[verdict]++;
                    verdict = verdict_translation_table[verdict];
                }
                afpc->stats.packets_received++;
                c++;
send_packet:
                if (verdict == DAQ_VERDICT_PASS && instance->peer)
                {
                    eth = (const struct ethhdr *)data;
                    sll = &instance->peer->sll;
                    sll->sll_protocol = eth->h_proto;
                    sendto(instance->peer->fd, data, hdr->tp_snaplen, 0, (struct sockaddr *) sll, sizeof(*sll));
                }
                hdr->tp_status = TP_STATUS_KERNEL;
                instance->entry = instance->entry->next;
            }
        }
        if (!got_one && !ignored_one)
        {
            for (i = 0, instance = afpc->instances; instance; i++, instance = instance->next)
            {
                pfd[i].fd = instance->fd;
                pfd[i].revents = 0;
                pfd[i].events = POLLIN;
            }
            result = poll(pfd, afpc->intf_count, afpc->timeout);
            if (result < 0)
            {
                DPE(afpc->errbuf, "%s: Poll failed: %s", __FUNCTION__, strerror(errno));
                return DAQ_ERROR;
            }
            else if (result == 0)
                break;
        }
    }
    return 0;
}

static int afpacket_daq_inject(void *handle, const DAQ_PktHdr_t *hdr, const uint8_t *packet_data, uint32_t len, int reverse)
{
    AFPacket_Context_t *afpc = (AFPacket_Context_t *) handle;
    AFPacketInstance *instance;
    struct sockaddr_ll *sll;
    const struct ethhdr *eth;

    /* Find the instance that the packet was received on. */
    for (instance = afpc->instances; instance; instance = instance->next)
    {
        if (instance->index == hdr->device_index)
            break;
    }

    if (!instance || (!reverse && !(instance = instance->peer)))
        return DAQ_ERROR;

    eth = (const struct ethhdr *)packet_data;
    sll = &instance->sll;
    sll->sll_protocol = eth->h_proto;

    if (sendto(instance->fd, packet_data, len, 0, (struct sockaddr *)sll, sizeof(*sll)) < 0)
        return DAQ_ERROR;

    afpc->stats.packets_injected++;

    return DAQ_SUCCESS;
}

static int afpacket_daq_breakloop(void *handle)
{
    AFPacket_Context_t *afpc = (AFPacket_Context_t *) handle;

    afpc->break_loop = 1;

    return DAQ_SUCCESS;
}

static int afpacket_daq_stop(void *handle)
{
    AFPacket_Context_t *afpc = (AFPacket_Context_t *) handle;

    af_packet_close(afpc);

    return DAQ_SUCCESS;
}

static void afpacket_daq_shutdown(void *handle)
{
    AFPacket_Context_t *afpc = (AFPacket_Context_t *) handle;

    af_packet_close(afpc);
    if (afpc->device)
        free(afpc->device);
    if (afpc->filter)
        free(afpc->filter);
    free(afpc);
}

static DAQ_State afpacket_daq_check_status(void *handle)
{
    AFPacket_Context_t *afpc = (AFPacket_Context_t *) handle;

    return afpc->state;
}

static int afpacket_daq_get_stats(void *handle, DAQ_Stats_t *stats)
{
    AFPacket_Context_t *afpc = (AFPacket_Context_t *) handle;

    update_hw_stats(afpc);
    memcpy(stats, &afpc->stats, sizeof(DAQ_Stats_t));

    return DAQ_SUCCESS;
}

static void afpacket_daq_reset_stats(void *handle)
{
    AFPacket_Context_t *afpc = (AFPacket_Context_t *) handle;

    reset_stats(afpc);
}

static int afpacket_daq_get_snaplen(void *handle)
{
    AFPacket_Context_t *afpc = (AFPacket_Context_t *) handle;

    return afpc->snaplen;
}

static uint32_t afpacket_daq_get_capabilities(void *handle)
{
    return DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT | DAQ_CAPA_UNPRIV_START | DAQ_CAPA_BREAKLOOP | DAQ_CAPA_BPF | DAQ_CAPA_DEVICE_INDEX;
}

static int afpacket_daq_get_datalink_type(void *handle)
{
    return DLT_EN10MB;
}

static const char *afpacket_daq_get_errbuf(void *handle)
{
    AFPacket_Context_t *afpc = (AFPacket_Context_t *) handle;

    return afpc->errbuf;
}

static void afpacket_daq_set_errbuf(void *handle, const char *string)
{
    AFPacket_Context_t *afpc = (AFPacket_Context_t *) handle;

    if (!string)
        return;

    DPE(afpc->errbuf, "%s", string);
}

static int afpacket_daq_get_device_index(void *handle, const char *string)
{
    AFPacket_Context_t *afpc = (AFPacket_Context_t *) handle;
    AFPacketInstance *instance;

    for (instance = afpc->instances; instance; instance = instance->next)
    {
        if (!strcmp(string, instance->name))
            return instance->index;
    }

    return DAQ_ERROR_NODEV;
}

#ifdef BUILDING_SO
SO_PUBLIC const DAQ_Module_t DAQ_MODULE_DATA = 
#else
const DAQ_Module_t afpacket_daq_module_data = 
#endif
{
    .api_version = DAQ_API_VERSION,
    .module_version = DAQ_AFPACKET_VERSION,
    .name = "afpacket",
    .type = DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
    .initialize = afpacket_daq_initialize,
    .set_filter = afpacket_daq_set_filter,
    .start = afpacket_daq_start,
    .acquire = afpacket_daq_acquire,
    .inject = afpacket_daq_inject,
    .breakloop = afpacket_daq_breakloop,
    .stop = afpacket_daq_stop,
    .shutdown = afpacket_daq_shutdown,
    .check_status = afpacket_daq_check_status,
    .get_stats = afpacket_daq_get_stats,
    .reset_stats = afpacket_daq_reset_stats,
    .get_snaplen = afpacket_daq_get_snaplen,
    .get_capabilities = afpacket_daq_get_capabilities,
    .get_datalink_type = afpacket_daq_get_datalink_type,
    .get_errbuf = afpacket_daq_get_errbuf,
    .set_errbuf = afpacket_daq_set_errbuf,
    .get_device_index = afpacket_daq_get_device_index
};
