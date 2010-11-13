/*
** Copyright (C) 2010 Sourcefire, Inc.
** Author: Michael R. Altizer <maltizer@sourcefire.com>
**
** Copyright (C) 2010 ntop.org
** Authors: Luca Deri <deri@ntop.org>
**          Will Metcalf <william.metcalf@gmail.com>
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

#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "pfring.h"
#include "sfbpf.h"
#include <sys/sysinfo.h> /* get_nprocs (void) */

#include "daq_api.h"

#define DAQ_PF_RING_VERSION 1

typedef struct _pfring_context
{
  char *device, *twin_device;
  char *filter_string;
  int snaplen;
  pfring *ring_handle, *twin_ring_handle;
  char errbuf[1024], *pkt_buffer;
  u_int breakloop;
  int promisc_flag;
  int timeout;
  DAQ_Analysis_Func_t analysis_func;
  uint32_t netmask;
  DAQ_Stats_t stats;
  u_int clusterid;
  u_int bindcpu;
  uint32_t base_recv[2];
  uint32_t base_drop[2];
  DAQ_State state;
} Pfring_Context_t;

static void pfring_daq_reset_stats(void *handle);
static int pfring_daq_set_filter(void *handle, const char *filter);

static pfring* pfring_daq_open(Pfring_Context_t *context, char *device)
{
  uint32_t default_net = 0xFFFFFF00;
  int pfring_rc;
  pfring *ring_handle;

  if (!device)
    {
      DPE(context->errbuf, "%s", "PF_RING a device must be specified");
      return NULL;
    }

  if (device)
    {
      context->pkt_buffer = (char*)malloc(context->snaplen+1);
      if (context->pkt_buffer == NULL) {
	DPE(context->errbuf, "pfring_daq_open(): unable to allocate enough memory for snaplen %d", context->snaplen);
	return NULL;
      }

      ring_handle = pfring_open(device, context->promisc_flag ? 1 : 0,
				context->snaplen, 1);

      if (!ring_handle) {
	DPE(context->errbuf, "pfring_open(): unable to open device '%s'. Please use -i <device>", device);
	return NULL;
      }
    }

  if (context->clusterid > 0)
    {
      pfring_rc = pfring_set_cluster(ring_handle, context->clusterid, cluster_per_flow);

      if (pfring_rc != 0)
	{
          DPE(context->errbuf, "pfring_set_cluster returned %d", pfring_rc);
          return NULL;
        }
    }

  context->netmask = htonl(default_net);

  if (context->filter_string)
    {
      if (pfring_daq_set_filter(ring_handle, context->filter_string))
	return NULL;
    }

  return(ring_handle);
}

static int update_hw_stats(Pfring_Context_t *context)
{
  pfring_stat ps;

  if (context->ring_handle && context->device)
    {
      memset(&ps, 0, sizeof(pfring_stat));
      if (pfring_stats(context->ring_handle, &ps) == -1)
        {
	  DPE(context->errbuf, "%s", "pfring_stats error");
	  return DAQ_ERROR;
        }

      context->stats.hw_packets_received = ps.recv - context->base_recv[0];
      context->stats.hw_packets_dropped = ps.drop - context->base_drop[0];
    }

  if (context->twin_ring_handle && context->twin_device)
    {
      memset(&ps, 0, sizeof(pfring_stat));
      if (pfring_stats(context->twin_ring_handle, &ps) == -1)
        {
	  DPE(context->errbuf, "%s", "pfring_stats error");
	  return DAQ_ERROR;
        }

      context->stats.hw_packets_received += ps.recv - context->base_recv[1];
      context->stats.hw_packets_dropped += ps.drop - context->base_drop[1];
    }

  return DAQ_SUCCESS;
}

static int pfring_daq_initialize(const DAQ_Config_t *config, void **ctxt_ptr, char *errbuf, size_t len)
{
  Pfring_Context_t *context;
  DAQ_Dict* entry;
  /* taken from pfcount example */
  u_int numCPU = get_nprocs();

  context = calloc(1, sizeof(Pfring_Context_t));
  if (!context)
    {
      snprintf(errbuf, len, "%s: Couldn't allocate memory for the new PF_RING context!", __FUNCTION__);
      return DAQ_ERROR_NOMEM;
    }

  context->clusterid = 0;
  context->snaplen = config->snaplen;
  context->promisc_flag = (config->flags & DAQ_CFG_PROMISC);
  context->timeout = (config->timeout > 0) ? (int) config->timeout : -1;

  context->device = strdup(config->name);
  if (!context->device)
    {
      snprintf(errbuf, len, "%s: Couldn't allocate memory for the device string!", __FUNCTION__);
      free(context);
      return DAQ_ERROR_NOMEM;
    }

  if (config->mode == DAQ_MODE_READ_FILE)
    {
      snprintf(errbuf, len, "%s: function not supported on PF_RING", __FUNCTION__);
      free(context);

      return DAQ_ERROR;
    } else if(config->mode == DAQ_MODE_INLINE)
    {
      /* ethX:ethY */
      char *column = strchr(context->device, ':');

      if(column != NULL) {
	column[0] = '\0';
	context->twin_device = &column[1];
      }
    }

  for ( entry = config->values; entry; entry = entry->next)
    {
      if ( !entry->value || !*entry->value )
	{
	  snprintf(errbuf, len,
		   "%s: variable needs value (%s)\n", __FUNCTION__, entry->key);
	  return DAQ_ERROR;
	}

      else if ( !strcmp(entry->key, "clusterid") )
	{
	  if (config->mode == DAQ_MODE_INLINE) {
	    snprintf(errbuf, len, "Clustering is not supported in inline mode\n");
	    return DAQ_ERROR;
	  } else
	    {
	      char* end = entry->value;
	      context->clusterid = (int)strtol(entry->value, &end, 0);
	      if ( *end || context->clusterid <= 0 ||context->clusterid > 65535 )
		{
		  snprintf(errbuf, len, "%s: bad clusterid (%s)\n",
			   __FUNCTION__, entry->value);
		  return DAQ_ERROR;
		}
	    }
	}
      else if ( !strcmp(entry->key, "bindcpu") )
	{
	  char* end = entry->value;
	  context->bindcpu = (int)strtol(entry->value, &end, 0);
	  if ( *end || context->bindcpu >= numCPU )
	    {
	      snprintf(errbuf, len, "%s: bad bindcpu (%s)\n",
		       __FUNCTION__, entry->value);
	      return DAQ_ERROR;
	    }
	  else
	    {
	      cpu_set_t mask;

	      CPU_ZERO(&mask);
	      CPU_SET((int)context->bindcpu, &mask);
	      if (sched_setaffinity(0, sizeof(mask), &mask) <0)
		{
		  snprintf(errbuf, len, "%s:failed to set bindcpu (%u) on pid %i\n",
			   __FUNCTION__, context->bindcpu, getpid());
		  return DAQ_ERROR;
		}
            }
	}

      else
	{
	  snprintf(errbuf, len,
		   "%s: unsupported variable (%s=%s)\n",
		   __FUNCTION__, entry->key, entry->value);
	  return DAQ_ERROR;
	}
    }

  context->state = DAQ_STATE_INITIALIZED;

  *ctxt_ptr = context;
  return DAQ_SUCCESS;
}

static int pfring_daq_set_filter(void *handle, const char *filter)
{
  Pfring_Context_t *context = (Pfring_Context_t *) handle;
  int ret;
  struct sfbpf_program fcode;

  if (context->ring_handle) {
    if (sfbpf_compile(context->snaplen, DLT_EN10MB, &fcode,
		      context->filter_string, 1, htonl(context->netmask)) < 0)
      {
	DPE(context->errbuf, "%s: BPF state machine compilation failed!", __FUNCTION__);
	return DAQ_ERROR;
      }

    if (setsockopt(pfring_get_selectable_fd(context->ring_handle), 0,
		   SO_ATTACH_FILTER, &fcode, sizeof(fcode)) == 0) {
      ret = DAQ_SUCCESS;
    } else
      ret = DAQ_ERROR;

    sfbpf_freecode(&fcode);
  } else {
    /* Just check if the filter is valid */

    if (sfbpf_compile(context->snaplen, DLT_EN10MB, &fcode, filter, 1, htonl(0xFFFFFF00) /* /24 */) < 0)
      {
	DPE(context->errbuf, "%s: BPF state machine compilation failed!", __FUNCTION__);
	return DAQ_ERROR;
      }

    ret = DAQ_SUCCESS;

    if (context->filter_string)
      free(context->filter_string);

    context->filter_string = strdup(filter);
    if (!context->filter_string)
      {
	DPE(context->errbuf, "%s: Couldn't allocate memory for the filter string!", __FUNCTION__);
	return DAQ_ERROR;
      }

    sfbpf_freecode(&fcode);
  }


  return ret;
}

static int pfring_daq_start(void *handle)
{
  Pfring_Context_t *context = (Pfring_Context_t *) handle;

  if(context->ring_handle == NULL) {
    context->ring_handle = pfring_daq_open(context, context->device);

    if(context->ring_handle == NULL)
      return DAQ_ERROR;
  }

  if(context->twin_device) {
    context->twin_ring_handle = pfring_daq_open(context, context->twin_device);

    if(context->twin_ring_handle == NULL)
      return DAQ_ERROR;
  }

  pfring_daq_reset_stats(context);
  context->state = DAQ_STATE_STARTED;

  return DAQ_SUCCESS;
}

static int pfring_daq_acquire(void *handle, int cnt, DAQ_Analysis_Func_t callback, void *user)
{
  Pfring_Context_t *context = (Pfring_Context_t *) handle;
  int ret;
  pfring *next_ring = context->ring_handle;

  context->analysis_func = callback;
  context->breakloop = 0;

  while ((!context->breakloop) && ((cnt == -1) || (cnt > 0)))
    {
      struct pfring_pkthdr phdr;
      DAQ_PktHdr_t hdr;
      DAQ_Verdict verdict;
      
      ret = pfring_read(next_ring, context->pkt_buffer, context->snaplen, &phdr, 0 /* Dont't wait */);
      if((ret == -1) && (context->twin_ring_handle != NULL))        
	  ret = pfring_read(context->twin_ring_handle, context->pkt_buffer, context->snaplen, &phdr, 0 /* Dont't wait */);
      else if(context->twin_ring_handle)
	next_ring = context->twin_ring_handle;

      if(ret == -1) {
	/* No packet to read: let's poll */
	struct pollfd pfd[2];
	int num = 1, rc;

	pfd[0].fd = context->ring_handle->fd, pfd[0].events = POLLIN, pfd[0].revents = 0;

	if(context->twin_ring_handle)
	  pfd[1].fd = context->twin_ring_handle->fd, pfd[1].events = POLLIN, pfd[1].revents = 0, num = 2;

	rc = poll(pfd, num, context->timeout);

	if(rc < 0) {
	  if(errno == EINTR)
	    break;

	  DPE(context->errbuf, "%s: Poll failed: %s (%d)", __FUNCTION__, strerror(errno), errno);
	  return DAQ_ERROR;
	}
      } else {
	hdr.caplen = phdr.caplen;
	hdr.pktlen = phdr.len;
	hdr.ts = phdr.ts;
	hdr.device_index = phdr.extended_hdr.if_index;
	hdr.flags = 0;

	context->stats.packets_received++;
	verdict = context->analysis_func(user, &hdr, (u_char*)context->pkt_buffer);
	if (verdict >= MAX_DAQ_VERDICT)
	  verdict = DAQ_VERDICT_PASS;

	if(verdict == DAQ_VERDICT_BLACKLIST) {
	  hash_filtering_rule hash_rule;
	  int rc;

	  /* Block the packet and block all future packets in the same flow systemwide. */

	  memset(&hash_rule, 0, sizeof(hash_rule));

	  hash_rule.vlan_id     = phdr.extended_hdr.parsed_pkt.vlan_id;
	  hash_rule.proto       = phdr.extended_hdr.parsed_pkt.l3_proto;
	  memcpy(&hash_rule.host_peer_a, &phdr.extended_hdr.parsed_pkt.ipv4_src, sizeof(ip_addr));
	  memcpy(&hash_rule.host_peer_b, &phdr.extended_hdr.parsed_pkt.ipv4_dst, sizeof(ip_addr));
	  hash_rule.port_peer_a = phdr.extended_hdr.parsed_pkt.l4_src_port;
	  hash_rule.port_peer_b = phdr.extended_hdr.parsed_pkt.l4_dst_port;
	  hash_rule.rule_action = dont_forward_packet_and_stop_rule_evaluation;
	  hash_rule.plugin_action.plugin_id = NO_PLUGIN_ID;

	  rc = pfring_handle_hash_filtering_rule(context->ring_handle, &hash_rule, 1 /* add_rule */);

	  /* printf("Verdict=%d [pfring_handle_hash_filtering_rule=%d]\n", verdict, rc); */
	} else if((verdict == DAQ_VERDICT_PASS) && (context->twin_ring_handle /* DAQ_MODE_INLINE */)) {
	  /* Userland PF_RING bridge */
	  if (pfring_send((next_ring == context->ring_handle) ? context->ring_handle : context->twin_ring_handle,
			  (char*)context->pkt_buffer, hdr.caplen) < 0)
	    {
	      DPE(context->errbuf, "%s", "pfring_send() error");
	      return DAQ_ERROR;
	    }

	  context->stats.packets_injected++;
	}

	context->stats.verdicts[verdict]++;
	if(cnt > 0) cnt--;
      }
    }

  return 0;
}

static int pfring_daq_inject(void *handle, const DAQ_PktHdr_t *hdr, const uint8_t *packet_data, uint32_t len, int reverse)
{
  Pfring_Context_t *context = (Pfring_Context_t *) handle;

  if (pfring_send(context->ring_handle, (char*)packet_data, len) < 0)
    {
      DPE(context->errbuf, "%s", "pfring_send() error");
      return DAQ_ERROR;
    }

  context->stats.packets_injected++;
  return DAQ_SUCCESS;
}

static int pfring_daq_breakloop(void *handle)
{
  Pfring_Context_t *context = (Pfring_Context_t *) handle;

  if (!context->ring_handle)
    return DAQ_ERROR;

  context->breakloop = 1;

  return DAQ_SUCCESS;
}

static int pfring_daq_stop(void *handle)
{
  Pfring_Context_t *context = (Pfring_Context_t *) handle;

  if (context->ring_handle)
    {
      /* Store the hardware stats for post-stop stat calls. */
      update_hw_stats(context);
      pfring_close(context->ring_handle);
      context->ring_handle = NULL;

      if (context->pkt_buffer)
	{
	  free(context->pkt_buffer);
	  context->pkt_buffer = NULL;
	}
    }

  context->state = DAQ_STATE_STOPPED;

  return DAQ_SUCCESS;
}

static void pfring_daq_shutdown(void *handle)
{
  Pfring_Context_t *context = (Pfring_Context_t *) handle;

  if (context->ring_handle)
    pfring_close(context->ring_handle);

  if (context->twin_ring_handle)
    pfring_close(context->twin_ring_handle);

  if (context->device)
    free(context->device);

  if (context->filter_string)
    free(context->filter_string);

  if (context->pkt_buffer)
    free(context->pkt_buffer);

  free(context);
}

static DAQ_State pfring_daq_check_status(void *handle)
{
  Pfring_Context_t *context = (Pfring_Context_t *) handle;

  return context->state;
}

static int pfring_daq_get_stats(void *handle, DAQ_Stats_t *stats)
{
  Pfring_Context_t *context = (Pfring_Context_t *) handle;

  if (update_hw_stats(context) != DAQ_SUCCESS)
    return DAQ_ERROR;

  memcpy(stats, &context->stats, sizeof(DAQ_Stats_t));

  return DAQ_SUCCESS;
}

static void pfring_daq_reset_stats(void *handle)
{
  Pfring_Context_t *context = (Pfring_Context_t *) handle;
  pfring_stat ps;

  memset(&context->stats, 0, sizeof(DAQ_Stats_t));

  if (!context->ring_handle)
    return;

  memset(&ps, 0, sizeof(pfring_stat));
  if (context->ring_handle && context->device && pfring_stats(context->ring_handle, &ps) == 0)
    {
      context->base_recv[0] = ps.recv;
      context->base_drop[0] = ps.drop;
    }

  if (context->twin_ring_handle && context->twin_device && pfring_stats(context->twin_ring_handle, &ps) == 0)
    {
      context->base_recv[1] = ps.recv;
      context->base_drop[1] = ps.drop;
    }
}

static int pfring_daq_get_snaplen(void *handle)
{
  Pfring_Context_t *context = (Pfring_Context_t *) handle;

  if (!context->ring_handle)
    return DAQ_ERROR;
  else
    return context->snaplen;
}

static uint32_t pfring_daq_get_capabilities(void *handle)
{
  return DAQ_CAPA_INJECT | DAQ_CAPA_INJECT_RAW | DAQ_CAPA_BREAKLOOP | DAQ_CAPA_UNPRIV_START | DAQ_CAPA_BPF;
}

static int pfring_daq_get_datalink_type(void *handle)
{
  Pfring_Context_t *context = (Pfring_Context_t *) handle;

  if (!context)
    return DAQ_ERROR;
  else
    return DLT_EN10MB;
}

static const char *pfring_daq_get_errbuf(void *handle)
{
  Pfring_Context_t *context = (Pfring_Context_t *) handle;

  return context->errbuf;
}

static void pfring_daq_set_errbuf(void *handle, const char *string)
{
  Pfring_Context_t *context = (Pfring_Context_t *) handle;

  if (!string)
    return;

  DPE(context->errbuf, "%s", string);
}

static int pfring_daq_get_device_index(void *handle, const char *device)
{
  return DAQ_ERROR_NOTSUP;
}

#ifdef BUILDING_SO
SO_PUBLIC const DAQ_Module_t DAQ_MODULE_DATA =
#else
  const DAQ_Module_t pfring_daq_module_data =
#endif
  {
    .api_version = DAQ_API_VERSION,
    .module_version = DAQ_PF_RING_VERSION,
    .name = "pfring",
    .type = DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
    .initialize = pfring_daq_initialize,
    .set_filter = pfring_daq_set_filter,
    .start = pfring_daq_start,
    .acquire = pfring_daq_acquire,
    .inject = pfring_daq_inject,
    .breakloop = pfring_daq_breakloop,
    .stop = pfring_daq_stop,
    .shutdown = pfring_daq_shutdown,
    .check_status = pfring_daq_check_status,
    .get_stats = pfring_daq_get_stats,
    .reset_stats = pfring_daq_reset_stats,
    .get_snaplen = pfring_daq_get_snaplen,
    .get_capabilities = pfring_daq_get_capabilities,
    .get_datalink_type = pfring_daq_get_datalink_type,
    .get_errbuf = pfring_daq_get_errbuf,
    .set_errbuf = pfring_daq_set_errbuf,
    .get_device_index = pfring_daq_get_device_index
  };
