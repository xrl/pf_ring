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

#include "daq_api.h"

#define DAQ_PF_RING_VERSION 1

typedef struct _pfring_context
{
  char *device;
  char *filter_string;
  int snaplen;
  pfring *handle;
  char errbuf[1024];
  u_int breakloop;
  int promisc_flag;
  int timeout;
  int buffer_size;
  int packets;
  int delayed_open;
  struct sfbpf_program fcode;
  DAQ_Analysis_Func_t analysis_func;
  u_char *user_data;
  uint32_t netmask;
  DAQ_Stats_t stats;
  uint32_t base_recv;
  uint32_t base_drop;
  uint64_t rollover_recv;
  uint64_t rollover_drop;
  uint32_t wrap_recv;
  uint32_t wrap_drop;
  u_int clusterid;
  u_int bindcpu;
  DAQ_State state;
} Pfring_Context_t;

static void pfring_daq_reset_stats(void *handle);

static int pfring_daq_open(Pfring_Context_t *context)
{
  uint32_t defaultnet = 0xFFFFFF00;
  int pfring_rc;

  if (context->handle)
    return DAQ_SUCCESS;

  if (!context->device)
    {
      DPE(context->errbuf, "%s", "PF_RING a device must be specified");
      return DAQ_ERROR;
    }

  if (context->device)
    {
      context->handle = pfring_open(context->device, context->promisc_flag ? 1 : 0,
				    context->snaplen, 1);

      if (!context->handle)
	return DAQ_ERROR;
    }

  if (context->clusterid > 0)
    {
      pfring_rc = pfring_set_cluster(context->handle, context->clusterid, cluster_per_flow);

    if (pfring_rc != 0)
	{
          DPE(context->errbuf, "pfring_set_cluster returned %d", pfring_rc);
          return DAQ_ERROR;
        }
    }

  context->netmask = htonl(defaultnet);

  return DAQ_SUCCESS;
}

static int update_hw_stats(Pfring_Context_t *context)
{
  pfring_stat ps;

  if (context->handle && context->device)
    {
      memset(&ps, 0, sizeof(pfring_stat));
      if (pfring_stats(context->handle, &ps) == -1)
        {
	  DPE(context->errbuf, "%s", "pfring_stats error");
	  return DAQ_ERROR;
        }

      /* PF_RING receive counter wrapped */
      if (ps.recv < context->wrap_recv)
	context->rollover_recv += UINT32_MAX;

      /* PF_RING drop counter wrapped */
      if (ps.drop < context->wrap_drop)
	context->rollover_drop += UINT32_MAX;

      context->wrap_recv = ps.recv;
      context->wrap_drop = ps.drop;

      context->stats.hw_packets_received = context->rollover_recv + context->wrap_recv - context->base_recv;
      context->stats.hw_packets_dropped = context->rollover_drop + context->wrap_drop - context->base_drop;
    }

  return DAQ_SUCCESS;
}

static int pfring_daq_initialize(const DAQ_Config_t *config, void **ctxt_ptr, char *errbuf, size_t len)
{
  Pfring_Context_t *context;
  DAQ_Dict* entry;
  /* taken from pfcount example */
  u_int numCPU = sysconf( _SC_NPROCESSORS_ONLN );

  context = calloc(1, sizeof(Pfring_Context_t));
  if (!context)
    {
      snprintf(errbuf, len, "%s: Couldn't allocate memory for the new PF_RING context!", __FUNCTION__);
      return DAQ_ERROR_NOMEM;
    }

  context->clusterid = 0;
  context->snaplen = config->snaplen;
  context->promisc_flag = (config->flags & DAQ_CFG_PROMISC);
  context->timeout = config->timeout;

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
	  char* end = entry->value;
	  context->clusterid = (int)strtol(entry->value, &end, 0);
	  if ( *end || context->clusterid <= 0 ||context->clusterid > 65535 )
	    {
	      snprintf(errbuf, len, "%s: bad clusterid (%s)\n",
		       __FUNCTION__, entry->value);
	      return DAQ_ERROR;
	    }
	}
      else if ( !strcmp(entry->key, "bindcpu") )
	{
	  char* end = entry->value;
	  context->bindcpu = (int)strtol(entry->value, &end, 0);
	  if ( *end || context->bindcpu > numCPU )
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

  if (!context->delayed_open)
    {
      if (pfring_daq_open(context) != DAQ_SUCCESS)
        {
	  snprintf(errbuf, len, "%s", context->errbuf);
	  free(context);
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
  struct sfbpf_program fcode;
  if (context->filter_string)
    free(context->filter_string);

  context->filter_string = strdup(filter);
  if (!context->filter_string)
    {
      DPE(context->errbuf, "%s: Couldn't allocate memory for the filter string!", __FUNCTION__);
      return DAQ_ERROR;
    }

  if (sfbpf_compile(context->snaplen, DLT_EN10MB, &fcode, context->filter_string, 1, 0) < 0)
    {
      DPE(context->errbuf, "%s: BPF state machine compilation failed!", __FUNCTION__);
      return DAQ_ERROR;
    }

  sfbpf_freecode(&context->fcode);
  context->fcode.bf_len = fcode.bf_len;
  context->fcode.bf_insns = fcode.bf_insns;

  /* TODO: MISSING pfring_setfilter() */
  return DAQ_SUCCESS;
}

static int pfring_daq_start(void *handle)
{
  Pfring_Context_t *context = (Pfring_Context_t *) handle;

  if (pfring_daq_open(context) != DAQ_SUCCESS)
    return DAQ_ERROR;

  pfring_daq_reset_stats(handle);

  if (context->filter_string)
    {
      /* TODO: MISSING pfring_daq_set_filter() */
      /*
        if (pfring_daq_set_filter(handle, context->filter_string))
	return DAQ_ERROR;
      */
      free(context->filter_string);
      context->filter_string = NULL;
    }

  context->state = DAQ_STATE_STARTED;

  return DAQ_SUCCESS;
}

static void pfring_process_loop(u_char *user, const struct pfring_pkthdr *pkth, const u_char *data)
{
  Pfring_Context_t *context = (Pfring_Context_t *) user;
  DAQ_PktHdr_t hdr;
  DAQ_Verdict verdict;

  hdr.caplen = pkth->caplen;
  hdr.pktlen = pkth->len;
  hdr.ts = pkth->ts;
  hdr.device_index = pkth->extended_hdr.if_index;
  hdr.flags = 0;

  /* Increment the current acquire loop's packet counter. */
  context->packets++;
  /* ...and then the module instance's packet counter. */
  context->stats.packets_received++;
  verdict = context->analysis_func(context->user_data, &hdr, data);
  if (verdict >= MAX_DAQ_VERDICT)
    verdict = DAQ_VERDICT_PASS;
  context->stats.verdicts[verdict]++;
}

static int pfring_daq_acquire(void *handle, int cnt, DAQ_Analysis_Func_t callback, void *user)
{
  Pfring_Context_t *context = (Pfring_Context_t *) handle;
  int ret;

  context->analysis_func = callback;
  context->user_data = user;

  context->packets = context->breakloop = 0;
  while (context->packets < cnt || cnt <= 0)
    {
      char pkt_buffer[1600];
      struct pfring_pkthdr hdr;

      if(context->breakloop) break;

      ret = pfring_read(context->handle, pkt_buffer, sizeof(pkt_buffer), &hdr, 1, 1);
      if (ret == -1)
        {
	  DPE(context->errbuf, "%s", "pfring_read() errpr");
	  return ret;
        } else
	context->packets++;

      pfring_process_loop((u_char*)context, &hdr, (u_char*)pkt_buffer);
    }

  return 0;
}

static int pfring_daq_inject(void *handle, const DAQ_PktHdr_t *hdr, const uint8_t *packet_data, uint32_t len, int reverse)
{
  Pfring_Context_t *context = (Pfring_Context_t *) handle;

  if (pfring_send(context->handle, packet_data, len) < 0)
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

  if (!context->handle)
    return DAQ_ERROR;

  context->breakloop = 1;

  return DAQ_SUCCESS;
}

static int pfring_daq_stop(void *handle)
{
  Pfring_Context_t *context = (Pfring_Context_t *) handle;

  if (context->handle)
    {
      /* Store the hardware stats for post-stop stat calls. */
      update_hw_stats(context);
      pfring_close(context->handle);
      context->handle = NULL;
    }

  context->state = DAQ_STATE_STOPPED;

  return DAQ_SUCCESS;
}

static void pfring_daq_shutdown(void *handle)
{
  Pfring_Context_t *context = (Pfring_Context_t *) handle;

  if (context->handle)
    pfring_close(context->handle);
  if (context->device)
    free(context->device);
  if (context->filter_string)
    free(context->filter_string);
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

  if (!context->handle)
    return;

  memset(&ps, 0, sizeof(pfring_stat));
  if (context->handle && context->device && pfring_stats(context->handle, &ps) == 0)
    {
      context->base_recv = context->wrap_recv = ps.recv;
      context->base_drop = context->wrap_drop = ps.drop;
    }
}

static int pfring_daq_get_snaplen(void *handle)
{
  Pfring_Context_t *context = (Pfring_Context_t *) handle;

  if (!context->handle)
    return DAQ_ERROR;
  else
    return context->snaplen;
}

static uint32_t pfring_daq_get_capabilities(void *handle)
{
  return /* DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | */ DAQ_CAPA_INJECT | DAQ_CAPA_INJECT_RAW
    | DAQ_CAPA_BREAKLOOP | DAQ_CAPA_UNPRIV_START | DAQ_CAPA_BPF;
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
