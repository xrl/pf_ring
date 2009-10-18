/* ***************************************************************
 *
 * (C) 2007-09 - Luca Deri <deri@ntop.org>
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

#include <linux/version.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19))
#include <linux/autoconf.h>
#else
#include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/in6.h>
#include <linux/init.h>
#include <linux/filter.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/textsearch.h>
#include <net/xfrm.h>
#include <net/sock.h>
#include <asm/io.h>   /* needed for virt_to_phys() */
#ifdef CONFIG_INET
#include <net/inet_common.h>
#endif
#include <net/ip.h>

/* Enable plugin PF_RING functions */
#define PF_RING_PLUGIN
#include <linux/pf_ring.h>

struct simple_stats {
  u_int64_t num_pkts, num_bytes;
};

static u_int16_t plugin_id = 1;

static struct pfring_plugin_registration reg;

/* ************************************ */

static int dummy_plugin_plugin_handle_skb(struct ring_opt *pfr,
					  filtering_rule_element *rule,
					  filtering_hash_bucket *hash_rule,
					  struct pfring_pkthdr *hdr,
					  struct sk_buff *skb,
					  u_int16_t filter_plugin_id,
					  struct parse_buffer **filter_rule_memory_storage,
					  rule_action_behaviour *behaviour)
{

  if(rule != NULL) {
    if(rule->plugin_data_ptr == NULL) {
      rule->plugin_data_ptr = (struct simple_stats*)kmalloc(sizeof(struct simple_stats), GFP_KERNEL);
      if(rule->plugin_data_ptr != NULL)
	memset(rule->plugin_data_ptr, 0, sizeof(struct simple_stats));
    }

    if(rule->plugin_data_ptr != NULL) {
      struct simple_stats *stats = (struct simple_stats*)rule->plugin_data_ptr;
      stats->num_pkts++, stats->num_bytes += hdr->len;

#ifdef DEBUG
      printk("-> dummy_plugin_plugin_handle_skb [pkts=%u][bytes=%u]\n",
	     (unsigned int)stats->num_pkts,
	     (unsigned int)stats->num_bytes);
#endif
    }
  }

  return(0);
}

/* ************************************ */

struct dummy_filter {
  u_int32_t src_host;
};

static int dummy_plugin_plugin_filter_skb(struct ring_opt *the_ring,
					  filtering_rule_element *rule,
					  struct pfring_pkthdr *hdr,
					  struct sk_buff *skb,
					  struct parse_buffer **parse_memory)
{
  struct dummy_filter *filter = (struct dummy_filter*)rule->rule.extended_fields.filter_plugin_data;

#ifdef DEBUG
  printk("-> dummy_plugin_plugin_filter_skb(host=0x%08X)\n", filter->src_host);
#endif

  /* Test allocation in order to show how memory placeholder works */
  if((*parse_memory) == NULL) {
    (*parse_memory) = kmalloc(sizeof(struct parse_buffer*), GFP_KERNEL);
    if(*parse_memory) {
      (*parse_memory)->mem_len = 4;
      (*parse_memory)->mem = kmalloc((*parse_memory)->mem_len, GFP_KERNEL);
      printk("-> dummy_plugin_plugin_filter_skb allocated memory\n");
    }
  }

  if(hdr->parsed_pkt.ipv4_src == filter->src_host)
    return(1); /* match */
  else
    return(0);
}

/* ************************************ */

static int dummy_plugin_plugin_get_stats(struct ring_opt *pfr,
					 filtering_rule_element *rule,
					 filtering_hash_bucket  *hash_bucket,
					 u_char* stats_buffer,
					 u_int stats_buffer_len)
{
#ifdef DEBUG
  printk("-> dummy_plugin_plugin_get_stats(len=%d)\n", stats_buffer_len);
#endif

  if(stats_buffer_len >= sizeof(struct simple_stats)) {
    if(rule->plugin_data_ptr == NULL)
      memset(stats_buffer, 0, sizeof(struct simple_stats));
    else
      memcpy(stats_buffer, rule->plugin_data_ptr, sizeof(struct simple_stats));

    return(sizeof(struct simple_stats));
  } else
    return(0);
}

/* ************************************ */

static int __init dummy_plugin_init(void)
{
  printk("Welcome to dummy plugin for PF_RING\n");

  reg.plugin_id                = plugin_id;
  reg.pfring_plugin_filter_skb = dummy_plugin_plugin_filter_skb;
  reg.pfring_plugin_handle_skb = dummy_plugin_plugin_handle_skb;
  reg.pfring_plugin_get_stats  = dummy_plugin_plugin_get_stats;

  snprintf(reg.name, sizeof(reg.name)-1, "dummy");
  snprintf(reg.description, sizeof(reg.description)-1, "This is a dummy plugin");

  register_plugin(&reg);

  printk("Dummy plugin started [id=%d]\n", plugin_id);
  return(0);
}

/* ************************************ */

static void __exit dummy_plugin_exit(void)
{
  printk("Thanks for having used dummy plugin for PF_RING\n");
  unregister_plugin(plugin_id);
}

/* ************************************ */

module_init(dummy_plugin_init);
module_exit(dummy_plugin_exit);
MODULE_LICENSE("GPL");

