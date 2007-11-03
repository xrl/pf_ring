/* ***************************************************************
 *
 * (C) 2007 - Luca Deri <deri@ntop.org>
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
#include <linux/ring.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/textsearch.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0))
#include <net/xfrm.h>
#else
#include <linux/poll.h>
#endif
#include <net/sock.h>
#include <asm/io.h>   /* needed for virt_to_phys() */
#ifdef CONFIG_INET
#include <net/inet_common.h>
#endif
#include <net/ip.h>

struct simple_stats {
  u_int64_t num_pkts, num_bytes;
};

static u_int16_t plugin_id = 1;

/* ************************************ */

static int dummy_plugin_plugin_handle_skb(filtering_rule_element *rule,
					  struct pcap_pkthdr *hdr,
					  struct sk_buff *skb, 
					  int displ)
{
  if(rule->plugin_data_ptr == NULL) {
    rule->plugin_data_ptr = (struct simple_stats*)kmalloc(sizeof(struct simple_stats), GFP_KERNEL);
    if(rule->plugin_data_ptr != NULL)
      memset(rule->plugin_data_ptr, 0, sizeof(struct simple_stats));
  }
  
  if(rule->plugin_data_ptr != NULL) {
    struct simple_stats *stats = (struct simple_stats*)rule->plugin_data_ptr;
    stats->num_pkts++, stats->num_bytes += hdr->len;

    /*
    printk("-> dummy_plugin_plugin_handle_skb [pkts=%u][bytes=%u]\n",
	   (unsigned int)stats->num_pkts,
	   (unsigned int)stats->num_bytes);
    */
  }

  return(0);
}

/* ************************************ */

static int dummy_plugin_plugin_get_stats(filtering_rule_element *rule,
					 u_char* stats_buffer, 
					 u_int stats_buffer_len)
{
  /* printk("-> dummy_plugin_plugin_get_stats(len=%d)\n", stats_buffer_len); */

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
  static struct pfring_plugin_registration reg;
  int rc;

  printk("Welcome to dummy plugin for PF_RING\n");
  
  reg.plugin_id                = plugin_id;
  reg.pfring_plugin_handle_skb = dummy_plugin_plugin_handle_skb;
  reg.pfring_plugin_get_stats  = dummy_plugin_plugin_get_stats;

  rc = do_register_pfring_plugin(&reg);

  printk("Dummy plugin registered [id=%d][rc=%d]\n", plugin_id, rc);
  return(0);
}

/* ************************************ */

static void __exit dummy_plugin_exit(void)
{
  printk("Thanks for using dummy plugin for PF_RING\n");

  do_unregister_pfring_plugin(plugin_id);
}

/* ************************************ */

module_init(dummy_plugin_init);
module_exit(dummy_plugin_exit);
MODULE_LICENSE("GPL");

