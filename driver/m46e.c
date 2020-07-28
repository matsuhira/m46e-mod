/*
 * M46E
 * Stateless Automatic IPv4 over IPv6 Tunneling
 *
 * Authors:
 * Mitarai         <m.mitarai@jp.fujitsu.com>
 *
 * https://sites.google.com/site/m46enet/
 *
 * Copyright (C)2010-2012 FUJITSU LIMITED
 *
 * Changes:
 * 2011.01.05 mitarai The interface determinism reason that transmits ICMP
 *                    is changed.
 * 2011.01.12 mitarai Statistical information is changed to 64bit.
 * 2012.07.26 mitarai Fragment support.
 * 2012.09.14 mitarai M46E-PR support.
 * 2012.12.03 tamagawa M46E MULTI PLANE support
 * 2013.08.22 tamagawa M46E Network NameSpace support
 * 2012.08.23 tamagawa M46E MULTI PLANE delete
 */
#include <linux/module.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/string.h>
#include <linux/icmp.h>
#include <linux/inetdevice.h>
#include <linux/netfilter_bridge.h>

#include <net/net_namespace.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0))
#include <net/ip6_tunnel.h>
#endif
#include <net/addrconf.h>
#include <net/netns/generic.h>
#include <net/icmp.h>
#include <net/route.h>
#include <net/ip.h>
#include <net/arp.h>
#include <net/xfrm.h>

#include "m46e.h"

MODULE_DESCRIPTION("Stateless Automatic IPv4 over IPv6 tunneling device");
MODULE_LICENSE("Proprietary");

static void m46_dev_setup(struct net_device *);

/* M46E Path MTU Discovery */
static int timerstop = 0;
static rwlock_t m46_pmtu_tbl_lock;
static struct timer_list m46_pmtu_timer;
static struct m46_pmtu_entry *m46_pmtu_tbl[M46_PMTU_HASH_SIZE];
static struct m46_pmtu_info m46_pmtu_info;

/* M46E Prefix m46_net */
static struct m46_pr_entry *m46_pr_tbl[M46_PR_HASH_SIZE];
static struct m46_pr_info m46_pr_info;

/* M46E Network NameSpace */
static struct m46_ns_entry *m46_ns_tbl;
static struct m46_ns_info m46_ns_info;
static int m46e_dev_num;

static inline u32 m46_hash(u32 key, u32 mask, u32 size)
{

	return jhash_1word((__force u32)(__be32)(key & inet_make_mask(mask)), mask)
		& (size - 1);
}

static inline void m46_make_ipv6hdr(struct sk_buff *skb, int pay_len)
{
	struct ipv6hdr *ipv6h = ipv6_hdr(skb);

	ipv6h->version = 6;
	ipv6h->priority = 0;
	ipv6h->flow_lbl[0] = 0;
	ipv6h->flow_lbl[1] = 0;
	ipv6h->flow_lbl[2] = 0;
	ipv6h->payload_len = htons(pay_len);
	ipv6h->nexthdr = IPPROTO_IPIP;
	ipv6h->hop_limit = 0x80;
}

static inline int m46_address_convert(struct sk_buff *skb, struct net_device *dev,
				       struct iphdr *ipv4h)
{
	struct ipv6hdr *ipv6h = ipv6_hdr(skb);
	struct inet6_dev *idev = (struct inet6_dev *)dev->ip6_ptr;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35))
	struct inet6_ifaddr *ifaddr;
#else
	struct inet6_ifaddr *ifaddr = (struct inet6_ifaddr *)idev->addr_list;
#endif

#ifdef M46E_AS
	struct tcphdr *tcph;
	struct udphdr *udph;
#endif

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35))
        list_for_each_entry(ifaddr, &idev->addr_list, if_list) {
        	if (ipv6_addr_src_scope(&ifaddr->addr) == IPV6_ADDR_SCOPE_GLOBAL) {
			break;
        	}
        }

        if (!ifaddr) {
		printk(KERN_INFO "m46e: ipv6 address not set.\n");
		return -1;
	}
#else
	if (!ifaddr) {
		printk(KERN_INFO "m46e: ipv6 address not set.\n");
		return -1;
	}

	for (; ifaddr; ifaddr = ifaddr->if_next) {
		if (ipv6_addr_src_scope(&ifaddr->addr) ==
		    IPV6_ADDR_SCOPE_GLOBAL)
			break;
	}

	if (!ifaddr) {
		printk(KERN_INFO "m46e: ipv6 address not set.(global scope)\n");
		return -1;
	}
#endif

        memcpy(&ipv6h->saddr, &ifaddr->addr, sizeof(struct in6_addr));
        memcpy(&ipv6h->daddr, &ifaddr->addr, sizeof(struct in6_addr));

#ifdef M46E_AS
	memcpy(&ipv6h->saddr.s6_addr16[5], &ipv4h->saddr,
	       sizeof(struct in_addr));
	memcpy(&ipv6h->daddr.s6_addr16[5], &ipv4h->daddr,
	       sizeof(struct in_addr));
	switch (ipv4h->protocol) {
	case IPPROTO_TCP:
		tcph = (struct tcphdr *)(ipv4h+1);
		ipv6h->daddr.s6_addr16[7] = tcph->dest;
		break;
	case IPPROTO_UDP:
		udph = (struct udphdr *)(ipv4h+1);
		ipv6h->daddr.s6_addr16[7] = udph->dest;
		break;
	default:
		return -1;
	}
#else
	memcpy(&ipv6h->saddr.s6_addr32[3], &ipv4h->saddr,
	       sizeof(struct in_addr));
	memcpy(&ipv6h->daddr.s6_addr32[3], &ipv4h->daddr,
	       sizeof(struct in_addr));
#endif

	return 0;
}

static struct inet6_ifaddr* m46_ifaddr_search(struct net_device *dev)
{
	struct inet6_dev *idev = (struct inet6_dev *)dev->ip6_ptr;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35))
	struct inet6_ifaddr *ifaddr;
#else
	struct inet6_ifaddr *ifaddr = (struct inet6_ifaddr *)idev->addr_list;
#endif

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35))
	list_for_each_entry(ifaddr, &idev->addr_list, if_list) {
#else
	for (; ifaddr; ifaddr = ifaddr->if_next) {
#endif
        	if (ipv6_addr_src_scope(&ifaddr->addr) == IPV6_ADDR_SCOPE_GLOBAL) {
			return ifaddr;
        	}
        }
	return NULL;
}


static uint32_t m46_get_planeid(struct net_device *dev)
{
	struct inet6_ifaddr *ifaddr;
	uint32_t planeid;

	ifaddr = m46_ifaddr_search(dev);

	if (!ifaddr) {
		printk(KERN_INFO "m46e: ipv6 address not set.(global scope)\n\n");
		return -1;
	}

	planeid = ntohl(ifaddr->addr.s6_addr32[2]);

	return planeid;
}


static inline int m46_address_search(struct sk_buff *skb, struct net_device *dev,
				      struct iphdr *ipv4h)
{
	struct ipv6hdr *ipv6h = ipv6_hdr(skb);
	struct inet6_ifaddr *ifaddr;
	struct m46_pr_entry *pr_ent;
	u32 index;
	u32 i = m46_pr_info.mask_max;
	uint32_t planeid;

	ifaddr = m46_ifaddr_search(dev);

	if (!ifaddr) {
		printk(KERN_INFO "m46e: ipv6 address not set.(global scope)\n");
		return -1;
	}

	planeid = ntohl(ifaddr->addr.s6_addr32[2]);

	/* search destination */
	for (; i >= m46_pr_info.mask_min; i--) {
		index = m46_hash(ipv4h->daddr, i, M46_PR_HASH_SIZE);
		for (pr_ent = m46_pr_tbl[index]; pr_ent != NULL; pr_ent = pr_ent->next) {
			if (i != pr_ent->ipv4mask)
				continue;
			if (planeid != pr_ent->plane_id)
				continue;
			if (!((ipv4h->daddr & inet_make_mask(i)) ^
				(pr_ent->ipv4addr.s_addr & inet_make_mask(pr_ent->ipv4mask)))) {
				ipv6h->saddr = ifaddr->addr;
				ipv6h->saddr.s6_addr32[3] = ipv4h->saddr;
				ipv6h->daddr = pr_ent->m46_addr;
				ipv6h->daddr.s6_addr32[3] = ipv4h->daddr;
				return 0;
			}
		}
	}

	/* default prefix */
	if (m46_pr_info.def_valid_flg) {
		ipv6h->saddr = ifaddr->addr;
		ipv6h->saddr.s6_addr32[3] = ipv4h->saddr;
		ipv6h->daddr = m46_pr_info.m46_def_pre;
		ipv6h->daddr.s6_addr32[2] = ifaddr->addr.s6_addr32[2];
		ipv6h->daddr.s6_addr32[3] = ipv4h->daddr;
		return 0;
	}

	/* not hit */
	return -1;
}

static int m46_pmtu_entry_set(struct m46_pmtu_entry *ent)
{
	struct m46_pmtu_entry *p, *q;
	u32 index;

	p = kmalloc(sizeof(struct m46_pmtu_entry), GFP_ATOMIC);
	if (p == NULL)
		return -ENOMEM;

	memcpy(p, ent, sizeof(struct m46_pmtu_entry));
	write_lock_bh(&m46_pmtu_tbl_lock);
	index = m46_hash(p->v4_host_addr.s_addr, 32, M46_PMTU_HASH_SIZE);
	p->next = NULL;
	if (m46_pmtu_tbl[index] == NULL) {
		/* new */
		m46_pmtu_tbl[index] = p;
	} else {
		/* chain */
		q = m46_pmtu_tbl[index];

		for (;; q = q->next) {
			if ((!(q->v4_host_addr.s_addr ^ p->v4_host_addr.s_addr))
			    && (q->plane_id == p->plane_id)) {
				if (q->pmtu_flags == M46_PMTU_STATIC_ENTRY) {
					q->m46_mtu = p->m46_mtu;
					q->plane_id = p->plane_id;
					kfree(p);
					write_unlock_bh(&m46_pmtu_tbl_lock);
					return 0;
				}
				if (p->pmtu_flags != M46_PMTU_STATIC_ENTRY) {
					/* because same entry, update mtu, expires */
					q->m46_mtu = p->m46_mtu;
					q->expires = get_jiffies_64() + m46_pmtu_info.timeout;
				} else {
					q->expires = 0;
				}
				q->pmtu_flags = p->pmtu_flags;
				kfree(p);
				write_unlock_bh(&m46_pmtu_tbl_lock);

				return 0;
			}
			if (q->next == NULL)
				break;
		}
		q->next = p;
	}

	/* New entry */
	if (p->pmtu_flags != M46_PMTU_STATIC_ENTRY) {
		p->expires = get_jiffies_64() + m46_pmtu_info.timeout;
	}
	m46_pmtu_info.entry_num++;
	write_unlock_bh(&m46_pmtu_tbl_lock);

	return 0;
}

static int m46_pmtu_set(__be32 daddr, __be32 mtu, uint32_t flags, uint32_t plane_id)
{
	struct m46_pmtu_entry ent;

	memset(&ent, 0, sizeof(struct m46_pmtu_entry));
	ent.v4_host_addr.s_addr = daddr;
	ent.m46_mtu = mtu;
	ent.pmtu_flags = flags;
	ent.plane_id = plane_id;

	return m46_pmtu_entry_set(&ent);
}

static int m46_pmtu_entry_free(struct m46_pmtu_entry *ent, u32 index)
{
	struct m46_pmtu_entry **p, *q;
	int err = -ENOENT;

	p = &m46_pmtu_tbl[index];
	q = m46_pmtu_tbl[index];

	for (; q != NULL; p = &q->next, q = q->next) {
		if ((!(ent->v4_host_addr.s_addr ^ q->v4_host_addr.s_addr))
		    && (ent->plane_id == q->plane_id)) {
			*p = q->next;
			kfree(q);
			m46_pmtu_info.entry_num--;
			err = 0;
			break;
		}
	}

	return err;
}

static int m46_pmtu_free(struct m46_pmtu_entry *ent)
{
	u32 index;
	int err;

	index = m46_hash(ent->v4_host_addr.s_addr, 32, M46_PMTU_HASH_SIZE);

	write_lock_bh(&m46_pmtu_tbl_lock);
	err = m46_pmtu_entry_free(ent, index);
	write_unlock_bh(&m46_pmtu_tbl_lock);

	return err;
}

static int m46_pmtu_entry_get_all(int *p)
{
	struct m46_pmtu_entry *ent, *q;
	int i;

	q = (struct m46_pmtu_entry *)p;

	read_lock_bh(&m46_pmtu_tbl_lock);
	for (i = 0; i < M46_PMTU_HASH_SIZE; i++) {
		ent = m46_pmtu_tbl[i];
		for (; ent != NULL; ent = ent->next, q++) {
			if (copy_to_user(q, ent, sizeof(struct m46_pmtu_entry))) {
				read_unlock_bh(&m46_pmtu_tbl_lock);
				return -EFAULT;
			}
		}
	}
	read_unlock_bh(&m46_pmtu_tbl_lock);
	return 0;
}

static void m46_pmtu_entry_free_all(void)
{
	struct m46_pmtu_entry *p, *q;
	int i;

	write_lock_bh(&m46_pmtu_tbl_lock);
	for (i = 0; i < M46_PMTU_HASH_SIZE; i++) {
		for (p = m46_pmtu_tbl[i]; p != NULL; p = q) {
			q = p->next;
			kfree(p);
			m46_pmtu_info.entry_num--;
		}
	}
	write_unlock_bh(&m46_pmtu_tbl_lock);
}

static void m46_pmtu_timer_func(unsigned long data)
{
	struct m46_pmtu_entry *p, *q;
	int i;

	if (timerstop == 1)
		return;

	write_lock_bh(&m46_pmtu_tbl_lock);
	for (i = 0; i < M46_PMTU_HASH_SIZE; i++) {
		for (p = m46_pmtu_tbl[i]; p != NULL; p = q) {
			q = p->next;
			if (p->pmtu_flags == M46_PMTU_STATIC_ENTRY)
				continue;
			if (!time_after_eq64(p->expires, get_jiffies_64())) {
				if (m46_pmtu_entry_free(p, i) < 0)
					printk(KERN_ERR "m46e: pmtu table free error.\n");
			}
		}
	}
	write_unlock_bh(&m46_pmtu_tbl_lock);

	m46_pmtu_timer.entry.prev = NULL;
	m46_pmtu_timer.entry.next = NULL;
	m46_pmtu_timer.expires    = jiffies + M46_PMTU_CYCLE_TIME;
	m46_pmtu_timer.data       = 0;
	m46_pmtu_timer.function   = m46_pmtu_timer_func;
	add_timer(&m46_pmtu_timer);
}

static int m46_frag_options(struct sk_buff * skb){
	unsigned char *optptr = skb_network_header(skb) + sizeof(struct iphdr);
	struct ip_options *ip_opt = &(IPCB(skb)->opt);
	int opt_list_len = ip_opt->optlen;
	int next_optlen = 0;
	
	ip_opt->ts = 0;
	ip_opt->rr = 0;
	ip_opt->rr_needaddr = 0;
	ip_opt->ts_needaddr = 0;
	ip_opt->ts_needtime = 0;
	
	/* set IPOPT_NOOP to all options not allowed to copy on fragmentation */
	for (; opt_list_len > 0; opt_list_len -= next_optlen) {
		if (*optptr == IPOPT_END) {
			/* End of Option list */
			break;
		}
		if (*optptr == IPOPT_NOOP){
			/* No Operation. (this option is used between options.
			 * for example to align option to 32bit boundary) */
			next_optlen = 1;
			optptr++;
			continue;
		}
		
		/* Length of option is in 2nd Byte of option */
		next_optlen = optptr[1];
		
		if (next_optlen < 2 || next_optlen > opt_list_len) {
			printk(KERN_INFO "m46e: unexpected option length.\n");
			return -1;
		}
		if (!IPOPT_COPIED(*optptr)) {
			memset(optptr, IPOPT_NOOP, next_optlen);
		}
		optptr += next_optlen;
	}
	
	return 0;
}

static int m46_encap2(struct sk_buff *skb, unsigned int len, struct net_device *dev)
{
	struct iphdr *iph = ip_hdr(skb);
	struct m46_tbl *t = netdev_priv(dev);
	struct net_device_stats *stats = &t->dev->stats;
	unsigned int max_headroom;
	int err;

	max_headroom = LL_RESERVED_SPACE(dev) + sizeof(struct ipv6hdr);

	if (skb_headroom(skb) < max_headroom || skb_shared(skb) ||
	    (skb_cloned(skb) && !skb_clone_writable(skb, 0))) {
		struct sk_buff *new_skb;
		if (!(new_skb = skb_realloc_headroom(skb, max_headroom))) {
			/* printk(KERN_INFO "m46e: skb_realloc_headroom error, encap2\n"); */
			return -1;
		}
		if (skb->sk)
			skb_set_owner_w(new_skb, skb->sk);
		kfree_skb(skb);
		skb = new_skb;
	}

	skb_push(skb, sizeof(struct ipv6hdr));
	skb_set_transport_header(skb, sizeof(struct ipv6hdr));
	skb_reset_network_header(skb);
	skb_set_mac_header(skb, -ETH_HLEN);
	skb_reset_mac_header(skb);

	m46_make_ipv6hdr(skb, len+20);

	if (m46_address_search(skb, dev, iph) < 0)
		return -1;

	skb->protocol = htons(ETH_P_IPV6);
	skb->pkt_type = PACKET_HOST;
	skb_dst_drop(skb);
	nf_reset(skb);

	err = netif_rx_ni(skb);
	if (err) {
		t->encap_tx_errors++;
		/* printk(KERN_INFO "m46e: netif_rx_ni() error, encap2. err = %d\n", err); */
		return -1;
	}

	stats->tx_packets++;
	stats->tx_bytes += len;
	t->encap_cnt++;
	return 0;
}

static int m46_fragment(struct sk_buff *skb, struct net_device *dev, u32 m46_mtu)
{
	struct iphdr *ipv4h;
	struct rtable *rt = skb_rtable(skb);
	struct sk_buff *new_skb;
	struct m46_tbl *t = netdev_priv(dev);
	unsigned int ipv4h_len, dgram_mtu, dgram_len, len, rsv_sp, pad;
	int next, offset;
	__be16 ipmf;
	int err = 0;

	/* 
	 * If "Dont Fragment" flag is ON and FORCE_FRAGMENT is OFF, send ICMP error
	 * (if FORCE_FRAGMENT is ON, turn off DF flag and do fragment.)
	 */
	ipv4h = ip_hdr(skb);
	if ((unlikely(ipv4h->frag_off & htons(IP_DF)))
			&& (m46_pmtu_info.force_fragment == FORCE_FRAGMENT_OFF)) {
		t->encap_send_icmp++;
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, htonl(m46_mtu));
		kfree_skb(skb);
		return 0;
	} else {
		ipv4h->frag_off &= ~htons(IP_DF);
	}
	IPCB(skb)->flags |= IPSKB_FRAG_COMPLETE;

	/* ipv4 header is included in all fragment, so length of datagram in one
	 * fragment will be (m46_mtu) - (ipv4 header length).
	 * (ipv6 heder length is already considered in m46_mtu)
	 */
	ipv4h_len = ipv4h->ihl * 4;
	dgram_mtu = m46_mtu - ipv4h_len;
	
	/* reserve space for head room */
	pad = nf_bridge_pad(skb);	
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35))
	rsv_sp = LL_RESERVED_SPACE_EXTRA(rt->dst.dev, pad);
#else
	rsv_sp = LL_RESERVED_SPACE_EXTRA(rt->u.dst.dev, pad);
#endif

#if	(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,34))
#if defined(CONFIG_BRIDGE_NETFILTER)
	if (skb->nf_bridge)
		dgram_mtu -= nf_bridge_mtu_reduction(skb);
#endif
#else
	dgram_mtu -= pad;
#endif
	
	/* add space for ipv6 header to head room */
	rsv_sp += sizeof(struct ipv6hdr);
	
	/* received packet might be fragmented already.
	 * so get original fragment offset and MF("More Fragments") flag,
	 * and start from that offset.
	 */
	offset = (ntohs(ipv4h->frag_off) & IP_OFFSET);
	ipmf = ipv4h->frag_off & htons(IP_MF);

	/* set starting position of copying original ip datagram(next).
	 * (data includes ipv4 header, so start copy after ipv4 header len)
	 * calc length of original data needed to be fragmented(dgram_len), 
	 * and continue till all data is fragmented.
	 */
	next = ipv4h_len;
	for (dgram_len = skb->len - ipv4h_len; dgram_len > 0; dgram_len -= len) {
		if (dgram_len > dgram_mtu){
			/* start point of each fragmented data must be aligned to 
	 		 * 8byte boundary. (because, offset is 8byte unit)
	 		 */
			len = (dgram_mtu & ~7);
		} else {
			len = dgram_len;
		}
		
		new_skb = alloc_skb(len+ipv4h_len+rsv_sp, GFP_ATOMIC);
		if (new_skb == NULL) {
			/* printk(KERN_INFO "m46e: no memory for new fragment\n"); */
			err = -ENOMEM;
			/* kfree_skb(skb); */
			return -1;
		}

		/* set data to new packet */
		new_skb->protocol = skb->protocol;
		new_skb->pkt_type = skb->pkt_type;
		new_skb->priority = skb->priority;
		new_skb->dev = skb->dev;
		new_skb->mark = skb->mark;
		new_skb->skb_iif = skb->skb_iif;
		skb_dst_drop(new_skb);
		skb_dst_set(new_skb, dst_clone(skb_dst(skb)));
		IPCB(new_skb)->flags = IPCB(skb)->flags;
		nf_copy(new_skb, skb);
		skb_copy_secmark(new_skb, skb);
#if defined(CONFIG_IP_VS) || defined(CONFIG_IP_VS_MODULE)
		new_skb->ipvs_property = skb->ipvs_property;
#endif
#if defined(CONFIG_NETFILTER_XT_TARGET_TRACE) || \
    defined(CONFIG_NETFILTER_XT_TARGET_TRACE_MODULE)
		new_skb->nf_trace = skb->nf_trace;
#endif
#ifdef CONFIG_NET_SCHED
		new_skb->tc_index = skb->tc_index;
#endif
		if (skb->sk)
			skb_set_owner_w(new_skb, skb->sk);
		
		/* set pointers */
		skb_reserve(new_skb, rsv_sp);
		skb_put(new_skb, len + ipv4h_len);
		skb_reset_network_header(new_skb);
		new_skb->transport_header = new_skb->network_header + ipv4h_len;
		
		/* copy ipv4 header to new packet */
		err = skb_copy_bits(skb, 0, skb_network_header(new_skb), ipv4h_len);
		if (err) {
			printk(KERN_INFO "m46e: failed to copy bits at fragment.\n");
			kfree_skb(new_skb);
			return -1;
		}
		
		/* After copying header(and options) to first segment, 
		 * set NOOP to options that shuld not be copied on fragmentation.
		 * (so they will not be copied after first segment)
		 */
		if (offset == 0) {
			err = m46_frag_options(skb);
			if (err) {
				kfree_skb(new_skb);
				return -1;
			}
		}
		
		/* copy "len" size IP datagram from original packet to new packet
		 * skb_copy_bits() can copy data from paged data too.
		 * (dont need to consider about frag_list)
		 */
		err = skb_copy_bits(skb, next, skb_transport_header(new_skb), len);
		if (err) {
			printk(KERN_INFO "m46e: failed to copy bits at fragment.\n");
			kfree_skb(new_skb);
			return -1;
		}
		next += len;
		
		/* set frag_offset to new packet */
		ipv4h = ip_hdr(new_skb);
		ipv4h->frag_off = htons(offset);

		/* If this is not last fragment, set MF("More Fragments") flag ON. */
		if ((dgram_len - len) > 0 || ipmf)
			ipv4h->frag_off |= htons(IP_MF);

		/* update offset for next frag. 
		 * (offset = ((bytes from top of original data)/ 8))
		 */
		offset += (len / 8);

		/* put new packet to sending queue. */
		ipv4h->tot_len = htons(len + ipv4h_len);
		ip_send_check(ipv4h);
		
		err = m46_encap2(new_skb, len, dev);
		if (err) {
			/* printk(KERN_INFO "m46e: fragment packet tx error. err = %d\n", err); */
			/* kfree_skb(new_skb); */
			/* kfree_skb(skb); */
			return -1;
		}
		t->encap_fragment_tx_packet++;
	}
	kfree_skb(skb);
	return 0;
}

static u32 m46_get_mtu(struct sk_buff *skb, struct net_device *dev)
{
	struct iphdr *ipv4h = ip_hdr(skb);
	struct m46_pmtu_entry *ent;
	u32 index, mtu = dev->mtu;
	uint32_t planeid;

	planeid = m46_get_planeid(dev);

	read_lock_bh(&m46_pmtu_tbl_lock);
	index = m46_hash(ipv4h->daddr, 32, M46_PMTU_HASH_SIZE);
	for (ent = m46_pmtu_tbl[index]; ent != NULL; ent = ent->next) {
		if (!(ipv4h->daddr ^ ent->v4_host_addr.s_addr)) {
			if (ent->plane_id == planeid) {
				mtu = ent->m46_mtu;
				break;
			}
		}
	}

	read_unlock_bh(&m46_pmtu_tbl_lock);
	return mtu - sizeof(struct ipv6hdr);
}

static inline int m46_encap(struct sk_buff *skb, struct net_device *dev)
{
	struct iphdr *ipv4h = ip_hdr(skb);
	struct net_device *ndev;
	struct m46_tbl *t = netdev_priv(dev);
	struct net_device_stats *stats = &t->dev->stats;
	int len = skb->len;
	int err;
	u32 m46_mtu;

	DBGp("%s() start.", __func__);

	m46_mtu = m46_get_mtu(skb, dev);
	if (len > m46_mtu) {
		struct rtable *rt;
		struct net_device *p_dev;
		unsigned save_rt_flags;

		for_each_netdev(dev_net(dev), ndev) {
			skb->dev = ndev;
			err = ip_route_input(skb, ipv4h->daddr, ipv4h->saddr,
					     ipv4h->tos, skb->dev);
			if (!err) {
				rt = skb_rtable(skb);
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35))
				p_dev = rt->dst.dev;
#else
				p_dev = rt->u.dst.dev;
#endif
				if (m46_fragment(skb, p_dev, m46_mtu)) {
					t->encap_fragment_tx_error++;
					/* printk(KERN_INFO "m46e: m46_fragment error.\n"); */
					/* skb already free */
					return 0;
				}
				return 0;
			}
		}

		/* self packet */
		for_each_netdev(dev_net(dev), ndev) {
			err = strncmp(ndev->name, "m46e", 5);
			if (err) {
				continue;
			}
			skb->dev = ndev;
			/* change saddr and daddr */
			err = ip_route_input(skb, ipv4h->saddr, ipv4h->daddr,
					     ipv4h->tos, skb->dev);
			if (!err) {
				rt = skb_rtable(skb);
				save_rt_flags = rt->rt_flags;
				rt->rt_flags &= ~RTCF_LOCAL;
				if (m46_fragment(skb, ndev, m46_mtu)) {
					rt->rt_flags = save_rt_flags;
					t->encap_fragment_tx_error++;
					/* printk(KERN_INFO "m46e: m46_fragment error2.\n"); */
					return -1;
				}
				rt->rt_flags = save_rt_flags;
				return 0;
			}
		}
		t->encap_send_icmp_no_route++;
		return -1;
	}

	if (skb_headroom(skb) < sizeof(struct ipv6hdr)) {
		struct sk_buff *new_skb;
		printk(KERN_INFO "m46e: headroom not enough.\n");
		if (!(new_skb = skb_realloc_headroom(skb, sizeof(struct ipv6hdr)))) {
			printk(KERN_INFO "m46e: skb_realloc_headroom error.\n");
			return -1;
		}
		if (skb->sk)
			skb_set_owner_w(new_skb, skb->sk);
			kfree_skb(skb);
			skb = new_skb;
	}

	skb_push(skb, sizeof(struct ipv6hdr));
	skb_set_transport_header(skb, sizeof(struct ipv6hdr));
	skb_reset_network_header(skb);
	skb_set_mac_header(skb, -ETH_HLEN);

	m46_make_ipv6hdr(skb, len);

#ifndef M46E_AS
	if (m46_address_search(skb, dev, ipv4h) < 0)
		return -1;
#else
	if (m46_address_convert(skb, dev, ipv4h) < 0)
		return -1;
#endif
	skb->protocol = htons(ETH_P_IPV6);
	skb->pkt_type = PACKET_HOST;
	skb_dst_drop(skb);
	nf_reset(skb);

	m46_encap_statistics_proto(skb, t);

	len = skb->len;
	err = netif_rx_ni(skb);
	if (err) {
		t->encap_tx_errors++;
		/* printk(KERN_INFO "m46e: netif_rx_ni() error. err = %d\n", err); */
		/* skb already free */
		return 0;
	}

	stats->tx_packets++;
	stats->tx_bytes += len;
	t->encap_cnt++;
	return 0;
}

static int m46_decap_send(struct sk_buff *skb, struct net_device *dev)
{
	struct m46_tbl *t = netdev_priv(dev);
	struct net_device_stats *stats = &t->dev->stats;
	uint32_t len;

	len = skb->len;
	m46_decap_statistics_proto(skb, t);

	if (netif_rx_ni(skb) == NET_XMIT_DROP) {
		stats->tx_fifo_errors++;
		stats->tx_dropped++;
		return 0; /* skb already free */
	}

	stats->tx_bytes += len;
	return 0;
}

static int m46_decap_ipip(struct sk_buff *skb, struct net_device *dev)
{
	secpath_reset(skb);
	skb_pull(skb, sizeof(struct ipv6hdr));
	skb_set_transport_header(skb, -(int)sizeof(struct ipv6hdr));
	skb_reset_network_header(skb);
	skb_set_mac_header(skb, -ETH_HLEN);

	skb->protocol = htons(ETH_P_IP);
	skb->pkt_type = PACKET_HOST;
	skb_dst_drop(skb);
	nf_reset(skb);

	return m46_decap_send(skb, dev);
}

static int m46_decap_icmp(struct sk_buff *skb, struct net_device *dev)
{
	struct ipv6hdr *ipv6h = ipv6_hdr(skb);
	struct icmp6hdr *icmp6h = icmp6_hdr(skb);
	struct iphdr *ipv4h;
	struct m46_tbl *t = netdev_priv(dev);
	uint32_t planeid;

	planeid = ntohl(ipv6h->daddr.s6_addr32[2]);

	/* ICMP for IPv6 */
	if (icmp6h->icmp6_type != ICMPV6_PKT_TOOBIG) {
		t->decap_next_hdr_type_errors++;
		return -1;
	}
	/* IPv4 in IPv6 check */
	if (ntohs(ipv6h->payload_len) <
	    (sizeof(struct ipv6hdr) + sizeof(struct iphdr))) {
		t->decap_payload_len_errors++;
		return -1;
	}
	/* update IPv6 header */
	ipv6h = (struct ipv6hdr *)(icmp6h + 1);
	if (ipv6h->nexthdr != IPPROTO_IPIP) {
		t->decap_icmpv6_proto_errors++;
		return -1;
	}
	ipv4h = (struct iphdr *)(ipv6h + 1);
	if (m46_pmtu_set(ipv4h->daddr, ntohl(icmp6h->icmp6_mtu), 0, planeid) < 0) {
		t->decap_pmtu_set_errors++;
		return -1;
	}
	kfree_skb(skb);
	return 0;
}

static inline int m46_decap(struct sk_buff *skb, struct net_device *dev)
{
	struct ipv6hdr *ipv6h = ipv6_hdr(skb);
	struct m46_tbl *t = netdev_priv(dev);
	struct net_device_stats *stats = &t->dev->stats;
	uint32_t planeid;
	int err;

	DBGp("%s() start.", __func__);

	planeid = htonl(ipv6h->daddr.s6_addr32[2]);

	if (ipv6h->nexthdr == IPPROTO_IPIP) {

		err = m46_decap_ipip(skb, dev);
		if (err < 0) {
			t->decap_tx_errors++;
			return err;
		}
		stats->tx_packets++;
		t->decap_cnt++;
	} else if (ipv6h->nexthdr == NEXTHDR_ICMP) {

		err = m46_decap_icmp(skb, dev);
		if (err < 0)
			return err;
	} else {
		t->decap_next_hdr_errors++;
		return -1;
	}
	return 0;
}

static netdev_tx_t m46_rcv(struct sk_buff *skb, struct net_device *dev)
{
	struct m46_tbl *t = netdev_priv(dev);
	struct net_device_stats *stats = &t->dev->stats;
	int ret;

	stats->rx_packets++;
	stats->rx_bytes += skb->len;

	switch (skb->protocol) {
	case htons(ETH_P_IP):
		ret = m46_encap(skb, dev);
		break;
	case htons(ETH_P_IPV6):
		ret = m46_decap(skb, dev);
		break;
	default:
		goto err_proc;
	}

	if (ret < 0)
		goto err_proc;

	return 0;

err_proc:
	kfree_skb(skb);
	return 0;
}


static int m46_pr_entry_set(struct m46_pr_entry *spe)
{
	struct m46_pr_entry *p, *q;
	u32 index;

	p = kmalloc(sizeof(struct m46_pr_entry), GFP_KERNEL);
	if (p == NULL)
		return -ENOMEM;

	memcpy(p, spe, sizeof(struct m46_pr_entry));
	index = m46_hash(p->ipv4addr.s_addr, p->ipv4mask, M46_PR_HASH_SIZE);
	p->next = NULL;
	if (m46_pr_tbl[index] == NULL) {
		/* new */
		m46_pr_tbl[index] = p;
	} else {
		/* chain */
		q = m46_pr_tbl[index];
		for (; q->next != NULL; q = q->next)
			;
		q->next = p;
	}
	if (p->ipv4mask > m46_pr_info.mask_max)
		m46_pr_info.mask_max = p->ipv4mask;
	if (p->ipv4mask < m46_pr_info.mask_min)
		m46_pr_info.mask_min = p->ipv4mask;
	m46_pr_info.entry_num++;
	return 0;
}

static int m46_pr_entry_free(struct m46_pr_entry *spe)
{
	struct m46_pr_entry **p, *q;
	u32 index;
	int err = -ENOENT, i = 0;

	index = m46_hash(spe->ipv4addr.s_addr, spe->ipv4mask, M46_PR_HASH_SIZE);

	p = &m46_pr_tbl[index];
	q = m46_pr_tbl[index];
	if (!p)
		return err;

	for (; q != NULL; p = &q->next, q = q->next, i++) {
		if (spe->ipv4mask != q->ipv4mask)
			continue;
		if (spe->plane_id != q->plane_id)
			continue;
		if (!((spe->ipv4addr.s_addr & inet_make_mask(spe->ipv4mask)) ^
		      (q->ipv4addr.s_addr & inet_make_mask(q->ipv4mask)))) {
			*p = q->next;
			kfree(q);
			m46_pr_info.entry_num--;
			return 0;
		}
	}

	return err;
}

static int m46_pr_entry_get_all(int *p)
{
	struct m46_pr_entry *ent, *q;
	int i;

	q = (struct m46_pr_entry *)p;

	for (i = 0; i < M46_PR_HASH_SIZE; i++) {
		ent = m46_pr_tbl[i];
		for (; ent != NULL; ent = ent->next, q++) {
			if (copy_to_user(q, ent, sizeof(struct m46_pr_entry)))
				return -EFAULT;
		}
	}
	return 0;
}

static void m46_pr_entry_free_all(void)
{
	struct m46_pr_entry *p, *q;
	int i, j;

	for (i = 0; i < M46_PR_HASH_SIZE; i++) {
		for (p = m46_pr_tbl[i], j = 0; p != NULL; j++) {
			q = p->next;
			kfree(p);
			m46_pr_info.entry_num--;
			p = q;
		}
	}
}

static int m46_alloc_dev(struct m46_ns_entry *sne)
{
	int err;
	char str[IFNAMSIZ];

	memset(str, 0, sizeof(str));

	sprintf(str, "m46e%d", m46e_dev_num++);
	strcpy(sne->m46_name, str);

	sne->m46_dev = alloc_netdev(sizeof(struct m46_tbl),  sne->m46_name,
			m46_dev_setup);

	if (!sne->m46_dev)
		return -ENOMEM;

	dev_hold(sne->m46_dev);

	if ((err = register_netdevice(sne->m46_dev))) {
		free_netdev(sne->m46_dev);
		return err;
	}

	return 0;
}

static int m46_ns_entry_set(struct m46_ns_entry *sne, int *i)
{
	struct m46_ns_entry *p, *q, *tmp, *ent;
	int err;

	/* exist same namespace. */
	for (tmp = m46_ns_tbl; tmp != NULL; tmp = tmp->next) {
		if (strcmp(tmp->namespace_name, sne->namespace_name) == 0)
			return -EBUSY;
	}

	p = kmalloc(sizeof(struct m46_ns_entry), GFP_KERNEL);
	if (p == NULL)
		return -ENOMEM;

	memcpy(p, sne, sizeof(struct m46_ns_entry));

	err = m46_alloc_dev(p);
	if (err) {
		printk(KERN_ERR "m46_ioctl() m46_alloc_dev error.\n");
		return err;
	}

	p->next = NULL;
	if (m46_ns_tbl == NULL) {
		/* new */
		m46_ns_tbl = p;
	} else {
		/* chain */
		for (q = m46_ns_tbl; q->next != NULL; q = q->next);
		q->next = p;
		p->prev = q;
	}

	m46_ns_info.entry_num++;

	ent = (struct m46_ns_entry *)i;
	if (copy_to_user(ent, p, sizeof(struct m46_ns_entry)))
		return -EFAULT;

	return 0;
}

static int m46_ns_entry_update(struct m46_ns_entry *sne)
{
	struct m46_ns_entry *p;

	for (p = m46_ns_tbl; p != NULL; p = p->next) {
		if (strcmp(p->namespace_name, sne->namespace_name) == 0) {
			memcpy(p, sne, sizeof(struct m46_ns_entry));
			return 0;
		}
	}

	printk(KERN_ERR "can't update entry.\n");
	return -EFAULT;
}

static void m46_ns_entry_free_all(void)
{
	struct m46_ns_entry *p, *q;

	for (p = m46_ns_tbl; p != NULL; ) {
		q = p->next;
		dev_put(p->m46_dev);
		unregister_netdev(p->m46_dev);
		memset(p, 0, sizeof(struct m46_ns_entry));
		kfree(p);
		p = NULL;
		p = q;
	}
	m46_ns_tbl = NULL;
}

static int m46_ns_entry_free(struct m46_ns_entry *sne)
{
	struct m46_ns_entry *p;

	p = m46_ns_tbl;
	if (!p)
		return -ENOENT;

	for (; p != NULL; p = p->next) {
		if (strcmp(p->namespace_name, sne->namespace_name) == 0) {
			if(p->prev == NULL) {
				if (p->next != NULL) {
					m46_ns_tbl = p->next;
					p->next->prev = NULL;
				} else {
					m46_ns_tbl = NULL;
				}
			} else {
				if (p->next != NULL) {
					p->prev->next = p->next;
					p->next->prev = p->prev;
				} else {
					p->prev->next = NULL;
				}
			}
			dev_put(p->m46_dev);
			unregister_netdevice(p->m46_dev);
			memset(p, 0, sizeof(struct m46_ns_entry));
			kfree(p);
			p = NULL;
			m46_ns_info.entry_num--;
			return 0;
		}
	}

	return -ENOENT;
}

static int m46_ns_get_entry(struct m46_ns_entry *sne, int *i)
{
	struct m46_ns_entry *p, *q;

	q = (struct m46_ns_entry *)i;

	for (p = m46_ns_tbl; p != NULL; p = p->next) {
		if (strcmp(p->namespace_name, sne->namespace_name) == 0) {
			if (copy_to_user(q, p, sizeof(struct m46_ns_entry)))
				return -EFAULT;
			return 0;
		}
	}

	return -EFAULT;
}

static int m46_ns_get_entry_all(int *i)
{
	struct m46_ns_entry *p, *q;

	q = (struct m46_ns_entry *)i;

	for (p = m46_ns_tbl; p != NULL; p = p->next, q++) {
		if (copy_to_user(q, p, sizeof(struct m46_ns_entry)))
			return -EFAULT;
	}

	return 0;
}

static int m46_ioctl_pr(struct ifreq *ifr)
{
	struct m46_pr_entry spe;
	struct m46_pr_info spi;
	uint32_t type;
	int err = 0;

	if (copy_from_user(&type, ifr->ifr_ifru.ifru_data, sizeof(uint32_t)))
		return -EFAULT;

	switch (type) {
	case M46_SETPRENTRY:
		if (copy_from_user(&spe, ifr->ifr_ifru.ifru_data,
				   sizeof(struct m46_pr_entry)))
			return -EFAULT;
		err = m46_pr_entry_set(&spe);
		break;
	case M46_FREEPRENTRY:
		if (copy_from_user(&spe, ifr->ifr_ifru.ifru_data,
				   sizeof(struct m46_pr_entry)))
			return -EFAULT;
		err = m46_pr_entry_free(&spe);
		break;
	case M46_GETPRENTRYNUM:
		if (copy_to_user(ifr->ifr_ifru.ifru_data, &m46_pr_info,
				 sizeof(struct m46_pr_info)))
			return -EFAULT;
		break;
	case M46_GETPRENTRY:
		err = m46_pr_entry_get_all(ifr->ifr_ifru.ifru_data);
		break;
	case M46_SETDEFPREFIX:
		if (copy_from_user(&spi, ifr->ifr_ifru.ifru_data,
				   sizeof(struct m46_pr_info)))
			return -EFAULT;
		m46_pr_info.def_valid_flg = 1;
		memcpy(&m46_pr_info.m46_def_pre, &spi.m46_def_pre,
		       sizeof(spi.m46_def_pre));
		break;
	case M46_FREEDEFPREFIX:
		if (copy_from_user(&spi, ifr->ifr_ifru.ifru_data,
				   sizeof(struct m46_pr_info)))
			return -EFAULT;
		m46_pr_info.def_valid_flg = 0;
		ipv6_addr_set(&m46_pr_info.m46_def_pre, 0, 0, 0, 0);
		break;
	default:
		err = -EINVAL;
		printk(KERN_ERR "m46_ioctl() unknown command type(%d)\n", type);
		break;
	}
	return err;
}

static int m46_ioctl_pmtu(struct ifreq *ifr)
{
	struct m46_pmtu_info pmtu_info;
	struct m46_pmtu_entry pmtu_ent;
	uint32_t type;
	int err = 0;

	if (copy_from_user(&type, ifr->ifr_ifru.ifru_data, sizeof(uint32_t)))
		return -EFAULT;

	switch (type) {
	case M46_GETPMTUENTRYNUM:
		m46_pmtu_info.now = get_jiffies_64();
		if (copy_to_user(ifr->ifr_ifru.ifru_data, &m46_pmtu_info,
				 sizeof(m46_pmtu_info)))
			return -EFAULT;
		break;
	case M46_GETPMTUENTRY:
		err = m46_pmtu_entry_get_all(ifr->ifr_ifru.ifru_data);
		break;
	case M46_SETPMTUENTRY:
		if (copy_from_user(&pmtu_ent, ifr->ifr_ifru.ifru_data,
				   sizeof(struct m46_pmtu_entry)))
			return -EFAULT;
		err = m46_pmtu_entry_set(&pmtu_ent);
		break;
	case M46_FREEPMTUENTRY:
		if (copy_from_user(&pmtu_ent, ifr->ifr_ifru.ifru_data,
				   sizeof(struct m46_pmtu_entry)))
			return -EFAULT;
		err = m46_pmtu_free(&pmtu_ent);
		break;
	case M46_SETPMTUTIME:
		if (copy_from_user(&pmtu_info, ifr->ifr_ifru.ifru_data,
				   sizeof(struct m46_pmtu_info)))
			return -EFAULT;
		m46_pmtu_info.timeout = pmtu_info.timeout * HZ;
		break;
	case M46_SETPMTUINFO:
		if (copy_from_user(&pmtu_info, ifr->ifr_ifru.ifru_data,
				   sizeof(struct m46_pmtu_info)))
			return -EFAULT;
		m46_pmtu_info.force_fragment = pmtu_info.force_fragment;
		break;
	default:
		err = -EINVAL;
		printk(KERN_ERR "m46_ioctl_pmtu() unknown command type(%d)\n", type);
		break;
	}
	return err;
}

static int m46_ioctl_ns(struct ifreq *ifr)
{
	struct m46_ns_entry sne;
	uint32_t type;
	int err = 0;

	if (copy_from_user(&type, ifr->ifr_ifru.ifru_data, sizeof(uint32_t)))
		return -EFAULT;

	switch (type) {
	case M46_ADDDEV:
		if (copy_from_user(&sne, ifr->ifr_ifru.ifru_data,
				   sizeof(struct m46_ns_entry)))
			return -EFAULT;
		err = m46_ns_entry_set(&sne, ifr->ifr_ifru.ifru_data);
		break;
	case M46_UPDATENSENTRY:
		if (copy_from_user(&sne, ifr->ifr_ifru.ifru_data,
				   sizeof(struct m46_ns_entry)))
			return -EFAULT;
		err = m46_ns_entry_update(&sne);
		break;
	case M46_FREENSENTRY:
		if (copy_from_user(&sne, ifr->ifr_ifru.ifru_data,
				   sizeof(struct m46_ns_entry)))
			return -EFAULT;
		err = m46_ns_entry_free(&sne);
		break;
	case M46_GETNSENTRY:
		if (copy_from_user(&sne, ifr->ifr_ifru.ifru_data,
				   sizeof(struct m46_ns_entry)))
			return -EFAULT;
		err = m46_ns_get_entry(&sne, ifr->ifr_ifru.ifru_data);
		break;
	case M46_GETNSENTRYNUM:
		if (copy_to_user(ifr->ifr_ifru.ifru_data, &m46_ns_info,
						 sizeof(m46_ns_info)))
					return -EFAULT;
		break;
	case M46_GETNSENTRYALL:
		err = m46_ns_get_entry_all(ifr->ifr_ifru.ifru_data);
		break;
	case M46_UPDATENSINFO:
		if (copy_from_user(&m46_ns_info, ifr->ifr_ifru.ifru_data,
				   sizeof(struct m46_ns_info)))
			return -EFAULT;
		break;
	default:
		err = -EINVAL;
		printk(KERN_ERR "m46_ioctl() unknown command type(%d)\n", type);
		break;
	}
	return err;
}


static int m46_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	struct m46_tbl *t = netdev_priv(dev);
	int err = 0;

	switch (cmd) {
	case M46_GETSTATISTICS:
		if (copy_to_user(ifr->ifr_ifru.ifru_data, t, sizeof(struct m46_tbl)))
			return -EFAULT;
		break;
	case M46_PR:
		err = m46_ioctl_pr(ifr);
		break;
	case M46_PMTU:
		err = m46_ioctl_pmtu(ifr);
		break;
	case M46_NS:
		err = m46_ioctl_ns(ifr);
		break;
	default:
		err = -EINVAL;
	}

	return err;
}

static int m46_change_mtu(struct net_device *dev, int new_mtu)
{
	if (new_mtu < IPV6_MIN_MTU)
		return -EINVAL;
	dev->mtu = new_mtu;
	return 0;
}

static const struct net_device_ops m46_netdev_ops = {
/*	.ndo_uninit = m46_dev_uninit, */
	.ndo_start_xmit = m46_rcv,
	.ndo_do_ioctl = m46_ioctl,
	.ndo_change_mtu = m46_change_mtu,
};

/**
 * m46_dev_setup - setup virtual device
 *   @dev: virtual device associated
 *
 * Description:
 *   Initialize function pointers and device parameters
 **/
static void m46_dev_setup(struct net_device *dev)
{
	struct m46_tbl *t = netdev_priv(dev);

	t->dev = dev;

	dev->netdev_ops = &m46_netdev_ops;
	dev->destructor = free_netdev;

	dev->type = ARPHRD_NONE;
	//dev->type = ARPHRD_ETHER;
	dev->hard_header_len = LL_MAX_HEADER + sizeof(struct ipv6hdr);
	dev->mtu = ETH_DATA_LEN;
	dev->flags |= IFF_NOARP;
	dev->addr_len = sizeof(struct in6_addr);
	dev->features |= NETIF_F_NETNS_LOCAL;
}

static void init_m46_pmtu(void)
{

	memset(m46_pmtu_tbl, 0, sizeof(m46_pmtu_tbl));
	memset(&m46_pmtu_info, 0, sizeof(m46_pmtu_info));
	rwlock_init(&m46_pmtu_tbl_lock);
	m46_pmtu_info.timeout = M46_PMTU_TIMEOUT_DEF;

	/* timer for PMTU */
	init_timer(&m46_pmtu_timer);
	m46_pmtu_timer.entry.prev = NULL;
	m46_pmtu_timer.entry.next = NULL;
	m46_pmtu_timer.expires    = jiffies + M46_PMTU_CYCLE_TIME;
	m46_pmtu_timer.data       = 0;
	m46_pmtu_timer.function   = m46_pmtu_timer_func;
	add_timer(&m46_pmtu_timer);
}

static void init_m46_pr(void)
{

	/* m46 hash table clear */
	memset(m46_pr_tbl, 0, sizeof(m46_pr_tbl));
	memset(&m46_pr_info, 0, sizeof(m46_pr_info));
	m46_pr_info.mask_min = 0xffffffff;
}

static void init_m46_ns(void)
{

	m46_ns_tbl = NULL;
	memset(&m46_ns_info, 0, sizeof(m46_ns_info));
	m46e_dev_num = 1;
}

static int __init m46_init(void)
{
	int err;

	DBGp("m46e init start.");

	m46_dev = alloc_netdev(sizeof(struct m46_tbl), "m46e0",
				m46_dev_setup);

	if (!m46_dev)
		return -ENOMEM;

	dev_hold(m46_dev);

	if ((err = register_netdev(m46_dev))) {
		free_netdev(m46_dev);
		return err;
	}

	init_m46_pmtu();
	init_m46_pr();
	init_m46_ns();
	DBGp("m46e init end.");
	return 0;
}

static void __exit m46_cleanup(void)
{

	timerstop = 1;
	del_timer_sync(&m46_pmtu_timer);
	m46_pmtu_entry_free_all();

	m46_pr_entry_free_all();

	m46_ns_entry_free_all();

	dev_put(m46_dev);
	unregister_netdev(m46_dev);
	DBGp("m46 exit!");
}


module_init(m46_init);
module_exit(m46_cleanup);
