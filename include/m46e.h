/*
 * M46E
 * Stateless Automatic IPv4 over IPv6 Tunneling
 *
 * Authors:
 * Mitarai           <m.mitarai@jp.fujitsu.com>
 * tamagawa          <tamagawa.daiki@jp.fujitsu.com>
 *
 * https://sites.google.com/site/m46enet/
 *
 * Copyright (C)2010-2013 FUJITSU LIMITED
 */

#ifndef _M46E_H
#define _M46E_H

//#define M46_DEBUG 1
//#define M46E_AS 1
#ifdef M46_DEBUG
#define DBGp(fmt, args...) do { printk(KERN_DEBUG fmt, ##args); } while(0)
#else
#define DBGp(fmt, ...) do { ; } while(0)
#endif

#define M46_PR_HASH_SIZE 128
#define M46_PMTU_HASH_SIZE 128
#define M46_SYS_CLOCK 1000
#define FORCE_FRAGMENT_OFF 0
#define FORCE_FRAGMENT_ON 1
#define NAMESPACE_LEN_MAX 64

#define M46_GETSTATISTICS	(SIOCDEVPRIVATE)
#define M46_PR			(SIOCDEVPRIVATE+1)
#define M46_SETPRENTRY		1
#define M46_FREEPRENTRY	2
#define M46_GETPRENTRYNUM	3
#define M46_GETPRENTRY		4
#define M46_SETDEFPREFIX	5
#define M46_FREEDEFPREFIX	6
#define M46_PMTU		(SIOCDEVPRIVATE+2)
#define M46_GETPMTUENTRYNUM	7
#define M46_GETPMTUENTRY	8
#define M46_SETPMTUENTRY	9
#define M46_FREEPMTUENTRY	10
#define M46_SETPMTUTIME	11
#define M46_SETPMTUINFO	12
#define M46_NS			(SIOCDEVPRIVATE+3)
#define M46_ADDDEV		13
#define M46_UPDATENSENTRY	14
#define M46_FREENSENTRY	15
#define M46_GETNSENTRY		16
#define M46_GETNSENTRYNUM	17
#define M46_GETNSENTRYALL	18
#define M46_UPDATENSINFO	19

#define M46_PMTU_STATIC_ENTRY 1
struct m46_pmtu_entry {
	uint32_t type;
	struct m46_pmtu_entry *next;
	struct in_addr v4_host_addr;
	uint32_t m46_mtu;
	uint32_t pmtu_flags;
	uint32_t plane_id;
	uint64_t expires;
};

struct m46_pmtu_info {
	uint32_t type;
	uint32_t entry_num;
	uint32_t timeout;
	uint32_t force_fragment;
	uint64_t now;
};

#define M46_PMTU_TIMEOUT_DEF (10 * 60 * HZ) /* 10 minutes */
#define M46_PMTU_CYCLE_TIME  (1 * 60 * HZ)  /*  1 minutes */
//#define M46_PMTU_CYCLE_TIME  (1 * HZ)  /*  1 sec */
#define M46_PMTU_EXPIRE_MIN 300    /* 5 minutes */
#define M46_PMTU_EXPIRE_MAX 86400  /* 24 hour */

struct m46_pr_entry {
	uint32_t type;
	struct m46_pr_entry *next;
	struct in_addr ipv4addr;
	uint32_t ipv4mask;
	uint32_t plane_id;
	uint32_t prefix_len;
	struct in6_addr m46_addr;
};

struct m46_pr_info {
	uint32_t type;
	uint32_t entry_num;
	uint32_t mask_max;
	uint32_t mask_min;
	uint32_t def_valid_flg;
	struct in6_addr m46_def_pre;
};

struct m46_ns_entry {
	uint32_t type;
	struct m46_ns_entry *prev;
	struct m46_ns_entry *next;
	struct net_device *m46_dev;
	uint32_t plane_id;
	pid_t pid;
	struct in6_addr backbone_addr;
	struct in6_addr namespace_addr;
	char namespace_name[NAMESPACE_LEN_MAX];
	char backbone_veth_name[IFNAMSIZ];
	char namespace_veth_name[IFNAMSIZ];
	char m46_name[IFNAMSIZ];
};

struct m46_ns_info {
	uint32_t type;
	uint32_t entry_num;
	uint32_t veth_num;
};

#ifdef __KERNEL__
struct m46_tbl {
	struct m46_tbl *next;
	struct net_device *dev;
	uint64_t encap_cnt;
	uint64_t decap_cnt;
	uint64_t decap_next_hdr_errors;
	uint64_t encap_tx_errors;
	uint64_t decap_tx_errors;
	uint64_t encap_send_icmp;
	uint64_t encap_send_icmp_no_route;
	uint64_t encap_no_mac_header;
	uint64_t decap_ttl_errors;
	uint64_t encap_icmp;
	uint64_t encap_tcp;
	uint64_t encap_udp;
	uint64_t encap_other;
	uint64_t encap_tcp_ftp;
	uint64_t encap_tcp_ssh;
	uint64_t encap_tcp_telnet;
	uint64_t encap_tcp_smtp;
	uint64_t encap_tcp_dns;
	uint64_t encap_tcp_bootps;
	uint64_t encap_tcp_bootpc;
	uint64_t encap_tcp_http;
	uint64_t encap_tcp_pop3;
	uint64_t encap_tcp_netbios;
	uint64_t encap_tcp_imap;
	uint64_t encap_tcp_snmp;
	uint64_t encap_tcp_https;
	uint64_t encap_tcp_asmp_ctl;
	uint64_t encap_tcp_asmp_data;
	uint64_t encap_tcp_other;
	uint64_t encap_udp_ftp;
	uint64_t encap_udp_ssh;
	uint64_t encap_udp_telnet;
	uint64_t encap_udp_smtp;
	uint64_t encap_udp_dns;
	uint64_t encap_udp_bootps;
	uint64_t encap_udp_bootpc;
	uint64_t encap_udp_http;
	uint64_t encap_udp_pop3;
	uint64_t encap_udp_netbios;
	uint64_t encap_udp_imap;
	uint64_t encap_udp_snmp;
	uint64_t encap_udp_https;
	uint64_t encap_udp_asmp_ctl;
	uint64_t encap_udp_asmp_data;
	uint64_t encap_udp_other;
	uint64_t decap_icmp;
	uint64_t decap_tcp;
	uint64_t decap_udp;
	uint64_t decap_other;
	uint64_t decap_tcp_ftp;
	uint64_t decap_tcp_ssh;
	uint64_t decap_tcp_telnet;
	uint64_t decap_tcp_smtp;
	uint64_t decap_tcp_dns;
	uint64_t decap_tcp_bootps;
	uint64_t decap_tcp_bootpc;
	uint64_t decap_tcp_http;
	uint64_t decap_tcp_pop3;
	uint64_t decap_tcp_netbios;
	uint64_t decap_tcp_imap;
	uint64_t decap_tcp_snmp;
	uint64_t decap_tcp_https;
	uint64_t decap_tcp_asmp_ctl;
	uint64_t decap_tcp_asmp_data;
	uint64_t decap_tcp_other;
	uint64_t decap_udp_ftp;
	uint64_t decap_udp_ssh;
	uint64_t decap_udp_telnet;
	uint64_t decap_udp_smtp;
	uint64_t decap_udp_dns;
	uint64_t decap_udp_bootps;
	uint64_t decap_udp_bootpc;
	uint64_t decap_udp_http;
	uint64_t decap_udp_pop3;
	uint64_t decap_udp_netbios;
	uint64_t decap_udp_imap;
	uint64_t decap_udp_snmp;
	uint64_t decap_udp_https;
	uint64_t decap_udp_asmp_ctl;
	uint64_t decap_udp_asmp_data;
	uint64_t decap_udp_other;
	uint64_t encap_fragment_tx_error;
	uint64_t encap_fragment_tx_packet;
	uint64_t decap_next_hdr_type_errors;
	uint64_t decap_payload_len_errors;
	uint64_t decap_icmpv6_proto_errors;
	uint64_t decap_pmtu_set_errors;
};

enum {
	PROTO_FTP1 = 20,
	PROTO_FTP2 = 21,
	PROTO_SSH = 22,
	PROTO_TELNET =23,
	PROTO_SMTP = 25,
	PROTO_DNS = 53,
	PROTO_BOOTPS = 67,
	PROTO_BOOTPC = 68,
	PROTO_HTTP = 80,
	PROTO_POP3 = 110,
	PROTO_NETBIOS = 139,
	PROTO_IMAP = 143,
	PROTO_SNMP = 161,
	PROTO_HTTPS = 443,
	PROTO_ASMP_CTL = 60230,
	PROTO_ASMP_DATA = 60231,
};

static struct net_device *m46_dev;

#ifdef M46_DEBUG
static inline void dump_data(char *str, void *p, int len)
{
	char data[40];
	int i, j;
	unsigned char *d;

	d = (unsigned char *)p;

	memset(data, 0, sizeof(data));

	if (strcmp(str, "no") != 0) {
		printk(KERN_INFO "\"%s\" len = %d\n", str, len);
	}

	for (; len > 0; len -= 16, d += 16) {
		if (len >= 16) {
			sprintf(data, "%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
				*d, *(d+1), *(d+2), *(d+3), *(d+4), *(d+5), *(d+6), *(d+7),
				*(d+8), *(d+9), *(d+10), *(d+11), *(d+12), *(d+13), *(d+14),
				*(d+15));
			printk(KERN_INFO "%s\n", data);
			memset(data, 0, sizeof(data));
		} else {
			for (i = 1, j = 0; len > 0 ;d++, len--, i++) {
				sprintf(&data[j], "%02x", *d);
				if (!(i % 4)) {
					j += 2;
					sprintf(&data[j], " ");
					j++;
				} else {
					j += 2;
				}
			}
			printk(KERN_INFO "%s\n", data);
		}
	}
}
#else
static inline void dump_data(char *str, void *p, int len) {return;}
#endif

static inline void m46_encap_statistics_proto(struct sk_buff *skb, struct m46_tbl *t)
{
	struct iphdr *v4hdr = ipip_hdr(skb);
	struct tcphdr *tcp;
	struct udphdr *udp;
	__be16 src, dst;

	switch (v4hdr->protocol) {
	case IPPROTO_TCP:
		t->encap_tcp++;
		tcp = (struct tcphdr *)(v4hdr+1);
		src = ntohs(tcp->source);
		dst = ntohs(tcp->dest);
		if (dst == PROTO_FTP1 || src == PROTO_FTP1)
			t->encap_tcp_ftp++;
		else if (dst == PROTO_FTP2 || src == PROTO_FTP2)
			t->encap_tcp_ftp++;
		else if (dst == PROTO_SSH || src == PROTO_SSH)
			t->encap_tcp_ssh++;
		else if (dst == PROTO_TELNET || src == PROTO_TELNET)
			t->encap_tcp_telnet++;
		else if (dst == PROTO_SMTP || src == PROTO_SMTP)
			t->encap_tcp_smtp++;
		else if (dst == PROTO_DNS || src == PROTO_DNS)
			t->encap_tcp_dns++;
		else if (dst == PROTO_BOOTPS || src == PROTO_BOOTPS)
			t->encap_tcp_bootps++;
		else if (dst == PROTO_BOOTPC || src == PROTO_BOOTPC)
			t->encap_tcp_bootpc++;
		else if (dst == PROTO_HTTP || src == PROTO_HTTP)
			t->encap_tcp_http++;
		else if (dst == PROTO_POP3 || src == PROTO_POP3)
			t->encap_tcp_pop3++;
		else if (dst == PROTO_NETBIOS || src == PROTO_NETBIOS)
			t->encap_tcp_netbios++;
		else if (dst == PROTO_IMAP || src == PROTO_IMAP)
			t->encap_tcp_imap++;
		else if (dst == PROTO_SNMP || src == PROTO_SNMP)
			t->encap_tcp_snmp++;
		else if (dst == PROTO_HTTPS || src == PROTO_HTTPS)
			t->encap_tcp_https++;
		else if (dst == PROTO_ASMP_CTL || src == PROTO_ASMP_CTL)
			t->encap_tcp_asmp_ctl++;
		else if (dst == PROTO_ASMP_DATA || src == PROTO_ASMP_DATA)
			t->encap_tcp_asmp_data++;
		else
			t->encap_tcp_other++;
		break;
	case IPPROTO_UDP:
		t->encap_udp++;
		udp = (struct udphdr *)(v4hdr+1);
		dst = ntohs(udp->dest);
		src = ntohs(udp->source);
		if (dst == PROTO_FTP1 || src == PROTO_FTP1)
			t->encap_udp_ftp++;
		else if (dst == PROTO_FTP2 || src == PROTO_FTP2)
			t->encap_udp_ftp++;
		else if (dst ==  PROTO_SSH || src == PROTO_SSH)
			t->encap_udp_ssh++;
		else if (dst == PROTO_TELNET || src == PROTO_TELNET)
			t->encap_udp_telnet++;
		else if (dst == PROTO_SMTP || src == PROTO_SMTP)
			t->encap_udp_smtp++;
		else if (dst == PROTO_DNS || src == PROTO_DNS)
			t->encap_udp_dns++;
		else if (dst == PROTO_BOOTPS || src == PROTO_BOOTPS)
			t->encap_udp_bootps++;
		else if (dst == PROTO_BOOTPC || src == PROTO_BOOTPC)
			t->encap_udp_bootpc++;
		else if (dst == PROTO_HTTP || src == PROTO_HTTP)
			t->encap_udp_http++;
		else if (dst == PROTO_POP3 || src == PROTO_POP3)
			t->encap_udp_pop3++;
		else if (dst == PROTO_NETBIOS || src == PROTO_NETBIOS)
			t->encap_udp_netbios++;
		else if (dst == PROTO_IMAP || src == PROTO_IMAP)
			t->encap_udp_imap++;
		else if (dst == PROTO_SNMP || src == PROTO_SNMP)
			t->encap_udp_snmp++;
		else if (dst == PROTO_HTTPS || src == PROTO_HTTPS)
			t->encap_udp_https++;
		else if (dst == PROTO_ASMP_CTL || src == PROTO_ASMP_CTL)
			t->encap_udp_asmp_ctl++;
		else if (dst == PROTO_ASMP_DATA || src == PROTO_ASMP_DATA)
			t->encap_udp_asmp_data++;
		else
			t->encap_udp_other++;
		break;
	case IPPROTO_ICMP:
		t->encap_icmp++;
		break;
	default:
		t->encap_other++;
		break;
	}
}

static inline void m46_decap_statistics_proto(struct sk_buff *skb, struct m46_tbl *t)
{
	struct iphdr *v4hdr = ip_hdr(skb);
	struct tcphdr *tcp;
	struct udphdr *udp;
	__be16 dst, src;

	switch (v4hdr->protocol) {
	case IPPROTO_TCP:
		t->decap_tcp++;
		tcp = (struct tcphdr *)(v4hdr+1);
		dst = ntohs(tcp->dest);
		src = ntohs(tcp->source);
		if (dst == PROTO_FTP1 || src == PROTO_FTP1)
			t->decap_tcp_ftp++;
		else if (dst == PROTO_FTP2 || src == PROTO_FTP2)
			t->decap_tcp_ftp++;
		else if (dst == PROTO_SSH || src == PROTO_SSH)
			t->decap_tcp_ssh++;
		else if (dst == PROTO_TELNET || src == PROTO_TELNET)
			t->decap_tcp_telnet++;
		else if (dst == PROTO_SMTP || src == PROTO_SMTP)
			t->decap_tcp_smtp++;
		else if (dst == PROTO_DNS || src == PROTO_DNS)
			t->decap_tcp_dns++;
		else if (dst == PROTO_BOOTPS || src == PROTO_BOOTPS)
			t->decap_tcp_bootps++;
		else if (dst == PROTO_BOOTPC || src == PROTO_BOOTPC)
			t->decap_tcp_bootpc++;
		else if (dst == PROTO_HTTP || src == PROTO_HTTP)
			t->decap_tcp_http++;
		else if (dst == PROTO_POP3 || src == PROTO_POP3)
			t->decap_tcp_pop3++;
		else if (dst == PROTO_NETBIOS || src == PROTO_NETBIOS)
			t->decap_tcp_netbios++;
		else if (dst == PROTO_IMAP || src == PROTO_IMAP)
			t->decap_tcp_imap++;
		else if (dst == PROTO_SNMP || src == PROTO_SNMP)
			t->decap_tcp_snmp++;
		else if (dst == PROTO_HTTPS || src == PROTO_HTTPS)
			t->decap_tcp_https++;
		else if (dst == PROTO_ASMP_CTL || src == PROTO_ASMP_CTL)
			t->decap_tcp_asmp_ctl++;
		else if (dst == PROTO_ASMP_DATA || src == PROTO_ASMP_DATA)
			t->decap_tcp_asmp_data++;
		else
			t->decap_tcp_other++;
		break;
	case IPPROTO_UDP:
		t->decap_udp++;
		udp = (struct udphdr *)(v4hdr+1);
		dst = ntohs(udp->dest);
		src = ntohs(udp->source);
		if (dst == PROTO_FTP1 || src == PROTO_FTP1)
			t->decap_udp_ftp++;
		else if (dst == PROTO_FTP2 || src == PROTO_FTP2)
			t->decap_udp_ftp++;
		else if (dst == PROTO_SSH || src == PROTO_SSH)
			t->decap_udp_ssh++;
		else if (dst == PROTO_TELNET || src == PROTO_TELNET)
			t->decap_udp_telnet++;
		else if (dst == PROTO_SMTP || src == PROTO_SMTP)
			t->decap_udp_smtp++;
		else if (dst == PROTO_DNS || src == PROTO_DNS)
			t->decap_udp_dns++;
		else if (dst == PROTO_BOOTPS || src == PROTO_BOOTPS)
			t->decap_udp_bootps++;
		else if (dst == PROTO_BOOTPC || src == PROTO_BOOTPC)
			t->decap_udp_bootpc++;
		else if (dst == PROTO_HTTP || src == PROTO_HTTP)
			t->decap_udp_http++;
		else if (dst == PROTO_POP3 || src == PROTO_POP3)
			t->decap_udp_pop3++;
		else if (dst == PROTO_NETBIOS || src == PROTO_NETBIOS)
			t->decap_udp_netbios++;
		else if (dst == PROTO_IMAP || src == PROTO_IMAP)
			t->decap_udp_imap++;
		else if (dst == PROTO_SNMP || src == PROTO_SNMP)
			t->decap_udp_snmp++;
		else if (dst == PROTO_HTTPS || src == PROTO_HTTPS)
			t->decap_udp_https++;
		else if (dst == PROTO_ASMP_CTL || src == PROTO_ASMP_CTL)
			t->decap_udp_asmp_ctl++;
		else if (dst == PROTO_ASMP_DATA || src == PROTO_ASMP_DATA)
			t->decap_udp_asmp_data++;
		else
			t->decap_udp_other++;
		break;
	case IPPROTO_ICMP:
		t->decap_icmp++;
		break;
	default:
		t->decap_other++;
		break;
	}
}
#endif /* __KERNEL__ */

#endif /* _M46E_H */
