/*
 * Command for M46E
 * Stateless Automatic IPv4 over IPv6 Tunneling
 *
 * Statistics of M46E
 *
 * Authors:
 * Mitarai         <m.mitarai@jp.fujitsu.com>
 *
 * https://sites.google.com/site/m46enet/
 *
 * Copyright (C)2010-2012 FUJITSU LIMITED
 *
 * Chaneges:
 * 2011.01.12 mitarai Statistical information is changed to 64bit.
 * 2012.09.14 mitarai Fragment support.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/netdevice.h>
#include "../include/m46e.h"
#include "m46e_cli.h"

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


const char *stats_str[] = {
	"Encapsulation packets",
	"Decapsulation packets",
	"Next header errors(Decap)",
	"Encapsulation tx errors",
	"Decapsulation tx errors",
	"Send ICMP packets(Encap)",
	"No route ICMP packets(Encap)",
	"No mac header(Encap)",
	"Ttl errors(Decap)",
	"Encapsulation icmp packets",
	"Encapsulation tcp packets",
	"Encapsulation udp packets",
	"Encapsulation other packets",
	"Encapsulation tcp packets(FTP)",
	"Encapsulation tcp packets(SSH)",
	"Encapsulation tcp packets(TELNET)",
	"Encapsulation tcp packets(SMTP)",
	"Encapsulation tcp packets(DNS)",
	"Encapsulation tcp packets(BOOTPS)",
	"Encapsulation tcp packets(BOOTPC)",
	"Encapsulation tcp packets(HTTP)",
	"Encapsulation tcp packets(POP3)",
	"Encapsulation tcp packets(NETBIOS)",
	"Encapsulation tcp packets(IMAP)",
	"Encapsulation tcp packets(SNMP)",
	"Encapsulation tcp packets(HTTPS)",
	"Encapsulation tcp packets(Any Source Multicast ctrl)",
	"Encapsulation tcp packets(Any Source Multicast data)",
	"Encapsulation tcp packets(OTHER)",
	"Encapsulation udp packets(FTP)",
	"Encapsulation udp packets(SSH)",
	"Encapsulation udp packets(TELNET)",
	"Encapsulation udp packets(SMTP)",
	"Encapsulation udp packets(DNS)",
	"Encapsulation udp packets(BOOTPS)",
	"Encapsulation udp packets(BOOTPC)",
	"Encapsulation udp packets(HTTP)",
	"Encapsulation udp packets(POP3)",
	"Encapsulation udp packets(NETBIOS)",
	"Encapsulation udp packets(IMAP)",
	"Encapsulation udp packets(SNMP)",
	"Encapsulation udp packets(HTTPS)",
	"Encapsulation udp packets(Any Source Multicast ctrl)",
	"Encapsulation udp packets(Any Source Multicast data)",
	"Encapsulation udp packets(OTHER)",
	"Decapsulation icmp packets",
	"Decapsulation tcp packets",
	"Decapsulation udp packets",
	"Decapsulation other packets",
	"Decapsulation tcp packets(FTP)",
	"Decapsulation tcp packets(SSH)",
	"Decapsulation tcp packets(TELNET)",
	"Decapsulation tcp packets(SMTP)",
	"Decapsulation tcp packets(DNS)",
	"Decapsulation tcp packets(BOOTPS)",
	"Decapsulation tcp packets(BOOTPC)",
	"Decapsulation tcp packets(HTTP)",
	"Decapsulation tcp packets(POP3)",
	"Decapsulation tcp packets(NETBIOS)",
	"Decapsulation tcp packets(IMAP)",
	"Decapsulation tcp packets(SNMP)",
	"Decapsulation tcp packets(HTTPS)",
	"Decapsulation tcp packets(Any Source Multicast ctrl)",
	"Decapsulation tcp packets(Any Source Multicast data)",
	"Decapsulation tcp packets(OTHER)",
	"Decapsulation udp packets(FTP)",
	"Decapsulation udp packets(SSH)",
	"Decapsulation udp packets(TELNET)",
	"Decapsulation udp packets(SMTP)",
	"Decapsulation udp packets(DNS)",
	"Decapsulation udp packets(BOOTPS)",
	"Decapsulation udp packets(BOOTPC)",
	"Decapsulation udp packets(HTTP)",
	"Decapsulation udp packets(POP3)",
	"Decapsulation udp packets(NETBIOS)",
	"Decapsulation udp packets(IMAP)",
	"Decapsulation udp packets(SNMP)",
	"Decapsulation udp packets(HTTPS)",
	"Decapsulation udp packets(Any Source Multicast ctrl)",
	"Decapsulation udp packets(Any Source Multicast data)",
	"Decapsulation udp packets(OTHER)",
	"Encapsulation fragmentation tx error",
	"Encapsulation fragmentation tx packet",
	NULL,
};

static int m46_search_if(char *ifn)
{
	FILE	*fp;
	char	buf[M46E_CLI_BUFSIZE];
	char	*cmdline = "/sbin/ip link";
	char	*i, *n;

	if ((fp=popen(cmdline,"r")) == NULL) {
		err(EXIT_FAILURE, "%s", cmdline);
		return -1;
	}

	memset(buf, 0, sizeof(buf));

	/* m46e device search */
	while(fgets(buf, M46E_CLI_BUFSIZE, fp) != NULL) {
		if (*buf != ' ') {
			i = strtok(buf, ":");
			if (i == NULL) {
				printf("cmd error\n");
				pclose(fp);
				return -1;
			}
			n = strtok(NULL, ":");
			if (n == NULL) {
				printf("cmd error\n");
				pclose(fp);
				return -1;
			}
			if (strncmp(&n[1], "m46e", 4) == 0) {
				strcpy(ifn, &n[1]);
				return 0;
			}
		}
	}

	pclose(fp);
	/* not exist net device */
	return -1;
}

int m46_statistics(int argc, char **argv)
{
	int sock;
	struct ifreq req;
	int ret, i;
	struct m46_tbl m46_tbl;
	uint64_t *p;
	char ifname[IFNAMSIZ];

	if (argc != 1) {
		/* command error */
		return -1;
	}

	memset(&m46_tbl, 0, sizeof(struct m46_tbl));

//	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		perror("create socket error.");
		setuid(getuid());
		return -1;
	}

	memset(ifname, 0, sizeof(ifname));
	ret = m46_search_if(ifname);
	if (ret < 0) {
		printf("m46e device not found.");
	}

	strcpy(req.ifr_name, ifname);
	req.ifr_data = &m46_tbl;
	ret = ioctl(sock, M46_GETSTATISTICS, &req);
	if (ret == -1) {
		perror("ioctl error.");
		close(sock);
		return -1;
	}

	close(sock);

	printf("\n     M46E statistics (%s)\n\n", ifname);

	p = &m46_tbl.encap_cnt;
	for (i = 0; stats_str[i]; i++, p++) {
		printf(" %20lu | %s\n", *p, stats_str[i]);
	}
	printf("\n");

	return 0;
}
