/*
 * Command for M46E path mtu discovery
 * Stateless Automatic IPv4 over IPv6 Tunneling
 *
 * M46E PMTU setting commands.
 *
 * Authors:
 * Mitarai           <m.mitarai@jp.fujitsu.com>
 * Tamagawa          <tamagawa.daiki@jp.fujitsu.com>
 *
 * Copyright (C)2012-2013 FUJITSU LIMITED
 *
 * 2012.10.05 mitarai  New.
 * 2013.02.18 tamagawa correspond m46e exclusive command
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <linux/netdevice.h>
#include "../include/m46e.h"
#include "m46e_cli.h"
#include "m46e_cli_err.h"

static int m46_pmtu_ioctl(void *, int);
static int m46_pmtu_sort(const void *, const void *);


int m46_pmtu_usage(int argc, char **argv)
{

	printf("\nUsage:\n");
	printf("pmtu -s <ip_addr> <mtu_value> <planeID>\n"
	       "pmtu -d <ip_addr> <planeID>\n"
	       "pmtu -t <timeout_value>\n"
	       "pmtu -f <on-off>\n");

	return 0;
}

static int m46_pmtu_ioctl(void *p, int kind)
{
	struct ifreq req;
	int sock, ret;

	memset(&req, 0, sizeof(req));
	req.ifr_data = p;
	strcpy(req.ifr_name, "m46e0");

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (!sock) {
		m46_debug_print(M46_PMTU_CMD_ERR, M46_PMTU_PERR_SOCK);
		return -1;
	}

	ret = ioctl(sock, kind, &req);
	if (ret)
		m46_debug_print(M46_PMTU_CMD_ERR, M46_PMTU_PERR_IOCTL);

	close(sock);
	return ret;
}

int m46_pmtu_set_force_fragment(int argc, char **argv)
{
	struct m46_pmtu_info spmi;
	int ret;

	if (argc != 3) {
		m46_pmtu_usage(argc, argv);
		return 0;	//Useageの表示のみでエラーにはしない。
	}

	memset(&spmi, 0, sizeof(struct m46_pmtu_info));

	if (strcmp(argv[2], "on") == 0)
		spmi.force_fragment = FORCE_FRAGMENT_ON;

	spmi.type = M46_SETPMTUINFO;

	ret = m46_pmtu_ioctl(&spmi, M46_PMTU);
	if (ret) {
		m46_debug_print(M46_PMTU_CMD_ERR, M46_PMTU_PERR_FRAG);
		return ret;
	}

	return 0;
}

int m46_pmtu_set(int argc, char **argv)
{
	struct in_addr v4addr;
	struct m46_pmtu_entry ent;
	uint32_t mtu;
	uint32_t plane_id;
	char *err = NULL;
	int ret;

	if (argc != 5) {
		m46_pmtu_usage(argc, argv);
		return 0;	//Useageの表示のみでエラーにはしない。
	}

	inet_pton(AF_INET, argv[2], &v4addr);

	mtu = strtoul(argv[3], &err, 0);

	plane_id = strtoul(argv[4], &err, 0);

	/* create entry */
	memset(&ent, 0, sizeof(struct m46_pmtu_entry));
	ent.v4_host_addr = v4addr;
	ent.m46_mtu = mtu;
	ent.plane_id = plane_id;
	ent.pmtu_flags = M46_PMTU_STATIC_ENTRY;
	ent.type = M46_SETPMTUENTRY;

	ret = m46_pmtu_ioctl(&ent, M46_PMTU);
	if (ret)
		m46_debug_print(M46_PMTU_CMD_ERR, M46_PMTU_PERR_SET);

	return ret;
}

int m46_pmtu_del(int argc, char **argv)
{
	struct in_addr v4addr;
	struct m46_pmtu_entry ent;
	int ret;
	uint32_t plane_id;
	char *err = NULL;

	if (argc != 4) {
		m46_pmtu_usage(argc, argv);
		return 0;	//Useageの表示のみでエラーにはしない。
	}

	inet_pton(AF_INET, argv[2], &v4addr);
	plane_id = strtoul(argv[3], &err, 0);

	/* create entry */
	memset(&ent, 0, sizeof(ent));
	ent.v4_host_addr = v4addr;
	ent.plane_id = plane_id;
	ent.type = M46_FREEPMTUENTRY;

	ret = m46_pmtu_ioctl(&ent, M46_PMTU);
	if (ret) {
		m46_debug_print(M46_PMTU_CMD_ERR, M46_PMTU_PERR_DEL);
		printf("specified entry does not exist.\n");
		return 0;	//ここでエラーメッセージを出すため、復帰値は0
	}

	return ret;
}

int m46_pmtu_time(int argc, char **argv)
{
	struct m46_pmtu_info inf;
	uint32_t time;
	int ret;
	char *err;

	if (argc != 3) {
		m46_pmtu_usage(argc, argv);
		return 0;	//Useageの表示のみでエラーにはしない。
	}

	memset(&inf, 0, sizeof(struct m46_pmtu_info));
	time = strtoul(argv[2], &err, 0);
	if (time < M46_PMTU_EXPIRE_MIN || time > M46_PMTU_EXPIRE_MAX) {
		printf("invalid timer value. %s\nrange is from %d to %d.\n", optarg,
		       M46_PMTU_EXPIRE_MIN, M46_PMTU_EXPIRE_MAX);
		return -1;
	}
	inf.timeout = time;
	inf.type = M46_SETPMTUTIME;

	ret = m46_pmtu_ioctl(&inf, M46_PMTU);
	if (ret)
		m46_debug_print(M46_PMTU_CMD_ERR, M46_PMTU_PERR_TIME);

	return ret;
}

static int m46_pmtu_sort(const void *a, const void *b)
{

	struct m46_pmtu_entry p, q;
	char c[16], d[16];

	memset(c, 0, sizeof(c));
	memset(d, 0, sizeof(d));

	memcpy(&p, a, sizeof(struct m46_pmtu_entry));
	memcpy(&q, b, sizeof(struct m46_pmtu_entry));

	if(p.plane_id < q.plane_id) {
		return -1;
	} else if(p.plane_id == q.plane_id) {
		inet_ntop(AF_INET, &p.v4_host_addr, c, sizeof(c));
		inet_ntop(AF_INET, &q.v4_host_addr, d, sizeof(d));
		return strcmp(c, d);
	}

	return 1;
}

int m46_pmtu_show(int argc, char **argv)
{
	struct m46_pmtu_info inf;
	struct m46_pmtu_entry *ent;
	int ret, i;
	int64_t time;
	char v4_str[16];
	char *tmp;

	memset(&inf, 0, sizeof(struct m46_pmtu_info));

	ret = m46_pmtu_get_ent_num(&inf);
	if (ret) {
		/* command error */
		return -1;
	}

	if (inf.force_fragment == FORCE_FRAGMENT_OFF) {
		printf("force fragment = OFF\n");
	} else {
		printf("force fragment = ON\n");
	}
	printf("Address          planeID     MTU   Life(sec) : initial value = %d\n", inf.timeout / M46_SYS_CLOCK);
	printf("---------------  ----------  ----  --------\n");

	if (!inf.entry_num) {
		printf("m46e pmtu table is not set.\n");
		return 0;
	}

	tmp = malloc((sizeof(struct m46_pmtu_entry) * inf.entry_num));
	if (!tmp) {
		m46_debug_print(M46_PMTU_CMD_ERR, M46_PR_PERR_MALLOC);
		return -1;
	}

	ent = (struct m46_pmtu_entry *)tmp;

	memset(ent, 0, sizeof(struct m46_pmtu_entry) * inf.entry_num);

	ret = m46_pmtu_get_ent(ent);
	if (ret) {
		free(tmp);
		return -1;
	}

	qsort((void *)ent, inf.entry_num, sizeof(struct m46_pmtu_entry), m46_pmtu_sort);

	for (i = 0; i < inf.entry_num; i++, ent++) {
		memset(v4_str, 0, sizeof(v4_str));
		inet_ntop(AF_INET, &ent->v4_host_addr, v4_str, sizeof(v4_str));
		printf("%-15s  ", v4_str);
		printf("%10u  ", ent->plane_id);
		printf("%-4d  ", ent->m46_mtu);
		if (ent->expires) {
			time = ent->expires - inf.now;
			if (time < 0) {
				printf("---\n");
			} else {
				time /= M46_SYS_CLOCK;
				printf("%-ld\n", time);
			}
		} else {
			printf("static\n");
		}
	}
	printf("Total entries : %d\n", inf.entry_num);

	free(tmp);

	return 0;
}

int m46_pmtu_get_ent_num(struct m46_pmtu_info *spmi)
{
	int ret;

	spmi->type = M46_GETPMTUENTRYNUM;

	ret = m46_pmtu_ioctl(spmi, M46_PMTU);
	if (ret) {
		m46_debug_print(M46_PMTU_CMD_ERR, M46_PMTU_PERR_GET);
		return ret;
	}

	return 0;

}

int m46_pmtu_get_ent(struct m46_pmtu_entry *spme)
{
	int ret;

	spme->type = M46_GETPMTUENTRY;

	ret = m46_pmtu_ioctl(spme, M46_PMTU);
	if (ret) {
		m46_debug_print(M46_PMTU_CMD_ERR, M46_PMTU_PERR_GET);
		return ret;
	}

	return 0;
}
