/*
 * Command for M46E Network NameSpace
 * Stateless Automatic IPv4 over IPv6 Tunneling
 *
 * Network NameSpace setting commands.
 *
 * Authors:
 * Tamagawa        <tamagawa.daiki@jp.fujitsu.com>
 *
 * Copyright (C)2012-2013 FUJITSU LIMITED
 *
 * 2013.08.22 tamagawa New.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sched.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/signalfd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <linux/sched.h>
#include "../include/m46e.h"
#include "m46e_cli.h"
#include "m46e_cli_err.h"

#define M46_NS_RESULT_SKIP_NLMSG 4
#define M46_NS_BACKLOG 5
#define M46_NS_RETRYNAMING 100
#define M46_NS_RETRYCONNECT 5
#define M46_NS_SELECT_WAIT_TIME_SEC 3
#define M46_NS_SELECT_WAIT_TIME_USEC 0
#define M46_NS_NETLINK_RCVBUF (16*1024)
#define M46_NS_NETLINK_SNDBUF (16*1024)
#define M46_NS_BBGWADDR "fe80::1"
#define M46_NS_NSGWADDR "fe80::2"
#define M46_NS_LINKLOCALPREFIX 64
#define M46_NS_SOCKDIR "/var/m46e/"
#define M46_NS_SOCKPATHSIZE 96
#define M46_NS_NODIR -1
#define M46_NS_SAMEDEVNAME -2

/* ns magic number */
enum {
	M46_DEV_MOVE =1,	/* device move complete */
	M46_CHILD_INIT,	/* child proc init run */
	M46_NAMESPACE_END,	/* delete namespace */
};

static int m46_ns_set_dev_name(int, char **, struct m46_ns_entry *);
static int m46_ns_set_dev_name_auto(struct m46_ns_entry *);
static int m46_ns_update_ent_info(struct m46_ns_info *);
static int m46_ns_set_peer_veth(struct m46_ns_entry *);
static int m46_ns_del_space(char *);
static pid_t m46_ns_set_namespace(void *);
static int m46_ns_cmd_handler(int);
static int m46_ns_create_sockdir(char *);
static int m46_ns_run_namespace(void *);
static int m46_ns_setting_init(struct m46_ns_entry *);
static void m46_ns_close_sock(int, int, char *);
static int m46_ns_init_child(struct m46_ns_entry *);
static int m46_ns_ifup(char *);
static int m46_ns_set_v6addr(char *, struct in6_addr *, u_int32_t);
static int m46_ns_start_sshd(void);
static int m46_ns_move_device(struct m46_ns_entry *);
static int m46_ns_move_device_by_index(const pid_t, char *);
static int m46_ns_netlink_open(unsigned long, int *, struct sockaddr_nl *, uint32_t *);
static int m46_ns_netlink_addattr_l(struct nlmsghdr *, int, int, const void *, int);
static int m46_ns_netlink_transaction(int, struct sockaddr_nl *, uint32_t, struct nlmsghdr *);
static int m46_ns_netlink_send(int, uint32_t, struct nlmsghdr*);
static int m46e_netlink_recv(int, struct sockaddr_nl *, uint32_t);
static int netlink_parse_ack(struct nlmsghdr*);
static int m46_ns_sync_child(struct m46_ns_entry *);
static int m46_ns_write_sock(int, struct m46_ns_req *, uint32_t);
static int m46_ns_read_sock(int, struct m46_ns_req *);
static int m46_ns_init_parent(struct m46_ns_entry *);
static int m46_ns_del_table(struct m46_ns_entry *);
static int m46_ns_del_child(struct m46_ns_entry *);
static int m46_ns_get_ent(struct m46_ns_entry *);
static int m46_ns_sort(const void *, const void *);
static int m46_ns_ioctl(void *, int);

int m46_ns_usage(int argc, char **argv)
{
	/* m46_ns_usage */
	printf("\nUsage:\n");
	printf("ns -s <NameSpace name> <planeid> <backbone v6 IF>"
			" <NameSpace v6 IF>\n");
	printf("ns -s <NameSpace name> <planeid>\n");
	printf("ns -d <NameSpace name>\n");
	printf("ns -m <IF> <NameSpace name>\n");
	printf("ns -i\n");

	return 0;
}

static int m46_ns_ioctl(void *p, int kind)
{
	struct ifreq req;
	int sock, ret;

	memset(&req, 0, sizeof(req));
	req.ifr_data = p;
	strcpy(req.ifr_name, "m46e0");

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (!sock) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_SOCK);
		return -1;
	}

	ret = ioctl(sock, kind, &req);
	if (ret)
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_IOCTL);

	close(sock);
	return ret;
}

int m46_ns_show_index(int argc, char **argv)
{
	FILE	*fp;
	char	buf[256];
	char	*cmdline = "/sbin/ip link";
	char	*index, *name;


	if ((fp=popen(cmdline,"r")) == NULL) {
		err(EXIT_FAILURE, "%s", cmdline);
		return -1;
	}

	printf("index    name \n");
	printf("-------- ---------------- \n");

	memset(buf, 0, sizeof(buf));

	while(fgets(buf, 256, fp) != NULL) {
		if (*buf != ' ') {
			index = strtok(buf, ":");
			if (index == NULL) {
				printf("%s\n", M46_NS_ERR_CMD);
				return -1;
			}
			name = strtok(NULL, ":");
			if (name == NULL) {
				printf("%s\n", M46_NS_ERR_CMD);
				return -1;
			}
			printf("%-8s %-16s\n", index, &name[1]);

		}
	}

	(void) pclose(fp);

	return 0;
}

static int m46_ns_sort(const void *a, const void *b)
{
	struct m46_ns_entry p, q;

	memcpy(&p, a, sizeof(struct m46_ns_entry));
	memcpy(&q, b, sizeof(struct m46_ns_entry));

	if (p.plane_id < q.plane_id) {
		return -1;
	} else if (p.plane_id == q.plane_id) {
		return 0;
	}

	return 1;
}

int m46_ns_get_ent_all(struct m46_ns_entry *sne)
{
	int ret;

	sne->type = M46_GETNSENTRYALL;

	ret = m46_ns_ioctl(sne, M46_NS);
	if (ret) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_GET);
		return ret;
	}

	return 0;
}

int m46_ns_show(int argc, char **argv)
{
	struct m46_ns_info sni;
	struct m46_ns_entry *sne;
	int i, ret;
	char v6_str[40];
	char *tmp;

	memset(&sni, 0, sizeof(struct m46_ns_info));

	ret = m46_ns_get_ent_info(&sni);
	if (ret)
		return 0;

	if (sni.entry_num == 0) {
		printf("M46E Network NameSpace Table is not set.\n");
		return 0;
	}

	tmp = malloc(sizeof(struct m46_ns_entry) * sni.entry_num);
	if (tmp == NULL) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_MALLOC);
		return -1;
	}

	sne = (struct m46_ns_entry *)tmp;

	memset(sne, 0, sizeof(struct m46_ns_entry) * sni.entry_num);

	ret = m46_ns_get_ent_all(sne);
	if (ret) {
		/* command error */
		free(tmp);
		return ret;
	}

	qsort((void *) sne, sni.entry_num, sizeof(struct m46_ns_entry),
			m46_ns_sort);

	printf("PlaneID     address      IF               NameSpace name\n");
	printf("----------  -----------  ---------------  --------------------\n");

	for (i = 0; i < sni.entry_num; i++, sne++) {
		memset(v6_str, 0, sizeof(v6_str));
	inet_ntop(AF_INET6, &sne->namespace_addr, v6_str, sizeof(v6_str));
	printf("%10u  %-11s  %-15s  %-s\n", sne->plane_id, v6_str,
			sne->backbone_veth_name, sne->namespace_name);
	}

	free(tmp);
	return 0;
}

static int m46_ns_get_ent(struct m46_ns_entry *sne)
{
	int ret;

	sne->type = M46_GETNSENTRY;

	ret = m46_ns_ioctl(sne, M46_NS);
	if (ret) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_GET);
		return ret;
	}

	return 0;
}

int m46_ns_move(int argc, char **argv)
{
	struct m46_ns_entry sne;
	int ret;

	if (argc < 4) {
		/* command error */
		m46_ns_usage(argc, argv);
		return  0;
	}

	memset(&sne, 0, sizeof(sne));

	strcpy(sne.namespace_name, argv[3]);

	ret = m46_ns_get_ent(&sne);
	if (ret) {
		printf("%s\n", M46_NS_ERR_CONNECTNS);
		return 0;
	}

	ret = m46_ns_move_device_by_index(sne.pid, argv[2]);
	if (ret) {
		printf("%s\n", M46_NS_ERR_MOVDEV);
		return 0;
	}

	return 0;
}

static int m46_ns_del_child(struct m46_ns_entry *sne)
{
	struct sockaddr_un sa;
	int sock;
	struct m46_ns_req req_p;
	char path[M46_NS_SOCKPATHSIZE];

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_SOCK);
		return -1;
	}

	memset(path, 0, sizeof(path));

	sa.sun_family = AF_UNIX;
	strcpy(path, M46_NS_SOCKDIR);
	strcat(path, sne->namespace_name);
	strcpy(sa.sun_path, path);

	if (connect(sock, (struct sockaddr *)&sa, sizeof(sa))) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_CONNECT);
		close(sock);
		return -1;
	}

	memset(&req_p, 0, sizeof(req_p));
	memcpy(&req_p.sne, sne, sizeof(struct m46_ns_entry));

	/* NameSpace終了通知 */
	if (m46_ns_write_sock(sock, &req_p, M46_NAMESPACE_END) < 0) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_WRITE);
		close(sock);
		return -1;
	}

	close(sock);
	return 0;
}

static int m46_ns_del_table(struct m46_ns_entry *sne)
{
	int ret;

	sne->type = M46_FREENSENTRY;
	ret = m46_ns_ioctl(sne, M46_NS);
	if (ret){
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_DEL);
		return ret;
	}

	return 0;
}

int m46_ns_del(int argc, char **argv)
{
	struct m46_ns_entry sne;
	int ret;

	if (argc < 3) {
		/* command error */
		m46_ns_usage(argc, argv);
		return  0;
	}

	memset(&sne, 0, sizeof(sne));

	strcpy(sne.namespace_name, argv[2]);

	ret = m46_ns_del_table(&sne);
	if (ret) {
		printf("%s\n", M46_NS_ERR_DEL);
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_DEL);
		return 0;
	}

	ret = m46_ns_del_child(&sne);
	if (ret) {
		printf("%s\n", M46_NS_ERR_CONNECTNS);
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_DEL);
		return 0;
	}

	return 0;
}

int m46_ns_update_ent(struct m46_ns_entry *sne)
{
	int ret;

	sne->type = M46_UPDATENSENTRY;
	ret = m46_ns_ioctl(sne, M46_NS);
	if (ret) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_UPDATE);
		return -1;
	}

	return 0;
}

static int m46_ns_init_parent(struct m46_ns_entry *sne)
{
	int ret;

	/* ペアvethの設定 */
	ret = m46_ns_ifup(sne->backbone_veth_name);
	if (ret) {
		printf("%s\n", M46_NS_ERR_IFUP_VETH);
		return -1;
	}

	inet_pton(AF_INET6, M46_NS_BBGWADDR, &sne->backbone_addr);

	ret = m46_ns_set_v6addr(sne->backbone_veth_name, &sne->backbone_addr,
							M46_NS_LINKLOCALPREFIX);
	if (ret) {
		printf("%s\n", M46_NS_ERR_V6ADDR);
		return -1;
	}

	return 0;
}

static int m46_ns_read_sock(int sock, struct m46_ns_req *req_p)
{
	if (read(sock, req_p, sizeof(struct m46_ns_req)) < 0) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_READ);
		return -1;
	}

	return 0;
}

static int m46_ns_write_sock(int sock, struct m46_ns_req *req_p, uint32_t num)
{
	req_p->magic_num = num;

	if (write(sock, req_p, sizeof(struct m46_ns_req)) < 0) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_WRITE);
		return -1;
	}

	return 0;
}

static int m46_ns_sync_child(struct m46_ns_entry *sne)
{
	struct sockaddr_un sa;
	int sock, i;
	struct m46_ns_req req_p;
	char path[M46_NS_SOCKPATHSIZE];


	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_SOCK);
		return -1;
	}

	memset(path, 0, sizeof(path));

	sa.sun_family = AF_UNIX;
	strcpy(path, M46_NS_SOCKDIR);
	strcat(path, sne->namespace_name);
	strcpy(sa.sun_path, path);

	/* 失敗したらconnectをリトライする(子プロセス設定待ち) */
	for (i = 0; i < M46_NS_RETRYCONNECT; i++) {
		if (connect(sock, (struct sockaddr *)&sa, sizeof(sa))) {
			/* 1sec待ってリトライ */
			sleep(1);
			continue;
		} else if (i == 4) {
			m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_CONNECT);
			close(sock);
			return -1;
		} else {
			break;
		}
	}

	memset(&req_p, 0, sizeof(req_p));
	memcpy(&req_p.sne, sne, sizeof(struct m46_ns_entry));

	/* デバイスの移動完了通知 */
	if (m46_ns_write_sock(sock, &req_p, M46_DEV_MOVE) < 0) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_WRITE);
		close(sock);
		return -1;
	}

	/* NameSpace設定完了受信・設定の取得 */
	if (m46_ns_read_sock(sock, &req_p) < 0) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_READ);
		close(sock);
		return -1;
	}
	memcpy(sne, &req_p.sne, sizeof(struct m46_ns_entry));

	close(sock);
	return 0;
}

static int netlink_parse_ack(struct nlmsghdr* nlmsg_h)
{
	struct nlmsgerr *nl_err;

	/* DONE Netlink Message ? */
	if (nlmsg_h->nlmsg_type == NLMSG_DONE)
		return -1;

	/* ACK Netlink Message ? */
	if (nlmsg_h->nlmsg_type == NLMSG_ERROR) {

		nl_err = (struct nlmsgerr*)NLMSG_DATA(nlmsg_h);

		/* payload length check */
		if (nlmsg_h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
			/* too short */
			printf("%s\n", M46_NS_ERR_NLMSG_LENGTH);
			return -1;
		}

		if (nl_err->error == 0) {
			/* ACK */
			return 0;
		} else {
			/* NACK (set System call ng)*/
			return -1;
		}
	}

	/* Unexpected  messege */
	return M46_NS_RESULT_SKIP_NLMSG;
}

int m46e_netlink_recv(int sock, struct sockaddr_nl *local_sa, uint32_t seq)
{
	int status, ret;
	struct nlmsghdr *nlmsg_h;
	struct sockaddr_nl nladdr;
	socklen_t nladdr_len = sizeof(nladdr);
	void *buf;

	buf = malloc(M46_NS_NETLINK_RCVBUF);
	if (buf == NULL) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_MALLOC);
		return -1;
	}

	/* Recv Netlink Message */
	while (1) {
		status = recvfrom(sock, buf, M46_NS_NETLINK_RCVBUF, 0,
			(struct sockaddr*) &nladdr, &nladdr_len);

		/* recv error */
		if (status < 0) {
			if ((errno == EINTR) || (errno == EAGAIN)){
				/* Interrupt */
				continue;
			}
			m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_NETRECV);
			free(buf);
			return -1;
		}

		/* No data */
		if (status == 0) {
			free(buf);
			return -1;
		}

		/* Sockaddr length check */
		if (nladdr_len != sizeof(nladdr)) {
			free(buf);
			return -1;
		}

		/* Parse Netlink Message */
		nlmsg_h = (struct nlmsghdr*)buf;
		while (NLMSG_OK(nlmsg_h, status)) {
			/* process id & sequence number check */
			if (nladdr.nl_pid != 0 || nlmsg_h->nlmsg_pid != local_sa->nl_pid
			|| nlmsg_h->nlmsg_seq != seq) {
				/* That netlink message is not my expected msg. */
				nlmsg_h = NLMSG_NEXT(nlmsg_h, status);
				continue;
			}

			/* Call the function of parse Netlink Message detail. */
			ret = netlink_parse_ack(nlmsg_h);

			/* M46_NS_RESULT_SKIP_NLMSG is skip messge */
			if (ret != M46_NS_RESULT_SKIP_NLMSG) {
				free(buf);
				/* Finish netlink message recieve & parse */
				return ret;
			}

			/* message skip */
			nlmsg_h = NLMSG_NEXT(nlmsg_h, status);
		}

		/* Recieve message Remain? */
		if (status) {
			free(buf);
			return -1;
		}
	}

	return -1;
}

static int m46_ns_netlink_send(int sock, uint32_t seq, struct nlmsghdr* nlm)
{
	int status;
	struct sockaddr_nl nladdr;

	/* NETLINK socket setting */
	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid    = 0;   /* To kernel */
	nladdr.nl_groups = 0;   /* No multicust */

	/* Netlink message header setting */
	nlm->nlmsg_seq = seq;

	/* Send netlink message */
	status = sendto(sock, nlm, nlm->nlmsg_len, 0,
			(struct sockaddr*) &nladdr, sizeof(nladdr));

	if (status < 0)
		return -1;

	return 0;
}

static int m46_ns_netlink_transaction(int sock, struct sockaddr_nl *local_sa,
		uint32_t seq, struct nlmsghdr *nlm)
{
	int ret;

	/* 要求送信 */
	ret = m46_ns_netlink_send(sock, seq, nlm);
	if (ret < 0)
		return -1;

	/* 応答受信 */
	ret = m46e_netlink_recv(sock, local_sa, seq);
	if (ret < 0)
		return -1;

	return 0;
}

static int m46_ns_netlink_addattr_l(struct nlmsghdr *n, int maxlen, int type,
		const void *data, int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + len > maxlen) {
		return -1;
	}

	rta = (struct rtattr*)(((void*)n) + NLMSG_ALIGN(n->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = len;

	memcpy(RTA_DATA(rta), data, alen);

	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + len;

	return 0;
}

static int m46_ns_netlink_open(unsigned long group, int *sock,
		struct sockaddr_nl *local, uint32_t *seq)
{
	socklen_t addr_len;
	int sysret;

	/* Netlink socket open */
	*sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (*sock < 0) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_SOCK);
		return -1;
	}

	/* Netlink socket bind */
	memset(local, 0, sizeof(*local));
	local->nl_family = AF_NETLINK;
	local->nl_pid = 0;
	local->nl_groups = group;

	sysret = bind(*sock, (struct sockaddr*)local, sizeof(*local));

	if (sysret < 0) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_BIND);
		close(*sock);
		return -1;
	}

	/* Get Netlink socket address */
	addr_len = sizeof(*local);

	if (getsockname(*sock, (struct sockaddr*)local, &addr_len) < 0) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_GETADDR);
		close(*sock);
		return -1;
	}

	/* sockaddr check */
	if ((addr_len != sizeof(*local)) || (local->nl_family != AF_NETLINK)) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_SOCKADDR);
		close(*sock);
		return -1;
	}

	/* set sequence number */
	*seq = time(NULL);

	return 0;
}

static int m46_ns_move_device_by_index(const pid_t pid, char *name)
{
	struct nlmsghdr *nlmsg;
	struct ifinfomsg *ifinfo;
	int sock;
	struct sockaddr_nl local;
	int ret;
	uint32_t seq;
	int ifindex;

	/* move m46e to namespace */
	ifindex = if_nametoindex(name);
	if (index < 0) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_NETLINK);
		return -1;
	}

	ret = m46_ns_netlink_open(0, &sock, &local, &seq);
	if (ret < 0) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_NETLINK);
		return -1;
	}

	nlmsg = malloc(M46_NS_NETLINK_SNDBUF);
	if (nlmsg == NULL) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_MALLOC);
		close(sock);
		return -1;
	}

	memset(nlmsg, 0, M46_NS_NETLINK_SNDBUF);

	ifinfo = (struct ifinfomsg *)(((void*)nlmsg) + NLMSG_HDRLEN);
	ifinfo->ifi_family = AF_UNSPEC;
	ifinfo->ifi_index  = ifindex;

	nlmsg->nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlmsg->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlmsg->nlmsg_type  = RTM_NEWLINK;

	ret = m46_ns_netlink_addattr_l(nlmsg, M46_NS_NETLINK_SNDBUF,
			IFLA_NET_NS_PID, &pid, sizeof(pid));
	if (ret != 0){
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_NETLINK);
		close(sock);
		free(nlmsg);
		return ENOMEM;
	}

	ret = m46_ns_netlink_transaction(sock, &local, seq, nlmsg);
	if (ret != 0){
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_NETLINK);
		close(sock);
		free(nlmsg);
		return -1;
	}

	close(sock);
	free(nlmsg);
	return 0;
}

static int m46_ns_move_device(struct m46_ns_entry *sne)
{
	int ret;

	/* move m46e to namespace */
	ret = m46_ns_move_device_by_index(sne->pid, sne->m46_name);
	if (ret < 0)
		return -1;

	/* move veth to namespace */
	ret = m46_ns_move_device_by_index(sne->pid, sne->namespace_veth_name);
	if (ret < 0)
		return -1;

	return 0;
}

static int m46_ns_del_space(char *sname)
{
	struct m46_ns_entry sne;
	int ret;

	memset(&sne, 0, sizeof(sne));

	strcpy(sne.namespace_name, sname);

	sne.type = M46_FREENSENTRY;
	ret = m46_ns_ioctl(&sne, M46_NS);
	if (ret) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_DEL);
		return -1;
	}

	ret = m46_ns_del_child(&sne);
	if (ret) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_DEL);
		return -1;
	}

	return 0;
}

static int m46_ns_set_peer_veth(struct m46_ns_entry *sne)
{
	char cmd[M46E_CLI_BUFSIZE];
	int ret;

	sprintf(cmd, "ip link add name %s type veth peer name %s > /dev/null",
			sne->backbone_veth_name, sne->namespace_veth_name);

	ret = system(cmd);
	if (ret < 0)
		return -1;

	return 0;
}


static int m46_ns_start_sshd(void)
{
	int ret;

	ret = system("/etc/init.d/sshd start > /dev/null");
	if (ret < 0)
		return -1;

	return 0;
}

static int m46_ns_set_v6addr(char *name, struct in6_addr *addr, u_int32_t prefixlen)
{
	 int fd;
	 struct m46_in6_ifreq ifr;
	 int n;

	 fd = socket(AF_INET6, SOCK_DGRAM, 0);

	 memset(&ifr, 0, sizeof(ifr));
	 ifr.ifr6_addr = *addr;
	 ifr.ifr6_prefixlen = prefixlen;
	 ifr.ifr6_ifindex = if_nametoindex(name);

	 n = ioctl(fd, SIOCSIFADDR, &ifr);
	 if (n < 0) {
		 m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_IOCTL);
		 close(fd);
		 return -1;
	 }

	 close(fd);
	 return 0;
}

static int m46_ns_ifup(char *name)
{
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	strncpy(ifr.ifr_name, name, IFNAMSIZ);

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) != 0) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_IOCTL);
		close(fd);
		return -1;
	}

	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

	if (ioctl(fd, SIOCSIFFLAGS, &ifr) != 0) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_IOCTL);
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

static int m46_ns_init_child(struct m46_ns_entry *sne)
{
	int ret;

	/* loデバイスの起動 */
	ret = m46_ns_ifup("lo");
	if (ret) {
		printf("%s\n", M46_NS_ERR_IFUP_LO);
		return -1;
	}
	/* m46eデバイスの設定 */
	ret = m46_ns_ifup(sne->m46_name);
	if (ret) {
		printf("%s\n", M46_NS_ERR_IFUP_M46E);
		return -1;
	}

	inet_pton(AF_INET6, M46_NS_NSGWADDR, &sne->namespace_addr);

	/* ペアvethの設定 */
	ret = m46_ns_ifup(sne->namespace_veth_name);
	if (ret) {
		printf("%s\n", M46_NS_ERR_IFUP_VETH);
		return -1;
	}
	ret = m46_ns_set_v6addr(sne->namespace_veth_name,
			&sne->namespace_addr, M46_NS_LINKLOCALPREFIX);
	if (ret) {
		printf("%s\n", M46_NS_ERR_V6ADDR);
		return -1;
	}

	m46_ns_start_sshd();

	return 0;
}

static void m46_ns_close_sock(int sock1, int sock2, char *path)
{

	close(sock1);
	close(sock2);
	unlink(path);

	return;
}

static int m46_ns_setting_init(struct m46_ns_entry *sne)
{
	int ret;

	/* ファイルシステムのマウント */
	ret = mount("procfs", "/proc", "proc", 0, NULL);
	if (ret) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_NSMOUNT);
		return -1;
	}

	/* ホスト名変更 */
	ret = sethostname(sne->namespace_name, strlen(sne->namespace_name));
	if (ret) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_NSHOST);
		return -1;
	}

	/* プロセス名変更 */
	ret = prctl(PR_SET_NAME, sne->namespace_name);
	if (ret) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_NSPROC);
		return -1;
	}

	return 0;
}

static int m46_ns_cmd_handler(int sock)
{
	int acc, ret;
	struct sockaddr_un cl;
	socklen_t addrsize;
	struct m46_ns_req req_p;

	addrsize = sizeof(struct sockaddr_un);

	acc = accept(sock, (struct sockaddr *)&cl, &addrsize);
	if (acc < 0) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_NSACC);
		close(acc);
		return -1;
	}

	memset(&req_p, 0, sizeof(req_p));

	if (m46_ns_read_sock(acc, &req_p) < 0) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_NSREAD);
		close(acc);
		return -1;
	}

	switch (req_p.magic_num) {
	case M46_DEV_MOVE:
		/* 子プロセス初期設定 */
		ret = m46_ns_init_child(&req_p.sne);
		if (ret) {
			printf("%s\n", M46_NS_ERR_CHILD_INIT);
			close(acc);
			return -1;
		}
		/* 子プロセス初期設定完了通知 */
		if (m46_ns_write_sock(acc, &req_p, M46_CHILD_INIT) < 0) {
			m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_NSWRITE);
			close(acc);
			return -1;
		}
		close(acc);
		break;
	case M46_NAMESPACE_END:
		close(acc);
		return M46_NAMESPACE_END;
	default:
		printf("%s\n", M46_NS_ERR_MAGNUM);
		close(acc);
		return -1;
	}

	return 0;
}

static int m46_ns_create_sockdir(char *path)
{
	mode_t mode;

	memset(path, 0, sizeof(*path));
	strcpy(path, M46_NS_SOCKDIR);

	/* socket格納ディレクトリがなければ作成 */
	if (access(path, F_OK) == M46_NS_NODIR) {
		mode = S_IRUSR | S_IRGRP | S_IXUSR | S_IXGRP | S_IWUSR | S_IWGRP;
		if (mkdir(path, mode)) {
			m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_NSMKDIR);
			return -1;
		}
	}

	return 0;
}

static int m46_ns_run_namespace(void *data)
{
	struct m46_ns_entry *sne;
	int sock, signal_fd, ret, maxfd;
	struct sockaddr_un sv;
	fd_set fds, readfds;
	struct timeval tv;
	char path[M46_NS_SOCKPATHSIZE];
	struct signalfd_siginfo si;
	sigset_t sigmask;

	sne = (struct m46_ns_entry *)data;

	/* namespaceシステム設定 */
	ret = m46_ns_setting_init(sne);
	if (ret)
		return -1;

	/* socket用ディレクトリ作成 */
	ret = m46_ns_create_sockdir(path);
	if (ret)
		return -1;

	memset(&sv, 0, sizeof(sv));
	sv.sun_family = AF_UNIX;
	strcat(path, sne->namespace_name);
	strcpy(sv.sun_path, path);

	/* 削除 */
	unlink(path);

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_NSSOCK);
		return -1;
	}

	ret = bind(sock, (struct sockaddr *)&sv, sizeof(sv));
	if (ret < 0) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_NSBIND);
		m46_ns_close_sock(sock, 0, path);
		return -1;
	}

	ret = listen(sock, M46_NS_BACKLOG);
	if (ret < 0) {
		m46_ns_close_sock(sock, 0, path);
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_NSLISTEN);
		return -1;
	}

	/* シグナルの登録 */
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGTERM);
	sigprocmask(SIG_BLOCK, &sigmask, 0);
	signal_fd = signalfd( -1, &sigmask, 0 );

	FD_ZERO(&readfds);
	FD_SET(sock, &readfds);
	FD_SET(signal_fd, &readfds);
	maxfd = -1;
	maxfd = max(maxfd, sock);
	maxfd = max(maxfd, signal_fd);

	/* 受信 */
	for (;;) {
		tv.tv_sec  = M46_NS_SELECT_WAIT_TIME_SEC;
		tv.tv_usec = M46_NS_SELECT_WAIT_TIME_USEC;
		memcpy(&fds, &readfds, sizeof(readfds));

		ret = select(maxfd+1, &fds, NULL, NULL, &tv);
		if (ret == 0) {
			if (if_nametoindex(sne->m46_name) == 0) {
				break;
			} else {
				continue;
			}
		} else if (ret < 0) {
			m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_NSSELECT);
			m46_ns_close_sock(sock, signal_fd, path);
			return -1;
		}
		if (FD_ISSET(sock, &fds)) {
			ret = m46_ns_cmd_handler(sock);
			if (ret == M46_NAMESPACE_END) {
				break;
			} else if (ret < 0) {
				m46_ns_close_sock(sock, signal_fd, path);
				return ret;
			}
		}
		if (FD_ISSET(signal_fd, &fds)) {
			read(signal_fd, &si, sizeof(si));
			if (si.ssi_signo == SIGTERM) {
				/* shutdown */
				break;
			}
		}
	}

	m46_ns_close_sock(sock, signal_fd, path);
	return 0;
}

static pid_t m46_ns_set_namespace(void *data)
{
	long  stack_size;
	void* stack;
	int   clone_flags;
        pid_t pid = 0;

	stack_size   = sysconf(_SC_PAGESIZE);
	stack        = alloca(stack_size);
	clone_flags  = CLONE_NEWNET;  /* ネットワーク空間 */
	clone_flags |= CLONE_NEWUTS;  /* UTS空間 */
	clone_flags |= CLONE_NEWPID;  /* PID空間 */
	clone_flags |= CLONE_NEWNS;   /* マウント空間 */

	pid = clone(m46_ns_run_namespace, stack+stack_size, clone_flags, data);

        return pid;
}

int m46_ns_add_dev(struct m46_ns_entry *sne)
{
	int ret;

	sne->type = M46_ADDDEV;
	ret = m46_ns_ioctl(sne, M46_NS);
	if (ret) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_ADDDEV);
		return ret;
	}

	return 0;
}

static int m46_ns_update_ent_info(struct m46_ns_info *sni)
{
	int ret;

	sni->type = M46_UPDATENSINFO;

	ret = m46_ns_ioctl(sni, M46_NS);
	if (ret) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_UPDATE);
		return ret;
	}

	return 0;
}

int m46_ns_get_ent_info(struct m46_ns_info *sni)
{
	int ret;

	sni->type = M46_GETNSENTRYNUM;

	ret = m46_ns_ioctl(sni, M46_NS);
	if (ret) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_GET);
		return ret;
	}

	return 0;
}

static int m46_ns_set_dev_name_auto(struct m46_ns_entry *sne)
{
	struct m46_ns_info sni;
	char str[IFNAMSIZ], str2[IFNAMSIZ];
	int ret, i;

	memset(&sni, 0, sizeof(struct m46_ns_info));

	ret = m46_ns_get_ent_info(&sni);
	if (ret)
		return ret;

	/* 名前が重複した場合リネームする */
	for (i = 0; i < M46_NS_RETRYNAMING; i++) {
		memset(str, 0, sizeof(str));
		memset(str2, 0, sizeof(str2));
		sprintf(str, "veth%d", sni.veth_num++);
		sprintf(str2, "veth%d", sni.veth_num++);
		if (if_nametoindex(str) == 0 && if_nametoindex(str2) == 0) {
			strcpy(sne->backbone_veth_name, str);
			strcpy(sne->namespace_veth_name, str2);
			break;
		}
	}

	if (i == M46_NS_RETRYNAMING) {
		printf("%s\n", M46_NS_ERR_RETDEVNAME);
		return -1;
	}

	ret = m46_ns_update_ent_info(&sni);
	if (ret)
		return ret;

	return 0;
}

static int m46_ns_set_dev_name(int argc, char **argv, struct m46_ns_entry *sne)
{
	int ret;

	if (argc == 6) {
		if (strcmp(argv[4], argv[5]) == 0){
			return M46_NS_SAMEDEVNAME;
		}
		strcpy(sne->backbone_veth_name, argv[4]);
		strcpy(sne->namespace_veth_name, argv[5]);
	} else if (argc == 4) {
		ret = m46_ns_set_dev_name_auto(sne);
		if (ret)
			return ret;
	} else {
		return -1;
	}

	return 0;
}

int m46_ns_set(int argc, char **argv)
{
	struct m46_ns_entry sne;
	int ret = 0;
	char **err = NULL;

	if (argc < 4 || argc > 6 || argc == 5) {
		/* command error */
		m46_ns_usage(argc, argv);
		return 0;
	}

	memset(&sne, 0, sizeof(sne));

	/* NameSpace名、planeid設定 */
	strcpy(sne.namespace_name, argv[2]);
	sne.plane_id = strtoul(argv[3], err, 0);

	/* 仮想インタフェース名設定 */
	ret = m46_ns_set_dev_name(argc, argv, &sne);
	if (ret) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_SET);
		if (ret == M46_NS_SAMEDEVNAME) {
			printf("%s\n", M46_NS_ERR_SAMEDEVNAME);
		} else {
			printf("%s\n", M46_NS_ERR_SETDEVNAME);
		}
		return 0;
	}

	/* m46eデバイス作成 */
	ret = m46_ns_add_dev(&sne);
	if (ret) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_SET);
		if (errno == EBUSY) {
			printf("%s\n", M46_NS_ERR_SAMESPACENAME);
		} else {
			printf("%s\n", M46_NS_ERR_ADD_M46E);
		}
		return 0;
	}

	/* NameSpace作成 */
	sne.pid = m46_ns_set_namespace(&sne);
	if (ret) {
		printf("%s\n", M46_NS_ERR_SETSPACE);
		m46_ns_del_space(sne.namespace_name);
		return 0;
	}

	/* ペア仮想インタフェース作成 */
	ret = m46_ns_set_peer_veth(&sne);
	if (ret) {
		printf("%s\n", M46_NS_ERR_CRATPERDEV);
		m46_ns_del_space(sne.namespace_name);
		return 0;
	}

	/* インタフェースの移動 */
	ret = m46_ns_move_device(&sne);
	if (ret) {
		printf("%s\n", M46_NS_ERR_MOVDEV);
		m46_ns_del_space(sne.namespace_name);
		return 0;
	}

	/* インタフェースの移動完了通知, NamaSpace設定待ち */
	ret = m46_ns_sync_child(&sne);
	if (ret) {
		printf("%s\n", M46_NS_ERR_SYNCHILD);
		m46_ns_del_space(sne.namespace_name);
		return 0;
	}

	/* backbone側の設定 */
	ret = m46_ns_init_parent(&sne);
	if (ret) {
		m46_ns_del_space(sne.namespace_name);
		return 0;
	}

	/* NameSpaceの情報を最新にアップデート */
	ret = m46_ns_update_ent(&sne);
	if (ret) {
		m46_debug_print(M46_NS_CMD_ERR, M46_NS_PERR_SET);
		printf("update NameSpace information failed\n");
		m46_ns_del_space(sne.namespace_name);
		return 0;
	}

	return 0;
}
