/*
 * Command for M46E-PR
 * Stateless Automatic IPv4 over IPv6 Tunneling
 *
 * M46E-PR setting commands.
 *
 * Authors:
 * Mitarai         <m.mitarai@jp.fujitsu.com>
 * Tamagawa        <tamagawa.daiki@jp.fujitsu.com>
 *
 * Copyright (C)2012-2013 FUJITSU LIMITED
 *
 * 2012.08.16 mitarai New.
 * 2012.08.31 tamagawa add m46_pr_entry_file.
 * 2013.02.18 tamagawa correspond m46e exclusive command
 * 2013.03.26 tamagawa planeid is changed to unsigned.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <linux/netdevice.h>
#include "../include/m46e.h"
#include "m46e_cli.h"
#include "m46e_cli_err.h"

/* read line max length */
#define M46E_PR_FILESET_LENGTH_MAX 128

#define PR_SET_FILENAME 2
#define COM_OPT_MAX 6
#define COM_OPT_MIN 2
#define ENTRY_ADD 0		/* entry add */
#define FORMAT_CHK 1		/* format check */

/* option length */
#define CMD_OPTIONS_MAX 6	/* command size max */
#define IPV4_LENGTH_MAX 18	/* IPv4 size max */
#define PREFIX_LENGTH_MAX 39	/* prefix size max */
#define PLANEID_LENGTH_MAX 10	/* plane ID size max */

/* error value */
#define FORMATERROR -1		/* format error */
#define CMDERROR -2		/* command error */
#define SOCKERROR -3		/* socket error */

static void m46_pr_cmd_malloc(char **);
static void m46_pr_cmd_free(int, char **);
static int m46_pr_ioctl(void *, int);
static int m46_pr_sort(const void *, const void *);

int m46_pr_usage(int argc, char **argv)
{

	/* m46_pr_usage */
	printf("\nUsage:\n");
	printf("pr -s pr-prefix <ipv4addr/mask> <m46e-prefix(64bit)> <planeID>\n");
	printf("pr -s default <m46e-prefix(64bit)>\n");
	printf("pr -d pr-prefix <ipv4addr/mask> <planeID>\n");
	printf("pr -d default\n");
	printf("pr -f <filepath>\n");
	printf("File format: ipv4addr/mask,m46e-prefix(64bit),planeID\n");

	return 0;
}

static int m46_pr_ioctl(void *p, int kind)
{
	struct ifreq req;
	int sock, ret;

	memset(&req, 0, sizeof(req));
	req.ifr_data = p;
	strcpy(req.ifr_name, "m46e0");

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (!sock) {
		m46_debug_print(M46_PR_CMD_ERR, M46_PR_PERR_SOCK);
		return -1;
	}

	ret = ioctl(sock, kind, &req);
	if (ret)
		m46_debug_print(M46_PR_CMD_ERR, M46_PR_PERR_IOCTL);

	close(sock);
	return ret;
}

int m46_pr_entry_add(int argc, char **argv)
{
	struct m46_pr_entry spe;
	struct m46_pr_info spi;
	int ret;
	char *p, *q, **err = NULL;

	if (strncmp(argv[2], "default", 7) == 0) {

		if (argc != 4) {
			/* command error */
			m46_pr_usage(argc, argv);
			return 0;	//Usage出すのみでエラーにはしない
		}

		/* default prefix set */
		memset(&spi, 0, sizeof(spi));
		inet_pton(AF_INET6, argv[3], &spi.m46_def_pre);
		spi.type = M46_SETDEFPREFIX;
		ret = m46_pr_ioctl(&spi, M46_PR);
		if (ret) {
			m46_debug_print(M46_PR_CMD_ERR, M46_PR_PERR_ADD);
		}
	} else {

		if (argc != 6) {
			/* command error */
			m46_pr_usage(argc, argv);
			return 0;	//Usage出すのみでエラーにはしない
		}

		/* PR entry set */
		memset(&spe, 0, sizeof(spe));

		/* v4アドレスの分解 */
		p = strtok(argv[3], "/");
		inet_pton(AF_INET, p, &spe.ipv4addr);


		/* マスクの分解 */
		q = strtok(NULL, "/");
		spe.ipv4mask = atoi(q);

		inet_pton(AF_INET6, argv[4], &spe.m46_addr);

		spe.m46_addr.s6_addr32[2] = htonl(strtoul(argv[5], err, 0));
		spe.m46_addr.s6_addr32[3] = spe.ipv4addr.s_addr;
		spe.plane_id = strtoul(argv[5], err, 0);
		spe.prefix_len = 96 + spe.ipv4mask;

		spe.type = M46_SETPRENTRY;

		ret = m46_pr_ioctl(&spe, M46_PR);
		if (ret) {
			m46_debug_print(M46_PR_CMD_ERR, M46_PR_PERR_ADD);
		}
	}

	return ret;
}

/*
 * entry_flag
 * ENTRY_ADD 0		add table entry
 * FORMAT_CHK 1		format check
 */
int m46_pr_entry_add_file(char **argv, int entry_flag)
{

	struct m46_pr_entry spe;
	struct m46_pr_info spi;
	int ret;
	char *p, *q, **err = NULL;


	if (strncmp(argv[3], "default", 7) == 0) {

		/* default prefix set */
		memset(&spi, 0, sizeof(spi));
		if (inet_pton(AF_INET6, argv[4], &spi.m46_def_pre) <= 0) {
			if (entry_flag == FORMAT_CHK) {
				return FORMATERROR;
			} else {
				return CMDERROR;
			}
		}

		/* フォーマットチェック時はテーブルの追加をしない */
		if (entry_flag == FORMAT_CHK)
			return 0;

		spi.type = M46_SETDEFPREFIX;

		ret = m46_pr_ioctl(&spi, M46_PR);
		if (ret)
			m46_debug_print(M46_PR_CMD_ERR, M46_PR_PERR_ADD);

	} else {

		/* PR entry set */
		memset(&spe, 0, sizeof(spe));

		/* v4アドレスの分解 */
		p = strtok(argv[3], "/");
		if (p == NULL) {
			if (entry_flag == FORMAT_CHK) {
				return FORMATERROR;
			} else {
				return CMDERROR;
			}
		}

		if (inet_pton(AF_INET, p, &spe.ipv4addr) <= 0) {
			if (entry_flag == FORMAT_CHK) {
				return FORMATERROR;
			} else {
				return CMDERROR;
			}
		}

		/* マスクの分解 */
		q = strtok(NULL, "/");
		if (q == NULL) {
			if (entry_flag == FORMAT_CHK) {
				return FORMATERROR;
			} else {
				return CMDERROR;
			}
		} else {
			spe.ipv4mask = atoi(q);
		}

		if (spe.ipv4mask < 1 || spe.ipv4mask > 32) {
			if (entry_flag == FORMAT_CHK) {
				return FORMATERROR;
			} else {
				return CMDERROR;
			}
		}

		if (inet_pton(AF_INET6, argv[4], &spe.m46_addr) <= 0) {
			if (entry_flag == FORMAT_CHK) {
				return FORMATERROR;
			} else {
				return CMDERROR;
			}
		}

		/* フォーマットチェック時はテーブルの追加をしない */
		if (entry_flag == FORMAT_CHK) {
			return 0;
		}

		spe.m46_addr.s6_addr32[2] = htonl(strtoul(argv[5], err, 0));
		spe.m46_addr.s6_addr32[3] = spe.ipv4addr.s_addr;
		spe.plane_id = strtoul(argv[5], err, 0);
		spe.prefix_len = 96 + spe.ipv4mask;

		spe.type = M46_SETPRENTRY;

		ret = m46_pr_ioctl(&spe, M46_PR);
		if (ret)
			m46_debug_print(M46_PR_CMD_ERR, M46_PR_PERR_ADD);
	}

	return ret;
}

int m46_pr_entry_del(int argc, char **argv)
{

	struct m46_pr_entry spe;
	struct m46_pr_info spi;
	int ret;
	char *p, *q, **err = NULL;

	if (strncmp(argv[2], "default", 7) == 0) {
		if (argc != 3) {
			/* command error */
			m46_pr_usage(argc, argv);
			return 0;	//Usageを出すのみで、エラーにはしない
		}
		/* default prefix free */
		memset(&spi, 0, sizeof(spi));

		spi.type = M46_FREEDEFPREFIX;

		ret = m46_pr_ioctl(&spi, M46_PR);
		if (ret) {
			m46_debug_print(M46_PR_CMD_ERR, M46_PR_PERR_DEL);
		}

	} else {
		if (argc != 5) {
			/* command error */
			m46_pr_usage(argc, argv);
			return 0;	//Usageを出すのみで、エラーにはしない
		}
		/* PR entry free */
		memset(&spe, 0, sizeof(spe));

		/* v4アドレスの分解 */
		p = strtok(argv[3], "/");
		if (p == NULL) {
			return CMDERROR;
		}

		if (inet_pton(AF_INET, p, &spe.ipv4addr) <= 0) {
			return CMDERROR;
		}

		/* マスクの分解 */
		q = strtok(NULL, "/");
		if (q == NULL) {
			return CMDERROR;
		} else {
			spe.ipv4mask = atoi(q);
		}

		if (spe.ipv4mask < 1 || spe.ipv4mask > 32) {
			return CMDERROR;
		}

		spe.plane_id = strtoul(argv[4], err, 0);

		spe.type = M46_FREEPRENTRY;

		ret = m46_pr_ioctl(&spe, M46_PR);
		if (ret) {
			m46_debug_print(M46_PR_CMD_ERR, M46_PR_PERR_DEL);
			printf("specified entry does not exist.\n");
			return 0;	//ここでメッセージ表示するため、エラーは返さない。
		}
	}

	return ret;
}

static int m46_pr_sort(const void *a, const void *b)
{

	struct m46_pr_entry p, q;
	char c[16], d[16];

	memset(c, 0, sizeof(c));
	memset(d, 0, sizeof(d));

	memcpy(&p, a, sizeof(struct m46_pr_entry));
	memcpy(&q, b, sizeof(struct m46_pr_entry));

	if(p.plane_id < q.plane_id) {
		return -1;
	} else if(p.plane_id == q.plane_id) {
		inet_ntop(AF_INET, &p.ipv4addr, c, sizeof(c));
		inet_ntop(AF_INET, &q.ipv4addr, d, sizeof(d));
		return strcmp(c, d);
	}

	return 1;
}

int m46_pr_entry_show(int argc, char **argv)
{

	struct m46_pr_info spi;
	struct m46_pr_entry *spe;
	int i, ret;
	char v4_str[16], v6_str[40];
	char *tmp;
	struct in6_addr tmp_default_addr;

	memset(&spi, 0, sizeof(struct m46_pr_info));

	ret = m46_pr_get_ent_num(&spi);
	if (ret) {
		/* command error */
		return -1;
	}

	if (spi.entry_num == 0 && spi.def_valid_flg == 0) {
		printf("M46E-PR Table is not set.\n");
		return 0;
	}

	if (spi.entry_num == 0) {

		printf("   PlaneID IPv4addr        Mask M46E-PR Prefix\n");
		printf("---------- --------------- ---- ---------------------------------------\n");

		memset(v6_str, 0, sizeof(v6_str));

		/* Prefixで使用されるのは、64bit目までなので、それ以降のbitを0にして表示 */
		tmp_default_addr = spi.m46_def_pre;
		tmp_default_addr.s6_addr32[2] = 0;
		tmp_default_addr.s6_addr32[3] = 0;
		inet_ntop(AF_INET6, &tmp_default_addr, v6_str, sizeof(v6_str));

		printf("%10s ", " ");
		printf("%-15s ", "default");
		printf("/%-3s ", "0");
		printf("%-39s\n", v6_str);

		return 0;
	}

	tmp = malloc(sizeof(struct m46_pr_entry) * spi.entry_num);
	if (tmp == NULL) {
		m46_debug_print(M46_PR_CMD_ERR, M46_PR_PERR_MALLOC);
		return -1;
	}

	spe = (struct m46_pr_entry *)tmp;

	memset(spe, 0, sizeof(struct m46_pr_entry) * spi.entry_num);

	ret = m46_pr_get_ent(spe);
	if (ret) {
		free(tmp);
		return -1;
	}

	qsort((void *)spe, spi.entry_num, sizeof(struct m46_pr_entry), m46_pr_sort);

	printf("   PlaneID IPv4addr        Mask M46E-PR Prefix\n");
	printf("---------- --------------- ---- ---------------------------------------\n");

	for (i = 0; i < spi.entry_num; i++, spe++) {
		memset(v4_str, 0, sizeof(v4_str));
		memset(v6_str, 0, sizeof(v6_str));
		inet_ntop(AF_INET, &spe->ipv4addr, v4_str, sizeof(v4_str));
		inet_ntop(AF_INET6, &spe->m46_addr, v6_str, sizeof(v6_str));
		printf("%10u ", spe->plane_id);
		printf("%-15s ", v4_str);
		printf("/%-3u ", spe->prefix_len);
		printf("%-39s\n", v6_str);
	}

	if (spi.def_valid_flg != 0) {
		memset(v6_str, 0, sizeof(v6_str));

		/* Prefixで使用されるのは、64bit目までなので、それ以降のbitを0にして表示 */
		tmp_default_addr = spi.m46_def_pre;
		tmp_default_addr.s6_addr32[2] = 0;
		tmp_default_addr.s6_addr32[3] = 0;
		inet_ntop(AF_INET6, &tmp_default_addr, v6_str, sizeof(v6_str));

		printf("%10s ", " ");
		printf("%-15s ", "default");
		printf("/%-3s ", "0");
		printf("%-39s\n", v6_str);
	}

	free(tmp);

	return 0;
}

int m46_pr_entry_file(int argc, char **argv)
{

	FILE *fp;
	char *info;				/* PR情報退避領域 */
	char *tmp;
	int line_cnt = 1;			/* 行数カウンタ */
	int err = 0;
	char *v[COM_OPT_MAX];			/* opt tmp */

	if (argc != 3) {
		/* command error */
		m46_pr_usage(argc, argv);
		return 0;	//Usageを出すのみで、エラーにはしない
	}

	if ((fp = fopen(argv[2], "r")) == NULL) {
		//printf("%s not exists\n", argv[2]);
		return -1;
	}

	memset(v, 0, COM_OPT_MAX);
	m46_pr_cmd_malloc(v);

	info = (char *) malloc(M46E_PR_FILESET_LENGTH_MAX);
	if (info == NULL) {
		m46_pr_cmd_free(COM_OPT_MAX, v);
		return -1;
	}

	memset(info, 0, M46E_PR_FILESET_LENGTH_MAX);

	/* ファイルからエントリを読込みフォーマットをチェックする */
	while (fgets(info, M46E_PR_FILESET_LENGTH_MAX, fp) != NULL) {

		/* 空行、コメント行は飛ばす */
		if (*info != '\r' && *info != '#' && *info != '\n') {

			tmp = strtok(info, ",");
			if (tmp == NULL || strlen(tmp) > IPV4_LENGTH_MAX) {
				printf("line %d : format error.\n", line_cnt++);
				err = FORMATERROR;
				continue;
			}
			strcpy(v[3], tmp);

			tmp = strtok(NULL, ",");
			if (tmp == NULL || strlen(tmp) > PREFIX_LENGTH_MAX) {
				printf("line %d : format error.\n", line_cnt++);
				err = FORMATERROR;
				continue;
			}
			strcpy(v[4], tmp);

			tmp = strtok(NULL, "");
			if (tmp == NULL || strlen(tmp) > PLANEID_LENGTH_MAX) {
				printf("line %d : format error.\n", line_cnt++);
				err = FORMATERROR;
				continue;
			}
			strcpy(v[5], tmp);

			if (FORMATERROR == m46_pr_entry_add_file(v, FORMAT_CHK)) {
				printf("line %d : format error.\n", line_cnt);
				err = FORMATERROR;
			}
		}
		line_cnt++;
	}

	/* フォーマットエラーがあった場合エントリを追加せず終了する */
	if (err == FORMATERROR) {
		fclose(fp);
		free(info);
		m46_pr_cmd_free(COM_OPT_MAX, v);
		printf("file entry failed.\n");
		return 0;	//エラーメッセージ"file entry failed"をここで出すので、復帰値は0
	} else {
		/* 再度先頭から読み込む */
		rewind(fp);
	}

	/* ファイルから読込んだテーブルエントリの追加 */
	while (fgets(info, M46E_PR_FILESET_LENGTH_MAX, fp) != NULL) {

		if (*info != '\r' && *info != '#' && *info != '\n') {

			strcpy(v[3], strtok(info, ","));
			strcpy(v[4], strtok(NULL, ","));
			strcpy(v[5], strtok(NULL, ""));
			if (m46_pr_entry_add_file(v,ENTRY_ADD)) {
				fclose(fp);
				free(info);
				m46_pr_cmd_free(COM_OPT_MAX, v);
				printf("file entry failed.\n");
				return 0;	//エラーメッセージ"file entry failed"をここで出すので、復帰値は0
			}
		}
	}

	fclose(fp);
	free(info);

	/* 退避領域の解放 */
	m46_pr_cmd_free(COM_OPT_MAX, v);

	return 0;
}


static void m46_pr_cmd_malloc(char **v)
{

	v[0] = NULL;
	v[1] = NULL;
	v[2] = NULL;

	/* 領域の確保 */
	v[3] = (char *) malloc(IPV4_LENGTH_MAX);
	if(v[3] == NULL) {
		m46_debug_print(M46_PR_CMD_ERR, M46_PR_PERR_MALLOC);
		exit(1);
	}
	memset(v[3], 0, IPV4_LENGTH_MAX);

	v[4] = (char *) malloc(PREFIX_LENGTH_MAX);
	if(v[4] == NULL) {
		m46_debug_print(M46_PR_CMD_ERR, M46_PR_PERR_MALLOC);
		free(v[3]);
		exit(1);
	}
	memset(v[4], 0, PREFIX_LENGTH_MAX);

	v[5] = (char *) malloc(PLANEID_LENGTH_MAX);
	if(v[5] == NULL) {
		m46_debug_print(M46_PR_CMD_ERR, M46_PR_PERR_MALLOC);
		free(v[3]);
		free(v[4]);
		exit(1);
	}
	memset(v[5], 0, PLANEID_LENGTH_MAX);

	return;

}

static void m46_pr_cmd_free(int argc, char **v)
{

	int i;


	for (i =3; i < argc; i++) {
		free(v[i]);
	}

	return;
}

int m46_pr_get_ent_num(struct m46_pr_info *spi)
{
	int ret;

	spi->type = M46_GETPRENTRYNUM;

	ret = m46_pr_ioctl(spi, M46_PR);
	if (ret) {
		m46_debug_print(M46_PR_CMD_ERR, M46_PR_PERR_GET);
		return ret;
	}

	return 0;

}

int m46_pr_get_ent(struct m46_pr_entry *spe)
{
	int ret;

	spe->type = M46_GETPRENTRY;

	ret = m46_pr_ioctl(spe, M46_PR);
	if (ret) {
		m46_debug_print(M46_PR_CMD_ERR, M46_PR_PERR_GET);
		return ret;
	}

	return 0;
}

