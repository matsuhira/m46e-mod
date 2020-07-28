/*
 * M46E
 * Stateless Automatic IPv4 over IPv6 Tunneling
 *
 * setting command check function.
 *
 * m46e_cli_chk.c
 *
 * Authors:
 * tamagawa          <tamagawa.daiki@jp.fujitsu.com>
 *
 * https://sites.google.com/site/m46enet/
 *
 * Copyright (C)2013 FUJITSU LIMITED
 *
 * Changes:
 * 2013.02.18 tamagawa New
 * 2013.03.26 tamagawa m46_chk_num is changed to unsigned.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <ctype.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "../include/m46e.h"
#include "m46e_cli.h"

/* v4アドレスチェック(IPアドレス、マスク) */
int m46_chk_ipv4_msk(char *str, char *chk_str)
{
	uint32_t mask;
	char *p, *q;
	char tmp[M46E_CLI_BUFSIZE];
	int chk_ret = 0;

	memcpy(tmp, str, (sizeof(tmp) - 1));

	/* v4アドレスの分解 */
	p = strtok(tmp, "/");
	if (p == NULL) {
		return M46E_CHKERR_SYNTAX;
	}

	chk_ret = m46_chk_ipv4(p, NULL);
	if (chk_ret < 0) {
		return chk_ret;
	}

	/* マスクの分解 */
	q = strtok(NULL, "/");
	if (q == NULL) {
		return M46E_CHKERR_SYNTAX;
	} else {
		mask = atoi(q);
	}

	if (mask < 1 || mask > 32) {
		return M46E_CHKERR_IPV4MASK_VALUE;
	}

	return 0;
}

/* v4アドレスチェック(IPアドレスのみ) */
int m46_chk_ipv4(char *str, char *chk_str)
{
	int digit, i, pos;
	char addr_tmp[M46E_TOKEN_LEN_MAX];
	char *ip_addr_p, *save_p, *p;

	memset(addr_tmp, 0, sizeof(addr_tmp));

	strcpy(addr_tmp, str);

	/* 入力形式チェック */
	for (digit = i = pos = 0; addr_tmp[i]; i++) {
		if (isdigit(addr_tmp[i]) != 0) {
			digit++;
		} else {
			if ((addr_tmp[i] == '.') && (digit > 0) && (digit < 4) && (pos < 4)) {
				digit = 0;
				pos++;
			} else {
				return M46E_CHKERR_IPV4ADDR;
			}
		}
	}

	if (pos != 3) {
		return M46E_CHKERR_IPV4ADDR;
	}

	/* 1～4オクテット目 */
	for (i = 0, p = &addr_tmp[0]; i < 4; i++, p = NULL) {
		if ((ip_addr_p = (char *)strtok_r(p, ".", &save_p)) == NULL) {
			return M46E_CHKERR_IPV4ADDR;
		}

		/* 範囲チェック */
		if ((0 > atoi(ip_addr_p)) || (atoi(ip_addr_p) > 255)) {
			return M46E_CHKERR_IPV4ADDR;
		}
	}

	return 0;
}

int m46_chk_ipv6(char *str, char *chk_str)
{
	struct in6_addr addr;

	if (inet_pton(AF_INET6, str, &addr) <= 0) {
		return M46E_CHKERR_IPV6ADDR;
	}

	return 0;
}

/*
 * 入力された数値が範囲内か
 */
int m46_chk_num(char *str, char *chk_str)
{
	unsigned int min, max, num;
	int i;
	char buf[M46E_CLI_BUFSIZE];
	char *tmp, **err = NULL;

	memset(buf, 0, sizeof(buf));
	strcpy(buf, chk_str);
	min = 0;

	/* チェック範囲設定 */
	for (i = 0; buf[i]; i++) {
		if (isdigit(buf[i]) == 0) {
			continue;
		}
		tmp = strchr(&buf[i], '-');
		if (tmp) {
			*tmp = '\0';
		}

		/* 最小値設定 */
		min = strtoul(&buf[i], err, 0);

		/* 区切り文字(-)まで移動 */
		for (; buf[i] != '\0'; i++) {
			;
		}
		i++;
		break;
	}

	max = strtoul(&buf[i], err, 0);

	/* 数値かどうかチェック */
	for (i = 0; str[i]; i++) {
		if (isdigit(str[i]) == 0) {
			return M46E_CHKERR_INVALID_VALUE;
		}
	}

	errno = 0;
	num = strtoul(str, err, 0);
	if (errno == ERANGE) {
		//printf("input value over flow.\n");
		return M46E_CHKERR_INVALID_VALUE;
	}
	if (num < min || num > max) {
		return M46E_CHKERR_INVALID_VALUE;
	}

	return 0;

}

int m46_chk_filepath(char *str, char *chk_str)
{

	FILE *fp;

	if ((fp = fopen(str, "r")) == NULL) {
		return M46E_CHKERR_FILE_NOT_FOUND;
	}

	return 0;
}

int m46_chk_ifname(char *str, char *chk_str)
{
	FILE	*fp;
	char	buf[M46E_CLI_BUFSIZE];
	char	*cmdline = "/sbin/ip link";
	char	*i, *n;


	if (strlen(str) >= IFNAMSIZ) {
		return M46E_CHKERR_IF_NOT_EXSIST;
	}

	if ((fp=popen(cmdline,"r")) == NULL) {
		err(EXIT_FAILURE, "%s", cmdline);
		return M46E_CHKERR_IP_CMD_ERROR;
	}

	memset(buf, 0, sizeof(buf));

	/* index name search */
	while(fgets(buf, M46E_CLI_BUFSIZE, fp) != NULL) {
		if (*buf != ' ') {
			i = strtok(buf, ":");
			if (i == NULL) {
				pclose(fp);
				return M46E_CHKERR_IP_CMD_ERROR;
			}
			n = strtok(NULL, ":");
			if (n == NULL) {
				pclose(fp);
				return M46E_CHKERR_IP_CMD_ERROR;
			}
			if (strcmp(&n[1], str) == 0) {
				pclose(fp);
				return 0;
			}
		}
	}

	pclose(fp);
	/* not exist net device */
	return M46E_CHKERR_IF_NOT_EXSIST;
}

int m46_dummy(char *str, char *chk_str)
{
	int ret;

	ret = strcmp(str, chk_str);
	if (ret == 0) {
		return -1;
	}

	return 0;
}

int m46_chk_set_veth(char *str, char *chk_str)
{
	int index;

	if (strlen(str) >= IFNAMSIZ)
		return M46E_CHKERR_IFNAME_LEN;

	index = if_nametoindex(str);
	if (index) {
		return M46E_CHKERR_IF_EXSIST;
	}

	return 0;
}

int m46_chk_namespace_name(char *str, char *chk_str)
{
	int i;

	if (strlen(str) >= NAMESPACE_LEN_MAX)
		return M46E_CHKERR_NSNAME_LEN;


	/* 先頭の文字としては使用できない */
	if (str[0] == '-' || str[0] =='.')
		return M46E_CHKERR_NSNAME;

	for(i = 1; str[i] != '\0'; i++) {
		if ((isalnum(str[i]) == 0) && (str[i] != '-') && (str[i] != '.')) {
			return M46E_CHKERR_NSNAME;
		}
		if (str[i+1] == '\0') {
			/* 最後の文字としては使用できない */
			if (str[i] == '.')
				return M46E_CHKERR_NSNAME;
		}

	}

	return 0;
}

int m46_chk_swich(char *str, char *chk_str)
{

	if (strcmp(str, "on") == 0 || strcmp(str, "off") == 0) {
		return 0;
	}

	return M46E_CHKERR_SWITCH;
}
