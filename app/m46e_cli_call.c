/*
 * M46E
 * Stateless Automatic IPv4 over IPv6 Tunneling
 *
 * setting command common function.
 *
 * m46e_cli_call.c
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
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/netdevice.h>
#include "../include/m46e.h"
#include "m46e_cli.h"
#include "m46e_cli_err.h"

#define GET_CONFIG_INFO_AND_ENTRY_NUM	0	/* get info and entry num*/
#define GET_CONFIG_ENTRY				1	/* get entry */

static int m46_over(char **);
static int m46_pr_conf(struct m46_pr_info *, struct m46_pr_entry *, int);
static void m46_pr_conf_output(FILE *, struct m46_pr_info *, struct m46_pr_entry *);
static int m46_pmtu_conf(struct m46_pmtu_info *, struct m46_pmtu_entry *, int);
static void m46_pmtu_conf_output(FILE *, struct m46_pmtu_info *, struct m46_pmtu_entry *);
static int m46_ns_conf(struct m46_ns_info *, struct m46_ns_entry *, int);
static void m46_ns_conf_outputs(FILE *, struct m46_ns_info *, struct m46_ns_entry *);

void m46_debug_print(char *str1, char *str2)
{
	char buf[32];

	if (M46_DEBUG_FLAG) {
		memset(buf, 0, sizeof(buf));
		sprintf(buf, "%s %s", str1, str2);
		perror(buf);
	}

	return;
}

int m46_com_help(int argc, char **argv)
{
	FILE	*fp;
	char	buf[M46E_CLI_BUFSIZE];
	char	*cmdline = "cat ./M46E_command_manual.txt";
	int	j = 0;
	char	ch;
        struct	winsize	winsz;

        /* 端末のwindow幅を取得する */
        ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsz);

	if ((fp=popen(cmdline,"r")) == NULL) {
		err(EXIT_FAILURE, "%s", cmdline);
		return -1;
	}

        while(fgets(buf, M46E_CLI_BUFSIZE, fp) != NULL) {
		j++;
		/* window幅分先行して出力する */
		if (j < winsz.ws_row) {
			fputs(buf, stdout);
			continue;
		}
		for(;;) {
			ch = fgetc(stdin);
			if((ch == '\n') || (ch == '\r')) {
				fputs(buf, stdout);
				break;
			} else if (ch == 0x20) {
				j = 0;
				fputs(buf, stdout);
				break;
			} else if (ch == 'q') {
				goto CLOSE;
			}
		}
        }

CLOSE:
	pclose(fp);

	return 0;

}

int m46_show_sys(int argc, char **argv)
{
	m46_sys_cmd_tbl_t *cmdp;

	cmdp = cmd_sys;

	if (cmdp->cmd_str == NULL) {
		/* no entry system command. */
		return 0;
	}

	for (; cmdp->cmd_str != NULL; cmdp++) {
		PUT_BAR_T(cmdp->cmd_str);
		system(cmdp->cmd_str);
	}

	return 0;

}

int m46_show_m46e(int argc, char **argv)
{
	PUT_BAR_T("PR");
	m46_pr_entry_show(argc, argv);
	PUT_BAR_T("PMTU");
	m46_pmtu_show(argc, argv);
	PUT_BAR_T("NS");
	m46_ns_show(argc, argv);

	return 0;
}

int m46_show_all(int argc, char **argv)
{
	m46_show_m46e(argc, argv);
	m46_show_sys(argc, argv);

	return 0;
}

#if 0
int m46_set_txquelen(int argc, char **argv)
{
	char cmdline[M46E_CLI_BUFSIZE];

	if (argc != 3) {
		/* cmmand error */
		return -1;
	}

	memset(cmdline, 0, sizeof(cmdline));

	strcpy(cmdline, "ifconfig ");
	strcat(cmdline, argv[1]);
	strcat(cmdline, " txqueuelen ");
	strcat(cmdline, argv[2]);

	system(cmdline);

	return 0;

}

int m46_set_backlog(int argc, char **argv)
{
	char cmdline[M46E_CLI_BUFSIZE];

	if (argc != 2) {
		/* cmmand error */
		return -1;
	}

	memset(cmdline, 0, sizeof(cmdline));

	strcpy(cmdline, "sysctl -w net.core.netdev_max_backlog=");
	strcat(cmdline, argv[1]);

	system(cmdline);

	return 0;
}
#endif /* m46ecliで全ての設定をできるようにしたい時に有効にする */

int m46_load_conf(int argc, char **argv)
{
	FILE *fp;
	char ch[M46E_CLI_BUFSIZE];

	memset(ch, 0, M46E_CLI_BUFSIZE);

	if ((fp = fopen(argv[2], "r")) == NULL) {
		//printf("%s not exists\n", argv[2]);
		printf("file not found.\n");
		return -1;
	}

	while (fgets(ch, M46E_CLI_BUFSIZE, fp) != NULL) {
		m46_blank_del(ch);
		m46_call_cmd(ch);
	}

	fclose(fp);
	return 0;
}


int m46_save_conf(int argc, char **argv)
{
	FILE *fp = NULL;
	struct m46_pr_info spi;
	struct m46_pr_entry *spe = NULL;
	struct m46_pmtu_info spmi;
	struct m46_pmtu_entry *spme = NULL;
	struct m46_ns_info sni;
	struct m46_ns_entry *sne = NULL;
	int ret = 0;

	memset(&spi, 0, sizeof(struct m46_pr_info));
	memset(&spmi, 0, sizeof(struct m46_pmtu_info));
	memset(&sni, 0, sizeof(struct m46_ns_info));

	if (argc != 3) {
		/* command error */
		ret = -1;
		goto RETURN;
	}

	//check overwrite
	if ((fp = fopen(argv[2], "r")) == NULL) {
		/* nothing to do */
	} else {
		if(m46_over(argv) != 0) {
			/* not save */
			ret = 0;
			goto RETURN;
		}
	}

	//get info and entry num
	if (m46_pr_conf(&spi, NULL, GET_CONFIG_INFO_AND_ENTRY_NUM)) {
		/* command error */
		ret = -1;
		goto RETURN;
	}
	if (m46_pmtu_conf(&spmi, NULL, GET_CONFIG_INFO_AND_ENTRY_NUM)) {
		/* command error */
		ret = -1;
		goto RETURN;
	}
	if (m46_ns_conf(&sni, NULL, GET_CONFIG_INFO_AND_ENTRY_NUM)) {
		/* command error */
		ret = -1;
		goto RETURN;
	}

	//malloc memory for entry
	if (spi.entry_num != 0) {
		spe = (struct m46_pr_entry *)malloc(sizeof(struct m46_pr_entry) * spi.entry_num);
		if (spe == NULL) {
			perror("m46e_pr_cmd: malloc");
			ret = -1;
			goto RETURN;
		}
		memset(spe, 0, sizeof(struct m46_pr_entry) * spi.entry_num);
	}
	if (spmi.entry_num != 0) {
		spme =(struct m46_pmtu_entry *)malloc(sizeof(struct m46_pmtu_entry) * spmi.entry_num);
		if (spme == NULL) {
			perror("m46e_pmtu_cmd: malloc");
			ret = -1;
			goto RETURN;
		}
		memset(spme, 0, sizeof(struct m46_pmtu_entry) * spmi.entry_num);
	}
	if (sni.entry_num != 0) {
		sne = (struct m46_ns_entry *)malloc(sizeof(struct m46_ns_entry) * sni.entry_num);
		if (sne == NULL) {
			perror("m46e_ns_cmd: malloc\n");
			ret = -1;
			goto RETURN;
		}
		memset(sne, 0, sizeof(struct m46_ns_entry) * sni.entry_num);
	}

	//get entry
	if (m46_pr_conf(&spi, spe, GET_CONFIG_ENTRY)) {
		/* command error */
		ret = -1;
		goto RETURN;
	}
	if (m46_pmtu_conf(&spmi, spme, GET_CONFIG_ENTRY)) {
		/* command error */
		ret = -1;
		goto RETURN;
	}
	if (m46_ns_conf(&sni, sne, GET_CONFIG_ENTRY)) {
		/* command error */
		ret = -1;
		goto RETURN;
	}

	//file output
	if ((fp = fopen(argv[2], "w")) == NULL) {
		printf("Can not open file.\n");
		ret = -1;
		goto RETURN;
	}
	m46_pr_conf_output(fp, &spi, spe);
	m46_pmtu_conf_output(fp, &spmi, spme);
	m46_ns_conf_outputs(fp, &sni, sne);

RETURN:
	if (spe != NULL) {
		free(spe);
	}
	if (spme != NULL) {
		free(spme);
	}
	if (sne != NULL) {
		free(sne);
	}
	if (fp != NULL) {
		fclose(fp);
	}
	return ret;
}

static int m46_over(char **argv)
{
	char buf[M46E_CLI_BUFSIZE], ch;

	printf(" overwrite `%s\' (yes/no)? ", argv[2]);

	memset(buf, 0, sizeof(buf));

	for(;;) {
		ch = fgetc(stdin);
		if (isprint(ch)) {
			printf("%c", ch);
			strncat(buf, &ch, 1);
		} else if ((ch == '\n') || (ch == '\r')) {
			printf("%c", ch);
			break;
		} else if (ch == '\b' || ch == 0x7f) {
			/* BackSpace */
			if (strlen(buf)) {
				buf[strlen(buf)-1] = '\0';
				printf("\b");
				printf("\x1b[0J");
			}
		}
	}

	if (buf[0] == 'y') {
		if ((strcmp(buf, "yes") == 0) || strlen(buf) == 1) {
			return 0;
		}
	}

	return -1;
}

static int m46_pr_conf(struct m46_pr_info *spi, struct m46_pr_entry *spe, int flag)
{
	if (flag == GET_CONFIG_INFO_AND_ENTRY_NUM) {
		if (m46_pr_get_ent_num(spi)) {
			/* command error */
			return -1;
		}
		return 0;	//エントリ数に依存しない情報とエントリ数を取得して終了
	}

	if (spi->entry_num != 0) {
		if (m46_pr_get_ent(spe)) {
			/* command error */
			return -1;
		}
	}

	return 0;
}

static void m46_pr_conf_output(FILE *fp, struct m46_pr_info *spi, struct m46_pr_entry *spe)
{
	char v4_str[16], v6_str[40];
	int i;

	for (i = 0; i < spi->entry_num; i++, spe++) {
		memset(v4_str, 0, sizeof(v4_str));
		memset(v6_str, 0, sizeof(v6_str));
		inet_ntop(AF_INET, &spe->ipv4addr, v4_str, sizeof(v4_str));
		inet_ntop(AF_INET6, &spe->m46_addr, v6_str, sizeof(v6_str));
		fprintf(fp, "pr -s pr-prefix %s/%d %s %u\n", v4_str, spe->ipv4mask, v6_str, spe->plane_id);
	}

	if (spi->def_valid_flg != 0) {
		memset(v6_str, 0, sizeof(v6_str));
		inet_ntop(AF_INET6, &spi->m46_def_pre, v6_str, sizeof(v6_str));
		fprintf(fp, "pr -s default %s\n", v6_str);
	}

	return;
}

static int m46_pmtu_conf(struct m46_pmtu_info *spmi, struct m46_pmtu_entry *spme, int flag)
{
	if (flag == GET_CONFIG_INFO_AND_ENTRY_NUM) {
		if (m46_pmtu_get_ent_num(spmi)) {
			/* command error */
			return -1;
		}
		return 0;	//エントリ数に依存しない情報とエントリ数を取得して終了
	}

	if (spmi->entry_num != 0) {
		if (m46_pmtu_get_ent(spme)) {
			/* command error */
			return -1;
		}
	}

	return 0;
}

static void m46_pmtu_conf_output(FILE *fp, struct m46_pmtu_info *spmi, struct m46_pmtu_entry *spme)
{
	char v4_str[16];
	int i;

	if (spmi->force_fragment != FORCE_FRAGMENT_OFF) {
		fprintf(fp, "pmtu -f on\n");
	} else {
		fprintf(fp, "pmtu -f off\n");
	}

	if ((spmi->timeout / M46_SYS_CLOCK) != 600) {
		fprintf(fp, "pmtu -t %d\n", (spmi->timeout / M46_SYS_CLOCK));
	}

	for (i = 0; i < spmi->entry_num; i++, spme++) {
		memset(v4_str, 0, sizeof(v4_str));
		inet_ntop(AF_INET, &spme->v4_host_addr, v4_str, sizeof(v4_str));
		fprintf(fp, "pmtu -s %s %d %u\n", v4_str, spme->m46_mtu, spme->plane_id);
	}

	return;
}

static int m46_ns_conf(struct m46_ns_info *sni, struct m46_ns_entry *sne, int flag)
{
	int ret;

	if (flag == GET_CONFIG_INFO_AND_ENTRY_NUM) {
		ret = m46_ns_get_ent_info(sni);
		if (ret) {
			return ret;
		}
		return 0;	//エントリ数に依存しない情報とエントリ数を取得して終了
	}

	if (sni->entry_num != 0) {
		ret = m46_ns_get_ent_all(sne);
		if (ret) {
			/* command error */
			return ret;
		}
	}

	return 0;
}

static void m46_ns_conf_outputs(FILE *fp, struct m46_ns_info *sni, struct m46_ns_entry *sne)
{
	int i;
	char v6_str[40];

	for (i = 0; i < sni->entry_num; i++, sne++) {
		memset(v6_str, 0, sizeof(v6_str));
		inet_ntop(AF_INET6, &sne->namespace_addr, v6_str, sizeof(v6_str));
		fprintf(fp, "ns -s %s %u %s %s\n", sne->namespace_name, sne->plane_id, sne->backbone_veth_name, sne->namespace_veth_name);
	}

	return;
}
