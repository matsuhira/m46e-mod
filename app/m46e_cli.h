/*
 * M46E
 * Stateless Automatic IPv4 over IPv6 Tunneling
 *
 * M46E setting command.
 *
 * m46e_cli.h
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

#ifndef M46E_CLI_H_
#define M46E_CLI_H_

#define PUT_PROMPT do{printf("m46e >");fflush(stdout);}while(0)
#define PUT_BAR_T(str)	printf("\n***********************************************************************\n"); \
			printf("* %s\n", str); \
			printf("***********************************************************************\n");
#define M46E_CLI_HISTORY_MAX 20
#define M46E_CLI_BUFSIZE 512
#define M46E_TOKEN_MAX 8
#define M46E_TOKEN_LEN_MAX 64
#define M46E_TAB_SIZE 8
#define M46E_TAB_WIDTH 60
#define M46E_CLI_HISTORY_MAX 20

/* chk func error */
#define M46E_CHKERR_SYNTAX -2
#define M46E_CHKERR_IPV4ADDR -3
#define M46E_CHKERR_IPV4MASK_VALUE -4
#define M46E_CHKERR_IPV6ADDR -5
#define M46E_CHKERR_INVALID_VALUE -6
#define M46E_CHKERR_FILE_NOT_FOUND -7
#define M46E_CHKERR_NSNAME_LEN -8
#define M46E_CHKERR_NSNAME -9
#define M46E_CHKERR_IFNAME_LEN -10
#define M46E_CHKERR_IF_EXSIST -11
#define M46E_CHKERR_IP_CMD_ERROR -12
#define M46E_CHKERR_IF_NOT_EXSIST -13
#define M46E_CHKERR_SWITCH -14

#define max(a, b) ((a) > (b) ? (a) : (b))

struct m46_cli_cmd_tbl {
	char *cmd_str;
	char *cmd_exp;
	struct m46_cli_cmd_tbl *next;
	int (*chk_func)(char *, char *);
	int (*call_func)(int, char **);
	int max_len;
};

typedef struct hist_tbl {
	struct hist_tbl *next;
	struct hist_tbl *prev;
	char str[M46E_CLI_BUFSIZE];
} hist_t;

/* system command */
typedef struct m46_sys_cmd_tbl {
	char *cmd_str;
} m46_sys_cmd_tbl_t;

struct m46_ns_req {
	uint32_t magic_num;
	struct m46_ns_entry sne;
};

struct m46_in6_ifreq {
	struct in6_addr ifr6_addr;
	u_int32_t ifr6_prefixlen;
	int ifr6_ifindex;
};

/* cli main */
void m46_call_cmd(char *);
void m46_blank_del(char *);

/* common call */
void m46_debug_print(char *, char *);
int m46_com_help(int, char **);
int m46_show_sys(int, char **);
int m46_show_m46e(int, char **);
int m46_show_all(int, char **);
int m46_load_conf(int, char **);
int m46_save_conf(int, char **);

/* PR */
int m46_pr_usage(int, char**);
int m46_pr_entry_add(int, char **);
int m46_pr_entry_del(int, char **);
int m46_pr_entry_show(int, char **);
int m46_pr_entry_file(int, char **);
int m46_pr_get_ent_num(struct m46_pr_info *);
int m46_pr_get_ent(struct m46_pr_entry *);

/* PMTU */
int m46_pmtu_usage(int, char **);
int m46_pmtu_set(int, char **);
int m46_pmtu_del(int, char **);
int m46_pmtu_time(int, char **);
int m46_pmtu_show(int, char **);
int m46_pmtu_get_ent_num(struct m46_pmtu_info *);
int m46_pmtu_get_ent(struct m46_pmtu_entry *);
int m46_pmtu_set_force_fragment(int, char **);

/* ns */
int m46_ns_usage(int, char **);
int m46_ns_show_index(int argc, char **argv);
int m46_ns_set(int, char **);
int m46_ns_del(int, char **);
int m46_ns_move(int, char **);
int m46_ns_show(int, char **);
int m46_ns_get_ent_all(struct m46_ns_entry *);
int m46_ns_get_ent_info(struct m46_ns_info *);

/* statistics */
int m46_statistics(int, char **);

/* system */
int m46_set_txquelen(int, char **);
int m46_set_backlog(int, char **);

/* check関数 */
int m46_chk_ipv4_msk(char *, char *);
int m46_chk_ipv4(char *, char *);
int m46_chk_ipv6(char *, char *);
int m46_chk_num(char *, char *);
int m46_chk_filepath(char *, char *);
int m46_chk_ifname(char *, char *);
int m46_dummy(char *, char *);
int m46_chk_set_veth(char *, char *);
int m46_chk_namespace_name(char *, char *);
int m46_chk_swich(char *, char *);

extern m46_sys_cmd_tbl_t cmd_sys[];
extern struct m46_cli_cmd_tbl cmd_root[];

#endif /* M46E_CLI_H_ */
