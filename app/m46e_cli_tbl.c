/*
 * M46E
 * Stateless Automatic IPv4 over IPv6 Tunneling
 *
 * setting command common function.
 *
 * m46e_cli_tbl.c
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

#include <string.h>
#include <arpa/inet.h>
#include <linux/netdevice.h>
#include "../include/m46e.h"
#include "m46e_cli.h"

/* -----------------------------------------------------------------------------
   save & load conf
   -----------------------------------------------------------------------------*/
/* load conf */
static struct m46_cli_cmd_tbl load_conf[] = {
	{"<filepath>", "setting file filepath", NULL, m46_chk_filepath, m46_load_conf},
	{NULL}
};

/* save conf */
static struct m46_cli_cmd_tbl save_conf[] = {
	{"<filepath>", "setting file filepath", NULL, m46_dummy, m46_save_conf},
	{NULL}
};

/* conf root */
static struct m46_cli_cmd_tbl cmd_conf[] = {
	{"save", "xxx", save_conf, NULL, NULL},
	{"load", "xxx", load_conf, NULL, NULL},
	{NULL}
};

/* -----------------------------------------------------------------------------
   system command
   -----------------------------------------------------------------------------*/
m46_sys_cmd_tbl_t cmd_sys[] = {
	{"ip rule"},
	{"ip route"},
	{"ifconfig"},
	{"route"},
	{"ip -6 route"},
	{NULL}
};

/* -----------------------------------------------------------------------------
   show
   -----------------------------------------------------------------------------*/
/* show root */
static struct m46_cli_cmd_tbl cmd_show[] = {
	{"all", "show all config", NULL, NULL, m46_show_all},
	{"m46e", "show m46e config", NULL, NULL, m46_show_m46e},
	{"pr", "show m46e-pr config", NULL, NULL, m46_pr_entry_show},
	{"pmtu", "show m46e-pmtu config", NULL, NULL, m46_pmtu_show},
	{"ns", "show m46e-ns config", NULL, NULL, m46_ns_show},
	{"system", "show system config", NULL, NULL, m46_show_sys},
	{NULL}
};

#if 0
/* -----------------------------------------------------------------------------
   net.core.netdev_max_backlog
   -----------------------------------------------------------------------------*/
/* set net.core.netdev_max_backlog */
static struct m46_cli_cmd_tbl set_ndev_backlog[] = {
	{"<1000-99999999999999999999>", "net.core.netdev_max_backlog value", NULL, m46_chk_num, m46_set_backlog},
	{NULL}
};

/* -----------------------------------------------------------------------------
   txquelen
   -----------------------------------------------------------------------------*/
/* set txquelen */
static struct m46_cli_cmd_tbl set_tx_quelen[] = {
	{"<1000-2147483647>", "txquelen value", NULL, m46_chk_num, m46_set_txquelen},
	{NULL}
};

/* set if */
static struct m46_cli_cmd_tbl set_tx_if[] = {
	{"<ifname>", "set txquelen device", set_tx_quelen, m46_chk_ifname, NULL},
	{NULL}
};
#endif /* m46ecliで全ての設定をできるようにしたい時に有効にする */

/* -----------------------------------------------------------------------------
   ns cmmand
   -----------------------------------------------------------------------------*/
/*
 * move
 */
/* NameSpace Name for move device */
static struct m46_cli_cmd_tbl move_dev_field[] = {
	{"<NameSpace Name>", "setting interface name", NULL, m46_chk_namespace_name, m46_ns_move},
	{NULL}
};

/* move device Name */
static struct m46_cli_cmd_tbl move_ns_devname_field[] = {
	{"<IF>", "setting interface name", move_dev_field, m46_chk_ifname, m46_ns_usage},
	{NULL}
};

/*
 * delete
 */
/* del NameSpace Name */
static struct m46_cli_cmd_tbl del_ns_nsname_field[] = {
	{"<NameSpace Name>", "setting NameSpace name", NULL, m46_chk_namespace_name, m46_ns_del},
	{NULL}
};

/*
 * set
 */
/* set NameSpace veth name */
static struct m46_cli_cmd_tbl set_ns_nsveth_field[] = {
	{"<NameSpace v6 IF>", "setting interface name", NULL, m46_chk_set_veth, m46_ns_set},
	{NULL}
};

/* set backbone veth name */
static struct m46_cli_cmd_tbl set_ns_bbveth_field[] = {
	{"<backbone v6 IF>", "setting interface name", set_ns_nsveth_field, m46_chk_set_veth, m46_ns_set},
	{NULL}
};

/* set plane id */
static struct m46_cli_cmd_tbl set_ns_planeid_field[] = {
	{"<0-4294967295>", "setting planeid", set_ns_bbveth_field, m46_chk_num, m46_ns_usage},
	{NULL}
};

/* set NameSpace Name */
static struct m46_cli_cmd_tbl set_ns_nsname_field[] = {
	{"<NameSpace Name>", "setting NameSpace name", set_ns_planeid_field, m46_chk_namespace_name, m46_ns_usage},
	{NULL}
};

/* ns root */
static struct m46_cli_cmd_tbl cmd_ns[] = {
	{"-s", "set ns entry", set_ns_nsname_field, NULL, m46_ns_show},
	{"-d", "delete ns entry", del_ns_nsname_field, NULL, m46_ns_show},
	{"-m", "move device", move_ns_devname_field, NULL, m46_ns_show},
	{"-i", "show ifindex list", NULL, NULL, m46_ns_show_index},
	{NULL}
};

/* -----------------------------------------------------------------------------
   pmtu cmmand
   -----------------------------------------------------------------------------*/
/*
 * set force fragment
 */
/* set force fragment flag */
static struct m46_cli_cmd_tbl set_pmtu_force_fragment[] = {
	{"<on-off>", "force fragment flag", NULL, m46_chk_swich, m46_pmtu_set_force_fragment},
	{NULL}
};

/*
 * expire
 */
/* set timeout */
static struct m46_cli_cmd_tbl set_pmtu_expire[] = {
	{"<300-86400>", "expire time", NULL, m46_chk_num, m46_pmtu_time},
	{NULL}
};

/*
 * delete
 */
/* delete plane id */
static struct m46_cli_cmd_tbl del_pmtu_plane_id[] = {
	{"<0-4294967295>", "planeID", NULL, m46_chk_num, m46_pmtu_del},
	{NULL}
};

/* delete ip v4 addr */
static struct m46_cli_cmd_tbl del_pmtu_v4addr[] = {
	{"<ipv4addr>", "ip v4 address", del_pmtu_plane_id, m46_chk_ipv4, m46_pmtu_usage},
	{NULL}
};

/*
 * set
 */
/* set plane id */
static struct m46_cli_cmd_tbl set_pmtu_plane_id[] = {
	{"<0-4294967295>", "planeID", NULL, m46_chk_num, m46_pmtu_set},
	{NULL}
};

/* set time value */
static struct m46_cli_cmd_tbl set_pmtu_mtu[] = {
	{"<1280-1500>", "Maximum Transmission Unit", set_pmtu_plane_id, m46_chk_num, m46_pmtu_usage},
	{NULL}
};

/* set ip v4 addr */
static struct m46_cli_cmd_tbl set_pmtu_v4addr[] = {
	{"<ipv4addr>", "ip v4 address", set_pmtu_mtu, m46_chk_ipv4, m46_pmtu_usage},
	{NULL}
};

/* pmtu root */
static struct m46_cli_cmd_tbl cmd_pmtu[] = {
	{"-s", "set", set_pmtu_v4addr, NULL, m46_pmtu_show},
	{"-d", "delete", del_pmtu_v4addr, NULL, m46_pmtu_show},
	{"-t", "pmtu entry expire time", set_pmtu_expire, NULL, m46_pmtu_show},
	{"-f", "set force fragment", set_pmtu_force_fragment, NULL, m46_pmtu_show},
	{NULL}
};

/* -----------------------------------------------------------------------------
   pr cmmand
   -----------------------------------------------------------------------------*/
/*
 * file
 */
/* entry add from file */
static struct m46_cli_cmd_tbl pr_filepath[] = {
	{"<filepath>", "setting file filepath", NULL, m46_chk_filepath, m46_pr_entry_file},
	{NULL}
};

/*
 * delete
 */
/* delete plane id */
static struct m46_cli_cmd_tbl del_pr_plane_id[] = {
	{"<0-4294967295>", "planeID", NULL, m46_chk_num, m46_pr_entry_del},
	{NULL}
};

/* delete ip v4 addr */
static struct m46_cli_cmd_tbl del_pr_v4addr[] = {
	{"<ipv4addr/mask>", "ip v4 address", del_pr_plane_id, m46_chk_ipv4_msk, m46_pr_usage},
	{NULL}
};

/* delete prefix */
static struct m46_cli_cmd_tbl del_prefix_field[] = {
	{"pr-prefix", "delete pr config", del_pr_v4addr, NULL, m46_pr_usage},
	{"default", "delete default prefix", NULL, NULL, m46_pr_entry_del},
	{NULL}
};

/*
 * set
 */
/* set m46e prefix */
static struct m46_cli_cmd_tbl set_default_m46_prefix[] = {
	{"<m46e-prefix(64bit)>", "default m46e-prefix", NULL, m46_chk_ipv6, m46_pr_entry_add},
	{NULL}
};

/* set plane id */
static struct m46_cli_cmd_tbl set_pr_plane_id[] = {
	{"<0-4294967295>", "planeID", NULL, m46_chk_num, m46_pr_entry_add},
	{NULL}
};

/* set m46e prefix */
static struct m46_cli_cmd_tbl set_pr_m46_prefix[] = {
	{"<m46e-prefix(64bit)>", "m46e-prefix", set_pr_plane_id, m46_chk_ipv6, m46_pr_usage},
	{NULL}
};

/* set ip v4 addr */
static struct m46_cli_cmd_tbl set_pr_v4addr[] = {
	{"<ipv4addr/mask>", "ip v4 address", set_pr_m46_prefix, m46_chk_ipv4_msk, m46_pr_usage},
	{NULL}
};

/* set prefix */
static struct m46_cli_cmd_tbl set_prefix_field[] = {
	{"pr-prefix", "set m46e pr prefix", set_pr_v4addr, NULL, m46_pr_usage},
	{"default", "set default prefix", set_default_m46_prefix, NULL, m46_pr_usage},
	{NULL}
};

/* pr root */
static struct m46_cli_cmd_tbl cmd_pr[] = {
	{"-s", "set pr entry", set_prefix_field, NULL, m46_pr_entry_show},
	{"-d", "delete", del_prefix_field, NULL, m46_pr_entry_show},
	{"-f", "setting for file", pr_filepath, NULL, m46_pr_entry_show},
	{NULL}
};

/*
 * root
 */
struct m46_cli_cmd_tbl cmd_root[] = {
	{"pr", "setting M46E PR", cmd_pr, NULL, NULL},
	{"pmtu", "setting M46E PMTU", cmd_pmtu, NULL, NULL},
	{"ns", "setting Network NameSpace", cmd_ns, NULL, NULL},
	{"statistics", "output M46E statistics", NULL, NULL, m46_statistics},
	{"config", "save & load config", cmd_conf, NULL, NULL},
#if 0
	{"txquelen", "setting device quelen", set_tx_if, NULL, NULL},
	{"backlog", "setting net.core.netdev_max_backlog", set_ndev_backlog, NULL, NULL},
#endif /* m46ecliで全ての設定をできるようにしたい時に有効にする */
	{"show", "show config", cmd_show, NULL, m46_show_all},
	{"help", "command manual", NULL, NULL, m46_com_help},
	{"exit", "exit M46E cli", NULL, NULL, NULL},
	{NULL}
};

