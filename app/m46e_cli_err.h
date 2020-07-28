/*
 * M46E
 * Stateless Automatic IPv4 over IPv6 Tunneling
 *
 * M46E setting command error message.
 *
 * m46e_cli_err.h
 *
 * Authors:
 * tamagawa          <tamagawa.daiki@jp.fujitsu.com>
 *
 * https://sites.google.com/site/m46enet/
 *
 * Copyright (C)2013 FUJITSU LIMITED
 *
 * Changes:
 * 2013.08.26 tamagawa New
 *
 */

#ifndef M46E_CLI_ERR_H_
#define M46E_CLI_ERR_H_

/*  error message */
#define M46_NS_ERR_CMD			"ip command error."
#define M46_NS_ERR_IFUP_VETH		"m46_ns_ifup(veth) faild."
#define M46_NS_ERR_IFUP_LO		"m46_ns_ifup(lo) faild."
#define M46_NS_ERR_IFUP_M46E		"m46_ns_ifup(m46e) faild."
#define M46_NS_ERR_V6ADDR		"m46_ns_set_v6addr(veth) faild."
#define M46_NS_ERR_NLMSG_LENGTH	"Ack netlink message. payload is too short."
#define M46_NS_ERR_CHILD_INIT		"child proc init faild."
#define M46_NS_ERR_MAGNUM		"unknown magic number."
#define M46_NS_ERR_RETDEVNAME		"set peer device name failed."
#define M46_NS_ERR_SAMEDEVNAME		"device name must be unique. do not set same device name to peer devices."
#define M46_NS_ERR_SETDEVNAME		"set peer eth name failed."
#define M46_NS_ERR_SAMESPACENAME	"specified NameSpace already exists."
#define M46_NS_ERR_ADD_M46E		"add m46e device failed."
#define M46_NS_ERR_SETSPACE		"create namespace failed."
#define M46_NS_ERR_CRATPERDEV		"create peer eth failed."
#define M46_NS_ERR_MOVDEV		"device move failed."
#define M46_NS_ERR_SYNCHILD		"sync child proc failed."
#define M46_NS_ERR_DEL			"specified entry does not exist."
#define M46_NS_ERR_CONNECTNS		"can't connect to specified NameSpace."

/* debug on = 1, off = 0 */
#define M46_DEBUG_FLAG 0

/* PR perror */
#define M46_PR_CMD_ERR			"m46_pr_cmd:"
#define M46_PR_PERR_ADD		"add"
#define M46_PR_PERR_DEL		"delete"
#define M46_PR_PERR_GET		"get"
#define M46_PR_PERR_MALLOC		"malloc"
#define M46_PR_PERR_SOCK		"socket"
#define M46_PR_PERR_IOCTL		"ioctl"

/* PMTU perror */
#define M46_PMTU_CMD_ERR		"m46_pmtu_cmd:"
#define M46_PMTU_PERR_SET		"set"
#define M46_PMTU_PERR_DEL		"delete"
#define M46_PMTU_PERR_GET		"get"
#define M46_PMTU_PERR_TIME		"time"
#define M46_PMTU_PERR_MALLOC		"malloc"
#define M46_PMTU_PERR_SOCK		"socket"
#define M46_PMTU_PERR_IOCTL		"ioctl"
#define M46_PMTU_PERR_FRAG		"force fragment"

/* NS perror */
#define M46_NS_CMD_ERR			"m46_ns_cmd:"
#define M46_NS_PERR_SET		"set"
#define M46_NS_PERR_ADDDEV		"add device"
#define M46_NS_PERR_DEL		"delete"
#define M46_NS_PERR_GET		"get"
#define M46_NS_PERR_UPDATE		"update"
#define M46_NS_PERR_MALLOC		"malloc"
#define M46_NS_PERR_SOCK		"socket"
#define M46_NS_PERR_CONNECT		"connect"
#define M46_NS_PERR_BIND		"bind"
#define M46_NS_PERR_LISTEN		"listen"
#define M46_NS_PERR_SELECT		"select"
#define M46_NS_PERR_ACC		"accept"
#define M46_NS_PERR_IOCTL		"ioctl"
#define M46_NS_PERR_WRITE		"writre"
#define M46_NS_PERR_READ		"read"
#define M46_NS_PERR_MOUNT		"mount"
#define M46_NS_PERR_HOST		"hostname"
#define M46_NS_PERR_PROC		"prctl"
#define M46_NS_PERR_MKDIR		"mkdir"
#define M46_NS_PERR_NETLINK		"netlink"
#define M46_NS_PERR_NETRECV		"netlink recv"
#define M46_NS_PERR_GETADDR		"get address"
#define M46_NS_PERR_SOCKADDR		"socket address"
#define M46_NS_PERR_NS			"namespace: "
#define M46_NS_PERR_NSMOUNT		M46_NS_PERR_NS M46_NS_PERR_MOUNT
#define M46_NS_PERR_NSHOST		M46_NS_PERR_NS M46_NS_PERR_HOST
#define M46_NS_PERR_NSPROC		M46_NS_PERR_NS M46_NS_PERR_PROC
#define M46_NS_PERR_NSMKDIR		M46_NS_PERR_NS M46_NS_PERR_MKDIR
#define M46_NS_PERR_NSSOCK		M46_NS_PERR_NS M46_NS_PERR_SOCK
#define M46_NS_PERR_NSBIND		M46_NS_PERR_NS M46_NS_PERR_BIND
#define M46_NS_PERR_NSLISTEN		M46_NS_PERR_NS M46_NS_PERR_LISTEN
#define M46_NS_PERR_NSSELECT		M46_NS_PERR_NS M46_NS_PERR_SELECT
#define M46_NS_PERR_NSACC		M46_NS_PERR_NS M46_NS_PERR_ACC
#define M46_NS_PERR_NSREAD		M46_NS_PERR_NS M46_NS_PERR_READ
#define M46_NS_PERR_NSWRITE		M46_NS_PERR_NS M46_NS_PERR_WRITE

#endif /* M46E_CLI_ERR_H_ */
