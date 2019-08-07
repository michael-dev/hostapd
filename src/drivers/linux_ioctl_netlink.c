/*
 * Linux ioctl helper functions for driver wrappers
 * Copyright (c) 2002-2010, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include <assert.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/route/link.h>
#include <netlink/route/link/bridge.h>

#include "utils/common.h"
#include "common/linux_bridge.h"
#include "linux_ioctl.h"


static struct nl_sock *global_nl = NULL;
static int global_sock = -1;
static int global_sock_ref = 0;

int linux_set_iface_flags(int sock, const char *ifname, int dev_up)
{
	assert(sock == global_sock);
	struct rtnl_link *link = NULL, *change = NULL;
	int err = -1;

	link = rtnl_link_alloc();
	if (!link)
		goto err;

	change = rtnl_link_alloc();
	if (!change)
	       goto err;

	rtnl_link_set_name(change, ifname);
	if (dev_up)
		rtnl_link_set_flags(change, IFF_UP);
	else
		rtnl_link_unset_flags(change, IFF_UP);

	err = rtnl_link_change(global_nl, link, change, 0);
err:
	if (link)
		rtnl_link_put(link);
	if (change)
		rtnl_link_put(change);

	return err;
}


int linux_iface_up(int sock, const char *ifname)
{
	assert(sock == global_sock);
	struct rtnl_link *link = NULL;
	int ret = -1;

	if (rtnl_link_get_kernel(global_nl, 0, ifname, &link) < 0)
		goto err;

	ret = !!(rtnl_link_get_flags(link) & IFF_UP);

err:
	if (link)
		rtnl_link_put(link);

	return ret;
}


int linux_get_ifhwaddr(int sock, const char *ifname, u8 *addr)
{
	assert(sock == global_sock);
	struct rtnl_link *link = NULL;
	struct nl_addr* nl_addr = NULL;
	int ret = -1;

	if (rtnl_link_get_kernel(global_nl, 0, ifname, &link) < 0)
		goto err;
	if (!link)
		goto err;

	nl_addr = rtnl_link_get_addr(link);
	if (!nl_addr)
		goto err;

	if (nl_addr_get_len(nl_addr) != ETH_ALEN)
		goto err;

	os_memcpy(addr, nl_addr_get_binary_addr(nl_addr), ETH_ALEN);
	ret = 0;

err:
	if (link)
		rtnl_link_put(link);

	return ret;
}


int linux_set_ifhwaddr(int sock, const char *ifname, const u8 *addr)
{
	assert(sock == global_sock);
	struct rtnl_link *link = NULL, *change = NULL;
	struct nl_addr *nl_addr = NULL;
	int err = -1;

	link = rtnl_link_alloc();
	if (!link)
		goto err;

	change = rtnl_link_alloc();
	if (!change)
	       goto err;

	rtnl_link_set_name(change, ifname);
	nl_addr = nl_addr_build(AF_BRIDGE, (u8 *) addr, ETH_ALEN);
	if (nl_addr == NULL)
		goto err;
	rtnl_link_set_addr(change, nl_addr);

	err = rtnl_link_change(global_nl, link, change, 0);
err:
	if (link)
		rtnl_link_put(link);
	if (change)
		rtnl_link_put(change);
	if (nl_addr)
		nl_addr_put(nl_addr);

	return err;
}


int linux_br_add(int sock, const char *brname)
{
	assert(sock == global_sock);
	int err;
	struct rtnl_link *link = NULL;

	link = rtnl_link_bridge_alloc();
	if (!link)
		return -1;
	rtnl_link_set_name(link, brname);
	rtnl_link_set_flags(link, IFF_UP);

	err = rtnl_link_add(global_nl, link, NLM_F_CREATE);
	rtnl_link_put(link);

	return err;
}


int linux_br_del(int sock, const char *brname)
{
	assert(sock == global_sock);
	struct rtnl_link *link;
	int err = -1;

	link = rtnl_link_alloc();
	if (!link)
		goto err;

	rtnl_link_set_name(link, brname);
	if (rtnl_link_delete(global_nl, link) < 0)
		goto err;

	err = 0;
err:
	if (link)
		rtnl_link_put(link);

	return err;
}


int linux_br_add_if(int sock, const char *brname, const char *ifname)
{
	assert(sock == global_sock);
	struct rtnl_link *link = NULL, *bridge = NULL, *change = NULL;
	int err = -1;

	link = rtnl_link_alloc();
	if (!link)
		goto err;

	change = rtnl_link_alloc();
	if (!change)
	       goto err;
	rtnl_link_set_name(change, ifname);

	if (rtnl_link_get_kernel(global_nl, 0, brname, &bridge) < 0)
		goto err;
	if (!bridge)
		goto err;

	rtnl_link_set_master(change, rtnl_link_get_ifindex(bridge));

	err = rtnl_link_change(global_nl, link, change, 0);
err:
	if (change)
		rtnl_link_put(change);
	if (link)
		rtnl_link_put(link);
	if (bridge)
		rtnl_link_put(bridge);

	return err;
}


int linux_br_del_if(int sock, const char *brname, const char *ifname)
{
	assert(sock == global_sock);
	struct rtnl_link *link = NULL;
	int err = -1;

	if (rtnl_link_get_kernel(global_nl, 0, ifname, &link) < 0)
		goto err;
	if (!link)
		goto err;

	if (rtnl_link_release(global_nl, link) < 0) // needs ifidx present
		goto err;

	err = 0;
err:
	if (link)
		rtnl_link_put(link);

	return err;
}


static struct rtnl_link *
_linux_master_get(const char *ifname)
{
	struct rtnl_link *link = NULL, *master = NULL;
	int master_idx;

	if (rtnl_link_get_kernel(global_nl, 0, ifname, &link) < 0)
		goto err;
	if (!link)
		goto err;

	master_idx = rtnl_link_get_master(link);
	if (!master_idx)
		goto err;

	if (rtnl_link_get_kernel(global_nl, master_idx, NULL, &master) < 0)
		goto err;

err:
	if (link)
		rtnl_link_put(link);

	return master;
}

int linux_br_exists(int sock, const char *br_name)
{
	assert(sock == global_sock);
	struct rtnl_link *link = NULL;
	int ret = -1;

	if (rtnl_link_get_kernel(global_nl, 0, br_name, &link) < 0)
		return -1;
	if (!link)
		return -1;

	ret = rtnl_link_is_bridge(link);
	if (link)
		rtnl_link_put(link);

	return ret;
}


int linux_br_get(char *brname, const char *ifname)
{
	int sock = linux_ioctl_socket();
	assert(sock == global_sock);
	int ret = -1;
	struct rtnl_link *master;

	master = _linux_master_get(ifname);
	if (!master)
		goto err;
	if (!rtnl_link_is_bridge(master))
		goto err;

	os_strlcpy(brname, rtnl_link_get_name(master), IFNAMSIZ);
	ret = 0;
err:
	if (master)
		rtnl_link_put(master);
	linux_ioctl_close(sock);

	return ret;
}


static int _multi_done(struct nl_msg *msg, void *arg)
{
	int *done = (int*) arg;
	*done = 1;
	return NL_OK;
}


static void _count_bridge_port2(struct nl_object *obj, void *arg)
{
	int *counter = (int *) arg;

	if (nl_object_get_msgtype(obj) != RTM_NEWLINK)
		return;
	(*counter)++;
}

static int _count_bridge_port(struct nl_msg *msg, void *arg)
{
	nl_msg_parse(msg, _count_bridge_port2, arg);
        return NL_OK;
}

int linux_br_getnumports(int sock, const char *br_name)
{
	int done = 0, counter = 0, brifidx;
	struct rtnl_link *link = NULL;
	struct nl_msg *nlmsg = NULL;
        struct ifinfomsg msg = { 0 };

	if (rtnl_link_get_kernel(global_nl, 0, br_name, &link) < 0)
		return -1;
	if (!link)
		return -1;
	brifidx = rtnl_link_get_ifindex(link);
	rtnl_link_put(link); link = NULL;

	nl_socket_modify_cb(global_nl, NL_CB_VALID, NL_CB_CUSTOM, _count_bridge_port, &counter);
	nl_socket_modify_cb(global_nl, NL_CB_FINISH, NL_CB_CUSTOM, _multi_done, &done);

	nlmsg = nlmsg_alloc_simple(RTM_GETLINK, NLM_F_DUMP);
	if (!nlmsg)
		return -1;
	if (nlmsg_append(nlmsg, &msg, sizeof(msg), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;
	NLA_PUT_U32(nlmsg, IFLA_MASTER, brifidx);

	if (nl_send_auto(global_nl, nlmsg) < 0)
		goto nla_put_failure;

	nlmsg_free(nlmsg);

	while (!done) {
		int err = nl_recvmsgs_default(global_nl);
		if (err < 0)
			wpa_printf(MSG_ERROR, "linux ioctl netlink: failed to dump links: %d/%s", errno, strerror(errno));
	}

	nl_socket_modify_cb(global_nl, NL_CB_VALID, NL_CB_DEFAULT, NULL, NULL);
	nl_socket_modify_cb(global_nl, NL_CB_FINISH, NL_CB_DEFAULT, NULL, NULL);

	return counter;
nla_put_failure:
	nlmsg_free(nlmsg);
	return -1;
}


int linux_master_get(char *master_ifname, const char *ifname)
{
	int ret = -1;
	struct rtnl_link *master;
	int sock = linux_ioctl_socket();

	master = _linux_master_get(ifname);
	if (!master)
		goto err;

	os_strlcpy(master_ifname, rtnl_link_get_name(master), IFNAMSIZ);
	ret = 0;
err:
	if (master)
		rtnl_link_put(master);
	linux_ioctl_close(sock);

	return ret;
}

int linux_ioctl_socket()
{
	if (global_sock_ref == 0) {
		global_nl = nl_socket_alloc();
		if (!global_nl) {
			wpa_printf(MSG_ERROR, "linux ioctl netlink: failed to alloc netlink socket");
			return -1;
		}

		nl_socket_disable_seq_check(global_nl);

		if (nl_connect(global_nl, NETLINK_ROUTE) < 0) {
			wpa_printf(MSG_ERROR, "linux ioctl netlink:: failed to connect to netlink");
			return -1;
		}

		global_sock = nl_socket_get_fd(global_nl);
	}

	global_sock_ref++;
	return global_sock;
}

void linux_ioctl_close(int sock)
{
	assert(sock == global_sock);

	if (global_sock_ref > 0 )
		global_sock_ref--;
	if (global_sock_ref > 0)
		return; // socket still in use
	nl_socket_free(global_nl);
	global_nl = NULL;
	global_sock = -1;
}
