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
#include <netlink/route/neighbour.h>
#include <netlink/route/link.h>
#include <netlink/route/link/bridge.h>
#include "linux/if_bridge.h"

#include "utils/common.h"
#include "common/linux_bridge.h"
#include "linux_ioctl.h"

#define MAX_VLAN_ID 4094

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


/* ops->changelink is not called during rtnl_newlink interface creation path,
 * but br_dev_newlink does not care about IFLA_BR_VLAN_FILTERING, only
 * br_changelink does.
 */
int linux_br_vlan_filtering(int sock, const char *brname, int vlan_filtering,
			    int pvid)
{
	assert(sock == global_sock);
	struct nl_msg *msg = NULL;
	struct nlattr *info = NULL, *infodata = NULL;
	int err = -1;
	struct ifinfomsg ifi = { 0 };

	msg = nlmsg_alloc_simple(RTM_NEWLINK, 0);
	if (!msg)
		return -1;

	ifi.ifi_family = AF_BRIDGE;
	if (nlmsg_append(msg, &ifi, sizeof(ifi), NLMSG_ALIGNTO) < 0)
		goto err;

	if (nla_put_string(msg, IFLA_IFNAME, brname) < 0)
		goto err;

	info = nla_nest_start(msg, IFLA_LINKINFO);
	if (!info)
		goto err;

	if (nla_put_string(msg, IFLA_INFO_KIND, "bridge") < 0)
		goto err;

	infodata = nla_nest_start(msg, IFLA_INFO_DATA);
	if (!infodata)
		goto err;

	if (nla_put_u8(msg, IFLA_BR_VLAN_FILTERING, vlan_filtering) < 0)
		goto err;

	if (vlan_filtering &&
	    nla_put_u16(msg, IFLA_BR_VLAN_DEFAULT_PVID, pvid) < 0)
		goto err;

	nla_nest_end(msg, infodata);

	nla_nest_end(msg, info);

	err = nl_send_sync(global_nl, msg);
	msg = NULL;
err:
	if (msg)
		nlmsg_free(msg);

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
	int err = -1;

	if (rtnl_link_get_kernel(global_nl, 0, br_name, &link) < 0)
		return -1;
	if (!link)
		return -1;
	brifidx = rtnl_link_get_ifindex(link);
	rtnl_link_put(link); link = NULL;

	nl_socket_modify_cb(global_nl, NL_CB_VALID, NL_CB_CUSTOM, _count_bridge_port, &counter);
	nl_socket_modify_cb(global_nl, NL_CB_FINISH, NL_CB_CUSTOM, _multi_done, &done);

	nlmsg = nlmsg_alloc_simple(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP);
	if (!nlmsg)
		return -1;
	if (nlmsg_append(nlmsg, &msg, sizeof(msg), NLMSG_ALIGNTO) < 0)
		goto err;
	if (nla_put_u32(nlmsg, IFLA_MASTER, brifidx) < 0)
		goto err;

	err = nl_send_sync(global_nl, nlmsg);
	nlmsg = NULL;
	if (err < 0)
		goto err;

	while (!done) {
		int err = nl_recvmsgs_default(global_nl);
		if (err < 0)
			wpa_printf(MSG_ERROR, "linux ioctl netlink: failed to dump links: %d/%s", errno, strerror(errno));
	}

	nl_socket_modify_cb(global_nl, NL_CB_VALID, NL_CB_DEFAULT, NULL, NULL);
	nl_socket_modify_cb(global_nl, NL_CB_FINISH, NL_CB_DEFAULT, NULL, NULL);

	return counter;
err:
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

static int
_linux_br_vlan(int sock, const char *ifname, int add, int untagged,
	       int numtagged, int *tagged)
{
	assert(sock == global_sock);
	struct nl_msg *nlmsg = NULL;
	struct rtnl_link *link = NULL;
	struct nlattr *af_spec = NULL;
	int err = -1, i;
	struct ifinfomsg ifi = { 0 };

	if (rtnl_link_get_kernel(global_nl, 0, ifname, &link) < 0)
		goto err;
	if (!link)
		goto err;

	nlmsg = nlmsg_alloc_simple(add ? RTM_SETLINK : RTM_DELLINK, 0);
        if (!nlmsg)
		goto err;

	ifi.ifi_index = rtnl_link_get_ifindex(link);
	ifi.ifi_family = AF_BRIDGE;
        if (nlmsg_append(nlmsg, &ifi, sizeof(ifi), NLMSG_ALIGNTO) < 0)
                goto err;

	af_spec = nla_nest_start(nlmsg, IFLA_AF_SPEC);
	if (!af_spec)
		goto err;

	/* IFLA_BRIDGE_FLAGS = u16, BRIDGE_FLAGS_SELF | BRIDGE_FLAGS_MASTER */

	/* add vlan info */
	if (untagged) {
		struct bridge_vlan_info vinfo = {};
		vinfo.flags = 0;
		if (add) {
			vinfo.flags |= BRIDGE_VLAN_INFO_PVID;
			vinfo.flags |= BRIDGE_VLAN_INFO_UNTAGGED;
		}
		vinfo.vid = untagged;

		if (nla_put(nlmsg, IFLA_BRIDGE_VLAN_INFO, sizeof(vinfo), &vinfo) < 0)
			goto err;
	}
	for (i = 0; i < numtagged && tagged[i]; i++) {
		if (tagged[i] == untagged ||
		    tagged[i] <= 0 || tagged[i] > MAX_VLAN_ID ||
		    (i > 0 && tagged[i] == tagged[i - 1]))
			continue;
		struct bridge_vlan_info vinfo = {};
		vinfo.vid = tagged[i];
		if (nla_put(nlmsg, IFLA_BRIDGE_VLAN_INFO, sizeof(vinfo), &vinfo) < 0)
			goto err;
	}

	nla_nest_end(nlmsg, af_spec);

	err = nl_send_sync(global_nl, nlmsg);
	nlmsg = NULL;

	wpa_printf(MSG_WARNING, "VLAN (netlink): Interface %s %s to vlan %d%s in _linux_br_vlan",
		   ifname, add ? "add":"del", untagged, (numtagged > 0 && tagged[0]) ? "+" : "");

err:
	if (link)
		rtnl_link_put(link);
	if (nlmsg)
		nlmsg_free(nlmsg);

	return err;
}

int linux_br_add_vlan(int sock, const char *ifname, int untagged,
		      int numtagged, int *tagged)
{
	return _linux_br_vlan(sock, ifname, 1, untagged, numtagged, tagged);
}

int linux_br_del_vlan(int sock, const char *ifname, int untagged,
		      int numtagged, int *tagged)
{
	return _linux_br_vlan(sock, ifname, 0, untagged, numtagged, tagged);
}

struct fdb_cache {
	struct fdb_cache *next;
	char br_name[IFNAMSIZ];
	u8 mac[6];
	u8 done:1;
	int ref;
};

struct fdb_cache *fdb_cache = NULL;

static int _linux_br_fdb(int add, const char *br_name, const u8* mac)
{
	struct rtnl_neigh *neigh = NULL;
	struct rtnl_link *link = NULL;
	struct nl_addr* nl_addr = NULL;
	int ret = -1;
	struct fdb_cache *entry = fdb_cache, *prev = NULL;

	while (entry) {
		if (os_memcmp(mac, entry->mac, ETH_ALEN) == 0 && 
		    os_strncmp(br_name, entry->br_name, sizeof(entry->br_name)) == 0)
			break;

		prev = entry;
		entry = entry -> next;
	}

	if (entry && add) {
		wpa_printf(MSG_WARNING, "FDB (netlink): bridge %s %s fdb mac %02x:%02x:%02x:%02x:%02x:%02x in _linux_br_fdb just incrementing ref",
			   br_name, add ? "add":"del", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		entry->ref++;
		if (entry->done)
			return 0;
	} else if (entry && !add) {
		entry->ref--;
		if (entry->ref > 0) {
			wpa_printf(MSG_WARNING, "FDB (netlink): bridge %s %s fdb mac %02x:%02x:%02x:%02x:%02x:%02x in _linux_br_fdb just decrementing ref",
				   br_name, add ? "add":"del", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
			return 0;
		}
		if (prev)
			prev->next = entry->next;
		else
			fdb_cache = entry->next;
		os_free(entry);
		entry = NULL;
	} else if (!entry && add) {
		entry = os_zalloc(sizeof(*entry));
		if (entry) {
			os_memcpy(entry->mac, mac, ETH_ALEN);
			os_strlcpy(entry->br_name, br_name, sizeof(entry->br_name));
			entry->ref = 1;
			entry->next = fdb_cache;
			fdb_cache = entry;
		}
	}

	if (rtnl_link_get_kernel(global_nl, 0, br_name, &link) < 0)
		goto err;

	neigh = rtnl_neigh_alloc();
	if (!neigh)
		goto err;

	nl_addr = nl_addr_build(AF_BRIDGE, (u8 *) mac, ETH_ALEN);
	if (nl_addr == NULL)
		goto err;
	rtnl_neigh_set_family(neigh, AF_BRIDGE);
	rtnl_neigh_set_ifindex(neigh, rtnl_link_get_ifindex(link));
	rtnl_neigh_set_lladdr(neigh, nl_addr);
	rtnl_neigh_set_state(neigh, NUD_PERMANENT);
	rtnl_neigh_set_flags(neigh, NTF_SELF);
	wpa_printf(MSG_WARNING, "FDB (netlink): bridge %s %s fdb mac %02x:%02x:%02x:%02x:%02x:%02x in _linux_br_fdb",
		   br_name, add ? "add":"del", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	if (add) {
		/* may add NLM_F_EXCL or NLM_F_APPEND */
		if (rtnl_neigh_add(global_nl, neigh, NLM_F_CREATE) < 0)
			goto err;
		if (entry)
			entry->done = 1;
	} else if (rtnl_neigh_delete(global_nl, neigh, 0) < 0)
			goto err;

	ret = 0;
err:
	if (link)
		rtnl_link_put(link);
	if (neigh)
		rtnl_neigh_put(neigh);
	if (nl_addr)
		nl_addr_put(nl_addr);

	return ret;
}
int linux_br_fdb_add(int sock, const char *br_name, const u8* mac)
{
	assert(sock == global_sock);
	return _linux_br_fdb(1, br_name, mac);
}

int linux_br_fdb_del(int sock, const char *br_name, const u8* mac)
{
	assert(sock == global_sock);
	return _linux_br_fdb(0, br_name, mac);
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
