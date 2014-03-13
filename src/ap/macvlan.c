#ifdef CONFIG_MACVLAN
#include "utils/includes.h"
#include "utils/common.h"
#include <netlink/attr.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/route/link.h>
/* require a very recent libnl with macvlan source mode patches applied */
#include <netlink/route/link/macvlan.h>
#include <netinet/ether.h>
 
/**
 * create macvlan interface using ifidx as base interface
 * and name ifname as new name and mode for mode
 * macaddr is optional
 */
int macvlan_add_interface(const int ifidx, const char* ifname, char* mode, const u8* macaddr)
{
	struct nl_sock *handle = NULL;
	struct rtnl_link *rlink = NULL;
	struct nl_addr *addr = NULL;
	int ret = -1;

	wpa_printf(MSG_DEBUG, "MACVLAN: add if_name=%s with parent %d in mode %s and mac %s",
			      ifname, ifidx, mode, (macaddr ? ether_ntoa( (const struct ether_addr*) macaddr) : "none"));

	/* open netlink connection */
	handle = nl_socket_alloc();
	if (!handle) {
		wpa_printf(MSG_ERROR, "MACVLAN: failed to alloc netlink socket");
		goto macvlan_out;
	}

	if (nl_connect(handle, NETLINK_ROUTE) < 0) {
		wpa_printf(MSG_ERROR, "MACVLAN: failed to connect to netlink");
		goto macvlan_out;
	}

 	rlink = rtnl_link_macvlan_alloc();
	if (!rlink) {
		wpa_printf(MSG_ERROR, "MACVLAN: failed to allocate new link");
		goto macvlan_out;
	}

	rtnl_link_set_name(rlink, ifname);

	rtnl_link_set_link(rlink, ifidx); /* add parent device */

	rtnl_link_macvlan_set_mode(rlink, rtnl_link_macvlan_str2mode(mode));

	if (macaddr) {
		addr = nl_addr_build(AF_LLC, (void *) macaddr, ETH_ALEN);
		rtnl_link_set_addr(rlink, addr);
		nl_addr_put(addr);
	}

	/* create macvlan interface */
	if ((ret = rtnl_link_add(handle, rlink, NLM_F_CREATE)) < 0) {
		wpa_printf(MSG_ERROR, "MACVLAN: failed to create link %s: %s (%d)",
			   ifname, strerror(errno), ret);
		goto macvlan_out;
	}

	ret = 0;

macvlan_out:
	if (rlink)
		rtnl_link_put(rlink);
	if (handle)
		nl_socket_free(handle);
	return ret;
}

/**
 * add mac to macvlan interface. Only valid in source mode.
 */
int macvlan_interface_change_mac(const int ifidx, int add, u8* macaddr)
{
	struct nl_sock *handle = NULL;
	struct nl_msg *msg;
	struct ifinfomsg ifi = {
		.ifi_index = ifidx,
	};
	struct nlattr *info, *infodata;
	struct nl_addr *addr = NULL;
	int err = -NLE_MSGSIZE;

	wpa_printf(MSG_DEBUG, "MACVLAN: %s mac=%s to ififx=%d", (add ? "add" : "del/flush"), (macaddr ? ether_ntoa((struct ether_addr *) macaddr) : "null"), ifidx);

	msg = nlmsg_alloc_simple(RTM_NEWLINK, 0);
	if (!msg)
		return -NLE_NOMEM;

	if (nlmsg_append(msg, &ifi, sizeof(ifi), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	if (!(info = nla_nest_start(msg, IFLA_LINKINFO)))
		goto nla_put_failure;

	NLA_PUT_STRING(msg, IFLA_INFO_KIND, "macvlan");

	if (!(infodata = nla_nest_start(msg, IFLA_INFO_DATA)))
		goto nla_put_failure;

	int mode;
	if (add)
		mode = MACVLAN_MACADDR_ADD;
	else if (macaddr)
		mode = MACVLAN_MACADDR_DEL;
	else
		mode = MACVLAN_MACADDR_FLUSH;

	NLA_PUT_U32(msg, IFLA_MACVLAN_MACADDR_MODE, mode);

	if (macaddr) {
		addr = nl_addr_build(AF_LLC, macaddr, ETH_ALEN);
		NLA_PUT_ADDR(msg, IFLA_MACVLAN_MACADDR, addr);
		nl_addr_put(addr);
	}

	nla_nest_end(msg, infodata);
	nla_nest_end(msg, info);

	handle = nl_socket_alloc();
	if (!handle) {
		wpa_printf(MSG_ERROR, "MACVLAN: failed to alloc netlink socket");
		goto nla_put_failure;
	}

	if ((err = nl_connect(handle, NETLINK_ROUTE)) < 0) {
		wpa_printf(MSG_ERROR, "MACVLAN: failed to connect to netlink");
		goto nla_put_failure;
	}

	err = nl_send_sync(handle, msg);
	msg = NULL;
	if (err < 0) {
		wpa_printf(MSG_ERROR, "MACVLAN: changing mac failed");
		goto nla_put_failure;
	}

nla_put_failure:
	if (msg)
		nlmsg_free(msg);
	if (handle)
		nl_socket_free(handle);
	return err;
}

int macvlan_del_interface(const int ifidx)
{
        struct rtnl_link *link;
        struct nl_sock *sk;
        int err;

        sk = nl_socket_alloc();
        if ((err = nl_connect(sk, NETLINK_ROUTE)) < 0) {
                perror("Unable to connect socket");
                return -1;
        }

        link = rtnl_link_alloc();
        rtnl_link_set_ifindex(link, ifidx);

        if ((err = rtnl_link_delete(sk, link)) < 0) {
                perror("Unable to delete link");
                return -1;
        }

        rtnl_link_put(link);
        nl_close(sk);

	return 0;
}

#endif /* CONFIG_MACVLAN */
