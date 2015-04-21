/*
 * hostapd / WPA authenticator glue code
 * Copyright (c) 2002-2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"

#ifdef CONFIG_LIBNL3_ROUTE
#include <netlink/route/link.h>
#include <netlink/route/link/macvlan.h>
#include "macvlan.h"


int macvlan_add(const char *if_name, const u8 *addr, const char *if_base)
{
	int err;
	struct rtnl_link *link = NULL;
	struct rtnl_link *base = NULL;
	struct nl_addr *nl_addr = NULL;
	struct nl_sock *handle = NULL;
	int ret = -1;

	handle = nl_socket_alloc();
	if (!handle) {
		wpa_printf(MSG_ERROR, "MACVLAN: failed to open netlink socket");
		goto macvlan_add_error;
	}

	if (nl_connect(handle, NETLINK_ROUTE) < 0) {
		wpa_printf(MSG_ERROR, "MACVLAN: failed to connect to netlink");
		goto macvlan_add_error;
	}

	if (rtnl_link_get_kernel(handle, 0, if_base, &base) < 0) {
		/* link does not exist */
		wpa_printf(MSG_ERROR, "MACVLAN: interface %s does not exists",
			   if_base);
		goto macvlan_add_error;
	}

	link = rtnl_link_macvlan_alloc();
	if (!link) {
		wpa_printf(MSG_ERROR, "MACVLAN: failed to allocate link");
		goto macvlan_add_error;
	}

	err = rtnl_link_macvlan_set_mode(link,
					 rtnl_link_macvlan_str2mode("bridge"));
	if (err < 0) {
		wpa_printf(MSG_ERROR,
			   "MACVLAN: failed to set link type to macvlan");
		goto macvlan_add_error;
	}

	nl_addr = nl_addr_build(AF_LLC, (void *) addr, ETH_ALEN);
	if (!nl_addr) {
		wpa_printf(MSG_ERROR, "MACVLAN: failed to parse addr");
		goto macvlan_add_error;
	}
	rtnl_link_set_addr(link, nl_addr);

	rtnl_link_set_name(link, if_name);

	rtnl_link_set_link(link, rtnl_link_get_ifindex(base));

	err = rtnl_link_add(handle, link, NLM_F_CREATE);
	if (err < 0) {
		wpa_printf(MSG_ERROR, "MACVLAN: failed to create link");
		goto macvlan_add_error;
	}
	ret = 0;

macvlan_add_error:
	if (link)
		rtnl_link_put(link);
	if (base)
		rtnl_link_put(base);
	if (addr)
		nl_addr_put(nl_addr);
	if (handle)
		nl_socket_free(handle);
	return ret;
}


int macvlan_del(const char *if_name)
{
	int ret = -1;
	struct nl_sock *handle = NULL;
	struct rtnl_link *rlink = NULL;

	wpa_printf(MSG_DEBUG, "MACVLAN: macvlan_del(if_name=%s)", if_name);

	handle = nl_socket_alloc();
	if (!handle) {
		wpa_printf(MSG_ERROR, "MACVLAN: failed to open netlink socket");
		goto macvlan_del_error;
	}

	if (nl_connect(handle, NETLINK_ROUTE) < 0) {
		wpa_printf(MSG_ERROR, "MACVLAN: failed to connect to netlink");
		goto macvlan_del_error;
	}

	if (rtnl_link_get_kernel(handle, 0, if_name, &rlink) < 0) {
		/* link does not exist */
		wpa_printf(MSG_ERROR, "MACVLAN: interface %s does not exists",
			   if_name);
		goto macvlan_del_error;
	}

	if (rtnl_link_delete(handle, rlink) < 0) {
		wpa_printf(MSG_ERROR, "MACVLAN: failed to remove link %s",
			   if_name);
		goto macvlan_del_error;
	}

	ret = 0;

macvlan_del_error:
	if (rlink)
		rtnl_link_put(rlink);
	if (handle)
		nl_socket_free(handle);
	return ret;
}
#endif /* CONFIG_LIBNL3_ROUTE */
