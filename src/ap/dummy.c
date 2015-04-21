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
#include "dummy.h"


int dummy_add(const char* if_name, const u8* addr)
{
	int err;
	struct rtnl_link *link = NULL;
	struct nl_addr *nl_addr = NULL;
	struct nl_sock *handle = NULL;
	int ret = -1;

	handle = nl_socket_alloc();
	if (!handle) {
		wpa_printf(MSG_ERROR, "DUMMY: failed to open netlink socket");
		goto dummy_add_error;
	}

	if (nl_connect(handle, NETLINK_ROUTE) < 0) {
		wpa_printf(MSG_ERROR, "DUMMY: failed to connect to netlink");
		goto dummy_add_error;
	}

	if (!(link = rtnl_link_alloc())) {
		wpa_printf(MSG_ERROR, "DUMMY: failed to allocate link");
		goto dummy_add_error;
	}

	if ((err = rtnl_link_set_type(link, "dummy")) < 0) {
		wpa_printf(MSG_ERROR, "DUMMY: failed to set link type to dummy");
		goto dummy_add_error;
	}

	nl_addr = nl_addr_build(AF_BRIDGE, (void *) addr, ETH_ALEN);
	if (!nl_addr) {
		wpa_printf(MSG_ERROR, "DUMMY: failed to parse addr");
		goto dummy_add_error;
	}
	rtnl_link_set_addr(link, nl_addr);
	nl_addr_put(nl_addr);

	rtnl_link_set_name(link, if_name);

	err = rtnl_link_add(handle, link, NLM_F_CREATE);
	if (err < 0) {
		wpa_printf(MSG_ERROR, "DUMMY: failed to create link");
		goto dummy_add_error;
	}
	ret = 0;

dummy_add_error:
	if (link)
		rtnl_link_put(link);

	if (handle)
		nl_socket_free(handle);
	return ret;
}


int dummy_del(const char *if_name)
{
	int ret = -1;
	struct nl_sock *handle = NULL;
	struct nl_cache *cache = NULL;
	struct rtnl_link *rlink = NULL;

	wpa_printf(MSG_DEBUG, "DUMMY: dummy_del(if_name=%s)", if_name);

	handle = nl_socket_alloc();
	if (!handle) {
		wpa_printf(MSG_ERROR, "DUMMY: failed to open netlink socket");
		goto dummy_del_error;
	}

	if (nl_connect(handle, NETLINK_ROUTE) < 0) {
		wpa_printf(MSG_ERROR, "DUMMY: failed to connect to netlink");
		goto dummy_del_error;
	}

	if (rtnl_link_alloc_cache(handle, AF_UNSPEC, &cache) < 0) {
		cache = NULL;
		wpa_printf(MSG_ERROR, "DUMMY: failed to alloc cache");
		goto dummy_del_error;
	}

	if (!(rlink = rtnl_link_get_by_name(cache, if_name))) {
		/* link does not exist */
		wpa_printf(MSG_ERROR, "DUMMY: interface %s does not exists",
			   if_name);
		goto dummy_del_error;
	}

	if (rtnl_link_delete(handle, rlink) < 0) {
		wpa_printf(MSG_ERROR, "DUMMY: failed to remove link %s",
			   if_name);
		goto dummy_del_error;
	}

	ret = 0;

dummy_del_error:
	if (rlink)
		rtnl_link_put(rlink);
	if (cache)
		nl_cache_free(cache);
	if (handle)
		nl_socket_free(handle);
	return ret;
}
#endif /* CONFIG_LIBNL3_ROUTE */
