/*
 * hostapd / WPA authenticator glue code
 * Copyright (c) 2002-2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "hostapd.h"

#ifdef CONFIG_LIBNL3_ROUTE
#include <netlink/route/link.h>
#include <netlink/route/link/macvlan.h>
#endif /* CONFIG_LIBNL3_ROUTE */

#include "macvlan.h"


struct macvlan_iface {
	char if_name[IFNAMSIZ + 1];
	char if_base[IFNAMSIZ + 1];
	u8 addr[ETH_ALEN];
	int usage;
	struct macvlan_iface *next;
};


/* Increment ref counter for if_name */
static struct macvlan_iface * macvlan_list_get(struct hostapd_data *hapd,
					       const char *if_base,
					       const u8 *addr)
{
	struct macvlan_iface *next, **macvlan_ifaces;
	struct hapd_interfaces *interfaces;

	interfaces = hapd->iface->interfaces;
	macvlan_ifaces = &interfaces->macvlan_priv;

	for (next = *macvlan_ifaces; next; next = next->next) {
		if (os_strcmp(if_base, next->if_base) == 0 &&
		    os_memcmp(addr, next->addr, sizeof(next->addr)) == 0)
			break;
	}

	if (next)
		next->usage++;

	return next;
}


static void macvlan_list_add(struct hostapd_data *hapd, const char *if_name,
			     const char *if_base, const u8 *addr)
{
	struct macvlan_iface *next, **macvlan_ifaces;
	struct hapd_interfaces *interfaces;

	interfaces = hapd->iface->interfaces;
	macvlan_ifaces = &interfaces->macvlan_priv;

	next = os_zalloc(sizeof(*next));
	if (!next)
		return;

	os_strlcpy(next->if_name, if_name, sizeof(next->if_name));
	os_strlcpy(next->if_base, if_base, sizeof(next->if_base));
	os_memcpy(next->addr, addr, sizeof(next->addr));
	next->usage = 1;
	next->next = *macvlan_ifaces;
	*macvlan_ifaces = next;
}


/* Decrement reference counter for given if_name.
 * Return 1 iff reference counter was decreased to zero, else zero
 */
static int macvlan_list_put(struct hostapd_data *hapd, const char *if_name)
{
	struct macvlan_iface *next, *prev = NULL, **macvlan_ifaces;
	struct hapd_interfaces *interfaces;

	interfaces = hapd->iface->interfaces;
	macvlan_ifaces = &interfaces->macvlan_priv;

	for (next = *macvlan_ifaces; next; next = next->next) {
		if (os_strcmp(if_name, next->if_name) == 0)
			break;
		prev = next;
	}

	if (!next)
		return 0;

	next->usage--;
	if (next->usage)
		return 0;

	if (prev)
		prev->next = next->next;
	else
		*macvlan_ifaces = next->next;
	os_free(next);

	return 1;
}


#ifdef CONFIG_LIBNL3_ROUTE
static int macvlan_iface_add(const char *if_name, const u8 *addr,
			     const char *if_base)
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
	nl_addr_put(nl_addr);

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

	if (handle)
		nl_socket_free(handle);
	return ret;
}


static int macvlan_iface_del(const char *if_name)
{
	int ret = -1;
	struct nl_sock *handle = NULL;
	struct rtnl_link *rlink = NULL;

	wpa_printf(MSG_DEBUG, "MACVLAN: macvlan_iface_del(if_name=%s)",
		   if_name);

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


/* create or reuse macvlan interface
 * @param if_name proposed name, may be altered if required
 * @param addr mac-address
 * @param if_base macvlan lowerdev
 *
 * @returns 0 on success, negative error code else
 */
int macvlan_add(struct hostapd_data *hapd, char *if_name, size_t len,
		const u8 *addr, const char *if_base)
{
	struct macvlan_iface *info;
	int ret;

	info = macvlan_list_get(hapd, if_base, addr);

	if (info) {
		os_strlcpy(if_name, info->if_name, len);
		return 0;
	}

	ret = macvlan_iface_add(if_name, addr, if_base);
	if (ret == 0)
		macvlan_list_add(hapd, if_name, if_base, addr);

	return ret;
}


int macvlan_del(struct hostapd_data *hapd, const char *if_name)
{
	wpa_printf(MSG_DEBUG, "MACVLAN: macvlan_del(if_name=%s)", if_name);

	if (macvlan_list_put(hapd, if_name))
		return macvlan_iface_del(if_name);
	else
		return 0;
}
