/*
 * hostapd / VLAN initialization
 * Copyright 2003, Instant802 Networks, Inc.
 * Copyright 2005-2006, Devicescape Software, Inc.
 * Copyright (c) 2009, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "hostapd.h"
#include "vlan_priv.h"
#include "vlan_iface.h"

struct dynamic_iface {
	char ifname0[IFNAMSIZ+1];
	char ifname1[IFNAMSIZ+1];
	int usage;

	int clean;

	struct dynamic_iface *next;
};

/* Increment ref counter for ifname and add clean flag.
 * If not in list, add it only if some flags are given.
 */
void dyn_iface_get(char *ifname0, char *ifname1, int clean, struct hostapd_data *hapd) {
	struct dynamic_iface *next, **dynamic_ifaces;
	struct hapd_interfaces *interfaces;

	interfaces = hapd->iface->interfaces;
	dynamic_ifaces = &interfaces->vlan_priv->dynamic_ifaces;

	for (next = *dynamic_ifaces; next; next = next->next) {
		if (os_strcmp(ifname0, next->ifname0))
			continue;
		if (os_strcmp(ifname1, next->ifname1))
			continue;
		break;
	}

	if (next) {
		next->usage++;
		next->clean |= clean;
		wpa_printf(MSG_DEBUG, "VLAN: %s (%s, %s, %x) ref <- %d", __func__, ifname0, ifname1, clean, next->usage);
		return;
	}

	if (!clean) {
		wpa_printf(MSG_DEBUG, "VLAN: %s (%s, %s, %x) undef", __func__, ifname0, ifname1, clean);
		return;
	}

	next = os_zalloc(sizeof(*next));
	if (!next)
		return;
	os_strlcpy(next->ifname0, ifname0, sizeof(next->ifname0));
	os_strlcpy(next->ifname1, ifname1, sizeof(next->ifname1));
	next->usage = 1;
	next->clean = clean;
	next->next = *dynamic_ifaces;
	*dynamic_ifaces = next;

	wpa_printf(MSG_DEBUG, "VLAN: %s (%s, %s, %x) new ref %d", __func__, ifname0, ifname1, clean, next->usage);
}

/* Decrement reference counter for given ifname.
 * Return clean flag iff reference counter was decreased to zero, else zero
 */
int dyn_iface_put(char *ifname0, char *ifname1, struct hostapd_data *hapd) {
	struct dynamic_iface *next, *prev = NULL, **dynamic_ifaces;
	struct hapd_interfaces *interfaces;
	int clean;

	interfaces = hapd->iface->interfaces;
	dynamic_ifaces = &interfaces->vlan_priv->dynamic_ifaces;

	for (next = *dynamic_ifaces; next; prev = next, next = next->next) {
		if (os_strcmp(ifname0, next->ifname0))
			continue;
		if (os_strcmp(ifname1, next->ifname1))
			continue;
		break;
	}

	if (!next) {
		wpa_printf(MSG_DEBUG, "VLAN: %s (%s, %s) missing", __func__, ifname0, ifname1);
		return 0;
	}

	next->usage--;

	if (next->usage) {
		wpa_printf(MSG_DEBUG, "VLAN: %s (%s, %s) new ref %d, ret %x", __func__, ifname0, ifname1, next->usage, 0);
		return 0;
	}

	if (prev)
		prev->next = next->next;
	else
		*dynamic_ifaces = next->next;
	clean = next->clean;
	os_free(next);

	wpa_printf(MSG_DEBUG, "VLAN: %s (%s, %s) freed, ret %x", __func__, ifname0, ifname1, clean);

	return clean;
}


