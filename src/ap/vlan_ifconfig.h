/*
 * hostapd / VLAN ifconfig helpers
 * Copyright 2003, Instant802 Networks, Inc.
 * Copyright 2005-2006, Devicescape Software, Inc.
 * Copyright (c) 2009, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef HOSTAPD_VLAN_IFCONFIG_H
#define HOSTAPD_VLAN_IFCONFIG_H
int ifconfig_up(const char *if_name);
int iface_exists(const char *ifname);
int ifconfig_down(const char *if_name);
#endif /* HOSTAPD_VLAN_IFCONFIG_H */
