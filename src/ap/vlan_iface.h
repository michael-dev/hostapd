/*
 * hostapd / VLAN initialization
 * Copyright 2003, Instant802 Networks, Inc.
 * Copyright 2005-2006, Devicescape Software, Inc.
 * Copyright (c) 2009, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef VLAN_IFACE_H
#define VLAN_IFACE_H
struct hostapd_data;

#define DVLAN_CLEAN_BR         0x1
#define DVLAN_CLEAN_VLAN       0x2
#define DVLAN_CLEAN_VLAN_PORT  0x4

void dyn_iface_get(char *ifname0, char *ifname1, int clean, struct hostapd_data *hapd);
int dyn_iface_put(char *ifname0, char *ifname1, struct hostapd_data *hapd);

#endif /* VLAN_IFACE_H */
