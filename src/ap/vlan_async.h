/*
 * hostapd / VLAN initialization
 * Copyright 2003, Instant802 Networks, Inc.
 * Copyright 2005-2006, Devicescape Software, Inc.
 * Copyright (c) 2009, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef VLAN_ASYNC_H
#define VLAN_ASYNC_H
struct hostapd_vlan;
struct hostapd_data;

void vlan_configure(struct hostapd_vlan *vlan, struct hostapd_data *hapd);
void vlan_deconfigure(struct hostapd_vlan *vlan, struct hostapd_data *hapd);
void vlan_finish_async(struct hostapd_vlan *vlan, struct hostapd_data *hapd);
#endif /* VLAN_ASYNC_H */
